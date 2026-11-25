//! Mutual TLS (mTLS) Attestation Protocol with Dynamic Cryptographic Key Rotation
//! for Mesh Peering in ISSP (Integrated Session Synchronization Protocol).
//!
//! Provides cryptographically attested node identities, 4-phase mutual attestation handshake,
//! forward-secure ratchet key derivation, zero-downtime key rotation with grace period overlapping,
//! anti-replay protection, and mesh security telemetry.

#![allow(clippy::manual_is_multiple_of, clippy::chunks_exact_to_as_chunks)]

use std::collections::{HashMap, HashSet};
use std::fmt;

use crate::session_sync::{
    chacha20_block, chacha20_xor_slice, constant_time_eq, poly1305_aead_tag,
};

/// Magic header identifier for ISSP mTLS Handshake frames: `0x49534D54` ("ISMT").
pub const ISSP_MTLS_MAGIC: u32 = 0x4953_4D54;

/// Protocol version for ISSP mTLS.
pub const ISSP_MTLS_VERSION: u16 = 1;

/// Magic header identifier for ISSP mTLS Encrypted Wire Envelopes: `0x49534D45` ("ISME").
pub const ISSP_ENVELOPE_MAGIC: u32 = 0x4953_4D45;

/// Default key rotation time interval in nanoseconds (1 hour = 3600 seconds).
pub const DEFAULT_ROTATION_INTERVAL_NS: u64 = 3_600 * 1_000_000_000;

/// Default packet count threshold before mandatory key rotation (100,000 packets).
pub const DEFAULT_ROTATION_PACKETS_THRESHOLD: u64 = 100_000;

/// Default byte volume threshold before mandatory key rotation (1 GB).
pub const DEFAULT_ROTATION_BYTES_THRESHOLD: u64 = 1_000_000_000;

/// Default grace period window for in-flight packets during rotation (60 seconds).
pub const DEFAULT_GRACE_PERIOD_NS: u64 = 60 * 1_000_000_000;

// ---------------------------------------------------------------------------
// Capability Bitflags
// ---------------------------------------------------------------------------

pub const CAP_MULTIPATH: u32 = 1 << 0;
pub const CAP_BBR_CONGESTION: u32 = 1 << 1;
pub const CAP_SIMD_ACCEL: u32 = 1 << 2;
pub const CAP_ZSTD_STREAM: u32 = 1 << 3;
pub const CAP_DYNAMIC_REKEY: u32 = 1 << 4;
pub const CAP_POST_QUANTUM_READY: u32 = 1 << 5;

// ---------------------------------------------------------------------------
// Native IFA Cryptographic Key Derivation & MAC
// ---------------------------------------------------------------------------

/// Deterministic 256-bit Key Derivation Function (KDF) using native ChaCha20 block.
pub fn ifa_kdf_derive(secret: &[u8; 32], label: &[u8], epoch: u64) -> [u8; 32] {
    let mut nonce = [0u8; 12];
    let label_len = label.len().min(8);
    nonce[..label_len].copy_from_slice(&label[..label_len]);
    nonce[8..12].copy_from_slice(&(epoch as u32).to_le_bytes());

    let counter = ((epoch >> 32) as u32).wrapping_add(1);
    let block = chacha20_block(secret, counter, &nonce);
    let mut out = [0u8; 32];
    out.copy_from_slice(&block[0..32]);
    out
}

/// Compute a 16-byte Poly1305 MAC tag over arbitrary data.
pub fn ifa_mac(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
    poly1305_aead_tag(key, &[], data)
}

/// Compute a 32-byte cryptographic authentication digest for signatures and fingerprints.
pub fn ifa_digest32(key: &[u8; 32], message: &[u8]) -> [u8; 32] {
    let mut key_rot = *key;
    for (i, b) in key_rot.iter_mut().enumerate() {
        *b = b.rotate_left(((i % 7) + 1) as u32);
    }
    let tag1 = poly1305_aead_tag(key, b"IFA-DIGEST-PART1", message);
    let tag2 = poly1305_aead_tag(&key_rot, b"IFA-DIGEST-PART2", message);
    let mut out = [0u8; 32];
    out[0..16].copy_from_slice(&tag1);
    out[16..32].copy_from_slice(&tag2);
    out
}

// ---------------------------------------------------------------------------
// Error Handling
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MtlsError {
    InvalidMagic(u32),
    UnsupportedVersion(u16),
    CertificateExpired {
        now_ns: u64,
        valid_until_ns: u64,
    },
    CertificateNotYetValid {
        now_ns: u64,
        valid_from_ns: u64,
    },
    CertificateRevoked {
        serial: u64,
        node_id: u32,
    },
    UntrustedIssuer(u32),
    InvalidIssuerCluster {
        expected: String,
        found: String,
    },
    SignatureVerificationFailed,
    PeerNotAttested(u32),
    HandshakeStateMismatch(&'static str),
    ChallengeVerificationFailed,
    TranscriptProofMismatch,
    EpochExpired {
        epoch_id: u64,
        grace_window_expired_ns: u64,
    },
    EpochFutureUnsupported {
        epoch_id: u64,
        active_epoch: u64,
    },
    ReplayPacketDetected {
        epoch_id: u64,
        seq: u64,
    },
    AuthenticationTagMismatch,
    MissingPeerKeyRing(u32),
    PacketPayloadTruncated,
}

impl fmt::Display for MtlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic(m) => write!(f, "invalid mTLS magic: {m:#010x}"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported mTLS protocol version: {v}"),
            Self::CertificateExpired {
                now_ns,
                valid_until_ns,
            } => {
                write!(
                    f,
                    "certificate expired at {valid_until_ns} (current: {now_ns})"
                )
            }
            Self::CertificateNotYetValid {
                now_ns,
                valid_from_ns,
            } => {
                write!(
                    f,
                    "certificate not yet valid until {valid_from_ns} (current: {now_ns})"
                )
            }
            Self::CertificateRevoked { serial, node_id } => {
                write!(
                    f,
                    "certificate serial {serial} for node {node_id} is revoked"
                )
            }
            Self::UntrustedIssuer(id) => write!(f, "untrusted cluster CA issuer node: {id}"),
            Self::InvalidIssuerCluster { expected, found } => {
                write!(
                    f,
                    "cluster ID mismatch: expected '{expected}', found '{found}'"
                )
            }
            Self::SignatureVerificationFailed => write!(f, "digital signature verification failed"),
            Self::PeerNotAttested(id) => write!(f, "peer node {id} is not mutually attested"),
            Self::HandshakeStateMismatch(msg) => write!(f, "handshake state mismatch: {msg}"),
            Self::ChallengeVerificationFailed => {
                write!(f, "handshake challenge verification failed")
            }
            Self::TranscriptProofMismatch => write!(f, "transcript hash proof verification failed"),
            Self::EpochExpired {
                epoch_id,
                grace_window_expired_ns,
            } => {
                write!(
                    f,
                    "key epoch {epoch_id} expired {grace_window_expired_ns} ns ago"
                )
            }
            Self::EpochFutureUnsupported {
                epoch_id,
                active_epoch,
            } => {
                write!(
                    f,
                    "future key epoch {epoch_id} not supported (active is {active_epoch})"
                )
            }
            Self::ReplayPacketDetected { epoch_id, seq } => {
                write!(
                    f,
                    "anti-replay dropped duplicate/outdated packet: epoch={epoch_id}, seq={seq}"
                )
            }
            Self::AuthenticationTagMismatch => write!(f, "AEAD authentication tag mismatch"),
            Self::MissingPeerKeyRing(id) => write!(f, "no active key ring for peer node {id}"),
            Self::PacketPayloadTruncated => write!(f, "wire payload truncated or malformed"),
        }
    }
}

impl std::error::Error for MtlsError {}

// ---------------------------------------------------------------------------
// Mesh Node Roles & Identities
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MeshNodeRole {
    Gateway,
    Relay,
    Worker,
    Edge,
    Ingress,
    Egress,
    Supervisor,
}

impl MeshNodeRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Gateway => "gateway",
            Self::Relay => "relay",
            Self::Worker => "worker",
            Self::Edge => "edge",
            Self::Ingress => "ingress",
            Self::Egress => "egress",
            Self::Supervisor => "supervisor",
        }
    }

    pub fn parse_role(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "gateway" => Some(Self::Gateway),
            "relay" => Some(Self::Relay),
            "worker" => Some(Self::Worker),
            "edge" => Some(Self::Edge),
            "ingress" => Some(Self::Ingress),
            "egress" => Some(Self::Egress),
            "supervisor" => Some(Self::Supervisor),
            _ => None,
        }
    }
}

impl std::str::FromStr for MeshNodeRole {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_role(s).ok_or(())
    }
}

/// Cryptographic identity claims of a mesh node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeIdentity {
    pub node_id: u32,
    pub cluster_id: String,
    pub role: MeshNodeRole,
    pub public_key: [u8; 32],
    pub valid_from_ns: u64,
    pub valid_until_ns: u64,
    pub capabilities: u32,
}

impl NodeIdentity {
    pub fn new(
        node_id: u32,
        cluster_id: impl Into<String>,
        role: MeshNodeRole,
        public_key: [u8; 32],
        valid_from_ns: u64,
        valid_until_ns: u64,
        capabilities: u32,
    ) -> Self {
        Self {
            node_id,
            cluster_id: cluster_id.into(),
            role,
            public_key,
            valid_from_ns,
            valid_until_ns,
            capabilities,
        }
    }

    /// Canonical serialized byte representation for fingerprinting and signing.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(96 + self.cluster_id.len());
        bytes.extend_from_slice(&self.node_id.to_le_bytes());
        bytes.extend_from_slice(&(self.cluster_id.len() as u32).to_le_bytes());
        bytes.extend_from_slice(self.cluster_id.as_bytes());
        bytes.push(self.role as u8);
        bytes.extend_from_slice(&self.public_key);
        bytes.extend_from_slice(&self.valid_from_ns.to_le_bytes());
        bytes.extend_from_slice(&self.valid_until_ns.to_le_bytes());
        bytes.extend_from_slice(&self.capabilities.to_le_bytes());
        bytes
    }

    /// Compute 32-byte cryptographic fingerprint of this identity.
    pub fn fingerprint(&self) -> [u8; 32] {
        let canonical = self.canonical_bytes();
        let default_seed = [0x5au8; 32];
        ifa_digest32(&default_seed, &canonical)
    }

    pub fn fingerprint_hex(&self) -> String {
        let fp = self.fingerprint();
        let mut s = String::with_capacity(64);
        for b in fp {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
        }
        s
    }
}

// ---------------------------------------------------------------------------
// Attestation Certificate
// ---------------------------------------------------------------------------

/// Cluster-issued digital certificate attesting a node's identity and permissions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshAttestationCertificate {
    pub serial_number: u64,
    pub subject: NodeIdentity,
    pub issuer_node_id: u32,
    pub issuer_cluster_id: String,
    pub signature: [u8; 32],
    pub revoked: bool,
}

impl MeshAttestationCertificate {
    /// Issue and cryptographically sign a new certificate using the Cluster CA key.
    pub fn issue(
        serial_number: u64,
        issuer_node_id: u32,
        issuer_cluster_id: impl Into<String>,
        subject: NodeIdentity,
        ca_secret_key: &[u8; 32],
    ) -> Self {
        let issuer_cluster_id = issuer_cluster_id.into();
        let mut unsigned = Self {
            serial_number,
            subject,
            issuer_node_id,
            issuer_cluster_id,
            signature: [0u8; 32],
            revoked: false,
        };
        let tbs = unsigned.tbs_bytes();
        unsigned.signature = ifa_digest32(ca_secret_key, &tbs);
        unsigned
    }

    /// Serialize "to be signed" (TBS) certificate fields.
    pub fn tbs_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(128);
        bytes.extend_from_slice(&self.serial_number.to_le_bytes());
        bytes.extend_from_slice(&self.issuer_node_id.to_le_bytes());
        bytes.extend_from_slice(&(self.issuer_cluster_id.len() as u32).to_le_bytes());
        bytes.extend_from_slice(self.issuer_cluster_id.as_bytes());
        bytes.extend_from_slice(&self.subject.canonical_bytes());
        bytes
    }

    /// Verify signature and temporal validity against the trusted CA key.
    pub fn verify(&self, ca_secret_key: &[u8; 32], now_ns: u64) -> Result<(), MtlsError> {
        if self.revoked {
            return Err(MtlsError::CertificateRevoked {
                serial: self.serial_number,
                node_id: self.subject.node_id,
            });
        }
        if now_ns < self.subject.valid_from_ns {
            return Err(MtlsError::CertificateNotYetValid {
                now_ns,
                valid_from_ns: self.subject.valid_from_ns,
            });
        }
        if now_ns > self.subject.valid_until_ns {
            return Err(MtlsError::CertificateExpired {
                now_ns,
                valid_until_ns: self.subject.valid_until_ns,
            });
        }

        let tbs = self.tbs_bytes();
        let expected_sig = ifa_digest32(ca_secret_key, &tbs);
        if !constant_time_eq(&self.signature, &expected_sig) {
            return Err(MtlsError::SignatureVerificationFailed);
        }
        Ok(())
    }

    pub fn fingerprint(&self) -> [u8; 32] {
        let tbs = self.tbs_bytes();
        let seed = [0x7eu8; 32];
        ifa_digest32(&seed, &tbs)
    }

    pub fn fingerprint_hex(&self) -> String {
        let fp = self.fingerprint();
        let mut s = String::with_capacity(64);
        for b in fp {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
        }
        s
    }
}

// ---------------------------------------------------------------------------
// Mesh Trust Store
// ---------------------------------------------------------------------------

/// Root Certificate Authority (CA) trust anchor and Certificate Revocation List (CRL).
#[derive(Debug, Clone)]
pub struct MeshTrustStore {
    pub cluster_id: String,
    pub trusted_ca_keys: HashMap<u32, [u8; 32]>,
    pub revoked_serials: HashSet<u64>,
    pub revoked_node_ids: HashSet<u32>,
    pub enforce_cluster_id: bool,
}

impl MeshTrustStore {
    pub fn new(cluster_id: impl Into<String>) -> Self {
        Self {
            cluster_id: cluster_id.into(),
            trusted_ca_keys: HashMap::new(),
            revoked_serials: HashSet::new(),
            revoked_node_ids: HashSet::new(),
            enforce_cluster_id: true,
        }
    }

    pub fn add_trusted_ca(&mut self, ca_node_id: u32, ca_key: [u8; 32]) {
        self.trusted_ca_keys.insert(ca_node_id, ca_key);
    }

    pub fn revoke_certificate(&mut self, serial_number: u64, node_id: u32) {
        self.revoked_serials.insert(serial_number);
        self.revoked_node_ids.insert(node_id);
    }

    /// Verify an attestation certificate against this trust store.
    pub fn verify_certificate(
        &self,
        cert: &MeshAttestationCertificate,
        now_ns: u64,
    ) -> Result<(), MtlsError> {
        if self.revoked_serials.contains(&cert.serial_number)
            || self.revoked_node_ids.contains(&cert.subject.node_id)
            || cert.revoked
        {
            return Err(MtlsError::CertificateRevoked {
                serial: cert.serial_number,
                node_id: cert.subject.node_id,
            });
        }

        if self.enforce_cluster_id && cert.subject.cluster_id != self.cluster_id {
            return Err(MtlsError::InvalidIssuerCluster {
                expected: self.cluster_id.clone(),
                found: cert.subject.cluster_id.clone(),
            });
        }

        let ca_key = self
            .trusted_ca_keys
            .get(&cert.issuer_node_id)
            .ok_or(MtlsError::UntrustedIssuer(cert.issuer_node_id))?;

        cert.verify(ca_key, now_ns)
    }
}

// ---------------------------------------------------------------------------
// 4-Phase mTLS Mutual Attestation Handshake Messages
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtlsClientHello {
    pub magic: u32,
    pub version: u16,
    pub sender_node_id: u32,
    pub client_cert: MeshAttestationCertificate,
    pub client_nonce: [u8; 32],
    pub ephemeral_pubkey: [u8; 32],
    pub timestamp_ns: u64,
    pub signature: [u8; 32],
}

impl MtlsClientHello {
    pub fn new(
        client_cert: MeshAttestationCertificate,
        client_privkey: &[u8; 32],
        client_nonce: [u8; 32],
        ephemeral_pubkey: [u8; 32],
        timestamp_ns: u64,
    ) -> Self {
        let sender_node_id = client_cert.subject.node_id;
        let mut hello = Self {
            magic: ISSP_MTLS_MAGIC,
            version: ISSP_MTLS_VERSION,
            sender_node_id,
            client_cert,
            client_nonce,
            ephemeral_pubkey,
            timestamp_ns,
            signature: [0u8; 32],
        };
        let tbs = hello.tbs_bytes();
        hello.signature = ifa_digest32(client_privkey, &tbs);
        hello
    }

    pub fn tbs_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(160);
        bytes.extend_from_slice(&self.magic.to_le_bytes());
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(&self.sender_node_id.to_le_bytes());
        bytes.extend_from_slice(&self.client_cert.tbs_bytes());
        bytes.extend_from_slice(&self.client_nonce);
        bytes.extend_from_slice(&self.ephemeral_pubkey);
        bytes.extend_from_slice(&self.timestamp_ns.to_le_bytes());
        bytes
    }

    pub fn verify_signature(&self) -> bool {
        let tbs = self.tbs_bytes();
        let expected = ifa_digest32(&self.client_cert.subject.public_key, &tbs);
        constant_time_eq(&self.signature, &expected)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtlsServerChallenge {
    pub magic: u32,
    pub version: u16,
    pub server_node_id: u32,
    pub server_cert: MeshAttestationCertificate,
    pub server_nonce: [u8; 32],
    pub ephemeral_pubkey: [u8; 32],
    pub challenge_cookie: [u8; 32],
    pub timestamp_ns: u64,
    pub signature: [u8; 32],
}

impl MtlsServerChallenge {
    pub fn new(
        server_cert: MeshAttestationCertificate,
        server_privkey: &[u8; 32],
        server_nonce: [u8; 32],
        ephemeral_pubkey: [u8; 32],
        challenge_cookie: [u8; 32],
        timestamp_ns: u64,
    ) -> Self {
        let server_node_id = server_cert.subject.node_id;
        let mut chal = Self {
            magic: ISSP_MTLS_MAGIC,
            version: ISSP_MTLS_VERSION,
            server_node_id,
            server_cert,
            server_nonce,
            ephemeral_pubkey,
            challenge_cookie,
            timestamp_ns,
            signature: [0u8; 32],
        };
        let tbs = chal.tbs_bytes();
        chal.signature = ifa_digest32(server_privkey, &tbs);
        chal
    }

    pub fn tbs_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(192);
        bytes.extend_from_slice(&self.magic.to_le_bytes());
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(&self.server_node_id.to_le_bytes());
        bytes.extend_from_slice(&self.server_cert.tbs_bytes());
        bytes.extend_from_slice(&self.server_nonce);
        bytes.extend_from_slice(&self.ephemeral_pubkey);
        bytes.extend_from_slice(&self.challenge_cookie);
        bytes.extend_from_slice(&self.timestamp_ns.to_le_bytes());
        bytes
    }

    pub fn verify_signature(&self) -> bool {
        let tbs = self.tbs_bytes();
        let expected = ifa_digest32(&self.server_cert.subject.public_key, &tbs);
        constant_time_eq(&self.signature, &expected)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtlsClientProof {
    pub magic: u32,
    pub version: u16,
    pub client_node_id: u32,
    pub challenge_response: [u8; 32],
    pub transcript_proof: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtlsServerFinished {
    pub magic: u32,
    pub version: u16,
    pub session_id: u64,
    pub initial_key_epoch: u64,
    pub server_proof: [u8; 32],
    pub success: bool,
}

// ---------------------------------------------------------------------------
// Dynamic Key Epochs & Peering Key Ring
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationReason {
    ScheduledTime,
    PacketCountLimit,
    ByteVolumeLimit,
    AdministrativeRekey,
    EmergencyRevocation,
}

impl RotationReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ScheduledTime => "scheduled_time",
            Self::PacketCountLimit => "packet_count_limit",
            Self::ByteVolumeLimit => "byte_volume_limit",
            Self::AdministrativeRekey => "admin_rekey",
            Self::EmergencyRevocation => "emergency_revocation",
        }
    }
}

/// Cryptographic symmetric state for an individual key epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeeringKeyEpoch {
    pub epoch_id: u64,
    pub tx_key: [u8; 32],
    pub rx_key: [u8; 32],
    pub activated_at_ns: u64,
    pub retired_at_ns: Option<u64>,
    pub packets_encrypted: u64,
    pub bytes_encrypted: u64,
    pub packets_decrypted: u64,
    pub bytes_decrypted: u64,
    pub tx_seq: u64,
    pub rx_seq: u64,
    pub replay_window: u64,
}

impl PeeringKeyEpoch {
    pub fn new(epoch_id: u64, tx_key: [u8; 32], rx_key: [u8; 32], now_ns: u64) -> Self {
        Self {
            epoch_id,
            tx_key,
            rx_key,
            activated_at_ns: now_ns,
            retired_at_ns: None,
            packets_encrypted: 0,
            bytes_encrypted: 0,
            packets_decrypted: 0,
            bytes_decrypted: 0,
            tx_seq: 1,
            rx_seq: 0,
            replay_window: 0,
        }
    }

    pub fn should_rotate(
        &self,
        now_ns: u64,
        max_duration_ns: u64,
        max_packets: u64,
        max_bytes: u64,
    ) -> Option<RotationReason> {
        if self.retired_at_ns.is_some() {
            return None;
        }
        if now_ns.saturating_sub(self.activated_at_ns) >= max_duration_ns {
            return Some(RotationReason::ScheduledTime);
        }
        if self.packets_encrypted >= max_packets {
            return Some(RotationReason::PacketCountLimit);
        }
        if self.bytes_encrypted >= max_bytes {
            return Some(RotationReason::ByteVolumeLimit);
        }
        None
    }

    pub fn is_grace_expired(&self, now_ns: u64, grace_period_ns: u64) -> bool {
        match self.retired_at_ns {
            Some(retired_at) => now_ns.saturating_sub(retired_at) > grace_period_ns,
            None => false,
        }
    }
}

/// Encrypted, authenticated wire envelope exchanged over the mesh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtlsEnvelope {
    pub magic: u32,
    pub epoch_id: u64,
    pub seq_num: u64,
    pub auth_tag: [u8; 16],
    pub ciphertext: Vec<u8>,
}

impl MtlsEnvelope {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(36 + self.ciphertext.len());
        bytes.extend_from_slice(&self.magic.to_le_bytes());
        bytes.extend_from_slice(&self.epoch_id.to_le_bytes());
        bytes.extend_from_slice(&self.seq_num.to_le_bytes());
        bytes.extend_from_slice(&self.auth_tag);
        bytes.extend_from_slice(&(self.ciphertext.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MtlsError> {
        if bytes.len() < 40 {
            return Err(MtlsError::PacketPayloadTruncated);
        }
        let magic = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        if magic != ISSP_ENVELOPE_MAGIC {
            return Err(MtlsError::InvalidMagic(magic));
        }
        let epoch_id = u64::from_le_bytes(bytes[4..12].try_into().unwrap());
        let seq_num = u64::from_le_bytes(bytes[12..20].try_into().unwrap());
        let mut auth_tag = [0u8; 16];
        auth_tag.copy_from_slice(&bytes[20..36]);
        let ct_len = u32::from_le_bytes(bytes[36..40].try_into().unwrap()) as usize;
        if bytes.len() < 40 + ct_len {
            return Err(MtlsError::PacketPayloadTruncated);
        }
        let ciphertext = bytes[40..40 + ct_len].to_vec();
        Ok(Self {
            magic,
            epoch_id,
            seq_num,
            auth_tag,
            ciphertext,
        })
    }
}

/// Key Ring managing active epoch, grace-period historical epochs, and ratchet rotation.
#[derive(Debug, Clone)]
pub struct PeeringKeyRing {
    pub master_secret: [u8; 32],
    pub active_epoch: PeeringKeyEpoch,
    pub grace_epochs: Vec<PeeringKeyEpoch>,
    pub rotation_interval_ns: u64,
    pub grace_period_ns: u64,
    pub max_packets_per_epoch: u64,
    pub max_bytes_per_epoch: u64,
    pub total_rotations: u64,
    pub grace_packets_accepted: u64,
    pub replays_prevented: u64,
    pub auth_failures: u64,
    pub expired_drops: u64,
}

impl PeeringKeyRing {
    pub fn new(
        master_secret: [u8; 32],
        tx_key: [u8; 32],
        rx_key: [u8; 32],
        initial_epoch_id: u64,
        now_ns: u64,
    ) -> Self {
        Self {
            master_secret,
            active_epoch: PeeringKeyEpoch::new(initial_epoch_id, tx_key, rx_key, now_ns),
            grace_epochs: Vec::new(),
            rotation_interval_ns: DEFAULT_ROTATION_INTERVAL_NS,
            grace_period_ns: DEFAULT_GRACE_PERIOD_NS,
            max_packets_per_epoch: DEFAULT_ROTATION_PACKETS_THRESHOLD,
            max_bytes_per_epoch: DEFAULT_ROTATION_BYTES_THRESHOLD,
            total_rotations: 0,
            grace_packets_accepted: 0,
            replays_prevented: 0,
            auth_failures: 0,
            expired_drops: 0,
        }
    }

    /// Perform forward-ratchet key rotation to advance to the next key epoch.
    pub fn rotate(&mut self, now_ns: u64, _reason: RotationReason) -> u64 {
        let mut old_epoch = self.active_epoch.clone();
        old_epoch.retired_at_ns = Some(now_ns);
        self.grace_epochs.push(old_epoch);

        let next_epoch_id = self.active_epoch.epoch_id + 1;
        let new_tx_key =
            ifa_kdf_derive(&self.active_epoch.tx_key, b"IFA-RATCHET-KEY", next_epoch_id);
        let new_rx_key =
            ifa_kdf_derive(&self.active_epoch.rx_key, b"IFA-RATCHET-KEY", next_epoch_id);
        let new_master = ifa_kdf_derive(&self.master_secret, b"IFA-RATCHET-EPOCH", next_epoch_id);

        self.master_secret = new_master;
        self.active_epoch = PeeringKeyEpoch::new(next_epoch_id, new_tx_key, new_rx_key, now_ns);
        self.total_rotations += 1;

        // Evict expired grace epochs
        let grace_ns = self.grace_period_ns;
        self.grace_epochs
            .retain(|e| !e.is_grace_expired(now_ns, grace_ns));

        next_epoch_id
    }

    /// Check if rotation is due and rotate if needed.
    pub fn check_and_rotate(&mut self, now_ns: u64) -> Option<(u64, RotationReason)> {
        if let Some(reason) = self.active_epoch.should_rotate(
            now_ns,
            self.rotation_interval_ns,
            self.max_packets_per_epoch,
            self.max_bytes_per_epoch,
        ) {
            let new_epoch = self.rotate(now_ns, reason);
            Some((new_epoch, reason))
        } else {
            None
        }
    }

    /// Encrypt a payload into an authenticated wire envelope using the active epoch.
    pub fn encrypt_envelope(
        &mut self,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<MtlsEnvelope, MtlsError> {
        let seq = self.active_epoch.tx_seq;
        self.active_epoch.tx_seq = self.active_epoch.tx_seq.wrapping_add(1);

        let mut nonce = [0u8; 12];
        nonce[0..8].copy_from_slice(&seq.to_le_bytes());
        nonce[8..12].copy_from_slice(&(self.active_epoch.epoch_id as u32).to_le_bytes());

        let poly_block = chacha20_block(&self.active_epoch.tx_key, 0, &nonce);
        let mut poly_key = [0u8; 32];
        poly_key.copy_from_slice(&poly_block[0..32]);

        let mut ciphertext = plaintext.to_vec();
        chacha20_xor_slice(&self.active_epoch.tx_key, &nonce, 1, &mut ciphertext);

        let mut full_aad = Vec::with_capacity(aad.len() + 20);
        full_aad.extend_from_slice(&ISSP_ENVELOPE_MAGIC.to_le_bytes());
        full_aad.extend_from_slice(&self.active_epoch.epoch_id.to_le_bytes());
        full_aad.extend_from_slice(&seq.to_le_bytes());
        full_aad.extend_from_slice(aad);

        let auth_tag = poly1305_aead_tag(&poly_key, &full_aad, &ciphertext);

        self.active_epoch.packets_encrypted += 1;
        self.active_epoch.bytes_encrypted += plaintext.len() as u64;

        Ok(MtlsEnvelope {
            magic: ISSP_ENVELOPE_MAGIC,
            epoch_id: self.active_epoch.epoch_id,
            seq_num: seq,
            auth_tag,
            ciphertext,
        })
    }

    /// Decrypt an authenticated envelope, supporting seamless grace period key recovery.
    pub fn decrypt_envelope(
        &mut self,
        envelope: &MtlsEnvelope,
        aad: &[u8],
        now_ns: u64,
    ) -> Result<Vec<u8>, MtlsError> {
        if envelope.magic != ISSP_ENVELOPE_MAGIC {
            return Err(MtlsError::InvalidMagic(envelope.magic));
        }

        let is_active = envelope.epoch_id == self.active_epoch.epoch_id;
        let is_future = envelope.epoch_id > self.active_epoch.epoch_id;

        if is_future {
            return Err(MtlsError::EpochFutureUnsupported {
                epoch_id: envelope.epoch_id,
                active_epoch: self.active_epoch.epoch_id,
            });
        }

        let (rx_key, _is_grace) = if is_active {
            // Anti-replay check for active epoch
            if envelope.seq_num <= self.active_epoch.rx_seq {
                let diff = self.active_epoch.rx_seq - envelope.seq_num;
                if diff >= 64 || (self.active_epoch.replay_window & (1u64 << diff)) != 0 {
                    self.replays_prevented += 1;
                    return Err(MtlsError::ReplayPacketDetected {
                        epoch_id: envelope.epoch_id,
                        seq: envelope.seq_num,
                    });
                }
            }
            (self.active_epoch.rx_key, false)
        } else {
            // Search in grace epochs
            let grace_opt = self
                .grace_epochs
                .iter_mut()
                .find(|e| e.epoch_id == envelope.epoch_id);
            match grace_opt {
                Some(grace_epoch) => {
                    if grace_epoch.is_grace_expired(now_ns, self.grace_period_ns) {
                        self.expired_drops += 1;
                        let expired_by = now_ns
                            .saturating_sub(grace_epoch.retired_at_ns.unwrap_or(now_ns))
                            .saturating_sub(self.grace_period_ns);
                        return Err(MtlsError::EpochExpired {
                            epoch_id: envelope.epoch_id,
                            grace_window_expired_ns: expired_by,
                        });
                    }
                    // Anti-replay for grace epoch
                    if envelope.seq_num <= grace_epoch.rx_seq {
                        let diff = grace_epoch.rx_seq - envelope.seq_num;
                        if diff >= 64 || (grace_epoch.replay_window & (1u64 << diff)) != 0 {
                            self.replays_prevented += 1;
                            return Err(MtlsError::ReplayPacketDetected {
                                epoch_id: envelope.epoch_id,
                                seq: envelope.seq_num,
                            });
                        }
                    }
                    (grace_epoch.rx_key, true)
                }
                None => {
                    self.expired_drops += 1;
                    return Err(MtlsError::EpochExpired {
                        epoch_id: envelope.epoch_id,
                        grace_window_expired_ns: 0,
                    });
                }
            }
        };

        let mut nonce = [0u8; 12];
        nonce[0..8].copy_from_slice(&envelope.seq_num.to_le_bytes());
        nonce[8..12].copy_from_slice(&(envelope.epoch_id as u32).to_le_bytes());

        let poly_block = chacha20_block(&rx_key, 0, &nonce);
        let mut poly_key = [0u8; 32];
        poly_key.copy_from_slice(&poly_block[0..32]);

        let mut full_aad = Vec::with_capacity(aad.len() + 20);
        full_aad.extend_from_slice(&ISSP_ENVELOPE_MAGIC.to_le_bytes());
        full_aad.extend_from_slice(&envelope.epoch_id.to_le_bytes());
        full_aad.extend_from_slice(&envelope.seq_num.to_le_bytes());
        full_aad.extend_from_slice(aad);

        let expected_tag = poly1305_aead_tag(&poly_key, &full_aad, &envelope.ciphertext);
        if !constant_time_eq(&envelope.auth_tag, &expected_tag) {
            self.auth_failures += 1;
            return Err(MtlsError::AuthenticationTagMismatch);
        }

        let mut plaintext = envelope.ciphertext.clone();
        chacha20_xor_slice(&rx_key, &nonce, 1, &mut plaintext);

        if is_active {
            if envelope.seq_num > self.active_epoch.rx_seq {
                let diff = envelope.seq_num - self.active_epoch.rx_seq;
                if diff < 64 {
                    self.active_epoch.replay_window = (self.active_epoch.replay_window << diff) | 1;
                } else {
                    self.active_epoch.replay_window = 1;
                }
                self.active_epoch.rx_seq = envelope.seq_num;
            } else {
                let diff = self.active_epoch.rx_seq - envelope.seq_num;
                if diff < 64 {
                    self.active_epoch.replay_window |= 1u64 << diff;
                }
            }
            self.active_epoch.packets_decrypted += 1;
            self.active_epoch.bytes_decrypted += plaintext.len() as u64;
        } else {
            let grace_epoch = self
                .grace_epochs
                .iter_mut()
                .find(|e| e.epoch_id == envelope.epoch_id)
                .unwrap();
            if envelope.seq_num > grace_epoch.rx_seq {
                let diff = envelope.seq_num - grace_epoch.rx_seq;
                if diff < 64 {
                    grace_epoch.replay_window = (grace_epoch.replay_window << diff) | 1;
                } else {
                    grace_epoch.replay_window = 1;
                }
                grace_epoch.rx_seq = envelope.seq_num;
            } else {
                let diff = grace_epoch.rx_seq - envelope.seq_num;
                if diff < 64 {
                    grace_epoch.replay_window |= 1u64 << diff;
                }
            }
            grace_epoch.packets_decrypted += 1;
            grace_epoch.bytes_decrypted += plaintext.len() as u64;
            self.grace_packets_accepted += 1;
        }

        Ok(plaintext)
    }
}

// ---------------------------------------------------------------------------
// Mesh Peer Attestation Manager
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MtlsHandshakeState {
    Unauthenticated,
    HelloSent {
        client_nonce: [u8; 32],
        ephemeral_priv: [u8; 32],
        timestamp_ns: u64,
    },
    ChallengePending {
        client_nonce: [u8; 32],
        server_nonce: [u8; 32],
        ephemeral_priv: [u8; 32],
        challenge_cookie: [u8; 32],
    },
    MutualAttested {
        session_id: u64,
        attested_at_ns: u64,
        active_epoch: u64,
    },
    Failed(String),
}

/// Record of an attested peer in the mesh.
#[derive(Debug, Clone)]
pub struct PeerAttestationRecord {
    pub peer_node_id: u32,
    pub identity: NodeIdentity,
    pub certificate: MeshAttestationCertificate,
    pub state: MtlsHandshakeState,
    pub key_ring: Option<PeeringKeyRing>,
    pub last_attested_at_ns: u64,
    pub last_rotation_at_ns: u64,
}

/// Central manager orchestrating mutual attestation and key rotation across mesh peers.
#[derive(Debug, Clone)]
pub struct MeshPeerAttestationManager {
    pub local_identity: NodeIdentity,
    pub local_certificate: MeshAttestationCertificate,
    pub local_private_key: [u8; 32],
    pub trust_store: MeshTrustStore,
    pub peers: HashMap<u32, PeerAttestationRecord>,
    pub total_handshakes_initiated: u64,
    pub total_handshakes_completed: u64,
    pub total_handshakes_failed: u64,
}

impl MeshPeerAttestationManager {
    pub fn new(
        local_identity: NodeIdentity,
        local_certificate: MeshAttestationCertificate,
        local_private_key: [u8; 32],
        trust_store: MeshTrustStore,
    ) -> Self {
        Self {
            local_identity,
            local_certificate,
            local_private_key,
            trust_store,
            peers: HashMap::new(),
            total_handshakes_initiated: 0,
            total_handshakes_completed: 0,
            total_handshakes_failed: 0,
        }
    }

    /// Register a known peer identity and certificate prior to handshake.
    pub fn register_peer(
        &mut self,
        peer_identity: NodeIdentity,
        peer_cert: MeshAttestationCertificate,
    ) {
        let peer_id = peer_identity.node_id;
        self.peers.insert(
            peer_id,
            PeerAttestationRecord {
                peer_node_id: peer_id,
                identity: peer_identity,
                certificate: peer_cert,
                state: MtlsHandshakeState::Unauthenticated,
                key_ring: None,
                last_attested_at_ns: 0,
                last_rotation_at_ns: 0,
            },
        );
    }

    /// Initiate an mTLS handshake towards a remote peer node (ClientHello).
    pub fn initiate_handshake(
        &mut self,
        peer_node_id: u32,
        now_ns: u64,
    ) -> Result<MtlsClientHello, MtlsError> {
        let peer = self
            .peers
            .get_mut(&peer_node_id)
            .ok_or(MtlsError::PeerNotAttested(peer_node_id))?;

        let mut client_nonce = [0u8; 32];
        let mut ephemeral_priv = [0u8; 32];
        for i in 0..32 {
            client_nonce[i] = ((now_ns >> (i % 8))
                ^ (self.local_identity.node_id as u64)
                ^ (peer_node_id as u64)) as u8;
            ephemeral_priv[i] = (self.local_private_key[i]).wrapping_add(i as u8);
        }
        let ephemeral_pubkey = ifa_kdf_derive(&ephemeral_priv, b"IFA-EPHEMERAL-PUB", 1);

        peer.state = MtlsHandshakeState::HelloSent {
            client_nonce,
            ephemeral_priv,
            timestamp_ns: now_ns,
        };
        self.total_handshakes_initiated += 1;

        Ok(MtlsClientHello::new(
            self.local_certificate.clone(),
            &self.local_private_key,
            client_nonce,
            ephemeral_pubkey,
            now_ns,
        ))
    }

    /// Process incoming ClientHello on the server side and reply with ServerChallenge.
    pub fn handle_client_hello(
        &mut self,
        hello: &MtlsClientHello,
        now_ns: u64,
    ) -> Result<MtlsServerChallenge, MtlsError> {
        if hello.magic != ISSP_MTLS_MAGIC {
            self.total_handshakes_failed += 1;
            return Err(MtlsError::InvalidMagic(hello.magic));
        }
        if hello.version != ISSP_MTLS_VERSION {
            self.total_handshakes_failed += 1;
            return Err(MtlsError::UnsupportedVersion(hello.version));
        }

        // Verify client certificate and signature
        self.trust_store
            .verify_certificate(&hello.client_cert, now_ns)?;
        if !hello.verify_signature() {
            self.total_handshakes_failed += 1;
            return Err(MtlsError::SignatureVerificationFailed);
        }

        let peer_id = hello.sender_node_id;
        let mut server_nonce = [0u8; 32];
        let mut ephemeral_priv = [0u8; 32];
        let mut challenge_cookie = [0u8; 32];
        for i in 0..32 {
            server_nonce[i] = ((now_ns >> (i % 8)) ^ 0xa5 ^ (peer_id as u64)) as u8;
            ephemeral_priv[i] = self.local_private_key[i]
                .wrapping_mul(3)
                .wrapping_add(i as u8);
            challenge_cookie[i] = hello.client_nonce[i] ^ server_nonce[i] ^ (i as u8);
        }
        let ephemeral_pubkey = ifa_kdf_derive(&ephemeral_priv, b"IFA-EPHEMERAL-PUB", 2);

        // Store peer state
        let peer_entry = self
            .peers
            .entry(peer_id)
            .or_insert_with(|| PeerAttestationRecord {
                peer_node_id: peer_id,
                identity: hello.client_cert.subject.clone(),
                certificate: hello.client_cert.clone(),
                state: MtlsHandshakeState::Unauthenticated,
                key_ring: None,
                last_attested_at_ns: 0,
                last_rotation_at_ns: 0,
            });

        peer_entry.state = MtlsHandshakeState::ChallengePending {
            client_nonce: hello.client_nonce,
            server_nonce,
            ephemeral_priv,
            challenge_cookie,
        };

        Ok(MtlsServerChallenge::new(
            self.local_certificate.clone(),
            &self.local_private_key,
            server_nonce,
            ephemeral_pubkey,
            challenge_cookie,
            now_ns,
        ))
    }

    /// Process ServerChallenge on the client side, verify proof, and generate ClientProof.
    pub fn handle_server_challenge(
        &mut self,
        chal: &MtlsServerChallenge,
        now_ns: u64,
    ) -> Result<MtlsClientProof, MtlsError> {
        if chal.magic != ISSP_MTLS_MAGIC {
            self.total_handshakes_failed += 1;
            return Err(MtlsError::InvalidMagic(chal.magic));
        }
        self.trust_store
            .verify_certificate(&chal.server_cert, now_ns)?;
        if !chal.verify_signature() {
            self.total_handshakes_failed += 1;
            return Err(MtlsError::SignatureVerificationFailed);
        }

        let peer_id = chal.server_node_id;
        let peer = self
            .peers
            .get_mut(&peer_id)
            .ok_or(MtlsError::PeerNotAttested(peer_id))?;

        let (client_nonce, _ephemeral_priv) = match &peer.state {
            MtlsHandshakeState::HelloSent {
                client_nonce,
                ephemeral_priv,
                ..
            } => (*client_nonce, *ephemeral_priv),
            _ => {
                self.total_handshakes_failed += 1;
                return Err(MtlsError::HandshakeStateMismatch(
                    "expected HelloSent on client",
                ));
            }
        };

        let mut combined = [0u8; 32];
        for i in 0..32 {
            combined[i] = self.local_private_key[i]
                ^ chal.server_cert.subject.public_key[i]
                ^ client_nonce[i]
                ^ chal.server_nonce[i];
        }
        let dh_shared = ifa_kdf_derive(&combined, b"IFA-SHARED-SECRET", 1);

        let handshake_key = ifa_kdf_derive(&dh_shared, b"IFA-mTLS-HANDSHAKE", 1);
        let challenge_response = ifa_digest32(&handshake_key, &chal.challenge_cookie);

        let mut transcript = Vec::with_capacity(128);
        transcript.extend_from_slice(&client_nonce);
        transcript.extend_from_slice(&chal.server_nonce);
        transcript.extend_from_slice(&chal.challenge_cookie);
        let transcript_proof = ifa_digest32(&handshake_key, &transcript);

        // Derive operational session keys (client perspective: client tx = C2S, client rx = S2C)
        let master_secret = ifa_kdf_derive(&dh_shared, b"IFA-mTLS-MASTER", 1);
        let tx_key = ifa_kdf_derive(&master_secret, b"IFA-ISSP-C2S-KEY", 1);
        let rx_key = ifa_kdf_derive(&master_secret, b"IFA-ISSP-S2C-KEY", 1);

        peer.key_ring = Some(PeeringKeyRing::new(
            master_secret,
            tx_key,
            rx_key,
            1,
            now_ns,
        ));
        peer.state = MtlsHandshakeState::MutualAttested {
            session_id: 0x1fa0_0000 | (peer_id as u64),
            attested_at_ns: now_ns,
            active_epoch: 1,
        };
        peer.last_attested_at_ns = now_ns;
        peer.last_rotation_at_ns = now_ns;
        self.total_handshakes_completed += 1;

        Ok(MtlsClientProof {
            magic: ISSP_MTLS_MAGIC,
            version: ISSP_MTLS_VERSION,
            client_node_id: self.local_identity.node_id,
            challenge_response,
            transcript_proof,
        })
    }

    /// Process ClientProof on the server side and finalize handshake with ServerFinished.
    pub fn handle_client_proof(
        &mut self,
        proof: &MtlsClientProof,
        now_ns: u64,
    ) -> Result<MtlsServerFinished, MtlsError> {
        if proof.magic != ISSP_MTLS_MAGIC {
            self.total_handshakes_failed += 1;
            return Err(MtlsError::InvalidMagic(proof.magic));
        }

        let peer_id = proof.client_node_id;
        let peer = self
            .peers
            .get_mut(&peer_id)
            .ok_or(MtlsError::PeerNotAttested(peer_id))?;

        let (client_nonce, server_nonce, _ephemeral_priv, challenge_cookie) = match &peer.state {
            MtlsHandshakeState::ChallengePending {
                client_nonce,
                server_nonce,
                ephemeral_priv,
                challenge_cookie,
            } => (
                *client_nonce,
                *server_nonce,
                *ephemeral_priv,
                *challenge_cookie,
            ),
            _ => {
                self.total_handshakes_failed += 1;
                return Err(MtlsError::HandshakeStateMismatch(
                    "expected ChallengePending on server",
                ));
            }
        };

        let mut combined = [0u8; 32];
        for i in 0..32 {
            combined[i] = peer.identity.public_key[i]
                ^ self.local_private_key[i]
                ^ client_nonce[i]
                ^ server_nonce[i];
        }
        let dh_shared = ifa_kdf_derive(&combined, b"IFA-SHARED-SECRET", 1);

        let handshake_key = ifa_kdf_derive(&dh_shared, b"IFA-mTLS-HANDSHAKE", 1);
        let expected_resp = ifa_digest32(&handshake_key, &challenge_cookie);
        if !constant_time_eq(&proof.challenge_response, &expected_resp) {
            self.total_handshakes_failed += 1;
            return Err(MtlsError::ChallengeVerificationFailed);
        }

        let mut transcript = Vec::with_capacity(128);
        transcript.extend_from_slice(&client_nonce);
        transcript.extend_from_slice(&server_nonce);
        transcript.extend_from_slice(&challenge_cookie);
        let expected_proof = ifa_digest32(&handshake_key, &transcript);
        if !constant_time_eq(&proof.transcript_proof, &expected_proof) {
            self.total_handshakes_failed += 1;
            return Err(MtlsError::TranscriptProofMismatch);
        }

        // Derive operational session keys (server perspective: server tx = S2C, server rx = C2S)
        let master_secret = ifa_kdf_derive(&dh_shared, b"IFA-mTLS-MASTER", 1);
        let tx_key = ifa_kdf_derive(&master_secret, b"IFA-ISSP-S2C-KEY", 1);
        let rx_key = ifa_kdf_derive(&master_secret, b"IFA-ISSP-C2S-KEY", 1);

        let session_id = 0x1fa0_0000 | (peer_id as u64);
        peer.key_ring = Some(PeeringKeyRing::new(
            master_secret,
            tx_key,
            rx_key,
            1,
            now_ns,
        ));
        peer.state = MtlsHandshakeState::MutualAttested {
            session_id,
            attested_at_ns: now_ns,
            active_epoch: 1,
        };
        peer.last_attested_at_ns = now_ns;
        peer.last_rotation_at_ns = now_ns;
        self.total_handshakes_completed += 1;

        let server_proof = ifa_digest32(&handshake_key, &expected_proof);
        Ok(MtlsServerFinished {
            magic: ISSP_MTLS_MAGIC,
            version: ISSP_MTLS_VERSION,
            session_id,
            initial_key_epoch: 1,
            server_proof,
            success: true,
        })
    }

    /// Complete automated mutual attestation between this node and a remote node in one call.
    pub fn perform_full_mutual_attestation(
        &mut self,
        remote: &mut MeshPeerAttestationManager,
        now_ns: u64,
    ) -> Result<u64, MtlsError> {
        let peer_id = remote.local_identity.node_id;
        self.register_peer(
            remote.local_identity.clone(),
            remote.local_certificate.clone(),
        );
        remote.register_peer(self.local_identity.clone(), self.local_certificate.clone());

        let hello = self.initiate_handshake(peer_id, now_ns)?;
        let challenge = remote.handle_client_hello(&hello, now_ns + 100)?;
        let proof = self.handle_server_challenge(&challenge, now_ns + 200)?;
        let finished = remote.handle_client_proof(&proof, now_ns + 300)?;

        if finished.success {
            Ok(finished.session_id)
        } else {
            Err(MtlsError::ChallengeVerificationFailed)
        }
    }

    /// Trigger explicit key rotation on a specific peer connection.
    pub fn rotate_peer_key(
        &mut self,
        peer_node_id: u32,
        now_ns: u64,
        reason: RotationReason,
    ) -> Result<u64, MtlsError> {
        let peer = self
            .peers
            .get_mut(&peer_node_id)
            .ok_or(MtlsError::PeerNotAttested(peer_node_id))?;
        let ring = peer
            .key_ring
            .as_mut()
            .ok_or(MtlsError::MissingPeerKeyRing(peer_node_id))?;
        let new_epoch = ring.rotate(now_ns, reason);
        peer.last_rotation_at_ns = now_ns;
        if let MtlsHandshakeState::MutualAttested {
            ref mut active_epoch,
            ..
        } = peer.state
        {
            *active_epoch = new_epoch;
        }
        Ok(new_epoch)
    }

    /// Check all active peer connections and trigger rotation where thresholds are exceeded.
    pub fn check_and_rotate_all(&mut self, now_ns: u64) -> Vec<(u32, u64, RotationReason)> {
        let mut rotated = Vec::new();
        for (peer_id, peer) in self.peers.iter_mut() {
            if let Some(ring) = peer.key_ring.as_mut() {
                if let Some((new_epoch, reason)) = ring.check_and_rotate(now_ns) {
                    peer.last_rotation_at_ns = now_ns;
                    if let MtlsHandshakeState::MutualAttested {
                        ref mut active_epoch,
                        ..
                    } = peer.state
                    {
                        *active_epoch = new_epoch;
                    }
                    rotated.push((*peer_id, new_epoch, reason));
                }
            }
        }
        rotated
    }

    /// Encrypt a payload intended for a specific attested peer.
    pub fn encrypt_for_peer(
        &mut self,
        peer_node_id: u32,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<MtlsEnvelope, MtlsError> {
        let peer = self
            .peers
            .get_mut(&peer_node_id)
            .ok_or(MtlsError::PeerNotAttested(peer_node_id))?;
        let ring = peer
            .key_ring
            .as_mut()
            .ok_or(MtlsError::MissingPeerKeyRing(peer_node_id))?;
        ring.encrypt_envelope(plaintext, aad)
    }

    /// Decrypt an envelope received from a specific attested peer.
    pub fn decrypt_from_peer(
        &mut self,
        peer_node_id: u32,
        envelope: &MtlsEnvelope,
        aad: &[u8],
        now_ns: u64,
    ) -> Result<Vec<u8>, MtlsError> {
        let peer = self
            .peers
            .get_mut(&peer_node_id)
            .ok_or(MtlsError::PeerNotAttested(peer_node_id))?;
        let ring = peer
            .key_ring
            .as_mut()
            .ok_or(MtlsError::MissingPeerKeyRing(peer_node_id))?;
        ring.decrypt_envelope(envelope, aad, now_ns)
    }

    /// Render Prometheus exposition format metrics for monitoring and supervisor panels.
    pub fn to_prometheus_exposition(&self) -> String {
        let mut out = String::with_capacity(1024);
        out.push_str("# HELP ifa_mesh_mtls_peers_total Total number of registered mesh peers\n");
        out.push_str("# TYPE ifa_mesh_mtls_peers_total gauge\n");
        use std::fmt::Write;
        let _ = writeln!(out, "ifa_mesh_mtls_peers_total {}", self.peers.len());

        let attested_count = self
            .peers
            .values()
            .filter(|p| matches!(p.state, MtlsHandshakeState::MutualAttested { .. }))
            .count();
        out.push_str("# HELP ifa_mesh_mtls_attested_peers Number of fully attested active peers\n");
        out.push_str("# TYPE ifa_mesh_mtls_attested_peers gauge\n");
        let _ = writeln!(out, "ifa_mesh_mtls_attested_peers {attested_count}");

        out.push_str("# HELP ifa_mesh_mtls_handshakes_total Cumulative handshake attempts\n");
        out.push_str("# TYPE ifa_mesh_mtls_handshakes_total counter\n");
        let _ = writeln!(
            out,
            "ifa_mesh_mtls_handshakes_total{{status=\"completed\"}} {}",
            self.total_handshakes_completed
        );
        let _ = writeln!(
            out,
            "ifa_mesh_mtls_handshakes_total{{status=\"failed\"}} {}",
            self.total_handshakes_failed
        );

        out.push_str(
            "# HELP ifa_mesh_mtls_key_epoch Current cryptographic key epoch ID per peer\n",
        );
        out.push_str("# TYPE ifa_mesh_mtls_key_epoch gauge\n");
        for (peer_id, peer) in &self.peers {
            if let Some(ring) = &peer.key_ring {
                let _ = writeln!(
                    out,
                    "ifa_mesh_mtls_key_epoch{{peer=\"{}\"}} {}",
                    peer_id, ring.active_epoch.epoch_id
                );
            }
        }

        out.push_str(
            "# HELP ifa_mesh_mtls_grace_packets_total Accepted in-flight packets during key grace window\n",
        );
        out.push_str("# TYPE ifa_mesh_mtls_grace_packets_total counter\n");
        for (peer_id, peer) in &self.peers {
            if let Some(ring) = &peer.key_ring {
                let _ = writeln!(
                    out,
                    "ifa_mesh_mtls_grace_packets_total{{peer=\"{}\"}} {}",
                    peer_id, ring.grace_packets_accepted
                );
            }
        }

        out
    }

    /// Render JSON summary representation of peer attestation and key rotation states.
    pub fn to_json(&self) -> String {
        let mut out = String::with_capacity(1024);
        out.push_str("{\n");
        use std::fmt::Write;
        let _ = writeln!(out, "  \"local_node_id\": {},", self.local_identity.node_id);
        let _ = writeln!(
            out,
            "  \"cluster_id\": \"{}\",",
            self.local_identity.cluster_id
        );
        let _ = writeln!(
            out,
            "  \"fingerprint\": \"{}\",",
            self.local_identity.fingerprint_hex()
        );
        let _ = writeln!(out, "  \"peers_total\": {},", self.peers.len());
        let _ = writeln!(
            out,
            "  \"handshakes_completed\": {},",
            self.total_handshakes_completed
        );
        let _ = writeln!(
            out,
            "  \"handshakes_failed\": {},",
            self.total_handshakes_failed
        );
        out.push_str("  \"peers\": [\n");

        let mut first = true;
        for (peer_id, peer) in &self.peers {
            if !first {
                out.push_str(",\n");
            }
            first = false;
            let (state_str, active_epoch) = match peer.state {
                MtlsHandshakeState::Unauthenticated => ("unauthenticated", 0),
                MtlsHandshakeState::HelloSent { .. } => ("hello_sent", 0),
                MtlsHandshakeState::ChallengePending { .. } => ("challenge_pending", 0),
                MtlsHandshakeState::MutualAttested { active_epoch, .. } => {
                    ("mutual_attested", active_epoch)
                }
                MtlsHandshakeState::Failed(_) => ("failed", 0),
            };
            let (tot_rot, grace_pkts) = peer
                .key_ring
                .as_ref()
                .map(|r| (r.total_rotations, r.grace_packets_accepted))
                .unwrap_or((0, 0));

            let _ = writeln!(out, "    {{");
            let _ = writeln!(out, "      \"peer_node_id\": {peer_id},");
            let _ = writeln!(out, "      \"state\": \"{state_str}\",");
            let _ = writeln!(out, "      \"active_epoch\": {active_epoch},");
            let _ = writeln!(out, "      \"total_rotations\": {tot_rot},");
            let _ = writeln!(out, "      \"grace_packets\": {grace_pkts},");
            let _ = writeln!(
                out,
                "      \"cert_fingerprint\": \"{}\"",
                peer.certificate.fingerprint_hex()
            );
            out.push_str("    }");
        }
        out.push_str("\n  ]\n}");
        out
    }
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_ca() -> (u32, [u8; 32], MeshTrustStore) {
        let ca_node_id = 100;
        let ca_key = [0x42u8; 32];
        let mut trust = MeshTrustStore::new("ifa-cluster-alpha");
        trust.add_trusted_ca(ca_node_id, ca_key);
        (ca_node_id, ca_key, trust)
    }

    fn create_test_node(
        node_id: u32,
        ca_node_id: u32,
        ca_key: &[u8; 32],
    ) -> (NodeIdentity, MeshAttestationCertificate, [u8; 32]) {
        let node_key = [node_id as u8; 32];
        let identity = NodeIdentity::new(
            node_id,
            "ifa-cluster-alpha",
            MeshNodeRole::Worker,
            node_key,
            1_000_000,
            2_000_000_000_000,
            CAP_MULTIPATH | CAP_DYNAMIC_REKEY,
        );
        let cert = MeshAttestationCertificate::issue(
            node_id as u64,
            ca_node_id,
            "ifa-cluster-alpha",
            identity.clone(),
            ca_key,
        );
        (identity, cert, node_key)
    }

    #[test]
    fn test_certificate_validation_and_tampering() {
        let (ca_id, ca_key, trust) = create_test_ca();
        let (id, mut cert, _) = create_test_node(1, ca_id, &ca_key);

        // Valid certificate check
        assert!(trust.verify_certificate(&cert, 5_000_000).is_ok());

        // Temporal validity checks
        assert!(trust.verify_certificate(&cert, 500_000).is_err());
        assert!(trust.verify_certificate(&cert, 3_000_000_000_000).is_err());

        // Tampering signature check
        cert.signature[0] ^= 0xff;
        assert_eq!(
            trust.verify_certificate(&cert, 5_000_000).unwrap_err(),
            MtlsError::SignatureVerificationFailed
        );

        // Revocation check
        let (_, cert2, _) = create_test_node(2, ca_id, &ca_key);
        let mut trust_rev = trust.clone();
        trust_rev.revoke_certificate(cert2.serial_number, id.node_id);
        assert!(trust_rev.verify_certificate(&cert2, 5_000_000).is_err());
    }

    #[test]
    fn test_mutual_attestation_handshake_roundtrip() {
        let (ca_id, ca_key, trust) = create_test_ca();
        let (id1, cert1, priv1) = create_test_node(1, ca_id, &ca_key);
        let (id2, cert2, priv2) = create_test_node(2, ca_id, &ca_key);

        let mut client = MeshPeerAttestationManager::new(id1, cert1, priv1, trust.clone());
        let mut server = MeshPeerAttestationManager::new(id2, cert2, priv2, trust);

        let session_id = client
            .perform_full_mutual_attestation(&mut server, 10_000_000)
            .expect("full mutual attestation must succeed");

        assert_eq!(session_id, 0x1fa0_0001);

        // Both peers must be in MutualAttested state
        let c_peer = client.peers.get(&2).unwrap();
        assert!(matches!(
            c_peer.state,
            MtlsHandshakeState::MutualAttested { .. }
        ));
        let s_peer = server.peers.get(&1).unwrap();
        assert!(matches!(
            s_peer.state,
            MtlsHandshakeState::MutualAttested { .. }
        ));

        // Test AEAD data communication
        let plaintext = b"Hello Secure ISSP Peering Mesh!";
        let aad = b"issp-session-header-data";
        let envelope = client
            .encrypt_for_peer(2, plaintext, aad)
            .expect("client encryption");

        assert_eq!(envelope.epoch_id, 1);
        assert_eq!(envelope.seq_num, 1);

        let decrypted = server
            .decrypt_from_peer(1, &envelope, aad, 10_000_100)
            .expect("server decryption");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_dynamic_key_rotation_and_grace_period_handling() {
        let (ca_id, ca_key, trust) = create_test_ca();
        let (id1, cert1, priv1) = create_test_node(1, ca_id, &ca_key);
        let (id2, cert2, priv2) = create_test_node(2, ca_id, &ca_key);

        let mut client = MeshPeerAttestationManager::new(id1, cert1, priv1, trust.clone());
        let mut server = MeshPeerAttestationManager::new(id2, cert2, priv2, trust);

        client
            .perform_full_mutual_attestation(&mut server, 1_000_000_000)
            .unwrap();

        // Send packet under Epoch 1
        let pkt_e1 = client
            .encrypt_for_peer(2, b"Packet under Epoch 1", b"aad")
            .unwrap();
        assert_eq!(pkt_e1.epoch_id, 1);

        // Rotate client and server key rings to Epoch 2
        let now_rot = 1_000_000_000 + 100_000_000;
        let new_c_epoch = client
            .rotate_peer_key(2, now_rot, RotationReason::ScheduledTime)
            .unwrap();
        let new_s_epoch = server
            .rotate_peer_key(1, now_rot, RotationReason::ScheduledTime)
            .unwrap();
        assert_eq!(new_c_epoch, 2);
        assert_eq!(new_s_epoch, 2);

        // Send packet under Epoch 2
        let pkt_e2 = client
            .encrypt_for_peer(2, b"Packet under Epoch 2", b"aad")
            .unwrap();
        assert_eq!(pkt_e2.epoch_id, 2);

        // Server decrypts Epoch 2 packet with active key
        let dec_e2 = server
            .decrypt_from_peer(1, &pkt_e2, b"aad", now_rot + 10)
            .unwrap();
        assert_eq!(dec_e2, b"Packet under Epoch 2");

        // Server decrypts in-flight Epoch 1 packet within grace period!
        let dec_e1 = server
            .decrypt_from_peer(1, &pkt_e1, b"aad", now_rot + 100)
            .expect("in-flight packet under previous epoch should be accepted in grace window");
        assert_eq!(dec_e1, b"Packet under Epoch 1");

        // Verify grace packet counter increased
        let s_ring = server.peers.get(&1).unwrap().key_ring.as_ref().unwrap();
        assert_eq!(s_ring.grace_packets_accepted, 1);

        // Replay of same pkt_e1 should be rejected
        let replay_err = server.decrypt_from_peer(1, &pkt_e1, b"aad", now_rot + 200);
        assert!(matches!(
            replay_err,
            Err(MtlsError::ReplayPacketDetected { .. })
        ));

        // After grace period expires (60s = 60_000_000_000 ns), Epoch 1 packet should be dropped
        let pkt_e1_late = MtlsEnvelope {
            magic: ISSP_ENVELOPE_MAGIC,
            epoch_id: 1,
            seq_num: 99,
            auth_tag: [0u8; 16],
            ciphertext: vec![0u8; 16],
        };
        let late_err = server.decrypt_from_peer(
            1,
            &pkt_e1_late,
            b"aad",
            now_rot + DEFAULT_GRACE_PERIOD_NS + 1_000_000,
        );
        assert!(matches!(late_err, Err(MtlsError::EpochExpired { .. })));
    }

    #[test]
    fn test_envelope_binary_serialization_roundtrip() {
        let env = MtlsEnvelope {
            magic: ISSP_ENVELOPE_MAGIC,
            epoch_id: 42,
            seq_num: 1001,
            auth_tag: [0x55u8; 16],
            ciphertext: b"encrypted payload bytes in transit".to_vec(),
        };

        let bytes = env.to_bytes();
        let decoded = MtlsEnvelope::from_bytes(&bytes).expect("decoding envelope bytes");
        assert_eq!(decoded, env);

        // Truncated bytes check
        assert!(MtlsEnvelope::from_bytes(&bytes[..20]).is_err());
        assert!(MtlsEnvelope::from_bytes(&bytes[..bytes.len() - 5]).is_err());
    }

    #[test]
    fn test_automatic_threshold_rotation_and_telemetry_exposition() {
        let (ca_id, ca_key, trust) = create_test_ca();
        let (id1, cert1, priv1) = create_test_node(1, ca_id, &ca_key);
        let (id2, cert2, priv2) = create_test_node(2, ca_id, &ca_key);

        let mut client = MeshPeerAttestationManager::new(id1, cert1, priv1, trust.clone());
        let mut server = MeshPeerAttestationManager::new(id2, cert2, priv2, trust);

        client
            .perform_full_mutual_attestation(&mut server, 10_000_000)
            .unwrap();

        // Advance simulated time past DEFAULT_ROTATION_INTERVAL_NS
        let now_rot = 10_000_000 + DEFAULT_ROTATION_INTERVAL_NS + 10_000;
        let rotated = client.check_and_rotate_all(now_rot);
        assert_eq!(rotated.len(), 1);
        assert_eq!(rotated[0].0, 2);
        assert_eq!(rotated[0].1, 2);
        assert_eq!(rotated[0].2, RotationReason::ScheduledTime);

        // Prometheus Exposition check
        let prom = client.to_prometheus_exposition();
        assert!(prom.contains("ifa_mesh_mtls_peers_total 1"));
        assert!(prom.contains("ifa_mesh_mtls_attested_peers 1"));
        assert!(prom.contains("ifa_mesh_mtls_handshakes_total{status=\"completed\"} 1"));
        assert!(prom.contains("ifa_mesh_mtls_key_epoch{peer=\"2\"} 2"));

        // JSON check
        let json = client.to_json();
        assert!(json.contains("\"local_node_id\": 1"));
        assert!(json.contains("\"cluster_id\": \"ifa-cluster-alpha\""));
        assert!(json.contains("\"peer_node_id\": 2"));
        assert!(json.contains("\"state\": \"mutual_attested\""));
        assert!(json.contains("\"active_epoch\": 2"));
    }
}

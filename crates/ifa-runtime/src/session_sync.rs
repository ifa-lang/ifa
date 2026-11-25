//! Multi-node session state synchronization and transparent datagram stream migration.
//!
//! This module implements the **IFA Session Synchronization Protocol (ISSP)** for
//! distributed MASQUE gateway clusters. It provides:
//!
//! - **Session State Snapshot** — serializable, opaque, versioned snapshot of a live
//!   datagram tunnel session (flow hash, sequence counters, AQM state, FEC context, key
//!   epoch, rate-limiter token bucket).
//! - **Gossip-based State Distribution** — lightweight CRC32-guarded gossip messages
//!   exchanged over a dedicated control UDP channel to replicate snapshots to peer nodes.
//! - **Transparent Migration** — when a primary node becomes unreachable, any peer
//!   holding a fresh enough snapshot can resume the session without renegotiation,
//!   providing continuity of sequence counters and crypto epoch to the remote endpoint.
//! - **Fencing & Epoch Guard** — a monotonic `migration_epoch` counter prevents split-brain
//!   double-serving of the same session on two nodes simultaneously.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum age of a session snapshot before it is considered stale for migration.
pub const SNAPSHOT_MAX_AGE: Duration = Duration::from_secs(5);

/// Maximum number of peer nodes tracked per local node.
pub const MAX_PEER_NODES: usize = 32;

/// Maximum number of live sessions per node.
pub const MAX_SESSIONS: usize = 1024;

/// Gossip message magic tag for ISSP frames.
pub const ISSP_MAGIC: u32 = 0x4953_5350; // 'ISSP'

/// ISSP gossip wire protocol version 1 (unencrypted with CRC32).
pub const ISSP_VERSION_V1: u32 = 1;

/// ISSP gossip wire protocol version 2 (ChaCha20-Poly1305 AEAD encrypted with PSK).
pub const ISSP_VERSION_V2_ENCRYPTED: u32 = 2;

/// Wire size of a serialised plaintext `GossipFrame` (v1) in bytes.
pub const GOSSIP_FRAME_SIZE: usize = 112;

/// Wire size of a serialised encrypted `SecureGossipFrame` (v2) in bytes.
pub const SECURE_GOSSIP_FRAME_SIZE: usize = 136;

// ---------------------------------------------------------------------------
// Session identifier
// ---------------------------------------------------------------------------

/// Globally unique identifier for a tunnel session, derived from the 5-tuple
/// flow hash and the originating node ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId {
    /// 64-bit flow hash (src_ip XOR dst_ip XOR ports XOR proto).
    pub flow_hash: u64,
    /// Node that originally created this session.
    pub origin_node: u32,
    /// Session creation nonce (randomised to prevent collisions on hash).
    pub nonce: u32,
}

impl SessionId {
    /// Construct a new session ID.
    pub fn new(flow_hash: u64, origin_node: u32, nonce: u32) -> Self {
        Self {
            flow_hash,
            origin_node,
            nonce,
        }
    }

    /// Encode as a compact 16-byte array for wire transmission.
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&self.flow_hash.to_be_bytes());
        b[8..12].copy_from_slice(&self.origin_node.to_be_bytes());
        b[12..16].copy_from_slice(&self.nonce.to_be_bytes());
        b
    }

    /// Decode from a compact 16-byte array.
    pub fn from_bytes(b: &[u8; 16]) -> Self {
        let flow_hash = u64::from_be_bytes(b[..8].try_into().unwrap());
        let origin_node = u32::from_be_bytes(b[8..12].try_into().unwrap());
        let nonce = u32::from_be_bytes(b[12..16].try_into().unwrap());
        Self {
            flow_hash,
            origin_node,
            nonce,
        }
    }
}

// ---------------------------------------------------------------------------
// Session State Snapshot
// ---------------------------------------------------------------------------

/// Datagram-stream state captured at a point in time for replication or migration.
///
/// All fields are `Copy` / primitive so the snapshot can be serialised cheaply
/// without heap allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionSnapshot {
    /// Session identifier.
    pub id: SessionId,

    /// Monotonic migration epoch.  Incremented by one each time ownership of
    /// this session is transferred.  A receiving node MUST reject any snapshot
    /// with `migration_epoch` ≤ its locally recorded epoch for this session.
    pub migration_epoch: u64,

    // --- Sequence / ordering state ---
    /// Highest sequence number sent by the local side.
    pub tx_seq: u64,
    /// Highest contiguous sequence number received (for reorder buffer).
    pub rx_seq_high: u64,
    /// Reorder window bitmap (64 slots).  Bit i is set if seq rx_seq_high - i
    /// was already received.
    pub reorder_bitmap: u64,

    // --- Rate-limiter token bucket state ---
    /// Current token count (scaled ×1000 to avoid float).
    pub token_bucket_scaled: u64,
    /// Configured token refill rate in tokens/ms (scaled ×1000).
    pub token_rate_scaled: u64,

    // --- AQM / CoDel sojourn state ---
    /// CoDel target sojourn (nanoseconds).
    pub codel_target_ns: u64,
    /// CoDel interval (nanoseconds).
    pub codel_interval_ns: u64,
    /// Number of consecutive CoDel drop intervals.
    pub codel_drop_count: u32,

    // --- FEC context ---
    /// Current FEC block index.
    pub fec_block_idx: u32,
    /// Number of source packets in the current FEC block.
    pub fec_src_count: u8,
    /// Number of repair packets already emitted in the current FEC block.
    pub fec_repair_count: u8,

    // --- Crypto epoch ---
    /// Current key epoch identifier (matches HPKE/PQC key rotation counter).
    pub crypto_epoch: u32,

    // --- Timestamp ---
    /// Wall-clock snapshot capture time as Unix seconds (for staleness check).
    pub captured_unix_secs: u64,
}

impl SessionSnapshot {
    /// Create a zeroed snapshot for a new session.
    pub fn new(id: SessionId, crypto_epoch: u32, captured_unix_secs: u64) -> Self {
        Self {
            id,
            migration_epoch: 0,
            tx_seq: 0,
            rx_seq_high: 0,
            reorder_bitmap: 0,
            token_bucket_scaled: 1_000_000,
            token_rate_scaled: 10_000,
            codel_target_ns: 5_000_000,
            codel_interval_ns: 100_000_000,
            codel_drop_count: 0,
            fec_block_idx: 0,
            fec_src_count: 0,
            fec_repair_count: 0,
            crypto_epoch,
            captured_unix_secs,
        }
    }

    /// Serialise into a 96-byte wire buffer (little-endian).
    pub fn to_wire(&self) -> [u8; 96] {
        let mut buf = [0u8; 96];
        let id_b = self.id.to_bytes();
        buf[0..16].copy_from_slice(&id_b);
        buf[16..24].copy_from_slice(&self.migration_epoch.to_le_bytes());
        buf[24..32].copy_from_slice(&self.tx_seq.to_le_bytes());
        buf[32..40].copy_from_slice(&self.rx_seq_high.to_le_bytes());
        buf[40..48].copy_from_slice(&self.reorder_bitmap.to_le_bytes());
        buf[48..56].copy_from_slice(&self.token_bucket_scaled.to_le_bytes());
        buf[56..64].copy_from_slice(&self.token_rate_scaled.to_le_bytes());
        buf[64..72].copy_from_slice(&self.codel_target_ns.to_le_bytes());
        buf[72..80].copy_from_slice(&self.codel_interval_ns.to_le_bytes());
        let mut misc = [0u8; 16];
        misc[0..4].copy_from_slice(&self.codel_drop_count.to_le_bytes());
        misc[4..8].copy_from_slice(&self.fec_block_idx.to_le_bytes());
        misc[8] = self.fec_src_count;
        misc[9] = self.fec_repair_count;
        misc[10..14].copy_from_slice(&self.crypto_epoch.to_le_bytes());
        buf[80..96].copy_from_slice(&misc);
        buf
    }

    /// Deserialise from a 96-byte wire buffer.
    pub fn from_wire(buf: &[u8; 96]) -> Self {
        let id = SessionId::from_bytes(buf[0..16].try_into().unwrap());
        let migration_epoch = u64::from_le_bytes(buf[16..24].try_into().unwrap());
        let tx_seq = u64::from_le_bytes(buf[24..32].try_into().unwrap());
        let rx_seq_high = u64::from_le_bytes(buf[32..40].try_into().unwrap());
        let reorder_bitmap = u64::from_le_bytes(buf[40..48].try_into().unwrap());
        let token_bucket_scaled = u64::from_le_bytes(buf[48..56].try_into().unwrap());
        let token_rate_scaled = u64::from_le_bytes(buf[56..64].try_into().unwrap());
        let codel_target_ns = u64::from_le_bytes(buf[64..72].try_into().unwrap());
        let codel_interval_ns = u64::from_le_bytes(buf[72..80].try_into().unwrap());
        let misc = &buf[80..96];
        let codel_drop_count = u32::from_le_bytes(misc[0..4].try_into().unwrap());
        let fec_block_idx = u32::from_le_bytes(misc[4..8].try_into().unwrap());
        let fec_src_count = misc[8];
        let fec_repair_count = misc[9];
        let crypto_epoch = u32::from_le_bytes(misc[10..14].try_into().unwrap());
        Self {
            id,
            migration_epoch,
            tx_seq,
            rx_seq_high,
            reorder_bitmap,
            token_bucket_scaled,
            token_rate_scaled,
            codel_target_ns,
            codel_interval_ns,
            codel_drop_count,
            fec_block_idx,
            fec_src_count,
            fec_repair_count,
            crypto_epoch,
            captured_unix_secs: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Gossip wire frame
// ---------------------------------------------------------------------------

/// ISSP gossip frame transmitted between nodes over the control UDP channel.
///
/// Wire layout (total = **112 bytes**):
/// ```text
///  0-  3  magic   = ISSP_MAGIC (0x49535350)
///  4-  7  version = 1
///  8- 11  sender_node_id
/// 12- 15  crc32   (computed over snapshot bytes at [16..112])
/// 16-111  snapshot (96 bytes)
/// ```
#[derive(Debug, Clone, Copy)]
pub struct GossipFrame {
    pub sender_node_id: u32,
    pub snapshot: SessionSnapshot,
}

impl GossipFrame {
    /// Encode to a 112-byte wire buffer with CRC32 integrity protection.
    pub fn encode(&self) -> [u8; GOSSIP_FRAME_SIZE] {
        let mut buf = [0u8; GOSSIP_FRAME_SIZE];
        buf[0..4].copy_from_slice(&ISSP_MAGIC.to_be_bytes());
        buf[4..8].copy_from_slice(&1u32.to_le_bytes()); // version = 1
        buf[8..12].copy_from_slice(&self.sender_node_id.to_le_bytes());
        // reserve [12..16] for CRC32 — computed after snapshot is written
        let snap = self.snapshot.to_wire();
        buf[16..112].copy_from_slice(&snap);
        let crc = crc32_ieee(&buf[16..112]);
        buf[12..16].copy_from_slice(&crc.to_le_bytes());
        buf
    }

    /// Decode and validate a 112-byte wire buffer.  Returns `None` on magic or
    /// CRC32 mismatch.
    pub fn decode(raw: &[u8; GOSSIP_FRAME_SIZE]) -> Option<Self> {
        let magic = u32::from_be_bytes(raw[0..4].try_into().unwrap());
        if magic != ISSP_MAGIC {
            return None;
        }
        let stored_crc = u32::from_le_bytes(raw[12..16].try_into().unwrap());
        let computed_crc = crc32_ieee(&raw[16..112]);
        if stored_crc != computed_crc {
            return None;
        }
        let sender_node_id = u32::from_le_bytes(raw[8..12].try_into().unwrap());
        let snap_buf: &[u8; 96] = raw[16..112].try_into().unwrap();
        let snapshot = SessionSnapshot::from_wire(snap_buf);
        Some(Self {
            sender_node_id,
            snapshot,
        })
    }
}

/// Software CRC32 (IEEE polynomial) without external dependency.
fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        let idx = ((crc ^ (byte as u32)) & 0xFF) as usize;
        crc = CRC32_TABLE[idx] ^ (crc >> 8);
    }
    !crc
}

/// Pre-computed CRC32/IEEE look-up table.
static CRC32_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            if c & 1 != 0 {
                c = 0xEDB8_8320 ^ (c >> 1);
            } else {
                c >>= 1;
            }
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
};

// ---------------------------------------------------------------------------
// RFC 8439 Deterministic Zero-GC ChaCha20-Poly1305 Engine
// ---------------------------------------------------------------------------

#[inline(always)]
fn chacha20_quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut state = [
        0x61707865,
        0x3320646e,
        0x79622d32,
        0x6b206574,
        u32::from_le_bytes(key[0..4].try_into().unwrap()),
        u32::from_le_bytes(key[4..8].try_into().unwrap()),
        u32::from_le_bytes(key[8..12].try_into().unwrap()),
        u32::from_le_bytes(key[12..16].try_into().unwrap()),
        u32::from_le_bytes(key[16..20].try_into().unwrap()),
        u32::from_le_bytes(key[20..24].try_into().unwrap()),
        u32::from_le_bytes(key[24..28].try_into().unwrap()),
        u32::from_le_bytes(key[28..32].try_into().unwrap()),
        counter,
        u32::from_le_bytes(nonce[0..4].try_into().unwrap()),
        u32::from_le_bytes(nonce[4..8].try_into().unwrap()),
        u32::from_le_bytes(nonce[8..12].try_into().unwrap()),
    ];

    let initial = state;

    for _ in 0..10 {
        chacha20_quarter_round(&mut state, 0, 4, 8, 12);
        chacha20_quarter_round(&mut state, 1, 5, 9, 13);
        chacha20_quarter_round(&mut state, 2, 6, 10, 14);
        chacha20_quarter_round(&mut state, 3, 7, 11, 15);

        chacha20_quarter_round(&mut state, 0, 5, 10, 15);
        chacha20_quarter_round(&mut state, 1, 6, 11, 12);
        chacha20_quarter_round(&mut state, 2, 7, 8, 13);
        chacha20_quarter_round(&mut state, 3, 4, 9, 14);
    }

    let mut out = [0u8; 64];
    for i in 0..16 {
        let val = state[i].wrapping_add(initial[i]);
        out[i * 4..(i + 1) * 4].copy_from_slice(&val.to_le_bytes());
    }
    out
}

fn chacha20_xor_slice(key: &[u8; 32], nonce: &[u8; 12], counter: u32, data: &mut [u8]) {
    let mut curr_counter = counter;
    for chunk in data.chunks_mut(64) {
        let block = chacha20_block(key, curr_counter, nonce);
        for (b, k) in chunk.iter_mut().zip(block.iter()) {
            *b ^= *k;
        }
        curr_counter = curr_counter.wrapping_add(1);
    }
}

struct Poly1305Accumulator {
    r0: u64,
    r1: u64,
    s0: u64,
    s1: u64,
    h0: u128,
    h1: u128,
    h2: u128,
}

impl Poly1305Accumulator {
    fn new(key: &[u8; 32]) -> Self {
        let r0 = u64::from_le_bytes(key[0..8].try_into().unwrap()) & 0x0ffffffc0fffffff;
        let r1 = u64::from_le_bytes(key[8..16].try_into().unwrap()) & 0x0ffffffc0ffffffc;
        let s0 = u64::from_le_bytes(key[16..24].try_into().unwrap());
        let s1 = u64::from_le_bytes(key[24..32].try_into().unwrap());
        Self {
            r0,
            r1,
            s0,
            s1,
            h0: 0,
            h1: 0,
            h2: 0,
        }
    }

    fn update_chunk(&mut self, chunk: &[u8]) {
        let mut block = [0u8; 17];
        block[..chunk.len()].copy_from_slice(chunk);
        block[chunk.len()] = 0x01;

        let n0 = u128::from_le_bytes(block[0..16].try_into().unwrap());
        let n1 = block[16] as u128;

        self.h0 += n0 & 0xffffffffffffffff;
        self.h1 += n0 >> 64;
        self.h2 += n1;

        let d0 = self.h0 * (self.r0 as u128);
        let d1 = self.h0 * (self.r1 as u128) + self.h1 * (self.r0 as u128);
        let d2 = self.h1 * (self.r1 as u128) + self.h2 * (self.r0 as u128) * 5;
        let d3 = self.h2 * (self.r1 as u128) * 5;

        let mut c = d0;
        self.h0 = c & 0xffffffffffffffff;
        c = (c >> 64) + d1;
        self.h1 = c & 0xffffffffffffffff;
        c = (c >> 64) + d2;
        self.h2 = c & 0x03;
        let carry = (c >> 2) + d3;
        let c_mod = carry * 5;
        self.h0 += c_mod;
        if self.h0 > 0xffffffffffffffff {
            let carry_h0 = self.h0 >> 64;
            self.h0 &= 0xffffffffffffffff;
            self.h1 += carry_h0;
            if self.h1 > 0xffffffffffffffff {
                self.h2 += self.h1 >> 64;
                self.h1 &= 0xffffffffffffffff;
            }
        }
    }

    fn update(&mut self, data: &[u8]) {
        for chunk in data.chunks(16) {
            self.update_chunk(chunk);
        }
    }

    fn update_padded_16(&mut self, data: &[u8]) {
        for chunk in data.chunks(16) {
            if chunk.len() == 16 {
                self.update_chunk(chunk);
            } else {
                let mut padded = [0u8; 16];
                padded[..chunk.len()].copy_from_slice(chunk);
                self.update_chunk(&padded);
            }
        }
    }

    fn finalize(self) -> [u8; 16] {
        let total_lo = self.h0 | (self.h1 << 64);
        let total_hi = self.h2 as u64;

        let (sub_lo, borrow) = total_lo.overflowing_sub(0xfffffffffffffffffffffffffffffffb);
        let sub_hi = total_hi.wrapping_sub(3).wrapping_sub(borrow as u64);

        let res_lo = if sub_hi == 0 { sub_lo } else { total_lo };

        let s = (self.s0 as u128) | ((self.s1 as u128) << 64);
        let out = res_lo.wrapping_add(s);
        out.to_le_bytes()
    }
}

fn poly1305_aead_tag(poly_key: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut acc = Poly1305Accumulator::new(poly_key);
    acc.update_padded_16(aad);
    acc.update_padded_16(ciphertext);
    let mut lengths = [0u8; 16];
    lengths[0..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    lengths[8..16].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    acc.update(&lengths);
    acc.finalize()
}

/// Constant-time slice comparison to prevent timing side-channels.
#[inline]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut res = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        res |= x ^ y;
    }
    res == 0
}

// ---------------------------------------------------------------------------
// Cluster Authentication Key (PSK)
// ---------------------------------------------------------------------------

/// 256-bit Pre-Shared Key (PSK) for authenticating cluster members and
/// encrypting ISSP gossip frames via ChaCha20-Poly1305.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ClusterPsk([u8; 32]);

impl std::fmt::Debug for ClusterPsk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ClusterPsk(***REDACTED***)")
    }
}

impl ClusterPsk {
    /// Construct a cluster key directly from 32 bytes of raw cryptographic material.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Access the underlying 32-byte key slice.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Deterministically derive a 256-bit PSK from a shared passphrase or cluster secret token.
    pub fn from_passphrase(passphrase: &[u8]) -> Self {
        let mut state = [0u8; 32];
        let salt = b"IFA-ISSP-CLUSTER-AUTH-PSK-v2\0\0\0\0";
        state.copy_from_slice(salt);
        for (i, &b) in passphrase.iter().enumerate() {
            state[i % 32] ^= b;
        }
        let nonce = [
            0x50, 0x53, 0x4b, 0x5f, 0x49, 0x53, 0x53, 0x50, 0x5f, 0x4b, 0x44, 0x46,
        ]; // "PSK_ISSP_KDF"
        let block = chacha20_block(&state, 1, &nonce);
        let mut key = [0u8; 32];
        key.copy_from_slice(&block[0..32]);
        Self(key)
    }
}

// ---------------------------------------------------------------------------
// Secure Gossip Frame (v2)
// ---------------------------------------------------------------------------

/// Encrypted, authenticated gossip frame for ISSP v2 (ChaCha20-Poly1305 AEAD).
///
/// Wire layout (total = **136 bytes**):
/// ```text
///   0.. 4   magic = ISSP_MAGIC (0x49535350)
///   4.. 8   version = ISSP_VERSION_V2_ENCRYPTED (2)
///   8..12   sender_node_id (u32 LE)
///  12..20   nonce_seq (u64 LE, monotonic anti-replay counter)
///  20..24   reserved = 0 (u32 LE)
///  24..40   auth_tag (16 bytes, Poly1305 MAC)
///  40..136  ciphertext (96 bytes, ChaCha20 encrypted SessionSnapshot)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecureGossipFrame {
    pub sender_node_id: u32,
    pub nonce_seq: u64,
    pub snapshot: SessionSnapshot,
}

impl SecureGossipFrame {
    /// Encode and encrypt into a 136-byte wire buffer using ChaCha20-Poly1305 AEAD.
    pub fn encode(&self, psk: &ClusterPsk) -> [u8; SECURE_GOSSIP_FRAME_SIZE] {
        let mut buf = [0u8; SECURE_GOSSIP_FRAME_SIZE];
        buf[0..4].copy_from_slice(&ISSP_MAGIC.to_be_bytes());
        buf[4..8].copy_from_slice(&ISSP_VERSION_V2_ENCRYPTED.to_le_bytes());
        buf[8..12].copy_from_slice(&self.sender_node_id.to_le_bytes());
        buf[12..20].copy_from_slice(&self.nonce_seq.to_le_bytes());
        buf[20..24].fill(0);

        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&self.sender_node_id.to_le_bytes());
        nonce[4..12].copy_from_slice(&self.nonce_seq.to_le_bytes());

        let snap_bytes = self.snapshot.to_wire();
        buf[40..136].copy_from_slice(&snap_bytes);

        chacha20_xor_slice(psk.as_bytes(), &nonce, 1, &mut buf[40..136]);

        let poly_block = chacha20_block(psk.as_bytes(), 0, &nonce);
        let mut poly_key = [0u8; 32];
        poly_key.copy_from_slice(&poly_block[0..32]);

        let tag = poly1305_aead_tag(&poly_key, &buf[0..24], &buf[40..136]);
        buf[24..40].copy_from_slice(&tag);

        buf
    }

    /// Decode and authenticate a 136-byte wire buffer using ChaCha20-Poly1305 AEAD.
    pub fn decode(
        raw: &[u8; SECURE_GOSSIP_FRAME_SIZE],
        psk: &ClusterPsk,
    ) -> Result<Self, SecurityError> {
        let magic = u32::from_be_bytes(raw[0..4].try_into().unwrap());
        if magic != ISSP_MAGIC {
            return Err(SecurityError::BadMagic);
        }
        let version = u32::from_le_bytes(raw[4..8].try_into().unwrap());
        if version != ISSP_VERSION_V2_ENCRYPTED {
            return Err(SecurityError::UnsupportedVersion(version));
        }

        let sender_node_id = u32::from_le_bytes(raw[8..12].try_into().unwrap());
        let nonce_seq = u64::from_le_bytes(raw[12..20].try_into().unwrap());

        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&raw[8..12]);
        nonce[4..12].copy_from_slice(&raw[12..20]);

        let poly_block = chacha20_block(psk.as_bytes(), 0, &nonce);
        let mut poly_key = [0u8; 32];
        poly_key.copy_from_slice(&poly_block[0..32]);

        let expected_tag = poly1305_aead_tag(&poly_key, &raw[0..24], &raw[40..136]);
        let stored_tag: &[u8; 16] = raw[24..40].try_into().unwrap();

        if !constant_time_eq(&expected_tag, stored_tag) {
            return Err(SecurityError::AuthenticationFailed);
        }

        let mut snap_buf = [0u8; 96];
        snap_buf.copy_from_slice(&raw[40..136]);
        chacha20_xor_slice(psk.as_bytes(), &nonce, 1, &mut snap_buf);

        let snapshot = SessionSnapshot::from_wire(&snap_buf);
        Ok(Self {
            sender_node_id,
            nonce_seq,
            snapshot,
        })
    }
}

// ---------------------------------------------------------------------------
// Local session registry
// ---------------------------------------------------------------------------

/// Per-session live record tracked by the local node.
#[derive(Debug)]
pub struct SessionRecord {
    /// Most recent snapshot of this session.
    pub snapshot: SessionSnapshot,
    /// Monotonic instant of last snapshot capture.
    pub last_captured: Instant,
    /// Whether this session is currently owned (primary) or shadow-replicated.
    pub is_primary: bool,
}

/// Global session state registry for a single node in the cluster.
pub struct SessionRegistry {
    /// Node's own identifier.
    pub node_id: u32,
    /// Live sessions keyed by SessionId.
    sessions: Mutex<HashMap<SessionId, SessionRecord>>,
    /// Configured cluster pre-shared key for encryption/auth.
    pub psk: Option<ClusterPsk>,
    /// Cluster security enforcement policy.
    pub policy: SecurityPolicy,
    /// Sequence counter for outgoing secure gossip frames.
    tx_nonce_seq: AtomicU64,
    /// Highest sequence number observed per peer node (anti-replay).
    peer_last_seq: Mutex<HashMap<u32, u64>>,
    /// Count of migrations performed by this node (exported to telemetry).
    pub migration_count: AtomicU64,
    /// Count of snapshot gossip messages received.
    pub gossip_rx_count: AtomicU64,
    /// Count of stale / rejected gossip messages (CRC fail or old epoch).
    pub gossip_rejected_count: AtomicU64,
    /// Count of frames rejected due to authentication/crypto failure.
    pub gossip_auth_failed_count: AtomicU64,
    /// Count of frames rejected due to replay detection.
    pub gossip_replay_failed_count: AtomicU64,
}

impl SessionRegistry {
    /// Create a new registry for the given node with default permissive policy and no PSK.
    pub fn new(node_id: u32) -> Arc<Self> {
        Arc::new(Self {
            node_id,
            sessions: Mutex::new(HashMap::new()),
            psk: None,
            policy: SecurityPolicy::Permissive,
            tx_nonce_seq: AtomicU64::new(1),
            peer_last_seq: Mutex::new(HashMap::new()),
            migration_count: AtomicU64::new(0),
            gossip_rx_count: AtomicU64::new(0),
            gossip_rejected_count: AtomicU64::new(0),
            gossip_auth_failed_count: AtomicU64::new(0),
            gossip_replay_failed_count: AtomicU64::new(0),
        })
    }

    /// Create a new registry hardened with a cluster Pre-Shared Key (PSK) and security policy.
    pub fn with_psk(node_id: u32, psk: ClusterPsk, policy: SecurityPolicy) -> Arc<Self> {
        Arc::new(Self {
            node_id,
            sessions: Mutex::new(HashMap::new()),
            psk: Some(psk),
            policy,
            tx_nonce_seq: AtomicU64::new(1),
            peer_last_seq: Mutex::new(HashMap::new()),
            migration_count: AtomicU64::new(0),
            gossip_rx_count: AtomicU64::new(0),
            gossip_rejected_count: AtomicU64::new(0),
            gossip_auth_failed_count: AtomicU64::new(0),
            gossip_replay_failed_count: AtomicU64::new(0),
        })
    }

    /// Register or update a primary session owned by this node.
    pub fn upsert_primary(&self, snapshot: SessionSnapshot) -> Result<(), SyncError> {
        let mut guard = self.sessions.lock().map_err(|_| SyncError::LockPoisoned)?;
        if guard.len() >= MAX_SESSIONS && !guard.contains_key(&snapshot.id) {
            return Err(SyncError::RegistryFull);
        }
        guard.insert(
            snapshot.id,
            SessionRecord {
                snapshot,
                last_captured: Instant::now(),
                is_primary: true,
            },
        );
        Ok(())
    }

    /// Apply a received gossip snapshot from a peer.  The snapshot is accepted
    /// only if its `migration_epoch` is strictly greater than the locally known
    /// epoch for that session (or the session is unknown).
    pub fn apply_gossip(&self, frame: &GossipFrame) -> GossipResult {
        self.gossip_rx_count.fetch_add(1, Ordering::Relaxed);

        if frame.sender_node_id == self.node_id {
            // Ignore self-gossip (loop-back prevention).
            return GossipResult::Ignored;
        }

        let mut guard = match self.sessions.lock() {
            Ok(g) => g,
            Err(_) => {
                self.gossip_rejected_count.fetch_add(1, Ordering::Relaxed);
                return GossipResult::Rejected(RejectReason::LockFailed);
            }
        };

        let snap = &frame.snapshot;

        if let Some(record) = guard.get_mut(&snap.id) {
            if snap.migration_epoch <= record.snapshot.migration_epoch {
                self.gossip_rejected_count.fetch_add(1, Ordering::Relaxed);
                return GossipResult::Rejected(RejectReason::StaleEpoch {
                    local: record.snapshot.migration_epoch,
                    received: snap.migration_epoch,
                });
            }
            // Accept fresher epoch — demote ourselves to shadow.
            record.snapshot = *snap;
            record.last_captured = Instant::now();
            record.is_primary = false;
            GossipResult::Updated
        } else {
            // New session seen for the first time.
            if guard.len() >= MAX_SESSIONS {
                self.gossip_rejected_count.fetch_add(1, Ordering::Relaxed);
                return GossipResult::Rejected(RejectReason::RegistryFull);
            }
            guard.insert(
                snap.id,
                SessionRecord {
                    snapshot: *snap,
                    last_captured: Instant::now(),
                    is_primary: false,
                },
            );
            GossipResult::Inserted
        }
    }

    /// Trigger a **transparent migration**: take ownership of a shadow session.
    ///
    /// The caller supplies the `session_id` of the session to migrate and the
    /// current Unix epoch seconds for staleness validation.  On success, returns
    /// the updated snapshot with an incremented `migration_epoch` that the caller
    /// must immediately propagate to peers.
    pub fn migrate_session(
        &self,
        session_id: SessionId,
        now_unix_secs: u64,
    ) -> Result<SessionSnapshot, SyncError> {
        let mut guard = self.sessions.lock().map_err(|_| SyncError::LockPoisoned)?;

        let record = guard
            .get_mut(&session_id)
            .ok_or(SyncError::SessionNotFound)?;

        // Reject stale snapshots — do not resume a session with ancient state.
        let age_secs = now_unix_secs.saturating_sub(record.snapshot.captured_unix_secs);
        if age_secs > SNAPSHOT_MAX_AGE.as_secs() {
            return Err(SyncError::SnapshotStale { age_secs });
        }

        if record.is_primary {
            return Err(SyncError::AlreadyPrimary);
        }

        // Bump migration epoch — this acts as a fencing token.
        record.snapshot.migration_epoch += 1;
        record.snapshot.captured_unix_secs = now_unix_secs;
        record.is_primary = true;
        self.migration_count.fetch_add(1, Ordering::Relaxed);

        Ok(record.snapshot)
    }

    /// Produce a gossip frame for the given session (primary or shadow) for
    /// broadcasting to peers.
    pub fn build_gossip_frame(&self, session_id: &SessionId) -> Option<GossipFrame> {
        let guard = self.sessions.lock().ok()?;
        let record = guard.get(session_id)?;
        Some(GossipFrame {
            sender_node_id: self.node_id,
            snapshot: record.snapshot,
        })
    }

    /// Collect IDs of sessions whose snapshot is older than `max_age` for
    /// eviction or re-gossip triggering.
    pub fn stale_sessions(&self, max_age: Duration) -> Vec<SessionId> {
        let guard = match self.sessions.lock() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };
        let now = Instant::now();
        guard
            .iter()
            .filter(|(_, r)| now.duration_since(r.last_captured) > max_age)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Remove a session that has been fully torn down.
    pub fn remove_session(&self, session_id: &SessionId) -> bool {
        let mut guard = match self.sessions.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        guard.remove(session_id).is_some()
    }

    /// Count of active sessions (primary + shadow).
    pub fn session_count(&self) -> usize {
        self.sessions.lock().map(|g| g.len()).unwrap_or(0)
    }

    /// Produce an encrypted, authenticated gossip frame (v2) for the given session.
    ///
    /// Returns `None` if the session is not found or if no PSK is configured.
    pub fn build_secure_gossip_frame(
        &self,
        session_id: &SessionId,
    ) -> Option<[u8; SECURE_GOSSIP_FRAME_SIZE]> {
        let psk = self.psk.as_ref()?;
        let guard = self.sessions.lock().ok()?;
        let record = guard.get(session_id)?;
        let nonce_seq = self.tx_nonce_seq.fetch_add(1, Ordering::Relaxed);
        let frame = SecureGossipFrame {
            sender_node_id: self.node_id,
            nonce_seq,
            snapshot: record.snapshot,
        };
        Some(frame.encode(psk))
    }

    /// Apply an encrypted gossip frame received from a peer node.
    pub fn apply_secure_gossip(
        &self,
        raw: &[u8; SECURE_GOSSIP_FRAME_SIZE],
    ) -> Result<GossipResult, SecurityError> {
        let psk = self.psk.as_ref().ok_or(SecurityError::PolicyViolation)?;
        let frame = match SecureGossipFrame::decode(raw, psk) {
            Ok(f) => f,
            Err(e) => {
                self.gossip_auth_failed_count
                    .fetch_add(1, Ordering::Relaxed);
                return Err(e);
            }
        };

        if frame.sender_node_id == self.node_id {
            return Ok(GossipResult::Ignored);
        }

        // Anti-replay check
        {
            let mut peer_map = self
                .peer_last_seq
                .lock()
                .map_err(|_| SecurityError::LockFailed)?;
            if let Some(&last_seq) = peer_map.get(&frame.sender_node_id) {
                if frame.nonce_seq <= last_seq {
                    self.gossip_replay_failed_count
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(SecurityError::ReplayDetected {
                        last_seq,
                        received_seq: frame.nonce_seq,
                    });
                }
            }
            peer_map.insert(frame.sender_node_id, frame.nonce_seq);
        }

        let unencrypted = GossipFrame {
            sender_node_id: frame.sender_node_id,
            snapshot: frame.snapshot,
        };
        Ok(self.apply_gossip(&unencrypted))
    }

    /// Universal ingest for raw gossip datagrams received over the control UDP socket.
    /// Automatically distinguishes v1 plaintext (112 bytes) and v2 encrypted (136 bytes) frames,
    /// enforcing the configured cluster security policy.
    pub fn apply_raw_gossip(&self, slice: &[u8]) -> Result<GossipResult, RawGossipError> {
        match slice.len() {
            SECURE_GOSSIP_FRAME_SIZE => {
                let raw_arr: &[u8; SECURE_GOSSIP_FRAME_SIZE] = slice.try_into().unwrap();
                if self.psk.is_none() {
                    return Err(RawGossipError::NoPskConfigured);
                }
                self.apply_secure_gossip(raw_arr)
                    .map_err(RawGossipError::Security)
            }
            GOSSIP_FRAME_SIZE => {
                if self.policy == SecurityPolicy::StrictPsk {
                    return Err(RawGossipError::Security(SecurityError::PolicyViolation));
                }
                let raw_arr: &[u8; GOSSIP_FRAME_SIZE] = slice.try_into().unwrap();
                let frame =
                    GossipFrame::decode(raw_arr).ok_or(RawGossipError::CorruptedPlaintext)?;
                let res = self.apply_gossip(&frame);
                match res {
                    GossipResult::Rejected(r) => Err(RawGossipError::Registry(r)),
                    other => Ok(other),
                }
            }
            other_len => Err(RawGossipError::InvalidLength(other_len)),
        }
    }

    /// Export telemetry snapshot for Prometheus / OpenTelemetry exporters.
    pub fn telemetry_snapshot(&self) -> SyncTelemetry {
        SyncTelemetry {
            node_id: self.node_id,
            session_count: self.session_count() as u64,
            migration_count: self.migration_count.load(Ordering::Relaxed),
            gossip_rx_count: self.gossip_rx_count.load(Ordering::Relaxed),
            gossip_rejected_count: self.gossip_rejected_count.load(Ordering::Relaxed),
            gossip_auth_failed_count: self.gossip_auth_failed_count.load(Ordering::Relaxed),
            gossip_replay_failed_count: self.gossip_replay_failed_count.load(Ordering::Relaxed),
        }
    }
}

// ---------------------------------------------------------------------------
// Result types & Security definitions
// ---------------------------------------------------------------------------

/// Security enforcement policy for ISSP cluster gossip frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SecurityPolicy {
    /// Strict: only encrypted/authenticated v2 frames are accepted and emitted.
    StrictPsk,
    /// Permissive: accepts both encrypted v2 and unencrypted v1 frames (for rolling cluster upgrades).
    #[default]
    Permissive,
    /// PlaintextOnly: legacy mode without encryption or authentication.
    PlaintextOnly,
}

/// Cryptographic or authentication error during ISSP gossip processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityError {
    /// Frame magic does not match ISSP_MAGIC.
    BadMagic,
    /// Wire protocol version is not recognized.
    UnsupportedVersion(u32),
    /// Authentication tag mismatch (wrong PSK, tampered header, or corrupted ciphertext).
    AuthenticationFailed,
    /// Detected replayed gossip frame with non-increasing sequence number.
    ReplayDetected { last_seq: u64, received_seq: u64 },
    /// Operation violated configured cluster security policy.
    PolicyViolation,
    /// Internal lock poisoned.
    LockFailed,
}

impl std::fmt::Display for SecurityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecurityError::BadMagic => write!(f, "invalid ISSP magic tag"),
            SecurityError::UnsupportedVersion(v) => write!(f, "unsupported ISSP version {v}"),
            SecurityError::AuthenticationFailed => write!(f, "cluster PSK authentication failed"),
            SecurityError::ReplayDetected {
                last_seq,
                received_seq,
            } => {
                write!(
                    f,
                    "gossip replay detected: received seq {received_seq} <= last seen {last_seq}"
                )
            }
            SecurityError::PolicyViolation => {
                write!(f, "cluster security policy rejected unencrypted frame")
            }
            SecurityError::LockFailed => write!(f, "internal security state lock poisoned"),
        }
    }
}

impl std::error::Error for SecurityError {}

/// Error returned when processing raw wire gossip bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawGossipError {
    /// Security or authentication error.
    Security(SecurityError),
    /// No PSK configured on this node, but an encrypted v2 frame was received.
    NoPskConfigured,
    /// Length of the raw buffer matches neither v1 (112) nor v2 (136).
    InvalidLength(usize),
    /// Plaintext frame CRC check failed.
    CorruptedPlaintext,
    /// Registry operation rejected the frame.
    Registry(RejectReason),
}

impl std::fmt::Display for RawGossipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RawGossipError::Security(e) => write!(f, "security error: {e}"),
            RawGossipError::NoPskConfigured => {
                write!(f, "received encrypted frame but no PSK configured")
            }
            RawGossipError::InvalidLength(len) => {
                write!(f, "invalid gossip frame length: {len} bytes")
            }
            RawGossipError::CorruptedPlaintext => {
                write!(f, "corrupted plaintext frame (CRC mismatch)")
            }
            RawGossipError::Registry(_) => write!(f, "registry rejected snapshot"),
        }
    }
}

impl std::error::Error for RawGossipError {}

/// Outcome of applying a gossip frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GossipResult {
    /// Frame was applied and updated an existing shadow session.
    Updated,
    /// Frame introduced a brand-new session into the shadow registry.
    Inserted,
    /// Frame was silently ignored (self-loop or no-op).
    Ignored,
    /// Frame was rejected.
    Rejected(RejectReason),
}

/// Reason a gossip frame was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// Received epoch ≤ locally known epoch.
    StaleEpoch { local: u64, received: u64 },
    /// Registry is at capacity.
    RegistryFull,
    /// Mutex was poisoned.
    LockFailed,
}

/// Errors returned by registry operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncError {
    /// Session was not found in the registry.
    SessionNotFound,
    /// This node is already the primary owner — no migration needed.
    AlreadyPrimary,
    /// Snapshot is too old to safely restore session state.
    SnapshotStale { age_secs: u64 },
    /// Registry is full — cannot insert more sessions.
    RegistryFull,
    /// Internal mutex was poisoned.
    LockPoisoned,
}

impl std::fmt::Display for SyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncError::SessionNotFound => write!(f, "session not found in registry"),
            SyncError::AlreadyPrimary => write!(f, "node already holds primary ownership"),
            SyncError::SnapshotStale { age_secs } => {
                write!(
                    f,
                    "snapshot is stale ({age_secs}s old, max {}s)",
                    SNAPSHOT_MAX_AGE.as_secs()
                )
            }
            SyncError::RegistryFull => write!(f, "registry capacity ({MAX_SESSIONS}) reached"),
            SyncError::LockPoisoned => write!(f, "internal mutex poisoned"),
        }
    }
}

impl std::error::Error for SyncError {}

/// Telemetry counters exported by the session synchronization subsystem.
#[derive(Debug, Clone, Copy)]
pub struct SyncTelemetry {
    pub node_id: u32,
    pub session_count: u64,
    pub migration_count: u64,
    pub gossip_rx_count: u64,
    pub gossip_rejected_count: u64,
    pub gossip_auth_failed_count: u64,
    pub gossip_replay_failed_count: u64,
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_id(flow: u64) -> SessionId {
        SessionId::new(flow, 1, 0xDEAD)
    }

    fn make_snap(id: SessionId, epoch: u64, unix: u64) -> SessionSnapshot {
        let mut s = SessionSnapshot::new(id, 1, unix);
        s.migration_epoch = epoch;
        s.tx_seq = 42;
        s.rx_seq_high = 40;
        s
    }

    // ---- SessionId round-trip ----
    #[test]
    fn test_session_id_roundtrip() {
        let id = SessionId::new(0xCAFEBABEDEAD_u64, 7, 0xABCD);
        assert_eq!(SessionId::from_bytes(&id.to_bytes()), id);
    }

    // ---- Snapshot wire round-trip ----
    #[test]
    fn test_snapshot_wire_roundtrip() {
        let id = make_id(1);
        let snap = make_snap(id, 3, 1_700_000_000);
        let wire = snap.to_wire();
        let decoded = SessionSnapshot::from_wire(&wire);
        assert_eq!(decoded.id, snap.id);
        assert_eq!(decoded.migration_epoch, snap.migration_epoch);
        assert_eq!(decoded.tx_seq, snap.tx_seq);
        assert_eq!(decoded.rx_seq_high, snap.rx_seq_high);
        assert_eq!(decoded.crypto_epoch, snap.crypto_epoch);
    }

    // ---- GossipFrame CRC integrity ----
    #[test]
    fn test_gossip_frame_crc_ok() {
        let id = make_id(2);
        let snap = make_snap(id, 1, 1_700_000_001);
        let frame = GossipFrame {
            sender_node_id: 42,
            snapshot: snap,
        };
        let encoded = frame.encode();
        let decoded = GossipFrame::decode(&encoded);
        assert!(decoded.is_some());
        let d = decoded.unwrap();
        assert_eq!(d.sender_node_id, 42);
        assert_eq!(d.snapshot.migration_epoch, 1);
    }

    #[test]
    fn test_gossip_frame_crc_corruption() {
        let id = make_id(3);
        let snap = make_snap(id, 1, 1_700_000_002);
        let frame = GossipFrame {
            sender_node_id: 1,
            snapshot: snap,
        };
        let mut encoded = frame.encode();
        encoded[20] ^= 0xFF; // corrupt snapshot byte
        assert!(GossipFrame::decode(&encoded).is_none());
    }

    #[test]
    fn test_gossip_frame_bad_magic() {
        let id = make_id(4);
        let snap = make_snap(id, 1, 1_700_000_003);
        let frame = GossipFrame {
            sender_node_id: 1,
            snapshot: snap,
        };
        let mut encoded = frame.encode();
        encoded[0] = 0x00; // corrupt magic
        assert!(GossipFrame::decode(&encoded).is_none());
    }

    // ---- Registry: upsert & gossip accept/reject ----
    #[test]
    fn test_registry_upsert_primary() {
        let reg = SessionRegistry::new(1);
        let id = make_id(10);
        let snap = make_snap(id, 0, 1_700_000_100);
        reg.upsert_primary(snap).unwrap();
        assert_eq!(reg.session_count(), 1);
    }

    #[test]
    fn test_gossip_insert_new_session() {
        let reg = SessionRegistry::new(1);
        let id = make_id(20);
        let snap = make_snap(id, 1, 1_700_000_200);
        let frame = GossipFrame {
            sender_node_id: 2,
            snapshot: snap,
        };
        let result = reg.apply_gossip(&frame);
        assert_eq!(result, GossipResult::Inserted);
        assert_eq!(reg.session_count(), 1);
    }

    #[test]
    fn test_gossip_update_fresher_epoch() {
        let reg = SessionRegistry::new(1);
        let id = make_id(30);
        let snap_v1 = make_snap(id, 1, 1_700_000_300);
        let frame_v1 = GossipFrame {
            sender_node_id: 2,
            snapshot: snap_v1,
        };
        reg.apply_gossip(&frame_v1);

        let snap_v2 = make_snap(id, 2, 1_700_000_301);
        let frame_v2 = GossipFrame {
            sender_node_id: 2,
            snapshot: snap_v2,
        };
        let result = reg.apply_gossip(&frame_v2);
        assert_eq!(result, GossipResult::Updated);
    }

    #[test]
    fn test_gossip_reject_stale_epoch() {
        let reg = SessionRegistry::new(1);
        let id = make_id(40);
        let snap_v2 = make_snap(id, 5, 1_700_000_400);
        let frame_v2 = GossipFrame {
            sender_node_id: 2,
            snapshot: snap_v2,
        };
        reg.apply_gossip(&frame_v2);

        // Send older epoch — must be rejected.
        let snap_old = make_snap(id, 3, 1_700_000_399);
        let frame_old = GossipFrame {
            sender_node_id: 2,
            snapshot: snap_old,
        };
        let result = reg.apply_gossip(&frame_old);
        assert!(matches!(
            result,
            GossipResult::Rejected(RejectReason::StaleEpoch { .. })
        ));
    }

    #[test]
    fn test_gossip_ignore_self() {
        let reg = SessionRegistry::new(7);
        let id = make_id(50);
        let snap = make_snap(id, 1, 1_700_000_500);
        let frame = GossipFrame {
            sender_node_id: 7,
            snapshot: snap,
        }; // same node id
        assert_eq!(reg.apply_gossip(&frame), GossipResult::Ignored);
        assert_eq!(reg.session_count(), 0);
    }

    // ---- Transparent migration ----
    #[test]
    fn test_migration_success() {
        let reg = SessionRegistry::new(1);
        let id = make_id(60);
        // Insert as shadow via gossip from node 2.
        let snap = make_snap(id, 2, 1_700_000_600);
        let frame = GossipFrame {
            sender_node_id: 2,
            snapshot: snap,
        };
        reg.apply_gossip(&frame);

        let migrated = reg.migrate_session(id, 1_700_000_601).unwrap();
        assert_eq!(migrated.migration_epoch, 3); // bumped by 1
        assert!(
            reg.build_gossip_frame(&id)
                .unwrap()
                .snapshot
                .migration_epoch
                == 3
        );
    }

    #[test]
    fn test_migration_already_primary() {
        let reg = SessionRegistry::new(1);
        let id = make_id(70);
        let snap = make_snap(id, 0, 1_700_000_700);
        reg.upsert_primary(snap).unwrap();
        let err = reg.migrate_session(id, 1_700_000_701).unwrap_err();
        assert_eq!(err, SyncError::AlreadyPrimary);
    }

    #[test]
    fn test_migration_stale_snapshot() {
        let reg = SessionRegistry::new(1);
        let id = make_id(80);
        // Insert as shadow with captured_unix_secs = 1000 (ancient).
        let snap = make_snap(id, 1, 1000);
        let frame = GossipFrame {
            sender_node_id: 2,
            snapshot: snap,
        };
        reg.apply_gossip(&frame);

        // Attempt migration with now = 1_700_000_000 → age >> 5s.
        let err = reg.migrate_session(id, 1_700_000_000).unwrap_err();
        assert!(matches!(err, SyncError::SnapshotStale { .. }));
    }

    #[test]
    fn test_migration_not_found() {
        let reg = SessionRegistry::new(1);
        let id = make_id(99);
        let err = reg.migrate_session(id, 1_700_000_000).unwrap_err();
        assert_eq!(err, SyncError::SessionNotFound);
    }

    // ---- Remove session ----
    #[test]
    fn test_remove_session() {
        let reg = SessionRegistry::new(1);
        let id = make_id(100);
        let snap = make_snap(id, 0, 1_700_001_000);
        reg.upsert_primary(snap).unwrap();
        assert!(reg.remove_session(&id));
        assert_eq!(reg.session_count(), 0);
        assert!(!reg.remove_session(&id)); // double-remove
    }

    // ---- Telemetry ----
    #[test]
    fn test_telemetry_counters() {
        let reg = SessionRegistry::new(5);
        let id = make_id(200);
        let snap = make_snap(id, 1, 1_700_002_000);
        // Apply valid gossip → gossip_rx +1
        let frame = GossipFrame {
            sender_node_id: 2,
            snapshot: snap,
        };
        reg.apply_gossip(&frame);
        // Apply stale gossip → gossip_rx +1, rejected +1
        let snap_old = make_snap(id, 0, 1_700_001_999);
        let frame_old = GossipFrame {
            sender_node_id: 2,
            snapshot: snap_old,
        };
        reg.apply_gossip(&frame_old);
        // Migrate → migration_count +1
        reg.migrate_session(id, 1_700_002_001).unwrap();

        let tel = reg.telemetry_snapshot();
        assert_eq!(tel.node_id, 5);
        assert_eq!(tel.gossip_rx_count, 2);
        assert_eq!(tel.gossip_rejected_count, 1);
        assert_eq!(tel.migration_count, 1);
        assert_eq!(tel.session_count, 1);
        assert_eq!(tel.gossip_auth_failed_count, 0);
        assert_eq!(tel.gossip_replay_failed_count, 0);
    }

    // ---- ISSP Hardening: Cluster PSK, ChaCha20-Poly1305 & Anti-Replay ----

    #[test]
    fn test_cluster_psk_derivation() {
        let psk1 = ClusterPsk::from_passphrase(b"masque-cluster-secret-prod-eu");
        let psk2 = ClusterPsk::from_passphrase(b"masque-cluster-secret-prod-eu");
        let psk3 = ClusterPsk::from_passphrase(b"masque-cluster-secret-staging");

        assert_eq!(psk1, psk2);
        assert_ne!(psk1, psk3);
        assert_ne!(psk1.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn test_secure_gossip_roundtrip() {
        let psk = ClusterPsk::from_passphrase(b"secure-token-alpha");
        let id = make_id(300);
        let snap = make_snap(id, 4, 1_700_003_000);
        let frame = SecureGossipFrame {
            sender_node_id: 11,
            nonce_seq: 101,
            snapshot: snap,
        };

        let encoded = frame.encode(&psk);
        assert_eq!(encoded.len(), SECURE_GOSSIP_FRAME_SIZE);

        let decoded = SecureGossipFrame::decode(&encoded, &psk).expect("decode failed");
        assert_eq!(decoded.sender_node_id, 11);
        assert_eq!(decoded.nonce_seq, 101);
        assert_eq!(decoded.snapshot.id, id);
        assert_eq!(decoded.snapshot.migration_epoch, 4);
        assert_eq!(decoded.snapshot.tx_seq, 42);
    }

    #[test]
    fn test_secure_gossip_wrong_key() {
        let psk_alice = ClusterPsk::from_passphrase(b"cluster-alice");
        let psk_eve = ClusterPsk::from_passphrase(b"cluster-eve-attacker");

        let id = make_id(301);
        let snap = make_snap(id, 1, 1_700_003_001);
        let frame = SecureGossipFrame {
            sender_node_id: 1,
            nonce_seq: 1,
            snapshot: snap,
        };

        let encoded = frame.encode(&psk_alice);
        let err = SecureGossipFrame::decode(&encoded, &psk_eve).unwrap_err();
        assert_eq!(err, SecurityError::AuthenticationFailed);
    }

    #[test]
    fn test_secure_gossip_tamper_header() {
        let psk = ClusterPsk::from_passphrase(b"cluster-key");
        let id = make_id(302);
        let snap = make_snap(id, 1, 1_700_003_002);
        let frame = SecureGossipFrame {
            sender_node_id: 2,
            nonce_seq: 5,
            snapshot: snap,
        };

        let mut encoded = frame.encode(&psk);
        // Tamper with sender_node_id in AAD (offset 8)
        encoded[8] ^= 0x01;
        let err = SecureGossipFrame::decode(&encoded, &psk).unwrap_err();
        assert_eq!(err, SecurityError::AuthenticationFailed);
    }

    #[test]
    fn test_secure_gossip_tamper_ciphertext() {
        let psk = ClusterPsk::from_passphrase(b"cluster-key");
        let id = make_id(303);
        let snap = make_snap(id, 1, 1_700_003_003);
        let frame = SecureGossipFrame {
            sender_node_id: 2,
            nonce_seq: 6,
            snapshot: snap,
        };

        let mut encoded = frame.encode(&psk);
        // Tamper with ciphertext byte (offset 45)
        encoded[45] ^= 0xFF;
        let err = SecureGossipFrame::decode(&encoded, &psk).unwrap_err();
        assert_eq!(err, SecurityError::AuthenticationFailed);
    }

    #[test]
    fn test_secure_gossip_bad_magic_and_version() {
        let psk = ClusterPsk::from_passphrase(b"cluster-key");
        let id = make_id(304);
        let snap = make_snap(id, 1, 1_700_003_004);
        let frame = SecureGossipFrame {
            sender_node_id: 2,
            nonce_seq: 7,
            snapshot: snap,
        };

        let mut encoded = frame.encode(&psk);
        encoded[0] = 0x00; // corrupt magic
        assert_eq!(
            SecureGossipFrame::decode(&encoded, &psk).unwrap_err(),
            SecurityError::BadMagic
        );

        let mut encoded2 = frame.encode(&psk);
        encoded2[4] = 99; // invalid version
        assert_eq!(
            SecureGossipFrame::decode(&encoded2, &psk).unwrap_err(),
            SecurityError::UnsupportedVersion(99)
        );
    }

    #[test]
    fn test_secure_gossip_anti_replay() {
        let psk = ClusterPsk::from_passphrase(b"cluster-replay-test");
        let reg = SessionRegistry::with_psk(1, psk, SecurityPolicy::StrictPsk);
        let id = make_id(305);
        let snap1 = make_snap(id, 1, 1_700_003_005);

        let frame1 = SecureGossipFrame {
            sender_node_id: 2,
            nonce_seq: 10,
            snapshot: snap1,
        };
        let raw1 = frame1.encode(&psk);

        // First apply -> success (Inserted)
        let res = reg.apply_secure_gossip(&raw1).unwrap();
        assert_eq!(res, GossipResult::Inserted);

        // Replay same seq 10 -> rejected
        let err = reg.apply_secure_gossip(&raw1).unwrap_err();
        assert!(matches!(
            err,
            SecurityError::ReplayDetected {
                last_seq: 10,
                received_seq: 10
            }
        ));

        // Older seq 9 -> rejected
        let snap_old = make_snap(id, 2, 1_700_003_006);
        let frame_old = SecureGossipFrame {
            sender_node_id: 2,
            nonce_seq: 9,
            snapshot: snap_old,
        };
        let raw_old = frame_old.encode(&psk);
        let err_old = reg.apply_secure_gossip(&raw_old).unwrap_err();
        assert!(matches!(
            err_old,
            SecurityError::ReplayDetected {
                last_seq: 10,
                received_seq: 9
            }
        ));

        // Fresh seq 11 -> accepted (Updated)
        let snap_fresh = make_snap(id, 2, 1_700_003_007);
        let frame_fresh = SecureGossipFrame {
            sender_node_id: 2,
            nonce_seq: 11,
            snapshot: snap_fresh,
        };
        let raw_fresh = frame_fresh.encode(&psk);
        let res_fresh = reg.apply_secure_gossip(&raw_fresh).unwrap();
        assert_eq!(res_fresh, GossipResult::Updated);

        // Telemetry check
        let tel = reg.telemetry_snapshot();
        assert_eq!(tel.gossip_replay_failed_count, 2);
    }

    #[test]
    fn test_registry_strict_policy_rejects_plaintext() {
        let psk = ClusterPsk::from_passphrase(b"strict-cluster");
        let reg = SessionRegistry::with_psk(1, psk, SecurityPolicy::StrictPsk);
        let id = make_id(306);
        let snap = make_snap(id, 1, 1_700_003_008);

        let plaintext_frame = GossipFrame {
            sender_node_id: 2,
            snapshot: snap,
        };
        let raw_plain = plaintext_frame.encode();

        let err = reg.apply_raw_gossip(&raw_plain).unwrap_err();
        assert_eq!(
            err,
            RawGossipError::Security(SecurityError::PolicyViolation)
        );
    }

    #[test]
    fn test_registry_permissive_policy_accepts_both() {
        let psk = ClusterPsk::from_passphrase(b"permissive-cluster");
        let reg = SessionRegistry::with_psk(1, psk, SecurityPolicy::Permissive);

        // 1) Apply plaintext v1 frame
        let id1 = make_id(307);
        let snap1 = make_snap(id1, 1, 1_700_003_009);
        let plain_frame = GossipFrame {
            sender_node_id: 2,
            snapshot: snap1,
        };
        let raw_plain = plain_frame.encode();
        let res_plain = reg.apply_raw_gossip(&raw_plain).unwrap();
        assert_eq!(res_plain, GossipResult::Inserted);

        // 2) Apply encrypted v2 frame
        let id2 = make_id(308);
        let snap2 = make_snap(id2, 1, 1_700_003_010);
        let sec_frame = SecureGossipFrame {
            sender_node_id: 3,
            nonce_seq: 1,
            snapshot: snap2,
        };
        let raw_sec = sec_frame.encode(&psk);
        let res_sec = reg.apply_raw_gossip(&raw_sec).unwrap();
        assert_eq!(res_sec, GossipResult::Inserted);

        assert_eq!(reg.session_count(), 2);
    }

    #[test]
    fn test_registry_build_secure_gossip_frame() {
        let psk = ClusterPsk::from_passphrase(b"cluster-builder");
        let reg = SessionRegistry::with_psk(42, psk, SecurityPolicy::StrictPsk);
        let id = make_id(309);
        let snap = make_snap(id, 0, 1_700_003_011);
        reg.upsert_primary(snap).unwrap();

        let secure_bytes = reg
            .build_secure_gossip_frame(&id)
            .expect("frame build failed");
        assert_eq!(secure_bytes.len(), SECURE_GOSSIP_FRAME_SIZE);

        let decoded = SecureGossipFrame::decode(&secure_bytes, &psk).unwrap();
        assert_eq!(decoded.sender_node_id, 42);
        assert_eq!(decoded.snapshot.id, id);
    }

    #[test]
    fn test_telemetry_crypto_and_replay_counters() {
        let psk = ClusterPsk::from_passphrase(b"telem-psk");
        let reg = SessionRegistry::with_psk(1, psk, SecurityPolicy::StrictPsk);

        // Corrupted secure frame -> auth failed counter +1
        let mut corrupted = [0u8; SECURE_GOSSIP_FRAME_SIZE];
        corrupted[0..4].copy_from_slice(&ISSP_MAGIC.to_be_bytes());
        corrupted[4..8].copy_from_slice(&ISSP_VERSION_V2_ENCRYPTED.to_le_bytes());
        let _ = reg.apply_secure_gossip(&corrupted);

        let tel = reg.telemetry_snapshot();
        assert_eq!(tel.gossip_auth_failed_count, 1);
        assert_eq!(tel.gossip_replay_failed_count, 0);
    }
}

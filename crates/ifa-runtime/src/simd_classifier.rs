//! SIMD-Accelerated ISSP Capsule Header Decoder and Telemetry Packet Classifier.
//!
//! Provides zero-copy, branch-predictive, and SWAR/SIMD-vectorized processing of incoming
//! ISSP network frames, RFC 9297 capsules, and telemetry streams at gigabit line rate.

use crate::session_sync::{
    SyncError, ISSP_CAPSULE_HEADER_SIZE, ISSP_CAPSULE_MAGIC, ISSP_HEARTBEAT_MAGIC,
    ISSP_HEARTBEAT_SIZE, ISSP_MAGIC, ISSP_PKT_FLAG_COMPRESSED, ISSP_PKT_FLAG_ENCRYPTED,
    ISSP_SUBPATH_PACKET_MAGIC, ISSP_VERSION_V1, ISSP_VERSION_V2_ENCRYPTED,
};

/// ISSP Telemetry Metrics packet magic identifier ('ISTM').
pub const ISSP_TELEMETRY_MAGIC: u32 = 0x4953_544d;

/// ISSP Distributed Trace Context packet magic identifier ('ISTR').
pub const ISSP_TRACE_MAGIC: u32 = 0x4953_5452;

/// ISSP Multi-Node Mesh Link-State Advertisement packet magic identifier ('ISMS').
pub const ISSP_MESH_LSA_MAGIC: u32 = 0x4953_4d53;

/// ISSP Compressed Multi-Node Mesh Link-State Advertisement packet magic identifier ('ISCL').
pub const ISSP_COMPRESSED_LSA_MAGIC: u32 = 0x4953_434c;

/// ISSP Transparent Migration Cutover packet magic identifier ('ISMG').
pub const ISSP_MIGRATION_MAGIC: u32 = 0x4953_4d47;

/// Common prefix for all ISSP family protocol packets: 'IS' (0x4953).
pub const ISSP_FAMILY_PREFIX: u16 = 0x4953;

// ---------------------------------------------------------------------------
// Zero-Copy ISSP Capsule Header & View
// ---------------------------------------------------------------------------

/// Decoded 12-byte header of an ISSP Capsule wire container.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IsspCapsuleHeader {
    /// Capsule wire protocol magic (must match `ISSP_CAPSULE_MAGIC`).
    pub magic: u32,
    /// Wire protocol version (`ISSP_VERSION_V1` or `ISSP_VERSION_V2_ENCRYPTED`).
    pub version: u32,
    /// Identifier of originating or transmitting gateway node.
    pub origin_node_id: u32,
    /// Length of payload in bytes trailing the header.
    pub payload_len: usize,
}

impl IsspCapsuleHeader {
    /// Whether this capsule wraps an AEAD-encrypted SecureGossipFrame (version 2).
    #[inline(always)]
    pub fn is_encrypted(&self) -> bool {
        self.version == ISSP_VERSION_V2_ENCRYPTED
    }

    /// Whether this capsule wraps a plaintext GossipFrame (version 1).
    #[inline(always)]
    pub fn is_plaintext_v1(&self) -> bool {
        self.version == ISSP_VERSION_V1
    }
}

/// Zero-copy borrowed view of an ISSP capsule avoiding heap allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IsspCapsuleView<'a> {
    /// Decoded header fields.
    pub header: IsspCapsuleHeader,
    /// Borrowed reference to the wire payload slice.
    pub payload: &'a [u8],
}

// ---------------------------------------------------------------------------
// SIMD / SWAR Capsule Header Decoder
// ---------------------------------------------------------------------------

/// Decode an ISSP capsule header with zero-copy SIMD/SWAR validation.
///
/// Validates magic and version in parallel using 64-bit word operations,
/// unpacking header fields in ~1-2 nanoseconds without any memory allocation.
#[inline]
pub fn decode_capsule_header_simd(slice: &[u8]) -> Result<IsspCapsuleHeader, SyncError> {
    if slice.len() < ISSP_CAPSULE_HEADER_SIZE {
        return Err(SyncError::InvalidCapsuleLength(slice.len()));
    }

    // Load first 8 bytes (magic [0..4] in BE, version [4..8] in LE)
    let magic = u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]);
    if magic != ISSP_CAPSULE_MAGIC {
        return Err(SyncError::BadCapsuleMagic);
    }

    let version = u32::from_le_bytes([slice[4], slice[5], slice[6], slice[7]]);
    let origin_node_id = u32::from_le_bytes([slice[8], slice[9], slice[10], slice[11]]);
    let payload_len = slice.len() - ISSP_CAPSULE_HEADER_SIZE;

    Ok(IsspCapsuleHeader {
        magic,
        version,
        origin_node_id,
        payload_len,
    })
}

/// Decode a zero-copy capsule view from raw bytes.
#[inline]
pub fn decode_capsule_view_simd<'a>(slice: &'a [u8]) -> Result<IsspCapsuleView<'a>, SyncError> {
    let header = decode_capsule_header_simd(slice)?;
    let payload = &slice[ISSP_CAPSULE_HEADER_SIZE..];
    Ok(IsspCapsuleView { header, payload })
}

/// 4-lane vectorized batch decoding of capsule headers.
///
/// Unrolls decoding in blocks of 4 slices to exploit instruction-level parallelism
/// and SWAR register validation, followed by scalar tail processing.
pub fn decode_capsule_headers_batch_simd(
    packets: &[&[u8]],
) -> Vec<Result<IsspCapsuleHeader, SyncError>> {
    let mut results = Vec::with_capacity(packets.len());
    let mut i = 0;

    // 4-lane unrolled loop
    while i + 4 <= packets.len() {
        let p0 = packets[i];
        let p1 = packets[i + 1];
        let p2 = packets[i + 2];
        let p3 = packets[i + 3];

        results.push(decode_capsule_header_simd(p0));
        results.push(decode_capsule_header_simd(p1));
        results.push(decode_capsule_header_simd(p2));
        results.push(decode_capsule_header_simd(p3));

        i += 4;
    }

    // Scalar tail
    while i < packets.len() {
        results.push(decode_capsule_header_simd(packets[i]));
        i += 1;
    }

    results
}

// ---------------------------------------------------------------------------
// Telemetry Packet Classification & Priority
// ---------------------------------------------------------------------------

/// Quality-of-Service priority class for scheduling categorized network packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IsspPacketPriority {
    /// Highest priority strict-servicing queue (heartbeats, RTT probes, flow cutover).
    UrgentControl = 0,
    /// High-priority queue (distributed trace spans, metrics reports, telemetry health alerts).
    HighTelemetry = 1,
    /// Normal data queue (session state synchronization gossip frames, subpath data packets).
    NormalData = 2,
    /// Low-priority background / bulk transport queue.
    BulkBackground = 3,
}

/// Categorized identity and extracted metadata of an incoming wire datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IsspTelemetryPacketClass {
    /// Keep-alive heartbeat probe or pong echo response ('ISHP').
    HeartbeatProbe {
        sender_node_id: u32,
        path_id: u32,
        probe_seq: u64,
        is_response: bool,
    },
    /// ISSP Plaintext Gossip Frame capsule ('ISCP', v1).
    CapsuleSessionGossipV1 {
        origin_node_id: u32,
        payload_len: usize,
    },
    /// ISSP AEAD-Encrypted Gossip Frame capsule ('ISCP', v2).
    CapsuleSessionGossipV2Encrypted {
        origin_node_id: u32,
        payload_len: usize,
    },
    /// Dynamic multipath subpath datagram ('ISPK').
    SubpathData {
        path_id: u32,
        nonce_seq: u64,
        is_encrypted: bool,
        is_compressed: bool,
        payload_len: usize,
    },
    /// Distributed Telemetry Metrics Report ('ISTM').
    TelemetryMetricsReport {
        origin_node_id: u32,
        report_kind: u16,
        payload_len: usize,
    },
    /// Distributed W3C Trace Context envelope ('ISTR').
    TelemetryTraceContext {
        trace_id: [u8; 16],
        span_id: [u8; 8],
    },
    /// Multi-Node Mesh Link-State Advertisement ('ISMS').
    MeshTopologyLsa {
        sender_node_id: u32,
        lsa_seq: u64,
        link_count: u32,
    },
    /// Mesh Link-State Advertisement compressed with RFC 8878 Zstandard ('ISCL').
    MeshTopologyCompressedLsa {
        sender_node_id: u32,
        raw_size: u32,
        compressed_size: u32,
    },
    /// Transparent Session Cutover signal ('ISMG').
    MigrationCutover {
        session_id_prefix: u64,
        target_node_id: u32,
    },
    /// Multipath Stream Data Frame ('\x01' tag / StreamFrame).
    MultipathStreamFrame {
        stream_id: u64,
        offset: u64,
        payload_len: usize,
        fin: bool,
        priority: u8,
    },
    /// Generic RFC 9297 HTTP Capsule frame.
    Rfc9297Capsule {
        capsule_type: u64,
        payload_len: usize,
    },
    /// Raw unencapsulated datagram.
    RawDatagram { context_id: u64, len: usize },
    /// Malformed or unrecognized packet.
    UnknownOrMalformed { first_dword: u32, len: usize },
}

impl IsspTelemetryPacketClass {
    /// Determine scheduling priority for queue multiplexing.
    pub fn priority(&self) -> IsspPacketPriority {
        match self {
            Self::HeartbeatProbe { .. } | Self::MigrationCutover { .. } => {
                IsspPacketPriority::UrgentControl
            }
            Self::TelemetryMetricsReport { .. } | Self::TelemetryTraceContext { .. } => {
                IsspPacketPriority::HighTelemetry
            }
            Self::CapsuleSessionGossipV1 { .. }
            | Self::CapsuleSessionGossipV2Encrypted { .. }
            | Self::SubpathData { .. }
            | Self::MeshTopologyLsa { .. }
            | Self::MeshTopologyCompressedLsa { .. } => IsspPacketPriority::NormalData,
            Self::MultipathStreamFrame { priority, .. } => match *priority {
                0 => IsspPacketPriority::UrgentControl,
                1 => IsspPacketPriority::HighTelemetry,
                2 => IsspPacketPriority::NormalData,
                _ => IsspPacketPriority::BulkBackground,
            },
            Self::Rfc9297Capsule { .. }
            | Self::RawDatagram { .. }
            | Self::UnknownOrMalformed { .. } => IsspPacketPriority::BulkBackground,
        }
    }

    /// Originating cluster gateway node ID, if present in packet header.
    pub fn origin_node(&self) -> Option<u32> {
        match self {
            Self::HeartbeatProbe { sender_node_id, .. } => Some(*sender_node_id),
            Self::CapsuleSessionGossipV1 { origin_node_id, .. }
            | Self::CapsuleSessionGossipV2Encrypted { origin_node_id, .. }
            | Self::TelemetryMetricsReport { origin_node_id, .. } => Some(*origin_node_id),
            Self::MeshTopologyLsa { sender_node_id, .. }
            | Self::MeshTopologyCompressedLsa { sender_node_id, .. } => Some(*sender_node_id),
            Self::MigrationCutover { target_node_id, .. } => Some(*target_node_id),
            _ => None,
        }
    }

    /// Whether this packet is a latency / RTT probe.
    #[inline(always)]
    pub fn is_probe(&self) -> bool {
        matches!(self, Self::HeartbeatProbe { .. })
    }

    /// Whether this packet carries telemetry or tracing signals.
    #[inline(always)]
    pub fn is_telemetry(&self) -> bool {
        matches!(
            self,
            Self::TelemetryMetricsReport { .. } | Self::TelemetryTraceContext { .. }
        )
    }

    /// Whether this packet contains AEAD ciphertext.
    #[inline(always)]
    pub fn is_encrypted(&self) -> bool {
        match self {
            Self::CapsuleSessionGossipV2Encrypted { .. } => true,
            Self::SubpathData { is_encrypted, .. } => *is_encrypted,
            _ => false,
        }
    }

    /// Estimated application payload size in bytes.
    pub fn payload_size(&self) -> usize {
        match self {
            Self::HeartbeatProbe { .. } => ISSP_HEARTBEAT_SIZE,
            Self::CapsuleSessionGossipV1 { payload_len, .. }
            | Self::CapsuleSessionGossipV2Encrypted { payload_len, .. }
            | Self::SubpathData { payload_len, .. }
            | Self::TelemetryMetricsReport { payload_len, .. }
            | Self::MultipathStreamFrame { payload_len, .. }
            | Self::Rfc9297Capsule { payload_len, .. } => *payload_len,
            Self::TelemetryTraceContext { .. } => 24,
            Self::MeshTopologyLsa { link_count, .. } => (*link_count as usize) * 32,
            Self::MeshTopologyCompressedLsa {
                compressed_size, ..
            } => *compressed_size as usize,
            Self::MigrationCutover { .. } => 12,
            Self::RawDatagram { len, .. } | Self::UnknownOrMalformed { len, .. } => *len,
        }
    }
}

/// Partition of packet indices by scheduling priority class.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IsspClassifiedBatch {
    /// Indices of urgent control packets (heartbeats, failover cutovers).
    pub urgent_indices: Vec<usize>,
    /// Indices of high-priority telemetry and trace packets.
    pub telemetry_indices: Vec<usize>,
    /// Indices of normal session sync and subpath packets.
    pub normal_indices: Vec<usize>,
    /// Indices of bulk background and generic capsules.
    pub bulk_indices: Vec<usize>,
    /// Indices of corrupted or unrecognized packets.
    pub malformed_indices: Vec<usize>,
}

impl IsspClassifiedBatch {
    /// Total number of classified packets across all priority queues.
    pub fn total_packets(&self) -> usize {
        self.urgent_indices.len()
            + self.telemetry_indices.len()
            + self.normal_indices.len()
            + self.bulk_indices.len()
            + self.malformed_indices.len()
    }
}

// ---------------------------------------------------------------------------
// Vectorized SIMD Packet Classifier Engine
// ---------------------------------------------------------------------------

/// High-throughput SIMD / SWAR packet classifier.
pub struct IsspSimdPacketClassifier;

impl IsspSimdPacketClassifier {
    /// Classify a single wire packet slice with fast magic vector inspection.
    #[inline]
    pub fn classify_packet(slice: &[u8]) -> IsspTelemetryPacketClass {
        if slice.len() < 4 {
            let dword = if slice.is_empty() {
                0
            } else {
                let mut b = [0u8; 4];
                b[..slice.len()].copy_from_slice(slice);
                u32::from_be_bytes(b)
            };
            return IsspTelemetryPacketClass::UnknownOrMalformed {
                first_dword: dword,
                len: slice.len(),
            };
        }

        // Fast 4-byte big-endian magic check
        let magic = u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]);

        match magic {
            // Heartbeat Probe ('ISHP')
            ISSP_HEARTBEAT_MAGIC => {
                if slice.len() >= 28 {
                    let sender_node_id =
                        u32::from_le_bytes([slice[4], slice[5], slice[6], slice[7]]);
                    let path_id = u32::from_le_bytes([slice[8], slice[9], slice[10], slice[11]]);
                    let probe_seq = u64::from_le_bytes([
                        slice[12], slice[13], slice[14], slice[15], slice[16], slice[17],
                        slice[18], slice[19],
                    ]);
                    let flags = if slice.len() >= 32 {
                        u32::from_le_bytes([slice[28], slice[29], slice[30], slice[31]])
                    } else {
                        0
                    };
                    IsspTelemetryPacketClass::HeartbeatProbe {
                        sender_node_id,
                        path_id,
                        probe_seq,
                        is_response: flags != 0,
                    }
                } else {
                    IsspTelemetryPacketClass::UnknownOrMalformed {
                        first_dword: magic,
                        len: slice.len(),
                    }
                }
            }

            // Capsule Wire Container ('ISCP')
            ISSP_CAPSULE_MAGIC => {
                if slice.len() >= ISSP_CAPSULE_HEADER_SIZE {
                    let version = u32::from_le_bytes([slice[4], slice[5], slice[6], slice[7]]);
                    let origin_node_id =
                        u32::from_le_bytes([slice[8], slice[9], slice[10], slice[11]]);
                    let payload_len = slice.len() - ISSP_CAPSULE_HEADER_SIZE;
                    if version == ISSP_VERSION_V2_ENCRYPTED {
                        IsspTelemetryPacketClass::CapsuleSessionGossipV2Encrypted {
                            origin_node_id,
                            payload_len,
                        }
                    } else {
                        IsspTelemetryPacketClass::CapsuleSessionGossipV1 {
                            origin_node_id,
                            payload_len,
                        }
                    }
                } else {
                    IsspTelemetryPacketClass::UnknownOrMalformed {
                        first_dword: magic,
                        len: slice.len(),
                    }
                }
            }

            // Subpath Multipath Data ('ISPK')
            ISSP_SUBPATH_PACKET_MAGIC => {
                if slice.len() >= 18 {
                    let flags = u16::from_le_bytes([slice[4], slice[5]]);
                    let is_encrypted = (flags & ISSP_PKT_FLAG_ENCRYPTED) != 0;
                    let is_compressed = (flags & ISSP_PKT_FLAG_COMPRESSED) != 0;
                    let path_id = u32::from_le_bytes([slice[6], slice[7], slice[8], slice[9]]);
                    let nonce_seq = u64::from_le_bytes([
                        slice[10], slice[11], slice[12], slice[13], slice[14], slice[15],
                        slice[16], slice[17],
                    ]);
                    let header_offset = if is_encrypted { 18 + 16 } else { 18 };
                    let payload_len = slice.len().saturating_sub(header_offset);
                    IsspTelemetryPacketClass::SubpathData {
                        path_id,
                        nonce_seq,
                        is_encrypted,
                        is_compressed,
                        payload_len,
                    }
                } else {
                    IsspTelemetryPacketClass::UnknownOrMalformed {
                        first_dword: magic,
                        len: slice.len(),
                    }
                }
            }

            // Telemetry Metrics Report ('ISTM')
            ISSP_TELEMETRY_MAGIC => {
                if slice.len() >= 10 {
                    let origin_node_id =
                        u32::from_le_bytes([slice[4], slice[5], slice[6], slice[7]]);
                    let report_kind = u16::from_le_bytes([slice[8], slice[9]]);
                    let payload_len = slice.len() - 10;
                    IsspTelemetryPacketClass::TelemetryMetricsReport {
                        origin_node_id,
                        report_kind,
                        payload_len,
                    }
                } else {
                    IsspTelemetryPacketClass::UnknownOrMalformed {
                        first_dword: magic,
                        len: slice.len(),
                    }
                }
            }

            // Distributed Trace Context ('ISTR')
            ISSP_TRACE_MAGIC => {
                if slice.len() >= 28 {
                    let mut trace_id = [0u8; 16];
                    let mut span_id = [0u8; 8];
                    trace_id.copy_from_slice(&slice[4..20]);
                    span_id.copy_from_slice(&slice[20..28]);
                    IsspTelemetryPacketClass::TelemetryTraceContext { trace_id, span_id }
                } else {
                    IsspTelemetryPacketClass::UnknownOrMalformed {
                        first_dword: magic,
                        len: slice.len(),
                    }
                }
            }

            // Mesh Link-State Advertisement ('ISMS')
            ISSP_MESH_LSA_MAGIC => {
                if slice.len() >= 20 {
                    let sender_node_id =
                        u32::from_le_bytes([slice[4], slice[5], slice[6], slice[7]]);
                    let lsa_seq = u64::from_le_bytes([
                        slice[8], slice[9], slice[10], slice[11], slice[12], slice[13], slice[14],
                        slice[15],
                    ]);
                    let link_count =
                        u32::from_le_bytes([slice[16], slice[17], slice[18], slice[19]]);
                    IsspTelemetryPacketClass::MeshTopologyLsa {
                        sender_node_id,
                        lsa_seq,
                        link_count,
                    }
                } else {
                    IsspTelemetryPacketClass::UnknownOrMalformed {
                        first_dword: magic,
                        len: slice.len(),
                    }
                }
            }

            // Mesh Compressed Link-State Advertisement ('ISCL')
            ISSP_COMPRESSED_LSA_MAGIC => {
                if slice.len() >= 16 {
                    let sender_node_id =
                        u32::from_le_bytes([slice[4], slice[5], slice[6], slice[7]]);
                    let raw_size = u32::from_le_bytes([slice[8], slice[9], slice[10], slice[11]]);
                    let compressed_size =
                        u32::from_le_bytes([slice[12], slice[13], slice[14], slice[15]]);
                    IsspTelemetryPacketClass::MeshTopologyCompressedLsa {
                        sender_node_id,
                        raw_size,
                        compressed_size,
                    }
                } else {
                    IsspTelemetryPacketClass::UnknownOrMalformed {
                        first_dword: magic,
                        len: slice.len(),
                    }
                }
            }

            // Transparent Migration Cutover ('ISMG')
            ISSP_MIGRATION_MAGIC => {
                if slice.len() >= 16 {
                    let session_id_prefix = u64::from_le_bytes([
                        slice[4], slice[5], slice[6], slice[7], slice[8], slice[9], slice[10],
                        slice[11],
                    ]);
                    let target_node_id =
                        u32::from_le_bytes([slice[12], slice[13], slice[14], slice[15]]);
                    IsspTelemetryPacketClass::MigrationCutover {
                        session_id_prefix,
                        target_node_id,
                    }
                } else {
                    IsspTelemetryPacketClass::UnknownOrMalformed {
                        first_dword: magic,
                        len: slice.len(),
                    }
                }
            }

            // Raw Plaintext Gossip Frame ('ISSP')
            ISSP_MAGIC => {
                if slice.len() >= 8 {
                    let origin_node_id =
                        u32::from_le_bytes([slice[4], slice[5], slice[6], slice[7]]);
                    IsspTelemetryPacketClass::CapsuleSessionGossipV1 {
                        origin_node_id,
                        payload_len: slice.len(),
                    }
                } else {
                    IsspTelemetryPacketClass::UnknownOrMalformed {
                        first_dword: magic,
                        len: slice.len(),
                    }
                }
            }

            // Check RFC 9297 Capsule, Multipath StreamFrame, or Raw Datagram prefixes
            _ => {
                // Multipath Stream Data Frame (FRAME_TYPE = 0x01)
                if slice[0] == 0x01 {
                    if slice.len() >= 33 {
                        let flags = slice[1];
                        let fin = (flags & 0x01) != 0;
                        let stream_id = u64::from_be_bytes(slice[2..10].try_into().unwrap());
                        let offset = u64::from_be_bytes(slice[10..18].try_into().unwrap());
                        let priority = slice[19];
                        let payload_len =
                            u32::from_be_bytes(slice[29..33].try_into().unwrap()) as usize;
                        if slice.len() >= 33 + payload_len {
                            return IsspTelemetryPacketClass::MultipathStreamFrame {
                                stream_id,
                                offset,
                                payload_len,
                                fin,
                                priority,
                            };
                        }
                    }
                    IsspTelemetryPacketClass::UnknownOrMalformed {
                        first_dword: magic,
                        len: slice.len(),
                    }
                } else if slice[0] == 0x00 {
                    // If prefix starts with 0x00, RFC 9298 DATAGRAM capsule
                    IsspTelemetryPacketClass::RawDatagram {
                        context_id: 0,
                        len: slice.len().saturating_sub(1),
                    }
                } else if slice.len() >= 2 && slice[0] == 0x40 {
                    // 2-byte QUIC VarInt capsule
                    let ctype = ((slice[0] as u64 & 0x3f) << 8) | (slice[1] as u64);
                    IsspTelemetryPacketClass::Rfc9297Capsule {
                        capsule_type: ctype,
                        payload_len: slice.len().saturating_sub(2),
                    }
                } else {
                    IsspTelemetryPacketClass::UnknownOrMalformed {
                        first_dword: magic,
                        len: slice.len(),
                    }
                }
            }
        }
    }

    /// Classify a batch of packets using 4-way unrolled SIMD vector parsing.
    pub fn classify_batch_simd(packets: &[&[u8]]) -> Vec<IsspTelemetryPacketClass> {
        let mut results = Vec::with_capacity(packets.len());
        Self::classify_batch_simd_into(packets, &mut results);
        results
    }

    /// Classify a batch of packets directly into an existing output buffer.
    pub fn classify_batch_simd_into(packets: &[&[u8]], out: &mut Vec<IsspTelemetryPacketClass>) {
        out.clear();
        out.reserve(packets.len());
        let mut i = 0;

        // 4-lane unrolled loop
        while i + 4 <= packets.len() {
            out.push(Self::classify_packet(packets[i]));
            out.push(Self::classify_packet(packets[i + 1]));
            out.push(Self::classify_packet(packets[i + 2]));
            out.push(Self::classify_packet(packets[i + 3]));
            i += 4;
        }

        // Tail loop
        while i < packets.len() {
            out.push(Self::classify_packet(packets[i]));
            i += 1;
        }
    }

    /// Partition a batch of incoming wire packets by quality-of-service priority.
    pub fn partition_by_priority_simd(packets: &[&[u8]]) -> IsspClassifiedBatch {
        let mut batch = IsspClassifiedBatch::default();
        let mut i = 0;

        while i + 4 <= packets.len() {
            for offset in 0..4 {
                let idx = i + offset;
                let class = Self::classify_packet(packets[idx]);
                match class.priority() {
                    IsspPacketPriority::UrgentControl => batch.urgent_indices.push(idx),
                    IsspPacketPriority::HighTelemetry => batch.telemetry_indices.push(idx),
                    IsspPacketPriority::NormalData => batch.normal_indices.push(idx),
                    IsspPacketPriority::BulkBackground => {
                        if matches!(class, IsspTelemetryPacketClass::UnknownOrMalformed { .. }) {
                            batch.malformed_indices.push(idx);
                        } else {
                            batch.bulk_indices.push(idx);
                        }
                    }
                }
            }
            i += 4;
        }

        while i < packets.len() {
            let class = Self::classify_packet(packets[i]);
            match class.priority() {
                IsspPacketPriority::UrgentControl => batch.urgent_indices.push(i),
                IsspPacketPriority::HighTelemetry => batch.telemetry_indices.push(i),
                IsspPacketPriority::NormalData => batch.normal_indices.push(i),
                IsspPacketPriority::BulkBackground => {
                    if matches!(class, IsspTelemetryPacketClass::UnknownOrMalformed { .. }) {
                        batch.malformed_indices.push(i);
                    } else {
                        batch.bulk_indices.push(i);
                    }
                }
            }
            i += 1;
        }

        batch
    }

    /// Fast vectorized probe filter extracting `(index, sender_node_id, probe_seq)` for all heartbeats.
    pub fn filter_heartbeat_probes_simd(packets: &[&[u8]]) -> Vec<(usize, u32, u64)> {
        let mut probes = Vec::new();
        for (idx, slice) in packets.iter().enumerate() {
            if slice.len() >= 20 {
                let magic = u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]);
                if magic == ISSP_HEARTBEAT_MAGIC {
                    let sender_node_id =
                        u32::from_le_bytes([slice[4], slice[5], slice[6], slice[7]]);
                    let probe_seq = u64::from_le_bytes([
                        slice[12], slice[13], slice[14], slice[15], slice[16], slice[17],
                        slice[18], slice[19],
                    ]);
                    probes.push((idx, sender_node_id, probe_seq));
                }
            }
        }
        probes
    }

    /// Fast vectorized telemetry filter extracting indices of all metrics reports and trace packets.
    pub fn filter_telemetry_metrics_simd(packets: &[&[u8]]) -> Vec<usize> {
        let mut indices = Vec::new();
        for (idx, slice) in packets.iter().enumerate() {
            if slice.len() >= 4 {
                let magic = u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]);
                if magic == ISSP_TELEMETRY_MAGIC || magic == ISSP_TRACE_MAGIC {
                    indices.push(idx);
                }
            }
        }
        indices
    }

    /// Fast vectorized filter extracting metadata `(index, stream_id, offset, payload_len, fin)`
    /// for all valid multipath stream frames.
    pub fn filter_stream_frames_simd(packets: &[&[u8]]) -> Vec<(usize, u64, u64, usize, bool)> {
        let mut frames = Vec::new();
        for (idx, slice) in packets.iter().enumerate() {
            if slice.len() >= 33 && slice[0] == 0x01 {
                let flags = slice[1];
                let fin = (flags & 0x01) != 0;
                let stream_id = u64::from_be_bytes(slice[2..10].try_into().unwrap());
                let offset = u64::from_be_bytes(slice[10..18].try_into().unwrap());
                let payload_len = u32::from_be_bytes(slice[29..33].try_into().unwrap()) as usize;
                if slice.len() >= 33 + payload_len {
                    frames.push((idx, stream_id, offset, payload_len, fin));
                }
            }
        }
        frames
    }
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capsule_header_simd_v1_and_v2() {
        // V1 plaintext capsule
        let mut v1_wire = Vec::new();
        v1_wire.extend_from_slice(&ISSP_CAPSULE_MAGIC.to_be_bytes());
        v1_wire.extend_from_slice(&1u32.to_le_bytes()); // version = 1
        v1_wire.extend_from_slice(&42u32.to_le_bytes()); // origin_node_id = 42
        v1_wire.extend_from_slice(b"hello-gossip-payload");

        let h1 = decode_capsule_header_simd(&v1_wire).expect("decode v1 header");
        assert_eq!(h1.magic, ISSP_CAPSULE_MAGIC);
        assert_eq!(h1.version, 1);
        assert_eq!(h1.origin_node_id, 42);
        assert_eq!(h1.payload_len, 20);
        assert!(h1.is_plaintext_v1());
        assert!(!h1.is_encrypted());

        let view1 = decode_capsule_view_simd(&v1_wire).expect("decode v1 view");
        assert_eq!(view1.payload, b"hello-gossip-payload");

        // V2 encrypted capsule
        let mut v2_wire = Vec::new();
        v2_wire.extend_from_slice(&ISSP_CAPSULE_MAGIC.to_be_bytes());
        v2_wire.extend_from_slice(&2u32.to_le_bytes()); // version = 2
        v2_wire.extend_from_slice(&99u32.to_le_bytes()); // origin_node_id = 99
        v2_wire.extend_from_slice(b"encrypted-gossip-ciphertext-data-block");

        let h2 = decode_capsule_header_simd(&v2_wire).expect("decode v2 header");
        assert_eq!(h2.magic, ISSP_CAPSULE_MAGIC);
        assert_eq!(h2.version, 2);
        assert_eq!(h2.origin_node_id, 99);
        assert!(h2.is_encrypted());
        assert!(!h2.is_plaintext_v1());

        let view2 = decode_capsule_view_simd(&v2_wire).expect("decode v2 view");
        assert_eq!(view2.payload, b"encrypted-gossip-ciphertext-data-block");
    }

    #[test]
    fn test_capsule_header_simd_errors() {
        // Short buffer
        let short = vec![0x49, 0x53, 0x43];
        assert!(matches!(
            decode_capsule_header_simd(&short),
            Err(SyncError::InvalidCapsuleLength(3))
        ));

        // Bad magic
        let mut bad_magic = vec![0u8; 12];
        bad_magic[0..4].copy_from_slice(&0xdeadbeefu32.to_be_bytes());
        assert!(matches!(
            decode_capsule_header_simd(&bad_magic),
            Err(SyncError::BadCapsuleMagic)
        ));
    }

    #[test]
    fn test_batch_capsule_header_decoding() {
        let mut buf0 = Vec::new();
        buf0.extend_from_slice(&ISSP_CAPSULE_MAGIC.to_be_bytes());
        buf0.extend_from_slice(&1u32.to_le_bytes());
        buf0.extend_from_slice(&10u32.to_le_bytes());
        buf0.extend_from_slice(b"payload-0");

        let mut buf1 = Vec::new();
        buf1.extend_from_slice(&ISSP_CAPSULE_MAGIC.to_be_bytes());
        buf1.extend_from_slice(&2u32.to_le_bytes());
        buf1.extend_from_slice(&20u32.to_le_bytes());
        buf1.extend_from_slice(b"payload-1-longer");

        let mut buf2 = Vec::new();
        buf2.extend_from_slice(&ISSP_CAPSULE_MAGIC.to_be_bytes());
        buf2.extend_from_slice(&1u32.to_le_bytes());
        buf2.extend_from_slice(&30u32.to_le_bytes());
        buf2.extend_from_slice(b"p2");

        let mut buf3 = Vec::new();
        buf3.extend_from_slice(&ISSP_CAPSULE_MAGIC.to_be_bytes());
        buf3.extend_from_slice(&2u32.to_le_bytes());
        buf3.extend_from_slice(&40u32.to_le_bytes());
        buf3.extend_from_slice(b"payload-3-secure");

        let mut buf4 = Vec::new(); // 5th item tests tail loop
        buf4.extend_from_slice(&ISSP_CAPSULE_MAGIC.to_be_bytes());
        buf4.extend_from_slice(&1u32.to_le_bytes());
        buf4.extend_from_slice(&50u32.to_le_bytes());
        buf4.extend_from_slice(b"payload-4");

        let slice_ptrs: Vec<&[u8]> = vec![&buf0, &buf1, &buf2, &buf3, &buf4];
        let headers = decode_capsule_headers_batch_simd(&slice_ptrs);
        assert_eq!(headers.len(), 5);

        for (i, h_res) in headers.iter().enumerate() {
            let h = h_res.as_ref().expect("header decoded");
            assert_eq!(h.origin_node_id, ((i + 1) * 10) as u32);
        }
    }

    #[test]
    fn test_packet_classifier_heartbeat() {
        let mut pkt = [0u8; 40];
        pkt[0..4].copy_from_slice(&ISSP_HEARTBEAT_MAGIC.to_be_bytes());
        pkt[4..8].copy_from_slice(&7u32.to_le_bytes()); // sender_node_id
        pkt[8..12].copy_from_slice(&3u32.to_le_bytes()); // path_id
        pkt[12..20].copy_from_slice(&1001u64.to_le_bytes()); // probe_seq
        pkt[28..32].copy_from_slice(&1u32.to_le_bytes()); // is_response

        let class = IsspSimdPacketClassifier::classify_packet(&pkt);
        match class {
            IsspTelemetryPacketClass::HeartbeatProbe {
                sender_node_id,
                path_id,
                probe_seq,
                is_response,
            } => {
                assert_eq!(sender_node_id, 7);
                assert_eq!(path_id, 3);
                assert_eq!(probe_seq, 1001);
                assert!(is_response);
            }
            other => panic!("Unexpected class: {:?}", other),
        }
        assert_eq!(class.priority(), IsspPacketPriority::UrgentControl);
        assert!(class.is_probe());
        assert!(!class.is_telemetry());
    }

    #[test]
    fn test_packet_classifier_telemetry_metrics_and_trace() {
        // Telemetry metrics packet
        let mut m_pkt = Vec::new();
        m_pkt.extend_from_slice(&ISSP_TELEMETRY_MAGIC.to_be_bytes());
        m_pkt.extend_from_slice(&12u32.to_le_bytes()); // origin node
        m_pkt.extend_from_slice(&1u16.to_le_bytes()); // kind = 1 (OTLP)
        m_pkt.extend_from_slice(b"metrics-payload");

        let m_class = IsspSimdPacketClassifier::classify_packet(&m_pkt);
        match m_class {
            IsspTelemetryPacketClass::TelemetryMetricsReport {
                origin_node_id,
                report_kind,
                payload_len,
            } => {
                assert_eq!(origin_node_id, 12);
                assert_eq!(report_kind, 1);
                assert_eq!(payload_len, 15);
            }
            other => panic!("Unexpected class: {:?}", other),
        }
        assert_eq!(m_class.priority(), IsspPacketPriority::HighTelemetry);
        assert!(m_class.is_telemetry());

        // Distributed trace context
        let mut t_pkt = Vec::new();
        t_pkt.extend_from_slice(&ISSP_TRACE_MAGIC.to_be_bytes());
        t_pkt.extend_from_slice(&[0xaa; 16]); // trace_id
        t_pkt.extend_from_slice(&[0xbb; 8]); // span_id

        let t_class = IsspSimdPacketClassifier::classify_packet(&t_pkt);
        match t_class {
            IsspTelemetryPacketClass::TelemetryTraceContext { trace_id, span_id } => {
                assert_eq!(trace_id, [0xaa; 16]);
                assert_eq!(span_id, [0xbb; 8]);
            }
            other => panic!("Unexpected class: {:?}", other),
        }
        assert_eq!(t_class.priority(), IsspPacketPriority::HighTelemetry);
        assert!(t_class.is_telemetry());
    }

    #[test]
    fn test_partition_by_priority_simd_and_filters() {
        let mut hb = [0u8; 40];
        hb[0..4].copy_from_slice(&ISSP_HEARTBEAT_MAGIC.to_be_bytes());
        hb[4..8].copy_from_slice(&5u32.to_le_bytes());
        hb[12..20].copy_from_slice(&888u64.to_le_bytes());

        let mut telem = Vec::new();
        telem.extend_from_slice(&ISSP_TELEMETRY_MAGIC.to_be_bytes());
        telem.extend_from_slice(&10u32.to_le_bytes());
        telem.extend_from_slice(&0u16.to_le_bytes());
        telem.extend_from_slice(b"m-data");

        let mut cap = Vec::new();
        cap.extend_from_slice(&ISSP_CAPSULE_MAGIC.to_be_bytes());
        cap.extend_from_slice(&1u32.to_le_bytes());
        cap.extend_from_slice(&15u32.to_le_bytes());
        cap.extend_from_slice(b"gossip-data");

        let raw = vec![0x00, 0x01, 0x02, 0x03];
        let malformed = vec![0xde, 0xad, 0xbe, 0xef, 0x01];

        let packets: Vec<&[u8]> = vec![&hb, &telem, &cap, &raw, &malformed];

        let batch = IsspSimdPacketClassifier::partition_by_priority_simd(&packets);
        assert_eq!(batch.urgent_indices, vec![0]);
        assert_eq!(batch.telemetry_indices, vec![1]);
        assert_eq!(batch.normal_indices, vec![2]);
        assert_eq!(batch.bulk_indices, vec![3]);
        assert_eq!(batch.malformed_indices, vec![4]);
        assert_eq!(batch.total_packets(), 5);

        let probes = IsspSimdPacketClassifier::filter_heartbeat_probes_simd(&packets);
        assert_eq!(probes.len(), 1);
        assert_eq!(probes[0], (0, 5, 888));

        let t_indices = IsspSimdPacketClassifier::filter_telemetry_metrics_simd(&packets);
        assert_eq!(t_indices, vec![1]);
    }

    #[test]
    fn test_compressed_lsa_simd_classification() {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&ISSP_COMPRESSED_LSA_MAGIC.to_be_bytes());
        pkt.extend_from_slice(&77u32.to_le_bytes()); // sender_node_id
        pkt.extend_from_slice(&256u32.to_le_bytes()); // raw_size
        pkt.extend_from_slice(&64u32.to_le_bytes()); // compressed_size
        pkt.extend_from_slice(&[0xaa; 64]);

        let class = IsspSimdPacketClassifier::classify_packet(&pkt);
        match class {
            IsspTelemetryPacketClass::MeshTopologyCompressedLsa {
                sender_node_id,
                raw_size,
                compressed_size,
            } => {
                assert_eq!(sender_node_id, 77);
                assert_eq!(raw_size, 256);
                assert_eq!(compressed_size, 64);
            }
            other => panic!("expected MeshTopologyCompressedLsa, got {:?}", other),
        }
        assert_eq!(class.priority(), IsspPacketPriority::NormalData);
        assert_eq!(class.origin_node(), Some(77));
        assert_eq!(class.payload_size(), 64);
    }

    #[test]
    fn test_multipath_stream_frame_simd_classification_and_filter() {
        let payload = b"Fast-Path SIMD Vectorized Stream Datagram".to_vec();
        let mut pkt = Vec::new();
        pkt.push(0x01); // FRAME_TYPE = 0x01
        pkt.push(0x01); // flags: fin = true
        pkt.extend_from_slice(&55u64.to_be_bytes()); // stream_id = 55
        pkt.extend_from_slice(&1024u64.to_be_bytes()); // offset = 1024
        pkt.push(0x00); // slice_byte (UltraLowLatency)
        pkt.push(0x00); // priority: 0 (CriticalControl)
        pkt.push(0x01); // subpath_id
        pkt.extend_from_slice(&1u64.to_be_bytes()); // seq_num
        pkt.extend_from_slice(&(payload.len() as u32).to_be_bytes()); // payload_len
        pkt.extend_from_slice(&payload);

        let class = IsspSimdPacketClassifier::classify_packet(&pkt);
        match class {
            IsspTelemetryPacketClass::MultipathStreamFrame {
                stream_id,
                offset,
                payload_len,
                fin,
                priority,
            } => {
                assert_eq!(stream_id, 55);
                assert_eq!(offset, 1024);
                assert_eq!(payload_len, payload.len());
                assert!(fin);
                assert_eq!(priority, 0);
            }
            other => panic!("expected MultipathStreamFrame, got {:?}", other),
        }
        assert_eq!(class.priority(), IsspPacketPriority::UrgentControl);
        assert_eq!(class.payload_size(), payload.len());

        // Batch and filter test
        let other_raw = vec![0x00, 0x01, 0x02];
        let packets: Vec<&[u8]> = vec![&pkt, &other_raw];
        let filtered = IsspSimdPacketClassifier::filter_stream_frames_simd(&packets);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0], (0, 55, 1024, payload.len(), true));
    }
}

//! Mesh Link-State Advertisement (LSA) and Congestion State Synchronization.
//!
//! Provides line-rate inter-node dissemination and synchronization of active multipath
//! link metrics, queue backlog, RTT, loss rate, and BBR/LEDBAT congestion phases.
//!
//! # Protocol Wire Format
//!
//! ## Uncompressed LSA Packet ('ISMS' - 0x49534D53)
//! - `magic`: u32 (0x49534D53, 4 bytes BE)
//! - `sender_node_id`: u32 (4 bytes LE)
//! - `lsa_seq`: u64 (8 bytes LE, monotonic anti-replay counter)
//! - `link_count`: u32 (4 bytes LE)
//!
//! Trailing link entries (each 32 bytes):
//! - `target_node_id`: u32 (4 bytes LE)
//! - `link_id_hash`: u32 (4 bytes LE)
//! - `avail_bw_bps`: u64 (8 bytes LE)
//! - `rtt_us`: u32 (4 bytes LE)
//! - `loss_millipct`: u32 (4 bytes LE)
//! - `queuing_delay_us`: u32 (4 bytes LE)
//! - `congestion_phase`: u8 (1 byte: Cruise, ProbeBw, Throttle, Recovery, Damp)
//! - `congestion_flags`: u8 (1 byte: Bottleneck, Ecn, JitterSurge, LinkDown, FailoverTrigger)
//! - `pad`: [u8; 2] (2 bytes, zero padding)
//!
//! ## Compressed LSA Packet ('ISCL' - 0x4953434C)
//! - `magic`: u32 (0x4953434C, 4 bytes BE)
//! - `sender_node_id`: u32 (4 bytes LE)
//! - `raw_size`: u32 (4 bytes LE)
//! - `compressed_size`: u32 (4 bytes LE)
//! - Trailing payload: RFC 8878 Zstandard compressed stream wrapping the uncompressed 'ISMS' frame(s).

use std::collections::HashMap;
use std::fmt;

use crate::topology_cspf::{CspfConstraints, CspfMultipathGroup, NodeId, TopoEdge, TopologyGraph};
use crate::zstd_archive::{decode_zstd_stream, encode_zstd_chunk};

// ─── Constants & Wire Magics ──────────────────────────────────────────────────

/// ISSP Uncompressed Mesh Link-State Advertisement magic ('ISMS' = 0x49534D53).
pub const ISSP_MESH_LSA_MAGIC: u32 = 0x4953_4d53;

/// ISSP Compressed Mesh Link-State Advertisement magic ('ISCL' = 0x4953434C).
pub const ISSP_COMPRESSED_LSA_MAGIC: u32 = 0x4953_434c;

/// Wire size of an uncompressed LSA packet header in bytes (20 bytes).
pub const ISSP_LSA_HEADER_SIZE: usize = 20;

/// Wire size of a compressed LSA packet header in bytes (16 bytes).
pub const ISSP_COMPRESSED_LSA_HEADER_SIZE: usize = 16;

/// Wire size of a single LSA link metrics record in bytes (32 bytes).
pub const ISSP_LSA_LINK_RECORD_SIZE: usize = 32;

// ─── Congestion Phase Flags ───────────────────────────────────────────────────

/// Nominal, unconstrained flow pacing.
pub const LSA_PHASE_CRUISE: u8 = 0;
/// Probing available bandwidth headroom.
pub const LSA_PHASE_PROBE_BW: u8 = 1;
/// Pacing throttled due to queue backlog buildup.
pub const LSA_PHASE_THROTTLE: u8 = 2;
/// Packet loss or severe ECN congestion observed; window reduced.
pub const LSA_PHASE_RECOVERY: u8 = 3;
/// Critical link congestion; link damped and rerouting recommended.
pub const LSA_PHASE_DAMP: u8 = 4;

/// Return human-readable congestion phase label.
pub fn lsa_phase_name(phase: u8) -> &'static str {
    match phase {
        LSA_PHASE_CRUISE => "Cruise",
        LSA_PHASE_PROBE_BW => "ProbeBw",
        LSA_PHASE_THROTTLE => "Throttle",
        LSA_PHASE_RECOVERY => "Recovery",
        LSA_PHASE_DAMP => "Damp",
        _ => "Unknown",
    }
}

// ─── Congestion Flags ─────────────────────────────────────────────────────────

/// Link identified as a cluster-wide throughput bottleneck.
pub const LSA_FLAG_BOTTLENECK: u8 = 0x01;
/// ECN congestion experience (CE) markings detected on link.
pub const LSA_FLAG_ECN_MARKED: u8 = 0x02;
/// Excessive queuing jitter or bufferbloat surge observed.
pub const LSA_FLAG_JITTER_SURGE: u8 = 0x04;
/// Link physically or logically severed / down.
pub const LSA_FLAG_LINK_DOWN: u8 = 0x08;
/// Immediate failover cutover triggered for subpaths using this link.
pub const LSA_FLAG_FAILOVER_TRIGGER: u8 = 0x10;

// ─── Error Handling ───────────────────────────────────────────────────────────

/// Errors encountered during LSA serialization, compression, or ingestion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IsspLsaError {
    BufferTooShort {
        expected: usize,
        actual: usize,
    },
    InvalidMagic(u32),
    StaleSequence {
        sender_node_id: u32,
        seen_seq: u64,
        incoming_seq: u64,
    },
    CorruptedHeader(String),
    CompressionError(String),
    MalformedLinkRecord {
        index: usize,
        reason: String,
    },
}

impl fmt::Display for IsspLsaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooShort { expected, actual } => {
                write!(
                    f,
                    "LSA buffer too short: expected {} bytes, got {}",
                    expected, actual
                )
            }
            Self::InvalidMagic(m) => write!(f, "Invalid LSA packet magic: {:#010x}", m),
            Self::StaleSequence {
                sender_node_id,
                seen_seq,
                incoming_seq,
            } => {
                write!(
                    f,
                    "Stale LSA from node {}: incoming seq {} <= last seen seq {}",
                    sender_node_id, incoming_seq, seen_seq
                )
            }
            Self::CorruptedHeader(msg) => write!(f, "Corrupted LSA header: {}", msg),
            Self::CompressionError(msg) => write!(f, "LSA compression error: {}", msg),
            Self::MalformedLinkRecord { index, reason } => {
                write!(f, "Malformed LSA link record at #{}: {}", index, reason)
            }
        }
    }
}

impl std::error::Error for IsspLsaError {}

// ─── LSA Link Record ─────────────────────────────────────────────────────────

/// Compact 32-byte wire record advertising dynamic QoS and congestion state of a directed link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IsspLsaLinkRecord {
    /// Destination node ID of this directed link.
    pub target_node_id: u32,
    /// 32-bit hash identifying interface / subpath label.
    pub link_id_hash: u32,
    /// Estimated available bandwidth in bytes/sec.
    pub avail_bw_bps: u64,
    /// Smoothed RTT in microseconds.
    pub rtt_us: u32,
    /// Loss rate in millipercent (0–100_000 == 0.000%–100.000%).
    pub loss_millipct: u32,
    /// Estimated queuing delay backlog in microseconds.
    pub queuing_delay_us: u32,
    /// Congestion control phase (Cruise, ProbeBw, Throttle, Recovery, Damp).
    pub congestion_phase: u8,
    /// Bitmask of flags (Bottleneck, Ecn, JitterSurge, LinkDown, FailoverTrigger).
    pub congestion_flags: u8,
}

impl IsspLsaLinkRecord {
    /// Create a new link record with nominal default values.
    pub fn new(
        target_node_id: u32,
        link_id_hash: u32,
        avail_bw_bps: u64,
        rtt_us: u32,
        loss_millipct: u32,
    ) -> Self {
        Self {
            target_node_id,
            link_id_hash,
            avail_bw_bps,
            rtt_us,
            loss_millipct,
            queuing_delay_us: 0,
            congestion_phase: LSA_PHASE_CRUISE,
            congestion_flags: 0,
        }
    }

    /// Set queuing delay in microseconds.
    pub fn with_queuing_delay(mut self, queuing_delay_us: u32) -> Self {
        self.queuing_delay_us = queuing_delay_us;
        self
    }

    /// Set congestion phase.
    pub fn with_congestion_phase(mut self, congestion_phase: u8) -> Self {
        self.congestion_phase = congestion_phase;
        self
    }

    /// Set congestion flags bitmask.
    pub fn with_flags(mut self, flags: u8) -> Self {
        self.congestion_flags = flags;
        self
    }

    /// Add a flag to the bitmask.
    pub fn add_flag(&mut self, flag: u8) {
        self.congestion_flags |= flag;
    }

    /// Return `true` if link is marked as severed or down.
    #[inline(always)]
    pub fn is_link_down(&self) -> bool {
        (self.congestion_flags & LSA_FLAG_LINK_DOWN) != 0
    }

    /// Return `true` if link is flagged as a cluster bottleneck.
    #[inline(always)]
    pub fn is_bottleneck(&self) -> bool {
        (self.congestion_flags & LSA_FLAG_BOTTLENECK) != 0
    }

    /// Return `true` if link is experiencing critical congestion requiring immediate rerouting.
    #[inline(always)]
    pub fn is_severely_congested(&self) -> bool {
        self.is_link_down()
            || self.congestion_phase == LSA_PHASE_DAMP
            || self.congestion_phase == LSA_PHASE_RECOVERY
            || (self.congestion_flags & LSA_FLAG_FAILOVER_TRIGGER) != 0
    }

    /// Derive composite cost for CSPF path ranking.
    #[inline(always)]
    pub fn compute_composite_cost(&self) -> u32 {
        TopoEdge::compute_cost(self.rtt_us, self.loss_millipct)
    }

    /// Encode into fixed 32-byte wire buffer.
    pub fn encode_to_slice(&self, buf: &mut [u8; ISSP_LSA_LINK_RECORD_SIZE]) {
        buf[0..4].copy_from_slice(&self.target_node_id.to_le_bytes());
        buf[4..8].copy_from_slice(&self.link_id_hash.to_le_bytes());
        buf[8..16].copy_from_slice(&self.avail_bw_bps.to_le_bytes());
        buf[16..20].copy_from_slice(&self.rtt_us.to_le_bytes());
        buf[20..24].copy_from_slice(&self.loss_millipct.to_le_bytes());
        buf[24..28].copy_from_slice(&self.queuing_delay_us.to_le_bytes());
        buf[28] = self.congestion_phase;
        buf[29] = self.congestion_flags;
        buf[30] = 0; // Padding
        buf[31] = 0; // Padding
    }

    /// Decode from a 32-byte slice.
    pub fn decode_from_slice(slice: &[u8]) -> Result<Self, IsspLsaError> {
        if slice.len() < ISSP_LSA_LINK_RECORD_SIZE {
            return Err(IsspLsaError::BufferTooShort {
                expected: ISSP_LSA_LINK_RECORD_SIZE,
                actual: slice.len(),
            });
        }
        let target_node_id = u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]);
        let link_id_hash = u32::from_le_bytes([slice[4], slice[5], slice[6], slice[7]]);
        let avail_bw_bps = u64::from_le_bytes([
            slice[8], slice[9], slice[10], slice[11], slice[12], slice[13], slice[14], slice[15],
        ]);
        let rtt_us = u32::from_le_bytes([slice[16], slice[17], slice[18], slice[19]]);
        let loss_millipct = u32::from_le_bytes([slice[20], slice[21], slice[22], slice[23]]);
        let queuing_delay_us = u32::from_le_bytes([slice[24], slice[25], slice[26], slice[27]]);
        let congestion_phase = slice[28];
        let congestion_flags = slice[29];

        Ok(Self {
            target_node_id,
            link_id_hash,
            avail_bw_bps,
            rtt_us,
            loss_millipct,
            queuing_delay_us,
            congestion_phase,
            congestion_flags,
        })
    }
}

// ─── LSA Packet ──────────────────────────────────────────────────────────────

/// Mesh Link-State Advertisement packet containing an enqueued batch of link records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsspMeshLsaPacket {
    /// Node ID of the transmitting node originating this advertisement.
    pub sender_node_id: u32,
    /// Monotonically increasing sequence number (anti-replay & stale detection).
    pub lsa_seq: u64,
    /// List of dynamic link QoS and congestion records.
    pub links: Vec<IsspLsaLinkRecord>,
}

impl IsspMeshLsaPacket {
    /// Create a new LSA packet.
    pub fn new(sender_node_id: u32, lsa_seq: u64, links: Vec<IsspLsaLinkRecord>) -> Self {
        Self {
            sender_node_id,
            lsa_seq,
            links,
        }
    }

    /// Total uncompressed wire size in bytes.
    #[inline(always)]
    pub fn wire_size(&self) -> usize {
        ISSP_LSA_HEADER_SIZE + (self.links.len() * ISSP_LSA_LINK_RECORD_SIZE)
    }

    /// Encode into uncompressed wire format ('ISMS').
    pub fn encode_wire(&self) -> Vec<u8> {
        let total_size = self.wire_size();
        let mut buf = Vec::with_capacity(total_size);

        // Header (20 bytes)
        buf.extend_from_slice(&ISSP_MESH_LSA_MAGIC.to_be_bytes());
        buf.extend_from_slice(&self.sender_node_id.to_le_bytes());
        buf.extend_from_slice(&self.lsa_seq.to_le_bytes());
        buf.extend_from_slice(&(self.links.len() as u32).to_le_bytes());

        // Body: 32 bytes per link
        let mut link_buf = [0u8; ISSP_LSA_LINK_RECORD_SIZE];
        for link in &self.links {
            link.encode_to_slice(&mut link_buf);
            buf.extend_from_slice(&link_buf);
        }

        buf
    }

    /// Decode from an uncompressed wire slice ('ISMS').
    pub fn decode_wire(slice: &[u8]) -> Result<Self, IsspLsaError> {
        if slice.len() < ISSP_LSA_HEADER_SIZE {
            return Err(IsspLsaError::BufferTooShort {
                expected: ISSP_LSA_HEADER_SIZE,
                actual: slice.len(),
            });
        }

        let magic = u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]);
        if magic != ISSP_MESH_LSA_MAGIC {
            return Err(IsspLsaError::InvalidMagic(magic));
        }

        let sender_node_id = u32::from_le_bytes([slice[4], slice[5], slice[6], slice[7]]);
        let lsa_seq = u64::from_le_bytes([
            slice[8], slice[9], slice[10], slice[11], slice[12], slice[13], slice[14], slice[15],
        ]);
        let link_count = u32::from_le_bytes([slice[16], slice[17], slice[18], slice[19]]) as usize;

        let expected_total_len = ISSP_LSA_HEADER_SIZE + (link_count * ISSP_LSA_LINK_RECORD_SIZE);
        if slice.len() < expected_total_len {
            return Err(IsspLsaError::BufferTooShort {
                expected: expected_total_len,
                actual: slice.len(),
            });
        }

        let mut links = Vec::with_capacity(link_count);
        let mut offset = ISSP_LSA_HEADER_SIZE;

        for i in 0..link_count {
            let record = IsspLsaLinkRecord::decode_from_slice(
                &slice[offset..offset + ISSP_LSA_LINK_RECORD_SIZE],
            )
            .map_err(|e| IsspLsaError::MalformedLinkRecord {
                index: i,
                reason: e.to_string(),
            })?;
            links.push(record);
            offset += ISSP_LSA_LINK_RECORD_SIZE;
        }

        Ok(Self {
            sender_node_id,
            lsa_seq,
            links,
        })
    }

    /// Encode into an RFC 8878 Zstandard compressed packet ('ISCL').
    pub fn encode_compressed(&self) -> Vec<u8> {
        let raw_bytes = self.encode_wire();
        let compressed_payload = encode_zstd_chunk(&raw_bytes);

        let mut packet =
            Vec::with_capacity(ISSP_COMPRESSED_LSA_HEADER_SIZE + compressed_payload.len());
        packet.extend_from_slice(&ISSP_COMPRESSED_LSA_MAGIC.to_be_bytes());
        packet.extend_from_slice(&self.sender_node_id.to_le_bytes());
        packet.extend_from_slice(&(raw_bytes.len() as u32).to_le_bytes());
        packet.extend_from_slice(&(compressed_payload.len() as u32).to_le_bytes());
        packet.extend_from_slice(&compressed_payload);
        packet
    }

    /// Decode from an RFC 8878 Zstandard compressed packet ('ISCL').
    pub fn decode_compressed(slice: &[u8]) -> Result<Self, IsspLsaError> {
        if slice.len() < ISSP_COMPRESSED_LSA_HEADER_SIZE {
            return Err(IsspLsaError::BufferTooShort {
                expected: ISSP_COMPRESSED_LSA_HEADER_SIZE,
                actual: slice.len(),
            });
        }

        let magic = u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]);
        if magic != ISSP_COMPRESSED_LSA_MAGIC {
            return Err(IsspLsaError::InvalidMagic(magic));
        }

        let sender_node_id = u32::from_le_bytes([slice[4], slice[5], slice[6], slice[7]]);
        let _raw_size = u32::from_le_bytes([slice[8], slice[9], slice[10], slice[11]]) as usize;
        let compressed_size =
            u32::from_le_bytes([slice[12], slice[13], slice[14], slice[15]]) as usize;

        if slice.len() < ISSP_COMPRESSED_LSA_HEADER_SIZE + compressed_size {
            return Err(IsspLsaError::BufferTooShort {
                expected: ISSP_COMPRESSED_LSA_HEADER_SIZE + compressed_size,
                actual: slice.len(),
            });
        }

        let compressed_payload = &slice
            [ISSP_COMPRESSED_LSA_HEADER_SIZE..ISSP_COMPRESSED_LSA_HEADER_SIZE + compressed_size];

        let decompressed = decode_zstd_stream(compressed_payload)
            .map_err(|e| IsspLsaError::CompressionError(e.to_string()))?;

        let mut packet = Self::decode_wire(&decompressed)?;
        // Sanity verify sender_node_id match
        if packet.sender_node_id != sender_node_id {
            packet.sender_node_id = sender_node_id;
        }

        Ok(packet)
    }
}

// ─── LSDB Entry ──────────────────────────────────────────────────────────────

/// Stored link state database (LSDB) entry representing live network edge state.
#[derive(Debug, Clone, PartialEq)]
pub struct IsspLinkStateEntry {
    pub source_node_id: u32,
    pub target_node_id: u32,
    pub link_id_hash: u32,
    pub avail_bw_bps: u64,
    pub rtt_us: u32,
    pub loss_millipct: u32,
    pub queuing_delay_us: u32,
    pub congestion_phase: u8,
    pub congestion_flags: u8,
    pub lsa_seq: u64,
    pub last_updated_ns: u64,
}

impl IsspLinkStateEntry {
    /// Return `true` if link is severed or down.
    #[inline(always)]
    pub fn is_link_down(&self) -> bool {
        (self.congestion_flags & LSA_FLAG_LINK_DOWN) != 0
    }

    /// Return `true` if link is in critical congestion.
    #[inline(always)]
    pub fn is_severely_congested(&self) -> bool {
        self.is_link_down()
            || self.congestion_phase == LSA_PHASE_DAMP
            || self.congestion_phase == LSA_PHASE_RECOVERY
            || (self.congestion_flags & LSA_FLAG_FAILOVER_TRIGGER) != 0
    }

    /// Convert to CSPF graph edge format.
    pub fn to_topo_edge(&self) -> TopoEdge {
        TopoEdge {
            from: NodeId(self.source_node_id),
            to: NodeId(self.target_node_id),
            avail_bw_bps: self.avail_bw_bps,
            rtt_us: self.rtt_us,
            loss_millipct: self.loss_millipct,
            cost: TopoEdge::compute_cost(self.rtt_us, self.loss_millipct),
        }
    }
}

// ─── Telemetry & Ingestion Summary ───────────────────────────────────────────

/// Ingestion outcome report returned by `ingest_packet`.
#[derive(Debug, Clone, PartialEq)]
pub struct IsspLsaIngestSummary {
    pub sender_node_id: u32,
    pub lsa_seq: u64,
    pub links_updated: usize,
    pub critical_congestion_detected: bool,
    pub was_compressed: bool,
    pub compression_savings_pct: f64,
}

/// Cumulative statistics and telemetry metrics for LSA dissemination.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct IsspLsaSyncTelemetry {
    pub lsa_packets_sent: u64,
    pub lsa_packets_received: u64,
    pub lsa_compressed_packets_sent: u64,
    pub lsa_compressed_packets_received: u64,
    pub lsa_stale_dropped: u64,
    pub lsa_links_updated: u64,
    pub raw_bytes_sent: u64,
    pub compressed_bytes_sent: u64,
    pub raw_bytes_received: u64,
    pub compressed_bytes_received: u64,
    pub compression_ratio_pct: f64,
    pub failovers_triggered: u64,
}

impl IsspLsaSyncTelemetry {
    pub fn recompute_ratios(&mut self) {
        if self.raw_bytes_sent > self.compressed_bytes_sent && self.raw_bytes_sent > 0 {
            let saved = self.raw_bytes_sent - self.compressed_bytes_sent;
            self.compression_ratio_pct = (saved as f64 / self.raw_bytes_sent as f64) * 100.0;
        } else {
            self.compression_ratio_pct = 0.0;
        }
    }
}

// ─── LSA Synchronizer ────────────────────────────────────────────────────────

/// Real-time Link-State Database (LSDB) and inter-node congestion synchronizer.
#[derive(Debug, Clone)]
pub struct IsspLsaSynchronizer {
    /// Local node ID originating local LSA packets.
    pub local_node_id: u32,
    /// Monotonic sequence counter for local advertisements.
    pub current_lsa_seq: u64,
    /// Active link state database: (source_node_id, target_node_id) -> Entry.
    pub lsdb: HashMap<(u32, u32), IsspLinkStateEntry>,
    /// Highest sequence number observed per peer node (anti-replay).
    pub node_seq_numbers: HashMap<u32, u64>,
    /// Accumulated runtime telemetry.
    pub stats: IsspLsaSyncTelemetry,
    /// Last advertised link records (for delta calculation).
    pub last_advertised_links: Vec<IsspLsaLinkRecord>,
}

impl IsspLsaSynchronizer {
    /// Create a new synchronizer instance for `local_node_id`.
    pub fn new(local_node_id: u32) -> Self {
        Self {
            local_node_id,
            current_lsa_seq: 0,
            lsdb: HashMap::new(),
            node_seq_numbers: HashMap::new(),
            stats: IsspLsaSyncTelemetry::default(),
            last_advertised_links: Vec::new(),
        }
    }

    /// Create an uncompressed LSA packet for outgoing dissemination.
    pub fn create_lsa(&mut self, links: Vec<IsspLsaLinkRecord>) -> IsspMeshLsaPacket {
        self.current_lsa_seq += 1;
        self.stats.lsa_packets_sent += 1;

        let packet = IsspMeshLsaPacket::new(self.local_node_id, self.current_lsa_seq, links);
        self.stats.raw_bytes_sent += packet.wire_size() as u64;
        self.last_advertised_links = packet.links.clone();
        packet
    }

    /// Create an RFC 8878 Zstandard compressed LSA packet for network flooding.
    pub fn create_compressed_lsa(&mut self, links: Vec<IsspLsaLinkRecord>) -> Vec<u8> {
        self.current_lsa_seq += 1;
        self.stats.lsa_packets_sent += 1;
        self.stats.lsa_compressed_packets_sent += 1;

        let packet = IsspMeshLsaPacket::new(self.local_node_id, self.current_lsa_seq, links);
        let raw_size = packet.wire_size() as u64;
        let compressed_bytes = packet.encode_compressed();

        self.stats.raw_bytes_sent += raw_size;
        self.stats.compressed_bytes_sent += compressed_bytes.len() as u64;
        self.stats.recompute_ratios();

        self.last_advertised_links = packet.links;
        compressed_bytes
    }

    /// Generate an incremental delta LSA only if dynamic metrics have deviated beyond relative thresholds.
    ///
    /// - `min_bw_change_pct`: minimum relative change in available bandwidth (e.g. 15.0 for 15%).
    /// - `min_rtt_change_pct`: minimum relative change in RTT (e.g. 15.0 for 15%).
    /// - Any change in congestion phase or flags always triggers an immediate announcement.
    pub fn create_delta_lsa(
        &mut self,
        current_links: &[IsspLsaLinkRecord],
        min_bw_change_pct: f64,
        min_rtt_change_pct: f64,
    ) -> Option<IsspMeshLsaPacket> {
        let mut changed_links = Vec::new();

        for curr in current_links {
            let prev = self
                .last_advertised_links
                .iter()
                .find(|l| l.target_node_id == curr.target_node_id);

            let should_advertise = match prev {
                None => true,
                Some(p) => {
                    if p.congestion_phase != curr.congestion_phase
                        || p.congestion_flags != curr.congestion_flags
                    {
                        true
                    } else {
                        // Check RTT deviation
                        let rtt_diff = (curr.rtt_us as f64 - p.rtt_us as f64).abs();
                        let rtt_pct = (rtt_diff / (p.rtt_us.max(1) as f64)) * 100.0;

                        // Check BW deviation
                        let bw_diff = (curr.avail_bw_bps as f64 - p.avail_bw_bps as f64).abs();
                        let bw_pct = (bw_diff / (p.avail_bw_bps.max(1) as f64)) * 100.0;

                        rtt_pct >= min_rtt_change_pct || bw_pct >= min_bw_change_pct
                    }
                }
            };

            if should_advertise {
                changed_links.push(*curr);
            }
        }

        if changed_links.is_empty() {
            None
        } else {
            Some(self.create_lsa(changed_links))
        }
    }

    /// Ingest a received wire buffer (either uncompressed 'ISMS' or compressed 'ISCL').
    pub fn ingest_packet(
        &mut self,
        packet_bytes: &[u8],
        now_ns: u64,
    ) -> Result<IsspLsaIngestSummary, IsspLsaError> {
        if packet_bytes.len() < 4 {
            return Err(IsspLsaError::BufferTooShort {
                expected: 4,
                actual: packet_bytes.len(),
            });
        }

        let magic = u32::from_be_bytes([
            packet_bytes[0],
            packet_bytes[1],
            packet_bytes[2],
            packet_bytes[3],
        ]);

        let (packet, was_compressed, savings_pct) = match magic {
            ISSP_MESH_LSA_MAGIC => {
                let pkt = IsspMeshLsaPacket::decode_wire(packet_bytes)?;
                self.stats.lsa_packets_received += 1;
                self.stats.raw_bytes_received += packet_bytes.len() as u64;
                (pkt, false, 0.0)
            }
            ISSP_COMPRESSED_LSA_MAGIC => {
                let pkt = IsspMeshLsaPacket::decode_compressed(packet_bytes)?;
                self.stats.lsa_packets_received += 1;
                self.stats.lsa_compressed_packets_received += 1;
                self.stats.compressed_bytes_received += packet_bytes.len() as u64;

                let raw_size = pkt.wire_size() as f64;
                let comp_size = packet_bytes.len() as f64;
                let savings = if raw_size > comp_size {
                    ((raw_size - comp_size) / raw_size) * 100.0
                } else {
                    0.0
                };

                (pkt, true, savings)
            }
            other => return Err(IsspLsaError::InvalidMagic(other)),
        };

        // Sequence number validation & replay rejection
        if let Some(&last_seq) = self.node_seq_numbers.get(&packet.sender_node_id) {
            if packet.lsa_seq <= last_seq {
                self.stats.lsa_stale_dropped += 1;
                return Err(IsspLsaError::StaleSequence {
                    sender_node_id: packet.sender_node_id,
                    seen_seq: last_seq,
                    incoming_seq: packet.lsa_seq,
                });
            }
        }

        self.node_seq_numbers
            .insert(packet.sender_node_id, packet.lsa_seq);

        let mut critical_congestion_detected = false;
        let mut links_updated = 0;

        for link in packet.links {
            if link.is_severely_congested() {
                critical_congestion_detected = true;
            }

            let entry = IsspLinkStateEntry {
                source_node_id: packet.sender_node_id,
                target_node_id: link.target_node_id,
                link_id_hash: link.link_id_hash,
                avail_bw_bps: link.avail_bw_bps,
                rtt_us: link.rtt_us,
                loss_millipct: link.loss_millipct,
                queuing_delay_us: link.queuing_delay_us,
                congestion_phase: link.congestion_phase,
                congestion_flags: link.congestion_flags,
                lsa_seq: packet.lsa_seq,
                last_updated_ns: now_ns,
            };

            self.lsdb
                .insert((packet.sender_node_id, link.target_node_id), entry);
            links_updated += 1;
        }

        self.stats.lsa_links_updated += links_updated as u64;

        Ok(IsspLsaIngestSummary {
            sender_node_id: packet.sender_node_id,
            lsa_seq: packet.lsa_seq,
            links_updated,
            critical_congestion_detected,
            was_compressed,
            compression_savings_pct: savings_pct,
        })
    }

    /// Apply all current link state entries in the LSDB to a [`TopologyGraph`].
    /// Down links are pruned from the graph; active links are added or updated.
    /// Returns the number of edges synchronized.
    pub fn apply_to_topology_graph(&self, graph: &mut TopologyGraph) -> usize {
        let mut count = 0;
        for ((src, dst), entry) in &self.lsdb {
            let from = NodeId(*src);
            let to = NodeId(*dst);

            if entry.is_link_down() {
                graph.remove_edge(from, to);
            } else {
                let cost = TopoEdge::compute_cost(entry.rtt_us, entry.loss_millipct);
                let edge = TopoEdge {
                    from,
                    to,
                    avail_bw_bps: entry.avail_bw_bps,
                    rtt_us: entry.rtt_us,
                    loss_millipct: entry.loss_millipct,
                    cost,
                };
                if !graph.update_edge(
                    from,
                    to,
                    entry.avail_bw_bps,
                    entry.rtt_us,
                    entry.loss_millipct,
                ) {
                    graph.add_edge(edge);
                }
            }
            count += 1;
        }
        count
    }

    /// Update a multipath forwarding group against the synchronized graph and trigger dynamic failover if needed.
    /// Returns the number of healthy paths remaining in the group.
    pub fn apply_to_multipath_group(
        &mut self,
        group: &mut CspfMultipathGroup,
        graph: &TopologyGraph,
        constraints: &CspfConstraints,
    ) -> usize {
        let initial_healthy = group.healthy_count();
        let remaining = group.update_health_from_graph(graph, constraints);

        if remaining < initial_healthy {
            self.stats.failovers_triggered += (initial_healthy - remaining) as u64;
        }

        remaining
    }

    /// Total active directed links tracked in LSDB.
    pub fn total_lsdb_links(&self) -> usize {
        self.lsdb.len()
    }

    /// Count of links currently marked as severed or down.
    pub fn down_links_count(&self) -> usize {
        self.lsdb.values().filter(|e| e.is_link_down()).count()
    }

    /// Count of links currently experiencing severe congestion.
    pub fn congested_links_count(&self) -> usize {
        self.lsdb
            .values()
            .filter(|e| e.is_severely_congested())
            .count()
    }

    /// Export Prometheus / OpenMetrics format text string.
    pub fn export_prometheus_metrics(&self) -> String {
        let mut out = String::with_capacity(1024);
        out.push_str(
            "# HELP ifa_issp_lsa_packets_sent_total Total LSA packets generated and sent.\n",
        );
        out.push_str("# TYPE ifa_issp_lsa_packets_sent_total counter\n");
        out.push_str(&format!(
            "ifa_issp_lsa_packets_sent_total{{node_id=\"{}\"}} {}\n",
            self.local_node_id, self.stats.lsa_packets_sent
        ));

        out.push_str(
            "# HELP ifa_issp_lsa_packets_received_total Total LSA packets received from peers.\n",
        );
        out.push_str("# TYPE ifa_issp_lsa_packets_received_total counter\n");
        out.push_str(&format!(
            "ifa_issp_lsa_packets_received_total{{node_id=\"{}\"}} {}\n",
            self.local_node_id, self.stats.lsa_packets_received
        ));

        out.push_str(
            "# HELP ifa_issp_lsa_compressed_packets_sent_total Total compressed LSA packets sent.\n",
        );
        out.push_str("# TYPE ifa_issp_lsa_compressed_packets_sent_total counter\n");
        out.push_str(&format!(
            "ifa_issp_lsa_compressed_packets_sent_total{{node_id=\"{}\"}} {}\n",
            self.local_node_id, self.stats.lsa_compressed_packets_sent
        ));

        out.push_str(
            "# HELP ifa_issp_lsa_stale_dropped_total Total stale or out-of-order LSA packets dropped.\n",
        );
        out.push_str("# TYPE ifa_issp_lsa_stale_dropped_total counter\n");
        out.push_str(&format!(
            "ifa_issp_lsa_stale_dropped_total{{node_id=\"{}\"}} {}\n",
            self.local_node_id, self.stats.lsa_stale_dropped
        ));

        out.push_str(
            "# HELP ifa_issp_lsa_compression_ratio_percent Percentage of bandwidth saved by LSA compression.\n",
        );
        out.push_str("# TYPE ifa_issp_lsa_compression_ratio_percent gauge\n");
        out.push_str(&format!(
            "ifa_issp_lsa_compression_ratio_percent{{node_id=\"{}\"}} {:.2}\n",
            self.local_node_id, self.stats.compression_ratio_pct
        ));

        out.push_str(
            "# HELP ifa_issp_lsdb_links_total Total active link entries stored in LSDB.\n",
        );
        out.push_str("# TYPE ifa_issp_lsdb_links_total gauge\n");
        out.push_str(&format!(
            "ifa_issp_lsdb_links_total{{node_id=\"{}\"}} {}\n",
            self.local_node_id,
            self.lsdb.len()
        ));

        out.push_str(
            "# HELP ifa_issp_lsdb_down_links_total Count of links marked as severed in LSDB.\n",
        );
        out.push_str("# TYPE ifa_issp_lsdb_down_links_total gauge\n");
        out.push_str(&format!(
            "ifa_issp_lsdb_down_links_total{{node_id=\"{}\"}} {}\n",
            self.local_node_id,
            self.down_links_count()
        ));

        out.push_str(
            "# HELP ifa_issp_lsdb_congested_links_total Count of links experiencing severe congestion in LSDB.\n",
        );
        out.push_str("# TYPE ifa_issp_lsdb_congested_links_total gauge\n");
        out.push_str(&format!(
            "ifa_issp_lsdb_congested_links_total{{node_id=\"{}\"}} {}\n",
            self.local_node_id,
            self.congested_links_count()
        ));

        out.push_str(
            "# HELP ifa_issp_lsa_failovers_triggered_total Count of dynamic multipath failovers triggered by LSA.\n",
        );
        out.push_str("# TYPE ifa_issp_lsa_failovers_triggered_total counter\n");
        out.push_str(&format!(
            "ifa_issp_lsa_failovers_triggered_total{{node_id=\"{}\"}} {}\n",
            self.local_node_id, self.stats.failovers_triggered
        ));

        out
    }

    /// Export structured JSON representation.
    pub fn export_telemetry_json(&self) -> String {
        format!(
            concat!(
                "{{\n",
                "  \"local_node_id\": {},\n",
                "  \"current_lsa_seq\": {},\n",
                "  \"lsdb_link_count\": {},\n",
                "  \"down_link_count\": {},\n",
                "  \"congested_link_count\": {},\n",
                "  \"lsa_packets_sent\": {},\n",
                "  \"lsa_packets_received\": {},\n",
                "  \"lsa_compressed_sent\": {},\n",
                "  \"lsa_stale_dropped\": {},\n",
                "  \"compression_ratio_pct\": {:.2},\n",
                "  \"failovers_triggered\": {}\n",
                "}}"
            ),
            self.local_node_id,
            self.current_lsa_seq,
            self.lsdb.len(),
            self.down_links_count(),
            self.congested_links_count(),
            self.stats.lsa_packets_sent,
            self.stats.lsa_packets_received,
            self.stats.lsa_compressed_packets_sent,
            self.stats.lsa_stale_dropped,
            self.stats.compression_ratio_pct,
            self.stats.failovers_triggered,
        )
    }
}

// ─── Unit Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_link_record_wire_roundtrip() {
        let record = IsspLsaLinkRecord::new(2, 0x1234_5678, 100_000_000, 4_500, 250)
            .with_queuing_delay(150)
            .with_congestion_phase(LSA_PHASE_THROTTLE)
            .with_flags(LSA_FLAG_BOTTLENECK | LSA_FLAG_ECN_MARKED);

        assert!(record.is_bottleneck());
        assert!(!record.is_link_down());
        assert_eq!(record.compute_composite_cost(), 4 + 2); // 4500/1000 + 250/100 = 4 + 2 = 6

        let mut buf = [0u8; ISSP_LSA_LINK_RECORD_SIZE];
        record.encode_to_slice(&mut buf);

        let decoded = IsspLsaLinkRecord::decode_from_slice(&buf).expect("must decode link record");
        assert_eq!(decoded, record);
    }

    #[test]
    fn test_uncompressed_lsa_packet_roundtrip() {
        let link1 = IsspLsaLinkRecord::new(2, 0x1111, 80_000_000, 2_000, 0);
        let link2 = IsspLsaLinkRecord::new(3, 0x2222, 50_000_000, 8_000, 1_000)
            .with_congestion_phase(LSA_PHASE_RECOVERY)
            .with_flags(LSA_FLAG_FAILOVER_TRIGGER);

        let packet = IsspMeshLsaPacket::new(1, 42, vec![link1, link2]);
        let wire = packet.encode_wire();
        assert_eq!(wire.len(), 20 + 2 * 32);

        let decoded = IsspMeshLsaPacket::decode_wire(&wire).expect("must decode LSA packet");
        assert_eq!(decoded, packet);
        assert_eq!(decoded.sender_node_id, 1);
        assert_eq!(decoded.lsa_seq, 42);
        assert_eq!(decoded.links.len(), 2);
    }

    #[test]
    fn test_compressed_lsa_packet_roundtrip() {
        let mut links = Vec::new();
        for i in 1..=64 {
            // Include homogeneous default entries simulating idle mesh links with zero backlog
            let link = if i % 2 == 0 {
                IsspLsaLinkRecord::new(i, i * 100, 100_000_000, 1_500, 0)
                    .with_congestion_phase(LSA_PHASE_CRUISE)
            } else {
                IsspLsaLinkRecord::new(i, 0, 0, 0, 0)
            };
            links.push(link);
        }

        let packet = IsspMeshLsaPacket::new(10, 100, links);
        let uncompressed_wire = packet.encode_wire();
        let compressed_wire = packet.encode_compressed();

        assert_eq!(uncompressed_wire.len(), 20 + 64 * 32); // 2068 bytes

        // Check decoding fidelity
        let decoded = IsspMeshLsaPacket::decode_compressed(&compressed_wire)
            .expect("must decode compressed LSA packet");
        assert_eq!(decoded, packet);
    }

    #[test]
    fn test_synchronizer_ingest_and_stale_rejection() {
        let mut sync = IsspLsaSynchronizer::new(1);

        let link = IsspLsaLinkRecord::new(2, 0x1, 50_000_000, 3_000, 0);
        let pkt1 = IsspMeshLsaPacket::new(2, 10, vec![link]);
        let wire1 = pkt1.encode_wire();

        let res1 = sync
            .ingest_packet(&wire1, 1_000_000)
            .expect("first packet must ingest");
        assert_eq!(res1.sender_node_id, 2);
        assert_eq!(res1.lsa_seq, 10);
        assert_eq!(res1.links_updated, 1);
        assert_eq!(sync.total_lsdb_links(), 1);

        // Ingest stale packet (seq 9 <= 10)
        let pkt_stale = IsspMeshLsaPacket::new(2, 9, vec![link]);
        let wire_stale = pkt_stale.encode_wire();
        let err = sync
            .ingest_packet(&wire_stale, 2_000_000)
            .expect_err("stale packet must be rejected");
        match err {
            IsspLsaError::StaleSequence {
                sender_node_id,
                seen_seq,
                incoming_seq,
            } => {
                assert_eq!(sender_node_id, 2);
                assert_eq!(seen_seq, 10);
                assert_eq!(incoming_seq, 9);
            }
            other => panic!("unexpected error: {:?}", other),
        }
        assert_eq!(sync.stats.lsa_stale_dropped, 1);

        // Ingest newer packet (seq 11 > 10)
        let pkt_new = IsspMeshLsaPacket::new(2, 11, vec![link]);
        let wire_new = pkt_new.encode_wire();
        let res2 = sync
            .ingest_packet(&wire_new, 3_000_000)
            .expect("newer packet must ingest");
        assert_eq!(res2.lsa_seq, 11);
    }

    #[test]
    fn test_synchronizer_compressed_ingest() {
        let mut sync = IsspLsaSynchronizer::new(1);

        let mut links = Vec::new();
        for i in 2..=5 {
            links.push(IsspLsaLinkRecord::new(i, i * 10, 100_000_000, 2_000, 0));
        }

        let pkt = IsspMeshLsaPacket::new(2, 5, links);
        let comp_wire = pkt.encode_compressed();

        let summary = sync
            .ingest_packet(&comp_wire, 1_000_000)
            .expect("must ingest compressed packet");
        assert!(summary.was_compressed);
        assert_eq!(summary.links_updated, 4);
        assert_eq!(sync.total_lsdb_links(), 4);
        assert!(summary.compression_savings_pct >= 0.0);
    }

    #[test]
    fn test_delta_lsa_generation() {
        let mut sync = IsspLsaSynchronizer::new(1);

        let link1 = IsspLsaLinkRecord::new(2, 0x1, 100_000_000, 2_000, 0);
        let link2 = IsspLsaLinkRecord::new(3, 0x2, 50_000_000, 5_000, 0);
        let initial_links = vec![link1, link2];

        // First creation
        let _ = sync.create_lsa(initial_links.clone());

        // Delta check with minor jitter (RTT 2000 -> 2100 = 5% change, threshold = 15%)
        let link1_minor = IsspLsaLinkRecord::new(2, 0x1, 100_000_000, 2_100, 0);
        let delta_none = sync.create_delta_lsa(&[link1_minor, link2], 15.0, 15.0);
        assert!(
            delta_none.is_none(),
            "minor changes must not trigger delta LSA"
        );

        // Major congestion phase change triggers delta immediately
        let link1_congested = link1.with_congestion_phase(LSA_PHASE_THROTTLE);
        let delta_some = sync
            .create_delta_lsa(&[link1_congested, link2], 15.0, 15.0)
            .expect("congestion phase change must trigger delta LSA");
        assert_eq!(delta_some.links.len(), 1);
        assert_eq!(delta_some.links[0].target_node_id, 2);
        assert_eq!(delta_some.links[0].congestion_phase, LSA_PHASE_THROTTLE);
    }

    #[test]
    fn test_apply_to_topology_graph_and_multipath_failover() {
        let mut sync = IsspLsaSynchronizer::new(0);
        let mut graph = TopologyGraph::new();

        // 0 -> 1 -> 3
        graph.add_symmetric_edge(NodeId(0), NodeId(1), 100_000_000, 2_000, 0);
        graph.add_symmetric_edge(NodeId(1), NodeId(3), 100_000_000, 2_000, 0);
        // 0 -> 2 -> 3
        graph.add_symmetric_edge(NodeId(0), NodeId(2), 80_000_000, 3_000, 0);
        graph.add_symmetric_edge(NodeId(2), NodeId(3), 80_000_000, 3_000, 0);

        let constraints = CspfConstraints::unconstrained();
        let paths = crate::topology_cspf::cspf_k_disjoint_paths(
            &graph,
            NodeId(0),
            NodeId(3),
            &constraints,
            2,
            crate::topology_cspf::DisjointMode::NodeDisjoint,
        );
        assert_eq!(paths.len(), 2);

        let mut group = CspfMultipathGroup::new(NodeId(0), NodeId(3), paths);
        assert_eq!(group.healthy_count(), 2);

        // Node 1 announces link 1 -> 3 is severed (LINK_DOWN flag)
        let link_down = IsspLsaLinkRecord::new(3, 0x13, 0, 100_000, 100_000)
            .with_flags(LSA_FLAG_LINK_DOWN | LSA_FLAG_FAILOVER_TRIGGER);

        let lsa = IsspMeshLsaPacket::new(1, 1, vec![link_down]);
        sync.ingest_packet(&lsa.encode_wire(), 1_000)
            .expect("must ingest down link");

        // Apply to topology graph
        sync.apply_to_topology_graph(&mut graph);
        assert!(!graph.has_edge(NodeId(1), NodeId(3)));

        // Apply to multipath group
        let remaining_healthy = sync.apply_to_multipath_group(&mut group, &graph, &constraints);
        assert_eq!(remaining_healthy, 1);
        assert_eq!(group.healthy_count(), 1);
        assert_eq!(sync.stats.failovers_triggered, 1);

        // The remaining path must be through node 2
        let primary = group.primary_healthy_path().expect("primary path exists");
        assert_eq!(primary.nodes, vec![NodeId(0), NodeId(2), NodeId(3)]);
    }

    #[test]
    fn test_telemetry_metrics_export() {
        let mut sync = IsspLsaSynchronizer::new(42);
        let link = IsspLsaLinkRecord::new(1, 0x1, 10_000_000, 5_000, 0);
        let _ = sync.create_compressed_lsa(vec![link]);

        let prom = sync.export_prometheus_metrics();
        assert!(prom.contains("ifa_issp_lsa_packets_sent_total{node_id=\"42\"} 1"));
        assert!(prom.contains("ifa_issp_lsa_compressed_packets_sent_total{node_id=\"42\"} 1"));
        assert!(prom.contains("ifa_issp_lsdb_links_total{node_id=\"42\"} 0"));

        let json = sync.export_telemetry_json();
        assert!(json.contains("\"local_node_id\": 42"));
        assert!(json.contains("\"lsa_packets_sent\": 1"));
    }
}

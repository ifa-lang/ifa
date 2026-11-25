//! RFC 8878 Zstandard Streaming Compression Pipeline for ISSP Congestion Traces and Multipath Telemetry.
//!
//! Provides line-rate, low-latency streaming compression, framed chunking, and deterministic
//! archiving of high-frequency congestion window telemetry (BBR/LEDBAT) and multipath balancing records.

#![allow(clippy::manual_is_multiple_of, clippy::chunks_exact_to_as_chunks)]

use std::fmt;
use std::io::{self, Write};

/// Zstandard Frame Magic Number (RFC 8878 Section 3.1.1): `0xFD2FB528`.
pub const ZSTD_MAGIC: u32 = 0xFD2F_B528;

/// Default window descriptor byte for 128 KB sliding window (Exponent 7, Mantissa 0): `(7 << 3) | 0 = 0x38`.
pub const ZSTD_WINDOW_DESC_128K: u8 = 0x38;

/// Zstandard Raw (uncompressed) block type.
pub const ZSTD_BLOCK_TYPE_RAW: u8 = 0;

/// Zstandard Run-Length Encoded (RLE) block type.
pub const ZSTD_BLOCK_TYPE_RLE: u8 = 1;

/// Zstandard Compressed (Huffman / FSE) block type.
pub const ZSTD_BLOCK_TYPE_COMPRESSED: u8 = 2;

/// Maximum block content size in Zstandard frame (128 KB).
pub const ZSTD_BLOCK_SIZE_MAX: usize = 128 * 1024;

/// Magic identifier for congestion trace records ('ISTR' = 0x49535452).
pub const ISSP_TRACE_MAGIC: u32 = 0x4953_5452;

/// Magic identifier for multipath telemetry snapshot records ('ISTM' = 0x4953544d).
pub const ISSP_TELEMETRY_MAGIC: u32 = 0x4953_544d;

/// Fixed wire size of a binary congestion trace record in bytes (64 bytes).
pub const ISSP_TRACE_RECORD_SIZE: usize = 64;

/// Fixed wire size of a binary multipath balancing telemetry record in bytes (64 bytes).
pub const ISSP_MULTIPATH_TELEMETRY_RECORD_SIZE: usize = 64;

// ---------------------------------------------------------------------------
// Trace Flags & Congestion Phases
// ---------------------------------------------------------------------------

pub const TRACE_FLAG_LOSS: u8 = 0x01;
pub const TRACE_FLAG_ECN: u8 = 0x02;
pub const TRACE_FLAG_RETRANSMIT: u8 = 0x04;
pub const TRACE_FLAG_PROBE: u8 = 0x08;
pub const TRACE_FLAG_RTT_SURGE: u8 = 0x10;
pub const TRACE_FLAG_CWND_REDUCED: u8 = 0x20;

pub const PHASE_SLOW_START: u8 = 0;
pub const PHASE_CONGESTION_AVOIDANCE: u8 = 1;
pub const PHASE_RECOVERY: u8 = 2;
pub const PHASE_DRAIN: u8 = 3;
pub const PHASE_PROBE_BW: u8 = 4;
pub const PHASE_PROBE_RTT: u8 = 5;

// ---------------------------------------------------------------------------
// Error Types
// ---------------------------------------------------------------------------

/// Errors encountered during Zstandard archive encoding or decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZstdArchiveError {
    /// Provided magic bytes do not match Zstandard or ISSP magic.
    InvalidMagic(u32),
    /// Frame header is malformed or contains unsupported configuration.
    UnsupportedFrameHeader(u8),
    /// Buffer ended unexpectedly before reading full descriptor or block.
    BufferTooShort { expected: usize, actual: usize },
    /// Unknown block type identifier in Zstandard block header.
    InvalidBlockType(u8),
    /// Record magic marker in decoded stream does not match expected value.
    CorruptedRecordMagic { expected: u32, actual: u32 },
    /// Record buffer length is not a valid multiple of fixed record size.
    InvalidRecordLength { expected: usize, actual: usize },
    /// Generic I/O or decode failure.
    DecodeError(String),
}

impl fmt::Display for ZstdArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic(m) => write!(f, "invalid magic tag: {:#010x}", m),
            Self::UnsupportedFrameHeader(h) => {
                write!(f, "unsupported zstd frame header descriptor: {:#04x}", h)
            }
            Self::BufferTooShort { expected, actual } => {
                write!(
                    f,
                    "buffer too short: expected {} bytes, got {}",
                    expected, actual
                )
            }
            Self::InvalidBlockType(b) => write!(f, "invalid zstd block type: {}", b),
            Self::CorruptedRecordMagic { expected, actual } => {
                write!(
                    f,
                    "corrupted record magic: expected {:#010x}, found {:#010x}",
                    expected, actual
                )
            }
            Self::InvalidRecordLength { expected, actual } => {
                write!(
                    f,
                    "invalid record length: expected multiple of {}, got {}",
                    expected, actual
                )
            }
            Self::DecodeError(msg) => write!(f, "zstd archive decode error: {}", msg),
        }
    }
}

impl std::error::Error for ZstdArchiveError {}

// ---------------------------------------------------------------------------
// Congestion Trace Record (64 Bytes Exact Wire Alignment)
// ---------------------------------------------------------------------------

/// Compact 64-byte binary congestion trace record.
///
/// Records granular BBR bandwidth estimation, LEDBAT queuing delay gradients,
/// pacing gain, and congestion window adjustments on an active subpath.
#[derive(Debug, Clone, PartialEq)]
pub struct IsspCongestionTraceRecord {
    pub node_id: u32,
    pub subpath_id: u32,
    pub congestion_phase: u8,
    pub flags: u8,
    pub pacing_gain_q8: u16,
    pub timestamp_ns: u64,
    pub flow_hash: u64,
    pub seq_num: u64,
    pub cwnd_bytes: u64,
    pub bandwidth_estimate_bps: u64,
    pub rtt_us: u32,
    pub queuing_delay_us: u32,
}

impl IsspCongestionTraceRecord {
    /// Serialize record to deterministic 64-byte wire layout.
    pub fn to_wire(&self) -> [u8; ISSP_TRACE_RECORD_SIZE] {
        let mut wire = [0u8; ISSP_TRACE_RECORD_SIZE];
        wire[0..4].copy_from_slice(&ISSP_TRACE_MAGIC.to_be_bytes());
        wire[4..8].copy_from_slice(&self.node_id.to_be_bytes());
        wire[8..12].copy_from_slice(&self.subpath_id.to_be_bytes());
        wire[12] = self.congestion_phase;
        wire[13] = self.flags;
        wire[14..16].copy_from_slice(&self.pacing_gain_q8.to_be_bytes());
        wire[16..24].copy_from_slice(&self.timestamp_ns.to_be_bytes());
        wire[24..32].copy_from_slice(&self.flow_hash.to_be_bytes());
        wire[32..40].copy_from_slice(&self.seq_num.to_be_bytes());
        wire[40..48].copy_from_slice(&self.cwnd_bytes.to_be_bytes());
        wire[48..56].copy_from_slice(&self.bandwidth_estimate_bps.to_be_bytes());
        wire[56..60].copy_from_slice(&self.rtt_us.to_be_bytes());
        wire[60..64].copy_from_slice(&self.queuing_delay_us.to_be_bytes());
        wire
    }

    /// Deserialize record from 64-byte wire slice.
    pub fn from_wire(slice: &[u8]) -> Result<Self, ZstdArchiveError> {
        if slice.len() < ISSP_TRACE_RECORD_SIZE {
            return Err(ZstdArchiveError::BufferTooShort {
                expected: ISSP_TRACE_RECORD_SIZE,
                actual: slice.len(),
            });
        }
        let magic = u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]);
        if magic != ISSP_TRACE_MAGIC {
            return Err(ZstdArchiveError::CorruptedRecordMagic {
                expected: ISSP_TRACE_MAGIC,
                actual: magic,
            });
        }
        let node_id = u32::from_be_bytes([slice[4], slice[5], slice[6], slice[7]]);
        let subpath_id = u32::from_be_bytes([slice[8], slice[9], slice[10], slice[11]]);
        let congestion_phase = slice[12];
        let flags = slice[13];
        let pacing_gain_q8 = u16::from_be_bytes([slice[14], slice[15]]);
        let timestamp_ns = u64::from_be_bytes([
            slice[16], slice[17], slice[18], slice[19], slice[20], slice[21], slice[22], slice[23],
        ]);
        let flow_hash = u64::from_be_bytes([
            slice[24], slice[25], slice[26], slice[27], slice[28], slice[29], slice[30], slice[31],
        ]);
        let seq_num = u64::from_be_bytes([
            slice[32], slice[33], slice[34], slice[35], slice[36], slice[37], slice[38], slice[39],
        ]);
        let cwnd_bytes = u64::from_be_bytes([
            slice[40], slice[41], slice[42], slice[43], slice[44], slice[45], slice[46], slice[47],
        ]);
        let bandwidth_estimate_bps = u64::from_be_bytes([
            slice[48], slice[49], slice[50], slice[51], slice[52], slice[53], slice[54], slice[55],
        ]);
        let rtt_us = u32::from_be_bytes([slice[56], slice[57], slice[58], slice[59]]);
        let queuing_delay_us = u32::from_be_bytes([slice[60], slice[61], slice[62], slice[63]]);

        Ok(Self {
            node_id,
            subpath_id,
            congestion_phase,
            flags,
            pacing_gain_q8,
            timestamp_ns,
            flow_hash,
            seq_num,
            cwnd_bytes,
            bandwidth_estimate_bps,
            rtt_us,
            queuing_delay_us,
        })
    }

    /// Decode a contiguous sequence of binary records from a raw uncompressed byte slice.
    pub fn decode_records_slice(raw: &[u8]) -> Result<Vec<Self>, ZstdArchiveError> {
        if raw.len() % ISSP_TRACE_RECORD_SIZE != 0 {
            return Err(ZstdArchiveError::InvalidRecordLength {
                expected: ISSP_TRACE_RECORD_SIZE,
                actual: raw.len(),
            });
        }
        let count = raw.len() / ISSP_TRACE_RECORD_SIZE;
        let mut records = Vec::with_capacity(count);
        for chunk in raw.chunks_exact(ISSP_TRACE_RECORD_SIZE) {
            records.push(Self::from_wire(chunk)?);
        }
        Ok(records)
    }

    /// Human-readable name of the current congestion control phase.
    pub fn phase_name(&self) -> &'static str {
        match self.congestion_phase {
            PHASE_SLOW_START => "SlowStart",
            PHASE_CONGESTION_AVOIDANCE => "CongestionAvoidance",
            PHASE_RECOVERY => "Recovery",
            PHASE_DRAIN => "Drain",
            PHASE_PROBE_BW => "ProbeBw",
            PHASE_PROBE_RTT => "ProbeRtt",
            _ => "Unknown",
        }
    }

    /// Check if a specific trace flag is active.
    pub fn has_flag(&self, flag: u8) -> bool {
        (self.flags & flag) != 0
    }

    /// Comma-separated list of active flags.
    pub fn flags_string(&self) -> String {
        let mut list = Vec::new();
        if self.has_flag(TRACE_FLAG_LOSS) {
            list.push("LOSS");
        }
        if self.has_flag(TRACE_FLAG_ECN) {
            list.push("ECN");
        }
        if self.has_flag(TRACE_FLAG_RETRANSMIT) {
            list.push("RETRANSMIT");
        }
        if self.has_flag(TRACE_FLAG_PROBE) {
            list.push("PROBE");
        }
        if self.has_flag(TRACE_FLAG_RTT_SURGE) {
            list.push("RTT_SURGE");
        }
        if self.has_flag(TRACE_FLAG_CWND_REDUCED) {
            list.push("CWND_REDUCED");
        }
        if list.is_empty() {
            "NONE".to_string()
        } else {
            list.join("|")
        }
    }

    /// Compact JSON representation without external serde dependency.
    pub fn to_json_string(&self) -> String {
        format!(
            "{{\"timestamp_ns\":{},\"node_id\":{},\"flow_hash\":\"{:#018x}\",\"subpath_id\":{},\"seq_num\":{},\"phase\":\"{}\",\"rtt_us\":{},\"queuing_delay_us\":{},\"cwnd_bytes\":{},\"bandwidth_bps\":{},\"pacing_gain_q8\":{},\"flags\":\"{}\"}}",
            self.timestamp_ns,
            self.node_id,
            self.flow_hash,
            self.subpath_id,
            self.seq_num,
            self.phase_name(),
            self.rtt_us,
            self.queuing_delay_us,
            self.cwnd_bytes,
            self.bandwidth_estimate_bps,
            self.pacing_gain_q8,
            self.flags_string()
        )
    }
}

// ---------------------------------------------------------------------------
// Multipath Telemetry Record (64 Bytes Exact Wire Alignment)
// ---------------------------------------------------------------------------

/// Compact 64-byte binary snapshot record of aggregated multipath balancing telemetry.
#[derive(Debug, Clone, PartialEq)]
pub struct IsspMultipathTelemetryRecord {
    pub node_id: u32,
    pub active_subpaths: u32,
    pub total_sessions: u32,
    pub avg_rtt_us: u32,
    pub max_queuing_delay_us: u32,
    pub timestamp_ns: u64,
    pub total_tx_bytes: u64,
    pub total_rx_bytes: u64,
    pub loss_events_count: u64,
    pub effective_throughput_bps: u64,
}

impl IsspMultipathTelemetryRecord {
    /// Serialize record to deterministic 64-byte wire layout.
    pub fn to_wire(&self) -> [u8; ISSP_MULTIPATH_TELEMETRY_RECORD_SIZE] {
        let mut wire = [0u8; ISSP_MULTIPATH_TELEMETRY_RECORD_SIZE];
        wire[0..4].copy_from_slice(&ISSP_TELEMETRY_MAGIC.to_be_bytes());
        wire[4..8].copy_from_slice(&self.node_id.to_be_bytes());
        wire[8..12].copy_from_slice(&self.active_subpaths.to_be_bytes());
        wire[12..16].copy_from_slice(&self.total_sessions.to_be_bytes());
        wire[16..20].copy_from_slice(&self.avg_rtt_us.to_be_bytes());
        wire[20..24].copy_from_slice(&self.max_queuing_delay_us.to_be_bytes());
        wire[24..32].copy_from_slice(&self.timestamp_ns.to_be_bytes());
        wire[32..40].copy_from_slice(&self.total_tx_bytes.to_be_bytes());
        wire[40..48].copy_from_slice(&self.total_rx_bytes.to_be_bytes());
        wire[48..56].copy_from_slice(&self.loss_events_count.to_be_bytes());
        wire[56..64].copy_from_slice(&self.effective_throughput_bps.to_be_bytes());
        wire
    }

    /// Deserialize record from 64-byte wire slice.
    pub fn from_wire(slice: &[u8]) -> Result<Self, ZstdArchiveError> {
        if slice.len() < ISSP_MULTIPATH_TELEMETRY_RECORD_SIZE {
            return Err(ZstdArchiveError::BufferTooShort {
                expected: ISSP_MULTIPATH_TELEMETRY_RECORD_SIZE,
                actual: slice.len(),
            });
        }
        let magic = u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]);
        if magic != ISSP_TELEMETRY_MAGIC {
            return Err(ZstdArchiveError::CorruptedRecordMagic {
                expected: ISSP_TELEMETRY_MAGIC,
                actual: magic,
            });
        }
        let node_id = u32::from_be_bytes([slice[4], slice[5], slice[6], slice[7]]);
        let active_subpaths = u32::from_be_bytes([slice[8], slice[9], slice[10], slice[11]]);
        let total_sessions = u32::from_be_bytes([slice[12], slice[13], slice[14], slice[15]]);
        let avg_rtt_us = u32::from_be_bytes([slice[16], slice[17], slice[18], slice[19]]);
        let max_queuing_delay_us = u32::from_be_bytes([slice[20], slice[21], slice[22], slice[23]]);
        let timestamp_ns = u64::from_be_bytes([
            slice[24], slice[25], slice[26], slice[27], slice[28], slice[29], slice[30], slice[31],
        ]);
        let total_tx_bytes = u64::from_be_bytes([
            slice[32], slice[33], slice[34], slice[35], slice[36], slice[37], slice[38], slice[39],
        ]);
        let total_rx_bytes = u64::from_be_bytes([
            slice[40], slice[41], slice[42], slice[43], slice[44], slice[45], slice[46], slice[47],
        ]);
        let loss_events_count = u64::from_be_bytes([
            slice[48], slice[49], slice[50], slice[51], slice[52], slice[53], slice[54], slice[55],
        ]);
        let effective_throughput_bps = u64::from_be_bytes([
            slice[56], slice[57], slice[58], slice[59], slice[60], slice[61], slice[62], slice[63],
        ]);

        Ok(Self {
            node_id,
            active_subpaths,
            total_sessions,
            avg_rtt_us,
            max_queuing_delay_us,
            timestamp_ns,
            total_tx_bytes,
            total_rx_bytes,
            loss_events_count,
            effective_throughput_bps,
        })
    }

    /// Decode a contiguous sequence of binary telemetry records from a raw uncompressed byte slice.
    pub fn decode_records_slice(raw: &[u8]) -> Result<Vec<Self>, ZstdArchiveError> {
        if raw.len() % ISSP_MULTIPATH_TELEMETRY_RECORD_SIZE != 0 {
            return Err(ZstdArchiveError::InvalidRecordLength {
                expected: ISSP_MULTIPATH_TELEMETRY_RECORD_SIZE,
                actual: raw.len(),
            });
        }
        let count = raw.len() / ISSP_MULTIPATH_TELEMETRY_RECORD_SIZE;
        let mut records = Vec::with_capacity(count);
        for chunk in raw.chunks_exact(ISSP_MULTIPATH_TELEMETRY_RECORD_SIZE) {
            records.push(Self::from_wire(chunk)?);
        }
        Ok(records)
    }

    /// Compact JSON representation.
    pub fn to_json_string(&self) -> String {
        format!(
            "{{\"timestamp_ns\":{},\"node_id\":{},\"active_subpaths\":{},\"total_sessions\":{},\"avg_rtt_us\":{},\"max_queuing_delay_us\":{},\"tx_bytes\":{},\"rx_bytes\":{},\"loss_events\":{},\"throughput_bps\":{}}}",
            self.timestamp_ns,
            self.node_id,
            self.active_subpaths,
            self.total_sessions,
            self.avg_rtt_us,
            self.max_queuing_delay_us,
            self.total_tx_bytes,
            self.total_rx_bytes,
            self.loss_events_count,
            self.effective_throughput_bps
        )
    }
}

// ---------------------------------------------------------------------------
// Telemetry and Statistics
// ---------------------------------------------------------------------------

/// Statistics and compression efficiency telemetry of an active Zstandard archive pipeline.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct IsspZstdArchiveTelemetry {
    pub total_records_ingested: u64,
    pub raw_bytes_in: u64,
    pub compressed_bytes_out: u64,
    pub frames_flushed: u64,
    pub blocks_raw: u64,
    pub blocks_rle: u64,
    pub bytes_saved: u64,
    pub compression_ratio_percent: f64,
    pub last_flush_timestamp_ns: u64,
}

impl IsspZstdArchiveTelemetry {
    pub fn update_ratios(&mut self) {
        if self.raw_bytes_in > self.compressed_bytes_out {
            self.bytes_saved = self.raw_bytes_in - self.compressed_bytes_out;
            self.compression_ratio_percent =
                (self.bytes_saved as f64 / self.raw_bytes_in as f64) * 100.0;
        } else {
            self.bytes_saved = 0;
            self.compression_ratio_percent = 0.0;
        }
    }
}

// ---------------------------------------------------------------------------
// RFC 8878 Zstandard Frame & Block Encoding
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum ChunkBlockSpec<'a> {
    Raw(&'a [u8]),
    Rle(u8, usize),
}

/// Encode a binary data chunk into a valid RFC 8878 Zstandard streaming frame,
/// partitioning runs of identical bytes into high-efficiency RLE blocks.
pub fn encode_zstd_chunk(data: &[u8]) -> Vec<u8> {
    let (frame, _, _) = encode_zstd_chunk_with_stats(data);
    frame
}

/// Encode a binary data chunk into a valid RFC 8878 Zstandard frame and return block counts.
pub fn encode_zstd_chunk_with_stats(data: &[u8]) -> (Vec<u8>, usize, usize) {
    if data.is_empty() {
        return (Vec::new(), 0, 0);
    }

    let mut specs = Vec::new();
    let mut pos = 0;
    let mut raw_start = 0;

    while pos < data.len() {
        let b = data[pos];
        let mut run_len = 1;
        while pos + run_len < data.len() && data[pos + run_len] == b {
            run_len += 1;
        }

        // Threshold for emitting an RLE block: 16 identical consecutive bytes
        if run_len >= 16 {
            if pos > raw_start {
                specs.push(ChunkBlockSpec::Raw(&data[raw_start..pos]));
            }
            specs.push(ChunkBlockSpec::Rle(b, run_len));
            pos += run_len;
            raw_start = pos;
        } else {
            pos += 1;
        }
    }
    if pos > raw_start {
        specs.push(ChunkBlockSpec::Raw(&data[raw_start..pos]));
    }

    let mut out = Vec::with_capacity(32 + data.len());
    // 1. Zstandard Magic: 0xFD2FB528 (little-endian: 0x28, 0xB5, 0x2F, 0xFD)
    out.extend_from_slice(&ZSTD_MAGIC.to_le_bytes());

    // 2. Frame Header Descriptor (FHD):
    // Single_Segment = 0, FCS_Field_Size = 0, Content_Checksum = 0, Dict_ID = 0 -> 0x00
    out.push(0x00);

    // 3. Window Descriptor: 128 KB sliding window (Exponent 7, Mantissa 0 -> 0x38)
    out.push(ZSTD_WINDOW_DESC_128K);

    let mut raw_blocks_count = 0;
    let mut rle_blocks_count = 0;

    let specs_len = specs.len();
    for (i, spec) in specs.into_iter().enumerate() {
        let is_last = i == specs_len - 1;
        match spec {
            ChunkBlockSpec::Raw(slice) => {
                // Split large slices if exceeding ZSTD_BLOCK_SIZE_MAX (128 KB)
                let chunks = slice.chunks(ZSTD_BLOCK_SIZE_MAX);
                let total_chunks = chunks.len();
                for (c_idx, chunk) in chunks.enumerate() {
                    let chunk_is_last = is_last && (c_idx == total_chunks - 1);
                    let last_bit = if chunk_is_last { 1u32 } else { 0u32 };
                    let bhdr_val = last_bit
                        | ((ZSTD_BLOCK_TYPE_RAW as u32) << 1)
                        | ((chunk.len() as u32) << 3);
                    let bhdr_bytes = bhdr_val.to_le_bytes();
                    out.extend_from_slice(&bhdr_bytes[0..3]);
                    out.extend_from_slice(chunk);
                    raw_blocks_count += 1;
                }
            }
            ChunkBlockSpec::Rle(b_val, mut count) => {
                while count > 0 {
                    let current_chunk_size = count.min(ZSTD_BLOCK_SIZE_MAX);
                    count -= current_chunk_size;
                    let chunk_is_last = is_last && (count == 0);
                    let last_bit = if chunk_is_last { 1u32 } else { 0u32 };
                    let bhdr_val = last_bit
                        | ((ZSTD_BLOCK_TYPE_RLE as u32) << 1)
                        | ((current_chunk_size as u32) << 3);
                    let bhdr_bytes = bhdr_val.to_le_bytes();
                    out.extend_from_slice(&bhdr_bytes[0..3]);
                    out.push(b_val);
                    rle_blocks_count += 1;
                }
            }
        }
    }

    (out, raw_blocks_count, rle_blocks_count)
}

// ---------------------------------------------------------------------------
// RFC 8878 Zstandard Frame & Stream Decompressor
// ---------------------------------------------------------------------------

/// Decode an RFC 8878 Zstandard stream containing one or more concatenated frames.
pub fn decode_zstd_stream(compressed: &[u8]) -> Result<Vec<u8>, ZstdArchiveError> {
    let mut pos = 0;
    let mut decompressed = Vec::new();

    while pos < compressed.len() {
        if pos + 4 > compressed.len() {
            return Err(ZstdArchiveError::BufferTooShort {
                expected: pos + 4,
                actual: compressed.len(),
            });
        }
        let magic = u32::from_le_bytes([
            compressed[pos],
            compressed[pos + 1],
            compressed[pos + 2],
            compressed[pos + 3],
        ]);
        if magic != ZSTD_MAGIC {
            return Err(ZstdArchiveError::InvalidMagic(magic));
        }
        pos += 4;

        if pos >= compressed.len() {
            return Err(ZstdArchiveError::BufferTooShort {
                expected: pos + 1,
                actual: compressed.len(),
            });
        }
        let fhd = compressed[pos];
        pos += 1;

        let single_segment = (fhd & 0x20) != 0;
        let fcs_flag = (fhd >> 6) & 0x03;
        let checksum_flag = (fhd & 0x04) != 0;
        let dict_flag = fhd & 0x03;

        if !single_segment {
            // Window descriptor byte
            if pos >= compressed.len() {
                return Err(ZstdArchiveError::BufferTooShort {
                    expected: pos + 1,
                    actual: compressed.len(),
                });
            }
            pos += 1;
        }

        // Dictionary ID skip
        let dict_id_len = match dict_flag {
            0 => 0,
            1 => 1,
            2 => 2,
            3 => 4,
            _ => 0,
        };
        pos += dict_id_len;

        // Frame content size skip
        let fcs_len = if single_segment {
            match fcs_flag {
                0 => 1,
                1 => 2,
                2 => 4,
                3 => 8,
                _ => 0,
            }
        } else {
            match fcs_flag {
                0 => 0,
                1 => 2,
                2 => 4,
                3 => 8,
                _ => 0,
            }
        };
        pos += fcs_len;

        // Read blocks
        loop {
            if pos + 3 > compressed.len() {
                return Err(ZstdArchiveError::BufferTooShort {
                    expected: pos + 3,
                    actual: compressed.len(),
                });
            }
            let b0 = compressed[pos] as u32;
            let b1 = compressed[pos + 1] as u32;
            let b2 = compressed[pos + 2] as u32;
            let bh = b0 | (b1 << 8) | (b2 << 16);
            pos += 3;

            let last_block = (bh & 0x01) != 0;
            let block_type = ((bh >> 1) & 0x03) as u8;
            let block_size = (bh >> 3) as usize;

            match block_type {
                ZSTD_BLOCK_TYPE_RAW => {
                    if pos + block_size > compressed.len() {
                        return Err(ZstdArchiveError::BufferTooShort {
                            expected: pos + block_size,
                            actual: compressed.len(),
                        });
                    }
                    decompressed.extend_from_slice(&compressed[pos..pos + block_size]);
                    pos += block_size;
                }
                ZSTD_BLOCK_TYPE_RLE => {
                    if pos >= compressed.len() {
                        return Err(ZstdArchiveError::BufferTooShort {
                            expected: pos + 1,
                            actual: compressed.len(),
                        });
                    }
                    let byte_val = compressed[pos];
                    pos += 1;
                    decompressed.resize(decompressed.len() + block_size, byte_val);
                }
                ZSTD_BLOCK_TYPE_COMPRESSED => {
                    return Err(ZstdArchiveError::DecodeError(
                        "external entropy-compressed block unsupported in embedded decoder; use raw/rle or unzstd"
                            .to_string(),
                    ));
                }
                other => return Err(ZstdArchiveError::InvalidBlockType(other)),
            }

            if last_block {
                break;
            }
        }

        if checksum_flag {
            // Skip 4-byte xxHash-64 lower 32 bits
            pos += 4;
        }
    }

    Ok(decompressed)
}

// ---------------------------------------------------------------------------
// High-Level Stream Decompressor
// ---------------------------------------------------------------------------

/// High-level parser decoding Zstandard stream archives back into structured records.
pub struct IsspZstdStreamDecompressor;

impl IsspZstdStreamDecompressor {
    /// Decompress raw byte payload from Zstandard compressed archive.
    pub fn decompress_raw(compressed: &[u8]) -> Result<Vec<u8>, ZstdArchiveError> {
        decode_zstd_stream(compressed)
    }

    /// Decompress and decode binary congestion trace records ('ISTR').
    pub fn decompress_trace_records(
        compressed: &[u8],
    ) -> Result<Vec<IsspCongestionTraceRecord>, ZstdArchiveError> {
        let raw = decode_zstd_stream(compressed)?;
        IsspCongestionTraceRecord::decode_records_slice(&raw)
    }

    /// Decompress and decode binary multipath telemetry records ('ISTM').
    pub fn decompress_telemetry_records(
        compressed: &[u8],
    ) -> Result<Vec<IsspMultipathTelemetryRecord>, ZstdArchiveError> {
        let raw = decode_zstd_stream(compressed)?;
        IsspMultipathTelemetryRecord::decode_records_slice(&raw)
    }
}

// ---------------------------------------------------------------------------
// Continuous Streaming Pipeline (Writer-Backed)
// ---------------------------------------------------------------------------

/// Streaming Zstandard compression pipeline.
///
/// Ingests telemetry and congestion trace records in line-rate micro-batches,
/// writes compressed RFC 8878 frames directly to underlying storage or network sink,
/// and tracks real-time compression efficiency.
pub struct IsspZstdStreamingPipeline<W: Write> {
    writer: W,
    buffer: Vec<u8>,
    chunk_threshold: usize,
    pub telemetry: IsspZstdArchiveTelemetry,
}

impl<W: Write> IsspZstdStreamingPipeline<W> {
    /// Create a new streaming pipeline with a specified chunk buffering threshold (e.g. 64 KB).
    pub fn new(writer: W, chunk_threshold: usize) -> Self {
        Self {
            writer,
            buffer: Vec::with_capacity(chunk_threshold.max(4096)),
            chunk_threshold: chunk_threshold.max(ISSP_TRACE_RECORD_SIZE),
            telemetry: IsspZstdArchiveTelemetry::default(),
        }
    }

    /// Ingest a single congestion trace record into the compression stream.
    pub fn ingest_trace(&mut self, record: &IsspCongestionTraceRecord) -> io::Result<()> {
        let wire = record.to_wire();
        self.ingest_raw(&wire)
    }

    /// Ingest a single multipath balancing telemetry record into the compression stream.
    pub fn ingest_telemetry(&mut self, record: &IsspMultipathTelemetryRecord) -> io::Result<()> {
        let wire = record.to_wire();
        self.ingest_raw(&wire)
    }

    /// Ingest raw bytes into the pipeline buffer, flushing an RFC 8878 frame when threshold is met.
    pub fn ingest_raw(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.buffer.extend_from_slice(bytes);
        self.telemetry.total_records_ingested += (bytes.len() / ISSP_TRACE_RECORD_SIZE) as u64;
        self.telemetry.raw_bytes_in += bytes.len() as u64;

        if self.buffer.len() >= self.chunk_threshold {
            self.flush_frame()?;
        }
        Ok(())
    }

    /// Flush all buffered data into a framed Zstandard segment.
    pub fn flush_frame(&mut self) -> io::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }

        let (frame, raw_blocks, rle_blocks) = encode_zstd_chunk_with_stats(&self.buffer);
        self.writer.write_all(&frame)?;
        self.writer.flush()?;

        self.telemetry.compressed_bytes_out += frame.len() as u64;
        self.telemetry.frames_flushed += 1;
        self.telemetry.blocks_raw += raw_blocks as u64;
        self.telemetry.blocks_rle += rle_blocks as u64;
        self.telemetry.update_ratios();

        self.buffer.clear();
        Ok(())
    }

    /// Finalize the stream by flushing any pending chunk and returning the inner writer.
    pub fn finish(mut self) -> io::Result<(W, IsspZstdArchiveTelemetry)> {
        self.flush_frame()?;
        Ok((self.writer, self.telemetry))
    }
}

// ---------------------------------------------------------------------------
// In-Memory Streaming Pipeline
// ---------------------------------------------------------------------------

/// In-memory Zstandard archive pipeline compressing into a byte vector.
pub struct IsspZstdMemoryPipeline {
    inner: IsspZstdStreamingPipeline<Vec<u8>>,
}

impl IsspZstdMemoryPipeline {
    /// Create a new in-memory pipeline with specified chunk threshold.
    pub fn new(chunk_threshold: usize) -> Self {
        Self {
            inner: IsspZstdStreamingPipeline::new(Vec::new(), chunk_threshold),
        }
    }

    /// Ingest a congestion trace record.
    pub fn ingest_trace(&mut self, record: &IsspCongestionTraceRecord) {
        let _ = self.inner.ingest_trace(record);
    }

    /// Ingest a multipath telemetry record.
    pub fn ingest_telemetry(&mut self, record: &IsspMultipathTelemetryRecord) {
        let _ = self.inner.ingest_telemetry(record);
    }

    /// Ingest raw bytes.
    pub fn ingest_raw(&mut self, bytes: &[u8]) {
        let _ = self.inner.ingest_raw(bytes);
    }

    /// Complete compression and return the compressed bytes and telemetry stats.
    pub fn finish(self) -> (Vec<u8>, IsspZstdArchiveTelemetry) {
        self.inner.finish().expect("in-memory write cannot fail")
    }
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_record_wire_roundtrip() {
        let rec = IsspCongestionTraceRecord {
            node_id: 42,
            subpath_id: 3,
            congestion_phase: PHASE_CONGESTION_AVOIDANCE,
            flags: TRACE_FLAG_LOSS | TRACE_FLAG_RTT_SURGE,
            pacing_gain_q8: 288, // 1.125
            timestamp_ns: 1_700_000_000_123_456_789,
            flow_hash: 0xfeed_face_cafe_babe,
            seq_num: 1542,
            cwnd_bytes: 65536,
            bandwidth_estimate_bps: 100_000_000,
            rtt_us: 14200,
            queuing_delay_us: 3800,
        };

        let wire = rec.to_wire();
        assert_eq!(wire.len(), ISSP_TRACE_RECORD_SIZE);
        let decoded = IsspCongestionTraceRecord::from_wire(&wire).unwrap();
        assert_eq!(decoded, rec);
        assert_eq!(decoded.phase_name(), "CongestionAvoidance");
        assert!(decoded.has_flag(TRACE_FLAG_LOSS));
        assert!(decoded.has_flag(TRACE_FLAG_RTT_SURGE));
        assert!(!decoded.has_flag(TRACE_FLAG_ECN));
        assert_eq!(decoded.flags_string(), "LOSS|RTT_SURGE");

        let json = decoded.to_json_string();
        assert!(json.contains("\"node_id\":42"));
        assert!(json.contains("\"subpath_id\":3"));
        assert!(json.contains("\"phase\":\"CongestionAvoidance\""));
        assert!(json.contains("\"flags\":\"LOSS|RTT_SURGE\""));
    }

    #[test]
    fn test_multipath_telemetry_wire_roundtrip() {
        let rec = IsspMultipathTelemetryRecord {
            node_id: 101,
            active_subpaths: 4,
            total_sessions: 8500,
            avg_rtt_us: 11500,
            max_queuing_delay_us: 2900,
            timestamp_ns: 1_700_000_000_987_654_321,
            total_tx_bytes: 50_000_000_000,
            total_rx_bytes: 48_000_000_000,
            loss_events_count: 14,
            effective_throughput_bps: 950_000_000,
        };

        let wire = rec.to_wire();
        assert_eq!(wire.len(), ISSP_MULTIPATH_TELEMETRY_RECORD_SIZE);
        let decoded = IsspMultipathTelemetryRecord::from_wire(&wire).unwrap();
        assert_eq!(decoded, rec);

        let json = decoded.to_json_string();
        assert!(json.contains("\"node_id\":101"));
        assert!(json.contains("\"active_subpaths\":4"));
        assert!(json.contains("\"total_sessions\":8500"));
    }

    #[test]
    fn test_zstd_raw_and_rle_roundtrip() {
        let mut original = Vec::new();
        original.extend_from_slice(b"Header raw payload non-repeating data.");
        original.resize(original.len() + 250, 0u8); // 250 zeros -> RLE block
        original.extend_from_slice(b"Middle non-repeating sequence 1234567890.");
        original.resize(original.len() + 180, b'Q'); // 180 'Q' -> RLE block
        original.extend_from_slice(b"Trailer final block data.");

        let (comp, raw_blocks, rle_blocks) = encode_zstd_chunk_with_stats(&original);
        assert!(comp.len() < original.len());
        assert!(raw_blocks >= 2);
        assert_eq!(rle_blocks, 2);

        let decomp = decode_zstd_stream(&comp).unwrap();
        assert_eq!(decomp, original);
    }

    #[test]
    fn test_zstd_streaming_pipeline_concatenated_frames() {
        let mut pipeline = IsspZstdMemoryPipeline::new(128); // Small 128-byte threshold to force multiple frames

        for i in 0..10 {
            let rec = IsspCongestionTraceRecord {
                node_id: 1,
                subpath_id: (i % 3) as u32,
                congestion_phase: PHASE_SLOW_START,
                flags: if i % 2 == 0 { TRACE_FLAG_PROBE } else { 0 },
                pacing_gain_q8: 256,
                timestamp_ns: 1000 + i as u64,
                flow_hash: 0x1234_5678 + i as u64,
                seq_num: i as u64,
                cwnd_bytes: 32768,
                bandwidth_estimate_bps: 50_000_000,
                rtt_us: 10000,
                queuing_delay_us: 1500,
            };
            pipeline.ingest_trace(&rec);
        }

        let (compressed, telemetry) = pipeline.finish();
        assert_eq!(telemetry.total_records_ingested, 10);
        assert_eq!(telemetry.raw_bytes_in, 10 * 64);
        assert!(telemetry.frames_flushed >= 2);
        assert!(telemetry.compressed_bytes_out > 0);

        // Decompress all concatenated frames back into records
        let records = IsspZstdStreamDecompressor::decompress_trace_records(&compressed).unwrap();
        assert_eq!(records.len(), 10);
        assert_eq!(records[0].node_id, 1);
        assert_eq!(records[0].seq_num, 0);
        assert_eq!(records[9].seq_num, 9);
    }

    #[test]
    fn test_zstd_pipeline_subprocess_cli_compatibility() {
        // If /usr/bin/zstd is installed, verify that official zstd tool decodes our stream identically
        if std::path::Path::new("/usr/bin/zstd").exists() {
            let mut pipeline = IsspZstdMemoryPipeline::new(256);
            for i in 0..20 {
                let rec = IsspCongestionTraceRecord {
                    node_id: 10,
                    subpath_id: 2,
                    congestion_phase: PHASE_PROBE_BW,
                    flags: TRACE_FLAG_ECN,
                    pacing_gain_q8: 320,
                    timestamp_ns: 2000 + i as u64,
                    flow_hash: 0x9999_8888,
                    seq_num: i as u64,
                    cwnd_bytes: 131072,
                    bandwidth_estimate_bps: 120_000_000,
                    rtt_us: 8500,
                    queuing_delay_us: 900,
                };
                pipeline.ingest_trace(&rec);
            }
            let (compressed, telemetry) = pipeline.finish();
            assert_eq!(telemetry.total_records_ingested, 20);

            use std::io::Write as _;
            use std::process::{Command, Stdio};

            let mut child = Command::new("/usr/bin/zstd")
                .arg("-d")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn zstd");

            {
                let stdin = child.stdin.as_mut().expect("stdin");
                stdin.write_all(&compressed).expect("write to zstd");
            }

            let output = child.wait_with_output().expect("wait zstd");
            assert!(
                output.status.success(),
                "zstd -d stderr: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(output.stdout.len(), 20 * ISSP_TRACE_RECORD_SIZE);

            // Reconstruct records from official zstd stdout
            let records = IsspCongestionTraceRecord::decode_records_slice(&output.stdout).unwrap();
            assert_eq!(records.len(), 20);
            assert_eq!(records[19].seq_num, 19);
        }
    }
}

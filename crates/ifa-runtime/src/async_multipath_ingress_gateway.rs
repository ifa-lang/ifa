//! Asynchronous Multipath Ingress Gateway (`AsyncMultipathIngressGateway`).
//!
//! Symmetric ingress counterpart to `AsyncMultipathEgressGateway`, providing
//! asynchronous UDP network reception, zero-copy wire envelope decoding,
//! CRC32 integrity verification, real-time jitter/RTT telemetry tracking,
//! instantaneous 1+1 bicasting packet deduplication, and direct routing
//! to `MultipathStreamMux` and `HybridFecArbiter`.
//!
//! Core Architectural Guarantees:
//! 1. **Zero-Copy Wire Envelope Decoding & CRC32 Verification**:
//!    - Strictly validates `IFA_EGRESS_MAGIC` (0x49464145) and protocol version.
//!    - Verifies IEEE 802.3 CRC32 checksum over the header prefix and payload directly
//!      from the receive buffer without extra allocations.
//!    - Detects wire corruptions and bit flips before passing packets upstream.
//! 2. **Instantaneous 1+1 Bicasting & Network Deduplication (Zero-Copy Bitset)**:
//!    - Employs a sliding-window bitset deduplicator tracking sequence numbers per flow.
//!    - Drops redundant 1+1 bicasting copies and transient network duplicates in O(1) time.
//!    - Retains **zero payload buffers** for deduplication, eliminating memory bloat.
//! 3. **Real-Time Subpath Jitter & One-Way Latency / RTT Tracking**:
//!    - Measures one-way transit delay using monotonic departure timestamps.
//!    - Computes RFC 3550 style interarrival jitter and EWMA smoothed RTT (SRTT).
//!    - Tracks minimum and maximum transit latencies per physical subpath interface.
//! 4. **Direct Demultiplexing & Dispatch**:
//!    - Routes verified application stream frames directly into `MultipathStreamMux`.
//!    - Directs forward error correction (FEC) parity symbols to redundancy processors.
//!    - Delivers un-framed raw payloads to application ingress queues.
//! 5. **Unified Observability & Audit**:
//!    - OpenMetrics / Prometheus exposition (`export_prometheus_metrics`).
//!    - Structured JSON audit trail (`generate_json_audit_trail`).
//!    - In-memory micro-benchmark suite (`run_async_multipath_ingress_gateway_benchmark`).
//!
//! Zero-simulation guarantee: operates strictly on real non-blocking sockets,
//! concrete timestamps, and physical wire envelopes.

#![allow(clippy::manual_is_multiple_of, clippy::too_many_arguments)]

use std::collections::{BTreeMap, VecDeque};
use std::fmt::Write as FmtWrite;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::async_multipath_egress_gateway::{
    EgressGatewayError, EgressWireEnvelope, EgressWireHeader, EGRESS_HEADER_SIZE, FLAG_BICAST_COPY,
    IFA_EGRESS_MAGIC, IFA_EGRESS_VERSION,
};
use crate::multipath_pacing_coordinator::OutboundItemKind;
use crate::multipath_stream_mux::{
    FlowControlFrame, MultipathStreamMux, StreamFrame, StreamId, StreamPriority,
};
use crate::reactor::AsyncUdpSocket;
use crate::traffic_slicing::FlowSliceClass;

// ---------------------------------------------------------------------------
// Deduplication Types & Sliding Window Bitset
// ---------------------------------------------------------------------------

/// Result of evaluating a packet's sequence number against the deduplication window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeduplicationResult {
    /// Packet is seen for the first time within the active window.
    FirstSeen,
    /// Packet is a duplicate of a previously received packet.
    Duplicate,
    /// Packet sequence number is too old (fell outside the trailing edge of the sliding window).
    TooOld,
}

/// Zero-copy sliding window deduplication tracker for a single flow.
///
/// Uses a circular bitset of configurable size (e.g. 4096 packets) to achieve O(1)
/// deduplication checks and insertions without retaining payload buffers in memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowDeduplicationWindow {
    /// Highest sequence number observed so far for this flow.
    pub highest_sequence: u64,
    /// Size of the sliding window in packets.
    pub window_size: usize,
    /// Circular bitset words (64 bits per word).
    bitset: Vec<u64>,
    /// Total count of unique packets accepted.
    pub total_first_seen: u64,
    /// Total count of duplicate packets rejected.
    pub total_duplicates: u64,
    /// Total count of packets rejected as too old.
    pub total_too_old: u64,
}

impl FlowDeduplicationWindow {
    /// Create a new deduplication window with the specified capacity in packets.
    pub fn new(window_size: usize) -> Self {
        let size = window_size.max(64);
        let words = size.div_ceil(64);
        Self {
            highest_sequence: 0,
            window_size: size,
            bitset: vec![0u64; words],
            total_first_seen: 0,
            total_duplicates: 0,
            total_too_old: 0,
        }
    }

    /// Check and mark a sequence number.
    /// Returns whether this packet is first seen, duplicate, or too old.
    pub fn check_and_mark(&mut self, sequence_number: u64) -> DeduplicationResult {
        if self.total_first_seen == 0 {
            // Very first packet received for this flow
            self.highest_sequence = sequence_number;
            let bit_idx = (sequence_number % self.window_size as u64) as usize;
            self.bitset[bit_idx / 64] |= 1u64 << (bit_idx % 64);
            self.total_first_seen += 1;
            return DeduplicationResult::FirstSeen;
        }

        if sequence_number > self.highest_sequence {
            let delta = sequence_number - self.highest_sequence;
            if delta >= self.window_size as u64 {
                // Large forward jump: wipe the entire bitset
                self.bitset.fill(0);
            } else {
                // Clear the bitset slots between old highest and new highest
                for s in (self.highest_sequence + 1)..=sequence_number {
                    let idx = (s % self.window_size as u64) as usize;
                    self.bitset[idx / 64] &= !(1u64 << (idx % 64));
                }
            }

            let bit_idx = (sequence_number % self.window_size as u64) as usize;
            self.bitset[bit_idx / 64] |= 1u64 << (bit_idx % 64);
            self.highest_sequence = sequence_number;
            self.total_first_seen += 1;
            DeduplicationResult::FirstSeen
        } else {
            let age = self.highest_sequence - sequence_number;
            if age >= self.window_size as u64 {
                self.total_too_old += 1;
                DeduplicationResult::TooOld
            } else {
                let bit_idx = (sequence_number % self.window_size as u64) as usize;
                let word_idx = bit_idx / 64;
                let mask = 1u64 << (bit_idx % 64);

                if (self.bitset[word_idx] & mask) != 0 {
                    self.total_duplicates += 1;
                    DeduplicationResult::Duplicate
                } else {
                    self.bitset[word_idx] |= mask;
                    self.total_first_seen += 1;
                    DeduplicationResult::FirstSeen
                }
            }
        }
    }
}

/// Multipath bicasting and network deduplicator managing per-flow sliding windows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BicastSlidingWindowDeduplicator {
    windows: BTreeMap<u64, FlowDeduplicationWindow>,
    window_size: usize,
}

impl BicastSlidingWindowDeduplicator {
    /// Create a new multipath deduplicator with default or customized window size.
    pub fn new(window_size: usize) -> Self {
        Self {
            windows: BTreeMap::new(),
            window_size: window_size.max(64),
        }
    }

    /// Check and mark a packet's sequence number within its flow.
    pub fn check_and_mark(&mut self, flow_id: u64, sequence_number: u64) -> DeduplicationResult {
        let win_size = self.window_size;
        let window = self
            .windows
            .entry(flow_id)
            .or_insert_with(|| FlowDeduplicationWindow::new(win_size));
        window.check_and_mark(sequence_number)
    }

    /// Total number of unique flows tracked.
    pub fn active_flows_count(&self) -> usize {
        self.windows.len()
    }

    /// Total duplicate packets rejected across all flows.
    pub fn total_duplicates(&self) -> u64 {
        self.windows.values().map(|w| w.total_duplicates).sum()
    }

    /// Total too-old packets rejected across all flows.
    pub fn total_too_old(&self) -> u64 {
        self.windows.values().map(|w| w.total_too_old).sum()
    }
}

// ---------------------------------------------------------------------------
// Subpath Real-Time RTT & Jitter Tracking
// ---------------------------------------------------------------------------

/// Real-time one-way transit latency and interarrival jitter tracker for a subpath interface.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SubpathMetricsTracker {
    pub subpath_id: u32,
    pub packets_received: u64,
    pub bytes_received: u64,
    pub last_departure_ns: u64,
    pub last_arrival_ns: u64,
    pub last_transit_ns: u64,
    pub srtt_ns: u64,
    pub min_rtt_ns: u64,
    pub max_rtt_ns: u64,
    pub jitter_ns: u64,
}

impl SubpathMetricsTracker {
    /// Create a new tracker for the specified subpath.
    pub fn new(subpath_id: u32) -> Self {
        Self {
            subpath_id,
            ..Default::default()
        }
    }

    /// Record a packet transit sample.
    pub fn record_sample(&mut self, departure_ns: u64, arrival_ns: u64, bytes: usize) {
        let transit_ns = arrival_ns.saturating_sub(departure_ns);

        if self.packets_received == 0 {
            self.srtt_ns = transit_ns;
            self.min_rtt_ns = transit_ns;
            self.max_rtt_ns = transit_ns;
            self.jitter_ns = 0;
        } else {
            self.min_rtt_ns = self.min_rtt_ns.min(transit_ns);
            self.max_rtt_ns = self.max_rtt_ns.max(transit_ns);

            // RFC 6298 style EWMA for smoothed one-way RTT: 7/8 * srtt + 1/8 * transit
            self.srtt_ns = (self.srtt_ns * 7 + transit_ns) / 8;

            // RFC 3550 interarrival jitter: J = J + (|D| - J) / 16
            let diff = transit_ns.abs_diff(self.last_transit_ns);
            self.jitter_ns = (self.jitter_ns * 15 + diff) / 16;
        }

        self.last_departure_ns = departure_ns;
        self.last_arrival_ns = arrival_ns;
        self.last_transit_ns = transit_ns;
        self.packets_received += 1;
        self.bytes_received += bytes as u64;
    }
}

// ---------------------------------------------------------------------------
// Physical Ingress Interface Definition
// ---------------------------------------------------------------------------

/// Physical or asynchronous network interface attached to the ingress gateway.
#[derive(Clone)]
pub struct PhysicalIngressInterface {
    pub subpath_id: u32,
    pub interface_name: String,
    pub socket: Arc<AsyncUdpSocket>,
    pub peer_addr: SocketAddr,
    pub active: bool,
    pub metrics: SubpathMetricsTracker,
    pub crc_errors: u64,
    pub duplicates_dropped: u64,
    pub bicast_duplicates_dropped: u64,
    pub would_block_count: u64,
    pub last_receive_ns: u64,
}

impl PhysicalIngressInterface {
    /// Create a new physical ingress interface descriptor.
    pub fn new(
        subpath_id: u32,
        interface_name: impl Into<String>,
        socket: Arc<AsyncUdpSocket>,
        peer_addr: SocketAddr,
        now_ns: u64,
    ) -> Self {
        Self {
            subpath_id,
            interface_name: interface_name.into(),
            socket,
            peer_addr,
            active: true,
            metrics: SubpathMetricsTracker::new(subpath_id),
            crc_errors: 0,
            duplicates_dropped: 0,
            bicast_duplicates_dropped: 0,
            would_block_count: 0,
            last_receive_ns: now_ns,
        }
    }
}

// ---------------------------------------------------------------------------
// Error Types
// ---------------------------------------------------------------------------

/// Errors encountered during ingress receiving, zero-copy decoding, or routing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngressGatewayError {
    /// Target subpath interface was not registered in the gateway.
    SubpathNotFound(u32),
    /// Subpath interface is administratively down or offline.
    InterfaceOffline(u32),
    /// Ingress buffer is too small to contain minimum wire envelope.
    BufferTooSmall { required: usize, provided: usize },
    /// Magic constant mismatch in received wire packet.
    InvalidMagic { expected: u32, received: u32 },
    /// CRC32 integrity check failed.
    CrcMismatch { computed: u32, embedded: u32 },
    /// Wire packet header corrupted or malformed.
    CorruptedHeader(String),
    /// Underlying socket transmission/reception failed.
    SocketError(String),
    /// Stream multiplexer ingestion error.
    StreamMuxError(String),
    /// Frame decoding failed.
    StreamDecodingError(String),
}

impl std::fmt::Display for IngressGatewayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SubpathNotFound(id) => write!(f, "Subpath interface {} not found", id),
            Self::InterfaceOffline(id) => write!(f, "Subpath interface {} is offline", id),
            Self::BufferTooSmall { required, provided } => {
                write!(
                    f,
                    "Ingress buffer too small: required {}, provided {}",
                    required, provided
                )
            }
            Self::InvalidMagic { expected, received } => {
                write!(
                    f,
                    "Invalid magic: expected 0x{:08X}, received 0x{:08X}",
                    expected, received
                )
            }
            Self::CrcMismatch { computed, embedded } => {
                write!(
                    f,
                    "CRC32 mismatch: computed 0x{:08X}, embedded 0x{:08X}",
                    computed, embedded
                )
            }
            Self::CorruptedHeader(msg) => write!(f, "Corrupted wire header: {}", msg),
            Self::SocketError(err) => write!(f, "Socket I/O error: {}", err),
            Self::StreamMuxError(err) => write!(f, "Stream multiplexer error: {}", err),
            Self::StreamDecodingError(err) => write!(f, "Stream frame decoding error: {}", err),
        }
    }
}

impl std::error::Error for IngressGatewayError {}

// ---------------------------------------------------------------------------
// Ingress Packets & Dispatch Targets
// ---------------------------------------------------------------------------

/// Direct routing target of an accepted and validated ingress payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestPayloadTarget {
    /// Ingested into `MultipathStreamMux` as an application stream frame.
    StreamFrameMux {
        stream_id: StreamId,
        offset: u64,
        newly_contiguous_bytes: usize,
        stream_completed: bool,
        hol_blocking_prevented: bool,
    },
    /// Ingested as a flow control signaling frame.
    ControlFrame,
    /// Forward Error Correction (FEC) redundancy block or parity symbol.
    FecParity,
    /// Un-framed raw application payload retained in gateway ingress queue.
    RawPayload { bytes: usize },
}

/// Detailed outcome of ingesting a single wire packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestPacketOutcome {
    /// Packet validated, deduplicated, and routed upstream.
    Accepted {
        flow_id: u64,
        sequence_number: u64,
        bytes: usize,
        target: IngestPayloadTarget,
        transit_latency_ns: u64,
    },
    /// Duplicate packet dropped (including 1+1 bicasting copies).
    Duplicate {
        flow_id: u64,
        sequence_number: u64,
        is_bicast_flag: bool,
    },
    /// Packet rejected because its sequence number is older than the sliding window.
    DroppedTooOld { flow_id: u64, sequence_number: u64 },
    /// Packet rejected due to CRC32 corruption.
    CorruptedCrc { computed: u32, embedded: u32 },
}

/// Validated raw ingress packet stored in the gateway's queue when stream mux is bypassed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedIngressPacket {
    pub header: EgressWireHeader,
    pub subpath_id: u32,
    pub arrival_time_ns: u64,
    pub transit_latency_ns: u64,
    pub payload: Vec<u8>,
}

/// Validated FEC parity symbol or redundancy record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FecParityRecord {
    pub subpath_id: u32,
    pub flow_id: u64,
    pub sequence_number: u64,
    pub slice_class: FlowSliceClass,
    pub arrival_time_ns: u64,
    pub transit_latency_ns: u64,
    pub payload: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration options for the `AsyncMultipathIngressGateway`.
#[derive(Debug, Clone, PartialEq)]
pub struct AsyncMultipathIngressGatewayConfig {
    /// Maximum number of packets received across all interfaces in a single cycle.
    pub max_batch_size: usize,
    /// Sliding window size in packets for per-flow deduplication.
    pub dedup_window_size: usize,
    /// Pre-allocated scratch receive buffer size.
    pub scratch_buffer_size: usize,
    /// Whether to route application frames directly into `MultipathStreamMux`.
    pub enable_stream_mux: bool,
    /// Automatically register unknown stream IDs into the multiplexer.
    pub auto_register_streams: bool,
    /// Default initial window size for auto-registered streams (bytes).
    pub default_stream_window: u64,
}

impl Default for AsyncMultipathIngressGatewayConfig {
    fn default() -> Self {
        Self {
            max_batch_size: 64,
            dedup_window_size: 4096,
            scratch_buffer_size: 65_536,
            enable_stream_mux: true,
            auto_register_streams: true,
            default_stream_window: 262_144, // 256 KiB
        }
    }
}

// ---------------------------------------------------------------------------
// Telemetry & Reports
// ---------------------------------------------------------------------------

/// Telemetry metrics for the `AsyncMultipathIngressGateway`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AsyncMultipathIngressGatewayTelemetry {
    pub total_wire_packets_received: u64,
    pub total_wire_bytes_received: u64,
    pub total_packets_accepted: u64,
    pub total_duplicates_dropped: u64,
    pub total_bicast_duplicates_dropped: u64,
    pub total_too_old_dropped: u64,
    pub total_crc_errors: u64,
    pub total_stream_frames_ingested: u64,
    pub total_control_frames_ingested: u64,
    pub total_fec_parity_ingested: u64,
    pub total_raw_packets_ingested: u64,
    pub total_would_block_events: u64,
    pub active_interfaces_count: usize,
    pub active_flows_tracked: usize,
}

/// Detailed outcome of an ingress processing cycle.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct IngressCycleReport {
    pub packets_received: usize,
    pub bytes_received: u64,
    pub packets_accepted: usize,
    pub duplicates_dropped: usize,
    pub bicast_duplicates_dropped: usize,
    pub crc_errors: usize,
    pub would_block_count: usize,
    pub active_interfaces: usize,
}

/// In-memory benchmark report for the ingress gateway.
#[derive(Debug, Clone, PartialEq)]
pub struct IngressGatewayBenchmarkReport {
    pub iterations: usize,
    pub elapsed_us: u64,
    pub total_bytes_processed: u64,
    pub total_packets_processed: u64,
    pub total_duplicates_filtered: u64,
    pub throughput_mbps: f64,
    pub pps: f64,
    pub avg_latency_ns: f64,
}

// ---------------------------------------------------------------------------
// Async Multipath Ingress Gateway Implementation
// ---------------------------------------------------------------------------

/// Asynchronous Multipath Ingress Gateway.
pub struct AsyncMultipathIngressGateway {
    config: AsyncMultipathIngressGatewayConfig,
    interfaces: BTreeMap<u32, PhysicalIngressInterface>,
    deduplicator: BicastSlidingWindowDeduplicator,
    stream_mux: MultipathStreamMux,
    raw_ingress_queue: VecDeque<ValidatedIngressPacket>,
    received_fec_parity_queue: VecDeque<FecParityRecord>,
    scratch_rx_buffer: Vec<u8>,
    telemetry: AsyncMultipathIngressGatewayTelemetry,
}

impl AsyncMultipathIngressGateway {
    /// Create a new ingress gateway with specified configuration.
    pub fn new(config: AsyncMultipathIngressGatewayConfig) -> Self {
        let dedup_window = config.dedup_window_size;
        let scratch_size = config.scratch_buffer_size;
        Self {
            config,
            interfaces: BTreeMap::new(),
            deduplicator: BicastSlidingWindowDeduplicator::new(dedup_window),
            stream_mux: MultipathStreamMux::new(),
            raw_ingress_queue: VecDeque::new(),
            received_fec_parity_queue: VecDeque::new(),
            scratch_rx_buffer: vec![0u8; scratch_size],
            telemetry: AsyncMultipathIngressGatewayTelemetry::default(),
        }
    }

    /// Register a physical ingress interface.
    pub fn register_interface(
        &mut self,
        interface: PhysicalIngressInterface,
    ) -> Result<(), IngressGatewayError> {
        let sid = interface.subpath_id;
        self.interfaces.insert(sid, interface);
        self.telemetry.active_interfaces_count = self.interfaces.len();
        Ok(())
    }

    /// Set an interface administrative status (active/offline).
    pub fn set_interface_active(&mut self, subpath_id: u32, active: bool) {
        if let Some(iface) = self.interfaces.get_mut(&subpath_id) {
            iface.active = active;
        }
    }

    /// Access reference to the coupled `MultipathStreamMux`.
    pub fn stream_mux(&self) -> &MultipathStreamMux {
        &self.stream_mux
    }

    /// Access mutable reference to the coupled `MultipathStreamMux`.
    pub fn stream_mux_mut(&mut self) -> &mut MultipathStreamMux {
        &mut self.stream_mux
    }

    /// Ingest a single raw wire packet received from a subpath interface.
    ///
    /// Performs zero-copy envelope decoding, CRC32 integrity verification,
    /// subpath RTT/jitter calculation, 1+1 bicasting deduplication, and
    /// direct demultiplexing to `MultipathStreamMux` or redundancy queues.
    pub fn ingest_wire_packet(
        &mut self,
        subpath_id: u32,
        packet_bytes: &[u8],
        now_ns: u64,
    ) -> Result<IngestPacketOutcome, IngressGatewayError> {
        self.telemetry.total_wire_packets_received += 1;
        self.telemetry.total_wire_bytes_received += packet_bytes.len() as u64;

        // 1. Zero-copy envelope decoding and CRC32 verification
        let (header, payload_slice) = match EgressWireEnvelope::decode_packet(packet_bytes) {
            Ok(res) => res,
            Err(EgressGatewayError::CrcMismatch { computed, embedded }) => {
                self.telemetry.total_crc_errors += 1;
                if let Some(iface) = self.interfaces.get_mut(&subpath_id) {
                    iface.crc_errors += 1;
                }
                return Ok(IngestPacketOutcome::CorruptedCrc { computed, embedded });
            }
            Err(e) => {
                return Err(IngressGatewayError::CorruptedHeader(e.to_string()));
            }
        };

        // 2. Real-time RTT & Jitter tracking for this subpath
        let transit_latency_ns = now_ns.saturating_sub(header.departure_time_ns);
        if let Some(iface) = self.interfaces.get_mut(&subpath_id) {
            iface
                .metrics
                .record_sample(header.departure_time_ns, now_ns, packet_bytes.len());
            iface.last_receive_ns = now_ns;
        }

        // 3. Instantaneous sliding-window deduplication (Zero-Copy Bitset)
        let is_bicast_flag = (header.flags & FLAG_BICAST_COPY) != 0;
        let dedup_result = self
            .deduplicator
            .check_and_mark(header.flow_id, header.sequence_number);

        self.telemetry.active_flows_tracked = self.deduplicator.active_flows_count();

        match dedup_result {
            DeduplicationResult::Duplicate => {
                self.telemetry.total_duplicates_dropped += 1;
                if is_bicast_flag {
                    self.telemetry.total_bicast_duplicates_dropped += 1;
                }
                if let Some(iface) = self.interfaces.get_mut(&subpath_id) {
                    iface.duplicates_dropped += 1;
                    if is_bicast_flag {
                        iface.bicast_duplicates_dropped += 1;
                    }
                }
                return Ok(IngestPacketOutcome::Duplicate {
                    flow_id: header.flow_id,
                    sequence_number: header.sequence_number,
                    is_bicast_flag,
                });
            }
            DeduplicationResult::TooOld => {
                self.telemetry.total_too_old_dropped += 1;
                return Ok(IngestPacketOutcome::DroppedTooOld {
                    flow_id: header.flow_id,
                    sequence_number: header.sequence_number,
                });
            }
            DeduplicationResult::FirstSeen => {
                self.telemetry.total_packets_accepted += 1;
            }
        }

        // 4. Direct Demultiplexing & Dispatch
        let target = self.dispatch_accepted_payload(&header, subpath_id, payload_slice, now_ns)?;

        Ok(IngestPacketOutcome::Accepted {
            flow_id: header.flow_id,
            sequence_number: header.sequence_number,
            bytes: payload_slice.len(),
            target,
            transit_latency_ns,
        })
    }

    /// Dispatch validated payload according to its outbound item kind and flags.
    fn dispatch_accepted_payload(
        &mut self,
        header: &EgressWireHeader,
        subpath_id: u32,
        payload: &[u8],
        now_ns: u64,
    ) -> Result<IngestPayloadTarget, IngressGatewayError> {
        match header.item_kind {
            OutboundItemKind::DataPacket | OutboundItemKind::ArqRetransmission { .. } => {
                if self.config.enable_stream_mux {
                    // Attempt decoding as StreamFrame
                    if let Ok(mut frame) = StreamFrame::decode(payload) {
                        frame.subpath_id = subpath_id as u8;

                        match self.stream_mux.ingest_incoming_frame(frame) {
                            Ok(outcome) => {
                                self.telemetry.total_stream_frames_ingested += 1;
                                Ok(IngestPayloadTarget::StreamFrameMux {
                                    stream_id: outcome.stream_id,
                                    offset: 0,
                                    newly_contiguous_bytes: outcome.newly_contiguous_bytes,
                                    stream_completed: outcome.stream_completed,
                                    hol_blocking_prevented: outcome.hol_blocking_prevented,
                                })
                            }
                            Err(e) => Err(IngressGatewayError::StreamMuxError(format!("{:?}", e))),
                        }
                    } else if let Ok(ctrl) = FlowControlFrame::decode(payload) {
                        let _ = self.stream_mux.ingest_control_frame(ctrl);
                        self.telemetry.total_control_frames_ingested += 1;
                        Ok(IngestPayloadTarget::ControlFrame)
                    } else {
                        // Store in raw queue
                        self.raw_ingress_queue.push_back(ValidatedIngressPacket {
                            header: header.clone(),
                            subpath_id,
                            arrival_time_ns: now_ns,
                            transit_latency_ns: now_ns.saturating_sub(header.departure_time_ns),
                            payload: payload.to_vec(),
                        });
                        self.telemetry.total_raw_packets_ingested += 1;
                        Ok(IngestPayloadTarget::RawPayload {
                            bytes: payload.len(),
                        })
                    }
                } else {
                    self.raw_ingress_queue.push_back(ValidatedIngressPacket {
                        header: header.clone(),
                        subpath_id,
                        arrival_time_ns: now_ns,
                        transit_latency_ns: now_ns.saturating_sub(header.departure_time_ns),
                        payload: payload.to_vec(),
                    });
                    self.telemetry.total_raw_packets_ingested += 1;
                    Ok(IngestPayloadTarget::RawPayload {
                        bytes: payload.len(),
                    })
                }
            }
            OutboundItemKind::FecParitySymbol { .. } => {
                self.received_fec_parity_queue.push_back(FecParityRecord {
                    subpath_id,
                    flow_id: header.flow_id,
                    sequence_number: header.sequence_number,
                    slice_class: header.slice_class,
                    arrival_time_ns: now_ns,
                    transit_latency_ns: now_ns.saturating_sub(header.departure_time_ns),
                    payload: payload.to_vec(),
                });
                self.telemetry.total_fec_parity_ingested += 1;
                Ok(IngestPayloadTarget::FecParity)
            }
            OutboundItemKind::ProbePacket => {
                // Handled during RTT/jitter sample recording above
                Ok(IngestPayloadTarget::RawPayload {
                    bytes: payload.len(),
                })
            }
        }
    }

    /// Non-blocking polling cycle across all active registered physical interfaces.
    pub fn process_ingress_cycle(
        &mut self,
        now_ns: u64,
        max_batch: Option<usize>,
    ) -> IngressCycleReport {
        let batch_limit = max_batch.unwrap_or(self.config.max_batch_size);
        let mut report = IngressCycleReport {
            active_interfaces: self.interfaces.values().filter(|i| i.active).count(),
            ..Default::default()
        };

        let subpath_ids: Vec<u32> = self.interfaces.keys().copied().collect();

        for sid in subpath_ids {
            if report.packets_received >= batch_limit {
                break;
            }

            let max_subpath_packets = batch_limit - report.packets_received;
            if let Ok(subpath_report) = self.poll_interface(sid, now_ns, max_subpath_packets) {
                report.packets_received += subpath_report.packets_received;
                report.bytes_received += subpath_report.bytes_received;
                report.packets_accepted += subpath_report.packets_accepted;
                report.duplicates_dropped += subpath_report.duplicates_dropped;
                report.bicast_duplicates_dropped += subpath_report.bicast_duplicates_dropped;
                report.crc_errors += subpath_report.crc_errors;
                report.would_block_count += subpath_report.would_block_count;
            }
        }

        report
    }

    /// Poll a single registered physical interface up to `max_packets`.
    pub fn poll_interface(
        &mut self,
        subpath_id: u32,
        now_ns: u64,
        max_packets: usize,
    ) -> Result<IngressCycleReport, IngressGatewayError> {
        let (socket, active) = {
            let iface = self
                .interfaces
                .get(&subpath_id)
                .ok_or(IngressGatewayError::SubpathNotFound(subpath_id))?;
            (iface.socket.clone(), iface.active)
        };

        if !active {
            return Err(IngressGatewayError::InterfaceOffline(subpath_id));
        }

        let mut report = IngressCycleReport::default();

        for _ in 0..max_packets {
            match socket.try_recv_from(&mut self.scratch_rx_buffer) {
                Ok(Some((n, _peer_addr))) => {
                    report.packets_received += 1;
                    report.bytes_received += n as u64;

                    let wire_packet = self.scratch_rx_buffer[0..n].to_vec();
                    match self.ingest_wire_packet(subpath_id, &wire_packet, now_ns) {
                        Ok(IngestPacketOutcome::Accepted { .. }) => {
                            report.packets_accepted += 1;
                        }
                        Ok(IngestPacketOutcome::Duplicate { is_bicast_flag, .. }) => {
                            report.duplicates_dropped += 1;
                            if is_bicast_flag {
                                report.bicast_duplicates_dropped += 1;
                            }
                        }
                        Ok(IngestPacketOutcome::DroppedTooOld { .. }) => {
                            report.duplicates_dropped += 1;
                        }
                        Ok(IngestPacketOutcome::CorruptedCrc { .. }) => {
                            report.crc_errors += 1;
                        }
                        Err(_) => {}
                    }
                }
                Ok(None) => {
                    // WouldBlock - no more datagrams on this socket right now
                    if let Some(iface) = self.interfaces.get_mut(&subpath_id) {
                        iface.would_block_count += 1;
                    }
                    self.telemetry.total_would_block_events += 1;
                    report.would_block_count += 1;
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if let Some(iface) = self.interfaces.get_mut(&subpath_id) {
                        iface.would_block_count += 1;
                    }
                    self.telemetry.total_would_block_events += 1;
                    report.would_block_count += 1;
                    break;
                }
                Err(e) => {
                    return Err(IngressGatewayError::SocketError(e.to_string()));
                }
            }
        }

        Ok(report)
    }

    /// Read reassembled stream data directly from `MultipathStreamMux`.
    pub fn read_stream_data(&mut self, stream_id: StreamId, max_len: usize) -> Option<Vec<u8>> {
        self.stream_mux.read_stream(stream_id, max_len)
    }

    /// Retrieve and pop the next raw un-framed packet from the ingress queue.
    pub fn pop_raw_packet(&mut self) -> Option<ValidatedIngressPacket> {
        self.raw_ingress_queue.pop_front()
    }

    /// Retrieve and pop the next received FEC parity record.
    pub fn pop_fec_parity(&mut self) -> Option<FecParityRecord> {
        self.received_fec_parity_queue.pop_front()
    }

    /// Access subpath metrics tracker for an interface.
    pub fn subpath_metrics(&self, subpath_id: u32) -> Option<&SubpathMetricsTracker> {
        self.interfaces.get(&subpath_id).map(|i| &i.metrics)
    }

    /// Access telemetry statistics.
    pub fn telemetry(&self) -> &AsyncMultipathIngressGatewayTelemetry {
        &self.telemetry
    }

    /// Export operational metrics in OpenMetrics / Prometheus exposition format.
    pub fn export_prometheus_metrics(&self) -> String {
        let mut out = String::with_capacity(2048);
        let t = &self.telemetry;

        let _ = writeln!(
            out,
            "# HELP ifa_ingress_packets_received_total Total wire datagrams received."
        );
        let _ = writeln!(out, "# TYPE ifa_ingress_packets_received_total counter");
        let _ = writeln!(
            out,
            "ifa_ingress_packets_received_total {}",
            t.total_wire_packets_received
        );

        let _ = writeln!(
            out,
            "# HELP ifa_ingress_bytes_received_total Total wire bytes received."
        );
        let _ = writeln!(out, "# TYPE ifa_ingress_bytes_received_total counter");
        let _ = writeln!(
            out,
            "ifa_ingress_bytes_received_total {}",
            t.total_wire_bytes_received
        );

        let _ = writeln!(
            out,
            "# HELP ifa_ingress_packets_accepted_total Total packets validated and accepted."
        );
        let _ = writeln!(out, "# TYPE ifa_ingress_packets_accepted_total counter");
        let _ = writeln!(
            out,
            "ifa_ingress_packets_accepted_total {}",
            t.total_packets_accepted
        );

        let _ = writeln!(
            out,
            "# HELP ifa_ingress_duplicates_dropped_total Total duplicate packets dropped."
        );
        let _ = writeln!(out, "# TYPE ifa_ingress_duplicates_dropped_total counter");
        let _ = writeln!(
            out,
            "ifa_ingress_duplicates_dropped_total {}",
            t.total_duplicates_dropped
        );

        let _ = writeln!(out, "# HELP ifa_ingress_bicast_duplicates_dropped_total Total 1+1 bicasting copies deduplicated.");
        let _ = writeln!(
            out,
            "# TYPE ifa_ingress_bicast_duplicates_dropped_total counter"
        );
        let _ = writeln!(
            out,
            "ifa_ingress_bicast_duplicates_dropped_total {}",
            t.total_bicast_duplicates_dropped
        );

        let _ = writeln!(
            out,
            "# HELP ifa_ingress_crc_errors_total Total packets rejected due to CRC32 corruption."
        );
        let _ = writeln!(out, "# TYPE ifa_ingress_crc_errors_total counter");
        let _ = writeln!(out, "ifa_ingress_crc_errors_total {}", t.total_crc_errors);

        let _ = writeln!(out, "# HELP ifa_ingress_stream_frames_ingested_total Stream frames passed to MultipathStreamMux.");
        let _ = writeln!(
            out,
            "# TYPE ifa_ingress_stream_frames_ingested_total counter"
        );
        let _ = writeln!(
            out,
            "ifa_ingress_stream_frames_ingested_total {}",
            t.total_stream_frames_ingested
        );

        for (sid, iface) in &self.interfaces {
            let m = &iface.metrics;
            let _ = writeln!(
                out,
                "ifa_ingress_subpath_srtt_ns{{subpath_id=\"{}\",iface=\"{}\"}} {}",
                sid, iface.interface_name, m.srtt_ns
            );
            let _ = writeln!(
                out,
                "ifa_ingress_subpath_jitter_ns{{subpath_id=\"{}\",iface=\"{}\"}} {}",
                sid, iface.interface_name, m.jitter_ns
            );
        }

        out
    }

    /// Generate structured JSON audit trail.
    pub fn generate_json_audit_trail(&self) -> String {
        let mut out = String::with_capacity(1024);
        let t = &self.telemetry;

        let _ = write!(
            out,
            "{{\"wire_packets_received\":{},\"wire_bytes_received\":{},\"packets_accepted\":{},\"duplicates_dropped\":{},\"bicast_duplicates_dropped\":{},\"too_old_dropped\":{},\"crc_errors\":{},\"stream_frames\":{},\"control_frames\":{},\"fec_parity\":{},\"raw_packets\":{},\"active_flows\":{},\"active_interfaces\":{}}}",
            t.total_wire_packets_received,
            t.total_wire_bytes_received,
            t.total_packets_accepted,
            t.total_duplicates_dropped,
            t.total_bicast_duplicates_dropped,
            t.total_too_old_dropped,
            t.total_crc_errors,
            t.total_stream_frames_ingested,
            t.total_control_frames_ingested,
            t.total_fec_parity_ingested,
            t.total_raw_packets_ingested,
            t.active_flows_tracked,
            t.active_interfaces_count
        );

        out
    }
}

// ---------------------------------------------------------------------------
// In-Memory Micro-Benchmark Suite
// ---------------------------------------------------------------------------

/// Execute a micro-benchmark of the `AsyncMultipathIngressGateway`.
pub fn run_async_multipath_ingress_gateway_benchmark(
    iterations: usize,
) -> IngressGatewayBenchmarkReport {
    let config = AsyncMultipathIngressGatewayConfig {
        max_batch_size: 128,
        dedup_window_size: 4096,
        scratch_buffer_size: 65_536,
        enable_stream_mux: true,
        auto_register_streams: true,
        default_stream_window: 262_144,
    };

    let mut gateway = AsyncMultipathIngressGateway::new(config);
    let now_ns = 1_000_000_000u64;

    // Synthesize valid wire envelopes
    let mut packets = Vec::with_capacity(iterations);
    let raw_payload = vec![0x37u8; 512];

    for i in 0..iterations {
        let flow_index = (i / 2) % 4;
        let s_id = StreamId::client_bidi(flow_index as u64);
        let seq = (i / 2) as u64; // Paired packets share flow and sequence (bicast duplicates)
        let frame = StreamFrame {
            stream_id: s_id,
            offset: (seq * 512),
            payload: raw_payload.clone(),
            fin: false,
            slice_class: FlowSliceClass::UltraLowLatency,
            priority: StreamPriority::CriticalControl,
            subpath_id: 1,
            seq_num: seq,
            is_bicast: i % 2 == 1,
        };
        let encoded_frame = frame.encode();

        let header = EgressWireHeader {
            magic: IFA_EGRESS_MAGIC,
            version: IFA_EGRESS_VERSION,
            slice_class: FlowSliceClass::UltraLowLatency,
            item_kind: OutboundItemKind::DataPacket,
            flags: if i % 2 == 1 { FLAG_BICAST_COPY } else { 0 },
            subpath_id: (i % 2 + 1) as u32,
            flow_id: s_id.raw(),
            sequence_number: seq,
            departure_time_ns: now_ns.saturating_sub(10_000_000),
            payload_length: encoded_frame.len() as u32,
            crc32: 0,
        };

        let mut envelope = EgressWireEnvelope::new(header, &encoded_frame);
        let mut target = vec![0u8; EGRESS_HEADER_SIZE + encoded_frame.len()];
        let wire_len = envelope.serialize_into(&mut target).expect("serialize");
        packets.push(target[0..wire_len].to_vec());
    }

    let start = std::time::Instant::now();
    let mut total_bytes = 0u64;

    for (i, p) in packets.iter().enumerate() {
        let sid = (i % 2 + 1) as u32;
        let _ = gateway.ingest_wire_packet(sid, p, now_ns + (i as u64 * 500));
        total_bytes += p.len() as u64;
    }

    let elapsed = start.elapsed();
    let elapsed_us = elapsed.as_micros().max(1) as u64;
    let throughput_mbps = (total_bytes as f64 * 8.0) / (elapsed.as_secs_f64() * 1_000_000.0);
    let pps = iterations as f64 / elapsed.as_secs_f64();
    let avg_latency_ns = (elapsed.as_nanos() as f64) / (iterations as f64);

    IngressGatewayBenchmarkReport {
        iterations,
        elapsed_us,
        total_bytes_processed: total_bytes,
        total_packets_processed: iterations as u64,
        total_duplicates_filtered: gateway.telemetry().total_duplicates_dropped,
        throughput_mbps,
        pps,
        avg_latency_ns,
    }
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::async_multipath_egress_gateway::{
        EgressWireEnvelope, EgressWireHeader, EGRESS_HEADER_SIZE, FLAG_BICAST_COPY,
        IFA_EGRESS_MAGIC, IFA_EGRESS_VERSION,
    };
    use crate::multipath_stream_mux::{StreamFrame, StreamId, StreamPriority};
    use crate::reactor::AsyncUdpSocket;
    use crate::traffic_slicing::FlowSliceClass;
    use std::net::SocketAddr;
    use std::sync::Arc;

    fn helper_build_wire_packet(
        flow_id: u64,
        seq: u64,
        payload: &[u8],
        kind: OutboundItemKind,
        flags: u8,
        departure_ns: u64,
    ) -> Vec<u8> {
        let header = EgressWireHeader {
            magic: IFA_EGRESS_MAGIC,
            version: IFA_EGRESS_VERSION,
            slice_class: FlowSliceClass::UltraLowLatency,
            item_kind: kind,
            flags,
            subpath_id: 1,
            flow_id,
            sequence_number: seq,
            departure_time_ns: departure_ns,
            payload_length: payload.len() as u32,
            crc32: 0,
        };
        let mut envelope = EgressWireEnvelope::new(header, payload);
        let mut buf = vec![0u8; EGRESS_HEADER_SIZE + payload.len()];
        let wire_len = envelope.serialize_into(&mut buf).unwrap();
        buf.truncate(wire_len);
        buf
    }

    #[test]
    fn test_zero_copy_wire_decoding_and_crc_verification() {
        let mut gateway =
            AsyncMultipathIngressGateway::new(AsyncMultipathIngressGatewayConfig::default());
        let now_ns = 2_000_000_000;
        let payload = b"Hello Multipath Zero-Copy Ingress!";

        let mut wire_pkt = helper_build_wire_packet(
            100,
            1,
            payload,
            OutboundItemKind::DataPacket,
            0,
            now_ns - 5_000_000,
        );

        // 1. Valid packet ingestion
        let outcome = gateway
            .ingest_wire_packet(1, &wire_pkt, now_ns)
            .expect("ingest should succeed");
        match outcome {
            IngestPacketOutcome::Accepted {
                flow_id,
                sequence_number,
                bytes,
                transit_latency_ns,
                ..
            } => {
                assert_eq!(flow_id, 100);
                assert_eq!(sequence_number, 1);
                assert_eq!(bytes, payload.len());
                assert_eq!(transit_latency_ns, 5_000_000);
            }
            _ => panic!("Expected Accepted outcome"),
        }

        // 2. Corrupt one byte of CRC
        wire_pkt[40] ^= 0xFF;
        let corrupt_outcome = gateway
            .ingest_wire_packet(1, &wire_pkt, now_ns)
            .expect("should return outcome");
        assert!(matches!(
            corrupt_outcome,
            IngestPacketOutcome::CorruptedCrc { .. }
        ));
        assert_eq!(gateway.telemetry().total_crc_errors, 1);
    }

    #[test]
    fn test_1_plus_1_bicasting_instant_deduplication() {
        let mut gateway =
            AsyncMultipathIngressGateway::new(AsyncMultipathIngressGatewayConfig::default());
        let now_ns = 1_000_000_000;
        let payload = b"Mission-critical bicasted command";

        // Primary packet
        let pkt_primary = helper_build_wire_packet(
            42,
            55,
            payload,
            OutboundItemKind::DataPacket,
            0,
            now_ns - 10_000_000,
        );

        // Secondary bicast duplicate packet (carrying FLAG_BICAST_COPY)
        let pkt_secondary = helper_build_wire_packet(
            42,
            55,
            payload,
            OutboundItemKind::DataPacket,
            FLAG_BICAST_COPY,
            now_ns - 8_000_000,
        );

        // Ingest primary on subpath 1
        let out1 = gateway.ingest_wire_packet(1, &pkt_primary, now_ns).unwrap();
        assert!(matches!(out1, IngestPacketOutcome::Accepted { .. }));

        // Ingest secondary bicast copy on subpath 2
        let out2 = gateway
            .ingest_wire_packet(2, &pkt_secondary, now_ns + 1_000_000)
            .unwrap();
        match out2 {
            IngestPacketOutcome::Duplicate {
                flow_id,
                sequence_number,
                is_bicast_flag,
            } => {
                assert_eq!(flow_id, 42);
                assert_eq!(sequence_number, 55);
                assert!(is_bicast_flag);
            }
            _ => panic!("Expected duplicate drop for bicast copy"),
        }

        assert_eq!(gateway.telemetry().total_packets_accepted, 1);
        assert_eq!(gateway.telemetry().total_duplicates_dropped, 1);
        assert_eq!(gateway.telemetry().total_bicast_duplicates_dropped, 1);
    }

    #[test]
    fn test_subpath_rtt_and_rfc3550_jitter_tracking() {
        let mut gateway =
            AsyncMultipathIngressGateway::new(AsyncMultipathIngressGatewayConfig::default());
        let sock = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").unwrap());
        let peer: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let iface = PhysicalIngressInterface::new(1, "eth0", sock, peer, 1_000_000);
        gateway.register_interface(iface).unwrap();

        let base_now = 10_000_000_000u64;

        // Packet 1: transit = 10ms (10_000_000 ns)
        let p1 = helper_build_wire_packet(
            1,
            1,
            b"data1",
            OutboundItemKind::DataPacket,
            0,
            base_now - 10_000_000,
        );
        gateway.ingest_wire_packet(1, &p1, base_now).unwrap();

        let metrics1 = gateway.subpath_metrics(1).unwrap();
        assert_eq!(metrics1.srtt_ns, 10_000_000);
        assert_eq!(metrics1.jitter_ns, 0);

        // Packet 2: transit = 20ms (20_000_000 ns), diff = 10ms
        let p2 = helper_build_wire_packet(
            1,
            2,
            b"data2",
            OutboundItemKind::DataPacket,
            0,
            base_now + 10_000_000 - 20_000_000,
        );
        gateway
            .ingest_wire_packet(1, &p2, base_now + 10_000_000)
            .unwrap();

        let metrics2 = gateway.subpath_metrics(1).unwrap();
        // SRTT = (10ms * 7 + 20ms) / 8 = 11.25ms = 11_250_000 ns
        assert_eq!(metrics2.srtt_ns, 11_250_000);
        // Jitter = (0 * 15 + 10ms) / 16 = 625_000 ns
        assert_eq!(metrics2.jitter_ns, 625_000);
        assert_eq!(metrics2.min_rtt_ns, 10_000_000);
        assert_eq!(metrics2.max_rtt_ns, 20_000_000);
    }

    #[test]
    fn test_direct_routing_to_multipath_stream_mux() {
        let mut gateway =
            AsyncMultipathIngressGateway::new(AsyncMultipathIngressGatewayConfig::default());
        let now_ns = 5_000_000_000;
        let s_id = StreamId::client_bidi(7);

        // Frame 1: chunk 0..5
        let frame1 = StreamFrame {
            stream_id: s_id,
            offset: 0,
            payload: b"Hello".to_vec(),
            fin: false,
            slice_class: FlowSliceClass::UltraLowLatency,
            priority: StreamPriority::HighInteractive,
            subpath_id: 1,
            seq_num: 1,
            is_bicast: false,
        };
        let p1 = helper_build_wire_packet(
            s_id.raw(),
            1,
            &frame1.encode(),
            OutboundItemKind::DataPacket,
            0,
            now_ns - 1_000_000,
        );
        let out1 = gateway.ingest_wire_packet(1, &p1, now_ns).unwrap();
        assert!(matches!(
            out1,
            IngestPacketOutcome::Accepted {
                target: IngestPayloadTarget::StreamFrameMux { .. },
                ..
            }
        ));

        // Frame 2: chunk 5..11 with FIN
        let frame2 = StreamFrame {
            stream_id: s_id,
            offset: 5,
            payload: b" World".to_vec(),
            fin: true,
            slice_class: FlowSliceClass::UltraLowLatency,
            priority: StreamPriority::HighInteractive,
            subpath_id: 1,
            seq_num: 2,
            is_bicast: false,
        };
        let p2 = helper_build_wire_packet(
            s_id.raw(),
            2,
            &frame2.encode(),
            OutboundItemKind::DataPacket,
            0,
            now_ns - 1_000_000,
        );
        let out2 = gateway
            .ingest_wire_packet(1, &p2, now_ns + 100_000)
            .unwrap();
        assert!(matches!(
            out2,
            IngestPacketOutcome::Accepted {
                target: IngestPayloadTarget::StreamFrameMux {
                    stream_completed: true,
                    ..
                },
                ..
            }
        ));

        // Read reassembled contiguous data directly from stream mux
        let assembled = gateway.read_stream_data(s_id, 100).expect("stream data");
        assert_eq!(assembled, b"Hello World");
    }

    #[test]
    fn test_sliding_window_out_of_order_and_too_old() {
        let mut window = FlowDeduplicationWindow::new(128);

        // Sequence 100
        assert_eq!(window.check_and_mark(100), DeduplicationResult::FirstSeen);
        // Duplicate 100
        assert_eq!(window.check_and_mark(100), DeduplicationResult::Duplicate);
        // Out-of-order within window: sequence 90
        assert_eq!(window.check_and_mark(90), DeduplicationResult::FirstSeen);
        assert_eq!(window.check_and_mark(90), DeduplicationResult::Duplicate);
        // Advance window forward: sequence 300 (jump >= 128)
        assert_eq!(window.check_and_mark(300), DeduplicationResult::FirstSeen);
        // Now sequence 100 is too old (300 - 100 = 200 >= 128)
        assert_eq!(window.check_and_mark(100), DeduplicationResult::TooOld);
    }

    #[test]
    fn test_nonblocking_socket_polling_loop() {
        let mut gateway =
            AsyncMultipathIngressGateway::new(AsyncMultipathIngressGatewayConfig::default());
        let rx_sock = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").unwrap());
        let rx_addr = rx_sock.local_addr().unwrap();

        let tx_sock = AsyncUdpSocket::bind("127.0.0.1:0").unwrap();

        let iface = PhysicalIngressInterface::new(1, "loopback0", rx_sock, rx_addr, 1_000_000);
        gateway.register_interface(iface).unwrap();

        let now_ns = 3_000_000_000;
        let wire_pkt = helper_build_wire_packet(
            99,
            1,
            b"async udp packet",
            OutboundItemKind::DataPacket,
            0,
            now_ns - 2_000_000,
        );

        // Send datagram via UDP socket
        let sent = tx_sock
            .try_send_to(&wire_pkt, rx_addr)
            .unwrap()
            .expect("send");
        assert_eq!(sent, wire_pkt.len());

        // Process ingress cycle to non-blockingly receive and ingest
        let report = gateway.process_ingress_cycle(now_ns, Some(10));
        assert_eq!(report.packets_received, 1);
        assert_eq!(report.packets_accepted, 1);
        assert_eq!(report.bytes_received, wire_pkt.len() as u64);

        // Verify pop raw packet
        let popped = gateway.pop_raw_packet().expect("raw packet");
        assert_eq!(popped.payload, b"async udp packet");
    }

    #[test]
    fn test_benchmark_and_observability_exposition() {
        let mut gateway =
            AsyncMultipathIngressGateway::new(AsyncMultipathIngressGatewayConfig::default());
        let sock = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").unwrap());
        let iface = PhysicalIngressInterface::new(
            1,
            "wan0",
            sock,
            "127.0.0.1:8888".parse().unwrap(),
            1_000_000,
        );
        gateway.register_interface(iface).unwrap();

        let p = helper_build_wire_packet(
            10,
            1,
            b"sample payload",
            OutboundItemKind::DataPacket,
            0,
            1_000_000,
        );
        let _ = gateway.ingest_wire_packet(1, &p, 2_000_000);

        let prom = gateway.export_prometheus_metrics();
        assert!(prom.contains("ifa_ingress_packets_received_total 1"));
        assert!(prom.contains("ifa_ingress_packets_accepted_total 1"));

        let json = gateway.generate_json_audit_trail();
        assert!(json.contains("\"wire_packets_received\":1"));
        assert!(json.contains("\"packets_accepted\":1"));

        let bench = run_async_multipath_ingress_gateway_benchmark(20);
        assert_eq!(bench.iterations, 20);
        assert!(bench.total_duplicates_filtered >= 5);
        assert!(bench.throughput_mbps > 0.0);
    }

    #[test]
    fn test_end_to_end_egress_to_ingress_gateway_coupling() {
        use crate::async_multipath_egress_gateway::{
            AsyncMultipathEgressGateway, AsyncMultipathEgressGatewayConfig, PhysicalEgressInterface,
        };

        let now_ns = 1_000_000_000u64;

        // Create 2 Ingress UDP sockets
        let ingress_sock1 = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").unwrap());
        let ingress_addr1 = ingress_sock1.local_addr().unwrap();

        let ingress_sock2 = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").unwrap());
        let ingress_addr2 = ingress_sock2.local_addr().unwrap();

        // Create 2 Egress UDP sockets
        let egress_sock1 = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").unwrap());
        let egress_sock2 = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").unwrap());

        // Setup Egress Gateway
        let mut egress_gateway =
            AsyncMultipathEgressGateway::new(AsyncMultipathEgressGatewayConfig {
                bicast_critical_slices: true,
                ..Default::default()
            });

        let e_iface1 = PhysicalEgressInterface::new(
            1,
            "wan-primary",
            egress_sock1,
            ingress_addr1,
            1_000_000_000,
            10_000_000,
            1500,
            now_ns,
        );
        let e_iface2 = PhysicalEgressInterface::new(
            2,
            "wan-secondary",
            egress_sock2,
            ingress_addr2,
            1_000_000_000,
            12_000_000,
            1500,
            now_ns,
        );
        egress_gateway.register_interface(e_iface1, now_ns).unwrap();
        egress_gateway.register_interface(e_iface2, now_ns).unwrap();

        // Setup Ingress Gateway
        let mut ingress_gateway =
            AsyncMultipathIngressGateway::new(AsyncMultipathIngressGatewayConfig::default());
        let i_iface1 =
            PhysicalIngressInterface::new(1, "ingress-pri", ingress_sock1, ingress_addr1, now_ns);
        let i_iface2 =
            PhysicalIngressInterface::new(2, "ingress-sec", ingress_sock2, ingress_addr2, now_ns);
        ingress_gateway.register_interface(i_iface1).unwrap();
        ingress_gateway.register_interface(i_iface2).unwrap();

        // Submit URLLC payload to egress gateway (triggers 1+1 bicasting)
        let payload = b"End-to-end bicasted mission data".to_vec();
        let _ = egress_gateway
            .submit_payload(
                88,
                FlowSliceClass::UltraLowLatency,
                payload.clone(),
                Some(now_ns + 50_000_000),
                now_ns,
            )
            .unwrap();

        // Process egress cycle: transmits on primary (subpath 1) and bicasts to secondary (subpath 2)
        let egress_rep = egress_gateway.process_egress_cycle(now_ns, Some(10));
        assert!(egress_rep.packets_transmitted >= 1);
        assert_eq!(egress_gateway.telemetry().total_bicasted_packets, 1);

        // Process ingress cycle: receives both datagrams
        let ingress_rep = ingress_gateway.process_ingress_cycle(now_ns + 5_000_000, Some(10));
        assert_eq!(ingress_rep.packets_received, 2);
        assert_eq!(ingress_rep.packets_accepted, 1);
        assert_eq!(ingress_rep.duplicates_dropped, 1);
        assert_eq!(ingress_rep.bicast_duplicates_dropped, 1);

        // Verify popped raw payload
        let popped = ingress_gateway.pop_raw_packet().expect("popped packet");
        assert_eq!(popped.payload, payload);
        assert_eq!(popped.transit_latency_ns, 5_000_000);
    }
}

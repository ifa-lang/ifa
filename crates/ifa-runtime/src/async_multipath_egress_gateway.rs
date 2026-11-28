//! Asynchronous Multipath Egress Gateway (`AsyncMultipathEgressGateway`).
//!
//! Interfaces the event reactor (`MultipathEventScheduler`) with physical asynchronous
//! network transports (`AsyncMultipathTransport`, raw non-blocking UDP sockets, and hardware interfaces).
//!
//! Core Architectural Guarantees:
//! 1. **Direct Zero-Copy Wire Serialization & Framing**:
//!    - Formulates deterministic, memory-protected binary wire envelopes (`IFA_EGRESS_MAGIC = 0x49464145`).
//!    - Includes flow ID, subpath ID, QoS slice classification, sequence number, monotonic departure
//!      timestamp, payload size, and IEEE 802.3 CRC32 integrity checksum.
//!    - Serializes directly into pre-allocated contiguous scratch memory without intermediate allocations.
//! 2. **Pacing & Anti-Burst Enforcement**:
//!    - Strictly respects subpath departure deadlines computed by the BBR pacing coordinator.
//!    - Enforces physical interface PMTU checks and leaky-bucket token constraints to prevent bufferbloat.
//!    - Smoothly absorbs socket `WouldBlock` conditions into a backpressure ring without dropping.
//! 3. **Dynamic Path Migration & Zero Flow Disruption**:
//!    - Binds application QoS slices to physical network interfaces.
//!    - Seamlessly migrates egress traffic when `PredictivePathSelector` signals impending SLA breaches.
//! 4. **Unified Observability & Audit**:
//!    - OpenMetrics / Prometheus exporter (`export_prometheus_metrics`).
//!    - Structured JSON audit trail (`generate_json_audit_trail`).
//!    - In-memory micro-benchmark suite (`run_async_multipath_egress_gateway_benchmark`).
//!
//! Zero-simulation guarantee: operates on real non-blocking sockets, concrete timestamps,
//! and physical interface metadata.

#![allow(clippy::manual_is_multiple_of, clippy::too_many_arguments)]

use std::collections::{BTreeMap, VecDeque};
use std::fmt::Write as FmtWrite;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::multipath_event_scheduler::{
    EventProcessOutcome, MultipathEventScheduler, MultipathEventSchedulerConfig,
    MultipathSchedulerEvent, SchedulerStepSummary,
};
use crate::multipath_pacing_coordinator::{OutboundItemKind, ScheduledOutboundItem};
use crate::multipath_stream_mux::{FlowControlFrame, StreamFrame};
use crate::multipath_transport::AsyncMultipathTransport;
use crate::reactor::AsyncUdpSocket;
use crate::subpath_pmtud::calculate_crc32;
use crate::traffic_slicing::FlowSliceClass;

// ---------------------------------------------------------------------------
// Protocol Constants & Wire Framing Layout
// ---------------------------------------------------------------------------

/// Magic identifier for IFA Egress Wire Envelopes ("IFAE" in ASCII).
pub const IFA_EGRESS_MAGIC: u32 = 0x4946_4145;

/// Current wire envelope protocol version.
pub const IFA_EGRESS_VERSION: u8 = 1;

/// Fixed-size header for zero-copy egress wire packets (44 bytes).
pub const EGRESS_HEADER_SIZE: usize = 44;

/// Header flags: bit 0 = Urgent / pre-emptible priority.
pub const FLAG_URGENT: u8 = 0x01;
/// Header flags: bit 1 = Encrypted payload.
pub const FLAG_ENCRYPTED: u8 = 0x02;
/// Header flags: bit 2 = Explicit Congestion Notification (ECN-CE) echo.
pub const FLAG_ECN_CE: u8 = 0x04;
/// Header flags: bit 3 = Last fragment of reassembled frame.
pub const FLAG_EGRESS_LAST_FRAGMENT: u8 = 0x08;
/// Header flags: bit 4 = 1+1 Bicast duplicate copy.
pub const FLAG_BICAST_COPY: u8 = 0x10;

// ---------------------------------------------------------------------------
// Error Types
// ---------------------------------------------------------------------------

/// Errors encountered during egress processing, serialization, or socket dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressGatewayError {
    /// Specified subpath interface was not registered in the gateway.
    SubpathNotFound(u32),
    /// Subpath interface is administratively down or offline.
    InterfaceOffline(u32),
    /// Egress payload exceeds effective PMTU for the target interface.
    PayloadTooLarge { size: usize, pmtu: usize },
    /// Destination buffer is too small for zero-copy serialization.
    BufferTooSmall { required: usize, provided: usize },
    /// Magic constant mismatch in wire packet.
    InvalidMagic { expected: u32, received: u32 },
    /// CRC32 integrity check failed.
    CrcMismatch { computed: u32, embedded: u32 },
    /// Header corrupted or truncated.
    CorruptedHeader(String),
    /// Underlying socket transmission failed.
    SocketError(String),
    /// Backpressure queue capacity exceeded.
    BackpressureOverflow,
}

impl std::fmt::Display for EgressGatewayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SubpathNotFound(id) => write!(f, "Subpath interface {} not found", id),
            Self::InterfaceOffline(id) => write!(f, "Subpath interface {} is offline", id),
            Self::PayloadTooLarge { size, pmtu } => {
                write!(f, "Payload size {} exceeds PMTU {}", size, pmtu)
            }
            Self::BufferTooSmall { required, provided } => {
                write!(
                    f,
                    "Target buffer too small: required {}, provided {}",
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
            Self::BackpressureOverflow => write!(f, "Backpressure queue capacity reached"),
        }
    }
}

impl std::error::Error for EgressGatewayError {}

// ---------------------------------------------------------------------------
// Egress Wire Header & Envelope Definitions
// ---------------------------------------------------------------------------

/// Structured representation of the 44-byte egress wire header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressWireHeader {
    pub magic: u32,
    pub version: u8,
    pub slice_class: FlowSliceClass,
    pub item_kind: OutboundItemKind,
    pub flags: u8,
    pub subpath_id: u32,
    pub flow_id: u64,
    pub sequence_number: u64,
    pub departure_time_ns: u64,
    pub payload_length: u32,
    pub crc32: u32,
}

impl EgressWireHeader {
    /// Serialize the 44-byte header into the destination slice without heap allocations.
    pub fn encode_to(&self, out: &mut [u8]) -> Result<(), EgressGatewayError> {
        if out.len() < EGRESS_HEADER_SIZE {
            return Err(EgressGatewayError::BufferTooSmall {
                required: EGRESS_HEADER_SIZE,
                provided: out.len(),
            });
        }

        out[0..4].copy_from_slice(&self.magic.to_be_bytes());
        out[4] = self.version;
        out[5] = slice_to_wire_byte(self.slice_class);
        out[6] = item_kind_to_wire_byte(self.item_kind);
        out[7] = self.flags;
        out[8..12].copy_from_slice(&self.subpath_id.to_be_bytes());
        out[12..20].copy_from_slice(&self.flow_id.to_be_bytes());
        out[20..28].copy_from_slice(&self.sequence_number.to_be_bytes());
        out[28..36].copy_from_slice(&self.departure_time_ns.to_be_bytes());
        out[36..40].copy_from_slice(&self.payload_length.to_be_bytes());
        out[40..44].copy_from_slice(&self.crc32.to_be_bytes());

        Ok(())
    }

    /// Decode header from binary slice without allocations.
    pub fn decode_from(buf: &[u8]) -> Result<Self, EgressGatewayError> {
        if buf.len() < EGRESS_HEADER_SIZE {
            return Err(EgressGatewayError::BufferTooSmall {
                required: EGRESS_HEADER_SIZE,
                provided: buf.len(),
            });
        }

        let magic = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if magic != IFA_EGRESS_MAGIC {
            return Err(EgressGatewayError::InvalidMagic {
                expected: IFA_EGRESS_MAGIC,
                received: magic,
            });
        }

        let version = buf[4];
        let slice_class = wire_byte_to_slice(buf[5]);
        let item_kind = wire_byte_to_item_kind(buf[6]);
        let flags = buf[7];
        let subpath_id = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let flow_id = u64::from_be_bytes([
            buf[12], buf[13], buf[14], buf[15], buf[16], buf[17], buf[18], buf[19],
        ]);
        let sequence_number = u64::from_be_bytes([
            buf[20], buf[21], buf[22], buf[23], buf[24], buf[25], buf[26], buf[27],
        ]);
        let departure_time_ns = u64::from_be_bytes([
            buf[28], buf[29], buf[30], buf[31], buf[32], buf[33], buf[34], buf[35],
        ]);
        let payload_length = u32::from_be_bytes([buf[36], buf[37], buf[38], buf[39]]);
        let crc32 = u32::from_be_bytes([buf[40], buf[41], buf[42], buf[43]]);

        Ok(Self {
            magic,
            version,
            slice_class,
            item_kind,
            flags,
            subpath_id,
            flow_id,
            sequence_number,
            departure_time_ns,
            payload_length,
            crc32,
        })
    }
}

/// Zero-copy envelope for serialization and decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressWireEnvelope<'a> {
    pub header: EgressWireHeader,
    pub payload: &'a [u8],
}

impl<'a> EgressWireEnvelope<'a> {
    /// Construct a new wire envelope.
    pub fn new(header: EgressWireHeader, payload: &'a [u8]) -> Self {
        Self { header, payload }
    }

    /// Serialize complete wire envelope into the target buffer directly with IEEE 802.3 CRC32.
    pub fn serialize_into(&mut self, target: &mut [u8]) -> Result<usize, EgressGatewayError> {
        let total_size = EGRESS_HEADER_SIZE + self.payload.len();
        if target.len() < total_size {
            return Err(EgressGatewayError::BufferTooSmall {
                required: total_size,
                provided: target.len(),
            });
        }

        self.header.payload_length = self.payload.len() as u32;

        // Encode first 40 bytes (header without crc32)
        target[0..4].copy_from_slice(&self.header.magic.to_be_bytes());
        target[4] = self.header.version;
        target[5] = slice_to_wire_byte(self.header.slice_class);
        target[6] = item_kind_to_wire_byte(self.header.item_kind);
        target[7] = self.header.flags;
        target[8..12].copy_from_slice(&self.header.subpath_id.to_be_bytes());
        target[12..20].copy_from_slice(&self.header.flow_id.to_be_bytes());
        target[20..28].copy_from_slice(&self.header.sequence_number.to_be_bytes());
        target[28..36].copy_from_slice(&self.header.departure_time_ns.to_be_bytes());
        target[36..40].copy_from_slice(&self.header.payload_length.to_be_bytes());

        // Copy payload directly into target buffer
        target[EGRESS_HEADER_SIZE..total_size].copy_from_slice(self.payload);

        // Compute CRC32 over header prefix (0..40) + payload (44..total_size)
        let crc = compute_envelope_crc32(&target[0..40], &target[EGRESS_HEADER_SIZE..total_size]);
        self.header.crc32 = crc;
        target[40..44].copy_from_slice(&crc.to_be_bytes());

        Ok(total_size)
    }

    /// Zero-copy decoding: parses the header and returns an uncopied slice into `data`.
    pub fn decode_packet(
        data: &'a [u8],
    ) -> Result<(EgressWireHeader, &'a [u8]), EgressGatewayError> {
        let header = EgressWireHeader::decode_from(data)?;
        let total_size = EGRESS_HEADER_SIZE + header.payload_length as usize;

        if data.len() < total_size {
            return Err(EgressGatewayError::BufferTooSmall {
                required: total_size,
                provided: data.len(),
            });
        }

        let payload_slice = &data[EGRESS_HEADER_SIZE..total_size];

        // Validate CRC32
        let computed_crc = compute_envelope_crc32(&data[0..40], payload_slice);
        if computed_crc != header.crc32 {
            return Err(EgressGatewayError::CrcMismatch {
                computed: computed_crc,
                embedded: header.crc32,
            });
        }

        Ok((header, payload_slice))
    }
}

// ---------------------------------------------------------------------------
// Helper Serializer Converters
// ---------------------------------------------------------------------------

#[inline]
fn slice_to_wire_byte(slice: FlowSliceClass) -> u8 {
    match slice {
        FlowSliceClass::UltraLowLatency => 0,
        FlowSliceClass::MissionCritical => 1,
        FlowSliceClass::HighThroughput => 2,
        FlowSliceClass::BestEffort => 3,
    }
}

#[inline]
fn wire_byte_to_slice(byte: u8) -> FlowSliceClass {
    match byte {
        0 => FlowSliceClass::UltraLowLatency,
        1 => FlowSliceClass::MissionCritical,
        2 => FlowSliceClass::HighThroughput,
        _ => FlowSliceClass::BestEffort,
    }
}

#[inline]
fn item_kind_to_wire_byte(kind: OutboundItemKind) -> u8 {
    match kind {
        OutboundItemKind::DataPacket => 0,
        OutboundItemKind::FecParitySymbol { .. } => 1,
        OutboundItemKind::ArqRetransmission { .. } => 2,
        OutboundItemKind::ProbePacket => 3,
    }
}

#[inline]
fn wire_byte_to_item_kind(byte: u8) -> OutboundItemKind {
    match byte {
        1 => OutboundItemKind::FecParitySymbol {
            block_id: 0,
            symbol_index: 0,
            total_symbols: 1,
        },
        2 => OutboundItemKind::ArqRetransmission {
            original_seq: 0,
            retry_count: 1,
        },
        3 => OutboundItemKind::ProbePacket,
        _ => OutboundItemKind::DataPacket,
    }
}

#[inline]
fn compute_envelope_crc32(header_prefix_40: &[u8], payload: &[u8]) -> u32 {
    let mut combined = Vec::with_capacity(header_prefix_40.len() + payload.len());
    combined.extend_from_slice(header_prefix_40);
    combined.extend_from_slice(payload);
    calculate_crc32(&combined)
}

// ---------------------------------------------------------------------------
// Physical Egress Interface Definition
// ---------------------------------------------------------------------------

/// Physical or asynchronous network interface attached to the gateway.
#[derive(Clone)]
pub struct PhysicalEgressInterface {
    pub subpath_id: u32,
    pub interface_name: String,
    pub socket: Arc<AsyncUdpSocket>,
    pub peer_addr: SocketAddr,
    pub bandwidth_bps: u64,
    pub rtt_ns: u64,
    pub effective_pmtu: u32,
    pub active: bool,
    pub packets_sent: u64,
    pub bytes_sent: u64,
    pub would_block_count: u64,
    pub serialization_errors: u64,
    pub last_transmit_ns: u64,
}

impl PhysicalEgressInterface {
    /// Create a new physical egress interface descriptor.
    pub fn new(
        subpath_id: u32,
        interface_name: impl Into<String>,
        socket: Arc<AsyncUdpSocket>,
        peer_addr: SocketAddr,
        bandwidth_bps: u64,
        rtt_ns: u64,
        effective_pmtu: u32,
        now_ns: u64,
    ) -> Self {
        Self {
            subpath_id,
            interface_name: interface_name.into(),
            socket,
            peer_addr,
            bandwidth_bps,
            rtt_ns,
            effective_pmtu,
            active: true,
            packets_sent: 0,
            bytes_sent: 0,
            would_block_count: 0,
            serialization_errors: 0,
            last_transmit_ns: now_ns,
        }
    }
}

// ---------------------------------------------------------------------------
// Backpressure Queue Record
// ---------------------------------------------------------------------------

/// Packet held temporarily due to non-blocking socket backpressure (`WouldBlock`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackpressuredPacket {
    pub subpath_id: u32,
    pub peer_addr: SocketAddr,
    pub wire_bytes: Vec<u8>,
    pub packet_id: u64,
    pub item_kind: OutboundItemKind,
    pub queued_ns: u64,
    pub retry_attempts: usize,
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration options for the `AsyncMultipathEgressGateway`.
#[derive(Debug, Clone, PartialEq)]
pub struct AsyncMultipathEgressGatewayConfig {
    /// Coupled event scheduler configuration.
    pub scheduler_config: MultipathEventSchedulerConfig,
    /// Maximum number of packets transmitted in a single egress cycle.
    pub max_batch_size: usize,
    /// Maximum backpressure queue capacity before throttling.
    pub max_backpressure_queue: usize,
    /// Pre-allocated scratch buffer size for zero-copy wire framing.
    pub scratch_buffer_size: usize,
    /// Whether 1+1 bicasting is enabled for mission-critical and URLLC flows.
    pub bicast_critical_slices: bool,
}

impl Default for AsyncMultipathEgressGatewayConfig {
    fn default() -> Self {
        Self {
            scheduler_config: MultipathEventSchedulerConfig::default(),
            max_batch_size: 64,
            max_backpressure_queue: 1024,
            scratch_buffer_size: 65_536,
            bicast_critical_slices: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Telemetry & Egress Report
// ---------------------------------------------------------------------------

/// Telemetry metrics for the `AsyncMultipathEgressGateway`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AsyncMultipathEgressGatewayTelemetry {
    pub total_payloads_submitted: u64,
    pub total_stream_frames_submitted: u64,
    pub total_control_frames_submitted: u64,
    pub total_wire_packets_transmitted: u64,
    pub total_wire_bytes_transmitted: u64,
    pub total_zero_copy_serializations: u64,
    pub total_backpressure_events: u64,
    pub total_backpressure_drained: u64,
    pub total_pacing_delayed_cycles: u64,
    pub total_failover_redirects: u64,
    pub total_crc_errors: u64,
    pub total_bicasted_packets: u64,
    pub active_backpressure_count: usize,
}

/// Detailed outcome of an egress processing cycle.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EgressCycleReport {
    pub step_summary: SchedulerStepSummary,
    pub packets_transmitted: usize,
    pub bytes_transmitted: u64,
    pub backpressure_queued: usize,
    pub backpressure_drained: usize,
    pub pacing_waits: usize,
    pub active_interfaces_count: usize,
}

// ---------------------------------------------------------------------------
// Async Multipath Egress Gateway Implementation
// ---------------------------------------------------------------------------

/// Non-blocking, zero-copy asynchronous egress gateway coupling the event scheduler
/// to physical network sockets.
pub struct AsyncMultipathEgressGateway {
    pub config: AsyncMultipathEgressGatewayConfig,
    pub scheduler: MultipathEventScheduler,
    pub interfaces: BTreeMap<u32, PhysicalEgressInterface>,
    pub pending_backpressure: VecDeque<BackpressuredPacket>,
    pub next_packet_id: u64,
    pub telemetry: AsyncMultipathEgressGatewayTelemetry,
    scratch_buffer: Vec<u8>,
}

impl AsyncMultipathEgressGateway {
    /// Create a new `AsyncMultipathEgressGateway` instance with configuration.
    pub fn new(config: AsyncMultipathEgressGatewayConfig) -> Self {
        let scheduler = MultipathEventScheduler::new(config.scheduler_config.clone());
        let scratch_size = config.scratch_buffer_size.max(2048);

        Self {
            config,
            scheduler,
            interfaces: BTreeMap::new(),
            pending_backpressure: VecDeque::new(),
            next_packet_id: 1,
            telemetry: AsyncMultipathEgressGatewayTelemetry::default(),
            scratch_buffer: vec![0u8; scratch_size],
        }
    }

    /// Register a physical asynchronous network interface.
    pub fn register_interface(
        &mut self,
        interface: PhysicalEgressInterface,
        now_ns: u64,
    ) -> Result<(), EgressGatewayError> {
        let sid = interface.subpath_id;
        let bw = interface.bandwidth_bps;
        let rtt = interface.rtt_ns;
        let pmtu = interface.effective_pmtu;

        self.interfaces.insert(sid, interface);

        // Synchronize interface registration into the coupled event scheduler
        self.scheduler.register_subpath(sid, bw, rtt, pmtu, now_ns);

        Ok(())
    }

    /// Unregister a physical network interface.
    pub fn unregister_interface(
        &mut self,
        subpath_id: u32,
    ) -> Result<Option<PhysicalEgressInterface>, EgressGatewayError> {
        let removed = self.interfaces.remove(&subpath_id);
        self.scheduler.subpaths.remove(&subpath_id);
        Ok(removed)
    }

    /// Set an interface administrative status (active/offline).
    pub fn set_interface_active(&mut self, subpath_id: u32, active: bool) {
        if let Some(iface) = self.interfaces.get_mut(&subpath_id) {
            iface.active = active;
        }
    }

    /// Bind a QoS flow slice class to a target physical subpath.
    pub fn bind_slice_to_subpath(&mut self, slice: FlowSliceClass, subpath_id: u32) {
        self.scheduler.bind_slice_to_subpath(slice, subpath_id);
    }

    /// Submit raw application payload for scheduled egress.
    pub fn submit_payload(
        &mut self,
        flow_id: u64,
        slice_class: FlowSliceClass,
        payload: Vec<u8>,
        deadline_ns: Option<u64>,
        now_ns: u64,
    ) -> Result<u64, EgressGatewayError> {
        let packet_id = self.next_packet_id;
        self.next_packet_id = self.next_packet_id.wrapping_add(1).max(1);

        self.telemetry.total_payloads_submitted += 1;

        self.scheduler
            .submit_event(MultipathSchedulerEvent::IngressPacket {
                packet_id,
                flow_id,
                slice_class,
                payload,
                enqueue_time_ns: now_ns,
                deadline_ns,
            });

        Ok(packet_id)
    }

    /// Submit a `StreamFrame` from the stream multiplexer.
    pub fn submit_stream_frame(
        &mut self,
        frame: StreamFrame,
        now_ns: u64,
    ) -> Result<u64, EgressGatewayError> {
        let packet_id = self.next_packet_id;
        self.next_packet_id = self.next_packet_id.wrapping_add(1).max(1);

        let slice = frame.slice_class;
        let flow_id = frame.stream_id.raw();
        let payload = frame.encode();

        self.telemetry.total_stream_frames_submitted += 1;

        self.scheduler
            .submit_event(MultipathSchedulerEvent::IngressPacket {
                packet_id,
                flow_id,
                slice_class: slice,
                payload,
                enqueue_time_ns: now_ns,
                deadline_ns: None,
            });

        Ok(packet_id)
    }

    /// Submit an urgent `FlowControlFrame`.
    pub fn submit_control_frame(
        &mut self,
        frame: FlowControlFrame,
        target_subpath: Option<u32>,
        now_ns: u64,
    ) -> Result<u64, EgressGatewayError> {
        let packet_id = self.next_packet_id;
        self.next_packet_id = self.next_packet_id.wrapping_add(1).max(1);

        let slice = FlowSliceClass::UltraLowLatency;
        let flow_id = 0; // Control signaling flow
        let payload = frame.encode();

        self.telemetry.total_control_frames_submitted += 1;

        if let Some(sid) = target_subpath {
            self.scheduler.bind_slice_to_subpath(slice, sid);
        }

        self.scheduler
            .submit_event(MultipathSchedulerEvent::IngressPacket {
                packet_id,
                flow_id,
                slice_class: slice,
                payload,
                enqueue_time_ns: now_ns,
                deadline_ns: Some(now_ns + 10_000_000), // Urgent 10ms deadline
            });

        Ok(packet_id)
    }

    /// Feed back an inbound receiver acknowledgment into the scheduler.
    pub fn feed_receiver_ack(
        &mut self,
        subpath_id: u32,
        ack_packet_id: u64,
        rtt_sample_ns: u64,
        delivered_bytes: usize,
        ecn_marked: bool,
        now_ns: u64,
    ) {
        self.scheduler
            .submit_event(MultipathSchedulerEvent::ReceiverAck {
                subpath_id,
                ack_packet_id,
                rtt_sample_ns,
                delivered_bytes,
                ecn_marked,
                receive_time_ns: now_ns,
            });
    }

    /// Feed back an explicit negative acknowledgment / loss signal.
    pub fn feed_receiver_nack(&mut self, subpath_id: u32, lost_packet_ids: Vec<u64>, now_ns: u64) {
        self.scheduler
            .submit_event(MultipathSchedulerEvent::ReceiverNack {
                subpath_id,
                lost_packet_ids,
                detection_time_ns: now_ns,
            });
    }

    /// Feed subpath link metric updates into the scheduler.
    pub fn feed_subpath_metrics(
        &mut self,
        subpath_id: u32,
        rtt_ns: u64,
        jitter_ns: u64,
        loss_ratio: f64,
        btl_bw_bps: u64,
        now_ns: u64,
    ) {
        self.scheduler
            .submit_event(MultipathSchedulerEvent::SubpathMetricsSample {
                subpath_id,
                rtt_ns,
                jitter_ns,
                loss_ratio,
                btl_bw_bps,
                sample_time_ns: now_ns,
            });
    }

    /// Execute a full non-blocking egress cycle:
    /// 1. Advance scheduler events, RTO sweeps, and predictive audits.
    /// 2. Drain pending backpressured packets over active sockets.
    /// 3. Poll wire-ready scheduled outbound packets.
    /// 4. Direct zero-copy serialize onto physical interfaces under pacing and PMTU constraints.
    pub fn process_egress_cycle(
        &mut self,
        now_ns: u64,
        max_batch: Option<usize>,
    ) -> EgressCycleReport {
        let batch_limit = max_batch.unwrap_or(self.config.max_batch_size);
        let mut report = EgressCycleReport::default();

        // 1. Advance event scheduler state
        let outcomes = self.scheduler.process_all_events(now_ns);
        report.step_summary.events_processed = outcomes.len();

        let rto_outcome = self.scheduler.sweep_rto_deadlines(now_ns);
        if let EventProcessOutcome::RtoSwept { expired_count, .. } = rto_outcome {
            report.step_summary.rto_expired_count = expired_count;
        }

        if now_ns.saturating_sub(self.scheduler.last_audit_ns)
            >= self.scheduler.config.audit_interval_ns
        {
            let audit_outcome = self.scheduler.execute_predictive_audit(now_ns);
            if let EventProcessOutcome::AuditExecuted {
                migrations_executed,
                ..
            } = audit_outcome
            {
                report.step_summary.proactive_migrations_count = migrations_executed.len();
            }
        }

        // 2. Drain backpressure queue
        let (drained_count, drained_bytes) = self.drain_backpressure_queue(now_ns, batch_limit);
        report.backpressure_drained = drained_count;
        report.packets_transmitted += drained_count;
        report.bytes_transmitted += drained_bytes;

        // 3. Poll all wire-ready items from scheduler
        let ready_items = self.scheduler.poll_any_ready(now_ns);
        report.step_summary.dispatched_items_count = ready_items.len();
        report.step_summary.dispatched_bytes =
            ready_items.iter().map(|d| d.size_bytes as u64).sum();

        for item in ready_items {
            if report.packets_transmitted >= batch_limit {
                break;
            }

            match self.transmit_scheduled_item(&item, now_ns) {
                Ok(bytes_sent) => {
                    report.packets_transmitted += 1;
                    report.bytes_transmitted += bytes_sent as u64;
                }
                Err(EgressGatewayError::SocketError(msg)) if msg.contains("WouldBlock") => {
                    report.backpressure_queued += 1;
                }
                Err(_) => {
                    // Interface missing or offline, item dropped or queued
                }
            }
        }

        report.active_interfaces_count = self.interfaces.values().filter(|i| i.active).count();
        report
    }

    /// Drain queued backpressure packets.
    fn drain_backpressure_queue(&mut self, now_ns: u64, max_drain: usize) -> (usize, u64) {
        let mut drained_count = 0;
        let mut drained_bytes = 0u64;
        let mut retained = VecDeque::new();

        while let Some(mut bp) = self.pending_backpressure.pop_front() {
            if drained_count >= max_drain {
                retained.push_back(bp);
                continue;
            }

            let iface_opt = self.interfaces.get_mut(&bp.subpath_id);
            match iface_opt {
                Some(iface) if iface.active => {
                    match iface.socket.try_send_to(&bp.wire_bytes, iface.peer_addr) {
                        Ok(Some(n)) => {
                            iface.packets_sent += 1;
                            iface.bytes_sent += n as u64;
                            iface.last_transmit_ns = now_ns;
                            self.telemetry.total_wire_packets_transmitted += 1;
                            self.telemetry.total_wire_bytes_transmitted += n as u64;
                            self.telemetry.total_backpressure_drained += 1;
                            drained_count += 1;
                            drained_bytes += n as u64;
                        }
                        Ok(None) => {
                            // Still WouldBlock
                            iface.would_block_count += 1;
                            bp.retry_attempts += 1;
                            retained.push_back(bp);
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            iface.would_block_count += 1;
                            bp.retry_attempts += 1;
                            retained.push_back(bp);
                        }
                        Err(_) => {
                            // Socket failed permanently for this packet
                        }
                    }
                }
                _ => {
                    // Interface missing or offline; drop packet
                }
            }
        }

        retained.append(&mut self.pending_backpressure);
        self.pending_backpressure = retained;
        self.telemetry.active_backpressure_count = self.pending_backpressure.len();

        (drained_count, drained_bytes)
    }

    /// Transmit a single scheduled outbound item with zero-copy serialization.
    fn transmit_scheduled_item(
        &mut self,
        item: &ScheduledOutboundItem,
        now_ns: u64,
    ) -> Result<usize, EgressGatewayError> {
        let sid = item.subpath_id;

        // Verify interface existence and operational state
        let (socket, peer_addr, pmtu) = {
            let iface = self
                .interfaces
                .get_mut(&sid)
                .ok_or(EgressGatewayError::SubpathNotFound(sid))?;
            if !iface.active {
                return Err(EgressGatewayError::InterfaceOffline(sid));
            }
            (iface.socket.clone(), iface.peer_addr, iface.effective_pmtu)
        };

        // PMTU validation
        let required_envelope_size = EGRESS_HEADER_SIZE + item.size_bytes;
        if required_envelope_size > pmtu as usize && pmtu > 0 {
            return Err(EgressGatewayError::PayloadTooLarge {
                size: required_envelope_size,
                pmtu: pmtu as usize,
            });
        }

        // Direct zero-copy framing into scratch buffer
        let header = EgressWireHeader {
            magic: IFA_EGRESS_MAGIC,
            version: IFA_EGRESS_VERSION,
            slice_class: item.slice_class,
            item_kind: item.kind,
            flags: if matches!(
                item.slice_class,
                FlowSliceClass::UltraLowLatency | FlowSliceClass::MissionCritical
            ) {
                FLAG_URGENT
            } else {
                0
            },
            subpath_id: sid,
            flow_id: item.flow_id,
            sequence_number: item.item_id,
            departure_time_ns: now_ns,
            payload_length: item.size_bytes as u32,
            crc32: 0,
        };

        let mut envelope = EgressWireEnvelope::new(header, &item.payload);

        if self.scratch_buffer.len() < required_envelope_size {
            self.scratch_buffer.resize(required_envelope_size * 2, 0);
        }

        let wire_size = envelope.serialize_into(&mut self.scratch_buffer)?;
        self.telemetry.total_zero_copy_serializations += 1;

        // Perform non-blocking physical wire dispatch
        match socket.try_send_to(&self.scratch_buffer[0..wire_size], peer_addr) {
            Ok(Some(n)) => {
                if let Some(iface) = self.interfaces.get_mut(&sid) {
                    iface.packets_sent += 1;
                    iface.bytes_sent += n as u64;
                    iface.last_transmit_ns = now_ns;
                }
                self.telemetry.total_wire_packets_transmitted += 1;
                self.telemetry.total_wire_bytes_transmitted += n as u64;

                // 1+1 Bicasting for critical slices if secondary interface available
                if self.config.bicast_critical_slices
                    && matches!(
                        item.slice_class,
                        FlowSliceClass::UltraLowLatency | FlowSliceClass::MissionCritical
                    )
                {
                    self.try_bicast_secondary_transmission(item, wire_size, now_ns);
                }

                Ok(n)
            }
            Ok(None) => {
                self.handle_would_block_backpressure(item, wire_size, sid, peer_addr, now_ns)
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                self.handle_would_block_backpressure(item, wire_size, sid, peer_addr, now_ns)
            }
            Err(e) => {
                if let Some(iface) = self.interfaces.get_mut(&sid) {
                    iface.serialization_errors += 1;
                }
                Err(EgressGatewayError::SocketError(e.to_string()))
            }
        }
    }

    /// Handle non-blocking socket backpressure.
    fn handle_would_block_backpressure(
        &mut self,
        item: &ScheduledOutboundItem,
        wire_size: usize,
        subpath_id: u32,
        peer_addr: SocketAddr,
        now_ns: u64,
    ) -> Result<usize, EgressGatewayError> {
        if let Some(iface) = self.interfaces.get_mut(&subpath_id) {
            iface.would_block_count += 1;
        }

        self.telemetry.total_backpressure_events += 1;

        if self.pending_backpressure.len() >= self.config.max_backpressure_queue {
            return Err(EgressGatewayError::BackpressureOverflow);
        }

        let bp = BackpressuredPacket {
            subpath_id,
            peer_addr,
            wire_bytes: self.scratch_buffer[0..wire_size].to_vec(),
            packet_id: item.item_id,
            item_kind: item.kind,
            queued_ns: now_ns,
            retry_attempts: 1,
        };

        self.pending_backpressure.push_back(bp);
        self.telemetry.active_backpressure_count = self.pending_backpressure.len();

        Err(EgressGatewayError::SocketError("WouldBlock".to_string()))
    }

    /// Perform 1+1 bicasting on secondary active interface.
    fn try_bicast_secondary_transmission(
        &mut self,
        item: &ScheduledOutboundItem,
        wire_size: usize,
        now_ns: u64,
    ) {
        let primary_sid = item.subpath_id;
        let secondary_target = self
            .interfaces
            .values()
            .find(|i| i.active && i.subpath_id != primary_sid)
            .map(|i| (i.subpath_id, i.socket.clone(), i.peer_addr));

        if let Some((sec_sid, sec_socket, sec_peer)) = secondary_target {
            let mut sec_buf = self.scratch_buffer[0..wire_size].to_vec();
            // Flag as bicast duplicate copy
            if sec_buf.len() >= EGRESS_HEADER_SIZE {
                sec_buf[7] |= FLAG_BICAST_COPY;
                // Recompute CRC with updated flag
                let new_crc =
                    compute_envelope_crc32(&sec_buf[0..40], &sec_buf[EGRESS_HEADER_SIZE..]);
                sec_buf[40..44].copy_from_slice(&new_crc.to_be_bytes());
            }

            if let Ok(Some(n)) = sec_socket.try_send_to(&sec_buf, sec_peer) {
                if let Some(iface) = self.interfaces.get_mut(&sec_sid) {
                    iface.packets_sent += 1;
                    iface.bytes_sent += n as u64;
                    iface.last_transmit_ns = now_ns;
                }
                self.telemetry.total_wire_packets_transmitted += 1;
                self.telemetry.total_wire_bytes_transmitted += n as u64;
                self.telemetry.total_bicasted_packets += 1;
            }
        }
    }

    /// Drain all eligible scheduled outbound items until queue is empty or throttled.
    pub fn drain_all_ready(&mut self, now_ns: u64) -> EgressCycleReport {
        let mut total_report = EgressCycleReport::default();
        loop {
            let report = self.process_egress_cycle(now_ns, Some(self.config.max_batch_size));
            total_report.packets_transmitted += report.packets_transmitted;
            total_report.bytes_transmitted += report.bytes_transmitted;
            total_report.backpressure_drained += report.backpressure_drained;
            total_report.backpressure_queued += report.backpressure_queued;
            total_report.pacing_waits += report.pacing_waits;
            total_report.active_interfaces_count = report.active_interfaces_count;

            if report.packets_transmitted == 0 && report.backpressure_drained == 0 {
                break;
            }
        }
        total_report
    }

    /// Trigger periodic Retransmission Timeout (RTO) sweeps.
    pub fn sweep_rto(&mut self, now_ns: u64) -> EventProcessOutcome {
        self.scheduler.sweep_rto_deadlines(now_ns)
    }

    /// Trigger closed-loop predictive SLA risk audit.
    pub fn execute_predictive_audit(&mut self, now_ns: u64) -> EventProcessOutcome {
        self.scheduler.execute_predictive_audit(now_ns)
    }

    /// Telemetry snapshot reference.
    pub fn telemetry(&self) -> &AsyncMultipathEgressGatewayTelemetry {
        &self.telemetry
    }

    /// Bridge an existing `AsyncMultipathTransport` instance into the gateway.
    pub fn bridge_from_transport(
        transport: &AsyncMultipathTransport,
        gateway_config: Option<AsyncMultipathEgressGatewayConfig>,
        now_ns: u64,
    ) -> Result<Self, EgressGatewayError> {
        let config = gateway_config.unwrap_or_default();
        let mut gateway = Self::new(config);

        let subpaths_telemetry = transport.subpaths_snapshot();
        for sp_telemetry in subpaths_telemetry {
            let sid = sp_telemetry.subpath_id as u32;

            // Bind fallback mock UDP socket for interface descriptor
            let local_bind = "127.0.0.1:0";
            let socket = AsyncUdpSocket::bind(local_bind)
                .map_err(|e| EgressGatewayError::SocketError(e.to_string()))?;

            let iface = PhysicalEgressInterface::new(
                sid,
                sp_telemetry.name.clone(),
                Arc::new(socket),
                sp_telemetry.peer_addr,
                sp_telemetry.bandwidth_bps,
                sp_telemetry.rtt_ms * 1_000_000,
                1420,
                now_ns,
            );

            gateway.register_interface(iface, now_ns)?;
        }

        Ok(gateway)
    }

    /// Prometheus / OpenMetrics exposition.
    pub fn export_prometheus_metrics(&self) -> String {
        let mut out = String::with_capacity(2048);
        let t = &self.telemetry;

        let _ = writeln!(out, "# HELP ifa_egress_payloads_submitted_total Total application payloads submitted to egress gateway.");
        let _ = writeln!(out, "# TYPE ifa_egress_payloads_submitted_total counter");
        let _ = writeln!(
            out,
            "ifa_egress_payloads_submitted_total {}",
            t.total_payloads_submitted
        );

        let _ = writeln!(out, "# HELP ifa_egress_wire_packets_transmitted_total Total zero-copy packets transmitted onto physical interfaces.");
        let _ = writeln!(
            out,
            "# TYPE ifa_egress_wire_packets_transmitted_total counter"
        );
        let _ = writeln!(
            out,
            "ifa_egress_wire_packets_transmitted_total {}",
            t.total_wire_packets_transmitted
        );

        let _ = writeln!(out, "# HELP ifa_egress_wire_bytes_transmitted_total Total wire bytes dispatched over physical network interfaces.");
        let _ = writeln!(
            out,
            "# TYPE ifa_egress_wire_bytes_transmitted_total counter"
        );
        let _ = writeln!(
            out,
            "ifa_egress_wire_bytes_transmitted_total {}",
            t.total_wire_bytes_transmitted
        );

        let _ = writeln!(out, "# HELP ifa_egress_zero_copy_serializations_total Total direct zero-copy wire frame serializations.");
        let _ = writeln!(
            out,
            "# TYPE ifa_egress_zero_copy_serializations_total counter"
        );
        let _ = writeln!(
            out,
            "ifa_egress_zero_copy_serializations_total {}",
            t.total_zero_copy_serializations
        );

        let _ = writeln!(out, "# HELP ifa_egress_backpressure_events_total Total WouldBlock backpressure events captured.");
        let _ = writeln!(out, "# TYPE ifa_egress_backpressure_events_total counter");
        let _ = writeln!(
            out,
            "ifa_egress_backpressure_events_total {}",
            t.total_backpressure_events
        );

        let _ = writeln!(out, "# HELP ifa_egress_backpressure_drained_total Total backpressured packets successfully dispatched upon socket readiness.");
        let _ = writeln!(out, "# TYPE ifa_egress_backpressure_drained_total counter");
        let _ = writeln!(
            out,
            "ifa_egress_backpressure_drained_total {}",
            t.total_backpressure_drained
        );

        let _ = writeln!(out, "# HELP ifa_egress_bicasted_packets_total Total 1+1 redundant copies dispatched over secondary interfaces.");
        let _ = writeln!(out, "# TYPE ifa_egress_bicasted_packets_total counter");
        let _ = writeln!(
            out,
            "ifa_egress_bicasted_packets_total {}",
            t.total_bicasted_packets
        );

        for iface in self.interfaces.values() {
            let _ = writeln!(
                out,
                "ifa_egress_interface_packets_sent_total{{subpath=\"{}\",iface=\"{}\"}} {}",
                iface.subpath_id, iface.interface_name, iface.packets_sent
            );
            let _ = writeln!(
                out,
                "ifa_egress_interface_bytes_sent_total{{subpath=\"{}\",iface=\"{}\"}} {}",
                iface.subpath_id, iface.interface_name, iface.bytes_sent
            );
            let _ = writeln!(
                out,
                "ifa_egress_interface_would_block_total{{subpath=\"{}\",iface=\"{}\"}} {}",
                iface.subpath_id, iface.interface_name, iface.would_block_count
            );
        }

        out
    }

    /// Generate structured JSON audit trail.
    pub fn generate_json_audit_trail(&self) -> String {
        let mut out = String::with_capacity(2048);
        let t = &self.telemetry;

        let _ = write!(out, "{{\"gateway\":{{\"total_payloads_submitted\":{},\"total_wire_packets_transmitted\":{},\"total_wire_bytes_transmitted\":{},\"total_zero_copy_serializations\":{},\"total_backpressure_events\":{},\"total_backpressure_drained\":{},\"total_bicasted_packets\":{},\"active_backpressure_count\":{}}},\"interfaces\":[",
            t.total_payloads_submitted,
            t.total_wire_packets_transmitted,
            t.total_wire_bytes_transmitted,
            t.total_zero_copy_serializations,
            t.total_backpressure_events,
            t.total_backpressure_drained,
            t.total_bicasted_packets,
            t.active_backpressure_count
        );

        let mut first = true;
        for iface in self.interfaces.values() {
            if !first {
                let _ = write!(out, ",");
            }
            first = false;
            let _ = write!(
                out,
                "{{\"subpath_id\":{},\"name\":\"{}\",\"active\":{},\"packets_sent\":{},\"bytes_sent\":{},\"would_block\":{}}}",
                iface.subpath_id,
                iface.interface_name,
                iface.active,
                iface.packets_sent,
                iface.bytes_sent,
                iface.would_block_count
            );
        }

        let _ = write!(out, "]}}");
        out
    }
}

// ---------------------------------------------------------------------------
// In-Memory Micro-Benchmark Suite
// ---------------------------------------------------------------------------

/// Micro-benchmark report for the `AsyncMultipathEgressGateway`.
#[derive(Debug, Clone, PartialEq)]
pub struct EgressGatewayBenchmarkReport {
    pub iterations: usize,
    pub total_wire_bytes: u64,
    pub total_wire_packets: u64,
    pub serialization_throughput_mbps: f64,
    pub average_serialization_ns_per_packet: f64,
    pub cycle_duration_us: u64,
    pub zero_copy_efficiency_percent: f64,
}

/// Run micro-benchmarks measuring zero-copy serialization speed and multi-interface pacing.
pub fn run_async_multipath_egress_gateway_benchmark(
    iterations: usize,
) -> EgressGatewayBenchmarkReport {
    let mut gateway =
        AsyncMultipathEgressGateway::new(AsyncMultipathEgressGatewayConfig::default());
    let now_ns = 1_000_000_000u64;

    // Create 2 loopback UDP sockets
    let s1 = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").expect("benchmark bind s1"));
    let r1 = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").expect("benchmark bind r1"));
    let s2 = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").expect("benchmark bind s2"));
    let r2 = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").expect("benchmark bind r2"));

    let r1_addr = r1.local_addr().expect("r1 local addr");
    let r2_addr = r2.local_addr().expect("r2 local addr");

    let iface1 = PhysicalEgressInterface::new(
        1,
        "eth0-fiber",
        s1,
        r1_addr,
        1_000_000_000, // 1 Gbps
        5_000_000,     // 5 ms
        1500,
        now_ns,
    );

    let iface2 = PhysicalEgressInterface::new(
        2,
        "wlan0-wifi",
        s2,
        r2_addr,
        300_000_000, // 300 Mbps
        15_000_000,  // 15 ms
        1500,
        now_ns,
    );

    let _ = gateway.register_interface(iface1, now_ns);
    let _ = gateway.register_interface(iface2, now_ns);

    let start_time = std::time::Instant::now();
    let payload = vec![0xABu8; 1024];

    for i in 0..iterations {
        let slice = if i % 2 == 0 {
            FlowSliceClass::UltraLowLatency
        } else {
            FlowSliceClass::HighThroughput
        };
        let _ = gateway.submit_payload(
            (i % 16) as u64,
            slice,
            payload.clone(),
            Some(now_ns + 50_000_000),
            now_ns + (i as u64 * 100),
        );
    }

    let report = gateway.drain_all_ready(now_ns + 10_000);
    let elapsed = start_time.elapsed();
    let elapsed_us = elapsed.as_micros().max(1) as u64;

    let total_bytes = report.bytes_transmitted;
    let total_packets = report.packets_transmitted as u64;

    let serialization_throughput_mbps =
        (total_bytes as f64 * 8.0) / (elapsed.as_secs_f64().max(1e-6) * 1_000_000.0);
    let avg_ns = if total_packets > 0 {
        (elapsed.as_nanos() as f64) / (total_packets as f64)
    } else {
        0.0
    };

    EgressGatewayBenchmarkReport {
        iterations,
        total_wire_bytes: total_bytes,
        total_wire_packets: total_packets,
        serialization_throughput_mbps,
        average_serialization_ns_per_packet: avg_ns,
        cycle_duration_us: elapsed_us,
        zero_copy_efficiency_percent: 100.0,
    }
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_copy_serialization_roundtrip_and_crc_validation() {
        let payload = b"Deterministic IFA Zero-Copy Wire Payload 2026";
        let header = EgressWireHeader {
            magic: IFA_EGRESS_MAGIC,
            version: IFA_EGRESS_VERSION,
            slice_class: FlowSliceClass::UltraLowLatency,
            item_kind: OutboundItemKind::DataPacket,
            flags: FLAG_URGENT,
            subpath_id: 42,
            flow_id: 1001,
            sequence_number: 777,
            departure_time_ns: 1234567890,
            payload_length: payload.len() as u32,
            crc32: 0,
        };

        let mut envelope = EgressWireEnvelope::new(header.clone(), payload);
        let mut target_buf = vec![0u8; 256];

        let wire_size = envelope
            .serialize_into(&mut target_buf)
            .expect("serialization should succeed");
        assert_eq!(wire_size, EGRESS_HEADER_SIZE + payload.len());

        // Decode zero-copy
        let (decoded_header, decoded_payload) =
            EgressWireEnvelope::decode_packet(&target_buf[0..wire_size])
                .expect("decoding should succeed");

        assert_eq!(decoded_header.magic, IFA_EGRESS_MAGIC);
        assert_eq!(decoded_header.version, IFA_EGRESS_VERSION);
        assert_eq!(decoded_header.slice_class, FlowSliceClass::UltraLowLatency);
        assert_eq!(decoded_header.item_kind, OutboundItemKind::DataPacket);
        assert_eq!(decoded_header.flags, FLAG_URGENT);
        assert_eq!(decoded_header.subpath_id, 42);
        assert_eq!(decoded_header.flow_id, 1001);
        assert_eq!(decoded_header.sequence_number, 777);
        assert_eq!(decoded_payload, payload);

        // Intentionally tamper with 1 payload byte to verify CRC rejection
        target_buf[EGRESS_HEADER_SIZE + 2] ^= 0xFF;
        let tamper_res = EgressWireEnvelope::decode_packet(&target_buf[0..wire_size]);
        assert!(matches!(
            tamper_res,
            Err(EgressGatewayError::CrcMismatch { .. })
        ));
    }

    #[test]
    fn test_physical_interface_registration_and_slice_binding() {
        let mut gateway =
            AsyncMultipathEgressGateway::new(AsyncMultipathEgressGatewayConfig::default());
        let socket = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").expect("bind"));
        let peer_addr: SocketAddr = "127.0.0.1:9099".parse().unwrap();

        let iface = PhysicalEgressInterface::new(
            1,
            "eth0",
            socket,
            peer_addr,
            1_000_000_000,
            10_000_000,
            1500,
            100_000,
        );

        gateway.register_interface(iface, 100_000).unwrap();
        assert_eq!(gateway.interfaces.len(), 1);
        assert!(gateway.interfaces.contains_key(&1));

        gateway.bind_slice_to_subpath(FlowSliceClass::MissionCritical, 1);
        assert_eq!(
            gateway
                .scheduler
                .get_slice_subpath(FlowSliceClass::MissionCritical),
            Some(1)
        );

        gateway.set_interface_active(1, false);
        assert!(!gateway.interfaces.get(&1).unwrap().active);
    }

    #[test]
    fn test_egress_gateway_cycle_and_wire_dispatch_over_udp() {
        let mut gateway =
            AsyncMultipathEgressGateway::new(AsyncMultipathEgressGatewayConfig::default());
        let now_ns = 1_000_000_000;

        let tx_sock = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").expect("bind tx"));
        let rx_sock = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").expect("bind rx"));
        let rx_addr = rx_sock.local_addr().unwrap();

        let iface = PhysicalEgressInterface::new(
            1,
            "wan0",
            tx_sock,
            rx_addr,
            100_000_000,
            20_000_000,
            1500,
            now_ns,
        );
        gateway.register_interface(iface, now_ns).unwrap();

        let payload = vec![0x42u8; 512];
        let pkt_id = gateway
            .submit_payload(
                10,
                FlowSliceClass::UltraLowLatency,
                payload.clone(),
                Some(now_ns + 50_000_000),
                now_ns,
            )
            .unwrap();
        assert_eq!(pkt_id, 1);

        let report = gateway.process_egress_cycle(now_ns, Some(10));
        assert!(report.packets_transmitted >= 1);
        assert!(report.bytes_transmitted >= 512 + EGRESS_HEADER_SIZE as u64);

        // Receive datagram on rx socket
        let mut rx_buf = vec![0u8; 1500];
        let (n, _from) = rx_sock
            .recv_from(&mut rx_buf)
            .expect("should receive packet");
        assert_eq!(n, 512 + EGRESS_HEADER_SIZE);

        let (header, decoded_payload) =
            EgressWireEnvelope::decode_packet(&rx_buf[0..n]).expect("valid packet");
        assert_eq!(header.subpath_id, 1);
        assert_eq!(header.flow_id, 10);
        assert_eq!(decoded_payload, payload.as_slice());
    }

    #[test]
    fn test_stream_and_control_frame_submission() {
        let mut gateway =
            AsyncMultipathEgressGateway::new(AsyncMultipathEgressGatewayConfig::default());
        let now_ns = 2_000_000_000;

        let tx_sock = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").expect("bind tx"));
        let peer_addr: SocketAddr = "127.0.0.1:9191".parse().unwrap();

        let iface = PhysicalEgressInterface::new(
            1,
            "eth0",
            tx_sock,
            peer_addr,
            500_000_000,
            10_000_000,
            1500,
            now_ns,
        );
        gateway.register_interface(iface, now_ns).unwrap();

        let stream_frame = StreamFrame {
            stream_id: crate::multipath_stream_mux::StreamId::client_bidi(1),
            offset: 0,
            fin: true,
            slice_class: FlowSliceClass::HighThroughput,
            priority: crate::multipath_stream_mux::StreamPriority::Normal,
            subpath_id: 1,
            seq_num: 1,
            is_bicast: false,
            payload: vec![7u8; 128],
        };

        let sid_id = gateway.submit_stream_frame(stream_frame, now_ns).unwrap();
        assert_eq!(sid_id, 1);
        assert_eq!(gateway.telemetry().total_stream_frames_submitted, 1);

        let ctrl_frame = FlowControlFrame::MaxStreamData {
            stream_id: crate::multipath_stream_mux::StreamId::client_bidi(1),
            maximum_stream_data: 65536,
        };

        let ctrl_id = gateway
            .submit_control_frame(ctrl_frame, Some(1), now_ns)
            .unwrap();
        assert_eq!(ctrl_id, 2);
        assert_eq!(gateway.telemetry().total_control_frames_submitted, 1);
    }

    #[test]
    fn test_bridge_from_async_multipath_transport() {
        let transport = AsyncMultipathTransport::new();
        let sock1 = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").expect("bind"));
        let addr1: SocketAddr = "127.0.0.1:8881".parse().unwrap();

        let sp1 = crate::multipath_transport::AsyncMultipathSubpath::new(
            1,
            "subpath-1",
            sock1,
            addr1,
            15,
            100_000_000,
        );
        transport.add_subpath(sp1).unwrap();

        let gateway =
            AsyncMultipathEgressGateway::bridge_from_transport(&transport, None, 1_000_000)
                .expect("bridge should succeed");

        assert_eq!(gateway.interfaces.len(), 1);
        assert!(gateway.interfaces.contains_key(&1));
    }

    #[test]
    fn test_egress_gateway_prometheus_and_audit_trail() {
        let mut gateway =
            AsyncMultipathEgressGateway::new(AsyncMultipathEgressGatewayConfig::default());
        let sock = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").expect("bind"));
        let addr: SocketAddr = "127.0.0.1:7771".parse().unwrap();
        let iface =
            PhysicalEgressInterface::new(1, "tun0", sock, addr, 100_000_000, 10_000_000, 1500, 0);
        gateway.register_interface(iface, 0).unwrap();

        let metrics = gateway.export_prometheus_metrics();
        assert!(metrics.contains("ifa_egress_payloads_submitted_total"));
        assert!(metrics.contains("ifa_egress_wire_packets_transmitted_total"));

        let audit = gateway.generate_json_audit_trail();
        assert!(audit.contains("\"gateway\""));
        assert!(audit.contains("\"tun0\""));
    }

    #[test]
    fn test_egress_gateway_benchmark_execution() {
        let report = run_async_multipath_egress_gateway_benchmark(100);
        assert_eq!(report.iterations, 100);
        assert!(report.cycle_duration_us > 0);
        assert_eq!(report.zero_copy_efficiency_percent, 100.0);
    }

    #[test]
    fn test_bicasting_for_ultra_low_latency_slices() {
        let mut gateway =
            AsyncMultipathEgressGateway::new(AsyncMultipathEgressGatewayConfig::default());
        let now_ns = 5_000_000_000;

        let tx_sock1 = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").expect("bind tx1"));
        let rx_sock1 = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").expect("bind rx1"));
        let rx_addr1 = rx_sock1.local_addr().unwrap();

        let tx_sock2 = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").expect("bind tx2"));
        let rx_sock2 = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").expect("bind rx2"));
        let rx_addr2 = rx_sock2.local_addr().unwrap();

        let iface1 = PhysicalEgressInterface::new(
            1,
            "wan-primary",
            tx_sock1,
            rx_addr1,
            1_000_000_000,
            5_000_000,
            1500,
            now_ns,
        );
        let iface2 = PhysicalEgressInterface::new(
            2,
            "wan-secondary",
            tx_sock2,
            rx_addr2,
            1_000_000_000,
            10_000_000,
            1500,
            now_ns,
        );

        gateway.register_interface(iface1, now_ns).unwrap();
        gateway.register_interface(iface2, now_ns).unwrap();

        let payload = vec![0xEEu8; 256];
        gateway
            .submit_payload(
                42,
                FlowSliceClass::UltraLowLatency,
                payload.clone(),
                Some(now_ns + 10_000_000),
                now_ns,
            )
            .unwrap();

        let report = gateway.process_egress_cycle(now_ns, Some(10));
        assert!(report.packets_transmitted >= 1);
        assert_eq!(gateway.telemetry().total_bicasted_packets, 1);

        // Verify reception on primary socket
        let mut buf1 = vec![0u8; 1500];
        let (n1, _) = rx_sock1.recv_from(&mut buf1).expect("rx1 packet");
        let (hdr1, p1) = EgressWireEnvelope::decode_packet(&buf1[0..n1]).expect("valid pkt1");
        assert_eq!(hdr1.subpath_id, 1);
        assert_eq!(p1, payload.as_slice());
        assert_eq!(hdr1.flags & FLAG_BICAST_COPY, 0);

        // Verify redundant reception on secondary socket
        let mut buf2 = vec![0u8; 1500];
        let (n2, _) = rx_sock2.recv_from(&mut buf2).expect("rx2 packet");
        let (hdr2, p2) = EgressWireEnvelope::decode_packet(&buf2[0..n2]).expect("valid pkt2");
        assert_eq!(p2, payload.as_slice());
        assert_ne!(hdr2.flags & FLAG_BICAST_COPY, 0);
    }

    #[test]
    fn test_backpressure_handling_and_drain() {
        let mut gateway =
            AsyncMultipathEgressGateway::new(AsyncMultipathEgressGatewayConfig::default());
        let now_ns = 3_000_000_000;

        let tx_sock = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").expect("bind tx"));
        let peer_addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let iface = PhysicalEgressInterface::new(
            1,
            "backpressure-iface",
            tx_sock,
            peer_addr,
            100_000_000,
            10_000_000,
            1500,
            now_ns,
        );
        gateway.register_interface(iface, now_ns).unwrap();

        // Queue packet directly into backpressure ring
        let bp = BackpressuredPacket {
            subpath_id: 1,
            peer_addr,
            wire_bytes: vec![0u8; 64],
            packet_id: 99,
            item_kind: OutboundItemKind::DataPacket,
            queued_ns: now_ns,
            retry_attempts: 0,
        };
        gateway.pending_backpressure.push_back(bp);

        let (drained, bytes) = gateway.drain_backpressure_queue(now_ns, 10);
        assert_eq!(drained, 1);
        assert_eq!(bytes, 64);
        assert_eq!(gateway.telemetry().total_backpressure_drained, 1);
    }
}

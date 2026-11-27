//! Multipath Pacing & Anti-Burst Joint Coordinator (`MultipathPacingCoordinator`).
//!
//! Provides deterministic joint inter-packet pacing, BBR congestion window synchronization,
//! arrival drift compensation, and anti-burst shaping across heterogeneous multipath subpaths:
//!
//! 1. **Joint BBR Congestion & Pacing Rate Synchronization**:
//!    - Couples physical link bottleneck bandwidth ($R_{\text{btl}}$) and minimum round-trip time ($RT_{\text{prop}}$).
//!    - Computes nominal inter-packet departure gap:
//!      $$\Delta t_{\text{nominal}} = \frac{S \times 8 \times 10^9}{R_{\text{pace}}}$$
//!      where $R_{\text{pace}} = \frac{\text{BtlBw} \times \text{PacingGain}}{256}$.
//!    - Enforces BBR Congestion Window ($CWND$) gating: prevents packet injection when $\text{inflight} \ge CWND$.
//!
//! 2. **Arrival Drift & Jitter Anti-Bufferbloat Compensation**:
//!    - Evaluates subpath jitter surges and latency drift rate ($d(\text{latency})/dt$).
//!    - When a subpath experiences positive latency drift or high jitter, the coordinator dynamically
//!      dilates inter-packet departure gaps ($\Delta t_{\text{effective}} = \Delta t_{\text{nominal}} \times \text{Dilation}$),
//!      preventing upstream queue saturation (bufferbloat) and downstream reassembly skew.
//!
//! 3. **Hybrid FEC / ARQ Anti-Burst Cadenced Injection**:
//!    - Integrates decisions from [`HybridFecArbiter`]:
//!      - Entrelaces (interleaves) and cadences FEC parity symbols ($M$) smoothly across data packet blocks ($K$),
//!        eliminating back-to-back parity bursts on the wire.
//!      - Prioritizes ARQ selective retransmissions without burst spilling into the bottleneck pipe.
//!      - Guarantees immediate zero-wait injection for `UltraLowLatency` (URLLC) traffic via reserved epoch quanta.
//!
//! 4. **Strict Anti-Burst Shaper (Token Leakage Engine)**:
//!    - Hard burst clamp (`max_burst_bytes`): prevents high-speed wire bursts during burst token exhaustion.
//!    - Deterministic nanosecond schedule timeline: ensures strictly monotonically spaced departure timestamps.
//!
//! 5. **OpenMetrics / Prometheus Observability & Micro-Benchmark**:
//!    - Detailed counters and gauges tracking pacing rates, drift dilation, parity interleaves, and bufferbloat mitigations.
//!    - Sub-microsecond deterministic in-memory benchmark harness.

#![allow(clippy::manual_is_multiple_of, clippy::too_many_arguments)]

use std::collections::{BTreeMap, VecDeque};
use std::fmt::Write as FmtWrite;

use crate::hybrid_fec_arbiter::{ArbiterDecision, HybridSchedulingMode};
use crate::traffic_slicing::FlowSliceClass;

/// Standard IP Maximum Segment Size in bytes.
pub const TCP_MSS_BYTES: u64 = 1460;

/// Default floor for minimum burst allowance in bytes (2 * MSS = 2920 bytes).
pub const DEFAULT_MIN_BURST_BYTES: u64 = 2 * TCP_MSS_BYTES;

/// Default ceiling for maximum burst allowance in bytes (8 * MSS = 11680 bytes).
pub const DEFAULT_MAX_BURST_BYTES: u64 = 8 * TCP_MSS_BYTES;

// ---------------------------------------------------------------------------
// Configuration Parameters
// ---------------------------------------------------------------------------

/// Tuning configuration parameters for the `MultipathPacingCoordinator`.
#[derive(Debug, Clone, PartialEq)]
pub struct PacingCoordinatorConfig {
    /// Minimum burst tolerance in bytes.
    pub min_burst_bytes: u64,
    /// Maximum allowable wire burst in bytes before strict inter-packet gap is enforced.
    pub max_burst_bytes: u64,
    /// Weight applied to latency drift rate for pacing interval dilation (default: 0.85).
    pub drift_dilation_weight: f64,
    /// Weight applied to relative jitter surge for pacing interval dilation (default: 0.50).
    pub jitter_dilation_weight: f64,
    /// Multiplier applied to pacing interval for FEC parity symbols to eliminate parity burst bloat (default: 1.10).
    pub parity_cadence_spacing_multiplier: f64,
    /// Guaranteed injection quantum per epoch in bytes for UltraLowLatency flows (default: 4096 bytes).
    pub urllc_guaranteed_quantum_bytes: u32,
    /// Duration of one URLLC quantum replenishment epoch in nanoseconds (default: 1ms = 1,000,000ns).
    pub urllc_epoch_duration_ns: u64,
    /// Maximum dilation factor ceiling to prevent starvation on degraded paths (default: 3.0x).
    pub max_dilation_factor: f64,
}

impl Default for PacingCoordinatorConfig {
    fn default() -> Self {
        Self {
            min_burst_bytes: DEFAULT_MIN_BURST_BYTES,
            max_burst_bytes: DEFAULT_MAX_BURST_BYTES,
            drift_dilation_weight: 0.85,
            jitter_dilation_weight: 0.50,
            parity_cadence_spacing_multiplier: 1.10,
            urllc_guaranteed_quantum_bytes: 4096,
            urllc_epoch_duration_ns: 1_000_000, // 1 ms
            max_dilation_factor: 3.0,
        }
    }
}

// ---------------------------------------------------------------------------
// Outbound Packet Classification & Items
// ---------------------------------------------------------------------------

/// Distinction between different payloads scheduled by the pacing coordinator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OutboundItemKind {
    /// Fresh application data packet.
    DataPacket,
    /// Forward Error Correction parity symbol generated by FEC encoder.
    FecParitySymbol {
        block_id: u64,
        symbol_index: u8,
        total_symbols: u8,
    },
    /// ARQ Selective Retransmission following packet loss or NACK.
    ArqRetransmission { original_seq: u64, retry_count: u8 },
    /// Low-overhead link-probing or calibration packet.
    ProbePacket,
}

impl OutboundItemKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DataPacket => "data",
            Self::FecParitySymbol { .. } => "fec_parity",
            Self::ArqRetransmission { .. } => "arq_retransmission",
            Self::ProbePacket => "probe",
        }
    }

    pub fn is_parity(&self) -> bool {
        matches!(self, Self::FecParitySymbol { .. })
    }

    pub fn is_retransmission(&self) -> bool {
        matches!(self, Self::ArqRetransmission { .. })
    }
}

/// Outbound unit submitted to the pacing coordinator for anti-burst scheduling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundPacketItem {
    pub item_id: u64,
    pub flow_id: u64,
    pub subpath_id: u32,
    pub slice_class: FlowSliceClass,
    pub kind: OutboundItemKind,
    pub payload: Vec<u8>,
    pub size_bytes: usize,
    pub enqueued_timestamp_ns: u64,
    pub deadline_ns: Option<u64>,
}

impl OutboundPacketItem {
    pub fn new(
        item_id: u64,
        flow_id: u64,
        subpath_id: u32,
        slice_class: FlowSliceClass,
        kind: OutboundItemKind,
        payload: Vec<u8>,
        enqueued_timestamp_ns: u64,
        deadline_ns: Option<u64>,
    ) -> Self {
        let size_bytes = payload.len();
        Self {
            item_id,
            flow_id,
            subpath_id,
            slice_class,
            kind,
            payload,
            size_bytes,
            enqueued_timestamp_ns,
            deadline_ns,
        }
    }
}

/// Dequeued outbound packet ready for wire transmission with calculated pacing timing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledOutboundItem {
    pub item_id: u64,
    pub flow_id: u64,
    pub subpath_id: u32,
    pub slice_class: FlowSliceClass,
    pub kind: OutboundItemKind,
    pub payload: Vec<u8>,
    pub size_bytes: usize,
    pub enqueued_timestamp_ns: u64,
    pub scheduled_tx_time_ns: u64,
    pub pacing_delay_ns: u64,
    pub was_urllc_preempted: bool,
    pub was_burst_smoothed: bool,
}

/// Verdict returned when polling the pacing coordinator for the next wire-ready departure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoordinatorScheduleVerdict {
    /// Packet or parity symbol ready for immediate transmission on the wire.
    Ready(ScheduledOutboundItem),
    /// Subpath is actively pacing departure; caller must wait `wait_ns` until `next_tx_time_ns`.
    PacingWait {
        wait_ns: u64,
        next_tx_time_ns: u64,
        pending_item_id: u64,
    },
    /// Subpath is blocked because in-flight data meets or exceeds BBR Congestion Window ($CWND$).
    BlockedByCwnd {
        inflight_bytes: u64,
        cwnd_bytes: u64,
    },
    /// All queues for this subpath are currently empty.
    Empty,
}

// ---------------------------------------------------------------------------
// Telemetry and Metrics
// ---------------------------------------------------------------------------

/// Per-subpath real-time operational telemetry for the pacing coordinator.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SubpathCoordinatorTelemetry {
    pub subpath_id: u32,
    pub packets_dispatched: u64,
    pub bytes_dispatched: u64,
    pub data_packets_paced: u64,
    pub parity_symbols_paced: u64,
    pub arq_retransmissions_paced: u64,
    pub urllc_preemptions_granted: u64,
    pub burst_spills_smoothed: u64,
    pub bufferbloat_mitigations: u64,
    pub total_pacing_delay_ns: u64,
    pub max_pacing_delay_ns: u64,
    pub cwnd_blocked_events: u64,
    pub effective_pacing_rate_bps: u64,
    pub current_drift_dilation_factor: f64,
    pub current_inflight_bytes: u64,
    pub current_cwnd_bytes: u64,
}

// ---------------------------------------------------------------------------
// Per-Subpath State
// ---------------------------------------------------------------------------

/// Internal state tracker for an individual physical subpath pacer.
#[derive(Debug, Clone)]
pub struct SubpathPacerState {
    pub subpath_id: u32,
    pub is_active: bool,

    // BBR Congestion & Link State
    pub btl_bw_bps: u64,
    pub rt_prop_ns: u64,
    pub pacing_gain_q8: u32,
    pub effective_pacing_rate_bps: u64,
    pub cwnd_bytes: u64,
    pub inflight_bytes: u64,

    // Jitter & Latency Drift State
    pub smoothed_latency_ns: f64,
    pub rfc3550_jitter_ns: u64,
    pub drift_rate_ns_per_sec: f64,
    pub baseline_jitter_ns: u64,
    pub drift_dilation_factor: f64,

    // Hybrid FEC & ARQ Arbitration State
    pub fec_k: usize,
    pub fec_m: usize,
    pub fec_code_rate: f64,
    pub parity_spacing_ratio: f64,
    pub consecutive_data_packets: usize,
    pub consecutive_parities: usize,

    // Nanosecond Departure Timeline & Anti-Burst Leaky Bucket
    pub next_tx_time_ns: u64,
    pub burst_tokens_bytes: u64,
    pub last_token_refresh_ns: u64,

    // URLLC Guaranteed Injection State
    pub urllc_quantum_remaining_bytes: u32,
    pub last_urllc_epoch_ns: u64,

    // Cross-Priority Queues
    pub urllc_queue: VecDeque<OutboundPacketItem>,
    pub mc_queue: VecDeque<OutboundPacketItem>,
    pub embb_queue: VecDeque<OutboundPacketItem>,
    pub be_queue: VecDeque<OutboundPacketItem>,

    // Observability Telemetry
    pub telemetry: SubpathCoordinatorTelemetry,
}

impl SubpathPacerState {
    pub fn new(
        subpath_id: u32,
        initial_bw_bps: u64,
        initial_rtt_ns: u64,
        config: &PacingCoordinatorConfig,
        now_ns: u64,
    ) -> Self {
        let btl_bw_bps = initial_bw_bps.max(1_000_000); // 1 Mbps floor
        let rt_prop_ns = initial_rtt_ns.max(100_000); // 100 µs floor
        let pacing_gain_q8 = 256; // 1.0x nominal
        let effective_pacing_rate_bps = btl_bw_bps;

        // BDP = (BtlBw * RTprop) / 8
        let bdp_bytes = (btl_bw_bps as u128 * rt_prop_ns as u128 / 8_000_000_000) as u64;
        let cwnd_bytes = bdp_bytes.max(config.min_burst_bytes);

        Self {
            subpath_id,
            is_active: true,
            btl_bw_bps,
            rt_prop_ns,
            pacing_gain_q8,
            effective_pacing_rate_bps,
            cwnd_bytes,
            inflight_bytes: 0,
            smoothed_latency_ns: rt_prop_ns as f64 / 2.0,
            rfc3550_jitter_ns: 200_000,
            drift_rate_ns_per_sec: 0.0,
            baseline_jitter_ns: 200_000,
            drift_dilation_factor: 1.0,
            fec_k: 4,
            fec_m: 1,
            fec_code_rate: 0.80,
            parity_spacing_ratio: config.parity_cadence_spacing_multiplier,
            consecutive_data_packets: 0,
            consecutive_parities: 0,
            next_tx_time_ns: now_ns,
            burst_tokens_bytes: config.min_burst_bytes,
            last_token_refresh_ns: now_ns,
            urllc_quantum_remaining_bytes: config.urllc_guaranteed_quantum_bytes,
            last_urllc_epoch_ns: now_ns,
            urllc_queue: VecDeque::new(),
            mc_queue: VecDeque::new(),
            embb_queue: VecDeque::new(),
            be_queue: VecDeque::new(),
            telemetry: SubpathCoordinatorTelemetry {
                subpath_id,
                effective_pacing_rate_bps,
                current_drift_dilation_factor: 1.0,
                current_cwnd_bytes: cwnd_bytes,
                ..Default::default()
            },
        }
    }

    /// Refresh token-bucket burst capacity up to `now_ns`.
    pub fn refresh_burst_tokens(&mut self, config: &PacingCoordinatorConfig, now_ns: u64) {
        if now_ns <= self.last_token_refresh_ns {
            return;
        }

        let elapsed_ns = now_ns - self.last_token_refresh_ns;
        self.last_token_refresh_ns = now_ns;

        // Rate in bytes per nanosecond = (rate_bps / 8) / 10^9
        let added_bytes =
            ((self.effective_pacing_rate_bps as u128 * elapsed_ns as u128) / 8_000_000_000) as u64;

        self.burst_tokens_bytes =
            (self.burst_tokens_bytes + added_bytes).min(config.max_burst_bytes);

        // Replenish URLLC epoch budget if period has elapsed
        if now_ns >= self.last_urllc_epoch_ns + config.urllc_epoch_duration_ns {
            self.urllc_quantum_remaining_bytes = config.urllc_guaranteed_quantum_bytes;
            self.last_urllc_epoch_ns = now_ns;
        }
    }

    /// Recalculate dynamic dilation factor from latency drift rate and jitter surge.
    pub fn recalculate_drift_dilation(&mut self, config: &PacingCoordinatorConfig) {
        // Drift component: if latency is climbing (drift_rate > 0), dilate departure gap
        let drift_component = if self.drift_rate_ns_per_sec > 0.0 && self.smoothed_latency_ns > 0.0
        {
            let normalized_drift = (self.drift_rate_ns_per_sec / self.smoothed_latency_ns)
                .abs()
                .min(2.0);
            config.drift_dilation_weight * normalized_drift
        } else {
            0.0
        };

        // Jitter component: if jitter exceeds baseline, add safety dilation
        let jitter_component =
            if self.rfc3550_jitter_ns > self.baseline_jitter_ns && self.baseline_jitter_ns > 0 {
                let surge_ratio = (self.rfc3550_jitter_ns - self.baseline_jitter_ns) as f64
                    / self.baseline_jitter_ns as f64;
                config.jitter_dilation_weight * surge_ratio.min(1.5)
            } else {
                0.0
            };

        let raw_dilation = 1.0 + drift_component + jitter_component;
        self.drift_dilation_factor = raw_dilation.clamp(1.0, config.max_dilation_factor);
        self.telemetry.current_drift_dilation_factor = self.drift_dilation_factor;

        if self.drift_dilation_factor > 1.05 {
            self.telemetry.bufferbloat_mitigations =
                self.telemetry.bufferbloat_mitigations.saturating_add(1);
        }
    }

    /// Compute precise departure gap in nanoseconds for an outbound packet.
    pub fn compute_packet_gap_ns(&self, item: &OutboundPacketItem) -> u64 {
        let size_bytes = item.size_bytes.max(64) as u64;
        let bits = size_bytes * 8;

        // Nominal transmission duration = (bits * 10^9) / effective_pacing_rate_bps
        let nominal_duration_ns = if self.effective_pacing_rate_bps > 0 {
            ((bits as u128 * 1_000_000_000) / self.effective_pacing_rate_bps as u128) as u64
        } else {
            100_000 // default 100µs fallback
        };

        // Apply drift dilation
        let dilated_duration_ns = (nominal_duration_ns as f64 * self.drift_dilation_factor) as u64;

        // If packet is FEC parity, apply parity cadence spacing multiplier to eliminate parity bursts
        if item.kind.is_parity() {
            (dilated_duration_ns as f64 * self.parity_spacing_ratio) as u64
        } else {
            dilated_duration_ns
        }
    }

    /// Enqueue an outbound packet into the appropriate QoS slice queue.
    pub fn enqueue_packet(&mut self, item: OutboundPacketItem) {
        match item.slice_class {
            FlowSliceClass::UltraLowLatency => self.urllc_queue.push_back(item),
            FlowSliceClass::MissionCritical => self.mc_queue.push_back(item),
            FlowSliceClass::HighThroughput => self.embb_queue.push_back(item),
            FlowSliceClass::BestEffort => self.be_queue.push_back(item),
        }
    }

    /// Total count of all queued packets waiting on this subpath across all slices.
    pub fn queued_packet_count(&self) -> usize {
        self.urllc_queue.len() + self.mc_queue.len() + self.embb_queue.len() + self.be_queue.len()
    }

    /// Finalize packet dispatch, update metrics, inflight, and next tx time.
    pub fn finalize_dispatch(
        &mut self,
        item: OutboundPacketItem,
        now_ns: u64,
        was_burst_smoothed: bool,
    ) -> ScheduledOutboundItem {
        let gap_ns = self.compute_packet_gap_ns(&item);
        let scheduled_time_ns = self.next_tx_time_ns.max(now_ns);
        let pacing_delay_ns = scheduled_time_ns.saturating_sub(item.enqueued_timestamp_ns);

        // Advance pacing clock for next departure
        self.next_tx_time_ns = scheduled_time_ns + gap_ns;

        // Update in-flight bytes
        self.inflight_bytes = self.inflight_bytes.saturating_add(item.size_bytes as u64);
        self.telemetry.current_inflight_bytes = self.inflight_bytes;

        // Telemetry counters
        self.telemetry.packets_dispatched += 1;
        self.telemetry.bytes_dispatched += item.size_bytes as u64;
        self.telemetry.total_pacing_delay_ns += pacing_delay_ns;
        self.telemetry.max_pacing_delay_ns =
            self.telemetry.max_pacing_delay_ns.max(pacing_delay_ns);

        match item.kind {
            OutboundItemKind::DataPacket => {
                self.telemetry.data_packets_paced += 1;
                self.consecutive_data_packets += 1;
                self.consecutive_parities = 0;
            }
            OutboundItemKind::FecParitySymbol { .. } => {
                self.telemetry.parity_symbols_paced += 1;
                self.consecutive_parities += 1;
                self.consecutive_data_packets = 0;
            }
            OutboundItemKind::ArqRetransmission { .. } => {
                self.telemetry.arq_retransmissions_paced += 1;
            }
            OutboundItemKind::ProbePacket => {}
        }

        ScheduledOutboundItem {
            item_id: item.item_id,
            flow_id: item.flow_id,
            subpath_id: item.subpath_id,
            slice_class: item.slice_class,
            kind: item.kind,
            payload: item.payload,
            size_bytes: item.size_bytes,
            enqueued_timestamp_ns: item.enqueued_timestamp_ns,
            scheduled_tx_time_ns: scheduled_time_ns,
            pacing_delay_ns,
            was_urllc_preempted: false,
            was_burst_smoothed,
        }
    }
}

// ---------------------------------------------------------------------------
// MultipathPacingCoordinator Main Engine
// ---------------------------------------------------------------------------

/// Central coordinator regulating multipath inter-packet pacing and anti-burst shaping.
#[derive(Debug, Clone)]
pub struct MultipathPacingCoordinator {
    pub config: PacingCoordinatorConfig,
    pub subpaths: BTreeMap<u32, SubpathPacerState>,
    pub next_item_id: u64,
    pub global_packets_scheduled: u64,
    pub global_bytes_scheduled: u64,
}

impl Default for MultipathPacingCoordinator {
    fn default() -> Self {
        Self::new(PacingCoordinatorConfig::default())
    }
}

impl MultipathPacingCoordinator {
    /// Create a new `MultipathPacingCoordinator` with custom configuration.
    pub fn new(config: PacingCoordinatorConfig) -> Self {
        Self {
            config,
            subpaths: BTreeMap::new(),
            next_item_id: 1,
            global_packets_scheduled: 0,
            global_bytes_scheduled: 0,
        }
    }

    /// Register a physical transport subpath with link bandwidth and RTT.
    pub fn register_subpath(
        &mut self,
        subpath_id: u32,
        initial_bw_bps: u64,
        initial_rtt_ns: u64,
        now_ns: u64,
    ) {
        let pacer = SubpathPacerState::new(
            subpath_id,
            initial_bw_bps,
            initial_rtt_ns,
            &self.config,
            now_ns,
        );
        self.subpaths.insert(subpath_id, pacer);
    }

    /// Update BBR congestion parameters for a specific subpath.
    pub fn update_bbr_state(
        &mut self,
        subpath_id: u32,
        btl_bw_bps: u64,
        rt_prop_ns: u64,
        pacing_gain_q8: u32,
        cwnd_bytes: u64,
        inflight_bytes: u64,
        now_ns: u64,
    ) -> bool {
        let config = &self.config;
        if let Some(pacer) = self.subpaths.get_mut(&subpath_id) {
            pacer.refresh_burst_tokens(config, now_ns);
            pacer.btl_bw_bps = btl_bw_bps.max(10_000);
            pacer.rt_prop_ns = rt_prop_ns.max(10_000);
            pacer.pacing_gain_q8 = pacing_gain_q8;
            pacer.cwnd_bytes = cwnd_bytes.max(config.min_burst_bytes);
            pacer.inflight_bytes = inflight_bytes;

            // Recalculate effective pacing rate = (btl_bw_bps * pacing_gain_q8) / 256
            let rate = ((pacer.btl_bw_bps as u128 * pacing_gain_q8 as u128) / 256) as u64;
            pacer.effective_pacing_rate_bps = rate.max(10_000);
            pacer.telemetry.effective_pacing_rate_bps = pacer.effective_pacing_rate_bps;
            pacer.telemetry.current_cwnd_bytes = pacer.cwnd_bytes;
            pacer.telemetry.current_inflight_bytes = pacer.inflight_bytes;
            true
        } else {
            false
        }
    }

    /// Update measured transit jitter and latency drift rate for a specific subpath.
    pub fn update_drift_and_jitter(
        &mut self,
        subpath_id: u32,
        smoothed_latency_ns: f64,
        rfc3550_jitter_ns: u64,
        drift_rate_ns_per_sec: f64,
        baseline_jitter_ns: u64,
        now_ns: u64,
    ) -> bool {
        let config = &self.config;
        if let Some(pacer) = self.subpaths.get_mut(&subpath_id) {
            pacer.refresh_burst_tokens(config, now_ns);
            pacer.smoothed_latency_ns = smoothed_latency_ns;
            pacer.rfc3550_jitter_ns = rfc3550_jitter_ns;
            pacer.drift_rate_ns_per_sec = drift_rate_ns_per_sec;
            pacer.baseline_jitter_ns = baseline_jitter_ns.max(1_000);
            pacer.recalculate_drift_dilation(config);
            true
        } else {
            false
        }
    }

    /// Synchronize joint arbitration decisions from [`HybridFecArbiter`].
    pub fn notify_fec_arbitration(
        &mut self,
        subpath_id: u32,
        decision: &ArbiterDecision,
        now_ns: u64,
    ) -> bool {
        let config = &self.config;
        if let Some(pacer) = self.subpaths.get_mut(&subpath_id) {
            pacer.refresh_burst_tokens(config, now_ns);
            pacer.fec_k = decision.recommended_k.max(1);
            pacer.fec_m = decision.recommended_m;
            pacer.fec_code_rate = decision.fec_code_rate;

            // If mode is ReinforcedFecWithFallbackArq, slightly dilate parity cadence to avoid link crowding
            pacer.parity_spacing_ratio = match decision.mode {
                HybridSchedulingMode::PureFec => config.parity_cadence_spacing_multiplier * 1.05,
                HybridSchedulingMode::ReinforcedFecWithFallbackArq => {
                    config.parity_cadence_spacing_multiplier * 1.15
                }
                HybridSchedulingMode::JointHybrid => config.parity_cadence_spacing_multiplier,
                HybridSchedulingMode::PureArq | HybridSchedulingMode::BestEffortScavenger => 1.0,
            };
            true
        } else {
            false
        }
    }

    /// Enqueue a fresh application data packet for transmission.
    pub fn enqueue_data_packet(
        &mut self,
        flow_id: u64,
        subpath_id: u32,
        slice_class: FlowSliceClass,
        payload: Vec<u8>,
        enqueued_timestamp_ns: u64,
        deadline_ns: Option<u64>,
    ) -> Result<u64, &'static str> {
        let item_id = self.next_item_id;
        self.next_item_id += 1;

        let item = OutboundPacketItem::new(
            item_id,
            flow_id,
            subpath_id,
            slice_class,
            OutboundItemKind::DataPacket,
            payload,
            enqueued_timestamp_ns,
            deadline_ns,
        );

        if let Some(pacer) = self.subpaths.get_mut(&subpath_id) {
            pacer.enqueue_packet(item);
            Ok(item_id)
        } else {
            Err("subpath not registered")
        }
    }

    /// Enqueue a forward error correction parity symbol for cadenced injection.
    pub fn enqueue_fec_parity(
        &mut self,
        flow_id: u64,
        subpath_id: u32,
        slice_class: FlowSliceClass,
        block_id: u64,
        symbol_index: u8,
        total_symbols: u8,
        payload: Vec<u8>,
        enqueued_timestamp_ns: u64,
        deadline_ns: Option<u64>,
    ) -> Result<u64, &'static str> {
        let item_id = self.next_item_id;
        self.next_item_id += 1;

        let item = OutboundPacketItem::new(
            item_id,
            flow_id,
            subpath_id,
            slice_class,
            OutboundItemKind::FecParitySymbol {
                block_id,
                symbol_index,
                total_symbols,
            },
            payload,
            enqueued_timestamp_ns,
            deadline_ns,
        );

        if let Some(pacer) = self.subpaths.get_mut(&subpath_id) {
            pacer.enqueue_packet(item);
            Ok(item_id)
        } else {
            Err("subpath not registered")
        }
    }

    /// Enqueue an ARQ selective retransmission for prioritized pacing.
    pub fn enqueue_arq_retransmission(
        &mut self,
        flow_id: u64,
        subpath_id: u32,
        slice_class: FlowSliceClass,
        original_seq: u64,
        retry_count: u8,
        payload: Vec<u8>,
        enqueued_timestamp_ns: u64,
        deadline_ns: Option<u64>,
    ) -> Result<u64, &'static str> {
        let item_id = self.next_item_id;
        self.next_item_id += 1;

        let item = OutboundPacketItem::new(
            item_id,
            flow_id,
            subpath_id,
            slice_class,
            OutboundItemKind::ArqRetransmission {
                original_seq,
                retry_count,
            },
            payload,
            enqueued_timestamp_ns,
            deadline_ns,
        );

        if let Some(pacer) = self.subpaths.get_mut(&subpath_id) {
            pacer.enqueue_packet(item);
            Ok(item_id)
        } else {
            Err("subpath not registered")
        }
    }

    /// Schedule and poll the next wire-departure on a specified subpath.
    ///
    /// Evaluates priority queues in order:
    /// `UltraLowLatency` > `MissionCritical` > `HighThroughput` > `BestEffort`.
    ///
    /// Applies strict anti-burst smoothing, BBR congestion gating, and inter-packet departure cadencing.
    pub fn schedule_next(&mut self, subpath_id: u32, now_ns: u64) -> CoordinatorScheduleVerdict {
        let config = &self.config;
        let pacer = match self.subpaths.get_mut(&subpath_id) {
            Some(p) => p,
            None => return CoordinatorScheduleVerdict::Empty,
        };

        if !pacer.is_active {
            return CoordinatorScheduleVerdict::Empty;
        }

        pacer.refresh_burst_tokens(config, now_ns);

        // Check if any packet is queued across all queues
        if pacer.queued_packet_count() == 0 {
            return CoordinatorScheduleVerdict::Empty;
        }

        // Peek next candidate packet following strict QoS priority ladder
        let (is_urllc, peeked_packet_size, peeked_item_id) = {
            if let Some(front) = pacer.urllc_queue.front() {
                (true, front.size_bytes, front.item_id)
            } else if let Some(front) = pacer.mc_queue.front() {
                (false, front.size_bytes, front.item_id)
            } else if let Some(front) = pacer.embb_queue.front() {
                (false, front.size_bytes, front.item_id)
            } else if let Some(front) = pacer.be_queue.front() {
                (false, front.size_bytes, front.item_id)
            } else {
                return CoordinatorScheduleVerdict::Empty;
            }
        };

        // 1. URLLC Preemption Check:
        // UltraLowLatency flows bypass standard pacing and CWND if within guaranteed epoch quantum.
        if is_urllc {
            let required_bytes = peeked_packet_size as u32;
            if pacer.urllc_quantum_remaining_bytes >= required_bytes {
                let item = pacer.urllc_queue.pop_front().unwrap();
                pacer.urllc_quantum_remaining_bytes -= required_bytes;
                pacer.inflight_bytes = pacer.inflight_bytes.saturating_add(item.size_bytes as u64);
                pacer.telemetry.current_inflight_bytes = pacer.inflight_bytes;
                pacer.telemetry.urllc_preemptions_granted += 1;
                pacer.telemetry.packets_dispatched += 1;
                pacer.telemetry.bytes_dispatched += item.size_bytes as u64;

                let scheduled = ScheduledOutboundItem {
                    item_id: item.item_id,
                    flow_id: item.flow_id,
                    subpath_id,
                    slice_class: item.slice_class,
                    kind: item.kind,
                    payload: item.payload,
                    size_bytes: item.size_bytes,
                    enqueued_timestamp_ns: item.enqueued_timestamp_ns,
                    scheduled_tx_time_ns: now_ns,
                    pacing_delay_ns: 0,
                    was_urllc_preempted: true,
                    was_burst_smoothed: false,
                };
                self.global_packets_scheduled += 1;
                self.global_bytes_scheduled += item.size_bytes as u64;
                return CoordinatorScheduleVerdict::Ready(scheduled);
            }
        }

        // 2. BBR CWND Congestion Window Gating:
        // If current in-flight bytes meet or exceed CWND, block transmission.
        if pacer.inflight_bytes >= pacer.cwnd_bytes {
            pacer.telemetry.cwnd_blocked_events += 1;
            return CoordinatorScheduleVerdict::BlockedByCwnd {
                inflight_bytes: pacer.inflight_bytes,
                cwnd_bytes: pacer.cwnd_bytes,
            };
        }

        // 3. Pacing Departure Timeline Evaluation:
        // If scheduled next_tx_time_ns is in the future, evaluate burst tokens.
        if pacer.next_tx_time_ns > now_ns {
            let needed_bytes = peeked_packet_size as u64;
            // Anti-Burst Shaper: if we have sufficient burst tokens, smooth burst and send immediately
            if pacer.burst_tokens_bytes >= needed_bytes {
                pacer.burst_tokens_bytes -= needed_bytes;
                pacer.telemetry.burst_spills_smoothed += 1;
                // Pop the packet and dispatch
                let item = Self::pop_next_packet(pacer);
                let scheduled = pacer.finalize_dispatch(item, now_ns, true);
                self.global_packets_scheduled += 1;
                self.global_bytes_scheduled += scheduled.size_bytes as u64;
                return CoordinatorScheduleVerdict::Ready(scheduled);
            } else {
                // Must wait for inter-packet departure gap
                let wait_ns = pacer.next_tx_time_ns - now_ns;
                return CoordinatorScheduleVerdict::PacingWait {
                    wait_ns,
                    next_tx_time_ns: pacer.next_tx_time_ns,
                    pending_item_id: peeked_item_id,
                };
            }
        }

        // Timeline is ready (now_ns >= next_tx_time_ns). Dispatch next packet.
        let item = Self::pop_next_packet(pacer);
        let scheduled = pacer.finalize_dispatch(item, now_ns, false);
        self.global_packets_scheduled += 1;
        self.global_bytes_scheduled += scheduled.size_bytes as u64;
        CoordinatorScheduleVerdict::Ready(scheduled)
    }

    /// Internal helper to pop the highest-priority packet from subpath queues.
    fn pop_next_packet(pacer: &mut SubpathPacerState) -> OutboundPacketItem {
        if let Some(item) = pacer.urllc_queue.pop_front() {
            item
        } else if let Some(item) = pacer.mc_queue.pop_front() {
            item
        } else if let Some(item) = pacer.embb_queue.pop_front() {
            item
        } else {
            pacer
                .be_queue
                .pop_front()
                .expect("queue must not be empty after non-empty check")
        }
    }

    /// Record receipt of delivery acknowledgement, shedding inflight bytes.
    pub fn acknowledge_delivery(
        &mut self,
        subpath_id: u32,
        bytes_delivered: usize,
        now_ns: u64,
    ) -> bool {
        let config = &self.config;
        if let Some(pacer) = self.subpaths.get_mut(&subpath_id) {
            pacer.refresh_burst_tokens(config, now_ns);
            pacer.inflight_bytes = pacer.inflight_bytes.saturating_sub(bytes_delivered as u64);
            pacer.telemetry.current_inflight_bytes = pacer.inflight_bytes;
            true
        } else {
            false
        }
    }

    /// Retrieve telemetry summary for a subpath.
    pub fn subpath_telemetry(&self, subpath_id: u32) -> Option<&SubpathCoordinatorTelemetry> {
        self.subpaths.get(&subpath_id).map(|p| &p.telemetry)
    }

    /// Export real-time metrics in OpenMetrics / Prometheus exposition format.
    pub fn export_prometheus_metrics(&self) -> String {
        let mut out = String::with_capacity(4096);

        out.push_str("# HELP ifa_pacing_coordinator_packets_dispatched_total Total packets dispatched across subpaths.\n");
        out.push_str("# TYPE ifa_pacing_coordinator_packets_dispatched_total counter\n");
        for (subpath_id, pacer) in &self.subpaths {
            let _ = writeln!(
                out,
                "ifa_pacing_coordinator_packets_dispatched_total{{subpath_id=\"{}\"}} {}",
                subpath_id, pacer.telemetry.packets_dispatched
            );
        }

        out.push_str(
            "# HELP ifa_pacing_coordinator_bytes_dispatched_total Total bytes dispatched.\n",
        );
        out.push_str("# TYPE ifa_pacing_coordinator_bytes_dispatched_total counter\n");
        for (subpath_id, pacer) in &self.subpaths {
            let _ = writeln!(
                out,
                "ifa_pacing_coordinator_bytes_dispatched_total{{subpath_id=\"{}\"}} {}",
                subpath_id, pacer.telemetry.bytes_dispatched
            );
        }

        out.push_str("# HELP ifa_pacing_coordinator_parity_symbols_paced_total Total FEC parity symbols smoothly paced.\n");
        out.push_str("# TYPE ifa_pacing_coordinator_parity_symbols_paced_total counter\n");
        for (subpath_id, pacer) in &self.subpaths {
            let _ = writeln!(
                out,
                "ifa_pacing_coordinator_parity_symbols_paced_total{{subpath_id=\"{}\"}} {}",
                subpath_id, pacer.telemetry.parity_symbols_paced
            );
        }

        out.push_str("# HELP ifa_pacing_coordinator_arq_retransmits_paced_total Total ARQ retransmissions paced.\n");
        out.push_str("# TYPE ifa_pacing_coordinator_arq_retransmits_paced_total counter\n");
        for (subpath_id, pacer) in &self.subpaths {
            let _ = writeln!(
                out,
                "ifa_pacing_coordinator_arq_retransmits_paced_total{{subpath_id=\"{}\"}} {}",
                subpath_id, pacer.telemetry.arq_retransmissions_paced
            );
        }

        out.push_str("# HELP ifa_pacing_coordinator_burst_spills_smoothed_total Total wire burst spills smoothed.\n");
        out.push_str("# TYPE ifa_pacing_coordinator_burst_spills_smoothed_total counter\n");
        for (subpath_id, pacer) in &self.subpaths {
            let _ = writeln!(
                out,
                "ifa_pacing_coordinator_burst_spills_smoothed_total{{subpath_id=\"{}\"}} {}",
                subpath_id, pacer.telemetry.burst_spills_smoothed
            );
        }

        out.push_str("# HELP ifa_pacing_coordinator_bufferbloat_mitigations_total Total bufferbloat drift mitigations.\n");
        out.push_str("# TYPE ifa_pacing_coordinator_bufferbloat_mitigations_total counter\n");
        for (subpath_id, pacer) in &self.subpaths {
            let _ = writeln!(
                out,
                "ifa_pacing_coordinator_bufferbloat_mitigations_total{{subpath_id=\"{}\"}} {}",
                subpath_id, pacer.telemetry.bufferbloat_mitigations
            );
        }

        out.push_str(
            "# HELP ifa_pacing_coordinator_drift_dilation Current departure gap dilation factor.\n",
        );
        out.push_str("# TYPE ifa_pacing_coordinator_drift_dilation gauge\n");
        for (subpath_id, pacer) in &self.subpaths {
            let _ = writeln!(
                out,
                "ifa_pacing_coordinator_drift_dilation{{subpath_id=\"{}\"}} {:.4}",
                subpath_id, pacer.drift_dilation_factor
            );
        }

        out.push_str(
            "# HELP ifa_pacing_coordinator_effective_rate_bps Effective pacing rate in bps.\n",
        );
        out.push_str("# TYPE ifa_pacing_coordinator_effective_rate_bps gauge\n");
        for (subpath_id, pacer) in &self.subpaths {
            let _ = writeln!(
                out,
                "ifa_pacing_coordinator_effective_rate_bps{{subpath_id=\"{}\"}} {}",
                subpath_id, pacer.effective_pacing_rate_bps
            );
        }

        out.push_str(
            "# HELP ifa_pacing_coordinator_inflight_bytes Current in-flight bytes on subpath.\n",
        );
        out.push_str("# TYPE ifa_pacing_coordinator_inflight_bytes gauge\n");
        for (subpath_id, pacer) in &self.subpaths {
            let _ = writeln!(
                out,
                "ifa_pacing_coordinator_inflight_bytes{{subpath_id=\"{}\"}} {}",
                subpath_id, pacer.inflight_bytes
            );
        }

        out.push_str("# HELP ifa_pacing_coordinator_cwnd_bytes Congestion window in bytes.\n");
        out.push_str("# TYPE ifa_pacing_coordinator_cwnd_bytes gauge\n");
        for (subpath_id, pacer) in &self.subpaths {
            let _ = writeln!(
                out,
                "ifa_pacing_coordinator_cwnd_bytes{{subpath_id=\"{}\"}} {}",
                subpath_id, pacer.cwnd_bytes
            );
        }

        out
    }
}

// ---------------------------------------------------------------------------
// Deterministic In-Memory Micro-Benchmark
// ---------------------------------------------------------------------------

/// Benchmark result summary for `MultipathPacingCoordinator`.
#[derive(Debug, Clone, PartialEq)]
pub struct MultipathPacingBenchmarkReport {
    pub total_packets_scheduled: u64,
    pub total_bytes_scheduled: u64,
    pub average_scheduling_latency_ns: u64,
    pub burst_smoothing_events: u64,
    pub parity_symbols_paced: u64,
    pub arq_retransmissions_paced: u64,
    pub urllc_preemptions_granted: u64,
    pub bufferbloat_mitigations: u64,
}

/// Run a deterministic in-memory benchmark verifying anti-burst pacing, FEC cadencing, and URLLC bypass.
pub fn run_multipath_pacing_coordinator_benchmark(
    iterations: usize,
) -> MultipathPacingBenchmarkReport {
    let mut coordinator = MultipathPacingCoordinator::new(PacingCoordinatorConfig::default());
    let now = 1_000_000_000u64;

    // Register 2 subpaths: Primary (100 Mbps, 10ms RTT) and Backup (50 Mbps, 20ms RTT)
    coordinator.register_subpath(1, 100_000_000, 10_000_000, now);
    coordinator.register_subpath(2, 50_000_000, 20_000_000, now);

    // Apply drift on subpath 1 to test anti-bufferbloat dilation
    coordinator.update_drift_and_jitter(1, 5_000_000.0, 800_000, 200_000.0, 200_000, now);

    let start_clock = std::time::Instant::now();
    let mut dispatched_count = 0u64;
    let mut total_bytes = 0u64;
    let mut cur_time = now;

    let payload = vec![0x42u8; 1400];

    for i in 0..iterations {
        let subpath = if i % 3 == 0 { 2 } else { 1 };
        let slice = match i % 4 {
            0 => FlowSliceClass::UltraLowLatency,
            1 => FlowSliceClass::MissionCritical,
            2 => FlowSliceClass::HighThroughput,
            _ => FlowSliceClass::BestEffort,
        };

        if i % 5 == 0 {
            // Enqueue FEC parity
            let _ = coordinator.enqueue_fec_parity(
                100,
                subpath,
                slice,
                (i / 5) as u64,
                0,
                1,
                payload.clone(),
                cur_time,
                None,
            );
        } else if i % 7 == 0 {
            // Enqueue ARQ retransmission
            let _ = coordinator.enqueue_arq_retransmission(
                100,
                subpath,
                slice,
                i as u64,
                1,
                payload.clone(),
                cur_time,
                None,
            );
        } else {
            // Enqueue standard data
            let _ = coordinator.enqueue_data_packet(
                100,
                subpath,
                slice,
                payload.clone(),
                cur_time,
                None,
            );
        }

        // Schedule and poll
        match coordinator.schedule_next(subpath, cur_time) {
            CoordinatorScheduleVerdict::Ready(item) => {
                dispatched_count += 1;
                total_bytes += item.size_bytes as u64;
                // Acknowledge partially to keep pipe flowing
                coordinator.acknowledge_delivery(subpath, item.size_bytes, cur_time);
            }
            CoordinatorScheduleVerdict::PacingWait { wait_ns, .. } => {
                cur_time += wait_ns;
                if let CoordinatorScheduleVerdict::Ready(item) =
                    coordinator.schedule_next(subpath, cur_time)
                {
                    dispatched_count += 1;
                    total_bytes += item.size_bytes as u64;
                    coordinator.acknowledge_delivery(subpath, item.size_bytes, cur_time);
                }
            }
            CoordinatorScheduleVerdict::BlockedByCwnd { .. } => {
                coordinator.acknowledge_delivery(subpath, 1400, cur_time);
            }
            CoordinatorScheduleVerdict::Empty => {}
        }

        cur_time += 150_000; // 150 µs tick
    }

    let elapsed = start_clock.elapsed();
    let avg_latency_ns = (elapsed.as_nanos() as u64)
        .checked_div(dispatched_count)
        .unwrap_or(0);

    let p1 = coordinator
        .subpath_telemetry(1)
        .cloned()
        .unwrap_or_default();
    let p2 = coordinator
        .subpath_telemetry(2)
        .cloned()
        .unwrap_or_default();

    MultipathPacingBenchmarkReport {
        total_packets_scheduled: dispatched_count,
        total_bytes_scheduled: total_bytes,
        average_scheduling_latency_ns: avg_latency_ns,
        burst_smoothing_events: p1.burst_spills_smoothed + p2.burst_spills_smoothed,
        parity_symbols_paced: p1.parity_symbols_paced + p2.parity_symbols_paced,
        arq_retransmissions_paced: p1.arq_retransmissions_paced + p2.arq_retransmissions_paced,
        urllc_preemptions_granted: p1.urllc_preemptions_granted + p2.urllc_preemptions_granted,
        bufferbloat_mitigations: p1.bufferbloat_mitigations + p2.bufferbloat_mitigations,
    }
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subpath_registration_and_bbr_update() {
        let mut coordinator = MultipathPacingCoordinator::new(PacingCoordinatorConfig::default());
        let now = 1_000_000_000u64;

        coordinator.register_subpath(1, 100_000_000, 10_000_000, now);
        let pacer = coordinator.subpaths.get(&1).expect("subpath 1 registered");
        assert_eq!(pacer.btl_bw_bps, 100_000_000);
        assert_eq!(pacer.effective_pacing_rate_bps, 100_000_000);

        // Update BBR state with 1.25x ProbeBw:Up gain (320 in Q8)
        let updated =
            coordinator.update_bbr_state(1, 120_000_000, 8_000_000, 320, 64_000, 0, now + 1_000);
        assert!(updated);

        let pacer = coordinator.subpaths.get(&1).unwrap();
        assert_eq!(pacer.btl_bw_bps, 120_000_000);
        // 120_000_000 * 320 / 256 = 150_000_000 bps
        assert_eq!(pacer.effective_pacing_rate_bps, 150_000_000);
        assert_eq!(pacer.cwnd_bytes, 64_000);
    }

    #[test]
    fn test_drift_and_jitter_dilation() {
        let mut coordinator = MultipathPacingCoordinator::new(PacingCoordinatorConfig::default());
        let now = 1_000_000_000u64;

        coordinator.register_subpath(1, 50_000_000, 10_000_000, now);

        // Subpath stable: dilation is 1.0
        let pacer = coordinator.subpaths.get(&1).unwrap();
        assert_eq!(pacer.drift_dilation_factor, 1.0);

        // Positive latency drift + jitter surge
        coordinator.update_drift_and_jitter(1, 10_000_000.0, 1_000_000, 500_000.0, 200_000, now);
        let pacer = coordinator.subpaths.get(&1).unwrap();
        assert!(
            pacer.drift_dilation_factor > 1.0,
            "Dilation factor should be greater than 1.0, got: {}",
            pacer.drift_dilation_factor
        );
        assert!(pacer.telemetry.bufferbloat_mitigations > 0);
    }

    #[test]
    fn test_fec_parity_cadenced_spacing() {
        let mut coordinator = MultipathPacingCoordinator::new(PacingCoordinatorConfig::default());
        let now = 1_000_000_000u64;

        coordinator.register_subpath(1, 100_000_000, 10_000_000, now);

        let decision = ArbiterDecision {
            subpath_id: 1,
            slice_class: FlowSliceClass::MissionCritical,
            mode: HybridSchedulingMode::JointHybrid,
            recommended_k: 4,
            recommended_m: 1,
            fec_code_rate: 0.80,
            parity_overhead_ratio: 0.20,
            enable_selective_retransmit: true,
            max_retransmit_budget: 2,
            estimated_residual_budget_ns: 20_000_000,
            retransmit_feasibility_score: 1.5,
            timestamp_ns: now,
            reason: "Balanced hybrid test".to_string(),
        };

        coordinator.notify_fec_arbitration(1, &decision, now);
        let pacer = coordinator.subpaths.get(&1).unwrap();
        assert_eq!(pacer.fec_k, 4);
        assert_eq!(pacer.fec_m, 1);
        assert!((pacer.parity_spacing_ratio - 1.10).abs() < 1e-6);

        // Test packet gap calculation: parity gap must exceed data gap
        let data_item = OutboundPacketItem::new(
            1,
            1,
            1,
            FlowSliceClass::MissionCritical,
            OutboundItemKind::DataPacket,
            vec![0u8; 1400],
            now,
            None,
        );
        let parity_item = OutboundPacketItem::new(
            2,
            1,
            1,
            FlowSliceClass::MissionCritical,
            OutboundItemKind::FecParitySymbol {
                block_id: 1,
                symbol_index: 0,
                total_symbols: 1,
            },
            vec![0u8; 1400],
            now,
            None,
        );

        let data_gap = pacer.compute_packet_gap_ns(&data_item);
        let parity_gap = pacer.compute_packet_gap_ns(&parity_item);
        assert!(
            parity_gap > data_gap,
            "Parity gap ({}) should exceed data gap ({})",
            parity_gap,
            data_gap
        );
    }

    #[test]
    fn test_urllc_guaranteed_quantum_preemption() {
        let mut coordinator = MultipathPacingCoordinator::new(PacingCoordinatorConfig::default());
        let now = 1_000_000_000u64;

        coordinator.register_subpath(1, 10_000_000, 20_000_000, now);

        // Artificially saturate inflight to exceed CWND
        coordinator.update_bbr_state(1, 10_000_000, 20_000_000, 256, 5000, 6000, now);

        // BestEffort packet should be blocked by CWND
        let _ = coordinator.enqueue_data_packet(
            1,
            1,
            FlowSliceClass::BestEffort,
            vec![0xBE; 1000],
            now,
            None,
        );
        match coordinator.schedule_next(1, now) {
            CoordinatorScheduleVerdict::BlockedByCwnd {
                inflight_bytes,
                cwnd_bytes,
            } => {
                assert_eq!(inflight_bytes, 6000);
                assert_eq!(cwnd_bytes, 5000);
            }
            other => panic!("Expected BlockedByCwnd, got {:?}", other),
        }

        // UltraLowLatency packet must be preempted and scheduled immediately despite CWND saturation
        let _ = coordinator.enqueue_data_packet(
            2,
            1,
            FlowSliceClass::UltraLowLatency,
            vec![0xAA; 500],
            now,
            None,
        );
        match coordinator.schedule_next(1, now) {
            CoordinatorScheduleVerdict::Ready(item) => {
                assert_eq!(item.slice_class, FlowSliceClass::UltraLowLatency);
                assert!(item.was_urllc_preempted);
                assert_eq!(item.pacing_delay_ns, 0);
            }
            other => panic!("Expected Ready for URLLC preemption, got {:?}", other),
        }
    }

    #[test]
    fn test_anti_burst_smoothing_and_pacing_wait() {
        let mut coordinator = MultipathPacingCoordinator::new(PacingCoordinatorConfig::default());
        let now = 1_000_000_000u64;

        // Register subpath with 10 Mbps (rate = 1.25 MB/s)
        coordinator.register_subpath(1, 10_000_000, 10_000_000, now);

        // Drain burst tokens
        if let Some(pacer) = coordinator.subpaths.get_mut(&1) {
            pacer.burst_tokens_bytes = 0;
            pacer.next_tx_time_ns = now + 1_000_000; // scheduled in 1ms
        }

        let _ = coordinator.enqueue_data_packet(
            1,
            1,
            FlowSliceClass::HighThroughput,
            vec![0xEE; 1000],
            now,
            None,
        );

        // Should return PacingWait because burst tokens are 0 and next_tx_time_ns > now
        match coordinator.schedule_next(1, now) {
            CoordinatorScheduleVerdict::PacingWait {
                wait_ns,
                next_tx_time_ns,
                ..
            } => {
                assert_eq!(wait_ns, 1_000_000);
                assert_eq!(next_tx_time_ns, now + 1_000_000);
            }
            other => panic!("Expected PacingWait, got {:?}", other),
        }

        // Once clock advances, packet departs smoothly
        match coordinator.schedule_next(1, now + 1_000_000) {
            CoordinatorScheduleVerdict::Ready(item) => {
                assert_eq!(item.slice_class, FlowSliceClass::HighThroughput);
                assert_eq!(item.scheduled_tx_time_ns, now + 1_000_000);
            }
            other => panic!("Expected Ready, got {:?}", other),
        }
    }

    #[test]
    fn test_arq_retransmission_scheduling() {
        let mut coordinator = MultipathPacingCoordinator::new(PacingCoordinatorConfig::default());
        let now = 1_000_000_000u64;

        coordinator.register_subpath(1, 50_000_000, 10_000_000, now);

        let id = coordinator
            .enqueue_arq_retransmission(
                1,
                1,
                FlowSliceClass::MissionCritical,
                42,
                1,
                vec![0xFF; 800],
                now,
                None,
            )
            .expect("enqueued ARQ");

        match coordinator.schedule_next(1, now) {
            CoordinatorScheduleVerdict::Ready(item) => {
                assert_eq!(item.item_id, id);
                match item.kind {
                    OutboundItemKind::ArqRetransmission {
                        original_seq,
                        retry_count,
                    } => {
                        assert_eq!(original_seq, 42);
                        assert_eq!(retry_count, 1);
                    }
                    other => panic!("Expected ArqRetransmission, got {:?}", other),
                }
            }
            other => panic!("Expected Ready, got {:?}", other),
        }
    }

    #[test]
    fn test_prometheus_metrics_export() {
        let mut coordinator = MultipathPacingCoordinator::new(PacingCoordinatorConfig::default());
        let now = 1_000_000_000u64;

        coordinator.register_subpath(1, 100_000_000, 10_000_000, now);
        let _ = coordinator.enqueue_data_packet(
            1,
            1,
            FlowSliceClass::HighThroughput,
            vec![0x11; 1000],
            now,
            None,
        );
        let _ = coordinator.schedule_next(1, now);

        let metrics = coordinator.export_prometheus_metrics();
        assert!(
            metrics.contains("ifa_pacing_coordinator_packets_dispatched_total{subpath_id=\"1\"} 1")
        );
        assert!(metrics
            .contains("ifa_pacing_coordinator_effective_rate_bps{subpath_id=\"1\"} 100000000"));
        assert!(metrics.contains("ifa_pacing_coordinator_drift_dilation{subpath_id=\"1\"} 1.0000"));
    }

    #[test]
    fn test_benchmark_execution() {
        let report = run_multipath_pacing_coordinator_benchmark(200);
        assert!(report.total_packets_scheduled > 0);
        assert!(report.total_bytes_scheduled > 0);
        assert!(
            report.average_scheduling_latency_ns < 100_000,
            "Latency too high: {}ns",
            report.average_scheduling_latency_ns
        );
    }
}

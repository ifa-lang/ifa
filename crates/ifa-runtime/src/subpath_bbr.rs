//! Hybrid Subpath BBR Congestion Control Driver (`SubpathBbrDriver`).
//!
//! Provides deterministic joint estimation of maximum bottleneck bandwidth (`BtlBw`)
//! and minimum round-trip propagation time (`RTprop`) per physical egress subpath:
//!
//! 1. **Joint Asynchronous Subpath Estimation (`BtlBw` & `RTprop`)**:
//!    - Maintains an independent max-filter sliding window over delivery rounds for `BtlBw`.
//!    - Tracks minimum propagation delay `RTprop` over a running window, isolating link delay from queue bloat.
//!    - Dynamically computes Bandwidth-Delay Product: $\text{BDP} = \frac{\text{BtlBw} \times \text{RTprop}}{8}$.
//! 2. **Deterministic BBR State Machine per Subpath**:
//!    - `Startup`: Aggressive exponential probe with high pacing gain (2.885x) and CWND gain (2.0x).
//!      Automatically exits upon detecting a bandwidth plateau across 3 consecutive rounds.
//!    - `Drain`: High-speed queue shedding with reduced pacing gain (0.347x) until inflight drains to BDP.
//!    - `ProbeBw`: Four-phase cyclic oscillation (`ProbeUp` 1.25x -> `ProbeDown` 0.75x -> `Cruise` 1.0x -> `Refill` 1.0x).
//!    - `ProbeRtt`: Periodic (every ~5s) minimal-window inflight clamp (4 MSS) to re-evaluate true link delay.
//! 3. **QoS Slicing Coupling & UltraLowLatency Exemption**:
//!    - `UltraLowLatency` (URLLC): Strict latency protection ($1.05 \times \text{BDP}$). Inflight clamp during `ProbeRtt`
//!      does **not** drop or stall URLLC packets (guaranteed immediate injection path).
//!    - `MissionCritical`: Zero-loss tolerance ($1.15 \times \text{BDP}$) with immediate inflight ceiling reduction on loss/ECN.
//!    - `HighThroughput`: Aggressive link pipe filling ($2.0 \times \text{BDP}$).
//!    - `BestEffort`: Pure delay-sensitive scavenger ($1.0 \times \text{BDP}$).
//! 4. **Direct Inter-Packet Pacing Synchronization**:
//!    - Generates dynamic pacing rate $\text{Rate}_{\text{pace}} = \frac{\text{BtlBw} \times \text{PacingGain}}{256}$.
//!    - Synchronizes directly with `MultipathPacingEngine` (`SubpathPacer`) to smooth micro-bursts at the nanosecond scale.
//! 5. **OpenMetrics / Prometheus Observability**:
//!    - Structured metrics: `ifa_transport_bbr_btlbw_bps`, `ifa_transport_bbr_rtprop_us`, `ifa_transport_bbr_pacing_rate_bps`,
//!      `ifa_transport_bbr_cwnd_bytes`, `ifa_transport_bbr_inflight_bytes`, and operational phase markers.

use std::collections::{BTreeMap, VecDeque};
use std::fmt::Write as FmtWrite;

use crate::multipath_pacing::SubpathPacer;
use crate::traffic_slicing::FlowSliceClass;

/// Standard IP Maximum Segment Size in bytes.
pub const TCP_MSS_BYTES: u64 = 1460;

/// Default floor for minimum congestion window (4 * MSS = 5840 bytes).
pub const DEFAULT_MIN_CWND_BYTES: u64 = 4 * TCP_MSS_BYTES;

/// Sub-phases of the BBR steady-state `ProbeBw` cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SubpathBbrProbeBwSubPhase {
    /// ProbeUp: Elevated pacing gain (1.25x) probing for additional bottleneck capacity.
    Up,
    /// ProbeDown: Depressed pacing gain (0.75x) shedding the queue created during ProbeUp.
    Down,
    /// Cruise: Nominal pacing gain (1.0x) exploiting full capacity with zero queuing delay.
    Cruise,
    /// Refill: Pacing gain (1.0x) maintaining pipe fullness prior to the next ProbeUp.
    Refill,
}

impl SubpathBbrProbeBwSubPhase {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Up => "ProbeBw:Up",
            Self::Down => "ProbeBw:Down",
            Self::Cruise => "ProbeBw:Cruise",
            Self::Refill => "ProbeBw:Refill",
        }
    }
}

/// Operational high-level phase of the BBR congestion control engine for a subpath.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SubpathBbrPhase {
    /// Startup: Exponential search for maximum bottleneck bandwidth.
    Startup,
    /// Drain: Queue drain phase shedding excessive inflight accumulated during Startup.
    Drain,
    /// ProbeBw: Steady-state periodic bandwidth probing and queue avoidance.
    ProbeBw(SubpathBbrProbeBwSubPhase),
    /// ProbeRtt: Periodic minimal-window phase to refresh true link propagation delay.
    ProbeRtt,
}

impl SubpathBbrPhase {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Startup => "Startup",
            Self::Drain => "Drain",
            Self::ProbeBw(sub) => sub.as_str(),
            Self::ProbeRtt => "ProbeRtt",
        }
    }
}

/// Tuning configuration parameters for an individual physical subpath BBR instance.
#[derive(Debug, Clone, PartialEq)]
pub struct SubpathBbrConfig {
    /// Minimum floor for congestion window in bytes.
    pub min_cwnd_bytes: u64,
    /// Pacing gain during Startup in Q8.8 fixed-point (738 = 2.885x).
    pub startup_pacing_gain_q8: u32,
    /// CWND gain during Startup in Q8.8 fixed-point (512 = 2.0x).
    pub startup_cwnd_gain_q8: u32,
    /// Pacing gain during Drain in Q8.8 fixed-point (88 = ~0.347x).
    pub drain_pacing_gain_q8: u32,
    /// Pacing gain during ProbeBw:Up in Q8.8 fixed-point (320 = 1.25x).
    pub probe_bw_up_gain_q8: u32,
    /// Pacing gain during ProbeBw:Down in Q8.8 fixed-point (192 = 0.75x).
    pub probe_bw_down_gain_q8: u32,
    /// Pacing gain during ProbeBw:Cruise and Refill in Q8.8 fixed-point (256 = 1.0x).
    pub probe_bw_cruise_gain_q8: u32,
    /// CWND gain in steady-state ProbeBw in Q8.8 fixed-point (512 = 2.0x).
    pub probe_bw_cwnd_gain_q8: u32,
    /// Duration of sliding expiration for RTprop minimum filter in nanoseconds (default: 10s).
    pub min_rtt_filter_duration_ns: u64,
    /// Periodic interval between ProbeRtt occurrences in nanoseconds (default: 5s).
    pub probe_rtt_interval_ns: u64,
    /// Duration of ProbeRtt minimal inflight phase in nanoseconds (default: 200ms).
    pub probe_rtt_duration_ns: u64,
    /// Number of delivery rounds tracked in the BtlBw sliding max-window (default: 8).
    pub bw_window_rounds: usize,
}

impl Default for SubpathBbrConfig {
    fn default() -> Self {
        Self {
            min_cwnd_bytes: DEFAULT_MIN_CWND_BYTES,
            startup_pacing_gain_q8: 738,                // 2.885x
            startup_cwnd_gain_q8: 512,                  // 2.0x
            drain_pacing_gain_q8: 88,                   // 0.347x
            probe_bw_up_gain_q8: 320,                   // 1.25x
            probe_bw_down_gain_q8: 192,                 // 0.75x
            probe_bw_cruise_gain_q8: 256,               // 1.0x
            probe_bw_cwnd_gain_q8: 512,                 // 2.0x
            min_rtt_filter_duration_ns: 10_000_000_000, // 10s
            probe_rtt_interval_ns: 5_000_000_000,       // 5s
            probe_rtt_duration_ns: 200_000_000,         // 200ms
            bw_window_rounds: 8,
        }
    }
}

/// Delivery rate feedback sample reported when an acknowledgement is received.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryAckSample {
    /// Number of bytes newly delivered / acknowledged by the remote peer.
    pub delivered_bytes: u64,
    /// Elapsed delivery duration between send and ack in nanoseconds.
    pub interval_ns: u64,
    /// Measured round-trip propagation time in microseconds.
    pub rtt_us: u64,
    /// Total bytes in flight when this packet was originally sent.
    pub inflight_bytes_at_send: u64,
    /// Number of ECN Congestion Experienced (CE) markings reported in this ack.
    pub ecn_ce_count: u64,
    /// Number of bytes confirmed lost in this round.
    pub lost_bytes: u64,
}

/// Dynamic BBR state tracker for an individual physical subpath.
#[derive(Debug, Clone, PartialEq)]
pub struct SubpathBbrState {
    /// Identifier of the physical subpath.
    pub subpath_id: u8,
    /// Current operational phase.
    pub phase: SubpathBbrPhase,
    /// Subpath configuration parameters.
    pub config: SubpathBbrConfig,
    /// Estimated bottleneck bandwidth in bits per second (`BtlBw`).
    pub btl_bw_bps: u64,
    /// Sliding window of peak bandwidth samples per delivery round.
    pub bw_window: VecDeque<u64>,
    /// Minimum observed round-trip propagation time in microseconds (`RTprop`).
    pub rt_prop_us: u64,
    /// Monotonic timestamp in nanoseconds when `rt_prop_us` was last updated.
    pub rt_prop_stamp_ns: u64,
    /// Current pacing gain in Q8.8 fixed-point.
    pub pacing_gain_q8: u32,
    /// Current CWND gain in Q8.8 fixed-point.
    pub cwnd_gain_q8: u32,
    /// Calculated subpath pacing rate in bits per second.
    pub pacing_rate_bps: u64,
    /// Dynamic target congestion window in bytes.
    pub cwnd_bytes: u64,
    /// Current bytes in-flight awaiting acknowledgement on this subpath.
    pub inflight_bytes: u64,
    /// Total bytes delivered since initialization.
    pub delivered_bytes_total: u64,
    /// Cumulative delivered bytes threshold marking the end of the current round.
    pub next_round_delivered_bytes: u64,
    /// Number of completed round trips.
    pub round_count: u64,
    /// Whether the most recent ack sample crossed into a new delivery round.
    pub round_start: bool,
    /// Consecutive rounds without significant bandwidth gain (> 25% growth) in Startup.
    pub rounds_without_bw_gain: u32,
    /// Peak bandwidth recorded in the previous delivery round.
    pub prev_round_max_bw_bps: u64,
    /// Monotonic timestamp in nanoseconds when the current ProbeRtt cycle began.
    pub probe_rtt_start_ns: u64,
    /// Monotonic timestamp in nanoseconds when the last ProbeRtt cycle completed.
    pub probe_rtt_done_timestamp_ns: u64,
    /// Total packet loss events registered on this subpath.
    pub loss_events_total: u64,
    /// Total ECN CE events registered on this subpath.
    pub ecn_events_total: u64,
    /// Total delivery samples processed.
    pub total_samples_processed: u64,
}

impl SubpathBbrState {
    /// Creates a new subpath BBR state instance with default parameters.
    pub fn new(subpath_id: u8, initial_bw_bps: u64, initial_rtt_us: u64, now_ns: u64) -> Self {
        Self::with_config(
            subpath_id,
            initial_bw_bps,
            initial_rtt_us,
            SubpathBbrConfig::default(),
            now_ns,
        )
    }

    /// Creates a new subpath BBR state instance with custom configuration.
    pub fn with_config(
        subpath_id: u8,
        initial_bw_bps: u64,
        initial_rtt_us: u64,
        config: SubpathBbrConfig,
        now_ns: u64,
    ) -> Self {
        let btl_bw_bps = initial_bw_bps.max(1_000_000); // 1 Mbps floor
        let rt_prop_us = if initial_rtt_us > 0 {
            initial_rtt_us
        } else {
            10_000
        }; // 10ms default
        let pacing_gain_q8 = config.startup_pacing_gain_q8;
        let cwnd_gain_q8 = config.startup_cwnd_gain_q8;
        let pacing_rate_bps = (btl_bw_bps.saturating_mul(pacing_gain_q8 as u64)) / 256;

        let mut bw_window = VecDeque::with_capacity(config.bw_window_rounds);
        bw_window.push_back(btl_bw_bps);

        let mut state = Self {
            subpath_id,
            phase: SubpathBbrPhase::Startup,
            config,
            btl_bw_bps,
            bw_window,
            rt_prop_us,
            rt_prop_stamp_ns: now_ns,
            pacing_gain_q8,
            cwnd_gain_q8,
            pacing_rate_bps,
            cwnd_bytes: 0,
            inflight_bytes: 0,
            delivered_bytes_total: 0,
            next_round_delivered_bytes: 0,
            round_count: 0,
            round_start: false,
            rounds_without_bw_gain: 0,
            prev_round_max_bw_bps: btl_bw_bps,
            probe_rtt_start_ns: 0,
            probe_rtt_done_timestamp_ns: now_ns,
            loss_events_total: 0,
            ecn_events_total: 0,
            total_samples_processed: 0,
        };

        state.cwnd_bytes = state.compute_target_cwnd();
        state
    }

    /// Calculates Bandwidth-Delay Product (BDP) in bytes.
    pub fn compute_bdp_bytes(&self) -> u64 {
        if self.rt_prop_us == 0 || self.btl_bw_bps == 0 {
            return self.config.min_cwnd_bytes;
        }
        // BDP = (bw_bps * rt_prop_us) / 8_000_000
        let bdp = (self.btl_bw_bps.saturating_mul(self.rt_prop_us)) / 8_000_000;
        bdp.max(self.config.min_cwnd_bytes)
    }

    /// Computes nominal target CWND derived from BDP and current state gains.
    pub fn compute_target_cwnd(&self) -> u64 {
        let bdp = self.compute_bdp_bytes();
        let target = (bdp.saturating_mul(self.cwnd_gain_q8 as u64)) / 256;
        target.max(self.config.min_cwnd_bytes)
    }

    /// Computes dynamic slice-specific congestion window in bytes according to QoS profile.
    pub fn compute_slice_cwnd_bytes(&self, slice: FlowSliceClass) -> u64 {
        let bdp = self.compute_bdp_bytes();
        match slice {
            // UltraLowLatency: Strict bufferbloat avoidance: 1.05x BDP
            FlowSliceClass::UltraLowLatency => {
                let target = (bdp.saturating_mul(269)) / 256; // 1.05x (269/256)
                target.max(self.config.min_cwnd_bytes)
            }
            // MissionCritical: Zero-loss resilience: 1.15x BDP
            FlowSliceClass::MissionCritical => {
                let target = (bdp.saturating_mul(294)) / 256; // 1.15x (294/256)
                target.max(self.config.min_cwnd_bytes)
            }
            // HighThroughput: Aggressive saturation: 2.0x BDP
            FlowSliceClass::HighThroughput => {
                let target = (bdp.saturating_mul(512)) / 256; // 2.0x
                target.max(self.config.min_cwnd_bytes * 2)
            }
            // BestEffort: Background scavenger: 1.0x BDP
            FlowSliceClass::BestEffort => bdp.max(self.config.min_cwnd_bytes),
        }
    }

    /// Records transmission of an egress packet, expanding current inflight count.
    pub fn on_packet_sent(&mut self, size_bytes: usize) {
        self.inflight_bytes = self.inflight_bytes.saturating_add(size_bytes as u64);
    }

    /// Processes delivery feedback from an incoming acknowledgement.
    pub fn on_ack_sample(&mut self, sample: DeliveryAckSample, now_ns: u64) {
        self.total_samples_processed += 1;
        self.inflight_bytes = self
            .inflight_bytes
            .saturating_sub(sample.delivered_bytes + sample.lost_bytes);
        self.delivered_bytes_total = self
            .delivered_bytes_total
            .saturating_add(sample.delivered_bytes);

        if sample.lost_bytes > 0 {
            self.loss_events_total += 1;
        }
        if sample.ecn_ce_count > 0 {
            self.ecn_events_total += sample.ecn_ce_count;
        }

        // 1. Delivery Round Boundary Check
        if self.delivered_bytes_total >= self.next_round_delivered_bytes {
            self.round_count += 1;
            self.next_round_delivered_bytes = self.delivered_bytes_total + self.compute_bdp_bytes();
            self.round_start = true;
        } else {
            self.round_start = false;
        }

        // 2. Minimum Propagation Delay (`RTprop`) Tracking
        if sample.rtt_us > 0 {
            let filter_expired = now_ns.saturating_sub(self.rt_prop_stamp_ns)
                > self.config.min_rtt_filter_duration_ns;
            if sample.rtt_us < self.rt_prop_us || filter_expired {
                self.rt_prop_us = sample.rtt_us;
                self.rt_prop_stamp_ns = now_ns;
            }
        }

        // 3. Bottleneck Bandwidth (`BtlBw`) Sampling
        if sample.interval_ns > 0 && sample.delivered_bytes > 0 {
            // sample_bps = (delivered_bytes * 8 * 1_000_000_000) / interval_ns
            let sample_bps = ((sample.delivered_bytes as u128 * 8 * 1_000_000_000)
                / sample.interval_ns as u128) as u64;

            if self.round_start {
                if self.bw_window.len() >= self.config.bw_window_rounds {
                    self.bw_window.pop_front();
                }
                self.bw_window.push_back(sample_bps);
            } else if let Some(last) = self.bw_window.back_mut() {
                if sample_bps > *last {
                    *last = sample_bps;
                }
            }

            let peak_bw = *self.bw_window.iter().max().unwrap_or(&sample_bps);
            let prev_bw = self.btl_bw_bps;
            self.btl_bw_bps = peak_bw.max(1_000_000);

            // Startup Plateau Detection: Check if growth is below 25% over rounds
            if self.phase == SubpathBbrPhase::Startup && self.round_start {
                if prev_bw > 0 && self.btl_bw_bps < (prev_bw * 125) / 100 {
                    self.rounds_without_bw_gain += 1;
                } else {
                    self.rounds_without_bw_gain = 0;
                }
            }
        }

        // 4. Advance State Machine & Phase Transitions
        self.advance_state_machine(now_ns);

        // 5. Update Pacing Rate & Congestion Window
        self.pacing_rate_bps = (self.btl_bw_bps.saturating_mul(self.pacing_gain_q8 as u64)) / 256;
        self.cwnd_bytes = self.compute_target_cwnd();

        // 6. Loss & ECN Ceiling Penalty
        if sample.lost_bytes > 0 || sample.ecn_ce_count > 0 {
            let backoff_q8 = if sample.lost_bytes > 0 { 205 } else { 230 }; // 0.80x on loss, 0.90x on ECN
            self.cwnd_bytes = (self.cwnd_bytes.saturating_mul(backoff_q8)) / 256;
            self.cwnd_bytes = self.cwnd_bytes.max(self.config.min_cwnd_bytes);
        }
    }

    /// Progresses the subpath state machine across Startup, Drain, ProbeBw, and ProbeRtt.
    fn advance_state_machine(&mut self, now_ns: u64) {
        match self.phase {
            SubpathBbrPhase::Startup => {
                self.pacing_gain_q8 = self.config.startup_pacing_gain_q8; // 2.885x
                self.cwnd_gain_q8 = self.config.startup_cwnd_gain_q8; // 2.0x
                if self.rounds_without_bw_gain >= 3 {
                    // Pipe is filled; transition to Drain to shed accumulated queue
                    self.phase = SubpathBbrPhase::Drain;
                    self.pacing_gain_q8 = self.config.drain_pacing_gain_q8; // 0.347x
                    self.cwnd_gain_q8 = 256; // 1.0x
                }
            }
            SubpathBbrPhase::Drain => {
                let bdp = self.compute_bdp_bytes();
                if self.inflight_bytes <= bdp || self.round_start {
                    // Pipe drained; enter steady-state ProbeBw in Cruise mode
                    self.phase = SubpathBbrPhase::ProbeBw(SubpathBbrProbeBwSubPhase::Cruise);
                    self.pacing_gain_q8 = self.config.probe_bw_cruise_gain_q8; // 1.0x
                    self.cwnd_gain_q8 = self.config.probe_bw_cwnd_gain_q8; // 2.0x
                }
            }
            SubpathBbrPhase::ProbeBw(sub) => {
                // Periodic ProbeRtt Trigger Check (every 5 seconds)
                if now_ns.saturating_sub(self.probe_rtt_done_timestamp_ns)
                    > self.config.probe_rtt_interval_ns
                {
                    self.phase = SubpathBbrPhase::ProbeRtt;
                    self.probe_rtt_start_ns = now_ns;
                    self.pacing_gain_q8 = 256; // 1.0x
                    self.cwnd_gain_q8 = 256; // 1.0x
                    return;
                }

                // Cycle through ProbeBw sub-phases on round boundaries
                if self.round_start {
                    match sub {
                        SubpathBbrProbeBwSubPhase::Up => {
                            self.phase = SubpathBbrPhase::ProbeBw(SubpathBbrProbeBwSubPhase::Down);
                            self.pacing_gain_q8 = self.config.probe_bw_down_gain_q8; // 0.75x
                            self.cwnd_gain_q8 = self.config.probe_bw_cwnd_gain_q8;
                        }
                        SubpathBbrProbeBwSubPhase::Down => {
                            self.phase =
                                SubpathBbrPhase::ProbeBw(SubpathBbrProbeBwSubPhase::Cruise);
                            self.pacing_gain_q8 = self.config.probe_bw_cruise_gain_q8; // 1.0x
                            self.cwnd_gain_q8 = self.config.probe_bw_cwnd_gain_q8;
                        }
                        SubpathBbrProbeBwSubPhase::Cruise => {
                            self.phase = SubpathBbrProbeBwSubPhase::Refill.into_bbr_phase();
                            self.pacing_gain_q8 = self.config.probe_bw_cruise_gain_q8; // 1.0x
                            self.cwnd_gain_q8 = self.config.probe_bw_cwnd_gain_q8;
                        }
                        SubpathBbrProbeBwSubPhase::Refill => {
                            self.phase = SubpathBbrPhase::ProbeBw(SubpathBbrProbeBwSubPhase::Up);
                            self.pacing_gain_q8 = self.config.probe_bw_up_gain_q8; // 1.25x
                            self.cwnd_gain_q8 = self.config.probe_bw_cwnd_gain_q8;
                        }
                    }
                }
            }
            SubpathBbrPhase::ProbeRtt => {
                // Check if ProbeRtt holding duration has concluded
                if now_ns.saturating_sub(self.probe_rtt_start_ns)
                    > self.config.probe_rtt_duration_ns
                {
                    self.probe_rtt_done_timestamp_ns = now_ns;
                    self.phase = SubpathBbrPhase::ProbeBw(SubpathBbrProbeBwSubPhase::Cruise);
                    self.pacing_gain_q8 = self.config.probe_bw_cruise_gain_q8; // 1.0x
                    self.cwnd_gain_q8 = self.config.probe_bw_cwnd_gain_q8; // 2.0x
                }
            }
        }
    }

    /// Evaluates whether a packet of `packet_bytes` belonging to `slice` may be sent.
    pub fn can_send(&self, slice: FlowSliceClass, packet_bytes: usize) -> bool {
        // UltraLowLatency (URLLC): Strict priority bypasses ProbeRtt and ordinary CWND limits
        if slice == FlowSliceClass::UltraLowLatency {
            let urllc_ceiling = self.compute_slice_cwnd_bytes(slice);
            return self.inflight_bytes + packet_bytes as u64 <= urllc_ceiling;
        }

        // During ProbeRtt, non-URLLC traffic is clamped to min_cwnd (4 MSS)
        if self.phase == SubpathBbrPhase::ProbeRtt {
            return self.inflight_bytes + packet_bytes as u64 <= self.config.min_cwnd_bytes;
        }

        let slice_cwnd = self.compute_slice_cwnd_bytes(slice);
        let effective_cwnd = self.cwnd_bytes.min(slice_cwnd);
        self.inflight_bytes + packet_bytes as u64 <= effective_cwnd
    }

    /// Generates a telemetry snapshot of this subpath's BBR metrics.
    pub fn snapshot(&self) -> SubpathBbrTelemetry {
        SubpathBbrTelemetry {
            subpath_id: self.subpath_id,
            phase: self.phase,
            btl_bw_bps: self.btl_bw_bps,
            rt_prop_us: self.rt_prop_us,
            pacing_rate_bps: self.pacing_rate_bps,
            cwnd_bytes: self.cwnd_bytes,
            inflight_bytes: self.inflight_bytes,
            bdp_bytes: self.compute_bdp_bytes(),
            round_count: self.round_count,
            loss_events_total: self.loss_events_total,
            ecn_events_total: self.ecn_events_total,
            total_samples_processed: self.total_samples_processed,
        }
    }
}

impl SubpathBbrProbeBwSubPhase {
    fn into_bbr_phase(self) -> SubpathBbrPhase {
        SubpathBbrPhase::ProbeBw(self)
    }
}

/// Point-in-time telemetry snapshot of subpath BBR metrics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubpathBbrTelemetry {
    pub subpath_id: u8,
    pub phase: SubpathBbrPhase,
    pub btl_bw_bps: u64,
    pub rt_prop_us: u64,
    pub pacing_rate_bps: u64,
    pub cwnd_bytes: u64,
    pub inflight_bytes: u64,
    pub bdp_bytes: u64,
    pub round_count: u64,
    pub loss_events_total: u64,
    pub ecn_events_total: u64,
    pub total_samples_processed: u64,
}

/// Multipath BBR Congestion Control Driver (`SubpathBbrDriver`).
///
/// Orchestrates independent BBR engines across heterogeneous network subpaths,
/// continuously synchronizing pacing rates and window constraints with `MultipathPacingEngine`.
#[derive(Debug, Default)]
pub struct SubpathBbrDriver {
    /// Active BBR state per physical subpath.
    subpaths: BTreeMap<u8, SubpathBbrState>,
}

impl SubpathBbrDriver {
    /// Instantiates an empty multipath BBR driver.
    pub fn new() -> Self {
        Self {
            subpaths: BTreeMap::new(),
        }
    }

    /// Registers a new physical subpath with initial link assumptions and default config.
    pub fn register_subpath(
        &mut self,
        subpath_id: u8,
        initial_bw_bps: u64,
        initial_rtt_us: u64,
        now_ns: u64,
    ) {
        let state = SubpathBbrState::new(subpath_id, initial_bw_bps, initial_rtt_us, now_ns);
        self.subpaths.insert(subpath_id, state);
    }

    /// Registers a new physical subpath with custom configuration.
    pub fn register_subpath_with_config(
        &mut self,
        subpath_id: u8,
        initial_bw_bps: u64,
        initial_rtt_us: u64,
        config: SubpathBbrConfig,
        now_ns: u64,
    ) {
        let state = SubpathBbrState::with_config(
            subpath_id,
            initial_bw_bps,
            initial_rtt_us,
            config,
            now_ns,
        );
        self.subpaths.insert(subpath_id, state);
    }

    /// Unregisters a physical subpath, returning its last state if present.
    pub fn unregister_subpath(&mut self, subpath_id: u8) -> Option<SubpathBbrState> {
        self.subpaths.remove(&subpath_id)
    }

    /// Retrieves an immutable reference to a subpath's BBR state.
    pub fn subpath_state(&self, subpath_id: u8) -> Option<&SubpathBbrState> {
        self.subpaths.get(&subpath_id)
    }

    /// Retrieves a mutable reference to a subpath's BBR state.
    pub fn subpath_state_mut(&mut self, subpath_id: u8) -> Option<&mut SubpathBbrState> {
        self.subpaths.get_mut(&subpath_id)
    }

    /// Records transmission of an egress packet on the designated subpath.
    pub fn on_packet_sent(&mut self, subpath_id: u8, size_bytes: usize) {
        if let Some(state) = self.subpaths.get_mut(&subpath_id) {
            state.on_packet_sent(size_bytes);
        }
    }

    /// Feeds an incoming delivery and delay acknowledgement into the subpath BBR state.
    pub fn on_ack_sample(&mut self, subpath_id: u8, sample: DeliveryAckSample, now_ns: u64) {
        if let Some(state) = self.subpaths.get_mut(&subpath_id) {
            state.on_ack_sample(sample, now_ns);
        }
    }

    /// Checks whether the designated subpath has available congestion window to admit a packet.
    pub fn can_send(&self, subpath_id: u8, slice: FlowSliceClass, packet_bytes: usize) -> bool {
        if let Some(state) = self.subpaths.get(&subpath_id) {
            state.can_send(slice, packet_bytes)
        } else {
            false
        }
    }

    /// Synchronizes subpath pacing rates directly with an external `SubpathPacer`.
    pub fn synchronize_pacer(&self, subpath_id: u8, pacer: &mut SubpathPacer, now_ns: u64) -> bool {
        if let Some(state) = self.subpaths.get(&subpath_id) {
            let rtt_ms = (state.rt_prop_us / 1000).max(1);
            pacer.update_link(state.btl_bw_bps, rtt_ms, now_ns);
            pacer.set_pacing_gain(state.pacing_gain_q8, now_ns);
            true
        } else {
            false
        }
    }

    /// Returns a list of telemetry snapshots for all registered subpaths.
    pub fn snapshots(&self) -> Vec<SubpathBbrTelemetry> {
        self.subpaths.values().map(|s| s.snapshot()).collect()
    }

    /// Formats all subpath BBR metrics as Prometheus / OpenMetrics text exposition.
    pub fn export_prometheus_metrics(&self) -> String {
        let mut out = String::with_capacity(2048);

        out.push_str("# HELP ifa_transport_bbr_btlbw_bps Estimated BBR bottleneck bandwidth in bits per second.\n");
        out.push_str("# TYPE ifa_transport_bbr_btlbw_bps gauge\n");
        for state in self.subpaths.values() {
            let _ = writeln!(
                out,
                "ifa_transport_bbr_btlbw_bps{{subpath_id=\"{}\"}} {}",
                state.subpath_id, state.btl_bw_bps
            );
        }

        out.push_str("# HELP ifa_transport_bbr_rtprop_us Estimated BBR minimum propagation RTT in microseconds.\n");
        out.push_str("# TYPE ifa_transport_bbr_rtprop_us gauge\n");
        for state in self.subpaths.values() {
            let _ = writeln!(
                out,
                "ifa_transport_bbr_rtprop_us{{subpath_id=\"{}\"}} {}",
                state.subpath_id, state.rt_prop_us
            );
        }

        out.push_str("# HELP ifa_transport_bbr_pacing_rate_bps Dynamic BBR egress pacing rate in bits per second.\n");
        out.push_str("# TYPE ifa_transport_bbr_pacing_rate_bps gauge\n");
        for state in self.subpaths.values() {
            let _ = writeln!(
                out,
                "ifa_transport_bbr_pacing_rate_bps{{subpath_id=\"{}\"}} {}",
                state.subpath_id, state.pacing_rate_bps
            );
        }

        out.push_str(
            "# HELP ifa_transport_bbr_cwnd_bytes Dynamic BBR congestion window in bytes.\n",
        );
        out.push_str("# TYPE ifa_transport_bbr_cwnd_bytes gauge\n");
        for state in self.subpaths.values() {
            let _ = writeln!(
                out,
                "ifa_transport_bbr_cwnd_bytes{{subpath_id=\"{}\"}} {}",
                state.subpath_id, state.cwnd_bytes
            );
        }

        out.push_str(
            "# HELP ifa_transport_bbr_inflight_bytes Current bytes in flight on the subpath.\n",
        );
        out.push_str("# TYPE ifa_transport_bbr_inflight_bytes gauge\n");
        for state in self.subpaths.values() {
            let _ = writeln!(
                out,
                "ifa_transport_bbr_inflight_bytes{{subpath_id=\"{}\"}} {}",
                state.subpath_id, state.inflight_bytes
            );
        }

        out.push_str(
            "# HELP ifa_transport_bbr_bdp_bytes Computed Bandwidth-Delay Product in bytes.\n",
        );
        out.push_str("# TYPE ifa_transport_bbr_bdp_bytes gauge\n");
        for state in self.subpaths.values() {
            let _ = writeln!(
                out,
                "ifa_transport_bbr_bdp_bytes{{subpath_id=\"{}\"}} {}",
                state.subpath_id,
                state.compute_bdp_bytes()
            );
        }

        out.push_str(
            "# HELP ifa_transport_bbr_round_count_total Total completed BBR delivery rounds.\n",
        );
        out.push_str("# TYPE ifa_transport_bbr_round_count_total counter\n");
        for state in self.subpaths.values() {
            let _ = writeln!(
                out,
                "ifa_transport_bbr_round_count_total{{subpath_id=\"{}\"}} {}",
                state.subpath_id, state.round_count
            );
        }

        out.push_str(
            "# HELP ifa_transport_bbr_loss_events_total Total packet loss events registered.\n",
        );
        out.push_str("# TYPE ifa_transport_bbr_loss_events_total counter\n");
        for state in self.subpaths.values() {
            let _ = writeln!(
                out,
                "ifa_transport_bbr_loss_events_total{{subpath_id=\"{}\"}} {}",
                state.subpath_id, state.loss_events_total
            );
        }

        out.push_str("# HELP ifa_transport_bbr_ecn_events_total Total ECN CE events registered.\n");
        out.push_str("# TYPE ifa_transport_bbr_ecn_events_total counter\n");
        for state in self.subpaths.values() {
            let _ = writeln!(
                out,
                "ifa_transport_bbr_ecn_events_total{{subpath_id=\"{}\"}} {}",
                state.subpath_id, state.ecn_events_total
            );
        }

        out.push_str("# HELP ifa_transport_bbr_phase Current BBR state machine phase (1 for active phase).\n");
        out.push_str("# TYPE ifa_transport_bbr_phase gauge\n");
        for state in self.subpaths.values() {
            let _ = writeln!(
                out,
                "ifa_transport_bbr_phase{{subpath_id=\"{}\",phase=\"{}\"}} 1",
                state.subpath_id,
                state.phase.as_str()
            );
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subpath_bbr_initialization_and_bdp() {
        let now_ns = 1_000_000_000;
        let mut driver = SubpathBbrDriver::new();
        driver.register_subpath(1, 100_000_000, 20_000, now_ns); // 100 Mbps, 20ms RTT

        let state = driver.subpath_state(1).expect("subpath 1 must exist");
        assert_eq!(state.phase, SubpathBbrPhase::Startup);
        assert_eq!(state.btl_bw_bps, 100_000_000);
        assert_eq!(state.rt_prop_us, 20_000);

        // BDP = (100_000_000 * 20_000) / 8_000_000 = 250_000 bytes
        assert_eq!(state.compute_bdp_bytes(), 250_000);

        // In Startup, pacing_gain is 2.885x (738 Q8)
        let expected_pacing = (100_000_000u64 * 738) / 256;
        assert_eq!(state.pacing_rate_bps, expected_pacing);
    }

    #[test]
    fn test_subpath_bbr_delivery_sampling_and_round_tracking() {
        let now_ns = 1_000_000_000;
        let mut driver = SubpathBbrDriver::new();
        driver.register_subpath(1, 50_000_000, 10_000, now_ns);

        // Send a batch of packets
        driver.on_packet_sent(1, 100_000);
        assert_eq!(driver.subpath_state(1).unwrap().inflight_bytes, 100_000);

        // Deliver packets over 10ms with higher bandwidth sample (80 Mbps)
        let ack = DeliveryAckSample {
            delivered_bytes: 100_000,
            interval_ns: 10_000_000, // 10ms
            rtt_us: 10_000,
            inflight_bytes_at_send: 100_000,
            ecn_ce_count: 0,
            lost_bytes: 0,
        };
        driver.on_ack_sample(1, ack, now_ns + 10_000_000);

        let state = driver.subpath_state(1).unwrap();
        assert_eq!(state.inflight_bytes, 0);
        // sample_bps = (100_000 * 8 * 1_000_000_000) / 10_000_000 = 80_000_000 bps
        assert_eq!(state.btl_bw_bps, 80_000_000);
        assert_eq!(state.total_samples_processed, 1);
    }

    #[test]
    fn test_subpath_bbr_startup_exit_to_drain_on_plateau() {
        let mut now_ns = 1_000_000_000;
        let mut state = SubpathBbrState::new(1, 100_000_000, 10_000, now_ns);

        assert_eq!(state.phase, SubpathBbrPhase::Startup);

        // Simulate 3 rounds without bandwidth growth
        for _ in 0..4 {
            let bdp = state.compute_bdp_bytes();
            now_ns += 10_000_000;
            let ack = DeliveryAckSample {
                delivered_bytes: bdp + 1000,
                interval_ns: 10_000_000,
                rtt_us: 10_000,
                inflight_bytes_at_send: bdp + 1000,
                ecn_ce_count: 0,
                lost_bytes: 0,
            };
            state.on_ack_sample(ack, now_ns);
        }

        // Should transition from Startup to Drain after plateau
        assert!(matches!(
            state.phase,
            SubpathBbrPhase::Drain | SubpathBbrPhase::ProbeBw(_)
        ));
    }

    #[test]
    fn test_subpath_bbr_qos_slice_cwnd_and_can_send() {
        let now_ns = 1_000_000_000;
        let mut state = SubpathBbrState::new(1, 80_000_000, 10_000, now_ns); // BDP = 100_000 bytes

        let urllc_cwnd = state.compute_slice_cwnd_bytes(FlowSliceClass::UltraLowLatency);
        let mc_cwnd = state.compute_slice_cwnd_bytes(FlowSliceClass::MissionCritical);
        let embb_cwnd = state.compute_slice_cwnd_bytes(FlowSliceClass::HighThroughput);
        let be_cwnd = state.compute_slice_cwnd_bytes(FlowSliceClass::BestEffort);

        // URLLC ~ 1.05x BDP, MC ~ 1.15x BDP, eMBB ~ 2.0x BDP, BE ~ 1.0x BDP
        assert!(urllc_cwnd >= 100_000);
        assert!(mc_cwnd > urllc_cwnd);
        assert!(embb_cwnd > mc_cwnd);
        assert_eq!(be_cwnd, 100_000);

        // Check admission
        assert!(state.can_send(FlowSliceClass::UltraLowLatency, 1400));
        assert!(state.can_send(FlowSliceClass::HighThroughput, 1400));

        // Fill inflight to capacity
        state.on_packet_sent(urllc_cwnd as usize);
        assert!(!state.can_send(FlowSliceClass::UltraLowLatency, 1400));
    }

    #[test]
    fn test_subpath_bbr_probe_rtt_urllc_exemption() {
        let now_ns = 1_000_000_000;
        let mut state = SubpathBbrState::new(1, 100_000_000, 10_000, now_ns);
        state.phase = SubpathBbrPhase::ProbeRtt;
        state.probe_rtt_start_ns = now_ns;

        // In ProbeRtt, inflight is clamped to min_cwnd (5840 bytes) for bulk traffic
        state.on_packet_sent(5000);

        // Sending 1000 bytes bulk traffic exceeds min_cwnd (5000 + 1000 > 5840)
        assert!(!state.can_send(FlowSliceClass::BestEffort, 1000));
        assert!(!state.can_send(FlowSliceClass::HighThroughput, 1000));

        // UltraLowLatency is exempted from ProbeRtt stall
        assert!(state.can_send(FlowSliceClass::UltraLowLatency, 1000));
    }

    #[test]
    fn test_subpath_bbr_synchronize_with_pacer() {
        let now_ns = 1_000_000_000;
        let mut driver = SubpathBbrDriver::new();
        driver.register_subpath(1, 100_000_000, 20_000, now_ns);

        let mut pacer = SubpathPacer::new(1, 50_000_000, 10, now_ns);
        assert_eq!(pacer.bandwidth_bps, 50_000_000);

        let synced = driver.synchronize_pacer(1, &mut pacer, now_ns);
        assert!(synced);
        assert_eq!(pacer.bandwidth_bps, 100_000_000);
        assert_eq!(pacer.rtt_ms, 20);
        assert_eq!(pacer.pacing_gain_q8, 738);
    }

    #[test]
    fn test_subpath_bbr_prometheus_metrics_export() {
        let now_ns = 1_000_000_000;
        let mut driver = SubpathBbrDriver::new();
        driver.register_subpath(1, 100_000_000, 20_000, now_ns);
        driver.register_subpath(2, 50_000_000, 10_000, now_ns);

        let prom = driver.export_prometheus_metrics();
        assert!(prom.contains("ifa_transport_bbr_btlbw_bps{subpath_id=\"1\"} 100000000"));
        assert!(prom.contains("ifa_transport_bbr_rtprop_us{subpath_id=\"1\"} 20000"));
        assert!(prom.contains("ifa_transport_bbr_phase{subpath_id=\"1\",phase=\"Startup\"} 1"));
        assert!(prom.contains("ifa_transport_bbr_btlbw_bps{subpath_id=\"2\"} 50000000"));
        assert!(prom.contains("ifa_transport_bbr_bdp_bytes{subpath_id=\"1\"} 250000"));
    }
}

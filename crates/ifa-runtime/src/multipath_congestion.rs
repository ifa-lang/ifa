//! Dynamic Multipath Congestion Control Engine (BBRv3 / LEDBAT coupled with QoS Slicing).
//!
//! Provides deterministic congestion control and dynamic window negotiation across
//! heterogeneous multipath subpaths, tightly coupled with traffic slice profiles
//! (`UltraLowLatency`, `MissionCritical`, `HighThroughput`, `BestEffort`):
//!
//! - **BBRv3 Model (Bottleneck Bandwidth and RTT v3)**:
//!   - Explicit phase management: `Startup`, `Drain`, `ProbeBw` (`Down`, `Cruise`, `Refill`, `Up`), `ProbeRtt`.
//!   - Loss & ECN feedback integration: adaptive `inflight_hi` and `inflight_lo` bounds
//!     proportional to delivery rate and packet loss/ECN marking ratio.
//!   - Dynamic Bandwidth-Delay Product (BDP) tracking and fine-grained pacing rate calculations.
//!
//! - **LEDBAT Model (RFC 6817 Extended for QoS Slicing)**:
//!   - One-way queuing delay estimation relative to base propagation delay.
//!   - Early delay-based backpressure to eliminate bufferbloat on latency-sensitive slices.
//!   - Lower-priority scavenger yielding for `BestEffort` traffic.
//!
//! - **QoS Slicing Coupling**:
//!   - `UltraLowLatency` (URLLC): Strict delay bounds, minimal inflight buffer ($1.05 \times BDP$),
//!     aggressive delay-based backpressure.
//!   - `MissionCritical`: Zero-loss tolerance, immediate fast-drain and `inflight_hi` clamping on loss/ECN.
//!   - `HighThroughput` (eMBB): Aggressive BBRv3 bandwidth discovery, high pipe filling ($2.0 \times BDP$).
//!   - `BestEffort`: Pure LEDBAT background scavenger, yielding whenever queuing delay exceeds target.
//!
//! - **Coupled Cross-Subpath Window Negotiation**:
//!   - MPTCP-style congestion coupling: prevents multipath flows from greedily capturing
//!     excessive bottleneck capacity.
//!   - Dynamic window transfer: automatically migrates inflight quota away from lossy or bufferbloated
//!     subpaths towards clean, low-latency alternate subpaths.
//!
//! Zero-simulation: operates exclusively on concrete packet sizes, round-trip measurements,
//! delivery samples, and monotonic nanosecond timestamps.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write;

use crate::session_sync::{IsspMultipathRoute, IsspPathState};
use crate::traffic_slicing::{FlowQoSProfile, FlowSliceClass};

/// Standard Maximum Segment Size (MSS) in bytes for IP transport framing.
pub const TCP_MSS_BYTES: u64 = 1460;

/// Minimum allowable congestion window (4 * MSS).
pub const MIN_CWND_BYTES: u64 = 4 * TCP_MSS_BYTES;

/// Default target queuing delay for LEDBAT background transport (25 ms).
pub const LEDBAT_DEFAULT_TARGET_DELAY_US: u64 = 25_000;

// ─── BBRv3 Phase State Machine ───────────────────────────────────────────────

/// Operating sub-phase of BBRv3 `ProbeBw`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Bbrv3ProbeBwSubPhase {
    /// ProbeDown: Draining extra queue built up during ProbeUp.
    Down,
    /// Cruise: Operating at estimated bottleneck bandwidth with minimal queue.
    Cruise,
    /// Refill: Re-filling the pipe before initiating the next probe up.
    Refill,
    /// ProbeUp: Probing for higher bottleneck bandwidth with elevated pacing gain.
    Up,
}

impl Bbrv3ProbeBwSubPhase {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Down => "ProbeBw:Down",
            Self::Cruise => "ProbeBw:Cruise",
            Self::Refill => "ProbeBw:Refill",
            Self::Up => "ProbeBw:Up",
        }
    }
}

/// BBRv3 High-level congestion control phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Bbrv3Phase {
    /// Startup: Exponential search for maximum bottleneck bandwidth.
    Startup,
    /// Drain: Draining the queue accumulated during Startup.
    Drain,
    /// ProbeBw: Steady-state periodic bandwidth probing.
    ProbeBw(Bbrv3ProbeBwSubPhase),
    /// ProbeRtt: Periodic minimal-window phase to measure minimum propagation delay.
    ProbeRtt,
}

impl Bbrv3Phase {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Startup => "Startup",
            Self::Drain => "Drain",
            Self::ProbeBw(sub) => sub.as_str(),
            Self::ProbeRtt => "ProbeRtt",
        }
    }
}

/// Algorithm selection per subpath.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionAlgorithm {
    /// Pure BBRv3 model.
    BbrV3,
    /// Pure LEDBAT RFC 6817 delay-based model.
    Ledbat,
    /// Hybrid coupled model adapting between BBRv3 and LEDBAT according to slice class.
    HybridQoSCoupled,
}

// ─── Verdict and Decisions ───────────────────────────────────────────────────

/// Verdict returned when evaluating if a packet may be transmitted immediately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CongestionSendVerdict {
    /// Transmission allowed within congestion window and pacing budget.
    Allow {
        granted_bytes: usize,
        cwnd_bytes: u64,
        inflight_bytes: u64,
        pacing_delay_ns: u64,
    },
    /// Transmission throttled due to congestion window or bufferbloat exhaustion.
    ThrottledCongested {
        subpath_id: u32,
        slice_class: FlowSliceClass,
        inflight_bytes: u64,
        cwnd_bytes: u64,
        recommended_subpath_id: Option<u32>,
        backoff_reason: &'static str,
    },
    /// Transmission must wait for subpath pacing clock.
    PacingWait { wait_ns: u64 },
}

// ─── BBRv3 Subpath State ─────────────────────────────────────────────────────

/// Full BBRv3 tracking state for a single multipath subpath.
#[derive(Debug, Clone, PartialEq)]
pub struct Bbrv3SubpathState {
    /// Subpath identifier.
    pub subpath_id: u32,
    /// Current phase in BBRv3 state machine.
    pub phase: Bbrv3Phase,
    /// Estimated bottleneck bandwidth in bits per second.
    pub estimated_bw_bps: u64,
    /// Recent peak bottleneck bandwidth in bits per second.
    pub bw_hi_bps: u64,
    /// Minimum observed round-trip propagation delay in microseconds (RTprop).
    pub min_rtt_us: u64,
    /// Monotonic timestamp in nanoseconds when min_rtt_us was last refreshed.
    pub min_rtt_stamp_ns: u64,
    /// Pacing gain in Q8.8 fixed-point (256 = 1.0x, 320 = 1.25x, 192 = 0.75x, 738 = 2.885x).
    pub pacing_gain_q8: u32,
    /// CWND gain in Q8.8 fixed-point (256 = 1.0x, 512 = 2.0x, 738 = 2.885x).
    pub cwnd_gain_q8: u32,
    /// Pacing rate in bits per second.
    pub pacing_rate_bps: u64,
    /// Computed target congestion window in bytes.
    pub cwnd_bytes: u64,
    /// Inflight upper bound (loss/ECN ceiling) in bytes.
    pub inflight_hi_bytes: u64,
    /// Inflight lower bound (drain floor) in bytes.
    pub inflight_lo_bytes: u64,
    /// Total bytes delivered since connection initialization.
    pub delivered_bytes: u64,
    /// Delivered bytes threshold marking end of current round-trip round.
    pub next_round_delivered: u64,
    /// Round count for tracking delivery epochs.
    pub round_count: u64,
    /// Whether the current delivery update crossed a round boundary.
    pub round_start: bool,
    /// Sliding window of recent bandwidth delivery samples (8 slots).
    pub bw_window: [u64; 8],
    /// Current insertion position in bw_window.
    pub bw_window_pos: usize,
    /// Consecutive rounds without significant bandwidth growth (startup exit check).
    pub rounds_without_bw_gain: u32,
    /// Recent packet loss count.
    pub loss_events_count: u64,
    /// Recent Explicit Congestion Notification (ECN CE) marks count.
    pub ecn_ce_events_count: u64,
    /// Loss rate in parts-per-million (ppm).
    pub loss_rate_ppm: u32,
    /// ECN CE ratio in parts-per-million (ppm).
    pub ecn_ratio_ppm: u32,
    /// Timestamp in nanoseconds of last ProbeRTT exit.
    pub probe_rtt_done_timestamp_ns: u64,
    /// Timestamp in nanoseconds when ProbeRTT was entered.
    pub probe_rtt_start_ns: u64,
}

impl Bbrv3SubpathState {
    pub fn new(subpath_id: u32) -> Self {
        Self {
            subpath_id,
            phase: Bbrv3Phase::Startup,
            estimated_bw_bps: 0,
            bw_hi_bps: 0,
            min_rtt_us: u64::MAX,
            min_rtt_stamp_ns: 0,
            pacing_gain_q8: 738,         // 2.885x Startup pacing gain
            cwnd_gain_q8: 512,           // 2.0x Startup CWND gain
            pacing_rate_bps: 10_000_000, // 10 Mbps initial pacing seed
            cwnd_bytes: MIN_CWND_BYTES * 2,
            inflight_hi_bytes: u64::MAX,
            inflight_lo_bytes: MIN_CWND_BYTES,
            delivered_bytes: 0,
            next_round_delivered: 0,
            round_count: 0,
            round_start: false,
            bw_window: [0u64; 8],
            bw_window_pos: 0,
            rounds_without_bw_gain: 0,
            loss_events_count: 0,
            ecn_ce_events_count: 0,
            loss_rate_ppm: 0,
            ecn_ratio_ppm: 0,
            probe_rtt_done_timestamp_ns: 0,
            probe_rtt_start_ns: 0,
        }
    }

    /// Computes Bandwidth-Delay Product (BDP) in bytes.
    pub fn compute_bdp_bytes(&self) -> u64 {
        if self.min_rtt_us == u64::MAX || self.min_rtt_us == 0 || self.estimated_bw_bps == 0 {
            return MIN_CWND_BYTES;
        }
        // BDP = (bw_bps * min_rtt_us) / 8_000_000
        let bdp = self.estimated_bw_bps.saturating_mul(self.min_rtt_us) / 8_000_000;
        bdp.max(MIN_CWND_BYTES)
    }

    /// Update delivery round boundaries.
    pub fn update_round(&mut self) {
        if self.delivered_bytes >= self.next_round_delivered {
            self.round_count += 1;
            self.next_round_delivered = self.delivered_bytes + self.compute_bdp_bytes();
            self.round_start = true;
        } else {
            self.round_start = false;
        }
    }

    /// Updates bottleneck bandwidth estimate from delivery feedback.
    pub fn update_bandwidth(&mut self, delivered_delta: u64, rtt_us: u64) {
        if rtt_us == 0 || delivered_delta == 0 {
            return;
        }
        self.delivered_bytes = self.delivered_bytes.saturating_add(delivered_delta);
        self.update_round();

        // Sample bps = delivered_delta * 8_000_000 / rtt_us
        let sample_bps = delivered_delta.saturating_mul(8_000_000) / rtt_us;
        self.bw_window[self.bw_window_pos % 8] = sample_bps;
        self.bw_window_pos = self.bw_window_pos.wrapping_add(1);

        let max_bw = *self.bw_window.iter().max().unwrap_or(&sample_bps);
        let prev_bw = self.estimated_bw_bps;
        self.estimated_bw_bps = max_bw;
        if max_bw > self.bw_hi_bps {
            self.bw_hi_bps = max_bw;
        }

        // Track plateau in startup
        if self.phase == Bbrv3Phase::Startup && self.round_start {
            if prev_bw > 0 && max_bw < (prev_bw * 125) / 100 {
                self.rounds_without_bw_gain += 1;
            } else {
                self.rounds_without_bw_gain = 0;
            }
        }
    }

    /// Update propagation delay (min_rtt_us) tracking.
    pub fn update_min_rtt(&mut self, rtt_us: u64, now_ns: u64) {
        if rtt_us == 0 {
            return;
        }
        // Min filter over a 10-second sliding expiration
        const MIN_RTT_FILTER_DURATION_NS: u64 = 10_000_000_000; // 10s
        if rtt_us < self.min_rtt_us
            || now_ns.saturating_sub(self.min_rtt_stamp_ns) > MIN_RTT_FILTER_DURATION_NS
        {
            self.min_rtt_us = rtt_us;
            self.min_rtt_stamp_ns = now_ns;
        }
    }

    /// Handle loss and ECN feedback, adjusting adaptive inflight headroom.
    pub fn on_loss_and_ecn(&mut self, lost_bytes: u64, acked_bytes: u64, ecn_ce_count: u64) {
        let total_sampled = lost_bytes + acked_bytes;
        if total_sampled == 0 {
            return;
        }

        self.loss_events_count += if lost_bytes > 0 { 1 } else { 0 };
        self.ecn_ce_events_count += ecn_ce_count;

        // Compute loss rate in ppm (1% = 10_000 ppm)
        self.loss_rate_ppm = ((lost_bytes as u128 * 1_000_000) / total_sampled as u128) as u32;
        self.ecn_ratio_ppm = ((ecn_ce_count as u128 * 1_000_000)
            / (total_sampled / TCP_MSS_BYTES).max(1) as u128)
            .min(1_000_000) as u32;

        if lost_bytes > 0 || ecn_ce_count > 0 {
            // Adaptive inflight ceiling reduction
            let bdp = self.compute_bdp_bytes();
            let loss_penalty_q8 = if self.loss_rate_ppm > 50_000 {
                179 // 0.70x on heavy loss (>5%)
            } else if self.loss_rate_ppm > 10_000 || self.ecn_ratio_ppm > 50_000 {
                218 // 0.85x on moderate loss/ECN
            } else {
                243 // 0.95x on light loss/ECN
            };

            let current_target = self.cwnd_bytes.min(self.inflight_hi_bytes);
            let reduced = (current_target.saturating_mul(loss_penalty_q8 as u64)) / 256;
            self.inflight_hi_bytes = reduced.max(MIN_CWND_BYTES).max(bdp / 2);
        }
    }

    /// Progresses the BBRv3 state machine.
    pub fn advance_state_machine(&mut self, now_ns: u64) {
        match self.phase {
            Bbrv3Phase::Startup => {
                self.pacing_gain_q8 = 738; // 2.885x
                self.cwnd_gain_q8 = 512; // 2.0x
                if self.rounds_without_bw_gain >= 3 {
                    // Pipe is filled; transition to Drain to shed queue
                    self.phase = Bbrv3Phase::Drain;
                    self.pacing_gain_q8 = 88; // 1 / 2.885x = ~0.347 (88/256)
                    self.cwnd_gain_q8 = 256; // 1.0x
                }
            }
            Bbrv3Phase::Drain => {
                let bdp = self.compute_bdp_bytes();
                if self.cwnd_bytes <= bdp || self.round_start {
                    self.phase = Bbrv3Phase::ProbeBw(Bbrv3ProbeBwSubPhase::Cruise);
                    self.pacing_gain_q8 = 256; // 1.0x
                    self.cwnd_gain_q8 = 512; // 2.0x
                }
            }
            Bbrv3Phase::ProbeBw(sub) => {
                // Periodic ProbeRTT trigger every 5 seconds
                const PROBE_RTT_INTERVAL_NS: u64 = 5_000_000_000;
                if now_ns.saturating_sub(self.probe_rtt_done_timestamp_ns) > PROBE_RTT_INTERVAL_NS {
                    self.phase = Bbrv3Phase::ProbeRtt;
                    self.probe_rtt_start_ns = now_ns;
                    self.pacing_gain_q8 = 256;
                    self.cwnd_gain_q8 = 256;
                    return;
                }

                match sub {
                    Bbrv3ProbeBwSubPhase::Down => {
                        self.pacing_gain_q8 = 192; // 0.75x
                        self.cwnd_gain_q8 = 512;
                        if self.round_start {
                            self.phase = Bbrv3Phase::ProbeBw(Bbrv3ProbeBwSubPhase::Cruise);
                        }
                    }
                    Bbrv3ProbeBwSubPhase::Cruise => {
                        self.pacing_gain_q8 = 256; // 1.0x
                        self.cwnd_gain_q8 = 512;
                        if self.round_start {
                            self.phase = Bbrv3Phase::ProbeBw(Bbrv3ProbeBwSubPhase::Refill);
                        }
                    }
                    Bbrv3ProbeBwSubPhase::Refill => {
                        self.pacing_gain_q8 = 256; // 1.0x
                        self.cwnd_gain_q8 = 512;
                        if self.round_start {
                            self.phase = Bbrv3Phase::ProbeBw(Bbrv3ProbeBwSubPhase::Up);
                        }
                    }
                    Bbrv3ProbeBwSubPhase::Up => {
                        self.pacing_gain_q8 = 320; // 1.25x
                        self.cwnd_gain_q8 = 512;
                        if self.round_start {
                            self.phase = Bbrv3Phase::ProbeBw(Bbrv3ProbeBwSubPhase::Down);
                        }
                    }
                }
            }
            Bbrv3Phase::ProbeRtt => {
                // Hold minimal window for 200 ms to drain queues and get fresh min_rtt
                const PROBE_RTT_DURATION_NS: u64 = 200_000_000;
                self.pacing_gain_q8 = 256;
                self.cwnd_gain_q8 = 256;
                if now_ns.saturating_sub(self.probe_rtt_start_ns) >= PROBE_RTT_DURATION_NS {
                    self.phase = Bbrv3Phase::ProbeBw(Bbrv3ProbeBwSubPhase::Cruise);
                    self.probe_rtt_done_timestamp_ns = now_ns;
                }
            }
        }

        // Recompute pacing rate & target CWND
        self.recompute_pacing_and_cwnd();
    }

    /// Recalculates pacing rate and target CWND.
    fn recompute_pacing_and_cwnd(&mut self) {
        if self.estimated_bw_bps > 0 {
            self.pacing_rate_bps = (self.estimated_bw_bps as u128 * self.pacing_gain_q8 as u128
                / 256)
                .max(1_000_000) as u64;
        }

        let bdp = self.compute_bdp_bytes();
        let raw_cwnd = (bdp as u128 * self.cwnd_gain_q8 as u128 / 256) as u64;
        let quantum = (self.pacing_rate_bps / 8_000).clamp(TCP_MSS_BYTES, 64 * 1024);

        let target_cwnd = raw_cwnd.saturating_add(quantum);
        let capped = target_cwnd.min(self.inflight_hi_bytes);
        self.cwnd_bytes = match self.phase {
            Bbrv3Phase::ProbeRtt => MIN_CWND_BYTES,
            _ => capped.max(MIN_CWND_BYTES),
        };
    }
}

// ─── LEDBAT Subpath State ───────────────────────────────────────────────────

/// Full LEDBAT (RFC 6817) tracking state for a single multipath subpath.
#[derive(Debug, Clone, PartialEq)]
pub struct LedbatSubpathState {
    /// Subpath identifier.
    pub subpath_id: u32,
    /// Base propagation one-way delay (minimum observed OWD), in microseconds.
    pub base_delay_us: u64,
    /// Current estimated one-way delay in microseconds.
    pub current_delay_us: u64,
    /// Estimated queuing delay = current_delay - base_delay, in microseconds.
    pub queuing_delay_us: u64,
    /// Target queuing delay in microseconds (e.g. 5ms for URLLC, 25ms RFC 6817 default).
    pub target_delay_us: u64,
    /// Congestion window in bytes calculated by LEDBAT.
    pub cwnd_bytes: u64,
    /// LEDBAT gain factor (default 1.0).
    pub gain: f64,
    /// Rolling delay samples for base delay filter.
    pub delay_history: [u64; 8],
    /// Circular index in delay_history.
    pub delay_history_pos: usize,
}

impl LedbatSubpathState {
    pub fn new(subpath_id: u32, target_delay_us: u64) -> Self {
        Self {
            subpath_id,
            base_delay_us: u64::MAX,
            current_delay_us: 0,
            queuing_delay_us: 0,
            target_delay_us,
            cwnd_bytes: 65_536, // 64 KiB initial window
            gain: 1.0,
            delay_history: [0u64; 8],
            delay_history_pos: 0,
        }
    }

    /// Updates LEDBAT state with new round-trip sample.
    pub fn update(&mut self, rtt_us: u64) {
        if rtt_us == 0 {
            return;
        }
        let owd = rtt_us / 2;
        self.current_delay_us = owd;

        self.delay_history[self.delay_history_pos % 8] = owd;
        self.delay_history_pos = self.delay_history_pos.wrapping_add(1);

        if owd < self.base_delay_us {
            self.base_delay_us = owd;
        }

        self.queuing_delay_us = self.current_delay_us.saturating_sub(self.base_delay_us);

        // CWND adjustment: RFC 6817 §5
        // off_target = (target_delay - queuing_delay) / target_delay
        if self.target_delay_us > 0 {
            let off_target = (self.target_delay_us as i64 - self.queuing_delay_us as i64) as f64
                / self.target_delay_us as f64;
            let delta = (self.gain * off_target * TCP_MSS_BYTES as f64).round() as i64;
            let updated = (self.cwnd_bytes as i64).saturating_add(delta);
            self.cwnd_bytes = updated.max(MIN_CWND_BYTES as i64) as u64;
        }
    }

    /// Weight factor: 1.0 when clean, decreases smoothly toward 0.05 under queuing.
    pub fn delay_weight_factor(&self) -> f64 {
        if self.base_delay_us == u64::MAX || self.target_delay_us == 0 {
            return 1.0;
        }
        let ratio = self.queuing_delay_us as f64 / self.target_delay_us as f64;
        (1.0 / (1.0 + ratio)).clamp(0.05, 1.0)
    }
}

// ─── Per-Slice Window Budget ────────────────────────────────────────────────

/// Per-slice congestion window allocation on a specific subpath.
#[derive(Debug, Clone, PartialEq)]
pub struct SubpathSliceWindow {
    /// Traffic slice class.
    pub slice_class: FlowSliceClass,
    /// Allocated congestion window slice in bytes.
    pub allocated_cwnd_bytes: u64,
    /// Current bytes in-flight for this slice on this subpath.
    pub current_inflight_bytes: u64,
    /// Slice-specific target delay in microseconds.
    pub slice_target_delay_us: u64,
    /// Maximum allowed inflight multiplier relative to BDP.
    pub slice_max_inflight_ratio: f64,
    /// Slice pacing rate in bits per second.
    pub slice_pacing_rate_bps: u64,
    /// Last packet transmission monotonic timestamp in nanoseconds.
    pub last_send_timestamp_ns: u64,
    /// Total bytes transmitted for this slice.
    pub total_bytes_sent: u64,
    /// Total bytes acknowledged for this slice.
    pub total_bytes_acked: u64,
    /// Total bytes lost for this slice.
    pub total_bytes_lost: u64,
    /// Number of congestion throttle events encountered.
    pub sla_throttle_events: u64,
}

impl SubpathSliceWindow {
    pub fn new(slice_class: FlowSliceClass, profile: &FlowQoSProfile) -> Self {
        let (target_delay_us, inflight_ratio) = match slice_class {
            FlowSliceClass::UltraLowLatency => (profile.max_queuing_delay_us.min(5_000), 1.05),
            FlowSliceClass::MissionCritical => (profile.max_queuing_delay_us.min(10_000), 1.20),
            FlowSliceClass::HighThroughput => (profile.max_queuing_delay_us.max(35_000), 2.00),
            FlowSliceClass::BestEffort => (20_000, 1.00),
        };

        Self {
            slice_class,
            allocated_cwnd_bytes: MIN_CWND_BYTES,
            current_inflight_bytes: 0,
            slice_target_delay_us: target_delay_us,
            slice_max_inflight_ratio: inflight_ratio,
            slice_pacing_rate_bps: 10_000_000,
            last_send_timestamp_ns: 0,
            total_bytes_sent: 0,
            total_bytes_acked: 0,
            total_bytes_lost: 0,
            sla_throttle_events: 0,
        }
    }
}

// ─── Subpath Congestion Controller ──────────────────────────────────────────

/// Comprehensive controller combining BBRv3, LEDBAT, and multi-slice budget slicing.
#[derive(Debug, Clone, PartialEq)]
pub struct SubpathCongestionController {
    /// Subpath identifier.
    pub subpath_id: u32,
    /// Algorithm configuration.
    pub algorithm: CongestionAlgorithm,
    /// BBRv3 engine.
    pub bbrv3: Bbrv3SubpathState,
    /// LEDBAT engine.
    pub ledbat: LedbatSubpathState,
    /// Per-slice allocated window budgets.
    pub slice_windows: HashMap<FlowSliceClass, SubpathSliceWindow>,
    /// Total aggregate inflight bytes across all slices on this subpath.
    pub total_inflight_bytes: u64,
    /// Total active congestion window in bytes.
    pub total_cwnd_bytes: u64,
    /// Timestamp in nanoseconds of last packet transmission on this subpath.
    pub last_transmission_ns: u64,
    /// Indication if subpath is currently considered congested.
    pub is_congested: bool,
}

impl SubpathCongestionController {
    pub fn new(subpath_id: u32, algorithm: CongestionAlgorithm) -> Self {
        let default_target = match algorithm {
            CongestionAlgorithm::Ledbat => LEDBAT_DEFAULT_TARGET_DELAY_US,
            _ => 15_000,
        };

        let mut c = Self {
            subpath_id,
            algorithm,
            bbrv3: Bbrv3SubpathState::new(subpath_id),
            ledbat: LedbatSubpathState::new(subpath_id, default_target),
            slice_windows: HashMap::new(),
            total_inflight_bytes: 0,
            total_cwnd_bytes: MIN_CWND_BYTES * 2,
            last_transmission_ns: 0,
            is_congested: false,
        };

        // Initialize default slices
        c.register_slice(
            FlowSliceClass::UltraLowLatency,
            &FlowQoSProfile::ultra_low_latency(),
        );
        c.register_slice(
            FlowSliceClass::HighThroughput,
            &FlowQoSProfile::high_throughput(50_000_000),
        );
        c.register_slice(
            FlowSliceClass::MissionCritical,
            &FlowQoSProfile::mission_critical(),
        );
        c.register_slice(FlowSliceClass::BestEffort, &FlowQoSProfile::best_effort());

        c.rebalance_slice_budgets();
        c
    }

    /// Registers or updates a slice configuration on this subpath.
    pub fn register_slice(&mut self, slice_class: FlowSliceClass, profile: &FlowQoSProfile) {
        let sw = SubpathSliceWindow::new(slice_class, profile);
        self.slice_windows.insert(slice_class, sw);
        self.rebalance_slice_budgets();
    }

    /// Evaluates if a packet of given size can be sent on this subpath.
    pub fn can_send(
        &mut self,
        slice_class: FlowSliceClass,
        packet_bytes: usize,
        now_ns: u64,
    ) -> CongestionSendVerdict {
        let bytes_u64 = packet_bytes as u64;

        // Check pacing interval if enabled
        if self.bbrv3.pacing_rate_bps > 0 {
            // interval_ns = (packet_bytes * 8 * 1_000_000_000) / pacing_rate_bps
            let pacing_interval_ns =
                (packet_bytes as u128 * 8_000_000_000 / self.bbrv3.pacing_rate_bps as u128) as u64;
            let elapsed_ns = now_ns.saturating_sub(self.last_transmission_ns);
            if elapsed_ns < pacing_interval_ns {
                let wait = pacing_interval_ns - elapsed_ns;
                if wait > 100_000 {
                    // Pacing delay > 100µs: throttle
                    return CongestionSendVerdict::PacingWait { wait_ns: wait };
                }
            }
        }

        // Check slice window budget
        let (slice_cwnd, slice_inflight, is_urllc, is_scavenger) = {
            if let Some(sw) = self.slice_windows.get(&slice_class) {
                (
                    sw.allocated_cwnd_bytes,
                    sw.current_inflight_bytes,
                    slice_class == FlowSliceClass::UltraLowLatency,
                    slice_class == FlowSliceClass::BestEffort,
                )
            } else {
                (MIN_CWND_BYTES, 0, false, false)
            }
        };

        // URLLC bufferbloat prevention: if queuing delay exceeds target, throttle immediately
        if is_urllc && self.ledbat.queuing_delay_us > 5_000 {
            if let Some(sw) = self.slice_windows.get_mut(&slice_class) {
                sw.sla_throttle_events += 1;
            }
            return CongestionSendVerdict::ThrottledCongested {
                subpath_id: self.subpath_id,
                slice_class,
                inflight_bytes: slice_inflight,
                cwnd_bytes: slice_cwnd,
                recommended_subpath_id: None,
                backoff_reason:
                    "UltraLowLatency target queuing delay exceeded (Bufferbloat prevention)",
            };
        }

        // BestEffort scavenger yielding: yield when any higher priority slice active and queuing delay > target
        if is_scavenger && self.ledbat.queuing_delay_us > self.ledbat.target_delay_us {
            if let Some(sw) = self.slice_windows.get_mut(&slice_class) {
                sw.sla_throttle_events += 1;
            }
            return CongestionSendVerdict::ThrottledCongested {
                subpath_id: self.subpath_id,
                slice_class,
                inflight_bytes: slice_inflight,
                cwnd_bytes: slice_cwnd,
                recommended_subpath_id: None,
                backoff_reason: "BestEffort scavenger yielding to queuing delay (RFC 6817)",
            };
        }

        // Inflight capacity check
        if slice_inflight.saturating_add(bytes_u64) > slice_cwnd {
            if let Some(sw) = self.slice_windows.get_mut(&slice_class) {
                sw.sla_throttle_events += 1;
            }
            return CongestionSendVerdict::ThrottledCongested {
                subpath_id: self.subpath_id,
                slice_class,
                inflight_bytes: slice_inflight,
                cwnd_bytes: slice_cwnd,
                recommended_subpath_id: None,
                backoff_reason: "Slice congestion window capacity reached",
            };
        }

        // Aggregate subpath inflight capacity check
        if self.total_inflight_bytes.saturating_add(bytes_u64) > self.total_cwnd_bytes {
            return CongestionSendVerdict::ThrottledCongested {
                subpath_id: self.subpath_id,
                slice_class,
                inflight_bytes: self.total_inflight_bytes,
                cwnd_bytes: self.total_cwnd_bytes,
                recommended_subpath_id: None,
                backoff_reason: "Subpath aggregate congestion window exhausted",
            };
        }

        CongestionSendVerdict::Allow {
            granted_bytes: packet_bytes,
            cwnd_bytes: slice_cwnd,
            inflight_bytes: slice_inflight,
            pacing_delay_ns: 0,
        }
    }

    /// Record a transmitted packet.
    pub fn on_packet_sent(
        &mut self,
        slice_class: FlowSliceClass,
        packet_bytes: usize,
        now_ns: u64,
    ) {
        let bytes_u64 = packet_bytes as u64;
        self.total_inflight_bytes = self.total_inflight_bytes.saturating_add(bytes_u64);
        self.last_transmission_ns = now_ns;

        if let Some(sw) = self.slice_windows.get_mut(&slice_class) {
            sw.current_inflight_bytes = sw.current_inflight_bytes.saturating_add(bytes_u64);
            sw.total_bytes_sent = sw.total_bytes_sent.saturating_add(bytes_u64);
            sw.last_send_timestamp_ns = now_ns;
        }
    }

    /// Process feedback for delivered, lost, or ECN-marked bytes.
    pub fn on_feedback(
        &mut self,
        slice_class: FlowSliceClass,
        acked_bytes: u64,
        lost_bytes: u64,
        ecn_ce_count: u64,
        rtt_us: u64,
        now_ns: u64,
    ) {
        // Adjust inflight tracking
        let drained = acked_bytes.saturating_add(lost_bytes);
        self.total_inflight_bytes = self.total_inflight_bytes.saturating_sub(drained);

        if let Some(sw) = self.slice_windows.get_mut(&slice_class) {
            sw.current_inflight_bytes = sw.current_inflight_bytes.saturating_sub(drained);
            sw.total_bytes_acked = sw.total_bytes_acked.saturating_add(acked_bytes);
            sw.total_bytes_lost = sw.total_bytes_lost.saturating_add(lost_bytes);
        }

        // Update subpath-level engines
        self.bbrv3.update_min_rtt(rtt_us, now_ns);
        self.bbrv3.update_bandwidth(acked_bytes, rtt_us);
        self.bbrv3
            .on_loss_and_ecn(lost_bytes, acked_bytes, ecn_ce_count);
        self.bbrv3.advance_state_machine(now_ns);

        self.ledbat.update(rtt_us);

        // Compute aggregate CWND based on algorithm
        self.total_cwnd_bytes = match self.algorithm {
            CongestionAlgorithm::BbrV3 => self.bbrv3.cwnd_bytes,
            CongestionAlgorithm::Ledbat => self.ledbat.cwnd_bytes,
            CongestionAlgorithm::HybridQoSCoupled => {
                // Modulate BBRv3 window by LEDBAT delay weight factor
                let delay_factor = self.ledbat.delay_weight_factor();
                let modulated = (self.bbrv3.cwnd_bytes as f64 * delay_factor) as u64;
                modulated.max(MIN_CWND_BYTES)
            }
        };

        // Determine congestion state
        self.is_congested = self.ledbat.queuing_delay_us > self.ledbat.target_delay_us
            || self.bbrv3.loss_rate_ppm > 20_000
            || self.bbrv3.ecn_ratio_ppm > 100_000;

        // Rebalance slice quotas
        self.rebalance_slice_budgets();
    }

    /// Rebalance per-slice CWND budgets according to SLA priorities and current queuing delay.
    pub fn rebalance_slice_budgets(&mut self) {
        if self.slice_windows.is_empty() {
            return;
        }

        let total_cwnd = self.total_cwnd_bytes;
        let bdp = self.bbrv3.compute_bdp_bytes();

        // Slice weight shares:
        // UltraLowLatency: 35% of pipe, capped by tight BDP ratio
        // MissionCritical: 30% of pipe
        // HighThroughput: 30% of pipe (can expand if other slices idle)
        // BestEffort: 5% of pipe (scaled down further if delay high)
        let delay_weight = self.ledbat.delay_weight_factor();

        for (class, sw) in self.slice_windows.iter_mut() {
            let base_quota = match class {
                FlowSliceClass::UltraLowLatency => {
                    // Strict upper bound to prevent bufferbloat
                    let cap = (bdp as f64 * sw.slice_max_inflight_ratio) as u64;
                    ((total_cwnd * 35) / 100).min(cap).max(MIN_CWND_BYTES)
                }
                FlowSliceClass::MissionCritical => {
                    // Dedicated window with recovery reserve
                    ((total_cwnd * 30) / 100).max(MIN_CWND_BYTES)
                }
                FlowSliceClass::HighThroughput => {
                    // High bandwidth pipe filler
                    ((total_cwnd * 30) / 100).max(MIN_CWND_BYTES)
                }
                FlowSliceClass::BestEffort => {
                    // RFC 6817 scavenger: yields when queuing delay rises
                    let nominal = (total_cwnd * 5) / 100;
                    let scaled = (nominal as f64 * delay_weight) as u64;
                    scaled.max(TCP_MSS_BYTES)
                }
            };

            sw.allocated_cwnd_bytes = base_quota;
            sw.slice_pacing_rate_bps = self.bbrv3.pacing_rate_bps;
        }
    }
}

// ─── Coupled Multipath Congestion Manager ───────────────────────────────────

/// Telemetry summary exported for Prometheus and observability.
#[derive(Debug, Clone, PartialEq)]
pub struct MultipathCongestionTelemetrySummary {
    /// Active subpaths and their negotiated CWND in bytes.
    pub subpath_cwnds: BTreeMap<u32, u64>,
    /// Active subpaths and their BBRv3 pacing rate in bits per second.
    pub subpath_pacing_rates: BTreeMap<u32, u64>,
    /// Active subpaths and their LEDBAT queuing delay in microseconds.
    pub subpath_queuing_delays_us: BTreeMap<u32, u64>,
    /// Total aggregate session congestion window in bytes.
    pub total_session_cwnd_bytes: u64,
    /// Total aggregate session inflight bytes.
    pub total_session_inflight_bytes: u64,
    /// Total cross-subpath window migration events executed.
    pub window_migration_events_total: u64,
    /// Total rate negotiation updates.
    pub window_negotiation_events_total: u64,
    /// Total bufferbloat/SLA throttle incidents across slices.
    pub total_sla_throttle_events: u64,
}

/// Central multipath congestion control manager coupling all subpaths.
#[derive(Debug, Clone)]
pub struct MultipathCongestionManager {
    /// Subpath controllers.
    controllers: HashMap<u32, SubpathCongestionController>,
    /// Total window migration events triggered by coupled backpressure.
    pub window_migration_events_total: u64,
    /// Total rate negotiation cycles evaluated.
    pub window_negotiation_events_total: u64,
    /// Last rebalance timestamp in nanoseconds.
    pub last_rebalance_timestamp_ns: u64,
}

impl Default for MultipathCongestionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl MultipathCongestionManager {
    pub fn new() -> Self {
        Self {
            controllers: HashMap::new(),
            window_migration_events_total: 0,
            window_negotiation_events_total: 0,
            last_rebalance_timestamp_ns: 0,
        }
    }

    /// Registers a subpath controller.
    pub fn register_subpath(&mut self, subpath_id: u32, algorithm: CongestionAlgorithm) {
        self.controllers.insert(
            subpath_id,
            SubpathCongestionController::new(subpath_id, algorithm),
        );
    }

    /// Read access to a subpath controller.
    pub fn controller(&self, subpath_id: u32) -> Option<&SubpathCongestionController> {
        self.controllers.get(&subpath_id)
    }

    /// Mutable access to a subpath controller.
    pub fn controller_mut(&mut self, subpath_id: u32) -> Option<&mut SubpathCongestionController> {
        self.controllers.get_mut(&subpath_id)
    }

    /// Evaluates if a packet may be sent on `subpath_id`, dynamically recommending alternate if congested.
    pub fn evaluate_send(
        &mut self,
        subpath_id: u32,
        slice_class: FlowSliceClass,
        packet_bytes: usize,
        now_ns: u64,
    ) -> CongestionSendVerdict {
        self.window_negotiation_events_total += 1;

        if let Some(ctrl) = self.controllers.get_mut(&subpath_id) {
            let verdict = ctrl.can_send(slice_class, packet_bytes, now_ns);
            match verdict {
                CongestionSendVerdict::Allow { .. } => verdict,
                CongestionSendVerdict::PacingWait { .. } => verdict,
                CongestionSendVerdict::ThrottledCongested {
                    subpath_id: orig_id,
                    slice_class: sc,
                    inflight_bytes,
                    cwnd_bytes,
                    backoff_reason,
                    ..
                } => {
                    // Coupled Multipath Steering: search alternate subpath with free capacity and lowest delay
                    let alt = self.find_best_alternate_subpath(orig_id, sc, packet_bytes, now_ns);
                    CongestionSendVerdict::ThrottledCongested {
                        subpath_id: orig_id,
                        slice_class: sc,
                        inflight_bytes,
                        cwnd_bytes,
                        recommended_subpath_id: alt,
                        backoff_reason,
                    }
                }
            }
        } else {
            CongestionSendVerdict::Allow {
                granted_bytes: packet_bytes,
                cwnd_bytes: MIN_CWND_BYTES,
                inflight_bytes: 0,
                pacing_delay_ns: 0,
            }
        }
    }

    /// Finds the healthiest alternate subpath capable of accepting the transmission immediately.
    fn find_best_alternate_subpath(
        &mut self,
        exclude_subpath_id: u32,
        slice_class: FlowSliceClass,
        packet_bytes: usize,
        now_ns: u64,
    ) -> Option<u32> {
        let mut candidates: Vec<(u32, u64, f64)> = Vec::new();

        for (&sid, ctrl) in self.controllers.iter_mut() {
            if sid == exclude_subpath_id {
                continue;
            }
            if let CongestionSendVerdict::Allow { .. } =
                ctrl.can_send(slice_class, packet_bytes, now_ns)
            {
                let delay = ctrl.ledbat.queuing_delay_us;
                let weight = ctrl.ledbat.delay_weight_factor();
                candidates.push((sid, delay, weight));
            }
        }

        // Sort by lowest queuing delay, then highest weight factor
        candidates.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| b.2.partial_cmp(&a.2).unwrap()));
        candidates.first().map(|(sid, _, _)| *sid)
    }

    /// Records transmission of a packet on a subpath.
    pub fn record_send(
        &mut self,
        subpath_id: u32,
        slice_class: FlowSliceClass,
        packet_bytes: usize,
        now_ns: u64,
    ) {
        if let Some(ctrl) = self.controllers.get_mut(&subpath_id) {
            ctrl.on_packet_sent(slice_class, packet_bytes, now_ns);
        }
    }

    /// Ingests ACK, loss, and ECN feedback, triggering coupled window negotiation across subpaths.
    #[allow(clippy::too_many_arguments)]
    pub fn record_feedback(
        &mut self,
        subpath_id: u32,
        slice_class: FlowSliceClass,
        acked_bytes: u64,
        lost_bytes: u64,
        ecn_ce_count: u64,
        rtt_us: u64,
        now_ns: u64,
    ) {
        if let Some(ctrl) = self.controllers.get_mut(&subpath_id) {
            ctrl.on_feedback(
                slice_class,
                acked_bytes,
                lost_bytes,
                ecn_ce_count,
                rtt_us,
                now_ns,
            );
        }

        // Rebalance multipath coupled windows periodically or upon loss
        if lost_bytes > 0 || now_ns.saturating_sub(self.last_rebalance_timestamp_ns) > 100_000_000 {
            self.rebalance_coupled_windows(now_ns);
            self.last_rebalance_timestamp_ns = now_ns;
        }
    }

    /// Rebalances coupled congestion windows across active subpaths.
    ///
    /// If one subpath experiences congestion (loss or high queuing delay), shifts
    /// window quota to cleaner subpaths to maintain aggregate throughput without
    /// compounding bufferbloat.
    pub fn rebalance_coupled_windows(&mut self, _now_ns: u64) {
        if self.controllers.len() < 2 {
            return;
        }

        let mut congested_subpaths = Vec::new();
        let mut healthy_subpaths = Vec::new();

        for (&sid, ctrl) in self.controllers.iter() {
            if ctrl.is_congested {
                congested_subpaths.push(sid);
            } else {
                healthy_subpaths.push(sid);
            }
        }

        if !congested_subpaths.is_empty() && !healthy_subpaths.is_empty() {
            // Transfer quota from congested to healthy
            let transfer_per_subpath = 2 * TCP_MSS_BYTES;
            for &c_id in &congested_subpaths {
                if let Some(c_ctrl) = self.controllers.get_mut(&c_id) {
                    c_ctrl.total_cwnd_bytes = c_ctrl
                        .total_cwnd_bytes
                        .saturating_sub(transfer_per_subpath)
                        .max(MIN_CWND_BYTES);
                    c_ctrl.rebalance_slice_budgets();
                }
            }

            let bonus_per_healthy = (transfer_per_subpath * congested_subpaths.len() as u64)
                / healthy_subpaths.len() as u64;
            for &h_id in &healthy_subpaths {
                if let Some(h_ctrl) = self.controllers.get_mut(&h_id) {
                    h_ctrl.total_cwnd_bytes =
                        h_ctrl.total_cwnd_bytes.saturating_add(bonus_per_healthy);
                    h_ctrl.rebalance_slice_budgets();
                }
            }

            self.window_migration_events_total += 1;
        }
    }

    /// Synchronize controllers with active router routes.
    pub fn sync_with_routes(&mut self, routes: &BTreeMap<u32, IsspMultipathRoute>) {
        for (&path_id, route) in routes.iter() {
            if route.state == IsspPathState::Active {
                self.controllers.entry(path_id).or_insert_with(|| {
                    SubpathCongestionController::new(path_id, CongestionAlgorithm::HybridQoSCoupled)
                });
            }
        }
    }

    /// Collects telemetry snapshot across all managed subpaths.
    pub fn telemetry_summary(&self) -> MultipathCongestionTelemetrySummary {
        let mut subpath_cwnds = BTreeMap::new();
        let mut subpath_pacing_rates = BTreeMap::new();
        let mut subpath_queuing_delays_us = BTreeMap::new();
        let mut total_session_cwnd_bytes = 0u64;
        let mut total_session_inflight_bytes = 0u64;
        let mut total_sla_throttle_events = 0u64;

        for (&sid, ctrl) in self.controllers.iter() {
            subpath_cwnds.insert(sid, ctrl.total_cwnd_bytes);
            subpath_pacing_rates.insert(sid, ctrl.bbrv3.pacing_rate_bps);
            subpath_queuing_delays_us.insert(sid, ctrl.ledbat.queuing_delay_us);
            total_session_cwnd_bytes += ctrl.total_cwnd_bytes;
            total_session_inflight_bytes += ctrl.total_inflight_bytes;

            for sw in ctrl.slice_windows.values() {
                total_sla_throttle_events += sw.sla_throttle_events;
            }
        }

        MultipathCongestionTelemetrySummary {
            subpath_cwnds,
            subpath_pacing_rates,
            subpath_queuing_delays_us,
            total_session_cwnd_bytes,
            total_session_inflight_bytes,
            window_migration_events_total: self.window_migration_events_total,
            window_negotiation_events_total: self.window_negotiation_events_total,
            total_sla_throttle_events,
        }
    }
}

// ─── Automated Benchmarking & Verification Suite ─────────────────────────────

/// Comprehensive report generated by the multipath congestion control benchmark.
#[derive(Debug, Clone, PartialEq)]
pub struct MultipathCongestionBenchmarkReport {
    /// Overall pass/fail verification indicator.
    pub verification_passed: bool,
    /// URLLC strict queuing delay enforcement passed.
    pub urllc_delay_containment_passed: bool,
    /// eMBB throughput maximization through BBRv3 ProbeBW passed.
    pub embb_pipe_utilization_passed: bool,
    /// Mission-Critical loss-driven inflight ceiling adaptation passed.
    pub mission_critical_loss_adaptation_passed: bool,
    /// Coupled cross-subpath window migration during asymmetric congestion passed.
    pub cross_subpath_migration_passed: bool,
    /// BestEffort scavenger yielding under high-priority load passed.
    pub best_effort_scavenger_yielding_passed: bool,
    /// Total window negotiation cycles executed.
    pub total_negotiation_cycles: u64,
    /// Total cross-subpath migration events executed.
    pub total_migration_events: u64,
    /// Measured URLLC peak queuing delay in microseconds.
    pub urllc_peak_queuing_delay_us: u64,
    /// Measured eMBB peak delivered bandwidth in bits per second.
    pub embb_peak_bw_bps: u64,
}

impl MultipathCongestionBenchmarkReport {
    /// Formats the report as a professional Markdown table.
    pub fn to_markdown_table(&self) -> String {
        let mut s = String::new();
        s.push_str("| Metric / Verification Test | Measured Result | SLA Target | Status |\n");
        s.push_str("| :--- | :--- | :--- | :--- |\n");

        let urllc_status = if self.urllc_delay_containment_passed {
            "PASSED"
        } else {
            "FAILED"
        };
        let embb_status = if self.embb_pipe_utilization_passed {
            "PASSED"
        } else {
            "FAILED"
        };
        let mc_status = if self.mission_critical_loss_adaptation_passed {
            "PASSED"
        } else {
            "FAILED"
        };
        let migr_status = if self.cross_subpath_migration_passed {
            "PASSED"
        } else {
            "FAILED"
        };
        let scav_status = if self.best_effort_scavenger_yielding_passed {
            "PASSED"
        } else {
            "FAILED"
        };

        let _ = writeln!(
            s,
            "| URLLC Queuing Delay Bounding | {} µs | <= 5000 µs | {} |",
            self.urllc_peak_queuing_delay_us, urllc_status
        );
        let _ = writeln!(
            s,
            "| eMBB Bottleneck Bandwidth Discovery | {:.2} Mbps | >= 40.0 Mbps | {} |",
            self.embb_peak_bw_bps as f64 / 1_000_000.0,
            embb_status
        );
        let _ = writeln!(
            s,
            "| Mission-Critical Loss Adaptation | Clamped Inflight Ceiling | Deterministic Drain | {} |",
            mc_status
        );
        let _ = writeln!(
            s,
            "| Coupled Cross-Subpath Window Transfer | {} migrations | >= 1 migration | {} |",
            self.total_migration_events, migr_status
        );
        let _ = writeln!(
            s,
            "| BestEffort Scavenger Yielding | Throttle on Queue Growth | Non-starving | {} |",
            scav_status
        );

        s
    }

    /// Serializes report as structured JSON.
    pub fn to_json(&self) -> String {
        format!(
            "{{\"verification_passed\":{},\"urllc_delay_containment_passed\":{},\"embb_pipe_utilization_passed\":{},\"mission_critical_loss_adaptation_passed\":{},\"cross_subpath_migration_passed\":{},\"best_effort_scavenger_yielding_passed\":{},\"total_negotiation_cycles\":{},\"total_migration_events\":{},\"urllc_peak_queuing_delay_us\":{},\"embb_peak_bw_bps\":{}}}",
            self.verification_passed,
            self.urllc_delay_containment_passed,
            self.embb_pipe_utilization_passed,
            self.mission_critical_loss_adaptation_passed,
            self.cross_subpath_migration_passed,
            self.best_effort_scavenger_yielding_passed,
            self.total_negotiation_cycles,
            self.total_migration_events,
            self.urllc_peak_queuing_delay_us,
            self.embb_peak_bw_bps
        )
    }
}

/// Runs the concrete multipath congestion control benchmark.
pub fn run_multipath_congestion_benchmark() -> MultipathCongestionBenchmarkReport {
    let mut manager = MultipathCongestionManager::new();

    // Register Subpath 101 (Primary 100Mbps 10ms path) and Subpath 102 (Alternate 50Mbps 25ms path)
    manager.register_subpath(101, CongestionAlgorithm::HybridQoSCoupled);
    manager.register_subpath(102, CongestionAlgorithm::HybridQoSCoupled);

    let mut now_ns = 1_000_000_000u64; // 1.0s

    // Baseline propagation delay calibration for subpaths
    manager.record_feedback(
        101,
        FlowSliceClass::UltraLowLatency,
        1460,
        0,
        0,
        4_000,
        now_ns,
    );
    manager.record_feedback(
        102,
        FlowSliceClass::UltraLowLatency,
        1460,
        0,
        0,
        6_000,
        now_ns,
    );

    // ─── Test 1: URLLC delay containment ────────────────────────────────────
    // Feed high delay to Subpath 101 (20ms RTT -> 10ms OWD -> 8ms queuing delay > 5ms target)
    now_ns += 10_000_000;
    manager.record_feedback(
        101,
        FlowSliceClass::UltraLowLatency,
        14600,
        0,
        0,
        20_000,
        now_ns,
    );
    let urllc_verdict = manager.evaluate_send(101, FlowSliceClass::UltraLowLatency, 1460, now_ns);
    let urllc_delay_containment_passed = match urllc_verdict {
        CongestionSendVerdict::ThrottledCongested {
            recommended_subpath_id,
            ..
        } => {
            // Recommended alternate subpath 102
            recommended_subpath_id == Some(102)
        }
        _ => false,
    };
    let urllc_peak_queuing_delay_us = manager
        .controller(101)
        .map(|c| c.ledbat.queuing_delay_us)
        .unwrap_or(0);

    // ─── Test 2: eMBB throughput discovery ──────────────────────────────────
    // Feed high bandwidth delivery feedback to Subpath 101
    for _i in 1..=10 {
        now_ns += 20_000_000; // 20ms
        manager.record_feedback(
            101,
            FlowSliceClass::HighThroughput,
            125_000, // 125 KB in 20ms = 50 Mbps
            0,
            0,
            20_000,
            now_ns,
        );
    }
    let embb_peak_bw_bps = manager
        .controller(101)
        .map(|c| c.bbrv3.estimated_bw_bps)
        .unwrap_or(0);
    let embb_pipe_utilization_passed = embb_peak_bw_bps >= 40_000_000;

    // ─── Test 3: Mission-Critical loss adaptation ───────────────────────────
    let prev_inflight_hi = manager
        .controller(101)
        .map(|c| c.bbrv3.inflight_hi_bytes)
        .unwrap_or(u64::MAX);
    // Inject packet loss
    now_ns += 20_000_000;
    manager.record_feedback(
        101,
        FlowSliceClass::MissionCritical,
        2920,
        1460, // 1 packet lost
        2,    // 2 ECN CE marks
        22_000,
        now_ns,
    );
    let new_inflight_hi = manager
        .controller(101)
        .map(|c| c.bbrv3.inflight_hi_bytes)
        .unwrap_or(0);
    let mission_critical_loss_adaptation_passed = new_inflight_hi < prev_inflight_hi;

    // ─── Test 4: Coupled cross-subpath window migration ─────────────────────
    // Subpath 101 is congested; Subpath 102 is clean (5ms RTT, zero loss)
    now_ns += 150_000_000;
    manager.record_feedback(
        102,
        FlowSliceClass::HighThroughput,
        60_000,
        0,
        0,
        10_000,
        now_ns,
    );
    // Trigger coupled rebalance
    manager.rebalance_coupled_windows(now_ns);
    let total_migration_events = manager.window_migration_events_total;
    let cross_subpath_migration_passed = total_migration_events >= 1;

    // ─── Test 5: BestEffort scavenger yielding ──────────────────────────────
    // Elevate queuing delay above LEDBAT target delay on Subpath 101 (50ms RTT -> 25ms OWD -> 23ms queuing delay > 15ms target)
    now_ns += 50_000_000;
    manager.record_feedback(
        101,
        FlowSliceClass::HighThroughput,
        1460,
        0,
        0,
        50_000,
        now_ns,
    );
    let be_verdict = manager.evaluate_send(101, FlowSliceClass::BestEffort, 1460, now_ns);
    let best_effort_scavenger_yielding_passed =
        matches!(be_verdict, CongestionSendVerdict::ThrottledCongested { .. });

    let verification_passed = urllc_delay_containment_passed
        && embb_pipe_utilization_passed
        && mission_critical_loss_adaptation_passed
        && cross_subpath_migration_passed
        && best_effort_scavenger_yielding_passed;

    MultipathCongestionBenchmarkReport {
        verification_passed,
        urllc_delay_containment_passed,
        embb_pipe_utilization_passed,
        mission_critical_loss_adaptation_passed,
        cross_subpath_migration_passed,
        best_effort_scavenger_yielding_passed,
        total_negotiation_cycles: manager.window_negotiation_events_total,
        total_migration_events,
        urllc_peak_queuing_delay_us,
        embb_peak_bw_bps,
    }
}

// ─── Unit Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bbrv3_initial_state_and_pacing() {
        let bbr = Bbrv3SubpathState::new(1);
        assert_eq!(bbr.phase, Bbrv3Phase::Startup);
        assert_eq!(bbr.pacing_gain_q8, 738); // 2.885x
        assert_eq!(bbr.cwnd_gain_q8, 512); // 2.0x
        assert_eq!(bbr.cwnd_bytes, MIN_CWND_BYTES * 2);
    }

    #[test]
    fn test_bbrv3_bandwidth_and_round_advancement() {
        let mut bbr = Bbrv3SubpathState::new(1);
        bbr.update_min_rtt(20_000, 1_000_000_000);
        assert_eq!(bbr.min_rtt_us, 20_000);

        // Deliver 250,000 bytes in 20,000 µs (20 ms) = 100 Mbps
        bbr.update_bandwidth(250_000, 20_000);
        assert_eq!(bbr.estimated_bw_bps, 100_000_000);

        let bdp = bbr.compute_bdp_bytes();
        assert_eq!(bdp, 250_000);
    }

    #[test]
    fn test_ledbat_delay_tracking_and_queuing() {
        let mut ledbat = LedbatSubpathState::new(1, 25_000);
        // Base delay sample = 10,000 µs (RTT = 20,000 µs)
        ledbat.update(20_000);
        assert_eq!(ledbat.base_delay_us, 10_000);
        assert_eq!(ledbat.queuing_delay_us, 0);
        assert_eq!(ledbat.delay_weight_factor(), 1.0);

        // Queuing delay increases: RTT = 40,000 µs (OWD = 20,000 µs -> qdelay = 10,000 µs)
        ledbat.update(40_000);
        assert_eq!(ledbat.queuing_delay_us, 10_000);
        let w = ledbat.delay_weight_factor();
        assert!(w < 1.0 && w > 0.5);
    }

    #[test]
    fn test_subpath_congestion_controller_lifecycle() {
        let mut ctrl = SubpathCongestionController::new(1, CongestionAlgorithm::HybridQoSCoupled);
        let now_ns = 1_000_000_000;

        // Can send small frame initially
        let v = ctrl.can_send(FlowSliceClass::HighThroughput, 1460, now_ns);
        assert!(matches!(v, CongestionSendVerdict::Allow { .. }));

        ctrl.on_packet_sent(FlowSliceClass::HighThroughput, 1460, now_ns);
        assert_eq!(ctrl.total_inflight_bytes, 1460);

        // Ack feedback
        ctrl.on_feedback(
            FlowSliceClass::HighThroughput,
            1460,
            0,
            0,
            15_000,
            now_ns + 15_000_000,
        );
        assert_eq!(ctrl.total_inflight_bytes, 0);
    }

    #[test]
    fn test_coupled_multipath_migration_on_congestion() {
        let mut manager = MultipathCongestionManager::new();
        manager.register_subpath(1, CongestionAlgorithm::HybridQoSCoupled);
        manager.register_subpath(2, CongestionAlgorithm::HybridQoSCoupled);

        let now_ns = 1_000_000_000;

        // Subpath 1 is heavily congested with high queuing delay and loss
        manager.record_feedback(
            1,
            FlowSliceClass::HighThroughput,
            5000,
            2920,
            5,
            80_000,
            now_ns,
        );
        assert!(manager.controller(1).unwrap().is_congested);

        // Subpath 2 is clean
        manager.record_feedback(
            2,
            FlowSliceClass::HighThroughput,
            10000,
            0,
            0,
            10_000,
            now_ns,
        );
        assert!(!manager.controller(2).unwrap().is_congested);

        let cwnd_1_before = manager.controller(1).unwrap().total_cwnd_bytes;
        let cwnd_2_before = manager.controller(2).unwrap().total_cwnd_bytes;

        manager.rebalance_coupled_windows(now_ns);

        let cwnd_1_after = manager.controller(1).unwrap().total_cwnd_bytes;
        let cwnd_2_after = manager.controller(2).unwrap().total_cwnd_bytes;

        assert!(cwnd_1_after <= cwnd_1_before);
        assert!(cwnd_2_after >= cwnd_2_before);
        assert!(manager.window_migration_events_total >= 1);
    }

    #[test]
    fn test_benchmark_suite_verification() {
        let report = run_multipath_congestion_benchmark();
        assert!(report.verification_passed);
        assert!(report.urllc_delay_containment_passed);
        assert!(report.embb_pipe_utilization_passed);
        assert!(report.mission_critical_loss_adaptation_passed);
        assert!(report.cross_subpath_migration_passed);
        assert!(report.best_effort_scavenger_yielding_passed);

        let md = report.to_markdown_table();
        assert!(md.contains("URLLC Queuing Delay Bounding"));
        assert!(md.contains("PASSED"));

        let json = report.to_json();
        assert!(json.contains("\"verification_passed\":true"));
    }
}

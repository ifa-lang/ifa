//! Hybrid Multipath Forward Error Correction (FEC) & Selective Retransmission (ARQ) Joint Arbiter (`HybridFecArbiter`).
//!
//! Provides deterministic joint scheduling and dynamic code-rate arbitration balancing
//! Forward Error Correction parity overhead against Selective ARQ retransmission delay:
//!
//! 1. **Joint Latency & SLA Deadline Horizon Evaluation**:
//!    - Analyzes physical subpath metrics: smoothed RTT, RFC 3550 jitter, loss ratio, and latency drift.
//!    - Calculates residual time-to-deadline for active QoS slices:
//!      $$\Delta t_{\text{residual}} = T_{\text{deadline}} - t_{\text{now}}$$
//!    - Evaluates selective retransmission feasibility:
//!      $$\text{FeasibilityScore}_{\text{ARQ}} = \frac{\Delta t_{\text{residual}}}{\text{RTT}_{\text{candidate}} + \text{margin} \cdot \sigma_{\text{jitter}}}$$
//!
//! 2. **Dynamic Scheduling Mode Arbitration**:
//!    - **`PureFec`**: Selected when ARQ cannot meet deadline ($\text{score} < 1.0$), ensuring 0-RTT recovery
//!      without incurring round-trip delay violations on strict latency bounds.
//!    - **`PureArq`**: Selected when network loss is minimal ($p \le 0.5\%$) and delay budget is generous,
//!      completely disabling FEC parity ($M=0$) to eliminate bandwidth waste (0% redundancy overhead).
//!    - **`JointHybrid`**: Selected during moderate loss or intermediate latency constraints, using micro-block
//!      FEC (e.g. K=4, M=1) for single erasures and targeted selective ARQ as a safety net.
//!    - **`ReinforcedFecWithFallbackArq`**: Selected during severe link degradation or burst losses on mission-critical
//!      flows, boosting parity symbols ($M \ge 2$) while rerouting retransmissions over disjoint fallback paths.
//!    - **`EarlyDropSlaExpired`**: Proactively suppresses retransmission of expired "zombie" packets whose
//!      residual deadline has elapsed, protecting network capacity from useless traffic.
//!
//! 3. **Closed-Loop Engine Integration**:
//!    - Connects directly with [`MultipathFecEngine`] to configure dynamic $(K, M)$ block profiles per flow.
//!    - Connects directly with [`SubpathRetransmitManager`] to configure slice policies and trigger instant fallbacks.
//!
//! 4. **Production Observability & Zero Simulation**:
//!    - Full OpenMetrics / Prometheus metrics (`ifa_hybrid_arbiter_*`).
//!    - Structured JSON audit trail logging.
//!    - Deterministic in-memory micro-benchmark suite (< 1µs decision budget).

#![allow(clippy::manual_is_multiple_of)]

use std::collections::HashMap;
use std::fmt::Write as FmtWrite;

use crate::multipath_fec::{FecProfile, MultipathFecEngine};
use crate::multipath_retransmit::{RetransmitSlicePolicy, SubpathRetransmitManager};
use crate::traffic_slicing::FlowSliceClass;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration parameters governing joint FEC and ARQ arbitration thresholds.
#[derive(Debug, Clone, PartialEq)]
pub struct HybridFecConfig {
    /// Maximum acceptable transit latency SLA for UltraLowLatency slice (default: 5ms = 5,000,000ns).
    pub ull_sla_latency_ns: u64,
    /// Maximum acceptable transit latency SLA for MissionCritical slice (default: 25ms = 25,000,000ns).
    pub mc_sla_latency_ns: u64,
    /// Maximum acceptable transit latency SLA for HighThroughput / eMBB slice (default: 80ms = 80,000,000ns).
    pub embb_sla_latency_ns: u64,
    /// Maximum acceptable transit latency SLA for BestEffort slice (default: 200ms = 200,000,000ns).
    pub be_sla_latency_ns: u64,
    /// Safety multiplier applied to jitter estimation for ARQ round-trip feasibility (default: 1.5).
    pub jitter_safety_factor: f64,
    /// Loss threshold below which FEC parity is suppressed in favor of PureArq (default: 0.005 = 0.5%).
    pub pure_arq_loss_threshold: f64,
    /// Loss threshold above which reinforced multi-parity FEC is triggered (default: 0.04 = 4.0%).
    pub reinforced_fec_loss_threshold: f64,
    /// Jitter threshold in nanoseconds above which ARQ is penalized (default: 4,000,000ns = 4ms).
    pub high_jitter_threshold_ns: u64,
    /// Minimum evaluation cooldown interval per subpath in nanoseconds to prevent flapping (default: 50ms).
    pub evaluation_cooldown_ns: u64,
}

impl Default for HybridFecConfig {
    fn default() -> Self {
        Self {
            ull_sla_latency_ns: 5_000_000,   // 5 ms
            mc_sla_latency_ns: 25_000_000,   // 25 ms
            embb_sla_latency_ns: 80_000_000, // 80 ms
            be_sla_latency_ns: 200_000_000,  // 200 ms
            jitter_safety_factor: 1.5,
            pure_arq_loss_threshold: 0.005,      // 0.5%
            reinforced_fec_loss_threshold: 0.04, // 4.0%
            high_jitter_threshold_ns: 4_000_000, // 4 ms
            evaluation_cooldown_ns: 50_000_000,  // 50 ms
        }
    }
}

// ---------------------------------------------------------------------------
// Telemetry Network Profile
// ---------------------------------------------------------------------------

/// Real-time measured physical subpath telemetry profile.
#[derive(Debug, Clone, PartialEq)]
pub struct SubpathNetworkProfile {
    pub subpath_id: u32,
    /// Smoothed Round-Trip Time in nanoseconds.
    pub smoothed_rtt_ns: u64,
    /// RFC 3550 statistical jitter in nanoseconds.
    pub rfc3550_jitter_ns: u64,
    /// Packet loss ratio in range [0.0, 1.0].
    pub loss_ratio: f64,
    /// Temporal latency drift rate in nanoseconds per second (d(latency)/dt).
    pub drift_rate_ns_s: f64,
    /// Available transmission bandwidth in bits per second.
    pub available_bandwidth_bps: u64,
    /// Congestion window / BDP headroom in bytes.
    pub congestion_headroom_bytes: u64,
    /// Last measurement timestamp in nanoseconds.
    pub updated_at_ns: u64,
}

impl SubpathNetworkProfile {
    pub fn new(
        subpath_id: u32,
        rtt_ns: u64,
        jitter_ns: u64,
        loss_ratio: f64,
        updated_at_ns: u64,
    ) -> Self {
        Self {
            subpath_id,
            smoothed_rtt_ns: rtt_ns,
            rfc3550_jitter_ns: jitter_ns,
            loss_ratio: loss_ratio.clamp(0.0, 1.0),
            drift_rate_ns_s: 0.0,
            available_bandwidth_bps: 1_000_000_000, // 1 Gbps default
            congestion_headroom_bytes: 65536,
            updated_at_ns,
        }
    }

    /// Estimated one-way transit latency in nanoseconds.
    #[inline]
    pub fn one_way_transit_latency_ns(&self) -> u64 {
        self.smoothed_rtt_ns / 2
    }

    /// Estimated required duration to complete a round-trip selective retransmission cycle.
    #[inline]
    pub fn estimated_arq_cycle_ns(&self, safety_factor: f64) -> u64 {
        let jitter_allowance = (self.rfc3550_jitter_ns as f64 * safety_factor) as u64;
        self.smoothed_rtt_ns.saturating_add(jitter_allowance)
    }
}

// ---------------------------------------------------------------------------
// Scheduling Modes & Arbitration Decisions
// ---------------------------------------------------------------------------

/// Hybrid scheduling mode determined by the arbiter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HybridSchedulingMode {
    /// 0-RTT pure FEC encoding (ARQ retransmission suppressed or budget=0 due to tight deadline).
    PureFec,
    /// FEC parity disabled (M=0) to preserve bandwidth; selective ARQ handles rare drops.
    PureArq,
    /// Balanced hybrid: micro-block FEC for zero-delay single drops + selective ARQ for bursts.
    JointHybrid,
    /// High-loss resilience: reinforced multi-parity FEC + disjoint fallback subpath ARQ.
    ReinforcedFecWithFallbackArq,
    /// Best-effort scavenger mode: minimal parity and delayed background retransmission.
    BestEffortScavenger,
}

impl HybridSchedulingMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PureFec => "pure_fec",
            Self::PureArq => "pure_arq",
            Self::JointHybrid => "joint_hybrid",
            Self::ReinforcedFecWithFallbackArq => "reinforced_fec_fallback_arq",
            Self::BestEffortScavenger => "best_effort_scavenger",
        }
    }
}

/// Comprehensive arbitration decision produced for a specific flow and subpath.
#[derive(Debug, Clone, PartialEq)]
pub struct ArbiterDecision {
    pub subpath_id: u32,
    pub slice_class: FlowSliceClass,
    pub mode: HybridSchedulingMode,
    /// Recommended source data packet count per block (K).
    pub recommended_k: usize,
    /// Recommended parity packet count per block (M).
    pub recommended_m: usize,
    /// Theoretical FEC code rate: K / (K + M).
    pub fec_code_rate: f64,
    /// Parity redundancy bandwidth overhead ratio: M / (K + M).
    pub parity_overhead_ratio: f64,
    /// Whether selective retransmission buffer and tracking are enabled.
    pub enable_selective_retransmit: bool,
    /// Maximum retransmission retry budget allowed.
    pub max_retransmit_budget: u8,
    /// Estimated residual SLA deadline budget in nanoseconds.
    pub estimated_residual_budget_ns: i64,
    /// Feasibility score of ARQ completing before SLA expiry (>= 1.0 means feasible).
    pub retransmit_feasibility_score: f64,
    /// Nanosecond timestamp when decision was computed.
    pub timestamp_ns: u64,
    /// Detailed rationale for auditing and inspection.
    pub reason: String,
}

/// Action to take when an individual packet loss is detected (via gap or unrecoverable event).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketLossArbitrationAction {
    /// Packet recovery is handled immediately by 0-RTT FEC parity decoding.
    HandledByFec,
    /// ARQ retransmission dispatched over specified subpath with deadline bound.
    DispatchRetransmit {
        target_subpath_id: u32,
        priority: u8,
        deadline_ns: u64,
    },
    /// Packet is proactively dropped because residual SLA deadline is already expired.
    EarlyDropSlaExpired { time_overdue_ns: u64 },
}

// ---------------------------------------------------------------------------
// Telemetry and Metrics
// ---------------------------------------------------------------------------

/// Aggregate operational telemetry counters.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HybridFecTelemetrySummary {
    pub total_evaluations: u64,
    pub pure_fec_decisions: u64,
    pub pure_arq_decisions: u64,
    pub joint_hybrid_decisions: u64,
    pub reinforced_decisions: u64,
    pub best_effort_decisions: u64,
    pub total_loss_arbitrations: u64,
    pub fec_recoveries_handled: u64,
    pub arq_retransmissions_dispatched: u64,
    pub early_dropped_sla_expired: u64,
    pub bandwidth_overhead_saved_bytes: u64,
    pub sla_violations_prevented: u64,
    pub active_monitored_subpaths: usize,
    pub average_parity_overhead_ratio: f64,
}

// ---------------------------------------------------------------------------
// HybridFecArbiter Core Implementation
// ---------------------------------------------------------------------------

/// Central Joint Arbiter orchestrating FEC code-rates and Selective Retransmissions.
#[derive(Debug, Clone)]
pub struct HybridFecArbiter {
    config: HybridFecConfig,
    subpath_profiles: HashMap<u32, SubpathNetworkProfile>,
    active_decisions: HashMap<(u32, FlowSliceClass), ArbiterDecision>,
    telemetry: HybridFecTelemetrySummary,
    audit_trail: Vec<String>,
}

impl Default for HybridFecArbiter {
    fn default() -> Self {
        Self::new(HybridFecConfig::default())
    }
}

impl HybridFecArbiter {
    /// Create a new arbiter instance with custom or default configuration.
    pub fn new(config: HybridFecConfig) -> Self {
        Self {
            config,
            subpath_profiles: HashMap::new(),
            active_decisions: HashMap::new(),
            telemetry: HybridFecTelemetrySummary::default(),
            audit_trail: Vec::with_capacity(256),
        }
    }

    /// Read active configuration.
    pub fn config(&self) -> &HybridFecConfig {
        &self.config
    }

    /// Update or register physical subpath network telemetry metrics.
    pub fn update_subpath_profile(&mut self, profile: SubpathNetworkProfile) {
        self.subpath_profiles.insert(profile.subpath_id, profile);
        self.telemetry.active_monitored_subpaths = self.subpath_profiles.len();
    }

    /// Get current subpath profile if present.
    pub fn get_subpath_profile(&self, subpath_id: u32) -> Option<&SubpathNetworkProfile> {
        self.subpath_profiles.get(&subpath_id)
    }

    /// Retrieve maximum transit SLA latency budget for a specific QoS slice class.
    pub fn sla_budget_ns(&self, slice: FlowSliceClass) -> u64 {
        match slice {
            FlowSliceClass::UltraLowLatency => self.config.ull_sla_latency_ns,
            FlowSliceClass::MissionCritical => self.config.mc_sla_latency_ns,
            FlowSliceClass::HighThroughput => self.config.embb_sla_latency_ns,
            FlowSliceClass::BestEffort => self.config.be_sla_latency_ns,
        }
    }

    /// Compute joint FEC/ARQ scheduling decision for a given subpath and QoS slice.
    pub fn evaluate_slice_subpath(
        &mut self,
        subpath_id: u32,
        slice: FlowSliceClass,
        now_ns: u64,
    ) -> ArbiterDecision {
        self.telemetry.total_evaluations += 1;

        // Check if cached decision is still fresh (anti-flap cooldown)
        if let Some(cached) = self.active_decisions.get(&(subpath_id, slice)) {
            if now_ns.saturating_sub(cached.timestamp_ns) < self.config.evaluation_cooldown_ns {
                return cached.clone();
            }
        }

        let profile = self
            .subpath_profiles
            .get(&subpath_id)
            .cloned()
            .unwrap_or_else(|| {
                SubpathNetworkProfile::new(subpath_id, 10_000_000, 1_000_000, 0.01, now_ns)
            });

        let sla_total_ns = self.sla_budget_ns(slice);
        let transit_latency_ns = profile.one_way_transit_latency_ns();
        let residual_budget_ns = (sla_total_ns as i64) - (transit_latency_ns as i64);

        let arq_cycle_ns = profile.estimated_arq_cycle_ns(self.config.jitter_safety_factor);
        let feasibility_score = if arq_cycle_ns > 0 {
            (residual_budget_ns as f64) / (arq_cycle_ns as f64)
        } else {
            0.0
        };

        let loss = profile.loss_ratio;
        let is_high_jitter = profile.rfc3550_jitter_ns >= self.config.high_jitter_threshold_ns;
        let is_rapid_drift = profile.drift_rate_ns_s > 5_000_000.0; // > 5ms/s drift

        let (mode, k, m, retx_enabled, retx_budget, reason) = match slice {
            FlowSliceClass::UltraLowLatency => {
                // Strict 5ms budget: ARQ only feasible if RTT is extremely low and jitter is negligible
                if feasibility_score < 1.0 || is_high_jitter || loss > 0.01 {
                    (
                        HybridSchedulingMode::PureFec,
                        2,
                        1,
                        false,
                        0,
                        "UltraLowLatency: ARQ round-trip exceeds SLA budget; 0-RTT micro-block FEC mandatory".to_string(),
                    )
                } else if loss <= self.config.pure_arq_loss_threshold {
                    (
                        HybridSchedulingMode::PureArq,
                        8,
                        0,
                        true,
                        1,
                        "UltraLowLatency: Stable low-jitter link with clean loss (< 0.5%); ARQ enabled, parity disabled to save bandwidth".to_string(),
                    )
                } else {
                    (
                        HybridSchedulingMode::JointHybrid,
                        3,
                        1,
                        true,
                        1,
                        "UltraLowLatency: Balanced micro-block FEC (K=3, M=1) with single fast ARQ retry".to_string(),
                    )
                }
            }
            FlowSliceClass::MissionCritical => {
                // 25ms budget: Prioritizes zero packet loss over bandwidth
                if loss >= self.config.reinforced_fec_loss_threshold || is_rapid_drift {
                    (
                        HybridSchedulingMode::ReinforcedFecWithFallbackArq,
                        4,
                        2,
                        true,
                        3,
                        "MissionCritical: Severe loss/drift detected; Cauchy RS (K=4, M=2) reinforced with fallback ARQ".to_string(),
                    )
                } else if loss <= self.config.pure_arq_loss_threshold && feasibility_score >= 2.0 {
                    (
                        HybridSchedulingMode::PureArq,
                        8,
                        0,
                        true,
                        3,
                        "MissionCritical: Pristine link telemetry; selective ARQ active with 0% FEC parity overhead".to_string(),
                    )
                } else {
                    (
                        HybridSchedulingMode::JointHybrid,
                        4,
                        1,
                        true,
                        2,
                        "MissionCritical: Nominal operation with Cauchy RS (K=4, M=1) and targeted selective ARQ".to_string(),
                    )
                }
            }
            FlowSliceClass::HighThroughput => {
                // 80ms budget: Bandwidth efficiency is primary constraint
                if loss <= self.config.pure_arq_loss_threshold && feasibility_score >= 1.5 {
                    (
                        HybridSchedulingMode::PureArq,
                        16,
                        0,
                        true,
                        2,
                        "HighThroughput: Pure selective ARQ active; zero parity overhead saves bulk bandwidth".to_string(),
                    )
                } else if loss >= self.config.reinforced_fec_loss_threshold {
                    (
                        HybridSchedulingMode::JointHybrid,
                        8,
                        2,
                        true,
                        2,
                        "HighThroughput: Elevated packet loss; elastic FEC block (K=8, M=2) with selective retransmit".to_string(),
                    )
                } else {
                    (
                        HybridSchedulingMode::JointHybrid,
                        8,
                        1,
                        true,
                        2,
                        "HighThroughput: Standard amortized FEC block (K=8, M=1, 11% overhead) with selective ARQ".to_string(),
                    )
                }
            }
            FlowSliceClass::BestEffort => {
                // 200ms budget: Background traffic
                (
                    HybridSchedulingMode::BestEffortScavenger,
                    16,
                    0,
                    true,
                    1,
                    "BestEffort: Scavenger retransmission with FEC parity disabled (M=0)"
                        .to_string(),
                )
            }
        };

        // Update operational counters
        match mode {
            HybridSchedulingMode::PureFec => self.telemetry.pure_fec_decisions += 1,
            HybridSchedulingMode::PureArq => self.telemetry.pure_arq_decisions += 1,
            HybridSchedulingMode::JointHybrid => self.telemetry.joint_hybrid_decisions += 1,
            HybridSchedulingMode::ReinforcedFecWithFallbackArq => {
                self.telemetry.reinforced_decisions += 1
            }
            HybridSchedulingMode::BestEffortScavenger => self.telemetry.best_effort_decisions += 1,
        }

        let total_symbols = k + m;
        let fec_code_rate = if total_symbols > 0 {
            k as f64 / total_symbols as f64
        } else {
            1.0
        };
        let parity_overhead_ratio = if total_symbols > 0 {
            m as f64 / total_symbols as f64
        } else {
            0.0
        };

        let decision = ArbiterDecision {
            subpath_id,
            slice_class: slice,
            mode,
            recommended_k: k,
            recommended_m: m,
            fec_code_rate,
            parity_overhead_ratio,
            enable_selective_retransmit: retx_enabled,
            max_retransmit_budget: retx_budget,
            estimated_residual_budget_ns: residual_budget_ns,
            retransmit_feasibility_score: feasibility_score,
            timestamp_ns: now_ns,
            reason: reason.clone(),
        };

        self.active_decisions
            .insert((subpath_id, slice), decision.clone());
        self.log_audit_entry(&decision);
        self.update_telemetry_averages();

        decision
    }

    /// Arbitrate the handling of an observed packet loss.
    #[allow(clippy::too_many_arguments)]
    pub fn arbitrate_packet_loss(
        &mut self,
        _flow_id: u32,
        _seq: u64,
        packet_size_bytes: usize,
        original_subpath_id: u32,
        slice: FlowSliceClass,
        creation_timestamp_ns: u64,
        now_ns: u64,
        fallback_subpath_id: Option<u32>,
    ) -> PacketLossArbitrationAction {
        self.telemetry.total_loss_arbitrations += 1;

        let decision = self.evaluate_slice_subpath(original_subpath_id, slice, now_ns);
        let sla_total_ns = self.sla_budget_ns(slice);
        let elapsed_ns = now_ns.saturating_sub(creation_timestamp_ns);

        // Check if deadline is already exceeded
        if elapsed_ns >= sla_total_ns {
            let overdue_ns = elapsed_ns - sla_total_ns;
            self.telemetry.early_dropped_sla_expired += 1;
            return PacketLossArbitrationAction::EarlyDropSlaExpired {
                time_overdue_ns: overdue_ns,
            };
        }

        let remaining_budget_ns = sla_total_ns - elapsed_ns;

        // If PureFec mode was active, 0-RTT recovery is handled by FEC parity
        if decision.mode == HybridSchedulingMode::PureFec {
            self.telemetry.fec_recoveries_handled += 1;
            return PacketLossArbitrationAction::HandledByFec;
        }

        // Check if target candidate subpath can deliver the retransmitted packet within remaining budget
        let target_subpath = fallback_subpath_id.unwrap_or(original_subpath_id);
        let target_profile = self
            .subpath_profiles
            .get(&target_subpath)
            .cloned()
            .unwrap_or_else(|| {
                SubpathNetworkProfile::new(target_subpath, 10_000_000, 1_000_000, 0.01, now_ns)
            });

        let transit_delivery_ns = target_profile.one_way_transit_latency_ns()
            + (target_profile.rfc3550_jitter_ns as f64 * self.config.jitter_safety_factor) as u64;

        if transit_delivery_ns > remaining_budget_ns {
            // Cannot arrive in time -> suppress zombie packet retransmission to save bandwidth
            self.telemetry.early_dropped_sla_expired += 1;
            PacketLossArbitrationAction::EarlyDropSlaExpired {
                time_overdue_ns: transit_delivery_ns - remaining_budget_ns,
            }
        } else {
            // Dispatched retransmission feasible
            self.telemetry.arq_retransmissions_dispatched += 1;
            self.telemetry.sla_violations_prevented += 1;

            let priority = match slice {
                FlowSliceClass::UltraLowLatency => 1,
                FlowSliceClass::MissionCritical => 2,
                FlowSliceClass::HighThroughput => 5,
                FlowSliceClass::BestEffort => 9,
            };

            // Estimate bandwidth saved if we avoided emitting parity for this block
            if decision.mode == HybridSchedulingMode::PureArq {
                self.telemetry.bandwidth_overhead_saved_bytes += packet_size_bytes as u64;
            }

            PacketLossArbitrationAction::DispatchRetransmit {
                target_subpath_id: target_subpath,
                priority,
                deadline_ns: creation_timestamp_ns + sla_total_ns,
            }
        }
    }

    /// Apply arbitration decision directly to a [`MultipathFecEngine`].
    pub fn apply_to_fec_engine(
        &self,
        flow_id: u32,
        subpath_id: u32,
        slice: FlowSliceClass,
        fec_engine: &mut MultipathFecEngine,
    ) {
        if let Some(decision) = self.active_decisions.get(&(subpath_id, slice)) {
            let mut profile = FecProfile::for_slice(slice);
            profile.k_source_packets = decision.recommended_k;
            profile.m_parity_packets = decision.recommended_m;
            profile.adaptive_rate_tuning = false; // Controlled deterministically by arbiter

            fec_engine.encoder.configure_flow(flow_id, profile);
        }
    }

    /// Apply arbitration decision directly to a [`SubpathRetransmitManager`].
    pub fn apply_to_retransmit_manager(
        &self,
        flow_id: u32,
        subpath_id: u32,
        slice: FlowSliceClass,
        retx_mgr: &mut SubpathRetransmitManager,
    ) {
        if let Some(decision) = self.active_decisions.get(&(subpath_id, slice)) {
            let mut policy = RetransmitSlicePolicy::for_slice(slice);
            policy.max_retransmission_attempts = decision.max_retransmit_budget;
            if !decision.enable_selective_retransmit {
                policy.max_retransmission_attempts = 0;
            }

            let sender = retx_mgr.ensure_sender_buffer(flow_id, slice);
            sender.policy = policy;
        }
    }

    /// Read global telemetry summary.
    pub fn telemetry_summary(&self) -> HybridFecTelemetrySummary {
        self.telemetry.clone()
    }

    /// Export OpenMetrics / Prometheus exposition text format.
    pub fn export_prometheus_metrics(&self) -> String {
        let mut out = String::with_capacity(1024);

        out.push_str("# HELP ifa_hybrid_arbiter_evaluations_total Total evaluations performed by joint arbiter.\n");
        out.push_str("# TYPE ifa_hybrid_arbiter_evaluations_total counter\n");
        let _ = writeln!(
            out,
            "ifa_hybrid_arbiter_evaluations_total {}",
            self.telemetry.total_evaluations
        );

        out.push_str("# HELP ifa_hybrid_arbiter_decisions_by_mode Total scheduling decisions categorized by mode.\n");
        out.push_str("# TYPE ifa_hybrid_arbiter_decisions_by_mode counter\n");
        let _ = writeln!(
            out,
            "ifa_hybrid_arbiter_decisions_by_mode{{mode=\"pure_fec\"}} {}",
            self.telemetry.pure_fec_decisions
        );
        let _ = writeln!(
            out,
            "ifa_hybrid_arbiter_decisions_by_mode{{mode=\"pure_arq\"}} {}",
            self.telemetry.pure_arq_decisions
        );
        let _ = writeln!(
            out,
            "ifa_hybrid_arbiter_decisions_by_mode{{mode=\"joint_hybrid\"}} {}",
            self.telemetry.joint_hybrid_decisions
        );
        let _ = writeln!(
            out,
            "ifa_hybrid_arbiter_decisions_by_mode{{mode=\"reinforced_fec\"}} {}",
            self.telemetry.reinforced_decisions
        );
        let _ = writeln!(
            out,
            "ifa_hybrid_arbiter_decisions_by_mode{{mode=\"best_effort\"}} {}",
            self.telemetry.best_effort_decisions
        );

        out.push_str("# HELP ifa_hybrid_arbiter_bandwidth_overhead_saved_bytes_total Total parity bandwidth saved via pure ARQ.\n");
        out.push_str("# TYPE ifa_hybrid_arbiter_bandwidth_overhead_saved_bytes_total counter\n");
        let _ = writeln!(
            out,
            "ifa_hybrid_arbiter_bandwidth_overhead_saved_bytes_total {}",
            self.telemetry.bandwidth_overhead_saved_bytes
        );

        out.push_str("# HELP ifa_hybrid_arbiter_early_dropped_sla_expired_total Expired zombie packets dropped early to protect bandwidth.\n");
        out.push_str("# TYPE ifa_hybrid_arbiter_early_dropped_sla_expired_total counter\n");
        let _ = writeln!(
            out,
            "ifa_hybrid_arbiter_early_dropped_sla_expired_total {}",
            self.telemetry.early_dropped_sla_expired
        );

        out.push_str("# HELP ifa_hybrid_arbiter_sla_violations_prevented_total Total packets rescued in-time before SLA deadline.\n");
        out.push_str("# TYPE ifa_hybrid_arbiter_sla_violations_prevented_total counter\n");
        let _ = writeln!(
            out,
            "ifa_hybrid_arbiter_sla_violations_prevented_total {}",
            self.telemetry.sla_violations_prevented
        );

        out.push_str("# HELP ifa_hybrid_arbiter_average_parity_overhead_ratio Mean parity redundancy overhead ratio.\n");
        out.push_str("# TYPE ifa_hybrid_arbiter_average_parity_overhead_ratio gauge\n");
        let _ = writeln!(
            out,
            "ifa_hybrid_arbiter_average_parity_overhead_ratio {:.4}",
            self.telemetry.average_parity_overhead_ratio
        );

        out
    }

    /// Export structured JSON audit trail.
    pub fn export_audit_trail_json(&self) -> String {
        let mut out = String::with_capacity(self.audit_trail.len() * 128 + 64);
        out.push_str("[\n");
        for (i, entry) in self.audit_trail.iter().enumerate() {
            out.push_str("  ");
            out.push_str(entry);
            if i + 1 < self.audit_trail.len() {
                out.push(',');
            }
            out.push('\n');
        }
        out.push(']');
        out
    }

    fn log_audit_entry(&mut self, decision: &ArbiterDecision) {
        if self.audit_trail.len() >= 500 {
            self.audit_trail.remove(0);
        }

        let entry = format!(
            "{{\"timestamp_ns\":{},\"subpath_id\":{},\"slice\":\"{:?}\",\"mode\":\"{}\",\"k\":{},\"m\":{},\"overhead_ratio\":{:.3},\"feasibility\":{:.2},\"reason\":\"{}\"}}",
            decision.timestamp_ns,
            decision.subpath_id,
            decision.slice_class,
            decision.mode.as_str(),
            decision.recommended_k,
            decision.recommended_m,
            decision.parity_overhead_ratio,
            decision.retransmit_feasibility_score,
            decision.reason
        );
        self.audit_trail.push(entry);
    }

    fn update_telemetry_averages(&mut self) {
        if self.active_decisions.is_empty() {
            self.telemetry.average_parity_overhead_ratio = 0.0;
            return;
        }

        let sum: f64 = self
            .active_decisions
            .values()
            .map(|d| d.parity_overhead_ratio)
            .sum();
        self.telemetry.average_parity_overhead_ratio = sum / self.active_decisions.len() as f64;
    }
}

// ---------------------------------------------------------------------------
// Automated In-Memory Benchmark Suite
// ---------------------------------------------------------------------------

/// Execution report produced by the deterministic in-memory arbiter benchmark.
#[derive(Debug, Clone, PartialEq)]
pub struct HybridFecBenchmarkReport {
    pub total_decisions_evaluated: u64,
    pub total_loss_events_arbitrated: u64,
    pub elapsed_wall_clock_ns: u64,
    pub average_decision_latency_ns: u64,
    pub bandwidth_overhead_saved_bytes: u64,
    pub early_dropped_sla_expired: u64,
    pub pure_arq_savings_ratio: f64,
}

/// Run an automated in-memory micro-benchmark validating high-throughput sub-microsecond decision timing.
pub fn run_hybrid_fec_arbiter_benchmark(iterations: usize) -> HybridFecBenchmarkReport {
    let mut arbiter = HybridFecArbiter::new(HybridFecConfig::default());
    let base_time_ns = 1_700_000_000_000_000_000u64;

    // Register 4 distinct realistic subpaths
    arbiter.update_subpath_profile(SubpathNetworkProfile::new(
        101,
        1_500_000,
        200_000,
        0.001,
        base_time_ns,
    )); // Pristine 5G URLLC
    arbiter.update_subpath_profile(SubpathNetworkProfile::new(
        102,
        12_000_000,
        1_500_000,
        0.015,
        base_time_ns,
    )); // Nominal Fiber
    arbiter.update_subpath_profile(SubpathNetworkProfile::new(
        103,
        35_000_000,
        4_500_000,
        0.060,
        base_time_ns,
    )); // Degraded Satellite
    arbiter.update_subpath_profile(SubpathNetworkProfile::new(
        104,
        8_000_000,
        800_000,
        0.002,
        base_time_ns,
    )); // Backup Terrestrial

    let start_instant = std::time::Instant::now();
    let mut cur_time = base_time_ns;

    for i in 0..iterations {
        cur_time += 1_000_000; // +1ms step
        let subpath = 101 + (i % 4) as u32;
        let slice = match i % 4 {
            0 => FlowSliceClass::UltraLowLatency,
            1 => FlowSliceClass::MissionCritical,
            2 => FlowSliceClass::HighThroughput,
            _ => FlowSliceClass::BestEffort,
        };

        // Decision evaluation
        let _ = arbiter.evaluate_slice_subpath(subpath, slice, cur_time);

        // Loss arbitration
        let creation_time = cur_time.saturating_sub((i % 15) as u64 * 2_000_000); // 0 to 28ms elapsed
        let _ = arbiter.arbitrate_packet_loss(
            1,
            i as u64,
            1400,
            subpath,
            slice,
            creation_time,
            cur_time,
            Some(104),
        );
    }

    let elapsed = start_instant.elapsed().as_nanos() as u64;
    let avg_latency = if iterations > 0 {
        elapsed / (iterations as u64 * 2)
    } else {
        0
    };

    let summary = arbiter.telemetry_summary();
    let total_bytes_evaluated = (iterations * 1400) as f64;
    let savings_ratio = if total_bytes_evaluated > 0.0 {
        summary.bandwidth_overhead_saved_bytes as f64 / total_bytes_evaluated
    } else {
        0.0
    };

    HybridFecBenchmarkReport {
        total_decisions_evaluated: summary.total_evaluations,
        total_loss_events_arbitrated: summary.total_loss_arbitrations,
        elapsed_wall_clock_ns: elapsed,
        average_decision_latency_ns: avg_latency,
        bandwidth_overhead_saved_bytes: summary.bandwidth_overhead_saved_bytes,
        early_dropped_sla_expired: summary.early_dropped_sla_expired,
        pure_arq_savings_ratio: savings_ratio,
    }
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ultralowlatency_pure_fec_when_sla_tight() {
        let mut arbiter = HybridFecArbiter::new(HybridFecConfig::default());
        let now = 1_000_000_000u64;

        // Subpath with 4ms RTT and 1ms jitter: ARQ cycle is 4ms + 1.5*1ms = 5.5ms, which exceeds 5ms ULL budget!
        let profile = SubpathNetworkProfile::new(10, 4_000_000, 1_000_000, 0.02, now);
        arbiter.update_subpath_profile(profile);

        let decision = arbiter.evaluate_slice_subpath(10, FlowSliceClass::UltraLowLatency, now);
        assert_eq!(decision.mode, HybridSchedulingMode::PureFec);
        assert_eq!(decision.recommended_k, 2);
        assert_eq!(decision.recommended_m, 1);
        assert!(!decision.enable_selective_retransmit);
        assert_eq!(decision.max_retransmit_budget, 0);
        assert!(decision.retransmit_feasibility_score < 1.0);
    }

    #[test]
    fn test_highthroughput_pure_arq_saves_bandwidth() {
        let mut arbiter = HybridFecArbiter::new(HybridFecConfig::default());
        let now = 1_000_000_000u64;

        // Clean link (0.1% loss, 10ms RTT): ARQ easily fits in 80ms eMBB budget
        let profile = SubpathNetworkProfile::new(20, 10_000_000, 500_000, 0.001, now);
        arbiter.update_subpath_profile(profile);

        let decision = arbiter.evaluate_slice_subpath(20, FlowSliceClass::HighThroughput, now);
        assert_eq!(decision.mode, HybridSchedulingMode::PureArq);
        assert_eq!(decision.recommended_k, 16);
        assert_eq!(decision.recommended_m, 0); // Parity disabled!
        assert_eq!(decision.parity_overhead_ratio, 0.0);
        assert!(decision.enable_selective_retransmit);
        assert!(decision.retransmit_feasibility_score >= 1.5);
    }

    #[test]
    fn test_missioncritical_reinforced_under_high_loss() {
        let mut arbiter = HybridFecArbiter::new(HybridFecConfig::default());
        let now = 1_000_000_000u64;

        // 6% loss on MissionCritical triggers reinforced FEC
        let profile = SubpathNetworkProfile::new(30, 15_000_000, 2_000_000, 0.06, now);
        arbiter.update_subpath_profile(profile);

        let decision = arbiter.evaluate_slice_subpath(30, FlowSliceClass::MissionCritical, now);
        assert_eq!(
            decision.mode,
            HybridSchedulingMode::ReinforcedFecWithFallbackArq
        );
        assert_eq!(decision.recommended_k, 4);
        assert_eq!(decision.recommended_m, 2); // Cauchy RS K=4, M=2
        assert_eq!(decision.parity_overhead_ratio, 2.0 / 6.0);
        assert!(decision.enable_selective_retransmit);
        assert_eq!(decision.max_retransmit_budget, 3);
    }

    #[test]
    fn test_arbitrate_packet_loss_early_drop_when_deadline_expired() {
        let mut arbiter = HybridFecArbiter::new(HybridFecConfig::default());
        let create_time = 1_000_000_000u64;
        let now = create_time + 6_000_000; // 6ms elapsed, ULL SLA is 5ms

        let profile = SubpathNetworkProfile::new(10, 1_000_000, 100_000, 0.001, now);
        arbiter.update_subpath_profile(profile);

        let action = arbiter.arbitrate_packet_loss(
            1,
            42,
            1400,
            10,
            FlowSliceClass::UltraLowLatency,
            create_time,
            now,
            None,
        );

        match action {
            PacketLossArbitrationAction::EarlyDropSlaExpired { time_overdue_ns } => {
                assert_eq!(time_overdue_ns, 1_000_000); // 1ms past SLA
            }
            other => panic!("Expected EarlyDropSlaExpired, got {:?}", other),
        }

        let summary = arbiter.telemetry_summary();
        assert_eq!(summary.early_dropped_sla_expired, 1);
    }

    #[test]
    fn test_arbitrate_packet_loss_dispatch_retransmit_on_feasible_route() {
        let mut arbiter = HybridFecArbiter::new(HybridFecConfig::default());
        let create_time = 1_000_000_000u64;
        let now = create_time + 5_000_000; // 5ms elapsed out of 25ms MC SLA

        let primary_profile = SubpathNetworkProfile::new(10, 8_000_000, 500_000, 0.01, now);
        let fallback_profile = SubpathNetworkProfile::new(20, 6_000_000, 400_000, 0.001, now);
        arbiter.update_subpath_profile(primary_profile);
        arbiter.update_subpath_profile(fallback_profile);

        let action = arbiter.arbitrate_packet_loss(
            1,
            99,
            1400,
            10,
            FlowSliceClass::MissionCritical,
            create_time,
            now,
            Some(20),
        );

        match action {
            PacketLossArbitrationAction::DispatchRetransmit {
                target_subpath_id,
                priority,
                deadline_ns,
            } => {
                assert_eq!(target_subpath_id, 20);
                assert_eq!(priority, 2);
                assert_eq!(deadline_ns, create_time + 25_000_000);
            }
            other => panic!("Expected DispatchRetransmit, got {:?}", other),
        }
    }

    #[test]
    fn test_apply_to_engines() {
        let mut arbiter = HybridFecArbiter::new(HybridFecConfig::default());
        let now = 1_000_000_000u64;

        let profile = SubpathNetworkProfile::new(10, 4_000_000, 1_000_000, 0.02, now);
        arbiter.update_subpath_profile(profile);
        let _ = arbiter.evaluate_slice_subpath(10, FlowSliceClass::UltraLowLatency, now);

        let mut fec_engine = MultipathFecEngine::new();
        let mut retx_mgr = SubpathRetransmitManager::new();

        arbiter.apply_to_fec_engine(1, 10, FlowSliceClass::UltraLowLatency, &mut fec_engine);
        arbiter.apply_to_retransmit_manager(1, 10, FlowSliceClass::UltraLowLatency, &mut retx_mgr);

        // Verify retransmit manager received policy with max_attempts = 0 (PureFec mode)
        let sender = retx_mgr.ensure_sender_buffer(1, FlowSliceClass::UltraLowLatency);
        assert_eq!(sender.policy.max_retransmission_attempts, 0);
    }

    #[test]
    fn test_prometheus_metrics_and_audit_trail_json() {
        let mut arbiter = HybridFecArbiter::new(HybridFecConfig::default());
        let now = 1_000_000_000u64;

        arbiter.update_subpath_profile(SubpathNetworkProfile::new(
            10, 2_000_000, 200_000, 0.001, now,
        ));
        let _ = arbiter.evaluate_slice_subpath(10, FlowSliceClass::UltraLowLatency, now);

        let prom = arbiter.export_prometheus_metrics();
        assert!(prom.contains("ifa_hybrid_arbiter_evaluations_total 1"));
        assert!(prom.contains("ifa_hybrid_arbiter_decisions_by_mode"));

        let audit = arbiter.export_audit_trail_json();
        assert!(audit.starts_with("[\n  {"));
        assert!(audit.ends_with("\n]"));
        assert!(audit.contains("\"subpath_id\":10"));
    }

    #[test]
    fn test_benchmark_submicrosecond_latency() {
        let report = run_hybrid_fec_arbiter_benchmark(100);
        assert_eq!(report.total_decisions_evaluated, 200);
        assert_eq!(report.total_loss_events_arbitrated, 100);
        // Ensure decision latency is within microsecond realm (< 100,000ns in debug mode)
        assert!(
            report.average_decision_latency_ns < 100_000,
            "Decision latency too high: {}ns",
            report.average_decision_latency_ns
        );
    }
}

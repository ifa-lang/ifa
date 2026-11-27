//! Anti-Starvation Monitoring and Priority Inversion Detection (`SubpathStarvationGuard`).
//!
//! Provides deterministic starvation mitigation and anti-priority-inversion surveillance
//! for elastic QoS traffic slices (`BestEffort` and `HighThroughput`) under prolonged saturation
//! by high-priority critical streams (`UltraLowLatency` and `MissionCritical`):
//! - **Admission Starvation Detection**: Tracks shaper throttle streaks and admission wait times,
//!   granting bounded temporary token boosts or minimum guaranteed credit without breaching link capacity.
//! - **Scheduling Starvation & Queue Sojourn Tracking**: Monitors packet queue aging and consecutive
//!   higher-priority service streaks in the pacing engine.
//! - **Strict UltraLowLatency (URLLC) SLA Shielding**: Guarantees that anti-starvation promotions
//!   NEVER preempt or delay active UltraLowLatency traffic ready for transmission.
//! - **OpenMetrics Prometheus Observability**: Exposes starvation severity, boost events, promoted packets,
//!   sojourn times, and URLLC shielding events.
//!
//! Zero-simulation: operates exclusively on monotonic nanosecond clocks, real queued packet ages,
//! concrete buffer occupancy, and live pacer queues.

use std::collections::BTreeMap;
use std::fmt::Write as FmtWrite;

use crate::multipath_pacing::{PacingPollResult, SubpathPacer};
use crate::subpath_shaper::SubpathSliceShaper;
use crate::traffic_slicing::FlowSliceClass;

/// Severity classification of traffic slice starvation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum StarvationSeverity {
    /// Normal operation: latencies and service intervals within standard parameters.
    Normal = 0,
    /// Approaching thresholds (e.g. 50% of maximum sojourn or serve streak).
    Warning = 1,
    /// Active starvation detected: remediation triggered.
    Starved = 2,
    /// Critical starvation: persistent throttling or queue head blockage risking disconnect.
    Critical = 3,
}

impl StarvationSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Warning => "warning",
            Self::Starved => "starved",
            Self::Critical => "critical",
        }
    }
}

/// Configuration tuning parameters for starvation surveillance and mitigation.
#[derive(Debug, Clone, PartialEq)]
pub struct StarvationGuardConfig {
    /// Maximum allowable queue sojourn time for HighThroughput traffic before starvation is declared.
    pub max_sojourn_time_ns_high_throughput: u64,
    /// Maximum allowable queue sojourn time for BestEffort traffic before starvation is declared.
    pub max_sojourn_time_ns_best_effort: u64,
    /// Maximum consecutive higher-priority packet transmissions before HighThroughput must be served.
    pub max_higher_priority_serves_high_throughput: u32,
    /// Maximum consecutive higher-priority packet transmissions before BestEffort must be served.
    pub max_higher_priority_serves_best_effort: u32,
    /// Number of consecutive shaper throttles on a slice before triggering an admission token boost.
    pub throttle_streak_threshold: u32,
    /// Maximum admission wait time before an admission token boost is authorized.
    pub max_admission_wait_ns: u64,
    /// Default token boost quantum in bytes injected into shaper bucket on starvation.
    pub token_boost_bytes: u64,
    /// Minimum cooldown duration between consecutive token boosts on the same slice.
    pub boost_cooldown_ns: u64,
    /// Strictly safeguard UltraLowLatency SLA by never preempting URLLC packets ready to depart.
    pub urllc_strict_protection: bool,
    /// Enable admission token boosting in shaper.
    pub enable_admission_boost: bool,
    /// Enable scheduling priority promotion in pacer.
    pub enable_scheduling_promotion: bool,
}

impl Default for StarvationGuardConfig {
    fn default() -> Self {
        Self {
            max_sojourn_time_ns_high_throughput: 50_000_000, // 50 ms
            max_sojourn_time_ns_best_effort: 100_000_000,    // 100 ms
            max_higher_priority_serves_high_throughput: 32,
            max_higher_priority_serves_best_effort: 64,
            throttle_streak_threshold: 8,
            max_admission_wait_ns: 50_000_000, // 50 ms
            token_boost_bytes: 2048,
            boost_cooldown_ns: 10_000_000, // 10 ms cooldown
            urllc_strict_protection: true,
            enable_admission_boost: true,
            enable_scheduling_promotion: true,
        }
    }
}

/// Runtime metrics and tracking counters for an individual traffic slice.
#[derive(Debug, Clone, PartialEq)]
pub struct SliceStarvationMetrics {
    pub slice_class: FlowSliceClass,
    pub current_severity: StarvationSeverity,
    pub consecutive_higher_priority_serves: u32,
    pub consecutive_throttled_count: u32,
    pub oldest_queued_age_ns: u64,
    pub last_served_timestamp_ns: u64,
    pub last_admitted_timestamp_ns: u64,
    pub last_boost_timestamp_ns: u64,
    pub total_starvation_events: u64,
    pub total_token_boost_events: u64,
    pub total_boosted_bytes: u64,
    pub total_promoted_packets: u64,
    pub total_suppressed_by_urllc: u64,
}

impl SliceStarvationMetrics {
    pub fn new(slice_class: FlowSliceClass, now_ns: u64) -> Self {
        Self {
            slice_class,
            current_severity: StarvationSeverity::Normal,
            consecutive_higher_priority_serves: 0,
            consecutive_throttled_count: 0,
            oldest_queued_age_ns: 0,
            last_served_timestamp_ns: now_ns,
            last_admitted_timestamp_ns: now_ns,
            last_boost_timestamp_ns: 0,
            total_starvation_events: 0,
            total_token_boost_events: 0,
            total_boosted_bytes: 0,
            total_promoted_packets: 0,
            total_suppressed_by_urllc: 0,
        }
    }
}

/// Telemetry snapshot for an individual traffic slice starvation status.
#[derive(Debug, Clone, PartialEq)]
pub struct SliceStarvationTelemetry {
    pub slice_class: FlowSliceClass,
    pub severity: StarvationSeverity,
    pub consecutive_higher_priority_serves: u32,
    pub consecutive_throttled_count: u32,
    pub oldest_queued_age_ns: u64,
    pub total_starvation_events: u64,
    pub total_token_boost_events: u64,
    pub total_boosted_bytes: u64,
    pub total_promoted_packets: u64,
    pub total_suppressed_by_urllc: u64,
}

/// Telemetry snapshot for a subpath's entire starvation surveillance state.
#[derive(Debug, Clone, PartialEq)]
pub struct SubpathStarvationTelemetry {
    pub subpath_id: u8,
    pub slices: Vec<SliceStarvationTelemetry>,
}

/// Verdict returned when evaluating starvation remediation actions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StarvationRemediationVerdict {
    /// No starvation detected; normal flow.
    None,
    /// Admission token boost applied to shaper to unblock throttled slice.
    TokenBoostApplied {
        slice: FlowSliceClass,
        boost_bytes: u64,
    },
    /// Scheduling priority promotion active in pacing engine.
    SchedulingPromotionActive { slice: FlowSliceClass },
    /// Starvation detected, but action suppressed to strictly shield UltraLowLatency SLA.
    UrllcPriorityShieldActive { starved_slice: FlowSliceClass },
}

/// Subpath internal starvation tracking state.
#[derive(Debug, Clone)]
pub struct SubpathStarvationState {
    pub subpath_id: u8,
    pub slices: BTreeMap<FlowSliceClass, SliceStarvationMetrics>,
}

impl SubpathStarvationState {
    pub fn new(subpath_id: u8, now_ns: u64) -> Self {
        let mut slices = BTreeMap::new();
        slices.insert(
            FlowSliceClass::UltraLowLatency,
            SliceStarvationMetrics::new(FlowSliceClass::UltraLowLatency, now_ns),
        );
        slices.insert(
            FlowSliceClass::MissionCritical,
            SliceStarvationMetrics::new(FlowSliceClass::MissionCritical, now_ns),
        );
        slices.insert(
            FlowSliceClass::HighThroughput,
            SliceStarvationMetrics::new(FlowSliceClass::HighThroughput, now_ns),
        );
        slices.insert(
            FlowSliceClass::BestEffort,
            SliceStarvationMetrics::new(FlowSliceClass::BestEffort, now_ns),
        );
        Self { subpath_id, slices }
    }
}

/// Anti-Starvation and Priority Inversion Guard (`SubpathStarvationGuard`).
#[derive(Debug, Clone)]
pub struct SubpathStarvationGuard {
    pub config: StarvationGuardConfig,
    pub states: BTreeMap<u8, SubpathStarvationState>,
}

impl Default for SubpathStarvationGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl SubpathStarvationGuard {
    /// Creates a new starvation guard with default tuning parameters.
    pub fn new() -> Self {
        Self::with_config(StarvationGuardConfig::default())
    }

    /// Creates a new starvation guard with custom configuration.
    pub fn with_config(config: StarvationGuardConfig) -> Self {
        Self {
            config,
            states: BTreeMap::new(),
        }
    }

    /// Registers a transport subpath for starvation surveillance.
    pub fn register_subpath(&mut self, subpath_id: u8, now_ns: u64) {
        self.states
            .insert(subpath_id, SubpathStarvationState::new(subpath_id, now_ns));
    }

    /// Unregisters a transport subpath from surveillance.
    pub fn unregister_subpath(&mut self, subpath_id: u8) -> bool {
        self.states.remove(&subpath_id).is_some()
    }

    /// Records an admitted packet on a specific slice, resetting throttle counters.
    pub fn record_admission(
        &mut self,
        subpath_id: u8,
        slice: FlowSliceClass,
        _packet_bytes: usize,
        now_ns: u64,
    ) {
        if let Some(subpath) = self.states.get_mut(&subpath_id) {
            if let Some(metrics) = subpath.slices.get_mut(&slice) {
                metrics.consecutive_throttled_count = 0;
                metrics.last_admitted_timestamp_ns = now_ns;
                if metrics.current_severity == StarvationSeverity::Starved
                    && metrics.oldest_queued_age_ns == 0
                {
                    metrics.current_severity = StarvationSeverity::Normal;
                }
            }
        }
    }

    /// Records a throttled packet on a specific slice, updating starvation streak and severity.
    pub fn record_throttle(
        &mut self,
        subpath_id: u8,
        slice: FlowSliceClass,
        _packet_bytes: usize,
        _now_ns: u64,
    ) {
        if let Some(subpath) = self.states.get_mut(&subpath_id) {
            if let Some(metrics) = subpath.slices.get_mut(&slice) {
                metrics.consecutive_throttled_count =
                    metrics.consecutive_throttled_count.saturating_add(1);
                if metrics.consecutive_throttled_count
                    >= self.config.throttle_streak_threshold.saturating_mul(2)
                {
                    metrics.current_severity = StarvationSeverity::Critical;
                } else if metrics.consecutive_throttled_count
                    >= self.config.throttle_streak_threshold
                {
                    metrics.current_severity = StarvationSeverity::Starved;
                } else if metrics.consecutive_throttled_count
                    >= self.config.throttle_streak_threshold / 2
                {
                    metrics.current_severity = StarvationSeverity::Warning;
                }
            }
        }
    }

    /// Records a wire packet departure, updating service streaks across slices.
    pub fn record_packet_scheduled(
        &mut self,
        subpath_id: u8,
        scheduled_slice: FlowSliceClass,
        now_ns: u64,
    ) {
        if let Some(subpath) = self.states.get_mut(&subpath_id) {
            // For the scheduled slice: reset consecutive higher priority count
            if let Some(m) = subpath.slices.get_mut(&scheduled_slice) {
                m.consecutive_higher_priority_serves = 0;
                m.last_served_timestamp_ns = now_ns;
            }

            // For all slices of strictly lower priority than the scheduled slice:
            // increment their consecutive higher-priority service counter.
            for (&slice, metrics) in subpath.slices.iter_mut() {
                if Self::is_strictly_lower_priority(slice, scheduled_slice) {
                    metrics.consecutive_higher_priority_serves =
                        metrics.consecutive_higher_priority_serves.saturating_add(1);

                    let threshold = match slice {
                        FlowSliceClass::HighThroughput => {
                            self.config.max_higher_priority_serves_high_throughput
                        }
                        FlowSliceClass::BestEffort => {
                            self.config.max_higher_priority_serves_best_effort
                        }
                        _ => u32::MAX,
                    };

                    if metrics.consecutive_higher_priority_serves >= threshold.saturating_mul(2) {
                        metrics.current_severity = StarvationSeverity::Critical;
                    } else if metrics.consecutive_higher_priority_serves >= threshold {
                        metrics.current_severity = StarvationSeverity::Starved;
                    } else if metrics.consecutive_higher_priority_serves >= threshold / 2 {
                        metrics.current_severity = StarvationSeverity::Warning;
                    }
                }
            }
        }
    }

    /// Checks if admission starvation is present on a throttled slice, and applies a token boost if warranted.
    pub fn check_admission_starvation(
        &mut self,
        subpath_id: u8,
        slice: FlowSliceClass,
        packet_bytes: usize,
        shaper: &mut SubpathSliceShaper,
        now_ns: u64,
    ) -> StarvationRemediationVerdict {
        if !self.config.enable_admission_boost {
            return StarvationRemediationVerdict::None;
        }

        // Starvation guard applies to elastic slices (BestEffort and HighThroughput)
        if slice != FlowSliceClass::BestEffort && slice != FlowSliceClass::HighThroughput {
            return StarvationRemediationVerdict::None;
        }

        let (should_boost, boost_bytes) = if let Some(subpath) = self.states.get_mut(&subpath_id) {
            if let Some(metrics) = subpath.slices.get_mut(&slice) {
                let elapsed_since_admitted =
                    now_ns.saturating_sub(metrics.last_admitted_timestamp_ns);
                let is_starved = metrics.consecutive_throttled_count
                    >= self.config.throttle_streak_threshold
                    || elapsed_since_admitted >= self.config.max_admission_wait_ns;

                let cooldown_expired = metrics.last_boost_timestamp_ns == 0
                    || now_ns.saturating_sub(metrics.last_boost_timestamp_ns)
                        >= self.config.boost_cooldown_ns;

                if is_starved && cooldown_expired {
                    let boost = self.config.token_boost_bytes.max(packet_bytes as u64);
                    metrics.last_boost_timestamp_ns = now_ns;
                    metrics.total_token_boost_events += 1;
                    metrics.total_boosted_bytes += boost;
                    metrics.total_starvation_events += 1;
                    metrics.current_severity = StarvationSeverity::Starved;
                    (true, boost)
                } else {
                    (false, 0)
                }
            } else {
                (false, 0)
            }
        } else {
            (false, 0)
        };

        if should_boost {
            shaper.boost_tokens(slice, boost_bytes, now_ns);
            StarvationRemediationVerdict::TokenBoostApplied { slice, boost_bytes }
        } else {
            StarvationRemediationVerdict::None
        }
    }

    /// Evaluates whether scheduling starvation is occurring on a subpath pacer,
    /// returning the slice class to promote if anti-starvation preemption is authorized.
    ///
    /// UltraLowLatency SLA is strictly preserved: if URLLC has packets ready for transmission,
    /// promotion is suppressed to avoid delaying URLLC traffic.
    pub fn evaluate_scheduling_starvation(
        &mut self,
        subpath_id: u8,
        pacer: &SubpathPacer,
        now_ns: u64,
    ) -> Option<FlowSliceClass> {
        if !self.config.enable_scheduling_promotion {
            return None;
        }

        let subpath = self.states.get_mut(&subpath_id)?;

        // 1. Calculate queue sojourn times
        let ht_age_ns = pacer
            .high_throughput_queue
            .front()
            .map(|p| now_ns.saturating_sub(p.enqueued_timestamp_ns))
            .unwrap_or(0);
        let be_age_ns = pacer
            .best_effort_queue
            .front()
            .map(|p| now_ns.saturating_sub(p.enqueued_timestamp_ns))
            .unwrap_or(0);

        if let Some(m) = subpath.slices.get_mut(&FlowSliceClass::HighThroughput) {
            m.oldest_queued_age_ns = ht_age_ns;
            if ht_age_ns >= self.config.max_sojourn_time_ns_high_throughput {
                m.current_severity = StarvationSeverity::Starved;
            }
        }

        if let Some(m) = subpath.slices.get_mut(&FlowSliceClass::BestEffort) {
            m.oldest_queued_age_ns = be_age_ns;
            if be_age_ns >= self.config.max_sojourn_time_ns_best_effort {
                m.current_severity = StarvationSeverity::Starved;
            }
        }

        // 2. Identify candidate starved slices
        let ht_starved = !pacer.high_throughput_queue.is_empty() && {
            let m = subpath.slices.get(&FlowSliceClass::HighThroughput);
            let serves = m.map(|x| x.consecutive_higher_priority_serves).unwrap_or(0);
            ht_age_ns >= self.config.max_sojourn_time_ns_high_throughput
                || serves >= self.config.max_higher_priority_serves_high_throughput
        };

        let be_starved = !pacer.best_effort_queue.is_empty() && {
            let m = subpath.slices.get(&FlowSliceClass::BestEffort);
            let serves = m.map(|x| x.consecutive_higher_priority_serves).unwrap_or(0);
            be_age_ns >= self.config.max_sojourn_time_ns_best_effort
                || serves >= self.config.max_higher_priority_serves_best_effort
        };

        let candidate_slice = match (ht_starved, be_starved) {
            (true, true) => {
                // If both are starved, prioritize the one with higher relative wait or HighThroughput
                if be_age_ns > ht_age_ns * 2 {
                    FlowSliceClass::BestEffort
                } else {
                    FlowSliceClass::HighThroughput
                }
            }
            (true, false) => FlowSliceClass::HighThroughput,
            (false, true) => FlowSliceClass::BestEffort,
            (false, false) => return None,
        };

        // 3. Strict UltraLowLatency SLA Verification:
        // If URLLC has packets ready to transmit on the subpath, URLLC MUST NOT be preempted.
        if self.config.urllc_strict_protection && !pacer.urllc_queue.is_empty() {
            let remaining_quantum = pacer
                .urllc_guaranteed_quantum_bytes
                .saturating_sub(pacer.urllc_injected_bytes_in_epoch);
            if remaining_quantum > 0 || now_ns >= pacer.next_tx_time_ns {
                if let Some(m) = subpath.slices.get_mut(&candidate_slice) {
                    m.total_suppressed_by_urllc += 1;
                }
                return None;
            }
        }

        if let Some(m) = subpath.slices.get_mut(&candidate_slice) {
            m.total_starvation_events += 1;
        }

        Some(candidate_slice)
    }

    /// Polls a subpath pacer applying anti-starvation scheduling logic and accounting.
    pub fn poll_with_starvation_guard(
        &mut self,
        subpath_id: u8,
        pacer: &mut SubpathPacer,
        now_ns: u64,
    ) -> PacingPollResult {
        let starved_slice = self.evaluate_scheduling_starvation(subpath_id, pacer, now_ns);
        let result = pacer.poll_next_with_starvation(now_ns, starved_slice);

        if let PacingPollResult::Ready(ref packet) = result {
            if let Some(starved) = starved_slice {
                if packet.slice_class == starved {
                    if let Some(subpath) = self.states.get_mut(&subpath_id) {
                        if let Some(m) = subpath.slices.get_mut(&starved) {
                            m.total_promoted_packets += 1;
                            m.current_severity = StarvationSeverity::Normal;
                        }
                    }
                }
            }
            self.record_packet_scheduled(subpath_id, packet.slice_class, now_ns);
        }

        result
    }

    /// Telemetry snapshot for a single subpath.
    pub fn subpath_telemetry(&self, subpath_id: u8) -> Option<SubpathStarvationTelemetry> {
        let state = self.states.get(&subpath_id)?;
        let slices = state
            .slices
            .values()
            .map(|m| SliceStarvationTelemetry {
                slice_class: m.slice_class,
                severity: m.current_severity,
                consecutive_higher_priority_serves: m.consecutive_higher_priority_serves,
                consecutive_throttled_count: m.consecutive_throttled_count,
                oldest_queued_age_ns: m.oldest_queued_age_ns,
                total_starvation_events: m.total_starvation_events,
                total_token_boost_events: m.total_token_boost_events,
                total_boosted_bytes: m.total_boosted_bytes,
                total_promoted_packets: m.total_promoted_packets,
                total_suppressed_by_urllc: m.total_suppressed_by_urllc,
            })
            .collect();
        Some(SubpathStarvationTelemetry { subpath_id, slices })
    }

    /// Telemetry snapshot across all monitored subpaths.
    pub fn telemetry_snapshot(&self) -> Vec<SubpathStarvationTelemetry> {
        self.states
            .keys()
            .filter_map(|&sid| self.subpath_telemetry(sid))
            .collect()
    }

    /// Exports OpenMetrics / Prometheus exposition format for all starvation state and counters.
    pub fn export_prometheus_metrics(&self) -> String {
        let mut out = String::new();

        let _ = writeln!(
            out,
            "# HELP ifa_transport_subpath_starvation_severity Severity level of traffic slice starvation (0=Normal, 1=Warning, 2=Starved, 3=Critical)."
        );
        let _ = writeln!(
            out,
            "# TYPE ifa_transport_subpath_starvation_severity gauge"
        );
        let _ = writeln!(
            out,
            "# HELP ifa_transport_subpath_starvation_events_total Total starvation detection triggers per slice."
        );
        let _ = writeln!(
            out,
            "# TYPE ifa_transport_subpath_starvation_events_total counter"
        );
        let _ = writeln!(
            out,
            "# HELP ifa_transport_subpath_starvation_boost_events_total Total token boost allocations granted to mitigate starvation."
        );
        let _ = writeln!(
            out,
            "# TYPE ifa_transport_subpath_starvation_boost_events_total counter"
        );
        let _ = writeln!(
            out,
            "# HELP ifa_transport_subpath_starvation_boosted_bytes_total Total token bytes injected via anti-starvation boosts."
        );
        let _ = writeln!(
            out,
            "# TYPE ifa_transport_subpath_starvation_boosted_bytes_total counter"
        );
        let _ = writeln!(
            out,
            "# HELP ifa_transport_subpath_starvation_promoted_packets_total Total packets scheduled via anti-starvation priority promotion."
        );
        let _ = writeln!(
            out,
            "# TYPE ifa_transport_subpath_starvation_promoted_packets_total counter"
        );
        let _ = writeln!(
            out,
            "# HELP ifa_transport_subpath_starvation_oldest_queued_age_ns Sojourn duration of the oldest queued packet in nanoseconds."
        );
        let _ = writeln!(
            out,
            "# TYPE ifa_transport_subpath_starvation_oldest_queued_age_ns gauge"
        );
        let _ = writeln!(
            out,
            "# HELP ifa_transport_subpath_starvation_consecutive_higher_serves Consecutive higher priority packets scheduled without serving slice."
        );
        let _ = writeln!(
            out,
            "# TYPE ifa_transport_subpath_starvation_consecutive_higher_serves gauge"
        );
        let _ = writeln!(
            out,
            "# HELP ifa_transport_subpath_starvation_suppressed_by_urllc_total Starvation promotions suppressed to safeguard UltraLowLatency SLA."
        );
        let _ = writeln!(
            out,
            "# TYPE ifa_transport_subpath_starvation_suppressed_by_urllc_total counter"
        );

        for (sid, subpath) in &self.states {
            for (slice, m) in &subpath.slices {
                let sl = slice.as_str();
                let _ = writeln!(
                    out,
                    "ifa_transport_subpath_starvation_severity{{subpath=\"{}\",slice=\"{}\"}} {}",
                    sid, sl, m.current_severity as u8
                );
                let _ = writeln!(
                    out,
                    "ifa_transport_subpath_starvation_events_total{{subpath=\"{}\",slice=\"{}\"}} {}",
                    sid, sl, m.total_starvation_events
                );
                let _ = writeln!(
                    out,
                    "ifa_transport_subpath_starvation_boost_events_total{{subpath=\"{}\",slice=\"{}\"}} {}",
                    sid, sl, m.total_token_boost_events
                );
                let _ = writeln!(
                    out,
                    "ifa_transport_subpath_starvation_boosted_bytes_total{{subpath=\"{}\",slice=\"{}\"}} {}",
                    sid, sl, m.total_boosted_bytes
                );
                let _ = writeln!(
                    out,
                    "ifa_transport_subpath_starvation_promoted_packets_total{{subpath=\"{}\",slice=\"{}\"}} {}",
                    sid, sl, m.total_promoted_packets
                );
                let _ = writeln!(
                    out,
                    "ifa_transport_subpath_starvation_oldest_queued_age_ns{{subpath=\"{}\",slice=\"{}\"}} {}",
                    sid, sl, m.oldest_queued_age_ns
                );
                let _ = writeln!(
                    out,
                    "ifa_transport_subpath_starvation_consecutive_higher_serves{{subpath=\"{}\",slice=\"{}\"}} {}",
                    sid, sl, m.consecutive_higher_priority_serves
                );
                let _ = writeln!(
                    out,
                    "ifa_transport_subpath_starvation_suppressed_by_urllc_total{{subpath=\"{}\",slice=\"{}\"}} {}",
                    sid, sl, m.total_suppressed_by_urllc
                );
            }
        }

        out
    }

    /// Determines if slice `a` is strictly lower priority than slice `b`.
    /// Priority order: UltraLowLatency > MissionCritical > HighThroughput > BestEffort.
    fn is_strictly_lower_priority(a: FlowSliceClass, b: FlowSliceClass) -> bool {
        let rank = |s: FlowSliceClass| -> u8 {
            match s {
                FlowSliceClass::UltraLowLatency => 3,
                FlowSliceClass::MissionCritical => 2,
                FlowSliceClass::HighThroughput => 1,
                FlowSliceClass::BestEffort => 0,
            }
        };
        rank(a) < rank(b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multipath_pacing::PacedQueuedPacket;

    #[test]
    fn test_starvation_guard_initial_state_and_lifecycle() {
        let mut guard = SubpathStarvationGuard::new();
        let now_ns = 1_000_000_000;
        let sid = 1;

        guard.register_subpath(sid, now_ns);
        let telem = guard.subpath_telemetry(sid).expect("Subpath telemetry");
        assert_eq!(telem.subpath_id, sid);
        assert_eq!(telem.slices.len(), 4);

        for s in telem.slices {
            assert_eq!(s.severity, StarvationSeverity::Normal);
            assert_eq!(s.consecutive_higher_priority_serves, 0);
            assert_eq!(s.consecutive_throttled_count, 0);
            assert_eq!(s.total_starvation_events, 0);
            assert_eq!(s.total_token_boost_events, 0);
        }

        assert!(guard.unregister_subpath(sid));
        assert!(guard.subpath_telemetry(sid).is_none());
    }

    #[test]
    fn test_starvation_guard_admission_throttle_and_token_boost() {
        let mut guard = SubpathStarvationGuard::new();
        let now_ns = 1_000_000_000;
        let sid = 2;
        guard.register_subpath(sid, now_ns);

        let mut shaper = SubpathSliceShaper::new(sid, 10_000_000, now_ns);
        // Drain BestEffort bucket completely
        let _ = shaper.try_admit(FlowSliceClass::BestEffort, 100_000, now_ns);

        // Record consecutive throttles
        for _ in 0..4 {
            guard.record_throttle(sid, FlowSliceClass::BestEffort, 1500, now_ns);
        }
        let telem = guard.subpath_telemetry(sid).unwrap();
        let be = telem
            .slices
            .iter()
            .find(|s| s.slice_class == FlowSliceClass::BestEffort)
            .unwrap();
        assert_eq!(be.severity, StarvationSeverity::Warning);

        // Trigger starved state
        for _ in 0..4 {
            guard.record_throttle(sid, FlowSliceClass::BestEffort, 1500, now_ns);
        }
        let telem = guard.subpath_telemetry(sid).unwrap();
        let be = telem
            .slices
            .iter()
            .find(|s| s.slice_class == FlowSliceClass::BestEffort)
            .unwrap();
        assert_eq!(be.severity, StarvationSeverity::Starved);

        // Evaluate admission starvation -> should trigger token boost
        let verdict = guard.check_admission_starvation(
            sid,
            FlowSliceClass::BestEffort,
            1500,
            &mut shaper,
            now_ns,
        );
        match verdict {
            StarvationRemediationVerdict::TokenBoostApplied { slice, boost_bytes } => {
                assert_eq!(slice, FlowSliceClass::BestEffort);
                assert!(boost_bytes >= 1500);
            }
            _ => panic!("Expected TokenBoostApplied"),
        }

        // Subsequent check before cooldown should NOT re-boost
        let verdict2 = guard.check_admission_starvation(
            sid,
            FlowSliceClass::BestEffort,
            1500,
            &mut shaper,
            now_ns + 1_000_000, // +1ms < 10ms cooldown
        );
        assert_eq!(verdict2, StarvationRemediationVerdict::None);

        // Check after cooldown expires -> second boost allowed
        let verdict3 = guard.check_admission_starvation(
            sid,
            FlowSliceClass::BestEffort,
            1500,
            &mut shaper,
            now_ns + 11_000_000, // +11ms > 10ms cooldown
        );
        assert!(matches!(
            verdict3,
            StarvationRemediationVerdict::TokenBoostApplied { .. }
        ));
    }

    #[test]
    fn test_starvation_guard_scheduling_promotion_under_continuous_high_priority() {
        let mut guard = SubpathStarvationGuard::new();
        let now_ns = 1_000_000_000;
        let sid = 3;
        guard.register_subpath(sid, now_ns);

        let mut pacer = SubpathPacer::new(sid, 20_000_000, 10, now_ns);

        // Enqueue 1 BestEffort packet
        let be_packet = PacedQueuedPacket::new(
            100,
            sid,
            FlowSliceClass::BestEffort,
            vec![9u8; 1200],
            now_ns,
        );
        pacer.enqueue(be_packet);

        // Enqueue multiple MissionCritical packets
        for i in 1..=10 {
            let mc_packet = PacedQueuedPacket::new(
                i,
                sid,
                FlowSliceClass::MissionCritical,
                vec![1u8; 800],
                now_ns,
            );
            pacer.enqueue(mc_packet);
        }

        // Simulate continuous higher priority serves
        for _ in 0..65 {
            guard.record_packet_scheduled(sid, FlowSliceClass::MissionCritical, now_ns);
        }

        // Pacer queue now has BestEffort starved by consecutive higher serves (> 64)
        let starved_candidate = guard.evaluate_scheduling_starvation(sid, &pacer, now_ns);
        assert_eq!(starved_candidate, Some(FlowSliceClass::BestEffort));

        // Polling with starvation guard must prioritize and dequeue the BestEffort packet!
        let poll_res = guard.poll_with_starvation_guard(sid, &mut pacer, now_ns);
        match poll_res {
            PacingPollResult::Ready(packet) => {
                assert_eq!(packet.packet_id, 100);
                assert_eq!(packet.slice_class, FlowSliceClass::BestEffort);
            }
            _ => panic!("Expected Ready packet with anti-starvation promotion"),
        }

        let telem = guard.subpath_telemetry(sid).unwrap();
        let be = telem
            .slices
            .iter()
            .find(|s| s.slice_class == FlowSliceClass::BestEffort)
            .unwrap();
        assert_eq!(be.total_promoted_packets, 1);
        assert_eq!(be.consecutive_higher_priority_serves, 0);
    }

    #[test]
    fn test_starvation_guard_strict_urllc_sla_shielding() {
        let mut guard = SubpathStarvationGuard::new();
        let now_ns = 1_000_000_000;
        let sid = 4;
        guard.register_subpath(sid, now_ns);

        let mut pacer = SubpathPacer::new(sid, 20_000_000, 10, now_ns);

        // Enqueue 1 BestEffort packet
        pacer.enqueue(PacedQueuedPacket::new(
            1,
            sid,
            FlowSliceClass::BestEffort,
            vec![7u8; 1000],
            now_ns,
        ));

        // Enqueue 1 UltraLowLatency packet
        pacer.enqueue(PacedQueuedPacket::new(
            2,
            sid,
            FlowSliceClass::UltraLowLatency,
            vec![8u8; 128],
            now_ns,
        ));

        // Trigger BestEffort starvation condition
        for _ in 0..70 {
            guard.record_packet_scheduled(sid, FlowSliceClass::MissionCritical, now_ns);
        }

        // Even though BestEffort is starved, UltraLowLatency is actively waiting in queue!
        // Anti-starvation promotion MUST yield to URLLC to safeguard strict latency SLA!
        let starved_candidate = guard.evaluate_scheduling_starvation(sid, &pacer, now_ns);
        assert_eq!(starved_candidate, None);

        // Polling with guard must return the UltraLowLatency packet, not BestEffort
        let poll_res = guard.poll_with_starvation_guard(sid, &mut pacer, now_ns);
        match poll_res {
            PacingPollResult::Ready(packet) => {
                assert_eq!(packet.packet_id, 2);
                assert_eq!(packet.slice_class, FlowSliceClass::UltraLowLatency);
            }
            _ => panic!("Expected Ready for URLLC packet"),
        }

        let telem = guard.subpath_telemetry(sid).unwrap();
        let be = telem
            .slices
            .iter()
            .find(|s| s.slice_class == FlowSliceClass::BestEffort)
            .unwrap();
        assert!(be.total_suppressed_by_urllc >= 1);
    }

    #[test]
    fn test_starvation_guard_prometheus_metrics_export() {
        let mut guard = SubpathStarvationGuard::new();
        let now_ns = 1_000_000_000;
        let sid = 5;
        guard.register_subpath(sid, now_ns);

        guard.record_throttle(sid, FlowSliceClass::BestEffort, 1500, now_ns);
        guard.record_packet_scheduled(sid, FlowSliceClass::MissionCritical, now_ns);

        let metrics = guard.export_prometheus_metrics();
        assert!(metrics.contains("ifa_transport_subpath_starvation_severity"));
        assert!(metrics.contains("ifa_transport_subpath_starvation_events_total"));
        assert!(metrics.contains("ifa_transport_subpath_starvation_boost_events_total"));
        assert!(metrics.contains("ifa_transport_subpath_starvation_promoted_packets_total"));
        assert!(metrics.contains("ifa_transport_subpath_starvation_suppressed_by_urllc_total"));
        assert!(metrics.contains("subpath=\"5\""));
    }
}

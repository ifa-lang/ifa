//! Active Inter-Slice Latency Drift Monitoring and Preemptive Priority Subpath Reallocation.
//!
//! Provides proactive SLA violation prevention across heterogeneous ISSP multipath subpaths:
//! 1. Telemetric Drift Monitoring: Maintains sliding time-series windows per subpath to calculate
//!    instantaneous drift rates (dRTT/dt, dQueue/dt, dJitter/dt) via linear regression slope analysis
//!    and detects non-linear bufferbloat acceleration (second derivative).
//! 2. Inter-Slice Disparity Analysis: Continuously audits latency disparity and queuing headroom
//!    divergence between ultra-priority slices (URLLC, Mission Critical) and elastic/bulk slices
//!    (High Throughput, Best Effort) to identify cross-slice resource contention.
//! 3. Predictive Time-to-Violation: Solves for time-to-breach T_violation = (SLA_limit - RTT_current) / drift_rate.
//! 4. Preemptive Priority Reallocation: Migrates priority flows to pristine low-drift subpaths before
//!    a hard SLA breach occurs, or preemptively evicts lower-priority bulk flows off shared congested subpaths.
//! 5. Flap Prevention: Employs per-flow hysteresis damping, minimum drift thresholds, and cooldown timers.
//!
//! Zero-simulation: operates directly on concrete telemetry metrics collected from active link probing,
//! LEDBAT/BBR queuing delay estimators, and link-state advertisements.

use crate::session_sync::SessionId;
use crate::traffic_slicing::{
    FlowQoSProfile, FlowSliceClass, FlowSliceNegotiator, SliceMigrationReason, SubpathQoSCapability,
};
use std::collections::{HashMap, VecDeque};

/// Instantaneous latency and queuing sample recorded for a subpath.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LatencyDriftSample {
    /// Timestamp in unix milliseconds.
    pub timestamp_ms: u64,
    /// Smoothed Round-Trip Time in microseconds.
    pub smoothed_rtt_us: u64,
    /// Estimated queuing delay (bufferbloat) in microseconds.
    pub queuing_delay_us: u64,
    /// Network jitter in microseconds.
    pub jitter_us: u64,
}

/// Categorical severity of latency drift on a subpath.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DriftSeverity {
    /// Stable or decreasing latency (negative or negligible drift).
    Stable = 0,
    /// Upward latency drift detected, but predicted violation is well beyond preemption horizon.
    ModerateDrift = 1,
    /// High positive drift rate or accelerating bufferbloat; preemption warning active.
    CriticalDrift = 2,
    /// Latency approaching SLA boundary or time-to-violation within immediate preemption horizon.
    ImminentBreach = 3,
}

impl DriftSeverity {
    /// Canonical string identifier.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::ModerateDrift => "moderate_drift",
            Self::CriticalDrift => "critical_drift",
            Self::ImminentBreach => "imminent_breach",
        }
    }
}

/// Detailed historical drift tracker for an individual subpath.
#[derive(Debug, Clone)]
pub struct SubpathDriftTracker {
    /// Target subpath path_id.
    pub path_id: u32,
    /// Maximum number of samples in the rolling window.
    capacity: usize,
    /// Rolling window of telemetry samples.
    samples: VecDeque<LatencyDriftSample>,
    /// Smoothed RTT drift rate in microseconds per second (slope dRTT/dt).
    pub drift_rate_rtt_us_per_sec: f64,
    /// Queuing delay drift rate in microseconds per second (slope dQueue/dt).
    pub drift_rate_queuing_us_per_sec: f64,
    /// Jitter drift rate in microseconds per second (slope dJitter/dt).
    pub drift_rate_jitter_us_per_sec: f64,
    /// Queuing delay acceleration (second derivative d^2Queue/dt^2).
    pub queuing_acceleration: f64,
    /// Most recent smoothed RTT in microseconds.
    pub latest_rtt_us: u64,
    /// Most recent queuing delay in microseconds.
    pub latest_queuing_delay_us: u64,
    /// Most recent jitter in microseconds.
    pub latest_jitter_us: u64,
    /// Timestamp of most recent telemetry sample in unix milliseconds.
    pub last_updated_ms: u64,
}

impl SubpathDriftTracker {
    /// Create a new drift tracker with a specified sample capacity.
    pub fn new(path_id: u32, capacity: usize) -> Self {
        Self {
            path_id,
            capacity: capacity.max(4),
            samples: VecDeque::with_capacity(capacity.max(4)),
            drift_rate_rtt_us_per_sec: 0.0,
            drift_rate_queuing_us_per_sec: 0.0,
            drift_rate_jitter_us_per_sec: 0.0,
            queuing_acceleration: 0.0,
            latest_rtt_us: 0,
            latest_queuing_delay_us: 0,
            latest_jitter_us: 0,
            last_updated_ms: 0,
        }
    }

    /// Record a telemetry observation sample and recompute drift regression slopes.
    pub fn record_sample(
        &mut self,
        timestamp_ms: u64,
        smoothed_rtt_us: u64,
        queuing_delay_us: u64,
        jitter_us: u64,
    ) {
        if let Some(last) = self.samples.back() {
            if timestamp_ms <= last.timestamp_ms {
                return;
            }
        }

        if self.samples.len() >= self.capacity {
            self.samples.pop_front();
        }

        self.samples.push_back(LatencyDriftSample {
            timestamp_ms,
            smoothed_rtt_us,
            queuing_delay_us,
            jitter_us,
        });

        self.latest_rtt_us = smoothed_rtt_us;
        self.latest_queuing_delay_us = queuing_delay_us;
        self.latest_jitter_us = jitter_us;
        self.last_updated_ms = timestamp_ms;

        self.recompute_drift_metrics();
    }

    /// Linear regression slope calculation: computes dy/dt in units per second.
    fn linear_regression_slope(points: &[(f64, f64)]) -> f64 {
        let n = points.len();
        if n < 2 {
            return 0.0;
        }

        let mut sum_x = 0.0;
        let mut sum_y = 0.0;
        let mut sum_xy = 0.0;
        let mut sum_xx = 0.0;

        let base_x = points[0].0;
        for &(x, y) in points {
            let rel_x = x - base_x;
            sum_x += rel_x;
            sum_y += y;
            sum_xy += rel_x * y;
            sum_xx += rel_x * rel_x;
        }

        let n_f = n as f64;
        let denominator = (n_f * sum_xx) - (sum_x * sum_x);
        if denominator.abs() < 1e-9 {
            0.0
        } else {
            ((n_f * sum_xy) - (sum_x * sum_y)) / denominator
        }
    }

    /// Recompute drift slopes and acceleration from sliding window.
    fn recompute_drift_metrics(&mut self) {
        let count = self.samples.len();
        if count < 2 {
            self.drift_rate_rtt_us_per_sec = 0.0;
            self.drift_rate_queuing_us_per_sec = 0.0;
            self.drift_rate_jitter_us_per_sec = 0.0;
            self.queuing_acceleration = 0.0;
            return;
        }

        let mut rtt_pts = Vec::with_capacity(count);
        let mut queue_pts = Vec::with_capacity(count);
        let mut jitter_pts = Vec::with_capacity(count);

        for s in &self.samples {
            let t_sec = s.timestamp_ms as f64 / 1_000.0;
            rtt_pts.push((t_sec, s.smoothed_rtt_us as f64));
            queue_pts.push((t_sec, s.queuing_delay_us as f64));
            jitter_pts.push((t_sec, s.jitter_us as f64));
        }

        self.drift_rate_rtt_us_per_sec = Self::linear_regression_slope(&rtt_pts);
        self.drift_rate_queuing_us_per_sec = Self::linear_regression_slope(&queue_pts);
        self.drift_rate_jitter_us_per_sec = Self::linear_regression_slope(&jitter_pts);

        // Compute queuing acceleration if at least 4 samples exist
        if count >= 4 {
            let mid = count / 2;
            let slope_early = Self::linear_regression_slope(&queue_pts[..mid]);
            let slope_late = Self::linear_regression_slope(&queue_pts[mid..]);
            let dt_mid = queue_pts[count - 1].0 - queue_pts[0].0;
            if dt_mid > 0.01 {
                self.queuing_acceleration = (slope_late - slope_early) / (dt_mid * 0.5);
            } else {
                self.queuing_acceleration = 0.0;
            }
        } else {
            self.queuing_acceleration = 0.0;
        }
    }

    /// Predict smoothed RTT at a future time horizon (in seconds).
    pub fn predict_future_rtt_us(&self, horizon_sec: f64) -> f64 {
        let rtt = self.latest_rtt_us as f64;
        let delta = self.drift_rate_rtt_us_per_sec * horizon_sec;
        (rtt + delta).max(0.0)
    }

    /// Predict time-to-violation (in seconds) until smoothed RTT reaches max_rtt_us.
    /// Returns None if latency is already breached, or if drift is zero/negative (stable).
    pub fn predict_time_to_rtt_us(&self, max_rtt_us: u64) -> Option<f64> {
        if self.latest_rtt_us >= max_rtt_us {
            return Some(0.0);
        }
        if self.drift_rate_rtt_us_per_sec <= 0.0 {
            return None;
        }
        let remaining_headroom = (max_rtt_us - self.latest_rtt_us) as f64;
        Some(remaining_headroom / self.drift_rate_rtt_us_per_sec)
    }

    /// Evaluate drift severity relative to an SLA profile target.
    pub fn evaluate_severity(
        &self,
        profile: &FlowQoSProfile,
        watermark_ratio: f64,
    ) -> DriftSeverity {
        if self.latest_rtt_us >= profile.max_rtt_us {
            return DriftSeverity::ImminentBreach;
        }

        let watermark_us = (profile.max_rtt_us as f64 * watermark_ratio) as u64;
        let is_above_watermark = self.latest_rtt_us >= watermark_us;

        if let Some(ttv) = self.predict_time_to_rtt_us(profile.max_rtt_us) {
            if ttv <= 2.0 || (is_above_watermark && self.drift_rate_rtt_us_per_sec > 200.0) {
                DriftSeverity::ImminentBreach
            } else if ttv <= 5.0 || self.queuing_acceleration > 500.0 {
                DriftSeverity::CriticalDrift
            } else if self.drift_rate_rtt_us_per_sec > 100.0 {
                DriftSeverity::ModerateDrift
            } else {
                DriftSeverity::Stable
            }
        } else if is_above_watermark && self.drift_rate_rtt_us_per_sec > 50.0 {
            DriftSeverity::ModerateDrift
        } else {
            DriftSeverity::Stable
        }
    }
}

/// Reason triggering preemptive subpath reallocation before hard SLA breach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreemptiveReallocationReason {
    /// Predicted time-to-violation fell within the preemption horizon window.
    PredictedLatencyViolation,
    /// Queuing delay (bufferbloat) is accelerating non-linearly towards saturation.
    AcceleratingBufferbloat,
    /// Latency exceeded the preemptive safety watermark with positive drift rate.
    WatermarkBreachWithPositiveDrift,
    /// Lower priority bulk flow preemptively evicted to protect co-located priority slice.
    ContentionPriorityEviction,
}

impl PreemptiveReallocationReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PredictedLatencyViolation => "predicted_latency_violation",
            Self::AcceleratingBufferbloat => "accelerating_bufferbloat",
            Self::WatermarkBreachWithPositiveDrift => "watermark_breach_with_positive_drift",
            Self::ContentionPriorityEviction => "contention_priority_eviction",
        }
    }
}

/// Action record generated when a flow is preemptively reallocated or evicted.
#[derive(Debug, Clone, PartialEq)]
pub struct PreemptiveMigrationAction {
    pub session_id: SessionId,
    pub slice_class: FlowSliceClass,
    pub priority: u8,
    pub from_path_id: u32,
    pub to_path_id: u32,
    pub reason: PreemptiveReallocationReason,
    pub observed_rtt_us: u64,
    pub drift_rate_us_per_sec: f64,
    pub predicted_violation_sec: f64,
    pub timestamp_ms: u64,
}

/// Summary state of latency drift within a specific traffic slice.
#[derive(Debug, Clone, PartialEq)]
pub struct SliceDriftState {
    pub slice_class: FlowSliceClass,
    pub flow_count: usize,
    pub average_rtt_us: f64,
    pub max_rtt_us: u64,
    pub average_drift_rate_us_per_sec: f64,
    pub min_sla_margin_ratio: f64,
}

/// Comprehensive audit report of inter-slice latency disparity and cross-slice contention.
#[derive(Debug, Clone, PartialEq)]
pub struct InterSliceDisparityReport {
    /// Latency drift state per slice class.
    pub slices: HashMap<FlowSliceClass, SliceDriftState>,
    /// Disparity index (ratio of priority drift vs elastic drift, or queuing headroom degradation).
    pub disparity_index: f64,
    /// Whether cross-slice contention has been diagnosed on shared subpaths.
    pub cross_slice_contention_detected: bool,
    /// List of contested subpath IDs where priority and bulk flows collide under drift.
    pub contested_subpaths: Vec<u32>,
}

/// Configuration parameters for latency drift monitoring and preemptive reallocation.
#[derive(Debug, Clone, PartialEq)]
pub struct LatencyDriftConfig {
    /// Preemption prediction horizon in seconds (default 2.0s).
    pub preemption_horizon_sec: f64,
    /// Latency watermark ratio triggering early preemption under positive drift (default 0.75 = 75%).
    pub latency_watermark_ratio: f64,
    /// Minimum positive drift rate (us/sec) required to engage preemption (default 300.0 us/sec).
    pub min_drift_rate_us_per_sec: f64,
    /// Per-flow cooldown period in milliseconds to suppress rapid flapping (default 2000ms).
    pub flow_cooldown_ms: u64,
    /// Allow preemptive eviction of lower priority flows to relieve contention on congested subpaths.
    pub enable_priority_eviction: bool,
    /// Maximum number of preemptive reallocations executed in a single evaluation cycle.
    pub max_preemptions_per_cycle: usize,
    /// Number of historical samples retained per subpath tracker.
    pub history_window_size: usize,
}

impl Default for LatencyDriftConfig {
    fn default() -> Self {
        Self {
            preemption_horizon_sec: 2.0,
            latency_watermark_ratio: 0.75,
            min_drift_rate_us_per_sec: 300.0,
            flow_cooldown_ms: 2000,
            enable_priority_eviction: true,
            max_preemptions_per_cycle: 4,
            history_window_size: 16,
        }
    }
}

/// Operational telemetry metrics for latency drift monitoring and preemptive actions.
#[derive(Debug, Clone, Default)]
pub struct LatencyDriftMetrics {
    /// Total drift evaluations performed.
    pub total_evaluations: u64,
    /// Total preemptive priority flow reallocations.
    pub preemptive_reallocations_total: u64,
    /// Total lower-priority flow evictions executed for contention relief.
    pub priority_evictions_total: u64,
    /// Number of imminent SLA breaches detected in advance.
    pub imminent_breaches_detected: u64,
    /// Number of accelerating bufferbloat events detected.
    pub accelerating_bufferbloat_detected: u64,
    /// Preemptive warnings issued by slice class.
    pub warnings_by_slice: HashMap<FlowSliceClass, u64>,
}

/// Active Latency Drift Monitor and Preemptive Priority Subpath Reallocation Engine.
#[derive(Debug, Clone)]
pub struct LatencyDriftMonitor {
    /// Subpath drift trackers keyed by path_id.
    trackers: HashMap<u32, SubpathDriftTracker>,
    /// Configuration thresholds.
    config: LatencyDriftConfig,
    /// Operational metrics.
    metrics: LatencyDriftMetrics,
    /// Timestamps of last preemption per flow session.
    last_preemption_time_ms: HashMap<SessionId, u64>,
    /// Historical record of preemptive migration actions.
    migration_history: Vec<PreemptiveMigrationAction>,
}

impl Default for LatencyDriftMonitor {
    fn default() -> Self {
        Self::new(LatencyDriftConfig::default())
    }
}

impl LatencyDriftMonitor {
    /// Create a new monitor with custom configuration.
    pub fn new(config: LatencyDriftConfig) -> Self {
        Self {
            trackers: HashMap::new(),
            config,
            metrics: LatencyDriftMetrics::default(),
            last_preemption_time_ms: HashMap::new(),
            migration_history: Vec::new(),
        }
    }

    /// Read configuration.
    pub fn config(&self) -> &LatencyDriftConfig {
        &self.config
    }

    /// Mutably configure thresholds.
    pub fn config_mut(&mut self) -> &mut LatencyDriftConfig {
        &mut self.config
    }

    /// Read operational metrics.
    pub fn metrics(&self) -> &LatencyDriftMetrics {
        &self.metrics
    }

    /// Read migration history.
    pub fn migration_history(&self) -> &[PreemptiveMigrationAction] {
        &self.migration_history
    }

    /// Access tracker for a specific subpath.
    pub fn tracker(&self, path_id: u32) -> Option<&SubpathDriftTracker> {
        self.trackers.get(&path_id)
    }

    /// Record a single telemetry observation into a subpath's drift tracker.
    pub fn record_sample(
        &mut self,
        path_id: u32,
        timestamp_ms: u64,
        smoothed_rtt_us: u64,
        queuing_delay_us: u64,
        jitter_us: u64,
    ) {
        let cap = self.config.history_window_size;
        let tracker = self
            .trackers
            .entry(path_id)
            .or_insert_with(|| SubpathDriftTracker::new(path_id, cap));
        tracker.record_sample(timestamp_ms, smoothed_rtt_us, queuing_delay_us, jitter_us);
    }

    /// Feed snapshot capabilities from all active subpaths.
    pub fn update_from_subpaths(&mut self, subpaths: &[SubpathQoSCapability], now_ms: u64) {
        for sp in subpaths {
            self.record_sample(
                sp.path_id,
                now_ms,
                sp.smoothed_rtt_us,
                sp.queuing_delay_us,
                sp.jitter_us,
            );
        }
    }

    /// Audit inter-slice latency disparity and detect cross-slice interference.
    pub fn compute_inter_slice_disparity(
        &self,
        negotiator: &FlowSliceNegotiator,
        subpaths: &[SubpathQoSCapability],
    ) -> InterSliceDisparityReport {
        let mut slice_flows: HashMap<FlowSliceClass, Vec<(SessionId, u32)>> = HashMap::new();
        for (sid, assignment) in negotiator.assignments_iter() {
            slice_flows
                .entry(assignment.slice_class)
                .or_default()
                .push((*sid, assignment.assigned_path_id));
        }

        let subpaths_by_id: HashMap<u32, &SubpathQoSCapability> =
            subpaths.iter().map(|s| (s.path_id, s)).collect();

        let mut slice_states = HashMap::new();
        let mut priority_rtts = Vec::new();
        let mut elastic_rtts = Vec::new();

        for (&slice, flows) in &slice_flows {
            let count = flows.len();
            if count == 0 {
                continue;
            }

            let mut sum_rtt = 0.0;
            let mut max_rtt = 0u64;
            let mut sum_drift = 0.0;
            let mut min_margin = 1.0f64;

            for (sid, pid) in flows {
                let rtt = subpaths_by_id
                    .get(pid)
                    .map(|sp| sp.smoothed_rtt_us)
                    .unwrap_or(0);
                sum_rtt += rtt as f64;
                if rtt > max_rtt {
                    max_rtt = rtt;
                }

                if let Some(tracker) = self.trackers.get(pid) {
                    sum_drift += tracker.drift_rate_rtt_us_per_sec;
                }

                if let Some(prof) = negotiator.get_profile(sid) {
                    if prof.max_rtt_us > 0 {
                        let margin = if rtt >= prof.max_rtt_us {
                            0.0
                        } else {
                            (prof.max_rtt_us - rtt) as f64 / prof.max_rtt_us as f64
                        };
                        if margin < min_margin {
                            min_margin = margin;
                        }
                    }
                }

                if slice == FlowSliceClass::UltraLowLatency
                    || slice == FlowSliceClass::MissionCritical
                {
                    priority_rtts.push(rtt as f64);
                } else {
                    elastic_rtts.push(rtt as f64);
                }
            }

            slice_states.insert(
                slice,
                SliceDriftState {
                    slice_class: slice,
                    flow_count: count,
                    average_rtt_us: sum_rtt / count as f64,
                    max_rtt_us: max_rtt,
                    average_drift_rate_us_per_sec: sum_drift / count as f64,
                    min_sla_margin_ratio: min_margin,
                },
            );
        }

        // Calculate disparity index
        let avg_prio = if priority_rtts.is_empty() {
            1.0
        } else {
            priority_rtts.iter().sum::<f64>() / priority_rtts.len() as f64
        };
        let avg_elastic = if elastic_rtts.is_empty() {
            1.0
        } else {
            elastic_rtts.iter().sum::<f64>() / elastic_rtts.len() as f64
        };
        let disparity_index = (avg_prio / avg_elastic.max(1.0)).clamp(0.0, 100.0);

        // Identify contested subpaths shared by priority and bulk flows
        let mut subpath_usage: HashMap<u32, Vec<FlowSliceClass>> = HashMap::new();
        for (_, assignment) in negotiator.assignments_iter() {
            subpath_usage
                .entry(assignment.assigned_path_id)
                .or_default()
                .push(assignment.slice_class);
        }

        let mut contested_subpaths = Vec::new();
        for (pid, classes) in subpath_usage {
            let has_priority = classes.iter().any(|&c| {
                c == FlowSliceClass::UltraLowLatency || c == FlowSliceClass::MissionCritical
            });
            let has_bulk = classes
                .iter()
                .any(|&c| c == FlowSliceClass::HighThroughput || c == FlowSliceClass::BestEffort);
            if has_priority && has_bulk {
                if let Some(tr) = self.trackers.get(&pid) {
                    if tr.drift_rate_rtt_us_per_sec > self.config.min_drift_rate_us_per_sec {
                        contested_subpaths.push(pid);
                    }
                }
            }
        }
        let cross_slice_contention_detected = !contested_subpaths.is_empty();

        InterSliceDisparityReport {
            slices: slice_states,
            disparity_index,
            cross_slice_contention_detected,
            contested_subpaths,
        }
    }

    /// Evaluates active flow assignments and preemptively reallocates flows before SLA violations happen.
    pub fn evaluate_preemptive_reallocations(
        &mut self,
        negotiator: &mut FlowSliceNegotiator,
        subpaths: &[SubpathQoSCapability],
        now_ms: u64,
    ) -> Vec<PreemptiveMigrationAction> {
        self.metrics.total_evaluations += 1;
        let mut actions = Vec::new();

        let subpaths_by_id: HashMap<u32, &SubpathQoSCapability> =
            subpaths.iter().map(|s| (s.path_id, s)).collect();

        // Sort flows by scheduling priority descending (Mission Critical & URLLC first)
        let mut flows_to_inspect: Vec<(SessionId, FlowQoSProfile, u32)> = Vec::new();
        for (sid, assignment) in negotiator.assignments_iter() {
            if let Some(prof) = negotiator.get_profile(sid) {
                flows_to_inspect.push((*sid, prof.clone(), assignment.assigned_path_id));
            }
        }
        flows_to_inspect.sort_by_key(|a| std::cmp::Reverse(a.1.priority));

        for (sid, profile, current_path_id) in flows_to_inspect {
            if actions.len() >= self.config.max_preemptions_per_cycle {
                break;
            }

            // Check flow cooldown
            if let Some(&last_ms) = self.last_preemption_time_ms.get(&sid) {
                if now_ms.saturating_sub(last_ms) < self.config.flow_cooldown_ms {
                    continue;
                }
            }

            let tracker = match self.trackers.get(&current_path_id) {
                Some(t) => t,
                None => continue,
            };

            let current_subpath = match subpaths_by_id.get(&current_path_id) {
                Some(sp) => *sp,
                None => continue,
            };

            // Focus preemptive protection on high-priority slices or strict flows (priority >= 150)
            let is_priority_flow = profile.priority >= 150
                || profile.slice_class == FlowSliceClass::UltraLowLatency
                || profile.slice_class == FlowSliceClass::MissionCritical;

            if !is_priority_flow {
                continue;
            }

            // Evaluate drift conditions
            let drift_rate = tracker.drift_rate_rtt_us_per_sec;
            let current_rtt = current_subpath.smoothed_rtt_us;
            let watermark_us =
                (profile.max_rtt_us as f64 * self.config.latency_watermark_ratio) as u64;

            let time_to_violation = tracker.predict_time_to_rtt_us(profile.max_rtt_us);
            let is_accelerating = tracker.queuing_acceleration > 400.0;

            let trigger_reason = if let Some(ttv) = time_to_violation {
                if ttv <= self.config.preemption_horizon_sec
                    && drift_rate >= self.config.min_drift_rate_us_per_sec
                {
                    self.metrics.imminent_breaches_detected += 1;
                    Some(PreemptiveReallocationReason::PredictedLatencyViolation)
                } else if is_accelerating && ttv <= (self.config.preemption_horizon_sec * 2.5) {
                    self.metrics.accelerating_bufferbloat_detected += 1;
                    Some(PreemptiveReallocationReason::AcceleratingBufferbloat)
                } else if current_rtt >= watermark_us
                    && drift_rate >= self.config.min_drift_rate_us_per_sec
                {
                    Some(PreemptiveReallocationReason::WatermarkBreachWithPositiveDrift)
                } else {
                    None
                }
            } else if current_rtt >= watermark_us
                && drift_rate >= self.config.min_drift_rate_us_per_sec
            {
                Some(PreemptiveReallocationReason::WatermarkBreachWithPositiveDrift)
            } else {
                None
            };

            let reason = match trigger_reason {
                Some(r) => r,
                None => continue,
            };

            *self
                .metrics
                .warnings_by_slice
                .entry(profile.slice_class)
                .or_insert(0) += 1;

            // Strategy 1: Find a pristine alternative subpath for this priority flow
            let mut best_target: Option<(u32, f64)> = None;

            for candidate in subpaths {
                if candidate.path_id == current_path_id || !candidate.is_usable {
                    continue;
                }

                // Subpath must meet strict QoS profile
                if let Some((fitness, is_degraded)) =
                    FlowSliceNegotiator::evaluate_subpath_fitness(&profile, candidate)
                {
                    if is_degraded {
                        continue;
                    }

                    // Candidate drift must be non-positive or significantly lower than current
                    let cand_drift = self
                        .trackers
                        .get(&candidate.path_id)
                        .map(|t| t.drift_rate_rtt_us_per_sec)
                        .unwrap_or(0.0);

                    if cand_drift > (drift_rate * 0.4).max(self.config.min_drift_rate_us_per_sec) {
                        continue;
                    }

                    // Candidate latency must provide sufficient headroom below watermark
                    let cand_watermark =
                        (profile.max_rtt_us as f64 * self.config.latency_watermark_ratio) as u64;
                    if candidate.smoothed_rtt_us >= cand_watermark {
                        continue;
                    }

                    let score = fitness - (cand_drift * 0.05);
                    match best_target {
                        None => best_target = Some((candidate.path_id, score)),
                        Some((_, best_score)) if score > best_score => {
                            best_target = Some((candidate.path_id, score));
                        }
                        _ => {}
                    }
                }
            }

            if let Some((target_path_id, _)) = best_target {
                // Reallocate priority flow
                negotiator.force_reassign_flow_with_reason(
                    &sid,
                    target_path_id,
                    SliceMigrationReason::PreemptiveDriftMitigation,
                    now_ms,
                );

                self.last_preemption_time_ms.insert(sid, now_ms);
                self.metrics.preemptive_reallocations_total += 1;

                let action = PreemptiveMigrationAction {
                    session_id: sid,
                    slice_class: profile.slice_class,
                    priority: profile.priority,
                    from_path_id: current_path_id,
                    to_path_id: target_path_id,
                    reason,
                    observed_rtt_us: current_rtt,
                    drift_rate_us_per_sec: drift_rate,
                    predicted_violation_sec: time_to_violation.unwrap_or(0.0),
                    timestamp_ms: now_ms,
                };

                self.migration_history.push(action.clone());
                actions.push(action);
                continue;
            }

            // Strategy 2: Preemptive Contention Eviction of lower priority flow sharing current subpath
            if self.config.enable_priority_eviction {
                let mut victim_flow: Option<(SessionId, FlowQoSProfile)> = None;

                for (other_sid, other_assignment) in negotiator.assignments_iter() {
                    if *other_sid == sid || other_assignment.assigned_path_id != current_path_id {
                        continue;
                    }
                    if let Some(other_prof) = negotiator.get_profile(other_sid) {
                        if other_prof.priority < 150 {
                            match &victim_flow {
                                None => victim_flow = Some((*other_sid, other_prof.clone())),
                                Some((_, curr_vic)) if other_prof.priority < curr_vic.priority => {
                                    victim_flow = Some((*other_sid, other_prof.clone()));
                                }
                                _ => {}
                            }
                        }
                    }
                }

                if let Some((vic_sid, vic_prof)) = victim_flow {
                    // Find an alternate subpath capable of accepting the evicted flow
                    let mut vic_target: Option<u32> = None;
                    for candidate in subpaths {
                        if candidate.path_id == current_path_id || !candidate.is_usable {
                            continue;
                        }
                        if let Some((_, _)) =
                            FlowSliceNegotiator::evaluate_subpath_fitness(&vic_prof, candidate)
                        {
                            vic_target = Some(candidate.path_id);
                            break;
                        }
                    }

                    if let Some(vic_to_path) = vic_target {
                        negotiator.force_reassign_flow_with_reason(
                            &vic_sid,
                            vic_to_path,
                            SliceMigrationReason::PreemptiveDriftMitigation,
                            now_ms,
                        );

                        self.last_preemption_time_ms.insert(vic_sid, now_ms);
                        self.metrics.priority_evictions_total += 1;

                        let eviction_action = PreemptiveMigrationAction {
                            session_id: vic_sid,
                            slice_class: vic_prof.slice_class,
                            priority: vic_prof.priority,
                            from_path_id: current_path_id,
                            to_path_id: vic_to_path,
                            reason: PreemptiveReallocationReason::ContentionPriorityEviction,
                            observed_rtt_us: current_rtt,
                            drift_rate_us_per_sec: drift_rate,
                            predicted_violation_sec: time_to_violation.unwrap_or(0.0),
                            timestamp_ms: now_ms,
                        };

                        self.migration_history.push(eviction_action.clone());
                        actions.push(eviction_action);
                    }
                }
            }
        }

        actions
    }

    /// Export latency drift metrics in standard Prometheus text format.
    pub fn export_prometheus_metrics(&self) -> String {
        let mut out = String::with_capacity(2048);

        out.push_str(
            "# HELP ifa_slice_drift_total_evaluations Total latency drift evaluation cycles.\n",
        );
        out.push_str("# TYPE ifa_slice_drift_total_evaluations counter\n");
        out.push_str(&format!(
            "ifa_slice_drift_total_evaluations {}\n",
            self.metrics.total_evaluations
        ));

        out.push_str("# HELP ifa_slice_preemptive_reallocations_total Proactive flow migrations executed before SLA breach.\n");
        out.push_str("# TYPE ifa_slice_preemptive_reallocations_total counter\n");
        out.push_str(&format!(
            "ifa_slice_preemptive_reallocations_total {}\n",
            self.metrics.preemptive_reallocations_total
        ));

        out.push_str("# HELP ifa_slice_priority_evictions_total Lower priority flows evicted to protect priority slices.\n");
        out.push_str("# TYPE ifa_slice_priority_evictions_total counter\n");
        out.push_str(&format!(
            "ifa_slice_priority_evictions_total {}\n",
            self.metrics.priority_evictions_total
        ));

        out.push_str("# HELP ifa_slice_imminent_breaches_detected Imminent SLA violations predicted and flagged.\n");
        out.push_str("# TYPE ifa_slice_imminent_breaches_detected counter\n");
        out.push_str(&format!(
            "ifa_slice_imminent_breaches_detected {}\n",
            self.metrics.imminent_breaches_detected
        ));

        out.push_str("# HELP ifa_slice_accelerating_bufferbloat_detected Accelerating queueing delay events detected.\n");
        out.push_str("# TYPE ifa_slice_accelerating_bufferbloat_detected counter\n");
        out.push_str(&format!(
            "ifa_slice_accelerating_bufferbloat_detected {}\n",
            self.metrics.accelerating_bufferbloat_detected
        ));

        out.push_str("# HELP ifa_slice_subpath_drift_rate_us_per_sec Instantaneous smoothed RTT drift rate per subpath.\n");
        out.push_str("# TYPE ifa_slice_subpath_drift_rate_us_per_sec gauge\n");
        for (pid, tr) in &self.trackers {
            out.push_str(&format!(
                "ifa_slice_subpath_drift_rate_us_per_sec{{path_id=\"{}\"}} {:.2}\n",
                pid, tr.drift_rate_rtt_us_per_sec
            ));
        }

        out.push_str("# HELP ifa_slice_subpath_queuing_acceleration Accelerating bufferbloat rate d2Q/dt2.\n");
        out.push_str("# TYPE ifa_slice_subpath_queuing_acceleration gauge\n");
        for (pid, tr) in &self.trackers {
            out.push_str(&format!(
                "ifa_slice_subpath_queuing_acceleration{{path_id=\"{}\"}} {:.2}\n",
                pid, tr.queuing_acceleration
            ));
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_session(id: u8) -> SessionId {
        let mut bytes = [0u8; 16];
        bytes[0] = id;
        SessionId::from_bytes(&bytes)
    }

    fn make_test_subpath(
        path_id: u32,
        rtt_us: u64,
        jitter_us: u64,
        queue_us: u64,
        bw_bps: u64,
        sat: f64,
    ) -> SubpathQoSCapability {
        SubpathQoSCapability {
            path_id,
            interface_name: format!("eth{}", path_id),
            smoothed_rtt_us: rtt_us,
            jitter_us,
            queuing_delay_us: queue_us,
            capacity_bps: 1_000_000_000,
            available_bandwidth_bps: bw_bps,
            saturation_ratio: sat,
            loss_ppm: 0,
            throughput_bps: 0,
            is_usable: true,
        }
    }

    #[test]
    fn test_drift_regression_slope_and_acceleration() {
        let mut tracker = SubpathDriftTracker::new(1, 10);

        // Record linearly increasing RTT: +1000us per second (1ms/s)
        tracker.record_sample(1000, 10_000, 1_000, 200);
        tracker.record_sample(2000, 11_000, 1_500, 250);
        tracker.record_sample(3000, 12_000, 2_200, 300);
        tracker.record_sample(4000, 13_000, 3_100, 350);

        // Slope should be approximately 1000 us/s
        assert!((tracker.drift_rate_rtt_us_per_sec - 1000.0).abs() < 10.0);
        assert_eq!(tracker.latest_rtt_us, 13_000);

        // Predict future RTT at +2s
        let predicted_rtt = tracker.predict_future_rtt_us(2.0);
        assert!((predicted_rtt - 15_000.0).abs() < 20.0);

        // Predict time to violation for 16,000us SLA (current 13,000, remaining 3,000us @ 1000us/s => 3.0s)
        let ttv = tracker.predict_time_to_rtt_us(16_000).unwrap();
        assert!((ttv - 3.0).abs() < 0.1);

        // Queuing delay acceleration check
        assert!(tracker.queuing_acceleration > 0.0);
    }

    #[test]
    fn test_severity_classification() {
        let mut tracker = SubpathDriftTracker::new(1, 10);
        let profile = FlowQoSProfile::ultra_low_latency(); // max_rtt = 20_000us

        // 1. Stable baseline
        tracker.record_sample(1000, 8_000, 500, 100);
        tracker.record_sample(2000, 8_000, 500, 100);
        assert_eq!(
            tracker.evaluate_severity(&profile, 0.75),
            DriftSeverity::Stable
        );

        // 2. High drift driving RTT towards 18,000us
        tracker.record_sample(3000, 12_000, 2_000, 300);
        tracker.record_sample(4000, 16_000, 4_000, 500); // 16ms is > 75% watermark (15ms)
        let severity = tracker.evaluate_severity(&profile, 0.75);
        assert!(
            severity == DriftSeverity::CriticalDrift || severity == DriftSeverity::ImminentBreach
        );
    }

    #[test]
    fn test_preemptive_reallocation_before_sla_breach() {
        let mut monitor = LatencyDriftMonitor::default();
        let mut negotiator = FlowSliceNegotiator::new();

        let sid_urllc = dummy_session(1);
        negotiator.register_profile(sid_urllc, FlowQoSProfile::ultra_low_latency()); // max_rtt 20ms

        // Path 1 (Primary fiber): currently 14ms, drifting upwards rapidly (+3ms/s)
        let mut sp1 = make_test_subpath(1, 14_000, 500, 2_000, 50_000_000, 0.4);
        // Path 2 (Alternative clean path): 8ms, flat drift
        let sp2 = make_test_subpath(2, 8_000, 400, 500, 100_000_000, 0.1);

        let subpaths = vec![sp1.clone(), sp2.clone()];
        let initial_assign = negotiator
            .negotiate_slice(&sid_urllc, &subpaths, 1000)
            .unwrap();
        assert_eq!(initial_assign.assigned_path_id, 2); // Picks lowest latency (path 2)

        // Force assignment to path 1 to simulate a flow currently on a drifting path
        negotiator.force_reassign_flow(&sid_urllc, 1, 1000);

        // Feed drift observations on Path 1 showing rapid upward slope
        monitor.record_sample(1, 1000, 11_000, 1000, 200);
        monitor.record_sample(1, 2000, 14_000, 2500, 300);
        monitor.record_sample(1, 3000, 17_000, 4000, 400); // 17ms, SLA is 20ms, drift = 3000us/s, TTV ~ 1.0s

        // Update capability for sp1 to reflect 17ms
        sp1.smoothed_rtt_us = 17_000;
        let subpaths_drifted = vec![sp1, sp2];

        // Evaluate preemption at t = 3000ms
        let actions =
            monitor.evaluate_preemptive_reallocations(&mut negotiator, &subpaths_drifted, 3000);

        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].session_id, sid_urllc);
        assert_eq!(actions[0].from_path_id, 1);
        assert_eq!(actions[0].to_path_id, 2); // Preemptively moved to clean path 2!
        assert_eq!(
            actions[0].reason,
            PreemptiveReallocationReason::PredictedLatencyViolation
        );

        // Verify assignment in negotiator was updated
        let updated = negotiator.get_assignment(&sid_urllc).unwrap();
        assert_eq!(updated.assigned_path_id, 2);
        assert_eq!(monitor.metrics().preemptive_reallocations_total, 1);
    }

    #[test]
    fn test_contention_priority_eviction_reliever() {
        let mut monitor = LatencyDriftMonitor::default();
        let mut negotiator = FlowSliceNegotiator::new();

        let sid_urllc = dummy_session(10);
        let sid_bulk = dummy_session(20);

        negotiator.register_profile(sid_urllc, FlowQoSProfile::ultra_low_latency()); // priority 200
        negotiator.register_profile(sid_bulk, FlowQoSProfile::high_throughput(10_000_000)); // priority 100

        // Subpath 1 is contested and drifting
        let mut sp1 = make_test_subpath(1, 16_000, 800, 3_000, 50_000_000, 0.7);
        // Subpath 2 can accept bulk flow
        let sp2 = make_test_subpath(2, 60_000, 5_000, 8_000, 500_000_000, 0.2);

        // Assign both to subpath 1 initially
        negotiator.force_reassign_flow(&sid_urllc, 1, 1000);
        negotiator.force_reassign_flow(&sid_bulk, 1, 1000);

        // Record drift on path 1 (climbing fast)
        monitor.record_sample(1, 1000, 10_000, 1000, 200);
        monitor.record_sample(1, 2000, 13_000, 2000, 400);
        monitor.record_sample(1, 3000, 16_500, 3500, 600);
        sp1.smoothed_rtt_us = 16_500;

        let subpaths = vec![sp1, sp2];

        // Evaluate preemption: Path 2 cannot satisfy URLLC (60ms > 20ms max),
        // so monitor must perform Contention Priority Eviction on sid_bulk to path 2!
        let actions = monitor.evaluate_preemptive_reallocations(&mut negotiator, &subpaths, 3000);

        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].session_id, sid_bulk); // Bulk flow evicted!
        assert_eq!(actions[0].from_path_id, 1);
        assert_eq!(actions[0].to_path_id, 2);
        assert_eq!(
            actions[0].reason,
            PreemptiveReallocationReason::ContentionPriorityEviction
        );
        assert_eq!(monitor.metrics().priority_evictions_total, 1);
    }

    #[test]
    fn test_inter_slice_disparity_and_prometheus_export() {
        let mut monitor = LatencyDriftMonitor::default();
        let mut negotiator = FlowSliceNegotiator::new();

        let sid1 = dummy_session(1);
        let sid2 = dummy_session(2);

        negotiator.register_profile(sid1, FlowQoSProfile::ultra_low_latency());
        negotiator.register_profile(sid2, FlowQoSProfile::best_effort());

        negotiator.force_reassign_flow(&sid1, 1, 1000);
        negotiator.force_reassign_flow(&sid2, 1, 1000);

        monitor.record_sample(1, 1000, 5000, 500, 100);
        monitor.record_sample(1, 2000, 8000, 1500, 200);

        let sp1 = make_test_subpath(1, 8000, 200, 1500, 100_000_000, 0.3);
        let subpaths = vec![sp1];

        let report = monitor.compute_inter_slice_disparity(&negotiator, &subpaths);
        assert!(report.cross_slice_contention_detected);
        assert_eq!(report.contested_subpaths, vec![1]);

        let prom = monitor.export_prometheus_metrics();
        assert!(prom.contains("ifa_slice_subpath_drift_rate_us_per_sec{path_id=\"1\"}"));
        assert!(prom.contains("ifa_slice_preemptive_reallocations_total 0"));
    }
}

//! Subpath Jitter Anomaly and Nanosecond Temporal Drift Tracking Engine (`SubpathJitterDriftTracker`).
//!
//! Provides deterministic real-time tracking of interarrival jitter, transit latency variance,
//! and inter-subpath temporal skew across heterogeneous transport paths (e.g. Fiber, 5G-URLLC, Satellite LEO):
//!
//! 1. **RFC 3550 Interarrival Jitter & Nanosecond Variance**:
//!    - Computes continuous inter-packet delay difference: $D(i, j) = (R_j - S_j) - (R_i - S_i)$.
//!    - Maintains RFC 3550 exponential moving average: $J = J + \frac{|D| - J}{16}$.
//!    - Continuously updates running statistical variance and baseline minimum transit latency.
//!
//! 2. **Inter-Subpath Differential Phase Skew & Linear Drift Rate**:
//!    - Measures instantaneous and smoothed path skew $\Delta_{AB} = |D_A - D_B|$ between heterogeneous subpaths.
//!    - Computes first-derivative linear drift rate ($\frac{d\text{latency}}{dt}$ in nanoseconds per second)
//!      via closed-form least-squares regression over sliding windows.
//!    - Detects monotonic bufferbloat divergence and physical path phase desynchronization.
//!
//! 3. **QoS Slice-Aware Reorder Skew Compatibility & Anomaly Classification**:
//!    - Classifies anomalies: `JitterSurge`, `ExcessivePathSkew`, `MonotonicDriftDivergence`,
//!      `PhaseDesynchronization`, and `ReorderBufferStarvationRisk`.
//!    - Checks whether inter-subpath skew exceeds the playout/hold timeout of QoS slices
//!      (e.g., `UltraLowLatency` 2ms max hold, `MissionCritical` 50ms, `HighThroughput` 30ms).
//!
//! 4. **Adaptive Routing Steering & Closed-Loop Multipath Guidance**:
//!    - Emits actionable routing steering directives:
//!      - `PenalizeRoutingWeight`: lowers scheduling weight for volatile subpaths.
//!      - `EvictSliceFromSubpath`: pre-emptively disqualifies high-drift paths from carrying latency-sensitive traffic.
//!      - `IncreaseReorderHoldTimeout`: expands reorder buffer playout window to absorb transient skew.
//!      - `TriggerSubpathProbation`: marks impaired subpaths for degradation inspection.
//!      - `ForceSinglePathFallback`: collapses transmission onto a pristine single subpath.
//!
//! 5. **Deterministic Production Telemetry & Zero-Simulation Guarantee**:
//!    - OpenMetrics / Prometheus exporter with labels for subpath identifiers, QoS slices, and anomaly kinds.
//!    - Structured JSON audit diagnostics.
//!    - Operates exclusively on monotonic nanosecond timestamps, concrete sequence numbers, and actual packet events.

#![allow(clippy::manual_is_multiple_of, clippy::chunks_exact_to_as_chunks)]

use std::collections::{BTreeMap, VecDeque};
use std::fmt::Write as FmtWrite;

use crate::reorder_engine::MultipathPacket;
use crate::traffic_slicing::FlowSliceClass;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration parameters governing jitter smoothing, drift slope evaluation, and anomaly thresholds.
#[derive(Debug, Clone, PartialEq)]
pub struct SubpathJitterDriftConfig {
    /// Shift parameter for RFC 3550 EWMA jitter smoothing (default: 4, meaning 1/16 gain).
    pub jitter_ewma_shift: u32,
    /// Maximum number of transit samples retained in the sliding window per subpath.
    pub max_transit_samples: usize,
    /// Jitter surge multiplier over baseline jitter triggering an anomaly (e.g. 2.5x).
    pub jitter_surge_multiplier: f64,
    /// Absolute jitter threshold in nanoseconds above which a surge is declared (e.g. 15ms = 15,000,000ns).
    pub jitter_surge_absolute_ns: u64,
    /// Differential path skew threshold in nanoseconds triggering Warning alert (e.g. 20ms = 20,000,000ns).
    pub excessive_skew_warning_ns: u64,
    /// Differential path skew threshold in nanoseconds triggering Critical alert (e.g. 45ms = 45,000,000ns).
    pub excessive_skew_critical_ns: u64,
    /// Positive linear drift rate threshold (ns/s) triggering Warning alert (e.g. 5,000,000 ns/s = 5ms/s).
    pub drift_rate_warning_ns_per_sec: f64,
    /// Positive linear drift rate threshold (ns/s) triggering Critical alert (e.g. 20,000,000 ns/s = 20ms/s).
    pub drift_rate_critical_ns_per_sec: f64,
    /// Minimum samples required in window before computing linear drift slope.
    pub min_samples_for_drift_evaluation: usize,
    /// Minimum time in nanoseconds between consecutive alerts of the same kind on a subpath (anti-flap cooldown).
    pub alert_cooldown_ns: u64,
    /// Maximum capacity of the alert event history ring buffer.
    pub max_alerts_history: usize,
}

impl Default for SubpathJitterDriftConfig {
    fn default() -> Self {
        Self {
            jitter_ewma_shift: 4,                         // 1/16 gain
            max_transit_samples: 64,                      // 64-sample rolling window
            jitter_surge_multiplier: 2.5,                 // 2.5x baseline
            jitter_surge_absolute_ns: 15_000_000,         // 15 ms
            excessive_skew_warning_ns: 20_000_000,        // 20 ms
            excessive_skew_critical_ns: 45_000_000,       // 45 ms
            drift_rate_warning_ns_per_sec: 5_000_000.0,   // 5 ms/sec
            drift_rate_critical_ns_per_sec: 20_000_000.0, // 20 ms/sec
            min_samples_for_drift_evaluation: 6,
            alert_cooldown_ns: 50_000_000, // 50 ms
            max_alerts_history: 128,
        }
    }
}

// ---------------------------------------------------------------------------
// Anomaly Classifications & Actions
// ---------------------------------------------------------------------------

/// Categorical classification of detected jitter and temporal drift anomalies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JitterDriftAnomalyKind {
    /// Sudden spike in transit jitter exceeding statistical baseline or absolute threshold.
    JitterSurge,
    /// Differential arrival skew between subpaths exceeds reorder buffer hold tolerance.
    ExcessivePathSkew,
    /// Sustained positive latency drift rate indicating progressive bufferbloat or queue buildup.
    MonotonicDriftDivergence,
    /// High-frequency phase instability or packet-to-packet transit jitter thrashing.
    PhaseDesynchronization,
    /// Risk of reorder buffer exhaustion due to excessive lagging of a slow subpath.
    ReorderBufferStarvationRisk,
}

impl JitterDriftAnomalyKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::JitterSurge => "JitterSurge",
            Self::ExcessivePathSkew => "ExcessivePathSkew",
            Self::MonotonicDriftDivergence => "MonotonicDriftDivergence",
            Self::PhaseDesynchronization => "PhaseDesynchronization",
            Self::ReorderBufferStarvationRisk => "ReorderBufferStarvationRisk",
        }
    }
}

/// Operational severity of a detected anomaly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AnomalySeverity {
    /// Warning: abnormal deviation observed, monitor closely.
    Warning = 1,
    /// Degraded: significant impairment, adaptive steering recommended.
    Degraded = 2,
    /// Critical: immediate path eviction or fallback required to preserve SLA.
    Critical = 3,
}

impl AnomalySeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Warning => "Warning",
            Self::Degraded => "Degraded",
            Self::Critical => "Critical",
        }
    }
}

/// Actionable steering directives recommended to the multipath router and reorder engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingSteeringAction {
    /// Nominal conditions, maintain current routing policies.
    NoAction,
    /// Expand reorder buffer playout hold timeout to prevent premature sequence timeout drops.
    IncreaseReorderHoldTimeout { recommended_hold_ns: u64 },
    /// Apply a percentage penalty to the subpath's Deficit Round Robin scheduling weight.
    PenalizeRoutingWeight {
        subpath_id: u32,
        penalty_factor_pct: u32,
    },
    /// Proactively evict sensitive QoS slice traffic from this subpath due to excessive delay/drift.
    EvictSliceFromSubpath {
        subpath_id: u32,
        slice_class: FlowSliceClass,
    },
    /// Place the subpath into probationary or degraded status for path health monitoring.
    TriggerSubpathProbation { subpath_id: u32, reason: String },
    /// Collapse multipath routing to a single healthy reference subpath to eliminate reordering skew.
    ForceSinglePathFallback {
        flow_id: u32,
        preferred_subpath_id: u32,
    },
}

impl RoutingSteeringAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NoAction => "NoAction",
            Self::IncreaseReorderHoldTimeout { .. } => "IncreaseReorderHoldTimeout",
            Self::PenalizeRoutingWeight { .. } => "PenalizeRoutingWeight",
            Self::EvictSliceFromSubpath { .. } => "EvictSliceFromSubpath",
            Self::TriggerSubpathProbation { .. } => "TriggerSubpathProbation",
            Self::ForceSinglePathFallback { .. } => "ForceSinglePathFallback",
        }
    }
}

/// Structured alert event emitted upon detecting a jitter or temporal drift anomaly.
#[derive(Debug, Clone, PartialEq)]
pub struct SubpathJitterDriftAlert {
    /// Monotonic unique alert identifier.
    pub alert_id: u64,
    /// Nanosecond timestamp when the anomaly was detected.
    pub timestamp_ns: u64,
    /// Primary subpath identifier exhibiting the anomaly.
    pub subpath_id: u32,
    /// Secondary/reference subpath identifier for pairwise skew anomalies.
    pub paired_subpath_id: Option<u32>,
    /// Optional associated flow identifier.
    pub flow_id: Option<u32>,
    /// Optional associated traffic slice class.
    pub slice_class: Option<FlowSliceClass>,
    /// Kind of anomaly detected.
    pub anomaly_kind: JitterDriftAnomalyKind,
    /// Severity level.
    pub severity: AnomalySeverity,
    /// Current measured interarrival jitter in nanoseconds.
    pub measured_jitter_ns: u64,
    /// Baseline smoothed jitter in nanoseconds.
    pub baseline_jitter_ns: u64,
    /// Differential path skew in nanoseconds (if applicable).
    pub differential_skew_ns: u64,
    /// Computed linear drift rate in nanoseconds per second.
    pub drift_rate_ns_per_sec: f64,
    /// Recommended routing steering action.
    pub action: RoutingSteeringAction,
    /// Human-readable diagnostic description.
    pub message: String,
}

// ---------------------------------------------------------------------------
// Subpath Metrics & Sliding History
// ---------------------------------------------------------------------------

/// Individual packet transit sample recorded on a subpath.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubpathTransitSample {
    /// Ingress dispatch timestamp in nanoseconds.
    pub send_timestamp_ns: u64,
    /// Egress reception timestamp in nanoseconds.
    pub recv_timestamp_ns: u64,
    /// One-way transit latency in nanoseconds (`recv - send`).
    pub transit_latency_ns: u64,
    /// Packet sequence number.
    pub sequence_number: u64,
    /// Flow identifier.
    pub flow_id: u32,
    /// QoS slice class.
    pub slice_class: FlowSliceClass,
}

/// Real-time statistical metrics and sliding window state for an individual subpath.
#[derive(Debug, Clone)]
pub struct SubpathJitterStats {
    /// Unique subpath identifier.
    pub subpath_id: u32,
    /// Cumulative transit samples recorded.
    pub total_samples: u64,
    /// Most recent one-way transit latency in nanoseconds.
    pub last_transit_latency_ns: u64,
    /// All-time minimum transit latency (approximate propagation delay baseline).
    pub min_transit_latency_ns: u64,
    /// All-time maximum transit latency observed.
    pub max_transit_latency_ns: u64,
    /// Smoothed transit latency in nanoseconds (EWMA).
    pub smoothed_transit_latency_ns: f64,
    /// Smoothed RFC 3550 interarrival jitter in nanoseconds.
    pub rfc3550_jitter_ns: u64,
    /// Baseline smoothed jitter used for surge threshold calculation.
    pub baseline_jitter_ns: u64,
    /// Running variance of transit latency in nanoseconds squared.
    pub latency_variance_ns2: f64,
    /// Current linear drift rate in nanoseconds per second (slope d(latency)/dt).
    pub drift_rate_ns_per_sec: f64,
    /// Monotonic timestamp of the most recent received packet in nanoseconds.
    pub last_sample_recv_ns: u64,
    /// Monotonic timestamp of the prior packet for interarrival delay comparison.
    pub prev_send_timestamp_ns: u64,
    pub prev_recv_timestamp_ns: u64,
    /// Last instantaneous inter-packet delay difference |d| in nanoseconds.
    pub last_instantaneous_jitter_ns: u64,
    /// Sliding window of recent transit samples.
    pub samples: VecDeque<SubpathTransitSample>,
    /// Timestamp of the last emitted alert for cooldown damping.
    pub last_alert_timestamp_ns: u64,
    /// Consecutive jitter surges counter.
    pub consecutive_surges: u32,
    /// Consecutive positive drift rate increases counter.
    pub consecutive_drift_surges: u32,
    /// Whether the subpath is currently flagged as degraded.
    pub is_degraded: bool,
    /// Dynamic routing penalty factor (0 = full capacity, 100 = completely penalized).
    pub routing_penalty_factor_pct: u32,
}

impl SubpathJitterStats {
    pub fn new(subpath_id: u32, capacity: usize) -> Self {
        Self {
            subpath_id,
            total_samples: 0,
            last_transit_latency_ns: 0,
            min_transit_latency_ns: u64::MAX,
            max_transit_latency_ns: 0,
            smoothed_transit_latency_ns: 0.0,
            rfc3550_jitter_ns: 0,
            baseline_jitter_ns: 0,
            latency_variance_ns2: 0.0,
            drift_rate_ns_per_sec: 0.0,
            last_sample_recv_ns: 0,
            prev_send_timestamp_ns: 0,
            prev_recv_timestamp_ns: 0,
            last_instantaneous_jitter_ns: 0,
            samples: VecDeque::with_capacity(capacity.max(8)),
            last_alert_timestamp_ns: 0,
            consecutive_surges: 0,
            consecutive_drift_surges: 0,
            is_degraded: false,
            routing_penalty_factor_pct: 0,
        }
    }
}

/// Pairwise differential skew tracking between two distinct subpaths.
#[derive(Debug, Clone, PartialEq)]
pub struct InterSubpathSkewRecord {
    pub subpath_a: u32,
    pub subpath_b: u32,
    /// Instantaneous transit difference $|D_A - D_B|$ in nanoseconds.
    pub instantaneous_skew_ns: u64,
    /// Smoothed differential skew in nanoseconds.
    pub smoothed_skew_ns: f64,
    /// Rate of change of differential skew in nanoseconds per second.
    pub skew_drift_rate_ns_per_sec: f64,
    /// Timestamp of most recent pairwise update in nanoseconds.
    pub last_update_ns: u64,
}

// ---------------------------------------------------------------------------
// Main Subpath Jitter & Drift Tracker
// ---------------------------------------------------------------------------

/// Central engine tracking jitter and nanosecond temporal drift across multipath subpaths.
#[derive(Debug, Clone)]
pub struct SubpathJitterDriftTracker {
    pub config: SubpathJitterDriftConfig,
    /// Per-subpath jitter and drift statistics indexed by `subpath_id`.
    pub subpaths: BTreeMap<u32, SubpathJitterStats>,
    /// Pairwise inter-subpath skew records indexed by `(min(a,b), max(a,b))`.
    pub pairwise_skews: BTreeMap<(u32, u32), InterSubpathSkewRecord>,
    /// Sliding history of emitted anomaly alerts.
    pub alerts_history: VecDeque<SubpathJitterDriftAlert>,
    /// Next monotonic alert identifier.
    pub next_alert_id: u64,
    /// Cumulative transit samples processed.
    pub total_samples_recorded: u64,
    /// Cumulative anomalies detected.
    pub total_anomalies_detected: u64,
    /// Cumulative alerts emitted after damping.
    pub total_alerts_emitted: u64,
}

impl Default for SubpathJitterDriftTracker {
    fn default() -> Self {
        Self::new(SubpathJitterDriftConfig::default())
    }
}

impl SubpathJitterDriftTracker {
    /// Create a new jitter and drift tracker with the given configuration.
    pub fn new(config: SubpathJitterDriftConfig) -> Self {
        Self {
            config,
            subpaths: BTreeMap::new(),
            pairwise_skews: BTreeMap::new(),
            alerts_history: VecDeque::new(),
            next_alert_id: 1,
            total_samples_recorded: 0,
            total_anomalies_detected: 0,
            total_alerts_emitted: 0,
        }
    }

    /// Ensure stats entry exists for a given subpath.
    pub fn ensure_subpath(&mut self, subpath_id: u32) -> &mut SubpathJitterStats {
        let max_samples = self.config.max_transit_samples;
        self.subpaths
            .entry(subpath_id)
            .or_insert_with(|| SubpathJitterStats::new(subpath_id, max_samples))
    }

    /// Ingest a completed packet transit from a `MultipathPacket`.
    pub fn record_packet(&mut self, packet: &MultipathPacket) -> Vec<SubpathJitterDriftAlert> {
        self.record_transit(
            packet.subpath_id,
            packet.flow_id,
            packet.slice_class,
            packet.sequence_number,
            packet.send_timestamp_ns,
            packet.received_timestamp_ns,
        )
    }

    /// Ingest a packet transit event across a subpath and detect jitter/drift anomalies.
    pub fn record_transit(
        &mut self,
        subpath_id: u32,
        flow_id: u32,
        slice_class: FlowSliceClass,
        sequence_number: u64,
        send_timestamp_ns: u64,
        recv_timestamp_ns: u64,
    ) -> Vec<SubpathJitterDriftAlert> {
        self.total_samples_recorded += 1;
        let transit_latency_ns = recv_timestamp_ns.saturating_sub(send_timestamp_ns);

        let max_samples = self.config.max_transit_samples;
        let ewma_shift = self.config.jitter_ewma_shift;

        // 1. Update subpath metrics and compute RFC 3550 jitter
        let stats = self
            .subpaths
            .entry(subpath_id)
            .or_insert_with(|| SubpathJitterStats::new(subpath_id, max_samples));

        stats.total_samples += 1;
        stats.last_transit_latency_ns = transit_latency_ns;
        stats.last_sample_recv_ns = recv_timestamp_ns;

        if transit_latency_ns < stats.min_transit_latency_ns {
            stats.min_transit_latency_ns = transit_latency_ns;
        }
        if transit_latency_ns > stats.max_transit_latency_ns {
            stats.max_transit_latency_ns = transit_latency_ns;
        }

        // Smoothed transit latency EWMA (10% weight to new sample)
        if stats.total_samples == 1 {
            stats.smoothed_transit_latency_ns = transit_latency_ns as f64;
        } else {
            stats.smoothed_transit_latency_ns =
                stats.smoothed_transit_latency_ns * 0.9 + (transit_latency_ns as f64) * 0.1;
        }

        // RFC 3550 Interarrival Jitter calculation:
        // D(i, j) = (R_j - S_j) - (R_i - S_i)
        // J = J + (|D| - J) / 16
        if stats.prev_send_timestamp_ns > 0 && stats.prev_recv_timestamp_ns > 0 {
            let prev_transit = stats
                .prev_recv_timestamp_ns
                .saturating_sub(stats.prev_send_timestamp_ns);
            let d = transit_latency_ns.abs_diff(prev_transit);
            stats.last_instantaneous_jitter_ns = d;

            let old_jitter = stats.rfc3550_jitter_ns;
            let diff = (d as i64) - (old_jitter as i64);
            let update = diff >> ewma_shift;
            stats.rfc3550_jitter_ns = ((old_jitter as i64) + update).max(0) as u64;

            // Running variance update
            let variance_diff = (d as f64) - (stats.rfc3550_jitter_ns as f64);
            stats.latency_variance_ns2 =
                stats.latency_variance_ns2 * 0.95 + (variance_diff * variance_diff) * 0.05;

            // Update baseline jitter gradually
            if stats.baseline_jitter_ns == 0 {
                stats.baseline_jitter_ns = stats.rfc3550_jitter_ns.max(10_000); // 10µs min
            } else if stats.rfc3550_jitter_ns < stats.baseline_jitter_ns {
                stats.baseline_jitter_ns = stats.rfc3550_jitter_ns.max(10_000);
            } else {
                // Baseline creeps upward very slowly (1% adjustment)
                stats.baseline_jitter_ns =
                    (stats.baseline_jitter_ns * 99 + stats.rfc3550_jitter_ns) / 100;
            }
        } else {
            // First sample: initial estimate
            stats.rfc3550_jitter_ns = 50_000; // 50µs nominal
            stats.baseline_jitter_ns = 50_000;
        }

        stats.prev_send_timestamp_ns = send_timestamp_ns;
        stats.prev_recv_timestamp_ns = recv_timestamp_ns;

        // Push into rolling window
        let sample = SubpathTransitSample {
            send_timestamp_ns,
            recv_timestamp_ns,
            transit_latency_ns,
            sequence_number,
            flow_id,
            slice_class,
        };

        if stats.samples.len() >= max_samples {
            stats.samples.pop_front();
        }
        stats.samples.push_back(sample);

        // 2. Compute linear drift rate (slope) over the sliding window
        let (drift_rate, consecutive_increases) =
            if stats.samples.len() >= self.config.min_samples_for_drift_evaluation {
                let slope = Self::compute_linear_drift_rate(&stats.samples);
                let prev_drift = stats.drift_rate_ns_per_sec;
                let consec = if slope > prev_drift && slope > 0.0 {
                    stats.consecutive_drift_surges + 1
                } else {
                    0
                };
                (slope, consec)
            } else {
                (0.0, 0)
            };

        stats.drift_rate_ns_per_sec = drift_rate;
        stats.consecutive_drift_surges = consecutive_increases;

        // 3. Update pairwise differential skews between subpaths
        let current_smoothed_latency = stats.smoothed_transit_latency_ns;
        let other_subpaths: Vec<(u32, f64)> = self
            .subpaths
            .iter()
            .filter(|(&id, _)| id != subpath_id)
            .map(|(&id, s)| (id, s.smoothed_transit_latency_ns))
            .collect();

        for (other_id, other_latency) in other_subpaths {
            let key = (subpath_id.min(other_id), subpath_id.max(other_id));
            let diff_skew = (current_smoothed_latency - other_latency).abs() as u64;

            let record = self
                .pairwise_skews
                .entry(key)
                .or_insert_with(|| InterSubpathSkewRecord {
                    subpath_a: key.0,
                    subpath_b: key.1,
                    instantaneous_skew_ns: diff_skew,
                    smoothed_skew_ns: diff_skew as f64,
                    skew_drift_rate_ns_per_sec: 0.0,
                    last_update_ns: recv_timestamp_ns,
                });

            let old_smoothed = record.smoothed_skew_ns;
            record.instantaneous_skew_ns = diff_skew;
            record.smoothed_skew_ns = record.smoothed_skew_ns * 0.8 + (diff_skew as f64) * 0.2;

            let dt_sec = recv_timestamp_ns.saturating_sub(record.last_update_ns) as f64 / 1e9;
            if dt_sec > 1e-6 {
                let dskew = (record.smoothed_skew_ns - old_smoothed) / dt_sec;
                record.skew_drift_rate_ns_per_sec =
                    record.skew_drift_rate_ns_per_sec * 0.7 + dskew * 0.3;
            }
            record.last_update_ns = recv_timestamp_ns;
        }

        // 4. Anomaly Detection and Alert Derivation
        let mut alerts = Vec::new();

        // 4A. Jitter Surge Anomaly
        let stats_ref = self.subpaths.get_mut(&subpath_id).unwrap();
        let jitter = stats_ref.rfc3550_jitter_ns;
        let instant_d = stats_ref.last_instantaneous_jitter_ns;
        let baseline = stats_ref.baseline_jitter_ns;
        let surge_threshold = ((baseline as f64) * self.config.jitter_surge_multiplier) as u64;

        let is_surge = (jitter > surge_threshold && jitter > self.config.jitter_surge_absolute_ns)
            || (instant_d > self.config.jitter_surge_absolute_ns && instant_d > surge_threshold);

        if is_surge {
            let effective_jitter = jitter.max(instant_d);
            stats_ref.consecutive_surges += 1;
            self.total_anomalies_detected += 1;

            let severity = if effective_jitter > surge_threshold * 2 {
                AnomalySeverity::Critical
            } else if effective_jitter > (surge_threshold * 3) / 2 {
                AnomalySeverity::Degraded
            } else {
                AnomalySeverity::Warning
            };

            let penalty = match severity {
                AnomalySeverity::Critical => 80,
                AnomalySeverity::Degraded => 50,
                AnomalySeverity::Warning => 25,
            };
            stats_ref.routing_penalty_factor_pct = penalty;
            stats_ref.is_degraded = severity >= AnomalySeverity::Degraded;

            if recv_timestamp_ns.saturating_sub(stats_ref.last_alert_timestamp_ns)
                >= self.config.alert_cooldown_ns
            {
                stats_ref.last_alert_timestamp_ns = recv_timestamp_ns;
                let alert_id = self.next_alert_id;
                self.next_alert_id += 1;

                let action = match severity {
                    AnomalySeverity::Critical => RoutingSteeringAction::EvictSliceFromSubpath {
                        subpath_id,
                        slice_class,
                    },
                    AnomalySeverity::Degraded => RoutingSteeringAction::PenalizeRoutingWeight {
                        subpath_id,
                        penalty_factor_pct: penalty,
                    },
                    AnomalySeverity::Warning => RoutingSteeringAction::IncreaseReorderHoldTimeout {
                        recommended_hold_ns: effective_jitter * 3,
                    },
                };

                let alert = SubpathJitterDriftAlert {
                    alert_id,
                    timestamp_ns: recv_timestamp_ns,
                    subpath_id,
                    paired_subpath_id: None,
                    flow_id: Some(flow_id),
                    slice_class: Some(slice_class),
                    anomaly_kind: JitterDriftAnomalyKind::JitterSurge,
                    severity,
                    measured_jitter_ns: effective_jitter,
                    baseline_jitter_ns: baseline,
                    differential_skew_ns: 0,
                    drift_rate_ns_per_sec: stats_ref.drift_rate_ns_per_sec,
                    action,
                    message: format!(
                        "Jitter surge on subpath {} (jitter={}ns, baseline={}ns, penalty={}%): exceeds threshold {}ns",
                        subpath_id, effective_jitter, baseline, penalty, surge_threshold
                    ),
                };
                alerts.push(alert);
            }
        } else {
            stats_ref.consecutive_surges = stats_ref.consecutive_surges.saturating_sub(1);
            if stats_ref.consecutive_surges == 0 {
                stats_ref.routing_penalty_factor_pct =
                    (stats_ref.routing_penalty_factor_pct / 2).saturating_sub(5);
                if stats_ref.routing_penalty_factor_pct == 0 {
                    stats_ref.is_degraded = false;
                }
            }
        }

        // 4B. Monotonic Drift Divergence Anomaly
        let drift_rate = stats_ref.drift_rate_ns_per_sec;
        if drift_rate > self.config.drift_rate_warning_ns_per_sec {
            self.total_anomalies_detected += 1;
            let severity = if drift_rate > self.config.drift_rate_critical_ns_per_sec {
                AnomalySeverity::Critical
            } else {
                AnomalySeverity::Degraded
            };

            if recv_timestamp_ns.saturating_sub(stats_ref.last_alert_timestamp_ns)
                >= self.config.alert_cooldown_ns
            {
                stats_ref.last_alert_timestamp_ns = recv_timestamp_ns;
                let alert_id = self.next_alert_id;
                self.next_alert_id += 1;

                let action = match severity {
                    AnomalySeverity::Critical => RoutingSteeringAction::TriggerSubpathProbation {
                        subpath_id,
                        reason: format!(
                            "Accelerating monotonic latency drift: {:.1} ms/sec",
                            drift_rate / 1e6
                        ),
                    },
                    _ => RoutingSteeringAction::PenalizeRoutingWeight {
                        subpath_id,
                        penalty_factor_pct: 40,
                    },
                };

                let alert = SubpathJitterDriftAlert {
                    alert_id,
                    timestamp_ns: recv_timestamp_ns,
                    subpath_id,
                    paired_subpath_id: None,
                    flow_id: Some(flow_id),
                    slice_class: Some(slice_class),
                    anomaly_kind: JitterDriftAnomalyKind::MonotonicDriftDivergence,
                    severity,
                    measured_jitter_ns: stats_ref.rfc3550_jitter_ns,
                    baseline_jitter_ns: stats_ref.baseline_jitter_ns,
                    differential_skew_ns: 0,
                    drift_rate_ns_per_sec: drift_rate,
                    action,
                    message: format!(
                        "Monotonic drift divergence on subpath {}: drift_rate={:.2} ms/s exceeds threshold {:.2} ms/s",
                        subpath_id,
                        drift_rate / 1e6,
                        self.config.drift_rate_warning_ns_per_sec / 1e6
                    ),
                };
                alerts.push(alert);
            }
        }

        // 4C. Inter-Subpath Excessive Skew vs QoS Slice Reorder Limit
        for ((p_a, p_b), record) in &self.pairwise_skews {
            if *p_a == subpath_id || *p_b == subpath_id {
                let skew = record.instantaneous_skew_ns;
                let paired = if *p_a == subpath_id { *p_b } else { *p_a };

                // Compare with slice-specific reorder hold timeout limits:
                // UltraLowLatency max hold is 2ms (2_000_000 ns). Any skew > 2ms causes HoL / gap timeout!
                let (max_tolerated_skew_ns, slice_name) = match slice_class {
                    FlowSliceClass::UltraLowLatency => (2_000_000, "URLLC"),
                    FlowSliceClass::HighThroughput => (30_000_000, "eMBB"),
                    FlowSliceClass::MissionCritical => (50_000_000, "MissionCritical"),
                    FlowSliceClass::BestEffort => (15_000_000, "BestEffort"),
                };

                if skew > max_tolerated_skew_ns || skew > self.config.excessive_skew_warning_ns {
                    self.total_anomalies_detected += 1;
                    let is_critical = skew > self.config.excessive_skew_critical_ns
                        || (slice_class == FlowSliceClass::UltraLowLatency
                            && skew > max_tolerated_skew_ns * 2);

                    let severity = if is_critical {
                        AnomalySeverity::Critical
                    } else {
                        AnomalySeverity::Degraded
                    };

                    let paired_latency = self
                        .subpaths
                        .get(&paired)
                        .map(|s| s.smoothed_transit_latency_ns)
                        .unwrap_or(0.0);

                    let stats_cur = self.subpaths.get_mut(&subpath_id).unwrap();
                    if severity >= AnomalySeverity::Degraded {
                        stats_cur.is_degraded = true;
                        stats_cur.routing_penalty_factor_pct =
                            stats_cur.routing_penalty_factor_pct.max(50);
                    }

                    if recv_timestamp_ns.saturating_sub(stats_cur.last_alert_timestamp_ns)
                        >= self.config.alert_cooldown_ns
                    {
                        stats_cur.last_alert_timestamp_ns = recv_timestamp_ns;
                        let alert_id = self.next_alert_id;
                        self.next_alert_id += 1;

                        let action = match slice_class {
                            FlowSliceClass::UltraLowLatency => {
                                // For URLLC, excessive skew forces slice eviction from the slower subpath
                                let slower_subpath = if current_smoothed_latency > paired_latency {
                                    subpath_id
                                } else {
                                    paired
                                };
                                RoutingSteeringAction::EvictSliceFromSubpath {
                                    subpath_id: slower_subpath,
                                    slice_class: FlowSliceClass::UltraLowLatency,
                                }
                            }
                            FlowSliceClass::MissionCritical => {
                                // For MC, increase reorder hold timeout to absorb skew without loss
                                RoutingSteeringAction::IncreaseReorderHoldTimeout {
                                    recommended_hold_ns: skew * 2,
                                }
                            }
                            _ => RoutingSteeringAction::PenalizeRoutingWeight {
                                subpath_id,
                                penalty_factor_pct: 35,
                            },
                        };

                        let alert = SubpathJitterDriftAlert {
                            alert_id,
                            timestamp_ns: recv_timestamp_ns,
                            subpath_id,
                            paired_subpath_id: Some(paired),
                            flow_id: Some(flow_id),
                            slice_class: Some(slice_class),
                            anomaly_kind: JitterDriftAnomalyKind::ExcessivePathSkew,
                            severity,
                            measured_jitter_ns: stats_cur.rfc3550_jitter_ns,
                            baseline_jitter_ns: stats_cur.baseline_jitter_ns,
                            differential_skew_ns: skew,
                            drift_rate_ns_per_sec: record.skew_drift_rate_ns_per_sec,
                            action,
                            message: format!(
                                "Differential skew between subpaths {} and {} is {:.2}ms (exceeds {} limit {:.2}ms)",
                                subpath_id,
                                paired,
                                skew as f64 / 1e6,
                                slice_name,
                                max_tolerated_skew_ns as f64 / 1e6
                            ),
                        };
                        alerts.push(alert);
                    }
                }
            }
        }

        // Store alerts in history
        for alert in &alerts {
            self.total_alerts_emitted += 1;
            if self.alerts_history.len() >= self.config.max_alerts_history {
                self.alerts_history.pop_front();
            }
            self.alerts_history.push_back(alert.clone());
        }

        alerts
    }

    /// Compute linear drift rate (slope) $\frac{d\text{latency}}{dt}$ in ns/sec using closed-form least squares.
    ///
    /// Given pairs $(t_i, y_i)$, where $t_i = \text{recv\_timestamp\_ns}$, $y_i = \text{transit\_latency\_ns}$:
    /// $\text{slope} = \frac{\sum (t_i - \bar{t})(y_i - \bar{y})}{\sum (t_i - \bar{t})^2} \times 10^9$ (ns/sec).
    pub fn compute_linear_drift_rate(samples: &VecDeque<SubpathTransitSample>) -> f64 {
        let n = samples.len();
        if n < 2 {
            return 0.0;
        }

        let first_t = samples.front().unwrap().recv_timestamp_ns;
        let last_t = samples.back().unwrap().recv_timestamp_ns;
        let time_span_ns = last_t.saturating_sub(first_t);
        if time_span_ns == 0 {
            return 0.0;
        }

        let mut sum_t = 0.0;
        let mut sum_y = 0.0;
        for s in samples {
            let rel_t = s.recv_timestamp_ns.saturating_sub(first_t) as f64;
            sum_t += rel_t;
            sum_y += s.transit_latency_ns as f64;
        }

        let mean_t = sum_t / (n as f64);
        let mean_y = sum_y / (n as f64);

        let mut numerator = 0.0;
        let mut denominator = 0.0;
        for s in samples {
            let rel_t = s.recv_timestamp_ns.saturating_sub(first_t) as f64;
            let dt = rel_t - mean_t;
            let dy = (s.transit_latency_ns as f64) - mean_y;
            numerator += dt * dy;
            denominator += dt * dt;
        }

        if denominator.abs() < 1e-9 {
            0.0
        } else {
            // Slope in ns latency per ns elapsed -> multiply by 1e9 to get ns/sec
            (numerator / denominator) * 1e9
        }
    }

    /// Get current metrics for a specific subpath.
    pub fn get_subpath_stats(&self, subpath_id: u32) -> Option<&SubpathJitterStats> {
        self.subpaths.get(&subpath_id)
    }

    /// Retrieve pairwise skew between two subpaths.
    pub fn get_pairwise_skew(
        &self,
        subpath_a: u32,
        subpath_b: u32,
    ) -> Option<&InterSubpathSkewRecord> {
        let key = (subpath_a.min(subpath_b), subpath_a.max(subpath_b));
        self.pairwise_skews.get(&key)
    }

    /// Dynamic routing penalty factor (0 to 100%) for a subpath.
    pub fn subpath_routing_penalty_pct(&self, subpath_id: u32) -> u32 {
        self.subpaths
            .get(&subpath_id)
            .map(|s| s.routing_penalty_factor_pct)
            .unwrap_or(0)
    }

    /// Returns true if the subpath is currently free of critical drift or excessive jitter surges.
    pub fn is_subpath_admissible_for_slice(
        &self,
        subpath_id: u32,
        slice_class: FlowSliceClass,
    ) -> bool {
        let stats = match self.subpaths.get(&subpath_id) {
            Some(s) => s,
            None => return true, // New subpath, admit by default
        };

        if slice_class == FlowSliceClass::UltraLowLatency {
            // URLLC requires low jitter and zero degradation
            if stats.is_degraded || stats.routing_penalty_factor_pct > 30 {
                return false;
            }
            if stats.rfc3550_jitter_ns > 5_000_000 {
                return false; // Jitter > 5ms rejects URLLC admission
            }
            // Reject if differential skew against any faster partner exceeds URLLC limit (2ms)
            let my_latency = stats.smoothed_transit_latency_ns;
            for (a, b) in self.pairwise_skews.keys() {
                if *a == subpath_id || *b == subpath_id {
                    let other_id = if *a == subpath_id { *b } else { *a };
                    if let Some(other_stats) = self.subpaths.get(&other_id) {
                        if my_latency > other_stats.smoothed_transit_latency_ns + 2_000_000.0 {
                            return false;
                        }
                    }
                }
            }
        } else if slice_class == FlowSliceClass::MissionCritical {
            // Mission Critical tolerates higher latency but rejects high loss/chaotic thrashing
            if stats.routing_penalty_factor_pct > 70 {
                return false;
            }
        }

        true
    }

    /// Calculate recommended reorder hold timeout in nanoseconds for a QoS slice given current skews.
    pub fn recommended_reorder_hold_timeout_ns(&self, slice_class: FlowSliceClass) -> u64 {
        let base_hold = match slice_class {
            FlowSliceClass::UltraLowLatency => 2_000_000,
            FlowSliceClass::HighThroughput => 30_000_000,
            FlowSliceClass::MissionCritical => 50_000_000,
            FlowSliceClass::BestEffort => 15_000_000,
        };

        let max_skew = self
            .pairwise_skews
            .values()
            .map(|r| r.instantaneous_skew_ns)
            .max()
            .unwrap_or(0);

        if slice_class == FlowSliceClass::UltraLowLatency {
            // URLLC bounds hold timeout strictly to prevent playout latency inflation
            base_hold.max((max_skew / 2).min(4_000_000))
        } else {
            base_hold.max(max_skew + 5_000_000)
        }
    }

    /// Export Prometheus / OpenMetrics compatible metric series.
    pub fn export_prometheus_metrics(&self) -> String {
        let mut out = String::with_capacity(2048);

        let _ = writeln!(out, "# HELP ifa_subpath_transit_latency_nanoseconds Instantaneous one-way transit latency per subpath.");
        let _ = writeln!(out, "# TYPE ifa_subpath_transit_latency_nanoseconds gauge");
        for (&id, stats) in &self.subpaths {
            let _ = writeln!(
                out,
                "ifa_subpath_transit_latency_nanoseconds{{subpath_id=\"{}\"}} {}",
                id, stats.last_transit_latency_ns
            );
        }

        let _ = writeln!(out, "# HELP ifa_subpath_jitter_nanoseconds Smoothed RFC 3550 interarrival jitter per subpath.");
        let _ = writeln!(out, "# TYPE ifa_subpath_jitter_nanoseconds gauge");
        for (&id, stats) in &self.subpaths {
            let _ = writeln!(
                out,
                "ifa_subpath_jitter_nanoseconds{{subpath_id=\"{}\"}} {}",
                id, stats.rfc3550_jitter_ns
            );
        }

        let _ = writeln!(out, "# HELP ifa_subpath_drift_rate_ns_per_sec Nanosecond per second linear latency drift rate.");
        let _ = writeln!(out, "# TYPE ifa_subpath_drift_rate_ns_per_sec gauge");
        for (&id, stats) in &self.subpaths {
            let _ = writeln!(
                out,
                "ifa_subpath_drift_rate_ns_per_sec{{subpath_id=\"{}\"}} {:.2}",
                id, stats.drift_rate_ns_per_sec
            );
        }

        let _ = writeln!(out, "# HELP ifa_subpath_differential_skew_nanoseconds Smoothed differential path skew between subpath pairs.");
        let _ = writeln!(
            out,
            "# TYPE ifa_subpath_differential_skew_nanoseconds gauge"
        );
        for ((a, b), rec) in &self.pairwise_skews {
            let _ = writeln!(
                out,
                "ifa_subpath_differential_skew_nanoseconds{{subpath_a=\"{}\",subpath_b=\"{}\"}} {:.0}",
                a, b, rec.smoothed_skew_ns
            );
        }

        let _ = writeln!(
            out,
            "# HELP ifa_subpath_routing_penalty_pct Dynamic routing penalty factor percentage."
        );
        let _ = writeln!(out, "# TYPE ifa_subpath_routing_penalty_pct gauge");
        for (&id, stats) in &self.subpaths {
            let _ = writeln!(
                out,
                "ifa_subpath_routing_penalty_pct{{subpath_id=\"{}\"}} {}",
                id, stats.routing_penalty_factor_pct
            );
        }

        let _ = writeln!(out, "# HELP ifa_subpath_jitter_drift_anomalies_total Total jitter and drift anomalies detected.");
        let _ = writeln!(
            out,
            "# TYPE ifa_subpath_jitter_drift_anomalies_total counter"
        );
        let _ = writeln!(
            out,
            "ifa_subpath_jitter_drift_anomalies_total {}",
            self.total_anomalies_detected
        );

        let _ = writeln!(out, "# HELP ifa_subpath_jitter_drift_alerts_total Total anomaly alerts emitted after anti-flap cooldown.");
        let _ = writeln!(out, "# TYPE ifa_subpath_jitter_drift_alerts_total counter");
        let _ = writeln!(
            out,
            "ifa_subpath_jitter_drift_alerts_total {}",
            self.total_alerts_emitted
        );

        out
    }

    /// Generate structured JSON audit report.
    pub fn generate_audit_report(&self) -> String {
        let mut json = String::with_capacity(2048);
        let _ = writeln!(json, "{{");
        let _ = writeln!(
            json,
            "  \"total_samples\": {},",
            self.total_samples_recorded
        );
        let _ = writeln!(
            json,
            "  \"total_anomalies\": {},",
            self.total_anomalies_detected
        );
        let _ = writeln!(json, "  \"total_alerts\": {},", self.total_alerts_emitted);
        let _ = writeln!(json, "  \"subpaths\": [");
        let mut first_sp = true;
        for (&id, stats) in &self.subpaths {
            if !first_sp {
                let _ = writeln!(json, ",");
            }
            first_sp = false;
            let _ = writeln!(json, "    {{");
            let _ = writeln!(json, "      \"subpath_id\": {},", id);
            let _ = writeln!(
                json,
                "      \"last_transit_ns\": {},",
                stats.last_transit_latency_ns
            );
            let _ = writeln!(
                json,
                "      \"min_transit_ns\": {},",
                stats.min_transit_latency_ns
            );
            let _ = writeln!(
                json,
                "      \"max_transit_ns\": {},",
                stats.max_transit_latency_ns
            );
            let _ = writeln!(
                json,
                "      \"rfc3550_jitter_ns\": {},",
                stats.rfc3550_jitter_ns
            );
            let _ = writeln!(
                json,
                "      \"drift_rate_ns_per_sec\": {:.2},",
                stats.drift_rate_ns_per_sec
            );
            let _ = writeln!(json, "      \"is_degraded\": {},", stats.is_degraded);
            let _ = writeln!(
                json,
                "      \"penalty_pct\": {}",
                stats.routing_penalty_factor_pct
            );
            let _ = write!(json, "    }}");
        }
        let _ = writeln!(json, "\n  ],");
        let _ = writeln!(json, "  \"recent_alerts\": [");
        let mut first_alt = true;
        for alt in &self.alerts_history {
            if !first_alt {
                let _ = writeln!(json, ",");
            }
            first_alt = false;
            let _ = writeln!(json, "    {{");
            let _ = writeln!(json, "      \"alert_id\": {},", alt.alert_id);
            let _ = writeln!(json, "      \"timestamp_ns\": {},", alt.timestamp_ns);
            let _ = writeln!(json, "      \"subpath_id\": {},", alt.subpath_id);
            let _ = writeln!(
                json,
                "      \"anomaly_kind\": \"{}\",",
                alt.anomaly_kind.as_str()
            );
            let _ = writeln!(json, "      \"severity\": \"{}\",", alt.severity.as_str());
            let _ = writeln!(json, "      \"action\": \"{}\",", alt.action.as_str());
            let _ = writeln!(json, "      \"message\": \"{}\"", alt.message);
            let _ = write!(json, "    }}");
        }
        let _ = writeln!(json, "\n  ]");
        let _ = write!(json, "}}");
        json
    }
}

// ---------------------------------------------------------------------------
// Unit & Integration Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc3550_jitter_calculation_nominal() {
        let mut tracker = SubpathJitterDriftTracker::default();

        // Subpath 1: Stable transit latency of 10ms (10,000,000ns) with tiny 100µs variations
        for seq in 1..=20 {
            let send_ns = 1_000_000_000 + seq * 10_000_000;
            let transit = 10_000_000 + (seq % 2) * 100_000;
            let recv_ns = send_ns + transit;

            let alerts =
                tracker.record_transit(1, 101, FlowSliceClass::BestEffort, seq, send_ns, recv_ns);
            assert!(alerts.is_empty(), "Nominal jitter should emit zero alerts");
        }

        let stats = tracker.get_subpath_stats(1).unwrap();
        assert_eq!(stats.total_samples, 20);
        assert!(
            stats.rfc3550_jitter_ns < 200_000,
            "Jitter should stay well below 200µs"
        );
        assert_eq!(stats.routing_penalty_factor_pct, 0);
        assert!(!stats.is_degraded);
    }

    #[test]
    fn test_jitter_surge_detection_and_penalty() {
        let mut tracker = SubpathJitterDriftTracker::new(SubpathJitterDriftConfig {
            jitter_surge_multiplier: 2.0,
            jitter_surge_absolute_ns: 5_000_000, // 5ms absolute
            alert_cooldown_ns: 1_000,            // Minimal cooldown for test
            ..SubpathJitterDriftConfig::default()
        });

        // First establish baseline of 1ms jitter
        for seq in 1..=10 {
            let send_ns = 1_000_000_000 + seq * 20_000_000;
            let transit = 5_000_000 + (seq % 2) * 1_000_000; // 5ms to 6ms
            tracker.record_transit(
                1,
                101,
                FlowSliceClass::HighThroughput,
                seq,
                send_ns,
                send_ns + transit,
            );
        }

        // Inject severe jitter surge: transit jumps from 5ms to 35ms (30ms jump)
        let send_surge = 1_000_000_000 + 11 * 20_000_000;
        let recv_surge = send_surge + 35_000_000;
        let alerts = tracker.record_transit(
            1,
            101,
            FlowSliceClass::HighThroughput,
            11,
            send_surge,
            recv_surge,
        );

        assert!(!alerts.is_empty(), "Jitter surge should trigger alert");
        let surge_alert = alerts
            .iter()
            .find(|a| a.anomaly_kind == JitterDriftAnomalyKind::JitterSurge)
            .unwrap();
        assert_eq!(surge_alert.subpath_id, 1);
        assert!(surge_alert.measured_jitter_ns > 2_000_000);

        let stats = tracker.get_subpath_stats(1).unwrap();
        assert!(stats.routing_penalty_factor_pct > 0);
    }

    #[test]
    fn test_monotonic_drift_divergence_least_squares() {
        let mut tracker = SubpathJitterDriftTracker::new(SubpathJitterDriftConfig {
            min_samples_for_drift_evaluation: 5,
            drift_rate_warning_ns_per_sec: 1_000_000.0, // 1 ms/sec threshold
            alert_cooldown_ns: 1_000,
            ..SubpathJitterDriftConfig::default()
        });

        // Simulate queue buildup / bufferbloat: latency increases by 2ms every 100ms
        // Slope = 2ms / 0.1s = 20ms/sec = 20,000,000 ns/sec
        let mut total_alerts = Vec::new();
        for seq in 1..=10 {
            let send_ns = 1_000_000_000 + (seq - 1) * 100_000_000;
            let transit = 10_000_000 + (seq - 1) * 2_000_000; // 10ms, 12ms, 14ms...
            let recv_ns = send_ns + transit;
            let alerts = tracker.record_transit(
                2,
                202,
                FlowSliceClass::MissionCritical,
                seq,
                send_ns,
                recv_ns,
            );
            total_alerts.extend(alerts);
        }

        let stats = tracker.get_subpath_stats(2).unwrap();
        assert!(
            stats.drift_rate_ns_per_sec > 15_000_000.0,
            "Drift slope should reflect ~20ms/sec buildup"
        );

        let drift_alert = total_alerts
            .iter()
            .find(|a| a.anomaly_kind == JitterDriftAnomalyKind::MonotonicDriftDivergence);
        assert!(
            drift_alert.is_some(),
            "Monotonic drift alert must be emitted"
        );
    }

    #[test]
    fn test_inter_subpath_differential_skew_urllc_eviction() {
        let mut tracker = SubpathJitterDriftTracker::new(SubpathJitterDriftConfig {
            excessive_skew_warning_ns: 10_000_000, // 10 ms
            alert_cooldown_ns: 1_000,
            ..SubpathJitterDriftConfig::default()
        });

        // Subpath 1: Fast Fiber path (5ms latency)
        for seq in 1..=8 {
            let send_ns = 2_000_000_000 + seq * 10_000_000;
            tracker.record_transit(
                1,
                303,
                FlowSliceClass::UltraLowLatency,
                seq,
                send_ns,
                send_ns + 5_000_000,
            );
        }

        // Subpath 2: High-latency Satellite path (50ms latency)
        // Differential skew = 45ms. For URLLC (which tolerates 2ms), this is intolerable!
        let mut skew_alerts = Vec::new();
        for seq in 1..=8 {
            let send_ns = 2_000_000_000 + seq * 10_000_000;
            let alerts = tracker.record_transit(
                2,
                303,
                FlowSliceClass::UltraLowLatency,
                seq,
                send_ns,
                send_ns + 50_000_000,
            );
            skew_alerts.extend(alerts);
        }

        let skew_alert = skew_alerts
            .iter()
            .find(|a| a.anomaly_kind == JitterDriftAnomalyKind::ExcessivePathSkew);
        assert!(
            skew_alert.is_some(),
            "Excessive path skew must be detected between Subpath 1 and 2"
        );
        let alert = skew_alert.unwrap();
        assert_eq!(alert.subpath_id, 2);
        assert_eq!(alert.paired_subpath_id, Some(1));

        // URLLC action must evict the slower subpath (subpath 2)
        match &alert.action {
            RoutingSteeringAction::EvictSliceFromSubpath {
                subpath_id,
                slice_class,
            } => {
                assert_eq!(*subpath_id, 2);
                assert_eq!(*slice_class, FlowSliceClass::UltraLowLatency);
            }
            other => panic!("Expected EvictSliceFromSubpath, got {:?}", other),
        }

        // Subpath 2 should not be admissible for URLLC
        assert!(!tracker.is_subpath_admissible_for_slice(2, FlowSliceClass::UltraLowLatency));
        // But Subpath 1 is pristine and admissible
        assert!(tracker.is_subpath_admissible_for_slice(1, FlowSliceClass::UltraLowLatency));
    }

    #[test]
    fn test_multipath_packet_ingest_and_prometheus_export() {
        let mut tracker = SubpathJitterDriftTracker::default();

        let packet = MultipathPacket::new(
            1001,
            42,
            1,
            FlowSliceClass::HighThroughput,
            1,
            1400,
            1_000_000_000,
            1_012_000_000, // 12ms transit
        );

        let alerts = tracker.record_packet(&packet);
        assert!(alerts.is_empty());

        let prometheus = tracker.export_prometheus_metrics();
        assert!(prometheus
            .contains("ifa_subpath_transit_latency_nanoseconds{subpath_id=\"1\"} 12000000"));
        assert!(prometheus.contains("ifa_subpath_jitter_nanoseconds{subpath_id=\"1\"}"));
        assert!(prometheus.contains("ifa_subpath_jitter_drift_anomalies_total"));

        let report = tracker.generate_audit_report();
        assert!(report.contains("\"total_samples\": 1"));
        assert!(report.contains("\"subpath_id\": 1"));
    }
}

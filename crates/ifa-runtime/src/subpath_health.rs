//! Dynamic Physical Subpath Health Monitoring, Degraded Path Detection, and Transparent Failover (`SubpathHealthMonitor`).
//!
//! Provides proactive physical subpath monitoring across heterogeneous network interfaces (e.g. 5G, fiber, satellite, Wi-Fi):
//! - **Degradation Detection**: Continuously tracks consecutive admission failures, PMTU probe losses, and RTT/jitter spikes.
//! - **Dynamic Health Scoring**: Computes composite subpath health scores (0–100) combining latency inflation, jitter variance,
//!   and drop penalties.
//! - **Transparent Critical Flow Failover**: Automatically steers critical traffic (`UltraLowLatency`, `MissionCritical`)
//!   to surviving healthy subpaths with zero session loss upon link impairment or shaper throttling.
//! - **Alerting & Webhook Hooks**: Emits structured degradation alert events and dispatches notifications via pluggable sinks.
//! - **OpenMetrics Observability**: Exports Prometheus metrics for subpath health scores, failover occurrences, and degradation counts.

use std::collections::{BTreeMap, VecDeque};
use std::fmt::Write as FmtWrite;
use std::sync::Arc;

use crate::traffic_slicing::FlowSliceClass;

/// Discrete operational health state of an egress physical transport subpath.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SubpathHealthState {
    /// Fully operational with nominal RTT, minimal jitter, and steady admissions (Score: 80–100).
    Healthy,
    /// Elevated latency, jitter, or intermittent admission drops (Score: 40–79).
    Degraded,
    /// Severe packet loss, high RTT spikes, or repeated throttling (Score: 1–39).
    Critical,
    /// Unresponsive subpath; consecutive probe timeouts or total link outage (Score: 0).
    Down,
}

impl SubpathHealthState {
    /// Returns true if the subpath can carry traffic without imminent risk of complete drop.
    pub fn is_viable(&self) -> bool {
        matches!(self, SubpathHealthState::Healthy | SubpathHealthState::Degraded)
    }

    /// Label string representation for metric exposition and log formatting.
    pub fn as_str(&self) -> &'static str {
        match self {
            SubpathHealthState::Healthy => "healthy",
            SubpathHealthState::Degraded => "degraded",
            SubpathHealthState::Critical => "critical",
            SubpathHealthState::Down => "down",
        }
    }
}

/// Configuration parameters and thresholds governing subpath health evaluations.
#[derive(Debug, Clone, PartialEq)]
pub struct SubpathHealthConfig {
    /// Maximum consecutive admission failures allowed before marking subpath as Critical.
    pub max_consecutive_admission_failures: u32,
    /// Maximum consecutive PMTU probe losses before transitioning to Down.
    pub max_consecutive_probe_losses: u32,
    /// RTT surge multiplier relative to baseline RTT triggering health penalty (e.g. 2.0x).
    pub rtt_spike_threshold_multiplier: f64,
    /// Jitter threshold in milliseconds above which penalties are applied.
    pub jitter_threshold_ms: u64,
    /// Health score boundary below which a subpath enters Degraded state.
    pub degraded_score_threshold: u8,
    /// Health score boundary below which a subpath enters Critical state.
    pub critical_score_threshold: u8,
    /// Maximum capacity of the alert events history buffer.
    pub max_alert_history: usize,
}

impl Default for SubpathHealthConfig {
    fn default() -> Self {
        Self {
            max_consecutive_admission_failures: 5,
            max_consecutive_probe_losses: 3,
            rtt_spike_threshold_multiplier: 2.0,
            jitter_threshold_ms: 30,
            degraded_score_threshold: 70,
            critical_score_threshold: 35,
            max_alert_history: 128,
        }
    }
}

/// Structured alert event emitted whenever a subpath transitions into a degraded or critical state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubpathDegradedAlertEvent {
    pub timestamp_ns: u64,
    pub subpath_id: u8,
    pub subpath_name: String,
    pub previous_state: SubpathHealthState,
    pub current_state: SubpathHealthState,
    pub health_score: u8,
    pub reason: String,
}

/// Pluggable sink trait for forwarding degradation alerts to webhooks, message queues, or event busses.
pub trait SubpathAlertSink: Send + Sync {
    fn on_alert(&self, alert: &SubpathDegradedAlertEvent);
}

/// Active health tracker for an individual physical subpath.
#[derive(Debug, Clone, PartialEq)]
pub struct SubpathHealthTracker {
    pub subpath_id: u8,
    pub name: String,
    pub state: SubpathHealthState,
    pub health_score: u8,
    pub baseline_rtt_ms: u64,
    pub current_rtt_ms: u64,
    pub rtt_jitter_ms: u64,
    pub smoothed_rtt_ms: f64,
    pub consecutive_admission_failures: u32,
    pub consecutive_probe_losses: u32,
    pub total_admission_failures: u64,
    pub total_probe_losses: u64,
    pub degraded_events_total: u64,
    pub failover_events_total: u64,
    pub last_state_change_timestamp_ns: u64,
    pub last_evaluation_timestamp_ns: u64,
}

impl SubpathHealthTracker {
    pub fn new(subpath_id: u8, name: impl Into<String>, initial_rtt_ms: u64, now_ns: u64) -> Self {
        Self {
            subpath_id,
            name: name.into(),
            state: SubpathHealthState::Healthy,
            health_score: 100,
            baseline_rtt_ms: initial_rtt_ms.max(1),
            current_rtt_ms: initial_rtt_ms,
            rtt_jitter_ms: 0,
            smoothed_rtt_ms: initial_rtt_ms as f64,
            consecutive_admission_failures: 0,
            consecutive_probe_losses: 0,
            total_admission_failures: 0,
            total_probe_losses: 0,
            degraded_events_total: 0,
            failover_events_total: 0,
            last_state_change_timestamp_ns: now_ns,
            last_evaluation_timestamp_ns: now_ns,
        }
    }

    /// Evaluates and recalculates the dynamic composite health score and state.
    pub fn recalculate_health(
        &mut self,
        config: &SubpathHealthConfig,
        now_ns: u64,
    ) -> Option<SubpathDegradedAlertEvent> {
        self.last_evaluation_timestamp_ns = now_ns;

        // Base score starts at 100
        let mut score: i32 = 100;

        // 1. RTT surge penalty
        if self.baseline_rtt_ms > 0 {
            let ratio = (self.current_rtt_ms as f64) / (self.baseline_rtt_ms as f64);
            if ratio > 1.2 {
                let rtt_penalty = ((ratio - 1.0) * 25.0).min(40.0) as i32;
                score -= rtt_penalty;
            }
        }

        // 2. Jitter penalty
        if self.rtt_jitter_ms > config.jitter_threshold_ms {
            let excess = self.rtt_jitter_ms.saturating_sub(config.jitter_threshold_ms);
            let jitter_penalty = ((excess as f64 * 0.75).min(30.0)) as i32;
            score -= jitter_penalty;
        }

        // 3. Consecutive admission failures penalty
        let admission_penalty = (self.consecutive_admission_failures * 15).min(50) as i32;
        score -= admission_penalty;

        // 4. Consecutive PMTU probe losses penalty
        let probe_penalty = (self.consecutive_probe_losses * 25).min(60) as i32;
        score -= probe_penalty;

        // Clamp score between 0 and 100
        let new_score = score.clamp(0, 100) as u8;

        // Determine target health state and final health score
        let (target_state, final_score) = if self.consecutive_probe_losses >= config.max_consecutive_probe_losses {
            (SubpathHealthState::Down, 0)
        } else if new_score < config.critical_score_threshold
            || self.consecutive_admission_failures >= config.max_consecutive_admission_failures
        {
            (SubpathHealthState::Critical, new_score)
        } else if new_score < config.degraded_score_threshold {
            (SubpathHealthState::Degraded, new_score)
        } else {
            (SubpathHealthState::Healthy, new_score)
        };

        self.health_score = final_score;

        if target_state != self.state {
            let prev_state = self.state;
            self.state = target_state;
            self.last_state_change_timestamp_ns = now_ns;

            if target_state != SubpathHealthState::Healthy {
                self.degraded_events_total = self.degraded_events_total.saturating_add(1);
            }

            let reason = format!(
                "State transition {:?} -> {:?} (score={}, RTT={}ms/base={}ms, jitter={}ms, adm_fail={}, probe_loss={})",
                prev_state, target_state, self.health_score, self.current_rtt_ms,
                self.baseline_rtt_ms, self.rtt_jitter_ms, self.consecutive_admission_failures,
                self.consecutive_probe_losses
            );

            Some(SubpathDegradedAlertEvent {
                timestamp_ns: now_ns,
                subpath_id: self.subpath_id,
                subpath_name: self.name.clone(),
                previous_state: prev_state,
                current_state: target_state,
                health_score: self.health_score,
                reason,
            })
        } else {
            None
        }
    }
}

/// Subpath Health Monitor orchestrating telemetry analysis, degradation alerts, and failover candidate selection.
pub struct SubpathHealthMonitor {
    config: SubpathHealthConfig,
    trackers: BTreeMap<u8, SubpathHealthTracker>,
    alert_history: VecDeque<SubpathDegradedAlertEvent>,
    alert_sinks: Vec<Arc<dyn SubpathAlertSink>>,
}

impl SubpathHealthMonitor {
    /// Creates a new subpath health monitor with default thresholds.
    pub fn new() -> Self {
        Self::with_config(SubpathHealthConfig::default())
    }

    /// Creates a new subpath health monitor with specified configuration parameters.
    pub fn with_config(config: SubpathHealthConfig) -> Self {
        let max_history = config.max_alert_history;
        Self {
            config,
            trackers: BTreeMap::new(),
            alert_history: VecDeque::with_capacity(max_history),
            alert_sinks: Vec::new(),
        }
    }

    /// Registers an alert notification sink (e.g. for Webhook emission).
    pub fn register_alert_sink(&mut self, sink: Arc<dyn SubpathAlertSink>) {
        self.alert_sinks.push(sink);
    }

    /// Registers a new subpath into the health monitor.
    pub fn register_subpath(
        &mut self,
        subpath_id: u8,
        name: impl Into<String>,
        initial_rtt_ms: u64,
        now_ns: u64,
    ) {
        let tracker = SubpathHealthTracker::new(subpath_id, name, initial_rtt_ms, now_ns);
        self.trackers.insert(subpath_id, tracker);
    }

    /// Removes a subpath from active health monitoring.
    pub fn unregister_subpath(&mut self, subpath_id: u8) -> Option<SubpathHealthTracker> {
        self.trackers.remove(&subpath_id)
    }

    /// Records a successful packet admission on a subpath, clearing consecutive failure streak.
    pub fn record_admission_success(&mut self, subpath_id: u8, now_ns: u64) {
        if let Some(tracker) = self.trackers.get_mut(&subpath_id) {
            tracker.consecutive_admission_failures = 0;
            if let Some(alert) = tracker.recalculate_health(&self.config, now_ns) {
                self.dispatch_alert(alert);
            }
        }
    }

    /// Records an admission failure (e.g. shaper throttled frame or send error).
    pub fn record_admission_failure(&mut self, subpath_id: u8, now_ns: u64) {
        if let Some(tracker) = self.trackers.get_mut(&subpath_id) {
            tracker.consecutive_admission_failures =
                tracker.consecutive_admission_failures.saturating_add(1);
            tracker.total_admission_failures = tracker.total_admission_failures.saturating_add(1);
            if let Some(alert) = tracker.recalculate_health(&self.config, now_ns) {
                self.dispatch_alert(alert);
            }
        }
    }

    /// Updates RTT and jitter measurements for a subpath based on recent ping/probe samples.
    pub fn record_rtt_measurement(&mut self, subpath_id: u8, sample_rtt_ms: u64, now_ns: u64) {
        if let Some(tracker) = self.trackers.get_mut(&subpath_id) {
            tracker.current_rtt_ms = sample_rtt_ms;

            // Exponentially Weighted Moving Average (EWMA) for smoothed RTT: alpha = 0.125
            let alpha = 0.125;
            let sample_f = sample_rtt_ms as f64;
            let diff = (sample_f - tracker.smoothed_rtt_ms).abs();
            tracker.smoothed_rtt_ms = (1.0 - alpha) * tracker.smoothed_rtt_ms + alpha * sample_f;

            // EWMA for jitter: beta = 0.25
            let beta = 0.25;
            tracker.rtt_jitter_ms = ((1.0 - beta) * (tracker.rtt_jitter_ms as f64) + beta * diff) as u64;

            if let Some(alert) = tracker.recalculate_health(&self.config, now_ns) {
                self.dispatch_alert(alert);
            }
        }
    }

    /// Records a PMTU probe timeout/loss on a subpath.
    pub fn record_probe_loss(&mut self, subpath_id: u8, now_ns: u64) {
        if let Some(tracker) = self.trackers.get_mut(&subpath_id) {
            tracker.consecutive_probe_losses = tracker.consecutive_probe_losses.saturating_add(1);
            tracker.total_probe_losses = tracker.total_probe_losses.saturating_add(1);
            if let Some(alert) = tracker.recalculate_health(&self.config, now_ns) {
                self.dispatch_alert(alert);
            }
        }
    }

    /// Records a PMTU probe acknowledgment on a subpath.
    pub fn record_probe_success(&mut self, subpath_id: u8, now_ns: u64) {
        if let Some(tracker) = self.trackers.get_mut(&subpath_id) {
            tracker.consecutive_probe_losses = 0;
            if let Some(alert) = tracker.recalculate_health(&self.config, now_ns) {
                self.dispatch_alert(alert);
            }
        }
    }

    /// Dispatches an alert to registered sinks and appends it to the internal history buffer.
    fn dispatch_alert(&mut self, alert: SubpathDegradedAlertEvent) {
        for sink in &self.alert_sinks {
            sink.on_alert(&alert);
        }
        if self.alert_history.len() >= self.config.max_alert_history {
            self.alert_history.pop_front();
        }
        self.alert_history.push_back(alert);
    }

    /// Selects the best surviving fallback subpath for transparent failover.
    ///
    /// Considers candidate subpaths, ranking by health score, latency, and available bandwidth.
    /// If a viable fallback is chosen, the failed subpath's `failover_events_total` counter is incremented.
    pub fn select_best_fallback_subpath(
        &mut self,
        failed_subpath_id: u8,
        slice_class: FlowSliceClass,
        active_subpaths: &[(u8, String, u64, u64, bool)],
    ) -> Option<u8> {
        let mut best_candidate: Option<(u8, f64)> = None;

        for &(candidate_id, _, rtt_ms, bw_bps, is_active) in active_subpaths {
            if candidate_id == failed_subpath_id || !is_active {
                continue;
            }

            let tracker = self.trackers.get(&candidate_id)?;
            if !tracker.state.is_viable() {
                continue;
            }

            // Weighted multi-factor ranking score:
            // Score = HealthScore * w_h + LatencyScore * w_l + BandwidthScore * w_bw
            let health_factor = tracker.health_score as f64; // 0..100
            let rtt_factor = 1000.0 / (rtt_ms.max(1) as f64); // Higher is faster
            let bw_factor = (bw_bps as f64) / 1_000_000.0; // Mbps

            let composite_score = match slice_class {
                FlowSliceClass::UltraLowLatency => {
                    // Heavily prioritize lowest latency and pristine health
                    health_factor * 0.50 + rtt_factor * 0.45 + (bw_factor.min(100.0)) * 0.05
                }
                FlowSliceClass::MissionCritical => {
                    // Maximum weight on health stability and reliability
                    health_factor * 0.70 + rtt_factor * 0.20 + (bw_factor.min(100.0)) * 0.10
                }
                FlowSliceClass::HighThroughput => {
                    // Prioritize bandwidth capacity
                    health_factor * 0.40 + (bw_factor.min(500.0)) * 0.45 + rtt_factor * 0.15
                }
                FlowSliceClass::BestEffort => {
                    // Balanced distribution
                    health_factor * 0.50 + (bw_factor.min(100.0)) * 0.30 + rtt_factor * 0.20
                }
            };

            match best_candidate {
                None => best_candidate = Some((candidate_id, composite_score)),
                Some((_, best_score)) if composite_score > best_score => {
                    best_candidate = Some((candidate_id, composite_score));
                }
                _ => {}
            }
        }

        if let Some((chosen_id, _)) = best_candidate {
            if let Some(failed_tracker) = self.trackers.get_mut(&failed_subpath_id) {
                failed_tracker.failover_events_total =
                    failed_tracker.failover_events_total.saturating_add(1);
            }
            Some(chosen_id)
        } else {
            None
        }
    }

    /// Retrieves an immutable reference to a subpath's health tracker.
    pub fn tracker(&self, subpath_id: u8) -> Option<&SubpathHealthTracker> {
        self.trackers.get(&subpath_id)
    }

    /// Retrieves all tracked subpaths.
    pub fn all_trackers(&self) -> &BTreeMap<u8, SubpathHealthTracker> {
        &self.trackers
    }

    /// Retrieves the recent alert history buffer.
    pub fn alert_history(&self) -> &VecDeque<SubpathDegradedAlertEvent> {
        &self.alert_history
    }

    /// Exports OpenMetrics/Prometheus formatted lines.
    pub fn export_prometheus_metrics(&self) -> String {
        let mut out = String::with_capacity(1024);

        let _ = writeln!(
            out,
            "# HELP ifa_transport_subpath_health_score Dynamic composite health score (0-100)"
        );
        let _ = writeln!(
            out,
            "# TYPE ifa_transport_subpath_health_score gauge"
        );
        for t in self.trackers.values() {
            let _ = writeln!(
                out,
                "ifa_transport_subpath_health_score{{subpath=\"{}\",name=\"{}\"}} {}",
                t.subpath_id, t.name, t.health_score
            );
        }

        let _ = writeln!(
            out,
            "# HELP ifa_transport_subpath_degraded_events_total Count of degraded or critical state transitions"
        );
        let _ = writeln!(
            out,
            "# TYPE ifa_transport_subpath_degraded_events_total counter"
        );
        for t in self.trackers.values() {
            let _ = writeln!(
                out,
                "ifa_transport_subpath_degraded_events_total{{subpath=\"{}\",name=\"{}\"}} {}",
                t.subpath_id, t.name, t.degraded_events_total
            );
        }

        let _ = writeln!(
            out,
            "# HELP ifa_transport_subpath_failover_events_total Failover events initiated away from this subpath"
        );
        let _ = writeln!(
            out,
            "# TYPE ifa_transport_subpath_failover_events_total counter"
        );
        for t in self.trackers.values() {
            let _ = writeln!(
                out,
                "ifa_transport_subpath_failover_events_total{{subpath=\"{}\",name=\"{}\"}} {}",
                t.subpath_id, t.name, t.failover_events_total
            );
        }

        let _ = writeln!(
            out,
            "# HELP ifa_transport_subpath_consecutive_admission_failures Consecutive admission failures on subpath"
        );
        let _ = writeln!(
            out,
            "# TYPE ifa_transport_subpath_consecutive_admission_failures gauge"
        );
        for t in self.trackers.values() {
            let _ = writeln!(
                out,
                "ifa_transport_subpath_consecutive_admission_failures{{subpath=\"{}\"}} {}",
                t.subpath_id, t.consecutive_admission_failures
            );
        }

        let _ = writeln!(
            out,
            "# HELP ifa_transport_subpath_consecutive_probe_losses Consecutive PMTU probe losses on subpath"
        );
        let _ = writeln!(
            out,
            "# TYPE ifa_transport_subpath_consecutive_probe_losses gauge"
        );
        for t in self.trackers.values() {
            let _ = writeln!(
                out,
                "ifa_transport_subpath_consecutive_probe_losses{{subpath=\"{}\"}} {}",
                t.subpath_id, t.consecutive_probe_losses
            );
        }

        let _ = writeln!(
            out,
            "# HELP ifa_transport_subpath_rtt_jitter_ms Subpath RTT jitter variance in milliseconds"
        );
        let _ = writeln!(
            out,
            "# TYPE ifa_transport_subpath_rtt_jitter_ms gauge"
        );
        for t in self.trackers.values() {
            let _ = writeln!(
                out,
                "ifa_transport_subpath_rtt_jitter_ms{{subpath=\"{}\"}} {}",
                t.subpath_id, t.rtt_jitter_ms
            );
        }

        let _ = writeln!(
            out,
            "# HELP ifa_transport_subpath_state Operational health state indicator (1 for active state, 0 otherwise)"
        );
        let _ = writeln!(
            out,
            "# TYPE ifa_transport_subpath_state gauge"
        );
        for t in self.trackers.values() {
            for state in [
                SubpathHealthState::Healthy,
                SubpathHealthState::Degraded,
                SubpathHealthState::Critical,
                SubpathHealthState::Down,
            ] {
                let val = if t.state == state { 1 } else { 0 };
                let _ = writeln!(
                    out,
                    "ifa_transport_subpath_state{{subpath=\"{}\",state=\"{}\"}} {}",
                    t.subpath_id,
                    state.as_str(),
                    val
                );
            }
        }

        out
    }
}

impl Default for SubpathHealthMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TestAlertSink {
        alert_count: AtomicUsize,
    }

    impl SubpathAlertSink for TestAlertSink {
        fn on_alert(&self, _alert: &SubpathDegradedAlertEvent) {
            self.alert_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn test_subpath_health_tracker_initial_state() {
        let tracker = SubpathHealthTracker::new(1, "eth0", 20, 1000);
        assert_eq!(tracker.state, SubpathHealthState::Healthy);
        assert_eq!(tracker.health_score, 100);
        assert_eq!(tracker.baseline_rtt_ms, 20);
        assert_eq!(tracker.consecutive_admission_failures, 0);
    }

    #[test]
    fn test_subpath_degradation_on_admission_failures() {
        let mut monitor = SubpathHealthMonitor::new();
        let sink = Arc::new(TestAlertSink {
            alert_count: AtomicUsize::new(0),
        });
        monitor.register_alert_sink(sink.clone());

        monitor.register_subpath(1, "lte-wan", 30, 1000);
        assert_eq!(monitor.tracker(1).unwrap().state, SubpathHealthState::Healthy);

        // Record 3 admission failures
        for _ in 0..3 {
            monitor.record_admission_failure(1, 2000);
        }
        let tracker = monitor.tracker(1).unwrap();
        assert_eq!(tracker.consecutive_admission_failures, 3);
        assert!(tracker.health_score < 70);
        assert_eq!(tracker.state, SubpathHealthState::Degraded);
        assert_eq!(sink.alert_count.load(Ordering::Relaxed), 1);

        // Record success, clears streak and restores Healthy
        monitor.record_admission_success(1, 3000);
        let tracker_restored = monitor.tracker(1).unwrap();
        assert_eq!(tracker_restored.consecutive_admission_failures, 0);
        assert_eq!(tracker_restored.state, SubpathHealthState::Healthy);
    }

    #[test]
    fn test_subpath_degradation_on_rtt_and_jitter_spike() {
        let mut monitor = SubpathHealthMonitor::new();
        monitor.register_subpath(2, "wwan-5g", 20, 1000);

        // Sudden RTT jump from 20ms to 90ms with heavy jitter
        monitor.record_rtt_measurement(2, 90, 2000);
        let tracker = monitor.tracker(2).unwrap();
        assert!(tracker.rtt_jitter_ms > 0);
        assert!(tracker.health_score < 100);
    }

    #[test]
    fn test_subpath_probe_loss_transitions_to_down() {
        let mut monitor = SubpathHealthMonitor::new();
        monitor.register_subpath(3, "sat-link", 600, 1000);

        // Default config max probe losses is 3
        monitor.record_probe_loss(3, 2000);
        assert_eq!(monitor.tracker(3).unwrap().consecutive_probe_losses, 1);
        monitor.record_probe_loss(3, 3000);
        assert_eq!(monitor.tracker(3).unwrap().consecutive_probe_losses, 2);
        monitor.record_probe_loss(3, 4000);

        let tracker = monitor.tracker(3).unwrap();
        assert_eq!(tracker.consecutive_probe_losses, 3);
        assert_eq!(tracker.state, SubpathHealthState::Down);
        assert_eq!(tracker.health_score, 0);

        // Probe recovery
        monitor.record_probe_success(3, 5000);
        let tracker_recovered = monitor.tracker(3).unwrap();
        assert_eq!(tracker_recovered.consecutive_probe_losses, 0);
        assert_eq!(tracker_recovered.state, SubpathHealthState::Healthy);
    }

    #[test]
    fn test_subpath_transparent_failover_selection() {
        let mut monitor = SubpathHealthMonitor::new();
        monitor.register_subpath(1, "eth0-wan", 10, 1000);
        monitor.register_subpath(2, "wwan-5g", 40, 1000);

        // Subpath 1 degrades heavily
        for _ in 0..5 {
            monitor.record_admission_failure(1, 2000);
        }
        assert_eq!(monitor.tracker(1).unwrap().state, SubpathHealthState::Critical);

        let subpaths = vec![
            (1, "eth0-wan".to_string(), 10, 100_000_000, true),
            (2, "wwan-5g".to_string(), 40, 50_000_000, true),
        ];

        let fallback = monitor.select_best_fallback_subpath(
            1,
            FlowSliceClass::UltraLowLatency,
            &subpaths,
        );
        assert_eq!(fallback, Some(2));
        assert_eq!(monitor.tracker(1).unwrap().failover_events_total, 1);
    }

    #[test]
    fn test_prometheus_metrics_export() {
        let mut monitor = SubpathHealthMonitor::new();
        monitor.register_subpath(1, "eth0", 15, 1000);
        monitor.record_admission_failure(1, 2000);

        let prom = monitor.export_prometheus_metrics();
        assert!(prom.contains("ifa_transport_subpath_health_score{subpath=\"1\",name=\"eth0\"}"));
        assert!(prom.contains("ifa_transport_subpath_degraded_events_total{subpath=\"1\",name=\"eth0\"}"));
        assert!(prom.contains("ifa_transport_subpath_state{subpath=\"1\",state=\""));
    }
}

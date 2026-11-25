//! Jitter Anomaly Detection and Predictive Dynamic Threshold Derivation Engine for BBR / LEDBAT.
//!
//! Provides real-time statistical anomaly classification (transient spikes, bufferbloat onset,
//! route shifts, microburst congestion) and dynamically calculates adaptive queuing delay targets
//! for LEDBAT and pacing rates / ProbeRTT triggers for BBR in high-speed multipath networks.

use crate::session_sync::{IsspCongestionState, IsspMultipathRoute};

/// Classification of observed jitter patterns and delay excursions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JitterAnomalyKind {
    /// Normal jitter variance within expected baseline bounds.
    Nominal,
    /// Transient delay spike (e.g. isolated Wi-Fi/cellular frame aggregation or retransmission).
    TransientSpike,
    /// Sustained monotonic increase in queuing delay without loss — early bufferbloat signal.
    BufferbloatOnset,
    /// Persistent step change in minimum propagation delay (e.g. physical rerouting or handover).
    RouteShift,
    /// High-frequency variance oscillations indicating switch buffer queue thrashing.
    MicroburstCongestion,
    /// Extreme jitter variance coupled with heavy packet loss or delay divergence.
    SevereImpairment,
}

impl JitterAnomalyKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Nominal => "Nominal",
            Self::TransientSpike => "TransientSpike",
            Self::BufferbloatOnset => "BufferbloatOnset",
            Self::RouteShift => "RouteShift",
            Self::MicroburstCongestion => "MicroburstCongestion",
            Self::SevereImpairment => "SevereImpairment",
        }
    }
}

/// Operational severity level associated with a jitter anomaly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AnomalySeverity {
    /// Standard operating state, zero mitigation needed.
    Nominal = 0,
    /// Mild jitter deviation, passive monitoring.
    Low = 1,
    /// Actionable variance detected; threshold adaptation activated.
    Medium = 2,
    /// High congestion / bufferbloat risk; aggressive backoff and pacing throttle.
    High = 3,
    /// Critical impairment; emergency routing backoff or immediate probe required.
    Critical = 4,
}

impl AnomalySeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Nominal => "Nominal",
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        }
    }
}

/// Recommended action derived for BBR / LEDBAT and the multipath scheduler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JitterMitigationAction {
    /// Continue nominal pacing and congestion window trajectory.
    Maintain,
    /// Dynamically contract LEDBAT target delay to aggressively drain upstream buffer.
    ContractLedbatTarget,
    /// Throttle BBR pacing rate below 1.0x to smooth out microburst packet trains.
    ScaleBbrPacing,
    /// Immediately trigger BBR ProbeRTT epoch to re-anchor invalid RTprop baseline.
    TriggerProbeRtt,
    /// De-prioritize or divert traffic away from this subpath in multipath scheduler.
    SteerMultipathTraffic,
}

impl JitterMitigationAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Maintain => "Maintain",
            Self::ContractLedbatTarget => "ContractLedbatTarget",
            Self::ScaleBbrPacing => "ScaleBbrPacing",
            Self::TriggerProbeRtt => "TriggerProbeRtt",
            Self::SteerMultipathTraffic => "SteerMultipathTraffic",
        }
    }
}

/// Predictively derived dynamic thresholds for BBR and LEDBAT congestion controllers.
#[derive(Debug, Clone, PartialEq)]
pub struct DynamicCongestionThresholds {
    /// Dynamically adapted LEDBAT target queuing delay in microseconds (RFC 6817 adaptation).
    pub dynamic_ledbat_target_us: u64,
    /// Dynamically adapted BBR pacing gain (Q8.8 fixed-point: 256 = 1.0x, 218 = 0.85x).
    pub dynamic_bbr_pacing_gain_q8: u32,
    /// Recommended duration for BBR minimum RTT expiry window in milliseconds.
    pub dynamic_bbr_min_rtt_window_ms: u64,
    /// Flag indicating that RTprop baseline is invalidated and immediate ProbeRTT is required.
    pub probe_rtt_required: bool,
    /// Predicted queuing delay 1-2 RTTs into the future in microseconds.
    pub predicted_queue_delay_us: u64,
    /// Continuous congestion risk index normalized in [0.0, 1.0].
    pub congestion_risk_score: f64,
    /// Recommended mitigation action.
    pub recommended_action: JitterMitigationAction,
}

impl Default for DynamicCongestionThresholds {
    fn default() -> Self {
        Self {
            dynamic_ledbat_target_us: 25_000,
            dynamic_bbr_pacing_gain_q8: 256,
            dynamic_bbr_min_rtt_window_ms: 10_000,
            probe_rtt_required: false,
            predicted_queue_delay_us: 0,
            congestion_risk_score: 0.0,
            recommended_action: JitterMitigationAction::Maintain,
        }
    }
}

/// Configuration parameters for the jitter anomaly detection engine.
#[derive(Debug, Clone, PartialEq)]
pub struct JitterDetectorConfig {
    /// History window capacity for sliding statistical estimates.
    pub window_size: usize,
    /// Z-score statistical threshold above which a delay deviation is marked an anomaly.
    pub spike_z_score_threshold: f64,
    /// Queuing delay gradient in microseconds indicating bufferbloat onset.
    pub bufferbloat_growth_threshold_us: u64,
    /// Step change in minimum propagation RTT in microseconds indicating a route shift.
    pub route_shift_step_us: u64,
    /// Minimum clamping floor for dynamic LEDBAT target delay in microseconds.
    pub min_ledbat_target_us: u64,
    /// Maximum clamping ceiling for dynamic LEDBAT target delay in microseconds.
    pub max_ledbat_target_us: u64,
    /// Baseline nominal LEDBAT target delay in microseconds (RFC 6817 default: 25ms).
    pub nominal_ledbat_target_us: u64,
    /// Nominal BBR pacing gain in Q8.8 fixed point (256 = 1.0x).
    pub bbr_nominal_gain_q8: u32,
    /// Backoff BBR pacing gain under microbursts/bloat in Q8.8 fixed point (218 = 0.85x).
    pub bbr_backoff_gain_q8: u32,
}

impl Default for JitterDetectorConfig {
    fn default() -> Self {
        Self {
            window_size: 32,
            spike_z_score_threshold: 2.5,
            bufferbloat_growth_threshold_us: 4_000, // 4 ms queuing rise
            route_shift_step_us: 12_000,            // 12 ms baseline step change
            min_ledbat_target_us: 5_000,            // 5 ms floor
            max_ledbat_target_us: 60_000,           // 60 ms ceiling
            nominal_ledbat_target_us: 25_000,       // 25 ms nominal
            bbr_nominal_gain_q8: 256,               // 1.0x
            bbr_backoff_gain_q8: 218,               // 0.85x
        }
    }
}

/// Detailed evaluation output for a single RTT sample.
#[derive(Debug, Clone, PartialEq)]
pub struct JitterSampleEvaluation {
    /// Monotonic sequence index of the sample.
    pub sample_index: u64,
    /// Raw measured round-trip time in microseconds.
    pub rtt_us: u64,
    /// Instantaneous jitter: |RTT_curr - RTT_prev| in microseconds.
    pub instantaneous_jitter_us: u64,
    /// RFC 3550 EWMA smoothed jitter in microseconds.
    pub rfc3550_jitter_us: u64,
    /// Statistical standard score (z-score) relative to the rolling distribution.
    pub z_score: f64,
    /// Minimum propagation delay baseline (RTprop) in microseconds.
    pub base_rtt_us: u64,
    /// Estimated queuing delay (RTT - base_rtt) in microseconds.
    pub queuing_delay_us: u64,
    /// Classified anomaly kind.
    pub anomaly_kind: JitterAnomalyKind,
    /// Severity classification.
    pub severity: AnomalySeverity,
    /// Dynamically derived BBR and LEDBAT thresholds.
    pub derived_thresholds: DynamicCongestionThresholds,
}

/// Summary statistical counters of the jitter detector.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct JitterDetectorStats {
    pub total_samples: u64,
    pub nominal_count: u64,
    pub spike_count: u64,
    pub bufferbloat_count: u64,
    pub route_shift_count: u64,
    pub microburst_count: u64,
    pub severe_count: u64,
    pub last_anomaly: Option<JitterAnomalyKind>,
    pub current_mean_rtt_us: f64,
    pub current_std_dev_us: f64,
    pub current_base_rtt_us: u64,
}

/// Real-time statistical jitter anomaly detection engine.
#[derive(Debug, Clone)]
pub struct JitterAnomalyDetector {
    config: JitterDetectorConfig,
    /// Rolling window of recent RTT samples.
    rtt_window: [u64; 64],
    window_pos: usize,
    sample_count: u64,
    /// Welford algorithm running state for numerical mean and variance.
    welford_count: u64,
    welford_mean: f64,
    welford_m2: f64,
    /// Fast EWMA (alpha = 0.25) for immediate trend tracking.
    fast_ewma_rtt: f64,
    /// Slow EWMA (alpha = 0.05) for stable baseline tracking.
    slow_ewma_rtt: f64,
    /// RFC 3550 inter-arrival jitter estimator in microseconds.
    rfc3550_jitter: f64,
    /// Last processed RTT sample in microseconds.
    last_rtt_us: u64,
    /// Minimum propagation delay observed (min-filter).
    min_rtt_us: u64,
    min_rtt_timestamp_ns: u64,
    /// Consecutive samples with monotonically increasing queuing delay.
    consecutive_bloat_samples: u32,
    /// Sign flip counter of recent jitter deltas for microburst oscillation detection.
    recent_sign_flips: u32,
    last_delta_sign: i8,
    /// Cooldown for ProbeRTT triggers following route shifts.
    probe_rtt_cooldown: u32,
    /// Cumulative sum (CUSUM) positive and negative drift statistics.
    cusum_pos: f64,
    cusum_neg: f64,
    /// Anomaly event counts.
    stats: JitterDetectorStats,
}

impl Default for JitterAnomalyDetector {
    fn default() -> Self {
        Self::new(JitterDetectorConfig::default())
    }
}

impl JitterAnomalyDetector {
    /// Create a new jitter anomaly detector with the given configuration.
    pub fn new(config: JitterDetectorConfig) -> Self {
        Self {
            config,
            rtt_window: [0u64; 64],
            window_pos: 0,
            sample_count: 0,
            welford_count: 0,
            welford_mean: 0.0,
            welford_m2: 0.0,
            fast_ewma_rtt: 0.0,
            slow_ewma_rtt: 0.0,
            rfc3550_jitter: 0.0,
            last_rtt_us: 0,
            min_rtt_us: u64::MAX,
            min_rtt_timestamp_ns: 0,
            consecutive_bloat_samples: 0,
            recent_sign_flips: 0,
            last_delta_sign: 0,
            probe_rtt_cooldown: 0,
            cusum_pos: 0.0,
            cusum_neg: 0.0,
            stats: JitterDetectorStats::default(),
        }
    }

    /// Reset all internal state and counters to initial configuration.
    pub fn reset(&mut self) {
        let cfg = self.config.clone();
        *self = Self::new(cfg);
    }

    /// Acknowledge that a BBR ProbeRTT epoch has been dispatched.
    pub fn acknowledge_probe_rtt(&mut self) {
        self.probe_rtt_cooldown = 0;
    }

    /// Returns the configured engine parameters.
    pub fn config(&self) -> &JitterDetectorConfig {
        &self.config
    }

    /// Returns the statistical summary counters.
    pub fn stats(&self) -> &JitterDetectorStats {
        &self.stats
    }

    /// Current running mean RTT in microseconds.
    pub fn mean_rtt_us(&self) -> f64 {
        if self.welford_count > 0 {
            self.welford_mean
        } else {
            0.0
        }
    }

    /// Current running standard deviation of RTT in microseconds.
    pub fn std_dev_rtt_us(&self) -> f64 {
        if self.welford_count > 1 {
            (self.welford_m2 / (self.welford_count - 1) as f64).sqrt()
        } else {
            0.0
        }
    }

    /// Current RFC 3550 smoothed jitter estimate in microseconds.
    pub fn rfc3550_jitter_us(&self) -> u64 {
        self.rfc3550_jitter.round().max(0.0) as u64
    }

    /// Current minimum propagation baseline (RTprop) in microseconds.
    pub fn base_rtt_us(&self) -> u64 {
        if self.min_rtt_us == u64::MAX {
            0
        } else {
            self.min_rtt_us
        }
    }

    /// Record a new RTT measurement and perform real-time classification and dynamic threshold derivation.
    pub fn record_sample(
        &mut self,
        rtt_us: u64,
        transit_delay_us: Option<u64>,
        timestamp_ns: u64,
    ) -> JitterSampleEvaluation {
        self.sample_count += 1;
        self.stats.total_samples += 1;

        // Use one-way transit delay if explicitly provided, else raw RTT
        let effective_rtt = transit_delay_us.unwrap_or(rtt_us).max(1);

        // Store sample in sliding window
        let win_size = self.config.window_size.clamp(4, 64);
        self.rtt_window[self.window_pos % win_size] = effective_rtt;
        self.window_pos = self.window_pos.wrapping_add(1);

        // Compute instantaneous jitter: D = |rtt_curr - rtt_prev|
        let inst_jitter = if self.last_rtt_us > 0 {
            effective_rtt.abs_diff(self.last_rtt_us)
        } else {
            0
        };

        // RFC 3550 jitter EWMA: J = J + (|D| - J) / 16
        if self.sample_count == 1 {
            self.rfc3550_jitter = inst_jitter as f64;
            self.fast_ewma_rtt = effective_rtt as f64;
            self.slow_ewma_rtt = effective_rtt as f64;
            self.min_rtt_us = effective_rtt;
            self.min_rtt_timestamp_ns = timestamp_ns;
        } else {
            self.rfc3550_jitter += (inst_jitter as f64 - self.rfc3550_jitter) / 16.0;
            self.fast_ewma_rtt = 0.25 * effective_rtt as f64 + 0.75 * self.fast_ewma_rtt;
            self.slow_ewma_rtt = 0.05 * effective_rtt as f64 + 0.95 * self.slow_ewma_rtt;
        }

        // Microburst oscillation tracking (delta signs)
        if self.last_rtt_us > 0 {
            let curr_sign = if effective_rtt > self.last_rtt_us {
                1
            } else if effective_rtt < self.last_rtt_us {
                -1
            } else {
                0
            };
            if curr_sign != 0 && self.last_delta_sign != 0 && curr_sign != self.last_delta_sign {
                self.recent_sign_flips = (self.recent_sign_flips + 1).min(16);
            } else if self.recent_sign_flips > 0 {
                self.recent_sign_flips -= 1;
            }
            self.last_delta_sign = curr_sign;
        }

        // Update Welford's algorithm for online variance & standard deviation
        self.welford_count += 1;
        let delta = effective_rtt as f64 - self.welford_mean;
        self.welford_mean += delta / self.welford_count as f64;
        let delta2 = effective_rtt as f64 - self.welford_mean;
        self.welford_m2 += delta * delta2;

        let std_dev = self.std_dev_rtt_us();
        let z_score = if std_dev > 1.0 {
            (effective_rtt as f64 - self.welford_mean) / std_dev
        } else {
            0.0
        };

        // Update RTprop min-filter
        let mut route_shifted = false;
        if effective_rtt < self.min_rtt_us {
            // Check if baseline dropped significantly (downward route shift)
            if self.min_rtt_us != u64::MAX
                && self
                    .min_rtt_us
                    .saturating_sub(effective_rtt)
                    > self.config.route_shift_step_us
            {
                route_shifted = true;
            }
            self.min_rtt_us = effective_rtt;
            self.min_rtt_timestamp_ns = timestamp_ns;
        } else if self.min_rtt_us != u64::MAX {
            // Check for upward route shift (fast EWMA sustained far above min_rtt for extended duration)
            let base_delta = self.fast_ewma_rtt - self.min_rtt_us as f64;
            if base_delta > self.config.route_shift_step_us as f64
                && self.slow_ewma_rtt - self.min_rtt_us as f64
                    > self.config.route_shift_step_us as f64
                && self.sample_count >= 8
            {
                route_shifted = true;
                // Re-anchor min_rtt to the new elevated propagation baseline
                self.min_rtt_us = self.slow_ewma_rtt.round() as u64;
                self.min_rtt_timestamp_ns = timestamp_ns;
            }
        }

        if route_shifted {
            self.probe_rtt_cooldown = 10;
        } else if self.probe_rtt_cooldown > 0 {
            self.probe_rtt_cooldown -= 1;
        }

        // Queuing delay estimate = RTT - min_rtt
        let queuing_delay = effective_rtt.saturating_sub(self.min_rtt_us);

        // Consecutive bloat tracking: monotonic rise in queuing delay
        if queuing_delay > self.config.bufferbloat_growth_threshold_us {
            self.consecutive_bloat_samples = self.consecutive_bloat_samples.saturating_add(1);
        } else {
            self.consecutive_bloat_samples = self.consecutive_bloat_samples.saturating_sub(1);
        }

        // CUSUM drift detection
        let target_slack = 0.5 * std_dev.max(100.0);
        let s_pos = (effective_rtt as f64 - self.welford_mean) - target_slack;
        let s_neg = -(effective_rtt as f64 - self.welford_mean) - target_slack;
        self.cusum_pos = (self.cusum_pos + s_pos).max(0.0);
        self.cusum_neg = (self.cusum_neg + s_neg).max(0.0);

        // Classification Logic
        let (anomaly_kind, severity) = self.classify_anomaly(
            effective_rtt,
            z_score,
            queuing_delay,
            route_shifted,
            std_dev,
        );

        // Update stats
        match anomaly_kind {
            JitterAnomalyKind::Nominal => self.stats.nominal_count += 1,
            JitterAnomalyKind::TransientSpike => self.stats.spike_count += 1,
            JitterAnomalyKind::BufferbloatOnset => self.stats.bufferbloat_count += 1,
            JitterAnomalyKind::RouteShift => self.stats.route_shift_count += 1,
            JitterAnomalyKind::MicroburstCongestion => self.stats.microburst_count += 1,
            JitterAnomalyKind::SevereImpairment => self.stats.severe_count += 1,
        }
        self.stats.last_anomaly = Some(anomaly_kind);
        self.stats.current_mean_rtt_us = self.welford_mean;
        self.stats.current_std_dev_us = std_dev;
        self.stats.current_base_rtt_us = self.min_rtt_us;

        // Predictive derivation of BBR / LEDBAT thresholds
        let derived_thresholds = self.derive_thresholds_for(
            anomaly_kind,
            severity,
            queuing_delay,
            std_dev,
            route_shifted,
        );

        self.last_rtt_us = effective_rtt;

        JitterSampleEvaluation {
            sample_index: self.sample_count,
            rtt_us: effective_rtt,
            instantaneous_jitter_us: inst_jitter,
            rfc3550_jitter_us: self.rfc3550_jitter_us(),
            z_score,
            base_rtt_us: self.base_rtt_us(),
            queuing_delay_us: queuing_delay,
            anomaly_kind,
            severity,
            derived_thresholds,
        }
    }

    /// Internal classification of the observed sample.
    fn classify_anomaly(
        &self,
        _effective_rtt: u64,
        z_score: f64,
        queuing_delay: u64,
        route_shifted: bool,
        std_dev: f64,
    ) -> (JitterAnomalyKind, AnomalySeverity) {
        if route_shifted {
            return (JitterAnomalyKind::RouteShift, AnomalySeverity::High);
        }

        // Severe impairment: massive queuing delay sustained over multiple samples
        if queuing_delay > self.config.max_ledbat_target_us * 3
            && self.consecutive_bloat_samples >= 5
        {
            return (JitterAnomalyKind::SevereImpairment, AnomalySeverity::Critical);
        }

        // Bufferbloat onset: consecutive monotonic queuing increase
        if self.consecutive_bloat_samples >= 3
            && queuing_delay >= self.config.bufferbloat_growth_threshold_us
        {
            let sev = if queuing_delay > self.config.nominal_ledbat_target_us {
                AnomalySeverity::High
            } else {
                AnomalySeverity::Medium
            };
            return (JitterAnomalyKind::BufferbloatOnset, sev);
        }

        // Transient spike: high z-score or sudden isolated excursion above baseline
        if z_score >= self.config.spike_z_score_threshold
            || (self.base_rtt_us() > 0
                && queuing_delay >= self.config.nominal_ledbat_target_us
                && self.consecutive_bloat_samples < 3)
        {
            let sev = if z_score >= 3.5 || queuing_delay >= self.config.max_ledbat_target_us {
                AnomalySeverity::Medium
            } else {
                AnomalySeverity::Low
            };
            return (JitterAnomalyKind::TransientSpike, sev);
        }

        // Microburst congestion: rapid oscillations with elevated variance
        if self.recent_sign_flips >= 4 && std_dev > 1_500.0 {
            return (
                JitterAnomalyKind::MicroburstCongestion,
                AnomalySeverity::Medium,
            );
        }

        // Nominal
        (JitterAnomalyKind::Nominal, AnomalySeverity::Nominal)
    }

    /// Predictively derive dynamic thresholds for BBR / LEDBAT.
    fn derive_thresholds_for(
        &self,
        anomaly_kind: JitterAnomalyKind,
        severity: AnomalySeverity,
        queuing_delay: u64,
        std_dev: f64,
        route_shifted: bool,
    ) -> DynamicCongestionThresholds {
        let base_target = self.config.nominal_ledbat_target_us;
        let mut target_delay;
        let pacing_gain;
        let mut min_rtt_win_ms = 10_000u64;
        let mut probe_rtt_req = false;
        let mut action;

        // Predictive queue delay projection: linear projection based on EWMA slope
        let queue_slope = (self.fast_ewma_rtt - self.slow_ewma_rtt).max(0.0);
        let predicted_queue_delay = (queuing_delay as f64 + queue_slope).round() as u64;

        // Base congestion risk in [0.0, 1.0]
        let mut risk_score = (queuing_delay as f64 / base_target as f64).clamp(0.0, 0.85);

        match anomaly_kind {
            JitterAnomalyKind::Nominal => {
                let adaptive = (0.2 * self.base_rtt_us() as f64 + 2.0 * std_dev).round() as u64;
                target_delay = adaptive
                    .clamp(self.config.min_ledbat_target_us, self.config.max_ledbat_target_us);
                pacing_gain = self.config.bbr_nominal_gain_q8; // 1.0x
                action = JitterMitigationAction::Maintain;
            }
            JitterAnomalyKind::TransientSpike => {
                target_delay = (base_target as f64 * 1.3).round() as u64;
                target_delay = target_delay.min(self.config.max_ledbat_target_us);
                pacing_gain = self.config.bbr_nominal_gain_q8;
                risk_score = (risk_score + 0.15).min(1.0);
                action = JitterMitigationAction::Maintain;
            }
            JitterAnomalyKind::BufferbloatOnset => {
                let contraction_factor = match severity {
                    AnomalySeverity::High | AnomalySeverity::Critical => 0.40,
                    _ => 0.65,
                };
                target_delay = (base_target as f64 * contraction_factor).round() as u64;
                target_delay = target_delay.max(self.config.min_ledbat_target_us);
                pacing_gain = self.config.bbr_backoff_gain_q8;
                risk_score = 0.80 + 0.15 * (severity as u8 as f64 / 4.0);
                action = JitterMitigationAction::ContractLedbatTarget;
            }
            JitterAnomalyKind::RouteShift => {
                probe_rtt_req = true;
                min_rtt_win_ms = 1_000;
                target_delay = base_target;
                pacing_gain = (self.config.bbr_nominal_gain_q8 as f64 * 0.90).round() as u32;
                risk_score = 0.70;
                action = JitterMitigationAction::TriggerProbeRtt;
            }
            JitterAnomalyKind::MicroburstCongestion => {
                pacing_gain = self.config.bbr_backoff_gain_q8;
                target_delay = (base_target as f64 * 0.85).round() as u64;
                risk_score = 0.65;
                action = JitterMitigationAction::ScaleBbrPacing;
            }
            JitterAnomalyKind::SevereImpairment => {
                target_delay = self.config.min_ledbat_target_us;
                pacing_gain = (self.config.bbr_nominal_gain_q8 as f64 * 0.70).round() as u32;
                risk_score = 1.0;
                action = JitterMitigationAction::SteerMultipathTraffic;
            }
        }

        if route_shifted || self.probe_rtt_cooldown > 0 {
            probe_rtt_req = true;
            action = JitterMitigationAction::TriggerProbeRtt;
        }

        DynamicCongestionThresholds {
            dynamic_ledbat_target_us: target_delay,
            dynamic_bbr_pacing_gain_q8: pacing_gain,
            dynamic_bbr_min_rtt_window_ms: min_rtt_win_ms,
            probe_rtt_required: probe_rtt_req,
            predicted_queue_delay_us: predicted_queue_delay,
            congestion_risk_score: risk_score.clamp(0.0, 1.0),
            recommended_action: action,
        }
    }

    /// Derive current dynamic thresholds using the latest detector state.
    pub fn derive_thresholds(&self) -> DynamicCongestionThresholds {
        let queuing = self.last_rtt_us.saturating_sub(self.base_rtt_us());
        let std_dev = self.std_dev_rtt_us();
        let last_kind = self.stats.last_anomaly.unwrap_or(JitterAnomalyKind::Nominal);
        let sev = match last_kind {
            JitterAnomalyKind::Nominal => AnomalySeverity::Nominal,
            JitterAnomalyKind::TransientSpike => AnomalySeverity::Low,
            JitterAnomalyKind::BufferbloatOnset => AnomalySeverity::High,
            JitterAnomalyKind::RouteShift => AnomalySeverity::High,
            JitterAnomalyKind::MicroburstCongestion => AnomalySeverity::Medium,
            JitterAnomalyKind::SevereImpairment => AnomalySeverity::Critical,
        };
        self.derive_thresholds_for(last_kind, sev, queuing, std_dev, false)
    }

    /// Export real-time Prometheus telemetry metrics for this detector instance.
    pub fn to_prometheus_metrics(&self, path_id: u32, iface: &str) -> String {
        let mut out = String::with_capacity(1024);
        let thresholds = self.derive_thresholds();

        out.push_str("# HELP ifa_jitter_mean_rtt_us Running mean round-trip time in microseconds.\n");
        out.push_str("# TYPE ifa_jitter_mean_rtt_us gauge\n");
        out.push_str(&format!(
            "ifa_jitter_mean_rtt_us{{path_id=\"{}\",iface=\"{}\"}} {:.1}\n",
            path_id, iface, self.welford_mean
        ));

        out.push_str("# HELP ifa_jitter_std_dev_us Running standard deviation of RTT in microseconds.\n");
        out.push_str("# TYPE ifa_jitter_std_dev_us gauge\n");
        out.push_str(&format!(
            "ifa_jitter_std_dev_us{{path_id=\"{}\",iface=\"{}\"}} {:.1}\n",
            path_id, iface, self.std_dev_rtt_us()
        ));

        out.push_str("# HELP ifa_jitter_rfc3550_us RFC 3550 interarrival jitter in microseconds.\n");
        out.push_str("# TYPE ifa_jitter_rfc3550_us gauge\n");
        out.push_str(&format!(
            "ifa_jitter_rfc3550_us{{path_id=\"{}\",iface=\"{}\"}} {}\n",
            path_id, iface, self.rfc3550_jitter_us()
        ));

        out.push_str("# HELP ifa_jitter_anomalies_total Total classified jitter anomalies by kind.\n");
        out.push_str("# TYPE ifa_jitter_anomalies_total counter\n");
        out.push_str(&format!(
            "ifa_jitter_anomalies_total{{path_id=\"{}\",iface=\"{}\",kind=\"nominal\"}} {}\n",
            path_id, iface, self.stats.nominal_count
        ));
        out.push_str(&format!(
            "ifa_jitter_anomalies_total{{path_id=\"{}\",iface=\"{}\",kind=\"spike\"}} {}\n",
            path_id, iface, self.stats.spike_count
        ));
        out.push_str(&format!(
            "ifa_jitter_anomalies_total{{path_id=\"{}\",iface=\"{}\",kind=\"bufferbloat\"}} {}\n",
            path_id, iface, self.stats.bufferbloat_count
        ));
        out.push_str(&format!(
            "ifa_jitter_anomalies_total{{path_id=\"{}\",iface=\"{}\",kind=\"route_shift\"}} {}\n",
            path_id, iface, self.stats.route_shift_count
        ));
        out.push_str(&format!(
            "ifa_jitter_anomalies_total{{path_id=\"{}\",iface=\"{}\",kind=\"microburst\"}} {}\n",
            path_id, iface, self.stats.microburst_count
        ));
        out.push_str(&format!(
            "ifa_jitter_anomalies_total{{path_id=\"{}\",iface=\"{}\",kind=\"severe\"}} {}\n",
            path_id, iface, self.stats.severe_count
        ));

        out.push_str("# HELP ifa_dynamic_ledbat_target_us Predictively derived dynamic LEDBAT target delay in microseconds.\n");
        out.push_str("# TYPE ifa_dynamic_ledbat_target_us gauge\n");
        out.push_str(&format!(
            "ifa_dynamic_ledbat_target_us{{path_id=\"{}\",iface=\"{}\"}} {}\n",
            path_id, iface, thresholds.dynamic_ledbat_target_us
        ));

        out.push_str("# HELP ifa_dynamic_bbr_pacing_gain Predictively derived BBR pacing gain multiplier (1.0 = 256).\n");
        out.push_str("# TYPE ifa_dynamic_bbr_pacing_gain gauge\n");
        out.push_str(&format!(
            "ifa_dynamic_bbr_pacing_gain{{path_id=\"{}\",iface=\"{}\"}} {:.3}\n",
            path_id, iface, thresholds.dynamic_bbr_pacing_gain_q8 as f64 / 256.0
        ));

        out.push_str("# HELP ifa_jitter_congestion_risk_score Normalized predictive congestion risk score [0.0, 1.0].\n");
        out.push_str("# TYPE ifa_jitter_congestion_risk_score gauge\n");
        out.push_str(&format!(
            "ifa_jitter_congestion_risk_score{{path_id=\"{}\",iface=\"{}\"}} {:.4}\n",
            path_id, iface, thresholds.congestion_risk_score
        ));

        out
    }

    /// Serialize detector state and derived thresholds to JSON.
    pub fn to_json(&self, path_id: u32, iface: &str) -> String {
        let thresholds = self.derive_thresholds();
        let last_str = self
            .stats
            .last_anomaly
            .map(|a| a.as_str())
            .unwrap_or("Nominal");

        format!(
            concat!(
                "{{",
                "\"path_id\":{},",
                "\"interface_name\":\"{}\",",
                "\"total_samples\":{},",
                "\"mean_rtt_us\":{:.2},",
                "\"std_dev_us\":{:.2},",
                "\"base_rtt_us\":{},",
                "\"rfc3550_jitter_us\":{},",
                "\"last_anomaly\":\"{}\",",
                "\"anomalies\":{{",
                "\"nominal\":{},",
                "\"transient_spike\":{},",
                "\"bufferbloat_onset\":{},",
                "\"route_shift\":{},",
                "\"microburst\":{},",
                "\"severe_impairment\":{}",
                "}},",
                "\"derived_thresholds\":{{",
                "\"dynamic_ledbat_target_us\":{},",
                "\"dynamic_bbr_pacing_gain_q8\":{},",
                "\"bbr_pacing_multiplier\":{:.3},",
                "\"probe_rtt_required\":{},",
                "\"predicted_queue_delay_us\":{},",
                "\"congestion_risk_score\":{:.4},",
                "\"recommended_action\":\"{}\"",
                "}}",
                "}}"
            ),
            path_id,
            iface,
            self.stats.total_samples,
            self.welford_mean,
            self.std_dev_rtt_us(),
            self.base_rtt_us(),
            self.rfc3550_jitter_us(),
            last_str,
            self.stats.nominal_count,
            self.stats.spike_count,
            self.stats.bufferbloat_count,
            self.stats.route_shift_count,
            self.stats.microburst_count,
            self.stats.severe_count,
            thresholds.dynamic_ledbat_target_us,
            thresholds.dynamic_bbr_pacing_gain_q8,
            thresholds.dynamic_bbr_pacing_gain_q8 as f64 / 256.0,
            thresholds.probe_rtt_required,
            thresholds.predicted_queue_delay_us,
            thresholds.congestion_risk_score,
            thresholds.recommended_action.as_str(),
        )
    }
}

/// Evaluator that bridges jitter anomaly detection with ISSP multipath routing.
#[derive(Debug, Clone)]
pub struct JitterMultipathBridge {
    detectors: Vec<(u32, String, JitterAnomalyDetector)>,
}

impl Default for JitterMultipathBridge {
    fn default() -> Self {
        Self::new()
    }
}

impl JitterMultipathBridge {
    pub fn new() -> Self {
        Self {
            detectors: Vec::new(),
        }
    }

    /// Register or get the detector for a specific subpath.
    pub fn get_or_create(
        &mut self,
        path_id: u32,
        iface: &str,
    ) -> &mut JitterAnomalyDetector {
        if let Some(pos) = self.detectors.iter().position(|(id, _, _)| *id == path_id) {
            return &mut self.detectors[pos].2;
        }
        self.detectors
            .push((path_id, iface.to_string(), JitterAnomalyDetector::default()));
        let last_idx = self.detectors.len() - 1;
        &mut self.detectors[last_idx].2
    }

    /// Process a telemetry heartbeat or frame feedback for a multipath route, updating congestion state.
    pub fn process_feedback(
        &mut self,
        route: &mut IsspMultipathRoute,
        rtt_us: u64,
        transit_delay_us: Option<u64>,
        timestamp_ns: u64,
    ) -> JitterSampleEvaluation {
        let detector = self.get_or_create(route.path_id, &route.interface_name);
        let eval = detector.record_sample(rtt_us, transit_delay_us, timestamp_ns);

        // Apply derived thresholds to the route's congestion models
        apply_dynamic_thresholds(&mut route.congestion, &eval.derived_thresholds);

        // Update path metrics
        route.metrics.jitter_us = eval.rfc3550_jitter_us;
        route.metrics.rtt_variance_us = (eval.derived_thresholds.congestion_risk_score * 10_000.0) as u64;

        eval
    }

    /// Generate an aggregated Prometheus exposition across all tracked subpaths.
    pub fn export_prometheus_metrics(&self) -> String {
        let mut out = String::new();
        for (path_id, iface, detector) in &self.detectors {
            out.push_str(&detector.to_prometheus_metrics(*path_id, iface));
            out.push('\n');
        }
        out
    }
}

/// Apply dynamically derived thresholds to BBR and LEDBAT congestion controllers.
pub fn apply_dynamic_thresholds(
    congestion: &mut IsspCongestionState,
    thresholds: &DynamicCongestionThresholds,
) {
    // 1. Dynamic LEDBAT target adaptation
    congestion.ledbat.target_delay_us = thresholds.dynamic_ledbat_target_us;

    // 2. Dynamic BBR pacing gain adaptation
    congestion.bbr.pacing_gain_q8 = thresholds.dynamic_bbr_pacing_gain_q8;

    // 3. Trigger ProbeRTT if route shift invalidated RTprop
    if thresholds.probe_rtt_required {
        congestion.bbr.rt_prop_us = u64::MAX;
        congestion.bbr.pacing_gain_q8 = (congestion.bbr.pacing_gain_q8 as f64 * 0.90) as u32;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nominal_stable_link_classification() {
        let mut detector = JitterAnomalyDetector::default();
        let base_rtt = 20_000; // 20 ms
        let mut evaluations = Vec::new();

        // Feed 30 samples with minor ±200 µs jitter
        for i in 0..30 {
            let jitter = (i % 5) * 80;
            let sample = base_rtt + jitter;
            let eval = detector.record_sample(sample, None, (i + 1) * 10_000_000);
            evaluations.push(eval);
        }

        let last_eval = evaluations.last().unwrap();
        assert_eq!(last_eval.anomaly_kind, JitterAnomalyKind::Nominal);
        assert_eq!(last_eval.severity, AnomalySeverity::Nominal);
        assert_eq!(last_eval.derived_thresholds.recommended_action, JitterMitigationAction::Maintain);
        assert!(last_eval.derived_thresholds.dynamic_bbr_pacing_gain_q8 >= 256);
        assert!(last_eval.derived_thresholds.congestion_risk_score < 0.2);
    }

    #[test]
    fn test_transient_spike_classification() {
        let mut detector = JitterAnomalyDetector::default();
        let base_rtt = 15_000;

        // Establish stable baseline
        for i in 0..20 {
            detector.record_sample(base_rtt + (i % 3) * 50, None, i * 10_000_000);
        }

        // Single isolated spike of 75 ms (e.g. WiFi frame retry)
        let spike_eval = detector.record_sample(75_000, None, 21 * 10_000_000);
        assert_eq!(spike_eval.anomaly_kind, JitterAnomalyKind::TransientSpike);
        assert!(spike_eval.z_score >= 2.5);
        // Under transient spike, LEDBAT target widens slightly to prevent false CWND collapse
        assert!(spike_eval.derived_thresholds.dynamic_ledbat_target_us >= 25_000);
    }

    #[test]
    fn test_bufferbloat_onset_and_ledbat_target_contraction() {
        let mut detector = JitterAnomalyDetector::default();
        let base_rtt = 10_000;

        // Establish stable baseline
        for i in 0..15 {
            detector.record_sample(base_rtt + (i % 2) * 50, None, i * 10_000_000);
        }

        // Simulate monotonically climbing queuing delay (10ms -> 50ms)
        let mut bloat_eval = None;
        for i in 1..=8 {
            let climbing_rtt = base_rtt + (i * 6_000); // +6ms per sample
            bloat_eval = Some(detector.record_sample(climbing_rtt, None, (15 + i) * 10_000_000));
        }

        let eval = bloat_eval.unwrap();
        assert_eq!(eval.anomaly_kind, JitterAnomalyKind::BufferbloatOnset);
        assert_eq!(eval.derived_thresholds.recommended_action, JitterMitigationAction::ContractLedbatTarget);
        // LEDBAT target should contract below nominal (25ms) to drain the bottleneck buffer
        assert!(eval.derived_thresholds.dynamic_ledbat_target_us < 25_000);
        // BBR pacing gain should throttle back to 0.85x
        assert_eq!(eval.derived_thresholds.dynamic_bbr_pacing_gain_q8, 218);
        assert!(eval.derived_thresholds.congestion_risk_score > 0.7);
    }

    #[test]
    fn test_route_shift_and_bbr_probe_rtt_trigger() {
        let mut detector = JitterAnomalyDetector::default();
        let base_rtt = 15_000; // 15 ms path

        for i in 0..20 {
            detector.record_sample(base_rtt + (i % 3) * 50, None, i * 10_000_000);
        }

        // Sudden step change to 55 ms path (route shift / handover)
        let new_path_rtt = 55_000;
        let mut last_eval = None;
        for i in 1..=10 {
            last_eval = Some(detector.record_sample(new_path_rtt + (i % 2) * 40, None, (20 + i) * 10_000_000));
        }

        let eval = last_eval.unwrap();
        assert!(eval.derived_thresholds.probe_rtt_required);
        assert_eq!(eval.derived_thresholds.recommended_action, JitterMitigationAction::TriggerProbeRtt);
    }

    #[test]
    fn test_microburst_congestion_pacing_scale() {
        let mut detector = JitterAnomalyDetector::default();
        let base_rtt = 20_000;

        for i in 0..10 {
            detector.record_sample(base_rtt, None, i * 10_000_000);
        }

        // Rapid oscillations: 20ms -> 35ms -> 20ms -> 35ms -> 20ms
        let mut last_eval = None;
        for i in 1..=12 {
            let rtt = if i % 2 == 0 { 20_000 } else { 38_000 };
            last_eval = Some(detector.record_sample(rtt, None, (10 + i) * 10_000_000));
        }

        let eval = last_eval.unwrap();
        assert_eq!(eval.derived_thresholds.recommended_action, JitterMitigationAction::ScaleBbrPacing);
        assert_eq!(eval.derived_thresholds.dynamic_bbr_pacing_gain_q8, 218);
    }

    #[test]
    fn test_prometheus_and_json_export() {
        let mut detector = JitterAnomalyDetector::default();
        for i in 1..=10 {
            detector.record_sample(20_000 + i * 200, None, i * 10_000_000);
        }

        let prom = detector.to_prometheus_metrics(1, "eth0-wan");
        assert!(prom.contains("ifa_jitter_mean_rtt_us{path_id=\"1\",iface=\"eth0-wan\"}"));
        assert!(prom.contains("ifa_dynamic_ledbat_target_us{path_id=\"1\",iface=\"eth0-wan\"}"));
        assert!(prom.contains("ifa_dynamic_bbr_pacing_gain{path_id=\"1\",iface=\"eth0-wan\"}"));

        let json = detector.to_json(1, "eth0-wan");
        assert!(json.contains("\"path_id\":1"));
        assert!(json.contains("\"interface_name\":\"eth0-wan\""));
        assert!(json.contains("\"dynamic_ledbat_target_us\":"));
        assert!(json.contains("\"dynamic_bbr_pacing_gain_q8\":"));
    }

    #[test]
    fn test_multipath_bridge_and_congestion_application() {
        let mut bridge = JitterMultipathBridge::new();
        let mut route = IsspMultipathRoute::new(1, 100, "eth0-wan", 1, 100);

        let eval = bridge.process_feedback(&mut route, 25_000, None, 100_000_000);
        assert_eq!(eval.rtt_us, 25_000);
        assert_eq!(route.congestion.ledbat.target_delay_us, eval.derived_thresholds.dynamic_ledbat_target_us);
        assert_eq!(route.congestion.bbr.pacing_gain_q8, eval.derived_thresholds.dynamic_bbr_pacing_gain_q8);
    }
}

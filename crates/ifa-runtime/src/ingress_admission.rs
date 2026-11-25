//! Distributed Ingress Admission Gatekeeper and Flow Policing Engine.
//!
//! Provides proactive ingress traffic shaping, priority-aware token bucket policing,
//! dynamic downstream backpressure propagation, and SLA-directed admission control
//! across heterogeneous network slices (URLLC, MissionCritical, eMBB, BestEffort).
//!
//! Zero-simulation: operates exclusively on concrete token calculations, live backpressure
//! signals emitted by downstream nodes, and active packet/byte accounting.

use std::collections::BTreeMap;
use std::fmt::Write;
use std::string::String;

use crate::multi_node_sla::ClosedLoopControlAction;
use crate::traffic_slicing::FlowSliceClass;

/// Reason an ingress packet or flow was rejected at the gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressRejectionReason {
    /// Token bucket completely exhausted and shaping is disabled.
    TokenBucketExhausted,
    /// Active downstream backpressure signal restricts ingress rate to near-zero.
    StrictBackpressureSaturation,
    /// Slice is administratively suspended or at zero capacity.
    SliceSuspended,
}

impl IngressRejectionReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TokenBucketExhausted => "token_bucket_exhausted",
            Self::StrictBackpressureSaturation => "strict_backpressure_saturation",
            Self::SliceSuspended => "slice_suspended",
        }
    }
}

/// Admission verdict for an incoming packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionDecision {
    /// Packet admitted immediately with zero delay.
    Admitted,
    /// Packet admitted with pacing delay requirement (in nanoseconds).
    PolicedDelayed { delay_ns: u64 },
    /// Packet throttled / dropped to protect downstream bufferbloat and SLA targets.
    PolicedThrottled { dropped_bytes: u64 },
    /// Packet rejected at ingress.
    Rejected { reason: IngressRejectionReason },
}

/// Active downstream backpressure state applied to a traffic slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveBackpressure {
    pub source_node_id: u32,
    pub throttled_slice: FlowSliceClass,
    pub recommended_max_rate_bps: u64,
    pub received_timestamp_ns: u64,
    pub ttl_ns: u64,
}

impl ActiveBackpressure {
    /// Whether this backpressure record has expired.
    pub fn is_expired(&self, now_ns: u64) -> bool {
        now_ns >= self.received_timestamp_ns.saturating_add(self.ttl_ns)
    }
}

/// Per-slice token bucket for rate shaping and policing.
#[derive(Debug, Clone)]
pub struct SliceTokenBucket {
    pub slice_class: FlowSliceClass,
    pub configured_rate_bps: u64,
    pub effective_rate_bps: u64,
    pub burst_bytes: u64,
    pub current_tokens_bytes: f64,
    pub last_replenish_timestamp_ns: u64,
    pub total_bytes_admitted: u64,
    pub total_packets_admitted: u64,
    pub total_bytes_throttled: u64,
    pub total_packets_throttled: u64,
    pub total_packets_rejected: u64,
}

impl SliceTokenBucket {
    /// Create a new token bucket with specified rate and burst depth.
    pub fn new(slice_class: FlowSliceClass, rate_bps: u64, burst_bytes: u64, now_ns: u64) -> Self {
        Self {
            slice_class,
            configured_rate_bps: rate_bps,
            effective_rate_bps: rate_bps,
            burst_bytes,
            current_tokens_bytes: burst_bytes as f64,
            last_replenish_timestamp_ns: now_ns,
            total_bytes_admitted: 0,
            total_packets_admitted: 0,
            total_bytes_throttled: 0,
            total_packets_throttled: 0,
            total_packets_rejected: 0,
        }
    }

    /// Replenish available tokens based on elapsed time and effective rate.
    pub fn replenish(&mut self, now_ns: u64) {
        if now_ns <= self.last_replenish_timestamp_ns {
            return;
        }

        let elapsed_ns = now_ns.saturating_sub(self.last_replenish_timestamp_ns);
        let elapsed_sec = (elapsed_ns as f64) / 1_000_000_000.0;
        let tokens_to_add = (self.effective_rate_bps as f64 / 8.0) * elapsed_sec;

        self.current_tokens_bytes =
            (self.current_tokens_bytes + tokens_to_add).min(self.burst_bytes as f64);
        self.last_replenish_timestamp_ns = now_ns;
    }

    /// Try consuming tokens for an incoming packet of `packet_bytes`.
    pub fn try_consume(&mut self, packet_bytes: usize, now_ns: u64) -> AdmissionDecision {
        self.replenish(now_ns);

        let required = packet_bytes as f64;
        if self.current_tokens_bytes >= required {
            self.current_tokens_bytes -= required;
            self.total_bytes_admitted = self
                .total_bytes_admitted
                .saturating_add(packet_bytes as u64);
            self.total_packets_admitted = self.total_packets_admitted.saturating_add(1);
            AdmissionDecision::Admitted
        } else {
            // Check if slice is configured for priority bypass or hard policing
            match self.slice_class {
                FlowSliceClass::UltraLowLatency | FlowSliceClass::MissionCritical => {
                    // Priority slices allow bounded burst credit up to 25% beyond bucket
                    let overdraft_limit = -(self.burst_bytes as f64 * 0.25);
                    if self.current_tokens_bytes - required >= overdraft_limit {
                        self.current_tokens_bytes -= required;
                        self.total_bytes_admitted = self
                            .total_bytes_admitted
                            .saturating_add(packet_bytes as u64);
                        self.total_packets_admitted = self.total_packets_admitted.saturating_add(1);
                        AdmissionDecision::Admitted
                    } else {
                        self.total_bytes_throttled = self
                            .total_bytes_throttled
                            .saturating_add(packet_bytes as u64);
                        self.total_packets_throttled =
                            self.total_packets_throttled.saturating_add(1);
                        AdmissionDecision::PolicedThrottled {
                            dropped_bytes: packet_bytes as u64,
                        }
                    }
                }
                FlowSliceClass::HighThroughput | FlowSliceClass::BestEffort => {
                    self.total_bytes_throttled = self
                        .total_bytes_throttled
                        .saturating_add(packet_bytes as u64);
                    self.total_packets_throttled = self.total_packets_throttled.saturating_add(1);
                    AdmissionDecision::PolicedThrottled {
                        dropped_bytes: packet_bytes as u64,
                    }
                }
            }
        }
    }
}

/// Configuration settings for the Ingress Admission Gatekeeper.
#[derive(Debug, Clone)]
pub struct IngressAdmissionConfig {
    pub default_rates: BTreeMap<FlowSliceClass, u64>,
    pub burst_depth_ms: u32,
    pub backpressure_ttl_ns: u64,
    pub priority_protection_enabled: bool,
    pub min_clamped_rate_bps: u64,
}

impl Default for IngressAdmissionConfig {
    fn default() -> Self {
        let mut default_rates = BTreeMap::new();
        default_rates.insert(FlowSliceClass::UltraLowLatency, 50_000_000); // 50 Mbps
        default_rates.insert(FlowSliceClass::MissionCritical, 100_000_000); // 100 Mbps
        default_rates.insert(FlowSliceClass::HighThroughput, 500_000_000); // 500 Mbps
        default_rates.insert(FlowSliceClass::BestEffort, 100_000_000); // 100 Mbps

        Self {
            default_rates,
            burst_depth_ms: 50,                 // 50 ms burst allowance
            backpressure_ttl_ns: 1_000_000_000, // 1 second TTL
            priority_protection_enabled: true,
            min_clamped_rate_bps: 1_000_000, // 1 Mbps minimum clamp
        }
    }
}

/// Aggregated metrics for Ingress Admission Gatekeeper.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct IngressAdmissionMetrics {
    pub total_admitted_packets: u64,
    pub total_admitted_bytes: u64,
    pub total_throttled_packets: u64,
    pub total_throttled_bytes: u64,
    pub total_rejected_packets: u64,
    pub total_backpressures_received: u64,
    pub total_backpressures_expired: u64,
    pub total_rate_restorations: u64,
}

/// Distributed Ingress Admission Gatekeeper.
#[derive(Debug, Clone)]
pub struct IngressAdmissionGatekeeper {
    local_node_id: u32,
    config: IngressAdmissionConfig,
    token_buckets: BTreeMap<FlowSliceClass, SliceTokenBucket>,
    active_backpressures: BTreeMap<(u32, FlowSliceClass), ActiveBackpressure>,
    metrics: IngressAdmissionMetrics,
}

impl IngressAdmissionGatekeeper {
    /// Create a new gatekeeper with specified node ID and configuration.
    pub fn new(local_node_id: u32, config: IngressAdmissionConfig, now_ns: u64) -> Self {
        let mut token_buckets = BTreeMap::new();
        for (&slice, &rate_bps) in &config.default_rates {
            let burst_bytes = (rate_bps / 8) * (config.burst_depth_ms as u64) / 1000;
            token_buckets.insert(
                slice,
                SliceTokenBucket::new(slice, rate_bps, burst_bytes.max(1500), now_ns),
            );
        }

        Self {
            local_node_id,
            config,
            token_buckets,
            active_backpressures: BTreeMap::new(),
            metrics: IngressAdmissionMetrics::default(),
        }
    }

    /// Create standard gatekeeper instance for a node with current epoch timestamp.
    pub fn default_for_node(local_node_id: u32) -> Self {
        Self::new(local_node_id, IngressAdmissionConfig::default(), 0)
    }

    /// Read local node ID.
    pub fn local_node_id(&self) -> u32 {
        self.local_node_id
    }

    /// Access reference to metrics.
    pub fn metrics(&self) -> &IngressAdmissionMetrics {
        &self.metrics
    }

    /// Ingest and apply an upstream backpressure action received from a downstream node.
    pub fn apply_backpressure(&mut self, action: &ClosedLoopControlAction, now_ns: u64) -> bool {
        if let ClosedLoopControlAction::UpstreamBackpressureSignal {
            source_node_id,
            ingress_node_id,
            throttled_slice,
            recommended_max_rate_bps,
        } = action
        {
            // Verify if signal is targeted at this node or universal coordinator
            if *ingress_node_id != self.local_node_id && *ingress_node_id != 1 {
                return false;
            }

            self.metrics.total_backpressures_received =
                self.metrics.total_backpressures_received.saturating_add(1);

            let record = ActiveBackpressure {
                source_node_id: *source_node_id,
                throttled_slice: *throttled_slice,
                recommended_max_rate_bps: (*recommended_max_rate_bps)
                    .max(self.config.min_clamped_rate_bps),
                received_timestamp_ns: now_ns,
                ttl_ns: self.config.backpressure_ttl_ns,
            };

            self.active_backpressures
                .insert((*source_node_id, *throttled_slice), record);
            self.recalculate_effective_rates(now_ns);
            true
        } else {
            false
        }
    }

    /// Prune expired backpressure signals and smoothly restore rates.
    pub fn prune_expired_backpressures(&mut self, now_ns: u64) -> usize {
        let initial_count = self.active_backpressures.len();
        self.active_backpressures
            .retain(|_, bp| !bp.is_expired(now_ns));
        let removed = initial_count.saturating_sub(self.active_backpressures.len());

        if removed > 0 {
            self.metrics.total_backpressures_expired = self
                .metrics
                .total_backpressures_expired
                .saturating_add(removed as u64);
            self.metrics.total_rate_restorations =
                self.metrics.total_rate_restorations.saturating_add(1);
            self.recalculate_effective_rates(now_ns);
        }

        removed
    }

    /// Recalculate effective token bucket rate caps across all slices.
    fn recalculate_effective_rates(&mut self, now_ns: u64) {
        for (&slice, bucket) in &mut self.token_buckets {
            bucket.replenish(now_ns);

            // Find lowest recommended rate among active backpressures for this slice
            let mut min_recommended_rate = None;
            for bp in self.active_backpressures.values() {
                if bp.throttled_slice == slice && !bp.is_expired(now_ns) {
                    min_recommended_rate = match min_recommended_rate {
                        None => Some(bp.recommended_max_rate_bps),
                        Some(current_min) => Some(current_min.min(bp.recommended_max_rate_bps)),
                    };
                }
            }

            if let Some(rate_cap) = min_recommended_rate {
                // Priority slices are protected: cannot be throttled by bulk backpressure
                if self.config.priority_protection_enabled
                    && matches!(
                        slice,
                        FlowSliceClass::UltraLowLatency | FlowSliceClass::MissionCritical
                    )
                {
                    bucket.effective_rate_bps = bucket.configured_rate_bps;
                } else {
                    let clamped = rate_cap.min(bucket.configured_rate_bps);
                    bucket.effective_rate_bps = clamped;
                    let clamped_burst =
                        ((clamped / 8) * (self.config.burst_depth_ms as u64) / 1000).max(1500);
                    bucket.burst_bytes = clamped_burst;
                    bucket.current_tokens_bytes =
                        bucket.current_tokens_bytes.min(clamped_burst as f64);
                }
            } else {
                bucket.effective_rate_bps = bucket.configured_rate_bps;
                let nominal_burst =
                    ((bucket.configured_rate_bps / 8) * (self.config.burst_depth_ms as u64) / 1000)
                        .max(1500);
                bucket.burst_bytes = nominal_burst;
            }
        }
    }

    /// Process an incoming packet for admission at ingress.
    pub fn admit_packet(
        &mut self,
        slice: FlowSliceClass,
        packet_bytes: usize,
        now_ns: u64,
    ) -> AdmissionDecision {
        // Auto-prune on packet ingestion if expired entries exist
        self.prune_expired_backpressures(now_ns);

        let decision = if let Some(bucket) = self.token_buckets.get_mut(&slice) {
            bucket.try_consume(packet_bytes, now_ns)
        } else {
            AdmissionDecision::Rejected {
                reason: IngressRejectionReason::SliceSuspended,
            }
        };

        match decision {
            AdmissionDecision::Admitted => {
                self.metrics.total_admitted_packets =
                    self.metrics.total_admitted_packets.saturating_add(1);
                self.metrics.total_admitted_bytes = self
                    .metrics
                    .total_admitted_bytes
                    .saturating_add(packet_bytes as u64);
            }
            AdmissionDecision::PolicedDelayed { .. } => {
                self.metrics.total_admitted_packets =
                    self.metrics.total_admitted_packets.saturating_add(1);
                self.metrics.total_admitted_bytes = self
                    .metrics
                    .total_admitted_bytes
                    .saturating_add(packet_bytes as u64);
            }
            AdmissionDecision::PolicedThrottled { dropped_bytes } => {
                self.metrics.total_throttled_packets =
                    self.metrics.total_throttled_packets.saturating_add(1);
                self.metrics.total_throttled_bytes = self
                    .metrics
                    .total_throttled_bytes
                    .saturating_add(dropped_bytes);
            }
            AdmissionDecision::Rejected { .. } => {
                self.metrics.total_rejected_packets =
                    self.metrics.total_rejected_packets.saturating_add(1);
            }
        }

        decision
    }

    /// Read effective rate limit for a slice.
    pub fn effective_rate_bps(&self, slice: FlowSliceClass) -> u64 {
        self.token_buckets
            .get(&slice)
            .map(|b| b.effective_rate_bps)
            .unwrap_or(0)
    }

    /// Read configured rate limit for a slice.
    pub fn configured_rate_bps(&self, slice: FlowSliceClass) -> u64 {
        self.token_buckets
            .get(&slice)
            .map(|b| b.configured_rate_bps)
            .unwrap_or(0)
    }

    /// Read count of active backpressures for a slice.
    pub fn active_backpressures_count(&self, slice: FlowSliceClass) -> usize {
        self.active_backpressures
            .values()
            .filter(|bp| bp.throttled_slice == slice)
            .count()
    }

    /// Read token bucket current fill ratio (0.0 to 1.0).
    pub fn token_fill_ratio(&self, slice: FlowSliceClass) -> f64 {
        self.token_buckets
            .get(&slice)
            .map(|b| {
                if b.burst_bytes > 0 {
                    (b.current_tokens_bytes / b.burst_bytes as f64).clamp(0.0, 1.0)
                } else {
                    0.0
                }
            })
            .unwrap_or(0.0)
    }

    /// Export Prometheus / OpenTelemetry telemetry format.
    pub fn export_prometheus_metrics(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "# HELP ifa_ingress_admitted_packets_total Total packets admitted through ingress gatekeeper"
        );
        let _ = writeln!(out, "# TYPE ifa_ingress_admitted_packets_total counter");
        let _ = writeln!(
            out,
            "ifa_ingress_admitted_packets_total{{node=\"{}\"}} {}",
            self.local_node_id, self.metrics.total_admitted_packets
        );

        let _ = writeln!(
            out,
            "# HELP ifa_ingress_admitted_bytes_total Total payload bytes admitted through ingress gatekeeper"
        );
        let _ = writeln!(out, "# TYPE ifa_ingress_admitted_bytes_total counter");
        let _ = writeln!(
            out,
            "ifa_ingress_admitted_bytes_total{{node=\"{}\"}} {}",
            self.local_node_id, self.metrics.total_admitted_bytes
        );

        let _ = writeln!(
            out,
            "# HELP ifa_ingress_throttled_packets_total Total packets throttled by ingress rate policer"
        );
        let _ = writeln!(out, "# TYPE ifa_ingress_throttled_packets_total counter");
        let _ = writeln!(
            out,
            "ifa_ingress_throttled_packets_total{{node=\"{}\"}} {}",
            self.local_node_id, self.metrics.total_throttled_packets
        );

        let _ = writeln!(
            out,
            "# HELP ifa_ingress_throttled_bytes_total Total bytes dropped/throttled by ingress policer"
        );
        let _ = writeln!(out, "# TYPE ifa_ingress_throttled_bytes_total counter");
        let _ = writeln!(
            out,
            "ifa_ingress_throttled_bytes_total{{node=\"{}\"}} {}",
            self.local_node_id, self.metrics.total_throttled_bytes
        );

        let _ = writeln!(
            out,
            "# HELP ifa_ingress_rejected_packets_total Total packets rejected at ingress gatekeeper"
        );
        let _ = writeln!(out, "# TYPE ifa_ingress_rejected_packets_total counter");
        let _ = writeln!(
            out,
            "ifa_ingress_rejected_packets_total{{node=\"{}\"}} {}",
            self.local_node_id, self.metrics.total_rejected_packets
        );

        let _ = writeln!(
            out,
            "# HELP ifa_ingress_active_backpressures Current count of active downstream backpressures"
        );
        let _ = writeln!(out, "# TYPE ifa_ingress_active_backpressures gauge");
        for &slice in &[
            FlowSliceClass::UltraLowLatency,
            FlowSliceClass::MissionCritical,
            FlowSliceClass::HighThroughput,
            FlowSliceClass::BestEffort,
        ] {
            let _ = writeln!(
                out,
                "ifa_ingress_active_backpressures{{node=\"{}\",slice=\"{}\"}} {}",
                self.local_node_id,
                slice.as_str(),
                self.active_backpressures_count(slice)
            );
        }

        let _ = writeln!(
            out,
            "# HELP ifa_ingress_effective_rate_bps Effective clamped bandwidth rate in bits per second"
        );
        let _ = writeln!(out, "# TYPE ifa_ingress_effective_rate_bps gauge");
        for &slice in &[
            FlowSliceClass::UltraLowLatency,
            FlowSliceClass::MissionCritical,
            FlowSliceClass::HighThroughput,
            FlowSliceClass::BestEffort,
        ] {
            let _ = writeln!(
                out,
                "ifa_ingress_effective_rate_bps{{node=\"{}\",slice=\"{}\"}} {}",
                self.local_node_id,
                slice.as_str(),
                self.effective_rate_bps(slice)
            );
        }

        out
    }
}

/// Report summarizing ingress admission performance and backpressure compliance.
#[derive(Debug, Clone, PartialEq)]
pub struct IngressAdmissionBenchmarkReport {
    pub nominal_admitted_packets: u64,
    pub backpressure_throttled_packets: u64,
    pub urllc_admission_ratio: f64,
    pub embb_admission_ratio: f64,
    pub backpressure_signals_applied: u64,
    pub rate_restorations_completed: u64,
    pub final_effective_embb_rate_bps: u64,
}

/// Automated benchmark for Ingress Admission Gatekeeper under downstream backpressure.
pub fn run_ingress_admission_benchmark() -> IngressAdmissionBenchmarkReport {
    let mut gatekeeper = IngressAdmissionGatekeeper::default_for_node(1);
    let mut now_ns = 1_000_000_000; // Start at 1s

    // Phase 1: Nominal operation.
    // Ingest 50 packets URLLC (64 bytes) and 50 packets eMBB (1500 bytes).
    let mut nominal_admitted = 0;
    for _ in 0..50 {
        if gatekeeper.admit_packet(FlowSliceClass::UltraLowLatency, 64, now_ns)
            == AdmissionDecision::Admitted
        {
            nominal_admitted += 1;
        }
        if gatekeeper.admit_packet(FlowSliceClass::HighThroughput, 1500, now_ns)
            == AdmissionDecision::Admitted
        {
            nominal_admitted += 1;
        }
        now_ns += 1_000_000; // 1 ms advance
    }

    // Phase 2: Downstream node 2 experiences bufferbloat and sends backpressure signal
    // clamping HighThroughput to 2 Mbps (250,000 bytes/sec).
    let backpressure_signal = ClosedLoopControlAction::UpstreamBackpressureSignal {
        source_node_id: 2,
        ingress_node_id: 1,
        throttled_slice: FlowSliceClass::HighThroughput,
        recommended_max_rate_bps: 2_000_000,
    };
    gatekeeper.apply_backpressure(&backpressure_signal, now_ns);

    // Try blasting 500 large eMBB packets (1500 bytes each = 750 KB) and 100 URLLC packets (64 bytes each).
    let mut urllc_admitted = 0;
    let mut embb_admitted = 0;
    let mut embb_throttled = 0;

    for _ in 0..100 {
        if gatekeeper.admit_packet(FlowSliceClass::UltraLowLatency, 64, now_ns)
            == AdmissionDecision::Admitted
        {
            urllc_admitted += 1;
        }
        now_ns += 100_000; // 100 µs
    }

    for _ in 0..500 {
        match gatekeeper.admit_packet(FlowSliceClass::HighThroughput, 1500, now_ns) {
            AdmissionDecision::Admitted => embb_admitted += 1,
            AdmissionDecision::PolicedThrottled { .. } => embb_throttled += 1,
            _ => {}
        }
        now_ns += 100_000; // 100 µs
    }

    // Phase 3: Healing. No backpressure arrives for 1.5s (exceeds TTL of 1s).
    now_ns += 1_500_000_000;
    let expired = gatekeeper.prune_expired_backpressures(now_ns);
    assert_eq!(expired, 1, "Expected exactly 1 backpressure to expire");

    let restored_rate = gatekeeper.effective_rate_bps(FlowSliceClass::HighThroughput);
    assert_eq!(
        restored_rate,
        gatekeeper.configured_rate_bps(FlowSliceClass::HighThroughput),
        "Rate must be restored to configured rate after backpressure decay"
    );

    let urllc_ratio = (urllc_admitted as f64) / 100.0;
    let embb_ratio = (embb_admitted as f64) / 500.0;

    IngressAdmissionBenchmarkReport {
        nominal_admitted_packets: nominal_admitted,
        backpressure_throttled_packets: embb_throttled,
        urllc_admission_ratio: urllc_ratio,
        embb_admission_ratio: embb_ratio,
        backpressure_signals_applied: gatekeeper.metrics().total_backpressures_received,
        rate_restorations_completed: gatekeeper.metrics().total_rate_restorations,
        final_effective_embb_rate_bps: restored_rate,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_bucket_nominal_replenish() {
        let mut bucket =
            SliceTokenBucket::new(FlowSliceClass::UltraLowLatency, 10_000_000, 10_000, 0);
        // Fully burst consumed
        let dec = bucket.try_consume(10_000, 0);
        assert_eq!(dec, AdmissionDecision::Admitted);

        // Immediate next packet rejected/throttled
        let dec2 = bucket.try_consume(5000, 0);
        assert!(matches!(dec2, AdmissionDecision::PolicedThrottled { .. }));

        // Replenish 1 second later (10 Mbps = 1.25 MB/s)
        let dec3 = bucket.try_consume(5000, 1_000_000_000);
        assert_eq!(dec3, AdmissionDecision::Admitted);
    }

    #[test]
    fn test_backpressure_application_and_decay() {
        let mut gatekeeper = IngressAdmissionGatekeeper::default_for_node(1);
        let now_ns = 1_000_000;

        assert_eq!(
            gatekeeper.effective_rate_bps(FlowSliceClass::HighThroughput),
            500_000_000
        );

        let signal = ClosedLoopControlAction::UpstreamBackpressureSignal {
            source_node_id: 3,
            ingress_node_id: 1,
            throttled_slice: FlowSliceClass::HighThroughput,
            recommended_max_rate_bps: 10_000_000,
        };

        let applied = gatekeeper.apply_backpressure(&signal, now_ns);
        assert!(applied);
        assert_eq!(
            gatekeeper.effective_rate_bps(FlowSliceClass::HighThroughput),
            10_000_000
        );
        assert_eq!(
            gatekeeper.active_backpressures_count(FlowSliceClass::HighThroughput),
            1
        );

        // Priority slices untouched
        assert_eq!(
            gatekeeper.effective_rate_bps(FlowSliceClass::UltraLowLatency),
            50_000_000
        );

        // Advance beyond TTL (1s)
        let pruned = gatekeeper.prune_expired_backpressures(now_ns + 1_500_000_000);
        assert_eq!(pruned, 1);
        assert_eq!(
            gatekeeper.effective_rate_bps(FlowSliceClass::HighThroughput),
            500_000_000
        );
        assert_eq!(
            gatekeeper.active_backpressures_count(FlowSliceClass::HighThroughput),
            0
        );
    }

    #[test]
    fn test_priority_protection_guarantee() {
        let mut gatekeeper = IngressAdmissionGatekeeper::default_for_node(1);
        let now_ns = 100_000;

        // Try applying backpressure against URLLC
        let signal = ClosedLoopControlAction::UpstreamBackpressureSignal {
            source_node_id: 4,
            ingress_node_id: 1,
            throttled_slice: FlowSliceClass::UltraLowLatency,
            recommended_max_rate_bps: 1_000_000,
        };

        gatekeeper.apply_backpressure(&signal, now_ns);
        // With priority protection enabled, URLLC effective rate remains at configured 50 Mbps
        assert_eq!(
            gatekeeper.effective_rate_bps(FlowSliceClass::UltraLowLatency),
            50_000_000
        );
    }

    #[test]
    fn test_prometheus_exposition_format() {
        let gatekeeper = IngressAdmissionGatekeeper::default_for_node(1);
        let metrics_text = gatekeeper.export_prometheus_metrics();

        assert!(metrics_text.contains("ifa_ingress_admitted_packets_total{node=\"1\"}"));
        assert!(metrics_text.contains("ifa_ingress_throttled_packets_total{node=\"1\"}"));
        assert!(metrics_text.contains(
            "ifa_ingress_effective_rate_bps{node=\"1\",slice=\"ultra_low_latency\"} 50000000"
        ));
        assert!(metrics_text.contains(
            "ifa_ingress_effective_rate_bps{node=\"1\",slice=\"high_throughput\"} 50000000"
        ));
    }

    #[test]
    fn test_run_ingress_admission_benchmark_scenario() {
        let report = run_ingress_admission_benchmark();
        assert_eq!(report.urllc_admission_ratio, 1.0);
        assert!(report.embb_admission_ratio < 1.0);
        assert!(report.backpressure_throttled_packets > 0);
        assert_eq!(report.backpressure_signals_applied, 1);
        assert_eq!(report.rate_restorations_completed, 1);
        assert_eq!(report.final_effective_embb_rate_bps, 500_000_000);
    }

    #[test]
    fn test_router_ingress_gatekeeper_integration() {
        use crate::session_sync::{IsspDynamicMultipathRouter, IsspRoutingPolicy};

        let mut router =
            IsspDynamicMultipathRouter::new(1, IsspRoutingPolicy::BandwidthAggregation);
        assert_eq!(
            router
                .ingress_gatekeeper()
                .effective_rate_bps(FlowSliceClass::HighThroughput),
            500_000_000
        );

        let signal = ClosedLoopControlAction::UpstreamBackpressureSignal {
            source_node_id: 2,
            ingress_node_id: 1,
            throttled_slice: FlowSliceClass::HighThroughput,
            recommended_max_rate_bps: 5_000_000,
        };
        let ok = router.apply_closed_loop_backpressure(&signal, 100);
        assert!(ok);
        assert_eq!(
            router
                .ingress_gatekeeper()
                .effective_rate_bps(FlowSliceClass::HighThroughput),
            5_000_000
        );

        let dec = router.admit_ingress_packet(FlowSliceClass::UltraLowLatency, 128, 100);
        assert_eq!(dec, AdmissionDecision::Admitted);

        let snap = router.balancing_snapshot(100);
        assert_eq!(snap.total_ingress_admitted_packets, 1);
        assert_eq!(snap.total_ingress_backpressures_applied, 1);
    }
}

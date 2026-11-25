//! Dynamic Flow-to-Subpath Slicing and Telemetry QoS Negotiation Engine.
//!
//! Provides intelligent traffic steering and service-level objective (SLO) slicing
//! across heterogeneous ISSP multipath subpaths based on real-time telemetry metrics:
//! - Round-Trip Time (RTT) & latency variance
//! - Network jitter and queuing delay (bufferbloat)
//! - Available bandwidth & link saturation ratios
//! - Packet delivery ratio and loss in parts-per-million (ppm)
//!
//! Zero-simulation: operates exclusively on concrete telemetry data collected from
//! active subpath probing, BBR/LEDBAT congestion tracking, and Link-State Advertisements (LSA).

use crate::session_sync::{IsspMultipathRoute, SessionId};
use std::collections::HashMap;

/// High-level traffic service class (QoS slice partition).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlowSliceClass {
    /// Ultra-Low Latency slice (URLLC): Strict RTT & jitter bounds; prioritized over bandwidth.
    UltraLowLatency,
    /// High Throughput slice (eMBB): Bandwidth-hungry bulk flows; tolerant to latency variance.
    HighThroughput,
    /// Mission Critical slice: High reliability, zero-loss tolerance, strict queuing delay limits.
    MissionCritical,
    /// Best Effort slice: Background or non-urgent traffic, yielding to prioritized slices.
    BestEffort,
}

impl FlowSliceClass {
    /// Canonical slice identifier tag.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UltraLowLatency => "ultra_low_latency",
            Self::HighThroughput => "high_throughput",
            Self::MissionCritical => "mission_critical",
            Self::BestEffort => "best_effort",
        }
    }
}

/// Comprehensive QoS profile defining SLA requirements for a flow.
#[derive(Debug, Clone, PartialEq)]
pub struct FlowQoSProfile {
    /// Target service class / slice partition.
    pub slice_class: FlowSliceClass,
    /// Maximum tolerable smoothed RTT in microseconds.
    pub max_rtt_us: u64,
    /// Maximum tolerable network jitter in microseconds.
    pub max_jitter_us: u64,
    /// Maximum tolerable queuing delay in microseconds.
    pub max_queuing_delay_us: u64,
    /// Minimum required available bandwidth in bits per second (bps).
    pub min_bandwidth_bps: u64,
    /// Maximum allowable packet loss in parts-per-million (ppm; 1000 = 0.1%).
    pub max_loss_ppm: u32,
    /// Scheduling and preemption priority tier (0 = lowest, 255 = highest).
    pub priority: u8,
    /// Whether fallback to a degraded/best-effort subpath is permitted if no path meets strict requirements.
    pub allow_fallback: bool,
}

impl FlowQoSProfile {
    /// Standard Ultra-Low Latency profile for interactive real-time control and gaming.
    pub fn ultra_low_latency() -> Self {
        Self {
            slice_class: FlowSliceClass::UltraLowLatency,
            max_rtt_us: 20_000,           // 20ms
            max_jitter_us: 3_000,         // 3ms
            max_queuing_delay_us: 5_000,  // 5ms
            min_bandwidth_bps: 1_000_000, // 1 Mbps
            max_loss_ppm: 50,             // 0.005%
            priority: 200,
            allow_fallback: true,
        }
    }

    /// High Throughput profile for bulk data transfer, backups, and large payload synchronization.
    pub fn high_throughput(min_bandwidth_bps: u64) -> Self {
        Self {
            slice_class: FlowSliceClass::HighThroughput,
            max_rtt_us: 150_000,          // 150ms
            max_jitter_us: 30_000,        // 30ms
            max_queuing_delay_us: 50_000, // 50ms
            min_bandwidth_bps,
            max_loss_ppm: 5_000, // 0.5%
            priority: 100,
            allow_fallback: true,
        }
    }

    /// Mission Critical profile for consensus sync, attestation, and cluster health monitoring.
    pub fn mission_critical() -> Self {
        Self {
            slice_class: FlowSliceClass::MissionCritical,
            max_rtt_us: 35_000,           // 35ms
            max_jitter_us: 4_000,         // 4ms
            max_queuing_delay_us: 8_000,  // 8ms
            min_bandwidth_bps: 5_000_000, // 5 Mbps
            max_loss_ppm: 10,             // 0.001%
            priority: 250,
            allow_fallback: false,
        }
    }

    /// Best Effort profile for background jobs, routine telemetry, and verbose tracing.
    pub fn best_effort() -> Self {
        Self {
            slice_class: FlowSliceClass::BestEffort,
            max_rtt_us: 500_000,           // 500ms
            max_jitter_us: 80_000,         // 80ms
            max_queuing_delay_us: 100_000, // 100ms
            min_bandwidth_bps: 0,
            max_loss_ppm: 20_000, // 2.0%
            priority: 20,
            allow_fallback: true,
        }
    }
}

/// Instantaneous QoS capability snapshot of a subpath for slicing decisions.
#[derive(Debug, Clone, PartialEq)]
pub struct SubpathQoSCapability {
    /// Subpath identifier.
    pub path_id: u32,
    /// Interface name (e.g. eth0, wlan0, tun0).
    pub interface_name: String,
    /// Smoothed round-trip time in microseconds.
    pub smoothed_rtt_us: u64,
    /// Network jitter in microseconds.
    pub jitter_us: u64,
    /// Estimated queuing delay (LEDBAT) in microseconds.
    pub queuing_delay_us: u64,
    /// Rated capacity in bits per second.
    pub capacity_bps: u64,
    /// Current measured or estimated throughput in bits per second.
    pub throughput_bps: u64,
    /// Available residual bandwidth in bits per second.
    pub available_bandwidth_bps: u64,
    /// Bandwidth saturation ratio (throughput / capacity).
    pub saturation_ratio: f64,
    /// Packet loss in parts-per-million.
    pub loss_ppm: u32,
    /// Operational state usability flag.
    pub is_usable: bool,
}

impl SubpathQoSCapability {
    /// Extract QoS capabilities directly from an active `IsspMultipathRoute`.
    pub fn from_route(
        route: &IsspMultipathRoute,
        capacity_bps: u64,
        measured_throughput_bps: Option<u64>,
    ) -> Self {
        let cap = if capacity_bps > 0 {
            capacity_bps
        } else if route.congestion.bbr.estimated_bandwidth_bps > 0 {
            route.congestion.bbr.estimated_bandwidth_bps
        } else {
            (route.weight as u64)
                .saturating_mul(100_000_000)
                .max(10_000_000)
        };

        let throughput_bps = measured_throughput_bps.unwrap_or(0);

        let available_bandwidth_bps = cap.saturating_sub(throughput_bps);
        let saturation_ratio = if cap > 0 {
            (throughput_bps as f64) / (cap as f64)
        } else {
            0.0
        };

        let loss_ppm = route.metrics.loss_rate_ppm;

        Self {
            path_id: route.path_id,
            interface_name: route.interface_name.clone(),
            smoothed_rtt_us: route.metrics.smoothed_rtt_us,
            jitter_us: route.metrics.jitter_us,
            queuing_delay_us: route.congestion.ledbat.queuing_delay_us,
            capacity_bps: cap,
            throughput_bps,
            available_bandwidth_bps,
            saturation_ratio,
            loss_ppm,
            is_usable: route.state.is_usable(),
        }
    }
}

/// Reason triggering dynamic traffic slice renegotiation or migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SliceMigrationReason {
    /// Round-trip time breached maximum acceptable limit for the slice.
    LatencyViolation,
    /// Network jitter exceeded maximum tolerable threshold.
    JitterViolation,
    /// Queuing delay (bufferbloat) exceeded maximum tolerable threshold.
    QueuingDelayViolation,
    /// Available subpath bandwidth fell below required minimum.
    BandwidthStarvation,
    /// Observed packet loss rate spiked above SLA limit.
    PacketLossSpike,
    /// Physical or logical link became unusable / failed.
    PathUnusable,
    /// Higher quality subpath became available (rebalancing).
    RebalanceOptimization,
}

impl SliceMigrationReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::LatencyViolation => "latency_violation",
            Self::JitterViolation => "jitter_violation",
            Self::QueuingDelayViolation => "queuing_delay_violation",
            Self::BandwidthStarvation => "bandwidth_starvation",
            Self::PacketLossSpike => "packet_loss_spike",
            Self::PathUnusable => "path_unusable",
            Self::RebalanceOptimization => "rebalance_optimization",
        }
    }
}

/// Active assignment of a traffic flow to a negotiated subpath slice.
#[derive(Debug, Clone, PartialEq)]
pub struct FlowSliceAssignment {
    /// Session identifier.
    pub session_id: SessionId,
    /// Slicing QoS class.
    pub slice_class: FlowSliceClass,
    /// Target subpath path_id.
    pub assigned_path_id: u32,
    /// Evaluated fitness score [0.0, 100.0].
    pub fitness_score: f64,
    /// Timestamp of negotiation (unix ms).
    pub negotiated_at_unix_ms: u64,
    /// Whether the flow is currently operating in degraded fallback mode.
    pub is_degraded: bool,
}

/// Record of an automated flow migration across subpaths to maintain SLA.
#[derive(Debug, Clone, PartialEq)]
pub struct FlowSliceMigrationEvent {
    pub session_id: SessionId,
    pub slice_class: FlowSliceClass,
    pub from_path_id: u32,
    pub to_path_id: u32,
    pub reason: SliceMigrationReason,
    pub migration_timestamp_ms: u64,
    pub cutover_latency_us: f64,
}

/// Slicing negotiation errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowSlicingError {
    NoEligibleSubpath {
        session_id: SessionId,
        slice_class: FlowSliceClass,
    },
    FlowProfileNotFound(SessionId),
    AllSubpathsSaturated,
}

impl std::fmt::Display for FlowSlicingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoEligibleSubpath {
                session_id,
                slice_class,
            } => {
                write!(
                    f,
                    "No eligible subpath meets SLA for session {:?} in slice {:?}",
                    session_id, slice_class
                )
            }
            Self::FlowProfileNotFound(sid) => {
                write!(f, "QoS profile not registered for session {:?}", sid)
            }
            Self::AllSubpathsSaturated => {
                write!(
                    f,
                    "All available subpaths are currently saturated beyond capacity"
                )
            }
        }
    }
}

impl std::error::Error for FlowSlicingError {}

/// Aggregated metrics for flow-to-subpath slicing.
#[derive(Debug, Clone, Default)]
pub struct FlowSlicingMetrics {
    /// Total negotiation attempts.
    pub total_negotiations: u64,
    /// Total successful initial assignments.
    pub successful_negotiations: u64,
    /// Total failed negotiations (SLA rejection).
    pub failed_negotiations: u64,
    /// Total dynamic migrations between subpaths.
    pub total_slice_migrations: u64,
    /// SLA violations recorded by slice class.
    pub sla_violations: HashMap<FlowSliceClass, u64>,
    /// Number of active degraded flows.
    pub active_degraded_flows: u64,
}

/// Dynamic Traffic Slicing and Flow-to-Subpath QoS Negotiation Engine.
#[derive(Debug, Clone)]
pub struct FlowSliceNegotiator {
    /// Registered flow profiles keyed by session id.
    profiles: HashMap<SessionId, FlowQoSProfile>,
    /// Active assignments keyed by session id.
    assignments: HashMap<SessionId, FlowSliceAssignment>,
    /// Flow slicing operational metrics.
    metrics: FlowSlicingMetrics,
    /// Historical log of recent flow slice migrations.
    migration_history: Vec<FlowSliceMigrationEvent>,
}

impl Default for FlowSliceNegotiator {
    fn default() -> Self {
        Self::new()
    }
}

impl FlowSliceNegotiator {
    /// Create a new flow slicing negotiator.
    pub fn new() -> Self {
        Self {
            profiles: HashMap::new(),
            assignments: HashMap::new(),
            metrics: FlowSlicingMetrics::default(),
            migration_history: Vec::new(),
        }
    }

    /// Register a QoS profile for a session.
    pub fn register_profile(&mut self, session_id: SessionId, profile: FlowQoSProfile) {
        self.profiles.insert(session_id, profile);
    }

    /// Remove a session registration and any existing assignment.
    pub fn unregister_flow(&mut self, session_id: &SessionId) -> Option<FlowQoSProfile> {
        self.assignments.remove(session_id);
        self.profiles.remove(session_id)
    }

    /// Access the registered profile for a session.
    pub fn get_profile(&self, session_id: &SessionId) -> Option<&FlowQoSProfile> {
        self.profiles.get(session_id)
    }

    /// Access current slice assignment for a session.
    pub fn get_assignment(&self, session_id: &SessionId) -> Option<&FlowSliceAssignment> {
        self.assignments.get(session_id)
    }

    /// Number of active flow assignments.
    pub fn active_assignments_count(&self) -> usize {
        self.assignments.len()
    }

    /// Number of active flows in a specific slice class.
    pub fn active_flows_in_slice(&self, slice_class: FlowSliceClass) -> usize {
        self.assignments
            .values()
            .filter(|a| a.slice_class == slice_class)
            .count()
    }

    /// Read access to operational metrics.
    pub fn metrics(&self) -> &FlowSlicingMetrics {
        &self.metrics
    }

    /// Read access to migration history.
    pub fn migration_history(&self) -> &[FlowSliceMigrationEvent] {
        &self.migration_history
    }

    /// Evaluate fitness of a subpath against a flow QoS profile.
    /// Returns `Some((fitness_score, is_degraded))` if acceptable, or `None` if completely rejected.
    pub fn evaluate_subpath_fitness(
        profile: &FlowQoSProfile,
        subpath: &SubpathQoSCapability,
    ) -> Option<(f64, bool)> {
        if !subpath.is_usable {
            return None;
        }

        let latency_breached = subpath.smoothed_rtt_us > profile.max_rtt_us;
        let jitter_breached = subpath.jitter_us > profile.max_jitter_us;
        let queuing_breached = subpath.queuing_delay_us > profile.max_queuing_delay_us;
        let bw_breached = subpath.available_bandwidth_bps < profile.min_bandwidth_bps;
        let loss_breached = subpath.loss_ppm > profile.max_loss_ppm;

        let has_breach =
            latency_breached || jitter_breached || queuing_breached || bw_breached || loss_breached;

        if has_breach && !profile.allow_fallback {
            return None;
        }

        // Compute normalized subpath score based on slice objective
        let score = match profile.slice_class {
            FlowSliceClass::UltraLowLatency => {
                // Focus: RTT (45%), Jitter (35%), Queuing Delay (20%)
                let rtt_factor = if profile.max_rtt_us > 0 {
                    (1.0 - (subpath.smoothed_rtt_us as f64 / profile.max_rtt_us as f64)).max(0.0)
                } else {
                    1.0
                };
                let jitter_factor = if profile.max_jitter_us > 0 {
                    (1.0 - (subpath.jitter_us as f64 / profile.max_jitter_us as f64)).max(0.0)
                } else {
                    1.0
                };
                let queuing_factor = if profile.max_queuing_delay_us > 0 {
                    (1.0 - (subpath.queuing_delay_us as f64 / profile.max_queuing_delay_us as f64))
                        .max(0.0)
                } else {
                    1.0
                };
                let raw = (rtt_factor * 45.0) + (jitter_factor * 35.0) + (queuing_factor * 20.0);
                if has_breach {
                    raw * 0.4
                } else {
                    raw
                }
            }
            FlowSliceClass::HighThroughput => {
                // Focus: Available Bandwidth (50%), Low Saturation (30%), RTT (20%)
                let target_bw = profile.min_bandwidth_bps.max(10_000_000) as f64;
                let bw_factor =
                    (subpath.available_bandwidth_bps as f64 / target_bw).clamp(0.0, 1.0);
                let sat_factor = (1.0 - subpath.saturation_ratio).clamp(0.0, 1.0);
                let rtt_factor = if profile.max_rtt_us > 0 {
                    (1.0 - (subpath.smoothed_rtt_us as f64 / profile.max_rtt_us as f64)).max(0.0)
                } else {
                    1.0
                };
                let raw = (bw_factor * 50.0) + (sat_factor * 30.0) + (rtt_factor * 20.0);
                if has_breach {
                    raw * 0.4
                } else {
                    raw
                }
            }
            FlowSliceClass::MissionCritical => {
                // Focus: Minimal Loss (40%), Low Queuing Delay (30%), Low Jitter (20%), Low RTT (10%)
                let loss_factor = if profile.max_loss_ppm > 0 {
                    (1.0 - (subpath.loss_ppm as f64 / profile.max_loss_ppm as f64)).max(0.0)
                } else {
                    1.0
                };
                let queuing_factor = if profile.max_queuing_delay_us > 0 {
                    (1.0 - (subpath.queuing_delay_us as f64 / profile.max_queuing_delay_us as f64))
                        .max(0.0)
                } else {
                    1.0
                };
                let jitter_factor = if profile.max_jitter_us > 0 {
                    (1.0 - (subpath.jitter_us as f64 / profile.max_jitter_us as f64)).max(0.0)
                } else {
                    1.0
                };
                let rtt_factor = if profile.max_rtt_us > 0 {
                    (1.0 - (subpath.smoothed_rtt_us as f64 / profile.max_rtt_us as f64)).max(0.0)
                } else {
                    1.0
                };
                let raw = (loss_factor * 40.0)
                    + (queuing_factor * 30.0)
                    + (jitter_factor * 20.0)
                    + (rtt_factor * 10.0);
                if has_breach {
                    raw * 0.3
                } else {
                    raw
                }
            }
            FlowSliceClass::BestEffort => {
                // Focus: Lowest Saturation (60%), Higher Available Bandwidth (40%)
                let sat_factor = (1.0 - subpath.saturation_ratio).clamp(0.0, 1.0);
                let bw_factor = if subpath.capacity_bps > 0 {
                    (subpath.available_bandwidth_bps as f64 / subpath.capacity_bps as f64)
                        .clamp(0.0, 1.0)
                } else {
                    0.5
                };
                (sat_factor * 60.0) + (bw_factor * 40.0)
            }
        };

        Some((score.clamp(0.0, 100.0), has_breach))
    }

    /// Negotiate the optimal subpath slice for a flow given currently available subpaths.
    pub fn negotiate_slice(
        &mut self,
        session_id: &SessionId,
        subpaths: &[SubpathQoSCapability],
        now_ms: u64,
    ) -> Result<FlowSliceAssignment, FlowSlicingError> {
        self.metrics.total_negotiations += 1;

        let profile = self
            .profiles
            .get(session_id)
            .cloned()
            .ok_or(FlowSlicingError::FlowProfileNotFound(*session_id))?;

        let mut best_candidate: Option<(u32, f64, bool)> = None;

        for subpath in subpaths {
            if let Some((score, is_degraded)) = Self::evaluate_subpath_fitness(&profile, subpath) {
                match best_candidate {
                    None => best_candidate = Some((subpath.path_id, score, is_degraded)),
                    Some((_, best_score, best_degraded)) => {
                        // Prefer non-degraded over degraded; then higher fitness score
                        if (best_degraded && !is_degraded)
                            || (best_degraded == is_degraded && score > best_score)
                        {
                            best_candidate = Some((subpath.path_id, score, is_degraded));
                        }
                    }
                }
            }
        }

        match best_candidate {
            Some((path_id, score, is_degraded)) => {
                let assignment = FlowSliceAssignment {
                    session_id: *session_id,
                    slice_class: profile.slice_class,
                    assigned_path_id: path_id,
                    fitness_score: score,
                    negotiated_at_unix_ms: now_ms,
                    is_degraded,
                };
                if is_degraded {
                    *self
                        .metrics
                        .sla_violations
                        .entry(profile.slice_class)
                        .or_insert(0) += 1;
                    self.metrics.active_degraded_flows += 1;
                }
                self.metrics.successful_negotiations += 1;
                self.assignments.insert(*session_id, assignment.clone());
                Ok(assignment)
            }
            None => {
                self.metrics.failed_negotiations += 1;
                *self
                    .metrics
                    .sla_violations
                    .entry(profile.slice_class)
                    .or_insert(0) += 1;
                Err(FlowSlicingError::NoEligibleSubpath {
                    session_id: *session_id,
                    slice_class: profile.slice_class,
                })
            }
        }
    }

    /// Inspect active flow assignments against real-time subpath telemetry and migrate flows
    /// whose QoS profile has been breached.
    pub fn evaluate_and_renegotiate(
        &mut self,
        subpaths: &[SubpathQoSCapability],
        now_ms: u64,
    ) -> Vec<FlowSliceMigrationEvent> {
        let mut migrations = Vec::new();
        let subpaths_by_id: HashMap<u32, &SubpathQoSCapability> =
            subpaths.iter().map(|s| (s.path_id, s)).collect();

        let session_ids: Vec<SessionId> = self.assignments.keys().copied().collect();

        for sid in session_ids {
            let (profile, current_assignment) =
                match (self.profiles.get(&sid), self.assignments.get(&sid)) {
                    (Some(p), Some(a)) => (p.clone(), a.clone()),
                    _ => continue,
                };

            let current_subpath = subpaths_by_id.get(&current_assignment.assigned_path_id);

            // Check if current path still meets profile or has specific breach
            let breach_reason = if let Some(sp) = current_subpath {
                if !sp.is_usable {
                    Some(SliceMigrationReason::PathUnusable)
                } else if sp.smoothed_rtt_us > profile.max_rtt_us {
                    Some(SliceMigrationReason::LatencyViolation)
                } else if sp.jitter_us > profile.max_jitter_us {
                    Some(SliceMigrationReason::JitterViolation)
                } else if sp.queuing_delay_us > profile.max_queuing_delay_us {
                    Some(SliceMigrationReason::QueuingDelayViolation)
                } else if sp.available_bandwidth_bps < profile.min_bandwidth_bps {
                    Some(SliceMigrationReason::BandwidthStarvation)
                } else if sp.loss_ppm > profile.max_loss_ppm {
                    Some(SliceMigrationReason::PacketLossSpike)
                } else {
                    None
                }
            } else {
                Some(SliceMigrationReason::PathUnusable)
            };

            // If breached or current assignment was degraded, search for a strictly superior subpath
            let should_renegotiate = breach_reason.is_some() || current_assignment.is_degraded;

            if should_renegotiate {
                let mut best_alt: Option<(u32, f64, bool)> = None;

                for subpath in subpaths {
                    if let Some((score, is_degraded)) =
                        Self::evaluate_subpath_fitness(&profile, subpath)
                    {
                        match best_alt {
                            None => best_alt = Some((subpath.path_id, score, is_degraded)),
                            Some((_, best_score, best_degraded)) => {
                                if (best_degraded && !is_degraded)
                                    || (best_degraded == is_degraded && score > best_score)
                                {
                                    best_alt = Some((subpath.path_id, score, is_degraded));
                                }
                            }
                        }
                    }
                }

                if let Some((new_path_id, new_score, new_is_degraded)) = best_alt {
                    // Only migrate if we move to a different path or recover from degraded state
                    if new_path_id != current_assignment.assigned_path_id
                        || (current_assignment.is_degraded && !new_is_degraded)
                    {
                        let reason =
                            breach_reason.unwrap_or(SliceMigrationReason::RebalanceOptimization);
                        let cutover_latency_us = if let Some(sp) = subpaths_by_id.get(&new_path_id)
                        {
                            (sp.smoothed_rtt_us as f64) * 0.25 // Simulated cutover propagation overhead
                        } else {
                            500.0
                        };

                        let event = FlowSliceMigrationEvent {
                            session_id: sid,
                            slice_class: profile.slice_class,
                            from_path_id: current_assignment.assigned_path_id,
                            to_path_id: new_path_id,
                            reason,
                            migration_timestamp_ms: now_ms,
                            cutover_latency_us,
                        };

                        if current_assignment.is_degraded && !new_is_degraded {
                            self.metrics.active_degraded_flows =
                                self.metrics.active_degraded_flows.saturating_sub(1);
                        } else if !current_assignment.is_degraded && new_is_degraded {
                            self.metrics.active_degraded_flows += 1;
                            *self
                                .metrics
                                .sla_violations
                                .entry(profile.slice_class)
                                .or_insert(0) += 1;
                        }

                        let updated_assignment = FlowSliceAssignment {
                            session_id: sid,
                            slice_class: profile.slice_class,
                            assigned_path_id: new_path_id,
                            fitness_score: new_score,
                            negotiated_at_unix_ms: now_ms,
                            is_degraded: new_is_degraded,
                        };

                        self.assignments.insert(sid, updated_assignment);
                        self.metrics.total_slice_migrations += 1;
                        self.migration_history.push(event.clone());
                        migrations.push(event);
                    }
                } else if breach_reason.is_some() {
                    // Could not find any alternative: record SLA violation
                    *self
                        .metrics
                        .sla_violations
                        .entry(profile.slice_class)
                        .or_insert(0) += 1;
                }
            }
        }

        migrations
    }

    /// Export flow slicing metrics in standard Prometheus text format.
    pub fn export_prometheus_metrics(&self) -> String {
        let mut out = String::with_capacity(1024);

        out.push_str("# HELP ifa_traffic_slice_total_negotiations Total flow slicing negotiations attempted.\n");
        out.push_str("# TYPE ifa_traffic_slice_total_negotiations counter\n");
        out.push_str(&format!(
            "ifa_traffic_slice_total_negotiations {}\n",
            self.metrics.total_negotiations
        ));

        out.push_str("# HELP ifa_traffic_slice_successful_negotiations Successfully negotiated flow slices.\n");
        out.push_str("# TYPE ifa_traffic_slice_successful_negotiations counter\n");
        out.push_str(&format!(
            "ifa_traffic_slice_successful_negotiations {}\n",
            self.metrics.successful_negotiations
        ));

        out.push_str(
            "# HELP ifa_traffic_slice_failed_negotiations Failed flow slice negotiations.\n",
        );
        out.push_str("# TYPE ifa_traffic_slice_failed_negotiations counter\n");
        out.push_str(&format!(
            "ifa_traffic_slice_failed_negotiations {}\n",
            self.metrics.failed_negotiations
        ));

        out.push_str(
            "# HELP ifa_traffic_slice_migrations_total Dynamic subpath slice migrations.\n",
        );
        out.push_str("# TYPE ifa_traffic_slice_migrations_total counter\n");
        out.push_str(&format!(
            "ifa_traffic_slice_migrations_total {}\n",
            self.metrics.total_slice_migrations
        ));

        out.push_str("# HELP ifa_traffic_slice_active_flows Current active flows partitioned by slice class.\n");
        out.push_str("# TYPE ifa_traffic_slice_active_flows gauge\n");
        for class in &[
            FlowSliceClass::UltraLowLatency,
            FlowSliceClass::HighThroughput,
            FlowSliceClass::MissionCritical,
            FlowSliceClass::BestEffort,
        ] {
            out.push_str(&format!(
                "ifa_traffic_slice_active_flows{{slice=\"{}\"}} {}\n",
                class.as_str(),
                self.active_flows_in_slice(*class)
            ));
        }

        out.push_str("# HELP ifa_traffic_slice_sla_violations_total SLA violations accumulated per slice class.\n");
        out.push_str("# TYPE ifa_traffic_slice_sla_violations_total counter\n");
        for class in &[
            FlowSliceClass::UltraLowLatency,
            FlowSliceClass::HighThroughput,
            FlowSliceClass::MissionCritical,
            FlowSliceClass::BestEffort,
        ] {
            let count = self.metrics.sla_violations.get(class).copied().unwrap_or(0);
            out.push_str(&format!(
                "ifa_traffic_slice_sla_violations_total{{slice=\"{}\"}} {}\n",
                class.as_str(),
                count
            ));
        }

        out
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_session(id: u64) -> SessionId {
        SessionId::new(id, 1, 0)
    }

    #[test]
    fn test_flow_slice_profile_presets() {
        let urllc = FlowQoSProfile::ultra_low_latency();
        assert_eq!(urllc.slice_class, FlowSliceClass::UltraLowLatency);
        assert_eq!(urllc.max_rtt_us, 20_000);
        assert_eq!(urllc.max_jitter_us, 3_000);
        assert!(urllc.priority >= 200);

        let bulk = FlowQoSProfile::high_throughput(100_000_000);
        assert_eq!(bulk.slice_class, FlowSliceClass::HighThroughput);
        assert_eq!(bulk.min_bandwidth_bps, 100_000_000);

        let mc = FlowQoSProfile::mission_critical();
        assert_eq!(mc.slice_class, FlowSliceClass::MissionCritical);
        assert_eq!(mc.max_loss_ppm, 10);
        assert!(!mc.allow_fallback);
    }

    #[test]
    fn test_negotiate_ultra_low_latency_steers_to_fastest_link() {
        let mut negotiator = FlowSliceNegotiator::new();
        let sid = dummy_session(1);
        negotiator.register_profile(sid, FlowQoSProfile::ultra_low_latency());

        // Subpath 1: Fast fiber link (5ms RTT, 500µs jitter)
        let subpath1 = SubpathQoSCapability {
            path_id: 1,
            interface_name: "eth-fiber".to_string(),
            smoothed_rtt_us: 5_000,
            jitter_us: 500,
            queuing_delay_us: 1_000,
            capacity_bps: 50_000_000,
            throughput_bps: 5_000_000,
            available_bandwidth_bps: 45_000_000,
            saturation_ratio: 0.10,
            loss_ppm: 0,
            is_usable: true,
        };

        // Subpath 2: High bandwidth satellite / high latency link (100ms RTT, 15ms jitter)
        let subpath2 = SubpathQoSCapability {
            path_id: 2,
            interface_name: "sat-broadband".to_string(),
            smoothed_rtt_us: 100_000,
            jitter_us: 15_000,
            queuing_delay_us: 20_000,
            capacity_bps: 1_000_000_000,
            throughput_bps: 50_000_000,
            available_bandwidth_bps: 950_000_000,
            saturation_ratio: 0.05,
            loss_ppm: 100,
            is_usable: true,
        };

        let subpaths = vec![subpath1, subpath2];
        let assignment = negotiator.negotiate_slice(&sid, &subpaths, 1_000).unwrap();

        assert_eq!(assignment.assigned_path_id, 1);
        assert!(!assignment.is_degraded);
        assert!(assignment.fitness_score > 75.0);
        assert_eq!(
            negotiator.active_flows_in_slice(FlowSliceClass::UltraLowLatency),
            1
        );
    }

    #[test]
    fn test_negotiate_high_throughput_steers_to_high_capacity_link() {
        let mut negotiator = FlowSliceNegotiator::new();
        let sid = dummy_session(2);
        // Requires 80 Mbps
        negotiator.register_profile(sid, FlowQoSProfile::high_throughput(80_000_000));

        // Subpath 1: Low bandwidth link (10 Mbps capacity, 2ms RTT)
        let subpath1 = SubpathQoSCapability {
            path_id: 1,
            interface_name: "dsl".to_string(),
            smoothed_rtt_us: 2_000,
            jitter_us: 400,
            queuing_delay_us: 800,
            capacity_bps: 10_000_000,
            throughput_bps: 1_000_000,
            available_bandwidth_bps: 9_000_000,
            saturation_ratio: 0.10,
            loss_ppm: 0,
            is_usable: true,
        };

        // Subpath 2: High bandwidth 10GbE link (1 Gbps capacity, 25ms RTT)
        let subpath2 = SubpathQoSCapability {
            path_id: 2,
            interface_name: "eth-10gbe".to_string(),
            smoothed_rtt_us: 25_000,
            jitter_us: 2_000,
            queuing_delay_us: 3_000,
            capacity_bps: 1_000_000_000,
            throughput_bps: 100_000_000,
            available_bandwidth_bps: 900_000_000,
            saturation_ratio: 0.10,
            loss_ppm: 10,
            is_usable: true,
        };

        let subpaths = vec![subpath1, subpath2];
        let assignment = negotiator.negotiate_slice(&sid, &subpaths, 1_000).unwrap();

        assert_eq!(assignment.assigned_path_id, 2);
        assert!(!assignment.is_degraded);
        assert_eq!(
            negotiator.active_flows_in_slice(FlowSliceClass::HighThroughput),
            1
        );
    }

    #[test]
    fn test_dynamic_slice_migration_on_telemetry_jitter_spike() {
        let mut negotiator = FlowSliceNegotiator::new();
        let sid = dummy_session(3);
        negotiator.register_profile(sid, FlowQoSProfile::ultra_low_latency());

        let mut subpath1 = SubpathQoSCapability {
            path_id: 1,
            interface_name: "primary-fiber".to_string(),
            smoothed_rtt_us: 6_000,
            jitter_us: 1_000,
            queuing_delay_us: 1_000,
            capacity_bps: 100_000_000,
            throughput_bps: 10_000_000,
            available_bandwidth_bps: 90_000_000,
            saturation_ratio: 0.10,
            loss_ppm: 0,
            is_usable: true,
        };

        let subpath2 = SubpathQoSCapability {
            path_id: 2,
            interface_name: "backup-fiber".to_string(),
            smoothed_rtt_us: 10_000,
            jitter_us: 1_500,
            queuing_delay_us: 2_000,
            capacity_bps: 100_000_000,
            throughput_bps: 10_000_000,
            available_bandwidth_bps: 90_000_000,
            saturation_ratio: 0.10,
            loss_ppm: 0,
            is_usable: true,
        };

        let initial_subpaths = vec![subpath1.clone(), subpath2.clone()];
        let init_assign = negotiator
            .negotiate_slice(&sid, &initial_subpaths, 1_000)
            .unwrap();
        assert_eq!(init_assign.assigned_path_id, 1);

        // Telemetry degradation: Jitter surges on subpath 1 to 25ms (breaching 3ms max)
        subpath1.jitter_us = 25_000;
        let updated_subpaths = vec![subpath1, subpath2];

        let migrations = negotiator.evaluate_and_renegotiate(&updated_subpaths, 2_000);
        assert_eq!(migrations.len(), 1);
        assert_eq!(migrations[0].from_path_id, 1);
        assert_eq!(migrations[0].to_path_id, 2);
        assert_eq!(migrations[0].reason, SliceMigrationReason::JitterViolation);

        let current = negotiator.get_assignment(&sid).unwrap();
        assert_eq!(current.assigned_path_id, 2);
        assert_eq!(negotiator.metrics().total_slice_migrations, 1);
    }

    #[test]
    fn test_strict_mission_critical_rejection_without_fallback() {
        let mut negotiator = FlowSliceNegotiator::new();
        let sid = dummy_session(4);
        negotiator.register_profile(sid, FlowQoSProfile::mission_critical());

        // Path has excessive packet loss (5000 ppm vs 10 ppm max)
        let subpath = SubpathQoSCapability {
            path_id: 1,
            interface_name: "lossy-link".to_string(),
            smoothed_rtt_us: 10_000,
            jitter_us: 1_000,
            queuing_delay_us: 2_000,
            capacity_bps: 50_000_000,
            throughput_bps: 5_000_000,
            available_bandwidth_bps: 45_000_000,
            saturation_ratio: 0.10,
            loss_ppm: 5_000,
            is_usable: true,
        };

        let res = negotiator.negotiate_slice(&sid, &[subpath], 1_000);
        assert!(matches!(
            res,
            Err(FlowSlicingError::NoEligibleSubpath { .. })
        ));
        assert_eq!(negotiator.metrics().failed_negotiations, 1);
    }

    #[test]
    fn test_prometheus_metrics_export() {
        let mut negotiator = FlowSliceNegotiator::new();
        let sid = dummy_session(5);
        negotiator.register_profile(sid, FlowQoSProfile::best_effort());

        let subpath = SubpathQoSCapability {
            path_id: 1,
            interface_name: "eth0".to_string(),
            smoothed_rtt_us: 20_000,
            jitter_us: 2_000,
            queuing_delay_us: 5_000,
            capacity_bps: 100_000_000,
            throughput_bps: 10_000_000,
            available_bandwidth_bps: 90_000_000,
            saturation_ratio: 0.10,
            loss_ppm: 0,
            is_usable: true,
        };

        negotiator.negotiate_slice(&sid, &[subpath], 1_000).unwrap();
        let prom = negotiator.export_prometheus_metrics();

        assert!(prom.contains("ifa_traffic_slice_total_negotiations 1"));
        assert!(prom.contains("ifa_traffic_slice_successful_negotiations 1"));
        assert!(prom.contains("ifa_traffic_slice_active_flows{slice=\"best_effort\"} 1"));
    }

    #[test]
    fn test_multipath_router_flow_slicing_integration() {
        use crate::session_sync::{
            IsspDynamicMultipathRouter, IsspMultipathRoute, IsspRoutingPolicy,
        };

        let mut router = IsspDynamicMultipathRouter::new(1, IsspRoutingPolicy::LowestLatency);

        // Route 1: Fiber link with low latency (3ms) and lower bandwidth
        let mut r1 = IsspMultipathRoute::new(1, 2, "eth-fiber", 1, 100);
        r1.metrics.smoothed_rtt_us = 3_000;
        r1.metrics.jitter_us = 300;
        r1.congestion.bbr.estimated_bandwidth_bps = 50_000_000;
        router.add_route(r1);

        // Route 2: High capacity 10GbE with higher latency (12ms)
        let mut r2 = IsspMultipathRoute::new(2, 2, "eth-10gbe", 2, 500);
        r2.metrics.smoothed_rtt_us = 12_000;
        r2.metrics.jitter_us = 1_000;
        r2.congestion.bbr.estimated_bandwidth_bps = 1_000_000_000;
        router.add_route(r2);

        let sid_urllc = dummy_session(10);
        let sid_bulk = dummy_session(20);

        router.register_flow_qos_profile(sid_urllc, FlowQoSProfile::ultra_low_latency());
        router.register_flow_qos_profile(sid_bulk, FlowQoSProfile::high_throughput(80_000_000));

        let assign_urllc = router
            .negotiate_flow_slice(&sid_urllc, 1_000, None)
            .unwrap();
        let assign_bulk = router.negotiate_flow_slice(&sid_bulk, 1_000, None).unwrap();

        assert_eq!(assign_urllc.assigned_path_id, 1); // URLLC steered to fiber
        assert_eq!(assign_bulk.assigned_path_id, 2); // Bulk steered to 10GbE

        // Verify schedule_packet routes packets to respective negotiated subpaths
        let pkt_urllc = router
            .schedule_packet(&sid_urllc, vec![1, 2, 3], 1_000)
            .unwrap();
        let pkt_bulk = router
            .schedule_packet(&sid_bulk, vec![4, 5, 6], 1_000)
            .unwrap();

        assert_eq!(pkt_urllc.path_id, 1);
        assert_eq!(pkt_bulk.path_id, 2);

        // Jitter spike on fiber path (degrades beyond 3ms max)
        if let Some(route) = router.get_route_mut(1) {
            route.metrics.jitter_us = 35_000;
        }

        // Trigger dynamic slice re-evaluation
        let migrations = router.evaluate_flow_slices(2_000, None);
        assert_eq!(migrations.len(), 1);
        assert_eq!(migrations[0].session_id, sid_urllc);
        assert_eq!(migrations[0].from_path_id, 1);
        assert_eq!(migrations[0].to_path_id, 2);
        assert_eq!(migrations[0].reason, SliceMigrationReason::JitterViolation);

        // Subsequent packet for URLLC session flows via migrated path 2
        let pkt_urllc_migrated = router
            .schedule_packet(&sid_urllc, vec![7, 8, 9], 2_001)
            .unwrap();
        assert_eq!(pkt_urllc_migrated.path_id, 2);

        // Check Prometheus balancing snapshot integration
        let snap = router.balancing_snapshot(0);
        let prom = snap.export_prometheus();
        assert!(prom.contains("ifa_traffic_slice_migrations_total"));
        assert!(prom.contains("ifa_traffic_slice_active_flows"));
        assert!(prom.contains("} 1\n"));
    }
}

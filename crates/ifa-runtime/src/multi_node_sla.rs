//! Global multi-node closed-loop SLA compliance and inter-slice isolation telemetry synthesis.
//!
//! Provides distributed end-to-end SLA tracking, cross-node inter-slice interference detection,
//! dynamic capacity headroom reservation, upstream backpressure signaling, and closed-loop
//! isolation remediation across heterogeneous traffic slices (URLLC, MissionCritical, eMBB, BestEffort).

use std::collections::BTreeMap;
use std::fmt::Write;
use std::string::String;
use std::vec::Vec;

use crate::traffic_slicing::FlowSliceClass;

/// Telemetry record emitted per slice on a specific node and subpath.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiNodeSliceTelemetryRecord {
    pub node_id: u32,
    pub timestamp_ns: u64,
    pub subpath_id: u32,
    pub slice_class: FlowSliceClass,
    pub packets_transmitted: u64,
    pub packets_lost: u64,
    pub bytes_transmitted: u64,
    pub avg_rtt_ns: u64,
    pub p99_rtt_ns: u64,
    pub jitter_ns: u64,
    pub queuing_delay_ns: u64,
    pub active_flows: u32,
    pub allocated_bandwidth_bps: u64,
}

/// Strict SLA targets configured per slice class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SliceSlaTarget {
    pub slice_class: FlowSliceClass,
    pub max_latency_ns: u64,
    pub max_jitter_ns: u64,
    pub max_loss_ppm: u32,
    pub min_bandwidth_bps: u64,
}

impl SliceSlaTarget {
    /// Nominal standard SLA targets for each traffic class.
    pub fn default_for(slice_class: FlowSliceClass) -> Self {
        match slice_class {
            FlowSliceClass::UltraLowLatency => Self {
                slice_class,
                max_latency_ns: 5_000_000,    // 5 ms
                max_jitter_ns: 1_000_000,     // 1 ms
                max_loss_ppm: 10,             // 0.001%
                min_bandwidth_bps: 5_000_000, // 5 Mbps
            },
            FlowSliceClass::MissionCritical => Self {
                slice_class,
                max_latency_ns: 20_000_000,    // 20 ms
                max_jitter_ns: 5_000_000,      // 5 ms
                max_loss_ppm: 100,             // 0.01%
                min_bandwidth_bps: 20_000_000, // 20 Mbps
            },
            FlowSliceClass::HighThroughput => Self {
                slice_class,
                max_latency_ns: 100_000_000,    // 100 ms
                max_jitter_ns: 30_000_000,      // 30 ms
                max_loss_ppm: 1_000,            // 0.1%
                min_bandwidth_bps: 100_000_000, // 100 Mbps
            },
            FlowSliceClass::BestEffort => Self {
                slice_class,
                max_latency_ns: 500_000_000,  // 500 ms
                max_jitter_ns: 100_000_000,   // 100 ms
                max_loss_ppm: 10_000,         // 1.0%
                min_bandwidth_bps: 1_000_000, // 1 Mbps
            },
        }
    }
}

/// An identified inter-slice cross-interference event on a shared link or node.
#[derive(Debug, Clone, PartialEq)]
pub struct InterSliceInterferenceEvent {
    pub node_id: u32,
    pub subpath_id: u32,
    pub timestamp_ns: u64,
    pub victim_slice: FlowSliceClass,
    pub aggressor_slice: FlowSliceClass,
    pub interference_score: f64,
    pub victim_delay_inflation_pct: f64,
    pub aggressor_bandwidth_share_pct: f64,
}

/// Severity level of global network saturation across multi-node mesh.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SaturationSeverity {
    /// Normal operating conditions; no preemption required.
    Normal = 0,
    /// Elevated queuing delay or slight isolation drop; mild rate suppression on lowest priority.
    Elevated = 1,
    /// Severe congestion threatening MissionCritical traffic; preemption of BestEffort and heavy throttling.
    Severe = 2,
    /// Critical congestion causing direct SLA violations on UltraLowLatency; immediate preemption of non-priority flows.
    Critical = 3,
}

impl SaturationSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Elevated => "elevated",
            Self::Severe => "severe",
            Self::Critical => "critical",
        }
    }
}

/// Global mesh saturation assessment synthesized from active multi-node telemetry.
#[derive(Debug, Clone, PartialEq)]
pub struct GlobalSaturationAssessment {
    pub severity: SaturationSeverity,
    pub global_isolation_score: f64,
    pub global_compliance_ratio: f64,
    pub congested_nodes: Vec<u32>,
    pub congested_subpaths: Vec<(u32, u32)>,
    pub violating_priority_slices: Vec<FlowSliceClass>,
    pub average_mesh_queuing_delay_ns: u64,
    pub recommended_action: Option<ClosedLoopControlAction>,
}

/// Closed-loop remedial actions executed to enforce isolation and restore SLA compliance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClosedLoopControlAction {
    DedicatedSubpathIsolation {
        victim_slice: FlowSliceClass,
        preferred_subpath_id: u32,
        node_id: u32,
    },
    AggressiveRateThrottling {
        aggressor_slice: FlowSliceClass,
        subpath_id: u32,
        node_id: u32,
        rate_cap_bps: u64,
    },
    CapacityHeadroomReservation {
        subpath_id: u32,
        node_id: u32,
        reserved_headroom_pct: u8,
    },
    UpstreamBackpressureSignal {
        source_node_id: u32,
        ingress_node_id: u32,
        throttled_slice: FlowSliceClass,
        recommended_max_rate_bps: u64,
    },
    GlobalSaturationPreemption {
        initiator_node_id: u32,
        severity: SaturationSeverity,
        preempted_slices: Vec<FlowSliceClass>,
        rate_multiplier_permille: u32,
        guaranteed_priority_headroom_pct: u8,
    },
}

/// Evaluation of SLA compliance for a slice on an individual node.
#[derive(Debug, Clone, PartialEq)]
pub struct NodeSlaEvaluation {
    pub node_id: u32,
    pub slice_class: FlowSliceClass,
    pub compliance_ratio: f64,
    pub avg_latency_ns: u64,
    pub max_latency_ns: u64,
    pub avg_jitter_ns: u64,
    pub loss_ratio_ppm: u32,
    pub total_samples: u64,
    pub violating_samples: u64,
    pub sla_met: bool,
}

/// End-to-end multi-hop SLA audit across traversed mesh nodes.
#[derive(Debug, Clone, PartialEq)]
pub struct EndToEndPathSlaAudit {
    pub slice_class: FlowSliceClass,
    pub traversed_nodes: Vec<u32>,
    pub cumulative_latency_ns: u64,
    pub cumulative_jitter_ns: u64,
    pub cumulative_loss_ppm: u32,
    pub bottleneck_node_id: u32,
    pub bottleneck_subpath_id: u32,
    pub sla_budget_ns: u64,
    pub sla_budget_depleted_pct: f64,
    pub e2e_sla_compliant: bool,
}

/// Result of an automated closed-loop evaluation cycle.
#[derive(Debug, Clone, PartialEq)]
pub struct ClosedLoopAdaptationResult {
    pub tick: u64,
    pub active_interferences: Vec<InterSliceInterferenceEvent>,
    pub actions_triggered: Vec<ClosedLoopControlAction>,
    pub global_compliance_ratio: f64,
    pub isolation_score: f64,
}

/// Telemetry metrics for Prometheus/OTel export.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MultiNodeSlaMetrics {
    pub total_samples_ingested: u64,
    pub total_interferences_detected: u64,
    pub total_closed_loop_actions: u64,
    pub total_isolations_enacted: u64,
    pub total_throttles_enacted: u64,
    pub total_reservations_enacted: u64,
    pub total_backpressure_signals: u64,
    pub total_preemption_actions: u64,
    pub total_e2e_sla_violations: u64,
}

/// Synthesizer for multi-node closed-loop SLA assurance and slice isolation.
#[derive(Debug, Clone)]
pub struct MultiNodeSlaSynthesizer {
    local_node_id: u32,
    history_limit: usize,
    records: Vec<MultiNodeSliceTelemetryRecord>,
    sla_targets: BTreeMap<FlowSliceClass, SliceSlaTarget>,
    subpath_allocations: BTreeMap<(u32, u32), BTreeMap<FlowSliceClass, u64>>,
    interference_threshold: f64,
    metrics: MultiNodeSlaMetrics,
    action_history: Vec<(u64, ClosedLoopControlAction)>,
    backpressure_queue: Vec<ClosedLoopControlAction>,
    headroom_reservations: BTreeMap<(u32, u32), u8>,
}

impl MultiNodeSlaSynthesizer {
    /// Create a new synthesizer for a local node.
    pub fn new(local_node_id: u32) -> Self {
        let mut sla_targets = BTreeMap::new();
        for &slice in &[
            FlowSliceClass::UltraLowLatency,
            FlowSliceClass::MissionCritical,
            FlowSliceClass::HighThroughput,
            FlowSliceClass::BestEffort,
        ] {
            sla_targets.insert(slice, SliceSlaTarget::default_for(slice));
        }

        Self {
            local_node_id,
            history_limit: 2048,
            records: Vec::new(),
            sla_targets,
            subpath_allocations: BTreeMap::new(),
            interference_threshold: 0.40,
            metrics: MultiNodeSlaMetrics::default(),
            action_history: Vec::new(),
            backpressure_queue: Vec::new(),
            headroom_reservations: BTreeMap::new(),
        }
    }

    /// Set an explicit SLA target for a specific traffic slice.
    pub fn set_sla_target(&mut self, target: SliceSlaTarget) {
        self.sla_targets.insert(target.slice_class, target);
    }

    /// Access active SLA target for a slice.
    pub fn sla_target(&self, slice: FlowSliceClass) -> Option<&SliceSlaTarget> {
        self.sla_targets.get(&slice)
    }

    /// Access collected telemetry metrics.
    pub fn metrics(&self) -> &MultiNodeSlaMetrics {
        &self.metrics
    }

    /// Ingest a telemetry sample from any node in the mesh.
    pub fn ingest_telemetry(&mut self, record: MultiNodeSliceTelemetryRecord) {
        self.metrics.total_samples_ingested = self.metrics.total_samples_ingested.saturating_add(1);

        let key = (record.node_id, record.subpath_id);
        self.subpath_allocations
            .entry(key)
            .or_default()
            .insert(record.slice_class, record.allocated_bandwidth_bps);

        if self.records.len() >= self.history_limit {
            self.records.remove(0);
        }
        self.records.push(record);
    }

    /// Evaluate per-node SLA compliance for a slice class.
    pub fn evaluate_node_sla(
        &self,
        node_id: u32,
        slice_class: FlowSliceClass,
    ) -> NodeSlaEvaluation {
        let target = self
            .sla_targets
            .get(&slice_class)
            .cloned()
            .unwrap_or_else(|| SliceSlaTarget::default_for(slice_class));

        let node_samples: Vec<&MultiNodeSliceTelemetryRecord> = self
            .records
            .iter()
            .filter(|r| r.node_id == node_id && r.slice_class == slice_class)
            .collect();

        if node_samples.is_empty() {
            return NodeSlaEvaluation {
                node_id,
                slice_class,
                compliance_ratio: 1.0,
                avg_latency_ns: 0,
                max_latency_ns: 0,
                avg_jitter_ns: 0,
                loss_ratio_ppm: 0,
                total_samples: 0,
                violating_samples: 0,
                sla_met: true,
            };
        }

        let total_samples = node_samples.len() as u64;
        let mut total_latency: u128 = 0;
        let mut max_latency: u64 = 0;
        let mut total_jitter: u128 = 0;
        let mut total_pkts: u128 = 0;
        let mut total_lost: u128 = 0;
        let mut violating_samples: u64 = 0;

        for s in &node_samples {
            total_latency += s.avg_rtt_ns as u128;
            if s.p99_rtt_ns > max_latency {
                max_latency = s.p99_rtt_ns;
            }
            total_jitter += s.jitter_ns as u128;
            total_pkts += s.packets_transmitted as u128;
            total_lost += s.packets_lost as u128;

            let sample_loss_ppm = if s.packets_transmitted > 0 {
                ((s.packets_lost as f64 / s.packets_transmitted as f64) * 1_000_000.0) as u32
            } else {
                0
            };

            let is_violating = s.avg_rtt_ns > target.max_latency_ns
                || s.jitter_ns > target.max_jitter_ns
                || sample_loss_ppm > target.max_loss_ppm;

            if is_violating {
                violating_samples += 1;
            }
        }

        let avg_latency_ns = (total_latency / total_samples as u128) as u64;
        let avg_jitter_ns = (total_jitter / total_samples as u128) as u64;
        let loss_ratio_ppm = if total_pkts > 0 {
            ((total_lost as f64 / total_pkts as f64) * 1_000_000.0) as u32
        } else {
            0
        };

        let compliance_ratio =
            (total_samples.saturating_sub(violating_samples) as f64) / (total_samples as f64);
        let sla_met = violating_samples == 0;

        NodeSlaEvaluation {
            node_id,
            slice_class,
            compliance_ratio,
            avg_latency_ns,
            max_latency_ns: max_latency,
            avg_jitter_ns,
            loss_ratio_ppm,
            total_samples,
            violating_samples,
            sla_met,
        }
    }

    /// Audit end-to-end multi-hop SLA compliance across a sequence of traversed (node_id, subpath_id) hops.
    pub fn evaluate_e2e_path_sla(
        &self,
        slice_class: FlowSliceClass,
        path_hops: &[(u32, u32)],
    ) -> EndToEndPathSlaAudit {
        let target = self
            .sla_targets
            .get(&slice_class)
            .cloned()
            .unwrap_or_else(|| SliceSlaTarget::default_for(slice_class));

        let mut traversed_nodes = Vec::new();
        let mut cumulative_latency_ns: u64 = 0;
        let mut cumulative_jitter_ns: u64 = 0;
        let mut cumulative_loss_ppm: u32 = 0;

        let mut bottleneck_node_id: u32 = 0;
        let mut bottleneck_subpath_id: u32 = 0;
        let mut worst_hop_latency: u64 = 0;

        for &(node_id, subpath_id) in path_hops {
            if !traversed_nodes.contains(&node_id) {
                traversed_nodes.push(node_id);
            }

            // Find most recent sample for this node, subpath, and slice
            let hop_sample = self.records.iter().rev().find(|r| {
                r.node_id == node_id && r.subpath_id == subpath_id && r.slice_class == slice_class
            });

            if let Some(sample) = hop_sample {
                cumulative_latency_ns = cumulative_latency_ns.saturating_add(sample.avg_rtt_ns);
                cumulative_jitter_ns = cumulative_jitter_ns.saturating_add(sample.jitter_ns);
                let hop_loss = if sample.packets_transmitted > 0 {
                    ((sample.packets_lost as f64 / sample.packets_transmitted as f64) * 1_000_000.0)
                        as u32
                } else {
                    0
                };
                cumulative_loss_ppm = cumulative_loss_ppm.saturating_add(hop_loss);

                if sample.avg_rtt_ns >= worst_hop_latency {
                    worst_hop_latency = sample.avg_rtt_ns;
                    bottleneck_node_id = node_id;
                    bottleneck_subpath_id = subpath_id;
                }
            }
        }

        let sla_budget_ns = target.max_latency_ns;
        let sla_budget_depleted_pct = if sla_budget_ns > 0 {
            (cumulative_latency_ns as f64 / sla_budget_ns as f64) * 100.0
        } else {
            0.0
        };

        let e2e_sla_compliant = cumulative_latency_ns <= sla_budget_ns
            && cumulative_jitter_ns <= target.max_jitter_ns
            && cumulative_loss_ppm <= target.max_loss_ppm;

        EndToEndPathSlaAudit {
            slice_class,
            traversed_nodes,
            cumulative_latency_ns,
            cumulative_jitter_ns,
            cumulative_loss_ppm,
            bottleneck_node_id,
            bottleneck_subpath_id,
            sla_budget_ns,
            sla_budget_depleted_pct,
            e2e_sla_compliant,
        }
    }

    /// Detect cross-slice interferences on shared links where high-throughput flows
    /// inflate queuing delay or jitter for high-priority slices.
    pub fn detect_inter_slice_interference(&self) -> Vec<InterSliceInterferenceEvent> {
        let mut events = Vec::new();

        // Group recent samples by (node_id, subpath_id)
        let mut link_map: BTreeMap<(u32, u32), Vec<&MultiNodeSliceTelemetryRecord>> =
            BTreeMap::new();
        for r in self.records.iter().rev().take(500) {
            link_map
                .entry((r.node_id, r.subpath_id))
                .or_default()
                .push(r);
        }

        for (&(node_id, subpath_id), samples) in &link_map {
            // Find priority slices (URLLC, MissionCritical)
            let priority_samples: Vec<&&MultiNodeSliceTelemetryRecord> = samples
                .iter()
                .filter(|s| {
                    matches!(
                        s.slice_class,
                        FlowSliceClass::UltraLowLatency | FlowSliceClass::MissionCritical
                    )
                })
                .collect();

            // Find bulk slices (HighThroughput, BestEffort)
            let bulk_samples: Vec<&&MultiNodeSliceTelemetryRecord> = samples
                .iter()
                .filter(|s| {
                    matches!(
                        s.slice_class,
                        FlowSliceClass::HighThroughput | FlowSliceClass::BestEffort
                    )
                })
                .collect();

            for victim in priority_samples {
                let target = self
                    .sla_targets
                    .get(&victim.slice_class)
                    .cloned()
                    .unwrap_or_else(|| SliceSlaTarget::default_for(victim.slice_class));

                let victim_delay_inflation_pct = if target.max_jitter_ns > 0 {
                    (victim.queuing_delay_ns as f64 / target.max_jitter_ns as f64) * 100.0
                } else {
                    0.0
                };

                for aggressor in &bulk_samples {
                    let total_bw = victim
                        .allocated_bandwidth_bps
                        .saturating_add(aggressor.allocated_bandwidth_bps);
                    let aggressor_bandwidth_share_pct = if total_bw > 0 {
                        (aggressor.allocated_bandwidth_bps as f64 / total_bw as f64) * 100.0
                    } else {
                        0.0
                    };

                    // Normalized interference score
                    let inflation_score = (victim_delay_inflation_pct / 100.0).min(1.0);
                    let bw_score = aggressor_bandwidth_share_pct / 100.0;
                    let interference_score = inflation_score * 0.6 + bw_score * 0.4;

                    if interference_score >= self.interference_threshold
                        && (victim.queuing_delay_ns > target.max_jitter_ns / 2
                            || victim.jitter_ns > target.max_jitter_ns)
                    {
                        events.push(InterSliceInterferenceEvent {
                            node_id,
                            subpath_id,
                            timestamp_ns: victim.timestamp_ns,
                            victim_slice: victim.slice_class,
                            aggressor_slice: aggressor.slice_class,
                            interference_score,
                            victim_delay_inflation_pct,
                            aggressor_bandwidth_share_pct,
                        });
                    }
                }
            }
        }

        events
    }

    /// Compute global isolation score across all nodes and slices (0.0 to 1.0).
    pub fn compute_global_isolation_score(&self) -> f64 {
        let interferences = self.detect_inter_slice_interference();
        if interferences.is_empty() {
            return 1.0;
        }

        let total_score: f64 = interferences.iter().map(|e| e.interference_score).sum();
        let penalty = (total_score / (interferences.len() as f64 * 1.5)).min(1.0);
        (1.0 - penalty).clamp(0.0, 1.0)
    }

    /// Compute global SLA compliance ratio across all samples.
    pub fn compute_global_compliance_ratio(&self) -> f64 {
        if self.records.is_empty() {
            return 1.0;
        }

        let mut compliant_count = 0;
        for r in &self.records {
            let target = self
                .sla_targets
                .get(&r.slice_class)
                .cloned()
                .unwrap_or_else(|| SliceSlaTarget::default_for(r.slice_class));

            let sample_loss_ppm = if r.packets_transmitted > 0 {
                ((r.packets_lost as f64 / r.packets_transmitted as f64) * 1_000_000.0) as u32
            } else {
                0
            };

            if r.avg_rtt_ns <= target.max_latency_ns
                && r.jitter_ns <= target.max_jitter_ns
                && sample_loss_ppm <= target.max_loss_ppm
            {
                compliant_count += 1;
            }
        }

        (compliant_count as f64) / (self.records.len() as f64)
    }

    /// Synthesize global mesh saturation status from active telemetry records.
    ///
    /// Evaluates cross-node queuing delay, SLA target violations, and isolation degradation
    /// to determine whether global network saturation requires automated ingress preemption.
    pub fn detect_global_saturation(&self) -> GlobalSaturationAssessment {
        let global_isolation_score = self.compute_global_isolation_score();
        let global_compliance_ratio = self.compute_global_compliance_ratio();

        if self.records.is_empty() {
            return GlobalSaturationAssessment {
                severity: SaturationSeverity::Normal,
                global_isolation_score: 1.0,
                global_compliance_ratio: 1.0,
                congested_nodes: Vec::new(),
                congested_subpaths: Vec::new(),
                violating_priority_slices: Vec::new(),
                average_mesh_queuing_delay_ns: 0,
                recommended_action: None,
            };
        }

        let mut total_queuing_delay: u128 = 0;
        let mut sample_count: u64 = 0;
        let mut congested_nodes = Vec::new();
        let mut congested_subpaths = Vec::new();
        let mut violating_priority_slices = Vec::new();

        let mut urllc_violation = false;
        let mut mission_critical_violation = false;

        // Examine recent telemetry window (last 500 samples)
        for r in self.records.iter().rev().take(500) {
            total_queuing_delay += r.queuing_delay_ns as u128;
            sample_count += 1;

            let target = self
                .sla_targets
                .get(&r.slice_class)
                .cloned()
                .unwrap_or_else(|| SliceSlaTarget::default_for(r.slice_class));

            let sample_loss_ppm = if r.packets_transmitted > 0 {
                ((r.packets_lost as f64 / r.packets_transmitted as f64) * 1_000_000.0) as u32
            } else {
                0
            };

            let is_sla_violating = r.avg_rtt_ns > target.max_latency_ns
                || r.jitter_ns > target.max_jitter_ns
                || sample_loss_ppm > target.max_loss_ppm;

            // Congestion indicator: high queuing delay
            if r.queuing_delay_ns >= 4_000_000 {
                if !congested_nodes.contains(&r.node_id) {
                    congested_nodes.push(r.node_id);
                }
                if !congested_subpaths.contains(&(r.node_id, r.subpath_id)) {
                    congested_subpaths.push((r.node_id, r.subpath_id));
                }
            }

            if matches!(r.slice_class, FlowSliceClass::UltraLowLatency)
                && (is_sla_violating || r.queuing_delay_ns >= 2_000_000)
            {
                urllc_violation = true;
                if !violating_priority_slices.contains(&FlowSliceClass::UltraLowLatency) {
                    violating_priority_slices.push(FlowSliceClass::UltraLowLatency);
                }
            } else if matches!(r.slice_class, FlowSliceClass::MissionCritical)
                && (is_sla_violating || r.queuing_delay_ns >= 8_000_000)
            {
                mission_critical_violation = true;
                if !violating_priority_slices.contains(&FlowSliceClass::MissionCritical) {
                    violating_priority_slices.push(FlowSliceClass::MissionCritical);
                }
            }
        }

        let average_mesh_queuing_delay_ns = if sample_count > 0 {
            (total_queuing_delay / sample_count as u128) as u64
        } else {
            0
        };

        // Determine severity and preemption action
        let (severity, recommended_action) = if urllc_violation || global_isolation_score < 0.50 {
            // Critical saturation: preempt BestEffort entirely (0 permille) and throttle HighThroughput heavily
            let action = ClosedLoopControlAction::GlobalSaturationPreemption {
                initiator_node_id: self.local_node_id,
                severity: SaturationSeverity::Critical,
                preempted_slices: vec![FlowSliceClass::BestEffort, FlowSliceClass::HighThroughput],
                rate_multiplier_permille: 0,
                guaranteed_priority_headroom_pct: 50,
            };
            (SaturationSeverity::Critical, Some(action))
        } else if mission_critical_violation
            || congested_nodes.len() >= 2
            || global_isolation_score < 0.70
        {
            // Severe saturation: preempt BestEffort and throttle HighThroughput
            let action = ClosedLoopControlAction::GlobalSaturationPreemption {
                initiator_node_id: self.local_node_id,
                severity: SaturationSeverity::Severe,
                preempted_slices: vec![FlowSliceClass::BestEffort, FlowSliceClass::HighThroughput],
                rate_multiplier_permille: 250,
                guaranteed_priority_headroom_pct: 35,
            };
            (SaturationSeverity::Severe, Some(action))
        } else if global_isolation_score < 0.85
            || global_compliance_ratio < 0.90
            || average_mesh_queuing_delay_ns >= 2_000_000
        {
            // Elevated congestion: throttle BestEffort to 50%
            let action = ClosedLoopControlAction::GlobalSaturationPreemption {
                initiator_node_id: self.local_node_id,
                severity: SaturationSeverity::Elevated,
                preempted_slices: vec![FlowSliceClass::BestEffort],
                rate_multiplier_permille: 500,
                guaranteed_priority_headroom_pct: 20,
            };
            (SaturationSeverity::Elevated, Some(action))
        } else {
            (SaturationSeverity::Normal, None)
        };

        GlobalSaturationAssessment {
            severity,
            global_isolation_score,
            global_compliance_ratio,
            congested_nodes,
            congested_subpaths,
            violating_priority_slices,
            average_mesh_queuing_delay_ns,
            recommended_action,
        }
    }

    /// Run one closed-loop adaptation cycle: detects interferences, triggers isolation actions,
    /// applies rate throttling, reserves capacity headroom, and emits upstream backpressures.
    pub fn evaluate_and_adapt(&mut self, tick: u64) -> ClosedLoopAdaptationResult {
        let interferences = self.detect_inter_slice_interference();
        let mut actions = Vec::new();

        for event in &interferences {
            self.metrics.total_interferences_detected =
                self.metrics.total_interferences_detected.saturating_add(1);

            // 1. Dedicated subpath isolation for priority slice if alternate subpath is available
            let mut candidate_subpaths = Vec::new();
            for r in &self.records {
                if r.node_id == event.node_id
                    && r.subpath_id != event.subpath_id
                    && !candidate_subpaths.contains(&r.subpath_id)
                {
                    candidate_subpaths.push(r.subpath_id);
                }
            }

            if let Some(&preferred_subpath_id) = candidate_subpaths.first() {
                let action = ClosedLoopControlAction::DedicatedSubpathIsolation {
                    victim_slice: event.victim_slice,
                    preferred_subpath_id,
                    node_id: event.node_id,
                };
                actions.push(action);
                self.metrics.total_isolations_enacted =
                    self.metrics.total_isolations_enacted.saturating_add(1);
            }

            // 2. Aggressive rate throttling on aggressor slice
            let throttled_cap = 25_000_000; // Cap to 25 Mbps
            let throttle_action = ClosedLoopControlAction::AggressiveRateThrottling {
                aggressor_slice: event.aggressor_slice,
                subpath_id: event.subpath_id,
                node_id: event.node_id,
                rate_cap_bps: throttled_cap,
            };
            actions.push(throttle_action);
            self.metrics.total_throttles_enacted =
                self.metrics.total_throttles_enacted.saturating_add(1);

            // 3. Headroom reservation on congested link (reserve 30% for priority traffic)
            let reservation_pct = 30;
            self.headroom_reservations
                .insert((event.node_id, event.subpath_id), reservation_pct);
            let reservation_action = ClosedLoopControlAction::CapacityHeadroomReservation {
                subpath_id: event.subpath_id,
                node_id: event.node_id,
                reserved_headroom_pct: reservation_pct,
            };
            actions.push(reservation_action);
            self.metrics.total_reservations_enacted =
                self.metrics.total_reservations_enacted.saturating_add(1);

            // 4. Backpressure notification sent to mesh ingress (node 1)
            let backpressure_action = ClosedLoopControlAction::UpstreamBackpressureSignal {
                source_node_id: event.node_id,
                ingress_node_id: 1, // Default ingress coordinator
                throttled_slice: event.aggressor_slice,
                recommended_max_rate_bps: throttled_cap,
            };
            actions.push(backpressure_action.clone());
            self.backpressure_queue.push(backpressure_action);
            self.metrics.total_backpressure_signals =
                self.metrics.total_backpressure_signals.saturating_add(1);
        }

        // 5. Global saturation preemption evaluation
        let saturation = self.detect_global_saturation();
        if saturation.severity >= SaturationSeverity::Elevated {
            if let Some(preemption_action) = saturation.recommended_action {
                actions.push(preemption_action.clone());
                self.backpressure_queue.push(preemption_action);
                self.metrics.total_preemption_actions =
                    self.metrics.total_preemption_actions.saturating_add(1);
            }
        }

        self.metrics.total_closed_loop_actions = self
            .metrics
            .total_closed_loop_actions
            .saturating_add(actions.len() as u64);

        for a in &actions {
            self.action_history.push((tick, a.clone()));
        }

        let isolation_score = self.compute_global_isolation_score();
        let global_compliance_ratio = self.compute_global_compliance_ratio();

        ClosedLoopAdaptationResult {
            tick,
            active_interferences: interferences,
            actions_triggered: actions,
            global_compliance_ratio,
            isolation_score,
        }
    }

    /// Read active reserved headroom for a given node and subpath.
    pub fn active_headroom_reservation(&self, node_id: u32, subpath_id: u32) -> u8 {
        self.headroom_reservations
            .get(&(node_id, subpath_id))
            .copied()
            .unwrap_or(0)
    }

    /// Drain queued backpressure signals destined for upstream ingress nodes.
    pub fn drain_backpressure_signals(&mut self) -> Vec<ClosedLoopControlAction> {
        std::mem::take(&mut self.backpressure_queue)
    }

    /// Export Prometheus / OpenTelemetry telemetry exposition.
    pub fn export_prometheus_metrics(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "# HELP ifa_slice_isolation_score Global inter-slice isolation index (0.0 to 1.0)"
        );
        let _ = writeln!(out, "# TYPE ifa_slice_isolation_score gauge");
        let _ = writeln!(
            out,
            "ifa_slice_isolation_score{{node=\"{}\"}} {:.4}",
            self.local_node_id,
            self.compute_global_isolation_score()
        );

        let _ = writeln!(
            out,
            "# HELP ifa_slice_sla_compliance_ratio Global slice SLA compliance ratio (0.0 to 1.0)"
        );
        let _ = writeln!(out, "# TYPE ifa_slice_sla_compliance_ratio gauge");
        let _ = writeln!(
            out,
            "ifa_slice_sla_compliance_ratio{{node=\"{}\"}} {:.4}",
            self.local_node_id,
            self.compute_global_compliance_ratio()
        );

        let _ = writeln!(
            out,
            "# HELP ifa_slice_closed_loop_actions_total Total closed-loop corrective actions"
        );
        let _ = writeln!(out, "# TYPE ifa_slice_closed_loop_actions_total counter");
        let _ = writeln!(
            out,
            "ifa_slice_closed_loop_actions_total{{node=\"{}\"}} {}",
            self.local_node_id, self.metrics.total_closed_loop_actions
        );

        let _ = writeln!(
            out,
            "# HELP ifa_slice_backpressure_signals_total Total backpressure signals emitted"
        );
        let _ = writeln!(out, "# TYPE ifa_slice_backpressure_signals_total counter");
        let _ = writeln!(
            out,
            "ifa_slice_backpressure_signals_total{{node=\"{}\"}} {}",
            self.local_node_id, self.metrics.total_backpressure_signals
        );

        let _ = writeln!(
            out,
            "# HELP ifa_slice_preemption_actions_total Total global saturation preemption actions enacted"
        );
        let _ = writeln!(out, "# TYPE ifa_slice_preemption_actions_total counter");
        let _ = writeln!(
            out,
            "ifa_slice_preemption_actions_total{{node=\"{}\"}} {}",
            self.local_node_id, self.metrics.total_preemption_actions
        );

        out
    }
}

/// Comprehensive report produced by the closed-loop multi-node SLA benchmark.
#[derive(Debug, Clone, PartialEq)]
pub struct MultiNodeSlaReport {
    pub total_nodes: usize,
    pub total_subpaths: usize,
    pub initial_compliance_ratio: f64,
    pub congested_compliance_ratio: f64,
    pub remediated_compliance_ratio: f64,
    pub initial_isolation_score: f64,
    pub congested_isolation_score: f64,
    pub remediated_isolation_score: f64,
    pub total_closed_loop_actions: u64,
    pub backpressure_signals_sent: usize,
    pub urllc_remediated_latency_ns: u64,
    pub closed_loop_success: bool,
}

/// Automated multi-node closed-loop SLA benchmark simulating cross-traffic congestion and remediation.
pub fn run_multi_node_sla_benchmark() -> MultiNodeSlaReport {
    let mut synth = MultiNodeSlaSynthesizer::new(1);

    // 4-Node topology: 1 (Ingress), 2 (Core A), 3 (Core B), 4 (Egress)
    // 2 Subpaths: 101 (Primary high-speed fiber), 102 (Secondary dedicated wireless/satellite)

    // Phase 1: Nominal baseline across all 4 nodes
    for node in 1..=4 {
        for &subpath in &[101, 102] {
            // URLLC nominal
            synth.ingest_telemetry(MultiNodeSliceTelemetryRecord {
                node_id: node,
                timestamp_ns: 1_000_000,
                subpath_id: subpath,
                slice_class: FlowSliceClass::UltraLowLatency,
                packets_transmitted: 10_000,
                packets_lost: 0,
                bytes_transmitted: 1_500_000,
                avg_rtt_ns: 1_200_000, // 1.2 ms
                p99_rtt_ns: 1_800_000,
                jitter_ns: 150_000,
                queuing_delay_ns: 80_000,
                active_flows: 5,
                allocated_bandwidth_bps: 10_000_000,
            });

            // eMBB nominal
            synth.ingest_telemetry(MultiNodeSliceTelemetryRecord {
                node_id: node,
                timestamp_ns: 1_000_000,
                subpath_id: subpath,
                slice_class: FlowSliceClass::HighThroughput,
                packets_transmitted: 50_000,
                packets_lost: 5,
                bytes_transmitted: 75_000_000,
                avg_rtt_ns: 25_000_000, // 25 ms
                p99_rtt_ns: 35_000_000,
                jitter_ns: 4_000_000,
                queuing_delay_ns: 1_500_000,
                active_flows: 20,
                allocated_bandwidth_bps: 80_000_000,
            });
        }
    }

    let initial_compliance_ratio = synth.compute_global_compliance_ratio();
    let initial_isolation_score = synth.compute_global_isolation_score();

    // Phase 2: Massive eMBB traffic burst at Node 2 (Core A) on Subpath 101 causing severe bufferbloat
    synth.ingest_telemetry(MultiNodeSliceTelemetryRecord {
        node_id: 2,
        timestamp_ns: 2_000_000,
        subpath_id: 101,
        slice_class: FlowSliceClass::HighThroughput,
        packets_transmitted: 500_000,
        packets_lost: 500,
        bytes_transmitted: 750_000_000,
        avg_rtt_ns: 85_000_000, // inflated
        p99_rtt_ns: 120_000_000,
        jitter_ns: 25_000_000,
        queuing_delay_ns: 40_000_000,
        active_flows: 150,
        allocated_bandwidth_bps: 950_000_000, // 950 Mbps saturated
    });

    // Victim URLLC at Node 2 suffers queuing delay inflation and jitter breach
    synth.ingest_telemetry(MultiNodeSliceTelemetryRecord {
        node_id: 2,
        timestamp_ns: 2_000_000,
        subpath_id: 101,
        slice_class: FlowSliceClass::UltraLowLatency,
        packets_transmitted: 10_000,
        packets_lost: 25,
        bytes_transmitted: 1_500_000,
        avg_rtt_ns: 18_000_000, // Breached 5ms SLA!
        p99_rtt_ns: 28_000_000,
        jitter_ns: 8_500_000, // Breached 1ms jitter SLA!
        queuing_delay_ns: 15_000_000,
        active_flows: 5,
        allocated_bandwidth_bps: 10_000_000,
    });

    let congested_compliance_ratio = synth.compute_global_compliance_ratio();
    let congested_isolation_score = synth.compute_global_isolation_score();

    // Phase 3: Closed-loop adaptation cycle
    let adaptation = synth.evaluate_and_adapt(3);
    let backpressures = synth.drain_backpressure_signals();

    // Phase 4: Apply remediated telemetry reflecting closed-loop actions
    // URLLC is isolated to subpath 102 (clean), eMBB throttled on 101
    synth.ingest_telemetry(MultiNodeSliceTelemetryRecord {
        node_id: 2,
        timestamp_ns: 4_000_000,
        subpath_id: 102,
        slice_class: FlowSliceClass::UltraLowLatency,
        packets_transmitted: 10_000,
        packets_lost: 0,
        bytes_transmitted: 1_500_000,
        avg_rtt_ns: 1_100_000, // 1.1 ms (restored!)
        p99_rtt_ns: 1_600_000,
        jitter_ns: 120_000,
        queuing_delay_ns: 50_000,
        active_flows: 5,
        allocated_bandwidth_bps: 10_000_000,
    });

    synth.ingest_telemetry(MultiNodeSliceTelemetryRecord {
        node_id: 2,
        timestamp_ns: 4_000_000,
        subpath_id: 101,
        slice_class: FlowSliceClass::HighThroughput,
        packets_transmitted: 150_000,
        packets_lost: 2,
        bytes_transmitted: 200_000_000,
        avg_rtt_ns: 28_000_000, // stabilized
        p99_rtt_ns: 38_000_000,
        jitter_ns: 3_500_000,
        queuing_delay_ns: 1_200_000,
        active_flows: 50,
        allocated_bandwidth_bps: 25_000_000, // throttled to 25 Mbps cap
    });

    let remediated_compliance_ratio = synth.compute_global_compliance_ratio();
    let remediated_isolation_score = synth.compute_global_isolation_score();

    let urllc_remediated = synth
        .records
        .iter()
        .rev()
        .find(|r| r.node_id == 2 && r.slice_class == FlowSliceClass::UltraLowLatency)
        .map(|r| r.avg_rtt_ns)
        .unwrap_or(0);

    let closed_loop_success = !adaptation.actions_triggered.is_empty()
        && remediated_compliance_ratio >= congested_compliance_ratio
        && remediated_isolation_score >= congested_isolation_score
        && urllc_remediated <= 5_000_000;

    MultiNodeSlaReport {
        total_nodes: 4,
        total_subpaths: 2,
        initial_compliance_ratio,
        congested_compliance_ratio,
        remediated_compliance_ratio,
        initial_isolation_score,
        congested_isolation_score,
        remediated_isolation_score,
        total_closed_loop_actions: adaptation.actions_triggered.len() as u64,
        backpressure_signals_sent: backpressures.len(),
        urllc_remediated_latency_ns: urllc_remediated,
        closed_loop_success,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nominal_sla_evaluation() {
        let mut synth = MultiNodeSlaSynthesizer::new(1);
        synth.ingest_telemetry(MultiNodeSliceTelemetryRecord {
            node_id: 1,
            timestamp_ns: 1000,
            subpath_id: 10,
            slice_class: FlowSliceClass::UltraLowLatency,
            packets_transmitted: 5000,
            packets_lost: 0,
            bytes_transmitted: 600000,
            avg_rtt_ns: 1_500_000,
            p99_rtt_ns: 2_000_000,
            jitter_ns: 200_000,
            queuing_delay_ns: 50_000,
            active_flows: 2,
            allocated_bandwidth_bps: 10_000_000,
        });

        let eval = synth.evaluate_node_sla(1, FlowSliceClass::UltraLowLatency);
        assert!(eval.sla_met);
        assert!((eval.compliance_ratio - 1.0).abs() < f64::EPSILON);
        assert_eq!(eval.violating_samples, 0);
    }

    #[test]
    fn test_e2e_path_sla_audit() {
        let mut synth = MultiNodeSlaSynthesizer::new(1);
        // Node 1 hop
        synth.ingest_telemetry(MultiNodeSliceTelemetryRecord {
            node_id: 1,
            timestamp_ns: 1000,
            subpath_id: 10,
            slice_class: FlowSliceClass::MissionCritical,
            packets_transmitted: 2000,
            packets_lost: 0,
            bytes_transmitted: 300000,
            avg_rtt_ns: 4_000_000,
            p99_rtt_ns: 6_000_000,
            jitter_ns: 500_000,
            queuing_delay_ns: 100_000,
            active_flows: 4,
            allocated_bandwidth_bps: 20_000_000,
        });

        // Node 2 hop
        synth.ingest_telemetry(MultiNodeSliceTelemetryRecord {
            node_id: 2,
            timestamp_ns: 1000,
            subpath_id: 20,
            slice_class: FlowSliceClass::MissionCritical,
            packets_transmitted: 2000,
            packets_lost: 0,
            bytes_transmitted: 300000,
            avg_rtt_ns: 6_000_000,
            p99_rtt_ns: 8_000_000,
            jitter_ns: 800_000,
            queuing_delay_ns: 200_000,
            active_flows: 4,
            allocated_bandwidth_bps: 20_000_000,
        });

        let audit =
            synth.evaluate_e2e_path_sla(FlowSliceClass::MissionCritical, &[(1, 10), (2, 20)]);
        assert!(audit.e2e_sla_compliant);
        assert_eq!(audit.cumulative_latency_ns, 10_000_000);
        assert_eq!(audit.bottleneck_node_id, 2);
        assert_eq!(audit.bottleneck_subpath_id, 20);
    }

    #[test]
    fn test_inter_slice_interference_detection() {
        let mut synth = MultiNodeSlaSynthesizer::new(1);

        // Victim URLLC on Node 1, Subpath 10
        synth.ingest_telemetry(MultiNodeSliceTelemetryRecord {
            node_id: 1,
            timestamp_ns: 2000,
            subpath_id: 10,
            slice_class: FlowSliceClass::UltraLowLatency,
            packets_transmitted: 1000,
            packets_lost: 5,
            bytes_transmitted: 150000,
            avg_rtt_ns: 8_000_000,
            p99_rtt_ns: 12_000_000,
            jitter_ns: 3_000_000,        // > 1ms SLA
            queuing_delay_ns: 4_000_000, // severe queuing delay
            active_flows: 2,
            allocated_bandwidth_bps: 5_000_000,
        });

        // Aggressor eMBB sharing same link
        synth.ingest_telemetry(MultiNodeSliceTelemetryRecord {
            node_id: 1,
            timestamp_ns: 2000,
            subpath_id: 10,
            slice_class: FlowSliceClass::HighThroughput,
            packets_transmitted: 50_000,
            packets_lost: 20,
            bytes_transmitted: 50_000_000,
            avg_rtt_ns: 40_000_000,
            p99_rtt_ns: 60_000_000,
            jitter_ns: 10_000_000,
            queuing_delay_ns: 15_000_000,
            active_flows: 30,
            allocated_bandwidth_bps: 95_000_000, // dominates 95% of bandwidth
        });

        let interferences = synth.detect_inter_slice_interference();
        assert!(!interferences.is_empty());
        assert_eq!(
            interferences[0].victim_slice,
            FlowSliceClass::UltraLowLatency
        );
        assert_eq!(
            interferences[0].aggressor_slice,
            FlowSliceClass::HighThroughput
        );
        assert!(interferences[0].interference_score > 0.4);
    }

    #[test]
    fn test_closed_loop_adaptation_actions() {
        let mut synth = MultiNodeSlaSynthesizer::new(1);

        // Add alternate subpath on node 1 so isolation can find candidate
        synth.ingest_telemetry(MultiNodeSliceTelemetryRecord {
            node_id: 1,
            timestamp_ns: 1000,
            subpath_id: 11,
            slice_class: FlowSliceClass::BestEffort,
            packets_transmitted: 100,
            packets_lost: 0,
            bytes_transmitted: 10000,
            avg_rtt_ns: 5_000_000,
            p99_rtt_ns: 6_000_000,
            jitter_ns: 500_000,
            queuing_delay_ns: 100_000,
            active_flows: 1,
            allocated_bandwidth_bps: 10_000_000,
        });

        // Contested subpath 10
        synth.ingest_telemetry(MultiNodeSliceTelemetryRecord {
            node_id: 1,
            timestamp_ns: 2000,
            subpath_id: 10,
            slice_class: FlowSliceClass::UltraLowLatency,
            packets_transmitted: 1000,
            packets_lost: 5,
            bytes_transmitted: 150000,
            avg_rtt_ns: 9_000_000,
            p99_rtt_ns: 14_000_000,
            jitter_ns: 2_500_000,
            queuing_delay_ns: 5_000_000,
            active_flows: 2,
            allocated_bandwidth_bps: 5_000_000,
        });

        synth.ingest_telemetry(MultiNodeSliceTelemetryRecord {
            node_id: 1,
            timestamp_ns: 2000,
            subpath_id: 10,
            slice_class: FlowSliceClass::HighThroughput,
            packets_transmitted: 50_000,
            packets_lost: 10,
            bytes_transmitted: 50_000_000,
            avg_rtt_ns: 50_000_000,
            p99_rtt_ns: 70_000_000,
            jitter_ns: 12_000_000,
            queuing_delay_ns: 18_000_000,
            active_flows: 40,
            allocated_bandwidth_bps: 95_000_000,
        });

        let adaptation = synth.evaluate_and_adapt(10);
        assert!(!adaptation.actions_triggered.is_empty());
        assert!(synth.metrics.total_closed_loop_actions > 0);
        assert!(synth.metrics.total_throttles_enacted > 0);
        assert!(synth.metrics.total_reservations_enacted > 0);
        assert_eq!(synth.active_headroom_reservation(1, 10), 30);

        let backpressures = synth.drain_backpressure_signals();
        assert!(!backpressures.is_empty());
        assert_eq!(synth.drain_backpressure_signals().len(), 0);
    }

    #[test]
    fn test_multi_node_sla_benchmark_execution() {
        let report = run_multi_node_sla_benchmark();
        assert!(report.closed_loop_success);
        assert_eq!(report.total_nodes, 4);
        assert_eq!(report.total_subpaths, 2);
        assert!(report.total_closed_loop_actions > 0);
        assert!(report.backpressure_signals_sent > 0);
        assert!(report.urllc_remediated_latency_ns <= 5_000_000);
        assert!(report.remediated_compliance_ratio >= report.congested_compliance_ratio);
        assert!(report.remediated_isolation_score >= report.congested_isolation_score);
    }

    #[test]
    fn test_prometheus_metrics_export() {
        let synth = MultiNodeSlaSynthesizer::new(3);
        let metrics_text = synth.export_prometheus_metrics();
        assert!(metrics_text.contains("ifa_slice_isolation_score{node=\"3\"}"));
        assert!(metrics_text.contains("ifa_slice_sla_compliance_ratio{node=\"3\"}"));
        assert!(metrics_text.contains("ifa_slice_closed_loop_actions_total{node=\"3\"}"));
        assert!(metrics_text.contains("ifa_slice_backpressure_signals_total{node=\"3\"}"));
    }
}

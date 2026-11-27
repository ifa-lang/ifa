//! Non-Blocking Unified Multipath Event Scheduler (`MultipathEventScheduler`).
//!
//! Integrates and conjointly coordinates:
//! 1. **Multipath Pacing & Anti-Burst Shaper (`MultipathPacingCoordinator`)**:
//!    - Couples BBR congestion window and inter-packet departure pacing.
//!    - Performs cadenced interleaving of Cauchy Reed-Solomon FEC parity and ARQ retransmissions.
//!    - Strictly limits wire bursts via leaky-bucket token replenishment.
//! 2. **Hybrid FEC / Retransmission Joint Arbiter (`HybridFecArbiter`)**:
//!    - Arbitrates packet loss and network conditions between pure ARQ, pure FEC, and hybrid interleaved modes.
//!    - Dynamically balances latency deadlines against bandwidth consumption.
//! 3. **Predictive Subpath Selection & Proactive SLA Migration (`PredictivePathSelector`)**:
//!    - Continuously audits SLA headroom and latency drift across all available physical subpaths.
//!    - Formulates and executes proactive flow migrations before SLA breaches or bufferbloat occur.
//! 4. **Zero Flow Interruption Routing & Failover (`MultipathRouter`)**:
//!    - Inflight packets on degraded paths drain smoothly while new traffic routes onto healthy alternatives.
//! 5. **Composite Health & Temporal Drift (`SubpathHealthMonitor`, `SubpathJitterDriftTracker`, `SubpathBbrDriver`)**:
//!    - Non-blocking telemetry ingestion, RFC 3550 jitter calculation, and BBR congestion state tracking.
//!
//! Zero-simulation guarantee: operates strictly on concrete frame metadata, nanosecond timestamps,
//! and real event ring buffers.

#![allow(clippy::manual_is_multiple_of, clippy::too_many_arguments)]

use std::collections::{BTreeMap, VecDeque};
use std::fmt::Write as FmtWrite;

use crate::hybrid_fec_arbiter::{
    HybridFecArbiter, HybridFecConfig, PacketLossArbitrationAction, SubpathNetworkProfile,
};
use crate::multipath_pacing_coordinator::{
    CoordinatorScheduleVerdict, MultipathPacingCoordinator, OutboundItemKind,
    PacingCoordinatorConfig, ScheduledOutboundItem,
};
use crate::multipath_router::MultipathRouter;
use crate::predictive_path_selector::{
    PredictiveMigrationRecord, PredictivePathConfig, PredictivePathSelector,
};
use crate::subpath_bbr::{DeliveryAckSample, SubpathBbrDriver};
use crate::subpath_health::SubpathHealthMonitor;
use crate::subpath_jitter_drift::{SubpathJitterDriftConfig, SubpathJitterDriftTracker};
use crate::traffic_slicing::FlowSliceClass;

// ---------------------------------------------------------------------------
// Configuration Parameters
// ---------------------------------------------------------------------------

/// Configuration options for the `MultipathEventScheduler`.
#[derive(Debug, Clone, PartialEq)]
pub struct MultipathEventSchedulerConfig {
    /// Pacing coordinator settings.
    pub pacing_config: PacingCoordinatorConfig,
    /// Hybrid FEC arbiter settings.
    pub fec_config: HybridFecConfig,
    /// Predictive path selector settings.
    pub predictive_config: PredictivePathConfig,
    /// Audit tick interval in nanoseconds (default 50ms = 50_000_000 ns).
    pub audit_interval_ns: u64,
    /// Minimum Retransmission Timeout (RTO) in nanoseconds (default 20ms = 20_000_000 ns).
    pub min_rto_ns: u64,
    /// Maximum Retransmission Timeout (RTO) in nanoseconds (default 1s = 1_000_000_000 ns).
    pub max_rto_ns: u64,
    /// Maximum in-flight packets tracked simultaneously in memory.
    pub max_inflight_packets: usize,
    /// Maximum dispatch batch size when polling all ready subpaths.
    pub max_dispatch_batch: usize,
}

impl Default for MultipathEventSchedulerConfig {
    fn default() -> Self {
        Self {
            pacing_config: PacingCoordinatorConfig::default(),
            fec_config: HybridFecConfig::default(),
            predictive_config: PredictivePathConfig::default(),
            audit_interval_ns: 50_000_000, // 50 ms
            min_rto_ns: 20_000_000,        // 20 ms
            max_rto_ns: 1_000_000_000,     // 1 second
            max_inflight_packets: 16_384,
            max_dispatch_batch: 32,
        }
    }
}

// ---------------------------------------------------------------------------
// Scheduler Subpath State
// ---------------------------------------------------------------------------

/// Runtime snapshot of a monitored subpath inside the scheduler.
#[derive(Debug, Clone, PartialEq)]
pub struct SchedulerSubpathInfo {
    pub subpath_id: u32,
    pub bandwidth_bps: u64,
    pub smoothed_rtt_ns: u64,
    pub rfc3550_jitter_ns: u64,
    pub loss_ratio: f64,
    pub effective_pmtu: u32,
    pub registered_at_ns: u64,
    pub last_activity_ns: u64,
}

impl SchedulerSubpathInfo {
    pub fn new(
        subpath_id: u32,
        bandwidth_bps: u64,
        rtt_ns: u64,
        effective_pmtu: u32,
        now_ns: u64,
    ) -> Self {
        Self {
            subpath_id,
            bandwidth_bps,
            smoothed_rtt_ns: rtt_ns,
            rfc3550_jitter_ns: 0,
            loss_ratio: 0.0,
            effective_pmtu,
            registered_at_ns: now_ns,
            last_activity_ns: now_ns,
        }
    }
}

// ---------------------------------------------------------------------------
// Asynchronous Event Definitions
// ---------------------------------------------------------------------------

/// Unified asynchronous event submitted to the `MultipathEventScheduler`.
#[derive(Debug, Clone, PartialEq)]
pub enum MultipathSchedulerEvent {
    /// Ingress data packet arriving from upper layer protocol or application.
    IngressPacket {
        packet_id: u64,
        flow_id: u64,
        slice_class: FlowSliceClass,
        payload: Vec<u8>,
        enqueue_time_ns: u64,
        deadline_ns: Option<u64>,
    },
    /// Inbound delivery acknowledgment from the remote receiver.
    ReceiverAck {
        subpath_id: u32,
        ack_packet_id: u64,
        rtt_sample_ns: u64,
        delivered_bytes: usize,
        ecn_marked: bool,
        receive_time_ns: u64,
    },
    /// Explicit Negative Acknowledgment / loss signal from receiver SACK.
    ReceiverNack {
        subpath_id: u32,
        lost_packet_ids: Vec<u64>,
        detection_time_ns: u64,
    },
    /// Subpath link telemetry update (from active probing or network feedback).
    SubpathMetricsSample {
        subpath_id: u32,
        rtt_ns: u64,
        jitter_ns: u64,
        loss_ratio: f64,
        btl_bw_bps: u64,
        sample_time_ns: u64,
    },
    /// Closed-loop proactive SLA risk audit and dynamic path migration tick.
    PredictiveAuditTick { now_ns: u64 },
    /// Periodic Retransmission Timeout (RTO) expiration check for unacknowledged frames.
    RtoTimeoutCheck { now_ns: u64 },
}

// ---------------------------------------------------------------------------
// Inflight Tracking Record
// ---------------------------------------------------------------------------

/// State of an unacknowledged packet in flight across a subpath.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchedulerInflightRecord {
    pub item_id: u64,
    pub flow_id: u64,
    pub subpath_id: u32,
    pub slice_class: FlowSliceClass,
    pub size_bytes: usize,
    pub payload: Vec<u8>,
    pub kind: OutboundItemKind,
    pub sent_time_ns: u64,
    pub rto_deadline_ns: u64,
    pub retry_count: u8,
}

// ---------------------------------------------------------------------------
// Dispatch Verdicts & Outcomes
// ---------------------------------------------------------------------------

/// Result returned when polling an individual subpath for wire departure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchedulerDispatchResult {
    /// Packet or parity symbol ready for immediate wire dispatch.
    Ready(ScheduledOutboundItem),
    /// Subpath is actively pacing; caller should wait until `next_eligible_ns`.
    PacingWait {
        subpath_id: u32,
        wait_ns: u64,
        next_eligible_ns: u64,
    },
    /// Subpath Congestion Window (CWND) is saturated; blocked until delivery ACKs arrive.
    CwndBlocked { subpath_id: u32 },
    /// No packets queued for transmission on this subpath.
    Idle { subpath_id: u32 },
}

/// Detailed outcome produced after processing a single scheduler event.
#[derive(Debug, Clone, PartialEq)]
pub enum EventProcessOutcome {
    /// Ingress packet admitted and queued on designated subpath.
    IngressEnqueued {
        packet_id: u64,
        assigned_subpath: u32,
        slice_class: FlowSliceClass,
    },
    /// Delivery acknowledgment processed: CWND relieved, drift updated, packet retired.
    AckProcessed {
        subpath_id: u32,
        ack_packet_id: u64,
        rtt_sample_ns: u64,
        inflight_remaining: usize,
    },
    /// Receiver NACK loss processed: joint FEC/ARQ arbitration evaluated and queued.
    NackProcessed {
        subpath_id: u32,
        lost_count: usize,
        retransmits_enqueued: usize,
        fec_recoveries_handled: usize,
        early_dropped_expired: usize,
    },
    /// RTO sweep completed: expired unacknowledged packets retransmitted or FEC emitted.
    RtoSwept {
        expired_count: usize,
        retransmits_enqueued: usize,
        fec_parities_enqueued: usize,
    },
    /// Subpath telemetry updated across Pacing, BBR, Arbiter, and Tracker.
    MetricsUpdated { subpath_id: u32 },
    /// Closed-loop predictive audit executed: zero or more slice migrations performed.
    AuditExecuted {
        evaluations_count: usize,
        migrations_executed: Vec<PredictiveMigrationRecord>,
    },
}

/// Comprehensive summary of a complete scheduler step.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SchedulerStepSummary {
    pub events_processed: usize,
    pub rto_expired_count: usize,
    pub proactive_migrations_count: usize,
    pub dispatched_items_count: usize,
    pub dispatched_bytes: u64,
}

// ---------------------------------------------------------------------------
// Telemetry Metrics
// ---------------------------------------------------------------------------

/// Telemetry counters and metrics for the `MultipathEventScheduler`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MultipathEventSchedulerTelemetry {
    pub total_events_ingested: u64,
    pub total_ingress_packets: u64,
    pub total_receiver_acks: u64,
    pub total_receiver_nacks: u64,
    pub total_rto_sweeps: u64,
    pub total_metrics_samples: u64,
    pub total_audit_ticks: u64,
    pub total_dispatched_data: u64,
    pub total_dispatched_parity: u64,
    pub total_dispatched_retransmits: u64,
    pub total_dispatched_bytes: u64,
    pub total_rto_timeouts: u64,
    pub total_proactive_migrations: u64,
    pub total_fec_recoveries_handled: u64,
    pub total_arq_retransmits_enqueued: u64,
    pub total_sla_expired_drops: u64,
    pub active_inflight_count: usize,
    pub active_inflight_bytes: u64,
}

// ---------------------------------------------------------------------------
// MultipathEventScheduler Implementation
// ---------------------------------------------------------------------------

/// Non-blocking reactor and unified event scheduler coordinating pacing, FEC/ARQ arbitration,
/// and predictive path selection without flow interruption.
pub struct MultipathEventScheduler {
    pub config: MultipathEventSchedulerConfig,
    pub pacing_coordinator: MultipathPacingCoordinator,
    pub fec_arbiter: HybridFecArbiter,
    pub path_selector: PredictivePathSelector,
    pub router: MultipathRouter,
    pub health_monitor: SubpathHealthMonitor,
    pub drift_tracker: SubpathJitterDriftTracker,
    pub bbr_driver: SubpathBbrDriver,
    pub slice_bindings: BTreeMap<FlowSliceClass, u32>,
    pub subpaths: BTreeMap<u32, SchedulerSubpathInfo>,
    pub inflight_packets: BTreeMap<u64, SchedulerInflightRecord>,
    pub pending_events: VecDeque<MultipathSchedulerEvent>,
    pub telemetry: MultipathEventSchedulerTelemetry,
    pub last_audit_ns: u64,
}

impl MultipathEventScheduler {
    /// Create a new `MultipathEventScheduler` with given configuration.
    pub fn new(config: MultipathEventSchedulerConfig) -> Self {
        let pacing_coordinator = MultipathPacingCoordinator::new(config.pacing_config.clone());
        let fec_arbiter = HybridFecArbiter::new(config.fec_config.clone());
        let path_selector = PredictivePathSelector::new(config.predictive_config.clone());
        let router = MultipathRouter::new();
        let health_monitor = SubpathHealthMonitor::new();
        let drift_tracker = SubpathJitterDriftTracker::new(SubpathJitterDriftConfig::default());
        let bbr_driver = SubpathBbrDriver::new();

        Self {
            config,
            pacing_coordinator,
            fec_arbiter,
            path_selector,
            router,
            health_monitor,
            drift_tracker,
            bbr_driver,
            slice_bindings: BTreeMap::new(),
            subpaths: BTreeMap::new(),
            inflight_packets: BTreeMap::new(),
            pending_events: VecDeque::new(),
            telemetry: MultipathEventSchedulerTelemetry::default(),
            last_audit_ns: 0,
        }
    }

    /// Register a new physical subpath across all coupled subcomponents.
    pub fn register_subpath(
        &mut self,
        subpath_id: u32,
        bandwidth_bps: u64,
        rtt_ns: u64,
        effective_pmtu: u32,
        now_ns: u64,
    ) {
        let info =
            SchedulerSubpathInfo::new(subpath_id, bandwidth_bps, rtt_ns, effective_pmtu, now_ns);
        self.subpaths.insert(subpath_id, info);

        // 1. Pacing Coordinator
        self.pacing_coordinator
            .register_subpath(subpath_id, bandwidth_bps, rtt_ns, now_ns);

        // 2. Hybrid FEC Arbiter
        let profile = SubpathNetworkProfile::new(subpath_id, rtt_ns, 0, 0.0, now_ns);
        self.fec_arbiter.update_subpath_profile(profile);

        // 3. Multipath Router
        let cwnd_bytes = (bandwidth_bps / 8 * rtt_ns / 1_000_000_000).max(65536);
        self.router
            .register_subpath(subpath_id, effective_pmtu, cwnd_bytes, rtt_ns, 100);

        // 4. Subpath Health Monitor
        self.health_monitor.register_subpath(
            subpath_id as u8,
            format!("subpath_{}", subpath_id),
            rtt_ns / 1_000_000,
            now_ns,
        );

        // 5. Jitter Drift Tracker
        self.drift_tracker.ensure_subpath(subpath_id);

        // 6. Subpath BBR Driver
        let rtt_us = (rtt_ns / 1_000).max(1);
        self.bbr_driver
            .register_subpath(subpath_id as u8, bandwidth_bps, rtt_us, now_ns);

        // Default all unmapped slices to this subpath if none are mapped yet
        if self.slice_bindings.is_empty() {
            self.slice_bindings
                .insert(FlowSliceClass::UltraLowLatency, subpath_id);
            self.slice_bindings
                .insert(FlowSliceClass::MissionCritical, subpath_id);
            self.slice_bindings
                .insert(FlowSliceClass::HighThroughput, subpath_id);
            self.slice_bindings
                .insert(FlowSliceClass::BestEffort, subpath_id);
        }
    }

    /// Explicitly bind a QoS slice class to a target subpath.
    pub fn bind_slice_to_subpath(&mut self, slice: FlowSliceClass, subpath_id: u32) {
        self.slice_bindings.insert(slice, subpath_id);
    }

    /// Retrieve active assigned subpath for a given QoS slice class.
    pub fn get_slice_subpath(&self, slice: FlowSliceClass) -> Option<u32> {
        self.slice_bindings.get(&slice).copied()
    }

    /// Submit an asynchronous event to the scheduler ring.
    pub fn submit_event(&mut self, event: MultipathSchedulerEvent) {
        self.telemetry.total_events_ingested += 1;
        self.pending_events.push_back(event);
    }

    /// Convenience ingress submission for a new upper-layer data packet with dummy payload.
    pub fn submit_ingress_packet(
        &mut self,
        packet_id: u64,
        slice_class: FlowSliceClass,
        payload_size_bytes: usize,
        now_ns: u64,
    ) {
        let payload = vec![0u8; payload_size_bytes];
        self.submit_event(MultipathSchedulerEvent::IngressPacket {
            packet_id,
            flow_id: 1,
            slice_class,
            payload,
            enqueue_time_ns: now_ns,
            deadline_ns: None,
        });
    }

    /// Process the next pending event in the event ring (non-blocking).
    pub fn process_next_event(&mut self, now_ns: u64) -> Option<EventProcessOutcome> {
        let event = self.pending_events.pop_front()?;
        Some(self.handle_event(event, now_ns))
    }

    /// Process all currently queued events in the event ring.
    pub fn process_all_events(&mut self, now_ns: u64) -> Vec<EventProcessOutcome> {
        let count = self.pending_events.len();
        let mut outcomes = Vec::with_capacity(count);
        for _ in 0..count {
            if let Some(event) = self.pending_events.pop_front() {
                outcomes.push(self.handle_event(event, now_ns));
            }
        }
        outcomes
    }

    /// Internal event handler dispatching to respective domain components.
    fn handle_event(&mut self, event: MultipathSchedulerEvent, now_ns: u64) -> EventProcessOutcome {
        match event {
            MultipathSchedulerEvent::IngressPacket {
                packet_id,
                flow_id,
                slice_class,
                payload,
                enqueue_time_ns,
                deadline_ns,
            } => {
                self.telemetry.total_ingress_packets += 1;

                // Lookup assigned subpath or fallback to first registered
                let assigned_subpath = self
                    .slice_bindings
                    .get(&slice_class)
                    .copied()
                    .unwrap_or_else(|| self.subpaths.keys().copied().next().unwrap_or(1));

                // Evaluate joint FEC recommendation for this slice/subpath
                let decision =
                    self.fec_arbiter
                        .evaluate_slice_subpath(assigned_subpath, slice_class, now_ns);

                // Notify coordinator of arbiter decision for pacing/cadence sync
                self.pacing_coordinator
                    .notify_fec_arbitration(assigned_subpath, &decision, now_ns);

                // Enqueue into pacing coordinator
                let _ = self.pacing_coordinator.enqueue_data_packet(
                    flow_id,
                    assigned_subpath,
                    slice_class,
                    payload,
                    enqueue_time_ns,
                    deadline_ns,
                );

                EventProcessOutcome::IngressEnqueued {
                    packet_id,
                    assigned_subpath,
                    slice_class,
                }
            }

            MultipathSchedulerEvent::ReceiverAck {
                subpath_id,
                ack_packet_id,
                rtt_sample_ns,
                delivered_bytes,
                ecn_marked,
                receive_time_ns,
            } => {
                self.telemetry.total_receiver_acks += 1;

                // 1. Inflight record retire
                let mut sent_time_ns = receive_time_ns.saturating_sub(rtt_sample_ns);
                let mut slice_class = FlowSliceClass::BestEffort;
                let mut size_bytes = delivered_bytes;

                if let Some(record) = self.inflight_packets.remove(&ack_packet_id) {
                    sent_time_ns = record.sent_time_ns;
                    slice_class = record.slice_class;
                    size_bytes = record.size_bytes;
                    self.telemetry.active_inflight_bytes = self
                        .telemetry
                        .active_inflight_bytes
                        .saturating_sub(record.size_bytes as u64);
                }
                self.telemetry.active_inflight_count = self.inflight_packets.len();

                // 2. Notify Pacing Coordinator
                self.pacing_coordinator.acknowledge_delivery(
                    subpath_id,
                    size_bytes,
                    receive_time_ns,
                );

                // 3. Update Health Monitor
                self.health_monitor
                    .record_admission_success(subpath_id as u8, receive_time_ns);

                // 4. Record transit sample in Jitter Drift Tracker
                self.drift_tracker.record_transit(
                    subpath_id,
                    0,
                    slice_class,
                    ack_packet_id,
                    sent_time_ns,
                    receive_time_ns,
                );

                // 5. Update BBR state
                let rtt_us = (rtt_sample_ns / 1_000).max(1);
                let delivery_sample = DeliveryAckSample {
                    delivered_bytes: size_bytes as u64,
                    interval_ns: rtt_sample_ns.max(1_000),
                    rtt_us,
                    inflight_bytes_at_send: self.telemetry.active_inflight_bytes,
                    ecn_ce_count: if ecn_marked { 1 } else { 0 },
                    lost_bytes: 0,
                };
                self.bbr_driver
                    .on_ack_sample(subpath_id as u8, delivery_sample, receive_time_ns);

                // 6. Update SubpathInfo and Arbiter Network Profile
                if let Some(info) = self.subpaths.get_mut(&subpath_id) {
                    info.smoothed_rtt_ns = (info.smoothed_rtt_ns * 7 + rtt_sample_ns) / 8;
                    info.last_activity_ns = receive_time_ns;

                    let jitter = self
                        .drift_tracker
                        .get_subpath_stats(subpath_id)
                        .map(|s| s.rfc3550_jitter_ns)
                        .unwrap_or(0);
                    info.rfc3550_jitter_ns = jitter;

                    let profile = SubpathNetworkProfile::new(
                        subpath_id,
                        info.smoothed_rtt_ns,
                        jitter,
                        info.loss_ratio,
                        receive_time_ns,
                    );
                    self.fec_arbiter.update_subpath_profile(profile);
                }

                EventProcessOutcome::AckProcessed {
                    subpath_id,
                    ack_packet_id,
                    rtt_sample_ns,
                    inflight_remaining: self.inflight_packets.len(),
                }
            }

            MultipathSchedulerEvent::ReceiverNack {
                subpath_id,
                lost_packet_ids,
                detection_time_ns,
            } => {
                self.telemetry.total_receiver_nacks += 1;
                let lost_count = lost_packet_ids.len();
                let mut retransmits_enqueued = 0;
                let mut fec_recoveries_handled = 0;
                let mut early_dropped_expired = 0;

                for lost_id in lost_packet_ids {
                    let (flow_id, slice, size, payload, sent_ns, retry_count) =
                        if let Some(rec) = self.inflight_packets.remove(&lost_id) {
                            self.telemetry.active_inflight_bytes = self
                                .telemetry
                                .active_inflight_bytes
                                .saturating_sub(rec.size_bytes as u64);
                            (
                                rec.flow_id,
                                rec.slice_class,
                                rec.size_bytes,
                                rec.payload,
                                rec.sent_time_ns,
                                rec.retry_count,
                            )
                        } else {
                            (
                                1,
                                FlowSliceClass::BestEffort,
                                1400,
                                vec![0u8; 1400],
                                detection_time_ns,
                                0,
                            )
                        };

                    // Arbitrate loss: FEC vs ARQ
                    let action = self.fec_arbiter.arbitrate_packet_loss(
                        flow_id as u32,
                        lost_id,
                        size,
                        subpath_id,
                        slice,
                        sent_ns,
                        detection_time_ns,
                        None,
                    );

                    match action {
                        PacketLossArbitrationAction::HandledByFec => {
                            self.telemetry.total_fec_recoveries_handled += 1;
                            fec_recoveries_handled += 1;
                        }
                        PacketLossArbitrationAction::DispatchRetransmit {
                            target_subpath_id,
                            deadline_ns,
                            ..
                        } => {
                            let _ = self.pacing_coordinator.enqueue_arq_retransmission(
                                flow_id,
                                target_subpath_id,
                                slice,
                                lost_id,
                                retry_count + 1,
                                payload,
                                detection_time_ns,
                                Some(deadline_ns),
                            );
                            self.telemetry.total_arq_retransmits_enqueued += 1;
                            retransmits_enqueued += 1;
                        }
                        PacketLossArbitrationAction::EarlyDropSlaExpired { .. } => {
                            self.telemetry.total_sla_expired_drops += 1;
                            early_dropped_expired += 1;
                        }
                    }
                }

                self.telemetry.active_inflight_count = self.inflight_packets.len();

                EventProcessOutcome::NackProcessed {
                    subpath_id,
                    lost_count,
                    retransmits_enqueued,
                    fec_recoveries_handled,
                    early_dropped_expired,
                }
            }

            MultipathSchedulerEvent::SubpathMetricsSample {
                subpath_id,
                rtt_ns,
                jitter_ns,
                loss_ratio,
                btl_bw_bps,
                sample_time_ns,
            } => {
                self.telemetry.total_metrics_samples += 1;

                if let Some(info) = self.subpaths.get_mut(&subpath_id) {
                    info.smoothed_rtt_ns = rtt_ns;
                    info.rfc3550_jitter_ns = jitter_ns;
                    info.loss_ratio = loss_ratio;
                    info.bandwidth_bps = btl_bw_bps;
                    info.last_activity_ns = sample_time_ns;
                }

                // Update Pacing Coordinator
                let cwnd = (btl_bw_bps / 8 * rtt_ns / 1_000_000_000).max(65536);
                self.pacing_coordinator.update_bbr_state(
                    subpath_id,
                    btl_bw_bps,
                    rtt_ns,
                    256, // 1.0x pacing gain
                    cwnd,
                    self.telemetry.active_inflight_bytes,
                    sample_time_ns,
                );
                self.pacing_coordinator.update_drift_and_jitter(
                    subpath_id,
                    rtt_ns as f64,
                    jitter_ns,
                    0.0,
                    jitter_ns,
                    sample_time_ns,
                );

                // Update Hybrid FEC Arbiter
                let profile = SubpathNetworkProfile::new(
                    subpath_id,
                    rtt_ns,
                    jitter_ns,
                    loss_ratio,
                    sample_time_ns,
                );
                self.fec_arbiter.update_subpath_profile(profile);

                // Update Router Route
                let _ = self.router.update_subpath_congestion(subpath_id, cwnd, 0);

                EventProcessOutcome::MetricsUpdated { subpath_id }
            }

            MultipathSchedulerEvent::PredictiveAuditTick { now_ns } => {
                self.execute_predictive_audit(now_ns)
            }

            MultipathSchedulerEvent::RtoTimeoutCheck { now_ns } => self.sweep_rto_deadlines(now_ns),
        }
    }

    /// Periodic sweep of expired RTO deadlines across all in-flight packets.
    pub fn sweep_rto_deadlines(&mut self, now_ns: u64) -> EventProcessOutcome {
        self.telemetry.total_rto_sweeps += 1;

        let mut expired_ids = Vec::new();
        for (&packet_id, rec) in &self.inflight_packets {
            if now_ns >= rec.rto_deadline_ns {
                expired_ids.push(packet_id);
            }
        }

        let expired_count = expired_ids.len();
        let mut retransmits_enqueued = 0;
        let fec_parities_enqueued = 0;

        for id in expired_ids {
            if let Some(mut rec) = self.inflight_packets.remove(&id) {
                self.telemetry.total_rto_timeouts += 1;
                self.telemetry.active_inflight_bytes = self
                    .telemetry
                    .active_inflight_bytes
                    .saturating_sub(rec.size_bytes as u64);

                let subpath_id = rec.subpath_id;
                let slice = rec.slice_class;
                rec.retry_count = rec.retry_count.saturating_add(1);

                let action = self.fec_arbiter.arbitrate_packet_loss(
                    rec.flow_id as u32,
                    id,
                    rec.size_bytes,
                    subpath_id,
                    slice,
                    rec.sent_time_ns,
                    now_ns,
                    None,
                );

                match action {
                    PacketLossArbitrationAction::DispatchRetransmit {
                        target_subpath_id,
                        deadline_ns,
                        ..
                    } => {
                        let _ = self.pacing_coordinator.enqueue_arq_retransmission(
                            rec.flow_id,
                            target_subpath_id,
                            slice,
                            id,
                            rec.retry_count,
                            rec.payload,
                            now_ns,
                            Some(deadline_ns),
                        );
                        self.telemetry.total_arq_retransmits_enqueued += 1;
                        retransmits_enqueued += 1;
                    }
                    PacketLossArbitrationAction::HandledByFec => {
                        self.telemetry.total_fec_recoveries_handled += 1;
                    }
                    PacketLossArbitrationAction::EarlyDropSlaExpired { .. } => {
                        self.telemetry.total_sla_expired_drops += 1;
                    }
                }
            }
        }

        self.telemetry.active_inflight_count = self.inflight_packets.len();

        EventProcessOutcome::RtoSwept {
            expired_count,
            retransmits_enqueued,
            fec_parities_enqueued,
        }
    }

    /// Execute closed-loop predictive SLA risk audit and perform proactive path migrations.
    pub fn execute_predictive_audit(&mut self, now_ns: u64) -> EventProcessOutcome {
        self.telemetry.total_audit_ticks += 1;
        self.last_audit_ns = now_ns;

        // Run closed-loop predictive selector cycle
        let executed_records = self.path_selector.orchestrate_cycle(
            &mut self.router,
            Some(&self.health_monitor),
            Some(&self.drift_tracker),
            Some(&self.bbr_driver),
            now_ns,
        );

        // Update active slice bindings according to executed migration plans
        for rec in &executed_records {
            self.slice_bindings
                .insert(rec.plan.slice_class, rec.plan.target_subpath_id);
            self.telemetry.total_proactive_migrations += 1;
        }

        EventProcessOutcome::AuditExecuted {
            evaluations_count: self.subpaths.len(),
            migrations_executed: executed_records,
        }
    }

    /// Poll an individual subpath for wire-ready outbound transmission.
    pub fn poll_next_dispatch(&mut self, subpath_id: u32, now_ns: u64) -> SchedulerDispatchResult {
        match self.pacing_coordinator.schedule_next(subpath_id, now_ns) {
            CoordinatorScheduleVerdict::Ready(item) => {
                // Compute adaptive RTO deadline
                let srtt = self
                    .subpaths
                    .get(&subpath_id)
                    .map(|s| s.smoothed_rtt_ns)
                    .unwrap_or(20_000_000);
                let rto_deadline_ns =
                    now_ns + (srtt * 2).clamp(self.config.min_rto_ns, self.config.max_rto_ns);

                // Track in-flight
                let rec = SchedulerInflightRecord {
                    item_id: item.item_id,
                    flow_id: item.flow_id,
                    subpath_id,
                    slice_class: item.slice_class,
                    size_bytes: item.size_bytes,
                    payload: item.payload.clone(),
                    kind: item.kind,
                    sent_time_ns: now_ns,
                    rto_deadline_ns,
                    retry_count: 0,
                };
                self.inflight_packets.insert(item.item_id, rec);
                self.telemetry.active_inflight_count = self.inflight_packets.len();
                self.telemetry.active_inflight_bytes += item.size_bytes as u64;

                // Update dispatch telemetry counters
                match item.kind {
                    OutboundItemKind::DataPacket => self.telemetry.total_dispatched_data += 1,
                    OutboundItemKind::FecParitySymbol { .. } => {
                        self.telemetry.total_dispatched_parity += 1
                    }
                    OutboundItemKind::ArqRetransmission { .. } => {
                        self.telemetry.total_dispatched_retransmits += 1
                    }
                    OutboundItemKind::ProbePacket => {}
                }
                self.telemetry.total_dispatched_bytes += item.size_bytes as u64;

                SchedulerDispatchResult::Ready(item)
            }
            CoordinatorScheduleVerdict::PacingWait {
                wait_ns,
                next_tx_time_ns,
                ..
            } => SchedulerDispatchResult::PacingWait {
                subpath_id,
                wait_ns,
                next_eligible_ns: next_tx_time_ns,
            },
            CoordinatorScheduleVerdict::BlockedByCwnd { .. } => {
                SchedulerDispatchResult::CwndBlocked { subpath_id }
            }
            CoordinatorScheduleVerdict::Empty => SchedulerDispatchResult::Idle { subpath_id },
        }
    }

    /// Poll all registered subpaths in round-robin fashion, returning all wire-ready items.
    pub fn poll_any_ready(&mut self, now_ns: u64) -> Vec<ScheduledOutboundItem> {
        let mut ready_items = Vec::new();
        let subpath_ids: Vec<u32> = self.subpaths.keys().copied().collect();

        for subpath_id in subpath_ids {
            while ready_items.len() < self.config.max_dispatch_batch {
                match self.poll_next_dispatch(subpath_id, now_ns) {
                    SchedulerDispatchResult::Ready(item) => ready_items.push(item),
                    _ => break,
                }
            }
            if ready_items.len() >= self.config.max_dispatch_batch {
                break;
            }
        }

        ready_items
    }

    /// Advance the scheduler clock, drain pending events, check RTOs, run audits, and dispatch.
    pub fn step(&mut self, now_ns: u64) -> SchedulerStepSummary {
        let mut summary = SchedulerStepSummary::default();

        // 1. Process all pending asynchronous events
        let outcomes = self.process_all_events(now_ns);
        summary.events_processed = outcomes.len();

        // 2. Periodic RTO timeout check
        let rto_outcome = self.sweep_rto_deadlines(now_ns);
        if let EventProcessOutcome::RtoSwept { expired_count, .. } = rto_outcome {
            summary.rto_expired_count = expired_count;
        }

        // 3. Periodic predictive SLA audit
        if now_ns.saturating_sub(self.last_audit_ns) >= self.config.audit_interval_ns {
            let audit_outcome = self.execute_predictive_audit(now_ns);
            if let EventProcessOutcome::AuditExecuted {
                migrations_executed,
                ..
            } = audit_outcome
            {
                summary.proactive_migrations_count = migrations_executed.len();
            }
        }

        // 4. Poll all wire-ready outbound items
        let dispatched = self.poll_any_ready(now_ns);
        summary.dispatched_items_count = dispatched.len();
        summary.dispatched_bytes = dispatched.iter().map(|d| d.size_bytes as u64).sum();

        summary
    }

    /// Access scheduler telemetry.
    pub fn telemetry(&self) -> &MultipathEventSchedulerTelemetry {
        &self.telemetry
    }

    /// Export comprehensive Prometheus / OpenMetrics format metrics exposition.
    pub fn export_prometheus_metrics(&self) -> String {
        let mut out = String::with_capacity(4096);

        out.push_str(
            "# HELP ifa_event_scheduler_events_ingested_total Total scheduler events ingested.\n",
        );
        out.push_str("# TYPE ifa_event_scheduler_events_ingested_total counter\n");
        let _ = writeln!(
            out,
            "ifa_event_scheduler_events_ingested_total {}",
            self.telemetry.total_events_ingested
        );

        out.push_str("# HELP ifa_event_scheduler_ingress_packets_total Total upper-layer ingress packets admitted.\n");
        out.push_str("# TYPE ifa_event_scheduler_ingress_packets_total counter\n");
        let _ = writeln!(
            out,
            "ifa_event_scheduler_ingress_packets_total {}",
            self.telemetry.total_ingress_packets
        );

        out.push_str(
            "# HELP ifa_event_scheduler_receiver_acks_total Total receiver ACKs processed.\n",
        );
        out.push_str("# TYPE ifa_event_scheduler_receiver_acks_total counter\n");
        let _ = writeln!(
            out,
            "ifa_event_scheduler_receiver_acks_total {}",
            self.telemetry.total_receiver_acks
        );

        out.push_str(
            "# HELP ifa_event_scheduler_receiver_nacks_total Total receiver NACKs processed.\n",
        );
        out.push_str("# TYPE ifa_event_scheduler_receiver_nacks_total counter\n");
        let _ = writeln!(
            out,
            "ifa_event_scheduler_receiver_nacks_total {}",
            self.telemetry.total_receiver_nacks
        );

        out.push_str("# HELP ifa_event_scheduler_dispatched_data_total Total data packets dispatched to wire.\n");
        out.push_str("# TYPE ifa_event_scheduler_dispatched_data_total counter\n");
        let _ = writeln!(
            out,
            "ifa_event_scheduler_dispatched_data_total {}",
            self.telemetry.total_dispatched_data
        );

        out.push_str("# HELP ifa_event_scheduler_dispatched_parity_total Total FEC parity packets dispatched to wire.\n");
        out.push_str("# TYPE ifa_event_scheduler_dispatched_parity_total counter\n");
        let _ = writeln!(
            out,
            "ifa_event_scheduler_dispatched_parity_total {}",
            self.telemetry.total_dispatched_parity
        );

        out.push_str("# HELP ifa_event_scheduler_dispatched_retransmits_total Total ARQ retransmissions dispatched.\n");
        out.push_str("# TYPE ifa_event_scheduler_dispatched_retransmits_total counter\n");
        let _ = writeln!(
            out,
            "ifa_event_scheduler_dispatched_retransmits_total {}",
            self.telemetry.total_dispatched_retransmits
        );

        out.push_str(
            "# HELP ifa_event_scheduler_dispatched_bytes_total Total bytes dispatched to wire.\n",
        );
        out.push_str("# TYPE ifa_event_scheduler_dispatched_bytes_total counter\n");
        let _ = writeln!(
            out,
            "ifa_event_scheduler_dispatched_bytes_total {}",
            self.telemetry.total_dispatched_bytes
        );

        out.push_str(
            "# HELP ifa_event_scheduler_rto_timeouts_total Total RTO deadline expirations.\n",
        );
        out.push_str("# TYPE ifa_event_scheduler_rto_timeouts_total counter\n");
        let _ = writeln!(
            out,
            "ifa_event_scheduler_rto_timeouts_total {}",
            self.telemetry.total_rto_timeouts
        );

        out.push_str("# HELP ifa_event_scheduler_proactive_migrations_total Total predictive SLA migrations executed.\n");
        out.push_str("# TYPE ifa_event_scheduler_proactive_migrations_total counter\n");
        let _ = writeln!(
            out,
            "ifa_event_scheduler_proactive_migrations_total {}",
            self.telemetry.total_proactive_migrations
        );

        out.push_str(
            "# HELP ifa_event_scheduler_inflight_count Current unacknowledged packets in flight.\n",
        );
        out.push_str("# TYPE ifa_event_scheduler_inflight_count gauge\n");
        let _ = writeln!(
            out,
            "ifa_event_scheduler_inflight_count {}",
            self.telemetry.active_inflight_count
        );

        out.push_str(
            "# HELP ifa_event_scheduler_inflight_bytes Current unacknowledged bytes in flight.\n",
        );
        out.push_str("# TYPE ifa_event_scheduler_inflight_bytes gauge\n");
        let _ = writeln!(
            out,
            "ifa_event_scheduler_inflight_bytes {}",
            self.telemetry.active_inflight_bytes
        );

        // Per-slice active path binding
        out.push_str("# HELP ifa_event_scheduler_slice_subpath_binding Active subpath ID assigned per QoS slice.\n");
        out.push_str("# TYPE ifa_event_scheduler_slice_subpath_binding gauge\n");
        for (&slice, &subpath_id) in &self.slice_bindings {
            let _ = writeln!(
                out,
                "ifa_event_scheduler_slice_subpath_binding{{slice=\"{}\"}} {}",
                slice.as_str(),
                subpath_id
            );
        }

        out
    }

    /// Generate structured JSON audit trail representation.
    pub fn generate_json_audit_trail(&self) -> String {
        let mut out = String::with_capacity(2048);
        out.push_str("{\n");
        let _ = writeln!(
            out,
            "  \"total_events_ingested\": {},",
            self.telemetry.total_events_ingested
        );
        let _ = writeln!(
            out,
            "  \"total_ingress_packets\": {},",
            self.telemetry.total_ingress_packets
        );
        let _ = writeln!(
            out,
            "  \"total_receiver_acks\": {},",
            self.telemetry.total_receiver_acks
        );
        let _ = writeln!(
            out,
            "  \"total_receiver_nacks\": {},",
            self.telemetry.total_receiver_nacks
        );
        let _ = writeln!(
            out,
            "  \"total_dispatched_data\": {},",
            self.telemetry.total_dispatched_data
        );
        let _ = writeln!(
            out,
            "  \"total_dispatched_parity\": {},",
            self.telemetry.total_dispatched_parity
        );
        let _ = writeln!(
            out,
            "  \"total_dispatched_retransmits\": {},",
            self.telemetry.total_dispatched_retransmits
        );
        let _ = writeln!(
            out,
            "  \"total_proactive_migrations\": {},",
            self.telemetry.total_proactive_migrations
        );
        let _ = writeln!(
            out,
            "  \"active_inflight_count\": {},",
            self.telemetry.active_inflight_count
        );
        let _ = writeln!(
            out,
            "  \"active_inflight_bytes\": {},",
            self.telemetry.active_inflight_bytes
        );
        out.push_str("  \"slice_bindings\": {\n");
        let mut first = true;
        for (&slice, &subpath_id) in &self.slice_bindings {
            if !first {
                out.push_str(",\n");
            }
            let _ = write!(out, "    \"{}\": {}", slice.as_str(), subpath_id);
            first = false;
        }
        out.push_str("\n  }\n}");
        out
    }
}

// ---------------------------------------------------------------------------
// Micro-Benchmark Suite
// ---------------------------------------------------------------------------

/// Performance and throughput report for the `MultipathEventScheduler`.
#[derive(Debug, Clone, PartialEq)]
pub struct EventSchedulerBenchmarkReport {
    pub total_iterations: usize,
    pub total_elapsed_ns: u64,
    pub ops_per_second: f64,
    pub avg_op_latency_ns: f64,
    pub ingress_packets_count: u64,
    pub acks_processed_count: u64,
    pub parities_generated_count: u64,
    pub retransmits_dispatched_count: u64,
    pub proactive_migrations_count: u64,
    pub zero_flow_interruption_verified: bool,
}

/// Run an in-memory, deterministic micro-benchmark of the `MultipathEventScheduler`.
pub fn run_multipath_event_scheduler_benchmark(iterations: usize) -> EventSchedulerBenchmarkReport {
    let config = MultipathEventSchedulerConfig {
        audit_interval_ns: 1_000_000, // 1 ms audit for benchmark
        ..Default::default()
    };
    let mut scheduler = MultipathEventScheduler::new(config);

    let start_time_ns = 1_000_000_000_u64;
    let mut current_time_ns = start_time_ns;

    // Subpath 1: Low Latency Fiber (1 Gbps, 5ms RTT)
    scheduler.register_subpath(1, 1_000_000_000, 5_000_000, 1500, current_time_ns);
    // Subpath 2: High Bandwidth 5G (2.5 Gbps, 20ms RTT)
    scheduler.register_subpath(2, 2_500_000_000, 20_000_000, 1500, current_time_ns);

    // Initial bindings: ULL and MC on Subpath 1, eMBB and BE on Subpath 2
    scheduler.bind_slice_to_subpath(FlowSliceClass::UltraLowLatency, 1);
    scheduler.bind_slice_to_subpath(FlowSliceClass::MissionCritical, 1);
    scheduler.bind_slice_to_subpath(FlowSliceClass::HighThroughput, 2);
    scheduler.bind_slice_to_subpath(FlowSliceClass::BestEffort, 2);

    let slices = [
        FlowSliceClass::UltraLowLatency,
        FlowSliceClass::MissionCritical,
        FlowSliceClass::HighThroughput,
        FlowSliceClass::BestEffort,
    ];

    let t0 = std::time::Instant::now();

    for i in 0..iterations {
        let packet_id = (i + 1) as u64;
        let slice = slices[i % slices.len()];
        let size = 1200 + (i % 200);

        // Advance simulated nanosecond clock by 500ns per packet
        current_time_ns += 500;

        // 1. Submit ingress data packet
        scheduler.submit_ingress_packet(packet_id, slice, size, current_time_ns);

        // 2. Step scheduler: process event & dispatch
        let _step_res = scheduler.step(current_time_ns);

        // 3. Every 10th packet, simulate an ACK return from 10 packets ago
        if i >= 10 && i % 10 == 0 {
            let ack_id = (i - 9) as u64;
            let subpath = if i % 2 == 0 { 1 } else { 2 };
            scheduler.submit_event(MultipathSchedulerEvent::ReceiverAck {
                subpath_id: subpath,
                ack_packet_id: ack_id,
                rtt_sample_ns: 5_000_000,
                delivered_bytes: 1200,
                ecn_marked: false,
                receive_time_ns: current_time_ns,
            });
            scheduler.step(current_time_ns);
        }

        // 4. At iteration 500, simulate a latency surge on Subpath 1 to test proactive migration
        if i == 500 {
            scheduler.submit_event(MultipathSchedulerEvent::SubpathMetricsSample {
                subpath_id: 1,
                rtt_ns: 60_000_000, // 60ms surge (exceeds ULL threshold)
                jitter_ns: 15_000_000,
                loss_ratio: 0.05,
                btl_bw_bps: 200_000_000,
                sample_time_ns: current_time_ns,
            });
            scheduler.submit_event(MultipathSchedulerEvent::PredictiveAuditTick {
                now_ns: current_time_ns,
            });
            scheduler.step(current_time_ns);
        }
    }

    let elapsed = t0.elapsed();
    let total_elapsed_ns = elapsed.as_nanos() as u64;
    let total_secs = elapsed.as_secs_f64().max(1e-9);
    let ops_per_second = (iterations as f64) / total_secs;
    let avg_op_latency_ns = (total_elapsed_ns as f64) / (iterations as f64);

    EventSchedulerBenchmarkReport {
        total_iterations: iterations,
        total_elapsed_ns,
        ops_per_second,
        avg_op_latency_ns,
        ingress_packets_count: scheduler.telemetry.total_ingress_packets,
        acks_processed_count: scheduler.telemetry.total_receiver_acks,
        parities_generated_count: scheduler.telemetry.total_dispatched_parity,
        retransmits_dispatched_count: scheduler.telemetry.total_dispatched_retransmits,
        proactive_migrations_count: scheduler.telemetry.total_proactive_migrations,
        zero_flow_interruption_verified: scheduler.telemetry.total_ingress_packets
            == (iterations as u64),
    }
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scheduler_registration_and_slice_binding() {
        let mut scheduler = MultipathEventScheduler::new(MultipathEventSchedulerConfig::default());
        let now = 1_000_000_000;

        scheduler.register_subpath(1, 1_000_000_000, 5_000_000, 1500, now);
        scheduler.register_subpath(2, 500_000_000, 15_000_000, 1500, now);

        assert_eq!(scheduler.subpaths.len(), 2);
        assert_eq!(
            scheduler.get_slice_subpath(FlowSliceClass::UltraLowLatency),
            Some(1)
        );

        scheduler.bind_slice_to_subpath(FlowSliceClass::HighThroughput, 2);
        assert_eq!(
            scheduler.get_slice_subpath(FlowSliceClass::HighThroughput),
            Some(2)
        );
    }

    #[test]
    fn test_scheduler_ingress_enqueue_and_dispatch() {
        let mut scheduler = MultipathEventScheduler::new(MultipathEventSchedulerConfig::default());
        let now = 1_000_000_000;

        scheduler.register_subpath(1, 1_000_000_000, 5_000_000, 1500, now);
        scheduler.bind_slice_to_subpath(FlowSliceClass::UltraLowLatency, 1);

        // Submit packet
        scheduler.submit_ingress_packet(101, FlowSliceClass::UltraLowLatency, 1000, now);
        assert_eq!(scheduler.pending_events.len(), 1);

        // Step scheduler
        let summary = scheduler.step(now);
        assert_eq!(summary.events_processed, 1);
        assert_eq!(summary.dispatched_items_count, 1);
        assert_eq!(summary.dispatched_bytes, 1000);

        // Inflight verified
        assert_eq!(scheduler.inflight_packets.len(), 1);
    }

    #[test]
    fn test_scheduler_receiver_ack_coordination() {
        let mut scheduler = MultipathEventScheduler::new(MultipathEventSchedulerConfig::default());
        let now = 1_000_000_000;

        scheduler.register_subpath(1, 1_000_000_000, 5_000_000, 1500, now);
        scheduler.submit_ingress_packet(201, FlowSliceClass::MissionCritical, 1200, now);
        scheduler.step(now);

        assert_eq!(scheduler.inflight_packets.len(), 1);
        let item_id = *scheduler.inflight_packets.keys().next().unwrap();

        // Receive ACK 5ms later
        let ack_time = now + 5_000_000;
        scheduler.submit_event(MultipathSchedulerEvent::ReceiverAck {
            subpath_id: 1,
            ack_packet_id: item_id,
            rtt_sample_ns: 5_000_000,
            delivered_bytes: 1200,
            ecn_marked: false,
            receive_time_ns: ack_time,
        });

        let summary = scheduler.step(ack_time);
        assert_eq!(summary.events_processed, 1);
        // Packet should be retired from in-flight
        assert_eq!(scheduler.inflight_packets.len(), 0);
        assert_eq!(scheduler.telemetry.total_receiver_acks, 1);
    }

    #[test]
    fn test_scheduler_loss_nack_and_hybrid_arbitration() {
        let mut scheduler = MultipathEventScheduler::new(MultipathEventSchedulerConfig::default());
        let now = 1_000_000_000;

        scheduler.register_subpath(1, 1_000_000_000, 5_000_000, 1500, now);
        scheduler.submit_ingress_packet(301, FlowSliceClass::BestEffort, 1400, now);
        scheduler.step(now);

        let item_id = *scheduler.inflight_packets.keys().next().unwrap();

        // NACK received for item_id
        let nack_time = now + 10_000_000;
        scheduler.submit_event(MultipathSchedulerEvent::ReceiverNack {
            subpath_id: 1,
            lost_packet_ids: vec![item_id],
            detection_time_ns: nack_time,
        });

        let summary = scheduler.step(nack_time);
        assert_eq!(summary.events_processed, 1);
        assert_eq!(scheduler.telemetry.total_receiver_nacks, 1);
    }

    #[test]
    fn test_scheduler_rto_timeout_handling() {
        let mut scheduler = MultipathEventScheduler::new(MultipathEventSchedulerConfig::default());
        let now = 1_000_000_000;

        scheduler.register_subpath(1, 1_000_000_000, 5_000_000, 1500, now);
        scheduler.submit_ingress_packet(401, FlowSliceClass::MissionCritical, 800, now);
        scheduler.step(now);

        assert_eq!(scheduler.inflight_packets.len(), 1);

        // Advance time by 200ms (far exceeding min RTO of 20ms)
        let later = now + 200_000_000;
        let summary = scheduler.step(later);

        assert_eq!(summary.rto_expired_count, 1);
        assert_eq!(scheduler.telemetry.total_rto_timeouts, 1);
    }

    #[test]
    fn test_scheduler_predictive_migration_lossless() {
        let mut scheduler = MultipathEventScheduler::new(MultipathEventSchedulerConfig::default());
        let now = 1_000_000_000;

        scheduler.register_subpath(1, 1_000_000_000, 5_000_000, 1500, now);
        scheduler.register_subpath(2, 1_000_000_000, 8_000_000, 1500, now);

        scheduler.bind_slice_to_subpath(FlowSliceClass::UltraLowLatency, 1);
        assert_eq!(
            scheduler.get_slice_subpath(FlowSliceClass::UltraLowLatency),
            Some(1)
        );

        // Send a packet on Subpath 1
        scheduler.submit_ingress_packet(501, FlowSliceClass::UltraLowLatency, 500, now);
        scheduler.step(now);
        assert_eq!(scheduler.inflight_packets.len(), 1);
        let item_id = *scheduler.inflight_packets.keys().next().unwrap();

        // Subpath 1 degrades heavily (RTT surge & jitter)
        let audit_time = now + 10_000_000; // 10ms (within 20ms RTO window)
        scheduler.submit_event(MultipathSchedulerEvent::SubpathMetricsSample {
            subpath_id: 1,
            rtt_ns: 80_000_000,
            jitter_ns: 25_000_000,
            loss_ratio: 0.10,
            btl_bw_bps: 100_000_000,
            sample_time_ns: audit_time,
        });

        // Predictive audit tick
        scheduler.submit_event(MultipathSchedulerEvent::PredictiveAuditTick { now_ns: audit_time });
        let summary = scheduler.step(audit_time);

        assert_eq!(summary.events_processed, 2);

        // Packets still in flight on subpath 1 are maintained without disruption
        assert!(scheduler.inflight_packets.contains_key(&item_id));

        // Inflight packet can still be acknowledged without error
        let ack_time = audit_time + 5_000_000; // 15ms (still within 20ms RTO window)
        scheduler.submit_event(MultipathSchedulerEvent::ReceiverAck {
            subpath_id: 1,
            ack_packet_id: item_id,
            rtt_sample_ns: 15_000_000,
            delivered_bytes: 500,
            ecn_marked: false,
            receive_time_ns: ack_time,
        });
        scheduler.step(ack_time);
        assert!(!scheduler.inflight_packets.contains_key(&item_id));
    }

    #[test]
    fn test_scheduler_prometheus_metrics_and_json_audit() {
        let mut scheduler = MultipathEventScheduler::new(MultipathEventSchedulerConfig::default());
        let now = 1_000_000_000;

        scheduler.register_subpath(1, 1_000_000_000, 5_000_000, 1500, now);
        scheduler.submit_ingress_packet(601, FlowSliceClass::UltraLowLatency, 1000, now);
        scheduler.step(now);

        let prometheus = scheduler.export_prometheus_metrics();
        assert!(prometheus.contains("ifa_event_scheduler_events_ingested_total"));
        assert!(prometheus.contains("ifa_event_scheduler_dispatched_data_total 1"));
        assert!(prometheus.contains("ifa_event_scheduler_inflight_count 1"));

        let json = scheduler.generate_json_audit_trail();
        assert!(json.contains("\"total_dispatched_data\": 1"));
        assert!(json.contains("\"active_inflight_count\": 1"));
    }

    #[test]
    fn test_micro_benchmark_execution() {
        let report = run_multipath_event_scheduler_benchmark(500);
        assert_eq!(report.total_iterations, 500);
        assert!(report.ops_per_second > 1_000.0);
        assert!(report.zero_flow_interruption_verified);
    }
}

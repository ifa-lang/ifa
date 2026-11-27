//! Unified Multipath Traffic Pipeline (`SubpathTrafficPipeline`).
//!
//! Orchestrates the end-to-end egress data path for heterogeneous multipath transport:
//! - **QoS Slicing & Policing (`SubpathSliceShaper`)**:
//!   Per-slice token-bucket rate limiting (`UltraLowLatency`, `MissionCritical`, `HighThroughput`, `BestEffort`).
//! - **Congestion Control & Bandwidth Estimation (`SubpathBbrDriver`)**:
//!   Per-subpath BBR state machine (`Startup`, `Drain`, `ProbeBw`, `ProbeRtt`) estimating `BtlBw` and `RTprop`.
//! - **Cross-Priority Pacing & Nanosecond Scheduling (`MultipathPacingEngine`)**:
//!   Cross-priority queues, deterministic inter-packet spacing, and preemptive `UltraLowLatency` injection.
//! - **Closed-Loop Feedback Controller**:
//!   Dynamic coupling between delivery acknowledgements, ECN marks, packet loss, and:
//!   - Dynamic Shaper bandwidth rebalancing when `BtlBw` adapts.
//!   - Dynamic Pacer pacing rate & gain synchronization.
//!   - Dynamic Backpressure Mitigation: throttles elastic traffic (`HighThroughput`, `BestEffort`)
//!     under downstream congestion while safeguarding mission-critical and URLLC SLAs.
//!   - Autonomous multi-round clean recovery.
//! - **Unified OpenMetrics Observability**:
//!   Comprehensive Prometheus metrics export spanning shaper, pacer, BBR, and pipeline telemetry.

use std::collections::BTreeMap;
use std::fmt::Write as FmtWrite;

use crate::multipath_pacing::{
    MultipathPacingEngine, PacedScheduledPacket, PacingPollResult, SubpathPacerConfig,
    SubpathPacingTelemetry, SubpathPacingVerdict,
};
use crate::subpath_bbr::{
    DeliveryAckSample, SubpathBbrConfig, SubpathBbrDriver, SubpathBbrPhase, SubpathBbrTelemetry,
};
use crate::subpath_shaper::{SubpathAdmissionVerdict, SubpathShaperTelemetry, SubpathSliceShaper};
use crate::subpath_starvation_guard::{
    StarvationGuardConfig, StarvationRemediationVerdict, SubpathStarvationGuard,
    SubpathStarvationTelemetry,
};
use crate::traffic_slicing::FlowSliceClass;

/// Verdict returned upon packet ingress submission to the pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipelineIngressVerdict {
    /// Packet admitted by shaper, within CWND, and enqueued into the pacing engine.
    Admitted {
        packet_id: u64,
        pacing_verdict: SubpathPacingVerdict,
    },
    /// Packet admitted with shaper pacing delay, within CWND, and enqueued into the pacing engine.
    AdmittedWithDelay {
        packet_id: u64,
        delay_ns: u64,
        pacing_verdict: SubpathPacingVerdict,
    },
    /// Packet dropped at ingress due to token exhaustion on its traffic slice.
    ThrottledByShaper { dropped_bytes: usize },
    /// Packet blocked by BBR congestion window saturation.
    BlockedByCwnd {
        inflight_bytes: u64,
        cwnd_bytes: u64,
    },
}

/// Result returned when polling an egress subpath for the next wire-ready packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipelinePollResult {
    /// A packet is ready for wire departure. Accounting in BBR and Shaper is performed automatically.
    Ready(PacedScheduledPacket),
    /// Subpath is actively pacing; caller should wait `wait_ns` nanoseconds until `next_wake_ns`.
    WaitPacing { wait_ns: u64, next_wake_ns: u64 },
    /// No packets queued for transmission on this subpath.
    Empty,
}

/// Summary of action taken upon processing an incoming delivery/acknowledgement sample.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedbackActionResult {
    pub subpath_id: u8,
    pub bbr_phase_before: SubpathBbrPhase,
    pub bbr_phase_after: SubpathBbrPhase,
    pub btl_bw_bps: u64,
    pub rt_prop_us: u64,
    pub pacing_rate_bps: u64,
    pub cwnd_bytes: u64,
    pub backpressure_applied: bool,
    pub backpressure_relieved: bool,
    pub active_backpressure_level_pct: u32,
    pub consecutive_clean_rounds: u32,
}

/// Errors that can occur within the traffic pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipelineError {
    SubpathNotFound { subpath_id: u8 },
    EmptyPayload,
    SubpathAlreadyExists { subpath_id: u8 },
}

/// Configuration tuning parameters for a subpath pipeline channel.
#[derive(Debug, Clone, PartialEq)]
pub struct SubpathPipelineConfig {
    pub subpath_id: u8,
    pub initial_bandwidth_bps: u64,
    pub initial_rtt_us: u64,
    pub burst_window_ms: u32,
    pub pacer_config: SubpathPacerConfig,
    pub bbr_config: SubpathBbrConfig,
    pub enable_bbr_shaper_sync: bool,
    pub enable_bbr_pacer_sync: bool,
    pub backpressure_loss_reduction_pct: u32,
    pub backpressure_ecn_reduction_pct: u32,
    pub clean_recovery_rounds_threshold: u32,
    pub urllc_bypass_cwnd: bool,
    pub starvation_config: StarvationGuardConfig,
}

impl SubpathPipelineConfig {
    pub fn new(subpath_id: u8, bandwidth_bps: u64, rtt_us: u64) -> Self {
        Self {
            subpath_id,
            initial_bandwidth_bps: bandwidth_bps,
            initial_rtt_us: rtt_us,
            burst_window_ms: SubpathSliceShaper::DEFAULT_BURST_WINDOW_MS,
            pacer_config: SubpathPacerConfig::default(),
            bbr_config: SubpathBbrConfig::default(),
            enable_bbr_shaper_sync: true,
            enable_bbr_pacer_sync: true,
            backpressure_loss_reduction_pct: 70, // 30% reduction on packet loss
            backpressure_ecn_reduction_pct: 85,  // 15% reduction on ECN
            clean_recovery_rounds_threshold: 3,  // 3 consecutive clean rounds to restore
            urllc_bypass_cwnd: true,
            starvation_config: StarvationGuardConfig::default(),
        }
    }
}

/// Channel runtime statistics and closed-loop feedback state.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SubpathChannelState {
    pub subpath_id: u8,
    pub consecutive_clean_rounds: u32,
    pub in_backpressure: bool,
    pub current_backpressure_pct: u32,
    pub total_ingress_packets: u64,
    pub total_ingress_bytes: u64,
    pub total_admitted_packets: u64,
    pub total_admitted_bytes: u64,
    pub total_throttled_packets: u64,
    pub total_throttled_bytes: u64,
    pub total_cwnd_blocked_packets: u64,
    pub total_cwnd_blocked_bytes: u64,
    pub total_egress_packets: u64,
    pub total_egress_bytes: u64,
    pub total_feedback_events: u64,
    pub total_loss_events: u64,
    pub total_ecn_events: u64,
}

/// Telemetry snapshot aggregating state from all components for a subpath.
#[derive(Debug, Clone, PartialEq)]
pub struct SubpathPipelineTelemetry {
    pub subpath_id: u8,
    pub channel_state: SubpathChannelState,
    pub bbr: SubpathBbrTelemetry,
    pub pacing: SubpathPacingTelemetry,
    pub shaper: SubpathShaperTelemetry,
    pub starvation: Option<SubpathStarvationTelemetry>,
}

/// Unified Multipath Traffic Pipeline combining Shaper, BBR Driver, and Pacing Engine.
#[derive(Debug, Default)]
pub struct SubpathTrafficPipeline {
    /// Active channel telemetry and feedback state per subpath.
    subpaths: BTreeMap<u8, SubpathChannelState>,
    /// Channel configurations per subpath.
    configs: BTreeMap<u8, SubpathPipelineConfig>,
    /// Per-subpath QoS slice shapers.
    shapers: BTreeMap<u8, SubpathSliceShaper>,
    /// Multipath BBR congestion control driver.
    bbr: SubpathBbrDriver,
    /// Cross-priority multipath pacing and scheduling engine.
    pacing: MultipathPacingEngine,
    /// Anti-starvation monitoring and priority inversion guard.
    pub starvation_guard: SubpathStarvationGuard,
}

impl SubpathTrafficPipeline {
    /// Instantiates an empty unified multipath traffic pipeline.
    pub fn new() -> Self {
        Self {
            subpaths: BTreeMap::new(),
            configs: BTreeMap::new(),
            shapers: BTreeMap::new(),
            bbr: SubpathBbrDriver::new(),
            pacing: MultipathPacingEngine::new(),
            starvation_guard: SubpathStarvationGuard::new(),
        }
    }

    /// Registers a physical subpath into the unified pipeline with default configuration.
    pub fn register_subpath(
        &mut self,
        subpath_id: u8,
        bandwidth_bps: u64,
        rtt_us: u64,
        now_ns: u64,
    ) -> Result<(), PipelineError> {
        let config = SubpathPipelineConfig::new(subpath_id, bandwidth_bps, rtt_us);
        self.register_subpath_with_config(config, now_ns)
    }

    /// Registers a physical subpath into the unified pipeline with custom configuration.
    pub fn register_subpath_with_config(
        &mut self,
        config: SubpathPipelineConfig,
        now_ns: u64,
    ) -> Result<(), PipelineError> {
        let sid = config.subpath_id;
        if self.subpaths.contains_key(&sid) {
            return Err(PipelineError::SubpathAlreadyExists { subpath_id: sid });
        }

        let rtt_ms = (config.initial_rtt_us / 1000).max(1);

        // 1. Initialize Shaper
        let shaper = SubpathSliceShaper::new(sid, config.initial_bandwidth_bps, now_ns);
        self.shapers.insert(sid, shaper);

        // 2. Initialize BBR Driver
        self.bbr.register_subpath_with_config(
            sid,
            config.initial_bandwidth_bps,
            config.initial_rtt_us,
            config.bbr_config.clone(),
            now_ns,
        );

        // 3. Initialize Pacing Engine
        self.pacing.register_subpath_with_config(
            sid,
            config.initial_bandwidth_bps,
            rtt_ms,
            config.pacer_config.clone(),
            now_ns,
        );

        if config.enable_bbr_pacer_sync {
            if let Some(pacer) = self.pacing.pacers.get_mut(&sid) {
                self.bbr.synchronize_pacer(sid, pacer, now_ns);
            }
        }

        // 4. Initialize Starvation Guard
        self.starvation_guard.register_subpath(sid, now_ns);

        // 5. Initialize Channel State
        let state = SubpathChannelState {
            subpath_id: sid,
            consecutive_clean_rounds: 0,
            in_backpressure: false,
            current_backpressure_pct: 100,
            ..Default::default()
        };
        self.subpaths.insert(sid, state);
        self.configs.insert(sid, config);

        Ok(())
    }

    /// Unregisters a subpath from all pipeline sub-components.
    pub fn unregister_subpath(&mut self, subpath_id: u8) -> bool {
        let removed_channel = self.subpaths.remove(&subpath_id).is_some();
        self.configs.remove(&subpath_id);
        self.shapers.remove(&subpath_id);
        self.bbr.unregister_subpath(subpath_id);
        self.pacing.unregister_subpath(subpath_id);
        self.starvation_guard.unregister_subpath(subpath_id);
        removed_channel
    }

    /// Submits a packet to the pipeline for admission shaping, CWND verification, and pacing.
    pub fn submit_packet(
        &mut self,
        subpath_id: u8,
        slice_class: FlowSliceClass,
        payload: Vec<u8>,
        now_ns: u64,
    ) -> Result<PipelineIngressVerdict, PipelineError> {
        if payload.is_empty() {
            return Err(PipelineError::EmptyPayload);
        }

        let config = match self.configs.get(&subpath_id) {
            Some(c) => c.clone(),
            None => return Err(PipelineError::SubpathNotFound { subpath_id }),
        };

        let packet_size = payload.len();
        {
            let state = self.subpaths.get_mut(&subpath_id).unwrap();
            state.total_ingress_packets += 1;
            state.total_ingress_bytes += packet_size as u64;
        }

        // 1. Shaper Admission Check
        let mut admission_verdict = {
            let shaper = self.shapers.get_mut(&subpath_id).unwrap();
            shaper.try_admit(slice_class, packet_size, now_ns)
        };

        // If throttled, check if anti-starvation guard authorizes a temporary token boost
        if let SubpathAdmissionVerdict::Throttled { .. } = admission_verdict {
            let shaper = self.shapers.get_mut(&subpath_id).unwrap();
            if let StarvationRemediationVerdict::TokenBoostApplied { .. } = self
                .starvation_guard
                .check_admission_starvation(subpath_id, slice_class, packet_size, shaper, now_ns)
            {
                admission_verdict = shaper.try_admit(slice_class, packet_size, now_ns);
            }
        }

        if let SubpathAdmissionVerdict::Throttled { dropped_bytes } = admission_verdict {
            self.starvation_guard
                .record_throttle(subpath_id, slice_class, packet_size, now_ns);
            let state = self.subpaths.get_mut(&subpath_id).unwrap();
            state.total_throttled_packets += 1;
            state.total_throttled_bytes += dropped_bytes as u64;
            return Ok(PipelineIngressVerdict::ThrottledByShaper { dropped_bytes });
        }

        self.starvation_guard
            .record_admission(subpath_id, slice_class, packet_size, now_ns);

        // 2. Congestion Window (BBR) Verification
        let can_send_bbr =
            if slice_class == FlowSliceClass::UltraLowLatency && config.urllc_bypass_cwnd {
                true
            } else {
                self.bbr.can_send(subpath_id, slice_class, packet_size)
            };

        if !can_send_bbr {
            let (inflight, cwnd) = self
                .bbr
                .subpath_state(subpath_id)
                .map(|s| (s.inflight_bytes, s.cwnd_bytes))
                .unwrap_or((0, 0));
            let state = self.subpaths.get_mut(&subpath_id).unwrap();
            state.total_cwnd_blocked_packets += 1;
            state.total_cwnd_blocked_bytes += packet_size as u64;
            return Ok(PipelineIngressVerdict::BlockedByCwnd {
                inflight_bytes: inflight,
                cwnd_bytes: cwnd,
            });
        }

        // 3. Pacing Evaluation & Enqueue
        let pacing_verdict = if let Some(pacer) = self.pacing.pacers.get_mut(&subpath_id) {
            pacer.evaluate_tx(slice_class, packet_size, now_ns)
        } else {
            SubpathPacingVerdict::Immediate
        };

        let packet_id = self
            .pacing
            .enqueue(subpath_id, slice_class, payload, now_ns);

        {
            let state = self.subpaths.get_mut(&subpath_id).unwrap();
            state.total_admitted_packets += 1;
            state.total_admitted_bytes += packet_size as u64;
        }

        match admission_verdict {
            SubpathAdmissionVerdict::Delayed { delay_ns } => {
                Ok(PipelineIngressVerdict::AdmittedWithDelay {
                    packet_id,
                    delay_ns,
                    pacing_verdict,
                })
            }
            SubpathAdmissionVerdict::Admitted => Ok(PipelineIngressVerdict::Admitted {
                packet_id,
                pacing_verdict,
            }),
            SubpathAdmissionVerdict::Throttled { .. } => unreachable!(),
        }
    }

    /// Polls a specific subpath for the next wire-transmission-ready packet.
    ///
    /// Automatically performs BBR inflight accounting (`on_packet_sent`) and
    /// shaper transit latency logging.
    pub fn poll_egress(
        &mut self,
        subpath_id: u8,
        now_ns: u64,
    ) -> Result<PipelinePollResult, PipelineError> {
        if !self.subpaths.contains_key(&subpath_id) {
            return Err(PipelineError::SubpathNotFound { subpath_id });
        }

        let poll_res = if let Some(pacer) = self.pacing.pacers.get_mut(&subpath_id) {
            self.starvation_guard
                .poll_with_starvation_guard(subpath_id, pacer, now_ns)
        } else {
            PacingPollResult::Empty
        };

        match poll_res {
            PacingPollResult::Ready(packet) => {
                self.bbr.on_packet_sent(subpath_id, packet.size_bytes);
                if let Some(shaper) = self.shapers.get_mut(&subpath_id) {
                    shaper.record_transit_latency(packet.slice_class, packet.pacing_delay_ns);
                }
                if let Some(state) = self.subpaths.get_mut(&subpath_id) {
                    state.total_egress_packets += 1;
                    state.total_egress_bytes += packet.size_bytes as u64;
                }
                Ok(PipelinePollResult::Ready(packet))
            }
            PacingPollResult::WaitPacing {
                wait_ns,
                next_wake_ns,
            } => Ok(PipelinePollResult::WaitPacing {
                wait_ns,
                next_wake_ns,
            }),
            PacingPollResult::Empty => Ok(PipelinePollResult::Empty),
        }
    }

    /// Polls across all managed subpaths, prioritizing `UltraLowLatency` packets first.
    pub fn poll_next_available(&mut self, now_ns: u64) -> Option<(u8, PacedScheduledPacket)> {
        let subpaths: Vec<u8> = self.subpaths.keys().copied().collect();
        for sid in subpaths {
            if let Ok(PipelinePollResult::Ready(packet)) = self.poll_egress(sid, now_ns) {
                return Some((sid, packet));
            }
        }
        None
    }

    /// Processes an incoming delivery feedback sample and executes closed-loop adaptations.
    pub fn on_delivery_ack(
        &mut self,
        subpath_id: u8,
        sample: DeliveryAckSample,
        now_ns: u64,
    ) -> Result<FeedbackActionResult, PipelineError> {
        let config = match self.configs.get(&subpath_id) {
            Some(c) => c.clone(),
            None => return Err(PipelineError::SubpathNotFound { subpath_id }),
        };

        let phase_before = match self.bbr.subpath_state(subpath_id) {
            Some(s) => s.phase,
            None => return Err(PipelineError::SubpathNotFound { subpath_id }),
        };

        // 1. Deliver sample to BBR state machine
        self.bbr.on_ack_sample(subpath_id, sample, now_ns);

        let (phase_after, btl_bw_bps, rt_prop_us, pacing_rate_bps, pacing_gain_q8, cwnd_bytes) = {
            let s = self.bbr.subpath_state(subpath_id).unwrap();
            (
                s.phase,
                s.btl_bw_bps,
                s.rt_prop_us,
                s.pacing_rate_bps,
                s.pacing_gain_q8,
                s.cwnd_bytes,
            )
        };

        // 2. Closed-Loop Synchronize with Pacing Engine
        if config.enable_bbr_pacer_sync {
            let rtt_ms = (rt_prop_us / 1000).max(1);
            self.pacing
                .update_subpath_link(subpath_id, btl_bw_bps, rtt_ms, now_ns);
            self.pacing
                .set_subpath_pacing_gain(subpath_id, pacing_gain_q8, now_ns);
        }

        // 3. Closed-Loop Synchronize with Slice Shaper
        if config.enable_bbr_shaper_sync {
            if let Some(shaper) = self.shapers.get_mut(&subpath_id) {
                shaper.rebalance(btl_bw_bps, now_ns);
            }
        }

        // 4. Closed-Loop Backpressure Adaptation
        let channel = self.subpaths.get_mut(&subpath_id).unwrap();
        channel.total_feedback_events += 1;

        let mut backpressure_applied = false;
        let mut backpressure_relieved = false;

        if sample.lost_bytes > 0 {
            channel.total_loss_events += 1;
            channel.consecutive_clean_rounds = 0;
            channel.in_backpressure = true;
            channel.current_backpressure_pct = config.backpressure_loss_reduction_pct;

            if let Some(shaper) = self.shapers.get_mut(&subpath_id) {
                // Apply aggressive backpressure to BestEffort and HighThroughput
                shaper.apply_backpressure_reduction(
                    FlowSliceClass::BestEffort,
                    (config.backpressure_loss_reduction_pct * 80) / 100, // deeper cut for BE
                    now_ns,
                );
                shaper.apply_backpressure_reduction(
                    FlowSliceClass::HighThroughput,
                    config.backpressure_loss_reduction_pct,
                    now_ns,
                );
                // UltraLowLatency and MissionCritical are strictly protected from backpressure degradation!
            }
            backpressure_applied = true;
        } else if sample.ecn_ce_count > 0 {
            channel.total_ecn_events += 1;
            channel.consecutive_clean_rounds = 0;
            channel.in_backpressure = true;
            channel.current_backpressure_pct = config.backpressure_ecn_reduction_pct;

            if let Some(shaper) = self.shapers.get_mut(&subpath_id) {
                // Apply moderate backpressure
                shaper.apply_backpressure_reduction(
                    FlowSliceClass::BestEffort,
                    config.backpressure_ecn_reduction_pct,
                    now_ns,
                );
                shaper.apply_backpressure_reduction(
                    FlowSliceClass::HighThroughput,
                    config.backpressure_ecn_reduction_pct,
                    now_ns,
                );
            }
            backpressure_applied = true;
        } else {
            // Clean sample without packet loss or ECN CE marks
            channel.consecutive_clean_rounds += 1;
            if channel.in_backpressure
                && channel.consecutive_clean_rounds >= config.clean_recovery_rounds_threshold
            {
                if let Some(shaper) = self.shapers.get_mut(&subpath_id) {
                    shaper.reset_backpressure_reduction(FlowSliceClass::BestEffort, now_ns);
                    shaper.reset_backpressure_reduction(FlowSliceClass::HighThroughput, now_ns);
                }
                channel.in_backpressure = false;
                channel.current_backpressure_pct = 100;
                backpressure_relieved = true;
            }
        }

        let active_backpressure_level_pct = channel.current_backpressure_pct;
        let consecutive_clean_rounds = channel.consecutive_clean_rounds;

        Ok(FeedbackActionResult {
            subpath_id,
            bbr_phase_before: phase_before,
            bbr_phase_after: phase_after,
            btl_bw_bps,
            rt_prop_us,
            pacing_rate_bps,
            cwnd_bytes,
            backpressure_applied,
            backpressure_relieved,
            active_backpressure_level_pct,
            consecutive_clean_rounds,
        })
    }

    /// Access immutable reference to channel state.
    pub fn channel_state(&self, subpath_id: u8) -> Option<&SubpathChannelState> {
        self.subpaths.get(&subpath_id)
    }

    /// Access immutable reference to subpath shaper.
    pub fn shaper(&self, subpath_id: u8) -> Option<&SubpathSliceShaper> {
        self.shapers.get(&subpath_id)
    }

    /// Access mutable reference to subpath shaper.
    pub fn shaper_mut(&mut self, subpath_id: u8) -> Option<&mut SubpathSliceShaper> {
        self.shapers.get_mut(&subpath_id)
    }

    /// Access immutable reference to BBR driver.
    pub fn bbr(&self) -> &SubpathBbrDriver {
        &self.bbr
    }

    /// Access mutable reference to BBR driver.
    pub fn bbr_mut(&mut self) -> &mut SubpathBbrDriver {
        &mut self.bbr
    }

    /// Access immutable reference to pacing engine.
    pub fn pacing(&self) -> &MultipathPacingEngine {
        &self.pacing
    }

    /// Access mutable reference to pacing engine.
    pub fn pacing_mut(&mut self) -> &mut MultipathPacingEngine {
        &mut self.pacing
    }

    /// Snapshots all components for a specific subpath into a single telemetry record.
    pub fn snapshot(&self, subpath_id: u8) -> Option<SubpathPipelineTelemetry> {
        let channel_state = self.subpaths.get(&subpath_id)?.clone();
        let bbr = self.bbr.subpath_state(subpath_id)?.snapshot();
        let pacing = self.pacing.pacers.get(&subpath_id)?.snapshot();
        let shaper = self.shapers.get(&subpath_id)?.snapshot();
        let starvation = self.starvation_guard.subpath_telemetry(subpath_id);

        Some(SubpathPipelineTelemetry {
            subpath_id,
            channel_state,
            bbr,
            pacing,
            shaper,
            starvation,
        })
    }

    /// Snapshots telemetry for all registered subpaths.
    pub fn all_snapshots(&self) -> Vec<SubpathPipelineTelemetry> {
        self.subpaths
            .keys()
            .filter_map(|&sid| self.snapshot(sid))
            .collect()
    }

    /// Generates OpenMetrics Prometheus metrics lines for a specific subpath pipeline.
    pub fn export_subpath_prometheus_metrics(&self, subpath_id: u8) -> Option<String> {
        let channel = self.subpaths.get(&subpath_id)?;
        let shaper = self.shapers.get(&subpath_id)?;
        let pacer = self.pacing.pacers.get(&subpath_id)?;
        let bbr_state = self.bbr.subpath_state(subpath_id)?;

        let mut out = String::new();
        let sid = subpath_id;
        let subpath_name = format!("subpath_{}", sid);

        let _ = writeln!(
            out,
            "ifa_subpath_pipeline_ingress_packets_total{{subpath_id=\"{}\"}} {}",
            sid, channel.total_ingress_packets
        );
        let _ = writeln!(
            out,
            "ifa_subpath_pipeline_ingress_bytes_total{{subpath_id=\"{}\"}} {}",
            sid, channel.total_ingress_bytes
        );
        let _ = writeln!(
            out,
            "ifa_subpath_pipeline_admitted_packets_total{{subpath_id=\"{}\"}} {}",
            sid, channel.total_admitted_packets
        );
        let _ = writeln!(
            out,
            "ifa_subpath_pipeline_admitted_bytes_total{{subpath_id=\"{}\"}} {}",
            sid, channel.total_admitted_bytes
        );
        let _ = writeln!(
            out,
            "ifa_subpath_pipeline_throttled_packets_total{{subpath_id=\"{}\"}} {}",
            sid, channel.total_throttled_packets
        );
        let _ = writeln!(
            out,
            "ifa_subpath_pipeline_throttled_bytes_total{{subpath_id=\"{}\"}} {}",
            sid, channel.total_throttled_bytes
        );
        let _ = writeln!(
            out,
            "ifa_subpath_pipeline_cwnd_blocked_packets_total{{subpath_id=\"{}\"}} {}",
            sid, channel.total_cwnd_blocked_packets
        );
        let _ = writeln!(
            out,
            "ifa_subpath_pipeline_cwnd_blocked_bytes_total{{subpath_id=\"{}\"}} {}",
            sid, channel.total_cwnd_blocked_bytes
        );
        let _ = writeln!(
            out,
            "ifa_subpath_pipeline_egress_packets_total{{subpath_id=\"{}\"}} {}",
            sid, channel.total_egress_packets
        );
        let _ = writeln!(
            out,
            "ifa_subpath_pipeline_egress_bytes_total{{subpath_id=\"{}\"}} {}",
            sid, channel.total_egress_bytes
        );
        let _ = writeln!(
            out,
            "ifa_subpath_pipeline_loss_events_total{{subpath_id=\"{}\"}} {}",
            sid, channel.total_loss_events
        );
        let _ = writeln!(
            out,
            "ifa_subpath_pipeline_ecn_events_total{{subpath_id=\"{}\"}} {}",
            sid, channel.total_ecn_events
        );
        let _ = writeln!(
            out,
            "ifa_subpath_pipeline_in_backpressure{{subpath_id=\"{}\"}} {}",
            sid,
            if channel.in_backpressure { 1 } else { 0 }
        );
        let _ = writeln!(
            out,
            "ifa_subpath_pipeline_backpressure_scale_pct{{subpath_id=\"{}\"}} {}",
            sid, channel.current_backpressure_pct
        );

        // Append sub-component metrics
        out.push_str(&shaper.export_prometheus_metrics(&subpath_name));

        // Format Pacer metrics
        let p_snap = pacer.snapshot();
        let _ = writeln!(
            out,
            "ifa_multipath_pacing_rate_bps{{subpath_id=\"{}\"}} {}",
            sid, p_snap.pacing_rate_bps
        );
        let _ = writeln!(
            out,
            "ifa_multipath_pacing_bdp_bytes{{subpath_id=\"{}\"}} {}",
            sid, p_snap.bdp_bytes
        );
        let _ = writeln!(
            out,
            "ifa_multipath_pacing_burst_quantum_bytes{{subpath_id=\"{}\"}} {}",
            sid, p_snap.burst_quantum_bytes
        );
        let _ = writeln!(
            out,
            "ifa_multipath_pacing_delayed_packets_total{{subpath_id=\"{}\"}} {}",
            sid, p_snap.total_delayed_packets
        );
        let _ = writeln!(
            out,
            "ifa_multipath_pacing_delay_ns_total{{subpath_id=\"{}\"}} {}",
            sid, p_snap.total_pacing_delay_ns
        );
        let _ = writeln!(
            out,
            "ifa_multipath_pacing_urllc_bypass_packets_total{{subpath_id=\"{}\"}} {}",
            sid, p_snap.total_urllc_bypass_packets
        );

        // Format BBR metrics
        let _ = writeln!(
            out,
            "ifa_multipath_bbr_btl_bw_bps{{subpath_id=\"{}\"}} {}",
            sid, bbr_state.btl_bw_bps
        );
        let _ = writeln!(
            out,
            "ifa_multipath_bbr_rt_prop_microseconds{{subpath_id=\"{}\"}} {}",
            sid, bbr_state.rt_prop_us
        );
        let _ = writeln!(
            out,
            "ifa_multipath_bbr_pacing_rate_bps{{subpath_id=\"{}\"}} {}",
            sid, bbr_state.pacing_rate_bps
        );
        let _ = writeln!(
            out,
            "ifa_multipath_bbr_cwnd_bytes{{subpath_id=\"{}\"}} {}",
            sid, bbr_state.cwnd_bytes
        );
        let _ = writeln!(
            out,
            "ifa_multipath_bbr_inflight_bytes{{subpath_id=\"{}\"}} {}",
            sid, bbr_state.inflight_bytes
        );

        Some(out)
    }

    /// Exports full OpenMetrics Prometheus exposition across all managed subpaths.
    pub fn export_prometheus_metrics(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "# HELP ifa_subpath_pipeline_ingress_packets_total Total ingress packets submitted to pipeline."
        );
        let _ = writeln!(
            out,
            "# TYPE ifa_subpath_pipeline_ingress_packets_total counter"
        );
        let _ = writeln!(
            out,
            "# HELP ifa_subpath_pipeline_admitted_packets_total Total ingress packets admitted for transmission."
        );
        let _ = writeln!(
            out,
            "# TYPE ifa_subpath_pipeline_admitted_packets_total counter"
        );
        let _ = writeln!(
            out,
            "# HELP ifa_subpath_pipeline_throttled_packets_total Total ingress packets dropped by shaper policing."
        );
        let _ = writeln!(
            out,
            "# TYPE ifa_subpath_pipeline_throttled_packets_total counter"
        );
        let _ = writeln!(
            out,
            "# HELP ifa_subpath_pipeline_cwnd_blocked_packets_total Total ingress packets blocked by BBR congestion window."
        );
        let _ = writeln!(
            out,
            "# TYPE ifa_subpath_pipeline_cwnd_blocked_packets_total counter"
        );
        let _ = writeln!(
            out,
            "# HELP ifa_subpath_pipeline_egress_packets_total Total packets departed on physical wire."
        );
        let _ = writeln!(
            out,
            "# TYPE ifa_subpath_pipeline_egress_packets_total counter"
        );
        let _ = writeln!(
            out,
            "# HELP ifa_subpath_pipeline_in_backpressure Whether subpath is under active backpressure throttling (1/0)."
        );
        let _ = writeln!(out, "# TYPE ifa_subpath_pipeline_in_backpressure gauge");

        for &sid in self.subpaths.keys() {
            if let Some(metrics) = self.export_subpath_prometheus_metrics(sid) {
                out.push_str(&metrics);
            }
        }

        out.push_str(&self.starvation_guard.export_prometheus_metrics());

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipeline_subpath_registration_and_unregistration() {
        let mut pipeline = SubpathTrafficPipeline::new();
        let now_ns = 1_000_000_000;

        assert!(pipeline
            .register_subpath(1, 10_000_000, 20_000, now_ns)
            .is_ok());
        // Duplicate registration should fail
        assert_eq!(
            pipeline.register_subpath(1, 10_000_000, 20_000, now_ns),
            Err(PipelineError::SubpathAlreadyExists { subpath_id: 1 })
        );

        assert!(pipeline.channel_state(1).is_some());
        assert!(pipeline.shaper(1).is_some());
        assert!(pipeline.bbr().subpath_state(1).is_some());
        assert!(pipeline.pacing().pacers.contains_key(&1));

        assert!(pipeline.unregister_subpath(1));
        assert!(pipeline.channel_state(1).is_none());
        assert!(pipeline.shaper(1).is_none());
        assert!(pipeline.bbr().subpath_state(1).is_none());
        assert!(!pipeline.pacing().pacers.contains_key(&1));
        assert!(!pipeline.unregister_subpath(1));
    }

    #[test]
    fn test_pipeline_nominal_admission_and_egress_flow() {
        let mut pipeline = SubpathTrafficPipeline::new();
        let now_ns = 1_000_000_000;
        let sid = 1;

        pipeline
            .register_subpath(sid, 20_000_000, 10_000, now_ns)
            .unwrap();

        // Submit packets across slices
        let p_urllc = vec![1u8; 256];
        let p_mc = vec![2u8; 512];
        let p_embb = vec![3u8; 1024];
        let p_be = vec![4u8; 256];

        let v1 = pipeline
            .submit_packet(sid, FlowSliceClass::UltraLowLatency, p_urllc, now_ns)
            .unwrap();
        let v2 = pipeline
            .submit_packet(sid, FlowSliceClass::MissionCritical, p_mc, now_ns)
            .unwrap();
        let v3 = pipeline
            .submit_packet(sid, FlowSliceClass::HighThroughput, p_embb, now_ns)
            .unwrap();
        let v4 = pipeline
            .submit_packet(sid, FlowSliceClass::BestEffort, p_be, now_ns)
            .unwrap();

        match v1 {
            PipelineIngressVerdict::Admitted { packet_id, .. } => assert_eq!(packet_id, 1),
            _ => panic!("Expected Admitted for URLLC"),
        }
        match v2 {
            PipelineIngressVerdict::Admitted { packet_id, .. } => assert_eq!(packet_id, 2),
            _ => panic!("Expected Admitted for MC"),
        }
        match v3 {
            PipelineIngressVerdict::Admitted { packet_id, .. } => assert_eq!(packet_id, 3),
            _ => panic!("Expected Admitted for eMBB"),
        }
        match v4 {
            PipelineIngressVerdict::Admitted { packet_id, .. } => assert_eq!(packet_id, 4),
            _ => panic!("Expected Admitted for BE"),
        }

        let st = pipeline.channel_state(sid).unwrap();
        assert_eq!(st.total_ingress_packets, 4);
        assert_eq!(st.total_admitted_packets, 4);

        // Poll egress packets and ensure priority order (URLLC -> MC -> HighThroughput -> BestEffort)
        let poll1 = pipeline.poll_egress(sid, now_ns).unwrap();
        match poll1 {
            PipelinePollResult::Ready(p) => {
                assert_eq!(p.slice_class, FlowSliceClass::UltraLowLatency);
                assert_eq!(p.size_bytes, 256);
            }
            _ => panic!("Expected Ready for poll1"),
        }

        // BBR inflight should now reflect the 256 bytes sent
        assert_eq!(
            pipeline.bbr().subpath_state(sid).unwrap().inflight_bytes,
            256
        );

        let poll2 = pipeline.poll_egress(sid, now_ns).unwrap();
        match poll2 {
            PipelinePollResult::Ready(p) => {
                assert_eq!(p.slice_class, FlowSliceClass::MissionCritical);
                assert_eq!(p.size_bytes, 512);
            }
            _ => panic!("Expected Ready for poll2"),
        }

        let poll3 = pipeline.poll_egress(sid, now_ns).unwrap();
        match poll3 {
            PipelinePollResult::Ready(p) => {
                assert_eq!(p.slice_class, FlowSliceClass::HighThroughput);
                assert_eq!(p.size_bytes, 1024);
            }
            _ => panic!("Expected Ready for poll3"),
        }

        let poll4 = pipeline.poll_egress(sid, now_ns).unwrap();
        match poll4 {
            PipelinePollResult::Ready(p) => {
                assert_eq!(p.slice_class, FlowSliceClass::BestEffort);
                assert_eq!(p.size_bytes, 256);
            }
            _ => panic!("Expected Ready for poll4"),
        }

        let poll5 = pipeline.poll_egress(sid, now_ns).unwrap();
        assert_eq!(poll5, PipelinePollResult::Empty);

        let st_after = pipeline.channel_state(sid).unwrap();
        assert_eq!(st_after.total_egress_packets, 4);
        assert_eq!(st_after.total_egress_bytes, 256 + 512 + 1024 + 256);
    }

    #[test]
    fn test_pipeline_shaper_throttling_best_effort() {
        let mut pipeline = SubpathTrafficPipeline::new();
        let now_ns = 1_000_000_000;
        let sid = 2;

        // Bandwidth: 1 Mbps (125 KB/s) -> BestEffort 10% = 12.5 KB/s
        pipeline
            .register_subpath(sid, 1_000_000, 20_000, now_ns)
            .unwrap();

        // Exhaust BestEffort bucket with large bursts
        let mut throttled_count = 0;
        for _ in 0..50 {
            let payload = vec![0xEE; 1500];
            let verdict = pipeline
                .submit_packet(sid, FlowSliceClass::BestEffort, payload, now_ns)
                .unwrap();
            if let PipelineIngressVerdict::ThrottledByShaper { .. } = verdict {
                throttled_count += 1;
            }
        }

        assert!(
            throttled_count > 0,
            "BestEffort burst should be throttled once bucket is exhausted"
        );
        let st = pipeline.channel_state(sid).unwrap();
        assert!(st.total_throttled_packets > 0);
        assert!(st.total_throttled_bytes > 0);
    }

    #[test]
    fn test_pipeline_bbr_cwnd_limit_and_urllc_bypass() {
        let mut pipeline = SubpathTrafficPipeline::new();
        let now_ns = 1_000_000_000;
        let sid = 3;

        pipeline
            .register_subpath(sid, 10_000_000, 50_000, now_ns)
            .unwrap();

        // Artificially saturate inflight in BBR
        let cwnd = pipeline.bbr().subpath_state(sid).unwrap().cwnd_bytes;
        pipeline.bbr_mut().on_packet_sent(sid, cwnd as usize);

        // Next bulk HighThroughput packet must be blocked by CWND
        let bulk_pkt = vec![0xBB; 2048];
        let verdict_bulk = pipeline
            .submit_packet(sid, FlowSliceClass::HighThroughput, bulk_pkt, now_ns)
            .unwrap();

        match verdict_bulk {
            PipelineIngressVerdict::BlockedByCwnd {
                inflight_bytes,
                cwnd_bytes,
            } => {
                assert!(inflight_bytes >= cwnd_bytes);
            }
            _ => panic!("Expected BlockedByCwnd for HighThroughput when CWND is saturated"),
        }

        // UltraLowLatency packet must bypass CWND constraint
        let urllc_pkt = vec![0xAA; 128];
        let verdict_urllc = pipeline
            .submit_packet(sid, FlowSliceClass::UltraLowLatency, urllc_pkt, now_ns)
            .unwrap();

        match verdict_urllc {
            PipelineIngressVerdict::Admitted { .. }
            | PipelineIngressVerdict::AdmittedWithDelay { .. } => {}
            _ => panic!("Expected URLLC packet to bypass CWND constraint and be admitted"),
        }
    }

    #[test]
    fn test_pipeline_feedback_loop_and_bbr_pacing_sync() {
        let mut pipeline = SubpathTrafficPipeline::new();
        let now_ns = 1_000_000_000;
        let sid = 4;

        pipeline
            .register_subpath(sid, 10_000_000, 40_000, now_ns)
            .unwrap();

        // Initial pacing rate should be derived from 10 Mbps with startup gain (2.885x)
        let initial_pacing_rate = pipeline.pacing().pacers.get(&sid).unwrap().pacing_rate_bps;
        assert!(initial_pacing_rate > 10_000_000);

        // Feed delivery sample with 25 Mbps measured delivery rate and 25ms RTT
        let sample = DeliveryAckSample {
            delivered_bytes: 312_500, // 312.5 KB delivered in 100ms = 25 Mbps
            interval_ns: 100_000_000,
            rtt_us: 25_000,
            inflight_bytes_at_send: 50_000,
            ecn_ce_count: 0,
            lost_bytes: 0,
        };

        let result = pipeline
            .on_delivery_ack(sid, sample, now_ns + 100_000_000)
            .unwrap();

        assert_eq!(result.subpath_id, sid);
        assert_eq!(result.btl_bw_bps, 25_000_000);
        assert_eq!(result.rt_prop_us, 25_000);
        assert!(!result.backpressure_applied);
        assert_eq!(result.consecutive_clean_rounds, 1);

        // Check that Pacer has been synchronized
        let pacer = pipeline.pacing().pacers.get(&sid).unwrap();
        assert_eq!(pacer.bandwidth_bps, 25_000_000);
        assert_eq!(pacer.rtt_ms, 25);

        // Check that Shaper has been rebalanced
        let shaper = pipeline.shaper(sid).unwrap();
        assert_eq!(shaper.subpath_bandwidth_bps, 25_000_000);
    }

    #[test]
    fn test_pipeline_closed_loop_backpressure_on_loss_and_recovery() {
        let mut pipeline = SubpathTrafficPipeline::new();
        let now_ns = 1_000_000_000;
        let sid = 5;

        pipeline
            .register_subpath(sid, 10_000_000, 20_000, now_ns)
            .unwrap();

        let initial_be_rate = pipeline
            .shaper(sid)
            .unwrap()
            .limiters
            .get(&FlowSliceClass::BestEffort)
            .unwrap()
            .effective_rate_bps;
        let initial_urllc_rate = pipeline
            .shaper(sid)
            .unwrap()
            .limiters
            .get(&FlowSliceClass::UltraLowLatency)
            .unwrap()
            .effective_rate_bps;

        // Feedback with packet loss -> triggers backpressure
        // 62_500 bytes delivered in 50ms = 10 Mbps (maintains steady 10 Mbps BtlBw)
        let loss_sample = DeliveryAckSample {
            delivered_bytes: 62_500,
            interval_ns: 50_000_000,
            rtt_us: 20_000,
            inflight_bytes_at_send: 100_000,
            ecn_ce_count: 0,
            lost_bytes: 1500,
        };

        let res1 = pipeline
            .on_delivery_ack(sid, loss_sample, now_ns + 50_000_000)
            .unwrap();
        assert!(res1.backpressure_applied);
        assert_eq!(res1.active_backpressure_level_pct, 70);

        let degraded_be_rate = pipeline
            .shaper(sid)
            .unwrap()
            .limiters
            .get(&FlowSliceClass::BestEffort)
            .unwrap()
            .effective_rate_bps;
        let current_urllc_rate = pipeline
            .shaper(sid)
            .unwrap()
            .limiters
            .get(&FlowSliceClass::UltraLowLatency)
            .unwrap()
            .effective_rate_bps;

        // BestEffort rate must be degraded
        assert!(degraded_be_rate < initial_be_rate);
        // UltraLowLatency rate must NOT be degraded
        assert_eq!(current_urllc_rate, initial_urllc_rate);

        let channel = pipeline.channel_state(sid).unwrap();
        assert!(channel.in_backpressure);
        assert_eq!(channel.total_loss_events, 1);

        // Feed 3 clean samples -> backpressure should be relieved
        for i in 1..=3 {
            let clean_sample = DeliveryAckSample {
                delivered_bytes: 62_500,
                interval_ns: 50_000_000,
                rtt_us: 20_000,
                inflight_bytes_at_send: 100_000,
                ecn_ce_count: 0,
                lost_bytes: 0,
            };
            let res = pipeline
                .on_delivery_ack(sid, clean_sample, now_ns + 50_000_000 + i * 50_000_000)
                .unwrap();
            if i == 3 {
                assert!(res.backpressure_relieved);
                assert_eq!(res.active_backpressure_level_pct, 100);
            }
        }

        let restored_be_rate = pipeline
            .shaper(sid)
            .unwrap()
            .limiters
            .get(&FlowSliceClass::BestEffort)
            .unwrap()
            .effective_rate_bps;
        assert_eq!(restored_be_rate, initial_be_rate);
        assert!(!pipeline.channel_state(sid).unwrap().in_backpressure);
    }

    #[test]
    fn test_pipeline_prometheus_metrics_export() {
        let mut pipeline = SubpathTrafficPipeline::new();
        let now_ns = 1_000_000_000;
        let sid = 6;

        pipeline
            .register_subpath(sid, 10_000_000, 20_000, now_ns)
            .unwrap();

        let payload = vec![0x42; 512];
        let _ = pipeline.submit_packet(sid, FlowSliceClass::UltraLowLatency, payload, now_ns);
        let _ = pipeline.poll_egress(sid, now_ns);

        let metrics = pipeline.export_prometheus_metrics();
        assert!(metrics.contains("ifa_subpath_pipeline_ingress_packets_total{subpath_id=\"6\"} 1"));
        assert!(metrics.contains("ifa_subpath_pipeline_admitted_packets_total{subpath_id=\"6\"} 1"));
        assert!(metrics.contains("ifa_subpath_pipeline_egress_packets_total{subpath_id=\"6\"} 1"));
        assert!(metrics.contains("ifa_multipath_shaper_admitted_packets_total{subpath_id=\"6\""));
        assert!(metrics.contains("ifa_multipath_pacing_rate_bps{subpath_id=\"6\""));
        assert!(metrics.contains("ifa_multipath_bbr_btl_bw_bps{subpath_id=\"6\""));
        assert!(metrics.contains("ifa_transport_subpath_starvation_severity{subpath=\"6\""));
    }

    #[test]
    fn test_pipeline_anti_starvation_admission_token_boost() {
        let mut pipeline = SubpathTrafficPipeline::new();
        let now_ns = 1_000_000_000;
        let sid = 7;

        pipeline
            .register_subpath(sid, 10_000_000, 20_000, now_ns)
            .unwrap();

        // 1. Drain the initial BestEffort burst bucket (8192 bytes) with 5 packets (7500 bytes)
        for _ in 0..5 {
            let res =
                pipeline.submit_packet(sid, FlowSliceClass::BestEffort, vec![0xAA; 1500], now_ns);
            assert!(matches!(
                res,
                Ok(PipelineIngressVerdict::Admitted { .. }
                    | PipelineIngressVerdict::AdmittedWithDelay { .. })
            ));
        }

        // 2. Submit packets when bucket is empty to accumulate consecutive throttles
        let mut throttled_count = 0;
        for _ in 0..8 {
            let res =
                pipeline.submit_packet(sid, FlowSliceClass::BestEffort, vec![0xBB; 1500], now_ns);
            if let Ok(PipelineIngressVerdict::ThrottledByShaper { .. }) = res {
                throttled_count += 1;
            }
        }
        assert_eq!(
            throttled_count, 8,
            "Expected exactly 8 throttles to hit streak threshold"
        );

        // 3. The 9th packet arrives with exhausted bucket:
        // Starvation guard detects throttle streak >= 8 and injects an emergency token boost!
        let boost_res = pipeline.submit_packet(
            sid,
            FlowSliceClass::BestEffort,
            vec![0xCC; 1500],
            now_ns + 1_000, // 1us later, negligible token replenish
        );

        match boost_res {
            Ok(PipelineIngressVerdict::Admitted { packet_id, .. }) => {
                assert!(packet_id > 0);
            }
            Ok(PipelineIngressVerdict::AdmittedWithDelay { packet_id, .. }) => {
                assert!(packet_id > 0);
            }
            other => panic!(
                "Expected Admitted or AdmittedWithDelay via anti-starvation boost, got: {:?}",
                other
            ),
        }

        let snap = pipeline.snapshot(sid).unwrap();
        let starvation = snap.starvation.unwrap();
        let be = starvation
            .slices
            .iter()
            .find(|s| s.slice_class == FlowSliceClass::BestEffort)
            .unwrap();
        assert!(be.total_token_boost_events >= 1);
        assert!(be.total_boosted_bytes >= 1500);
    }

    #[test]
    fn test_pipeline_scheduling_starvation_promotion_with_urllc_shielding() {
        let mut pipeline = SubpathTrafficPipeline::new();
        let now_ns = 1_000_000_000;
        let sid = 8;

        pipeline
            .register_subpath(sid, 20_000_000, 10_000, now_ns)
            .unwrap();

        // Submit 1 BestEffort packet
        let be_verdict = pipeline
            .submit_packet(sid, FlowSliceClass::BestEffort, vec![0xBE; 1000], now_ns)
            .unwrap();
        let be_id = match be_verdict {
            PipelineIngressVerdict::Admitted { packet_id, .. } => packet_id,
            PipelineIngressVerdict::AdmittedWithDelay { packet_id, .. } => packet_id,
            _ => panic!("Expected BE admitted"),
        };

        // Submit 10 MissionCritical packets
        for _ in 0..10 {
            let _ = pipeline.submit_packet(
                sid,
                FlowSliceClass::MissionCritical,
                vec![0xCC; 500],
                now_ns,
            );
        }

        // Trigger consecutive higher priority serves in starvation guard
        for _ in 0..70 {
            pipeline.starvation_guard.record_packet_scheduled(
                sid,
                FlowSliceClass::MissionCritical,
                now_ns,
            );
        }

        // Also submit an UltraLowLatency packet
        let urllc_verdict = pipeline
            .submit_packet(
                sid,
                FlowSliceClass::UltraLowLatency,
                vec![0x11; 128],
                now_ns,
            )
            .unwrap();
        let urllc_id = match urllc_verdict {
            PipelineIngressVerdict::Admitted { packet_id, .. } => packet_id,
            _ => panic!("Expected URLLC admitted"),
        };

        // 1st poll: URLLC MUST be scheduled first, preserving URLLC SLA despite BestEffort starvation!
        let poll1 = pipeline.poll_egress(sid, now_ns).unwrap();
        match poll1 {
            PipelinePollResult::Ready(packet) => {
                assert_eq!(packet.packet_id, urllc_id);
                assert_eq!(packet.slice_class, FlowSliceClass::UltraLowLatency);
            }
            _ => panic!("Expected Ready for URLLC"),
        }

        // 2nd poll: With URLLC queue now empty, BestEffort starvation promotion activates
        // and preempts MissionCritical packets!
        let poll2 = pipeline.poll_egress(sid, now_ns).unwrap();
        match poll2 {
            PipelinePollResult::Ready(packet) => {
                assert_eq!(packet.packet_id, be_id);
                assert_eq!(packet.slice_class, FlowSliceClass::BestEffort);
            }
            _ => panic!("Expected Ready for promoted BestEffort packet"),
        }
    }
}

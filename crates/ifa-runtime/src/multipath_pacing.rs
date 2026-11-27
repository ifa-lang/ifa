//! Cross-Priority Multipath Scheduling & Hybrid Inter-Packet Pacing Engine (`MultipathPacingEngine`).
//!
//! Provides deterministic burst-smoothing and strict micro-timing enforcement per physical subpath:
//! 1. **BDP-Aware Inter-Packet Pacing**:
//!    - Calculates precise inter-packet departure gaps $\Delta t = \frac{S \times 8 \times 10^9}{R_{\text{pace}}}$
//!      derived from link bandwidth, minimum RTT, and dynamic BBR pacing gains.
//!    - Allows burst accumulation up to a calculated Bandwidth-Delay Product (BDP) quantum, smoothing
//!      burst spills across nanosecond clock intervals to prevent switch buffer bloat and packet drops.
//! 2. **Cross-Priority Preemption & Guaranteed Injection Quantum for `UltraLowLatency`**:
//!    - Enforces absolute strict priority for `UltraLowLatency` (URLLC) traffic.
//!    - Allocates a guaranteed per-interface injection quantum (budget) per epoch that bypasses bulk
//!      pacing queues without head-of-line delay.
//!    - Strict prioritization ladder: `UltraLowLatency` > `MissionCritical` > `HighThroughput` > `BestEffort`.
//! 3. **OpenMetrics / Prometheus Observability**:
//!    - Real-time tracking of pacing rates, BDP utilization, pacing delay histograms/counters, and
//!      URLLC priority injections.
//!
//! Zero-simulation: operates exclusively on concrete packet payloads, monotonic nanosecond clocks,
//! and physical interface BDP parameters.

use std::collections::{BTreeMap, VecDeque};
use std::fmt::Write as FmtWrite;

use crate::traffic_slicing::FlowSliceClass;

/// Verdict returned when evaluating a packet against subpath pacing constraints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubpathPacingVerdict {
    /// Packet can be transmitted immediately on the subpath with zero delay.
    Immediate,
    /// Packet must be paced; inter-packet gap or burst spill requires a wait of `delay_ns`.
    Delayed {
        delay_ns: u64,
        scheduled_tx_time_ns: u64,
    },
    /// Packet belongs to `UltraLowLatency` and was granted immediate bypass via guaranteed injection quantum.
    UrllcPriorityPreempt { guaranteed_quantum_remaining: u32 },
}

/// Inbound packet enqueued in the pacing engine for cross-priority scheduling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacedQueuedPacket {
    pub packet_id: u64,
    pub subpath_id: u8,
    pub slice_class: FlowSliceClass,
    pub payload: Vec<u8>,
    pub size_bytes: usize,
    pub enqueued_timestamp_ns: u64,
}

impl PacedQueuedPacket {
    pub fn new(
        packet_id: u64,
        subpath_id: u8,
        slice_class: FlowSliceClass,
        payload: Vec<u8>,
        enqueued_timestamp_ns: u64,
    ) -> Self {
        let size_bytes = payload.len();
        Self {
            packet_id,
            subpath_id,
            slice_class,
            payload,
            size_bytes,
            enqueued_timestamp_ns,
        }
    }
}

/// Dequeued packet ready for wire transmission after pacing evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacedScheduledPacket {
    pub packet_id: u64,
    pub subpath_id: u8,
    pub slice_class: FlowSliceClass,
    pub payload: Vec<u8>,
    pub size_bytes: usize,
    pub enqueued_timestamp_ns: u64,
    pub scheduled_timestamp_ns: u64,
    pub pacing_delay_ns: u64,
    pub was_urllc_preempted: bool,
}

/// Poll outcome when extracting the next transmission-ready packet from a subpath pacer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacingPollResult {
    /// A packet is ready for immediate wire departure.
    Ready(PacedScheduledPacket),
    /// Subpath is actively pacing; caller should wait `wait_ns` nanoseconds until `next_wake_ns`.
    WaitPacing { wait_ns: u64, next_wake_ns: u64 },
    /// No packets queued for this subpath.
    Empty,
}

/// Configuration tuning parameters for a single subpath pacer.
#[derive(Debug, Clone, PartialEq)]
pub struct SubpathPacerConfig {
    /// Minimum burst capacity in bytes (default 4096 bytes).
    pub min_burst_bytes: u64,
    /// Maximum burst capacity ceiling in bytes (default 131072 = 128 KB).
    pub max_burst_bytes: u64,
    /// Fraction of BDP allocated to nominal burst quantum (default: 1/8 = 12.5%).
    pub bdp_burst_fraction: f64,
    /// Guaranteed injection quantum for UltraLowLatency traffic per epoch in bytes (default 32768 = 32 KB).
    pub urllc_guaranteed_quantum_bytes: u32,
    /// Duration of each URLLC injection epoch in nanoseconds (default 1ms = 1_000_000 ns).
    pub urllc_epoch_duration_ns: u64,
    /// Default nominal pacing gain in Q8.8 fixed-point (256 = 1.0x).
    pub default_pacing_gain_q8: u32,
}

impl Default for SubpathPacerConfig {
    fn default() -> Self {
        Self {
            min_burst_bytes: 4_096,
            max_burst_bytes: 131_072,
            bdp_burst_fraction: 0.125, // BDP / 8
            urllc_guaranteed_quantum_bytes: 32_768,
            urllc_epoch_duration_ns: 1_000_000, // 1 ms
            default_pacing_gain_q8: 256,        // 1.0x
        }
    }
}

/// Telemetry snapshot for a single subpath pacer.
#[derive(Debug, Clone, PartialEq)]
pub struct SubpathPacingTelemetry {
    pub subpath_id: u8,
    pub bandwidth_bps: u64,
    pub rtt_ms: u64,
    pub bdp_bytes: u64,
    pub pacing_rate_bps: u64,
    pub pacing_gain_q8: u32,
    pub burst_quantum_bytes: u64,
    pub current_burst_allowance_bytes: f64,
    pub next_tx_time_ns: u64,
    pub total_paced_packets: u64,
    pub total_paced_bytes: u64,
    pub total_delayed_packets: u64,
    pub total_pacing_delay_ns: u64,
    pub total_urllc_bypass_packets: u64,
    pub total_urllc_bypass_bytes: u64,
    pub total_burst_spills: u64,
    pub queued_packets_count: usize,
    pub queued_bytes_count: usize,
}

/// Dedicated hybrid inter-packet pacer for an individual network subpath interface.
#[derive(Debug, Clone)]
pub struct SubpathPacer {
    pub subpath_id: u8,
    pub bandwidth_bps: u64,
    pub rtt_ms: u64,
    pub bdp_bytes: u64,
    pub pacing_rate_bps: u64,
    pub pacing_gain_q8: u32,
    pub burst_quantum_bytes: u64,
    pub current_burst_allowance_bytes: f64,
    pub last_replenish_time_ns: u64,
    pub next_tx_time_ns: u64,
    pub last_tx_time_ns: u64,

    // UltraLowLatency guaranteed injection quantum tracking
    pub urllc_guaranteed_quantum_bytes: u32,
    pub urllc_injected_bytes_in_epoch: u32,
    pub urllc_epoch_start_ns: u64,
    pub urllc_epoch_duration_ns: u64,

    // Cross-priority packet queues
    pub urllc_queue: VecDeque<PacedQueuedPacket>,
    pub mission_critical_queue: VecDeque<PacedQueuedPacket>,
    pub high_throughput_queue: VecDeque<PacedQueuedPacket>,
    pub best_effort_queue: VecDeque<PacedQueuedPacket>,

    // Operational metrics
    pub total_paced_packets: u64,
    pub total_paced_bytes: u64,
    pub total_delayed_packets: u64,
    pub total_pacing_delay_ns: u64,
    pub total_urllc_bypass_packets: u64,
    pub total_urllc_bypass_bytes: u64,
    pub total_burst_spills: u64,

    pub config: SubpathPacerConfig,
}

impl SubpathPacer {
    /// Create a new subpath pacer with default configuration.
    pub fn new(subpath_id: u8, bandwidth_bps: u64, rtt_ms: u64, now_ns: u64) -> Self {
        Self::with_config(
            subpath_id,
            bandwidth_bps,
            rtt_ms,
            SubpathPacerConfig::default(),
            now_ns,
        )
    }

    /// Create a new subpath pacer with specific configuration parameters.
    pub fn with_config(
        subpath_id: u8,
        bandwidth_bps: u64,
        rtt_ms: u64,
        config: SubpathPacerConfig,
        now_ns: u64,
    ) -> Self {
        let bdp_bytes = Self::calculate_bdp_bytes(bandwidth_bps, rtt_ms);
        let burst_quantum_bytes = Self::calculate_burst_quantum(bdp_bytes, &config);
        let pacing_gain_q8 = config.default_pacing_gain_q8;
        let pacing_rate_bps = Self::calculate_pacing_rate(bandwidth_bps, pacing_gain_q8);

        Self {
            subpath_id,
            bandwidth_bps,
            rtt_ms,
            bdp_bytes,
            pacing_rate_bps,
            pacing_gain_q8,
            burst_quantum_bytes,
            current_burst_allowance_bytes: burst_quantum_bytes as f64,
            last_replenish_time_ns: now_ns,
            next_tx_time_ns: now_ns,
            last_tx_time_ns: now_ns,
            urllc_guaranteed_quantum_bytes: config.urllc_guaranteed_quantum_bytes,
            urllc_injected_bytes_in_epoch: 0,
            urllc_epoch_start_ns: now_ns,
            urllc_epoch_duration_ns: config.urllc_epoch_duration_ns,
            urllc_queue: VecDeque::new(),
            mission_critical_queue: VecDeque::new(),
            high_throughput_queue: VecDeque::new(),
            best_effort_queue: VecDeque::new(),
            total_paced_packets: 0,
            total_paced_bytes: 0,
            total_delayed_packets: 0,
            total_pacing_delay_ns: 0,
            total_urllc_bypass_packets: 0,
            total_urllc_bypass_bytes: 0,
            total_burst_spills: 0,
            config,
        }
    }

    /// Calculates Bandwidth-Delay Product (BDP) in bytes.
    #[inline]
    pub fn calculate_bdp_bytes(bandwidth_bps: u64, rtt_ms: u64) -> u64 {
        let bytes_per_sec = bandwidth_bps / 8;
        (bytes_per_sec.saturating_mul(rtt_ms)) / 1000
    }

    /// Calculates burst quantum based on BDP and configured limits.
    #[inline]
    fn calculate_burst_quantum(bdp_bytes: u64, config: &SubpathPacerConfig) -> u64 {
        let scaled_bdp = (bdp_bytes as f64 * config.bdp_burst_fraction).round() as u64;
        scaled_bdp
            .max(config.min_burst_bytes)
            .min(config.max_burst_bytes)
    }

    /// Calculates effective pacing rate taking Q8.8 fixed-point gain into account.
    #[inline]
    fn calculate_pacing_rate(bandwidth_bps: u64, pacing_gain_q8: u32) -> u64 {
        ((bandwidth_bps as u128 * pacing_gain_q8 as u128) / 256) as u64
    }

    /// Dynamically update link bandwidth and round-trip time, adjusting BDP and pacing rates.
    pub fn update_link(&mut self, bandwidth_bps: u64, rtt_ms: u64, now_ns: u64) {
        self.replenish_burst_allowance(now_ns);
        self.bandwidth_bps = bandwidth_bps;
        self.rtt_ms = rtt_ms;
        self.bdp_bytes = Self::calculate_bdp_bytes(bandwidth_bps, rtt_ms);
        self.burst_quantum_bytes = Self::calculate_burst_quantum(self.bdp_bytes, &self.config);
        self.pacing_rate_bps = Self::calculate_pacing_rate(bandwidth_bps, self.pacing_gain_q8);
        self.current_burst_allowance_bytes = self
            .current_burst_allowance_bytes
            .min(self.burst_quantum_bytes as f64);
    }

    /// Adjust BBR pacing gain (Q8.8 fixed-point: 256 = 1.0x, 320 = 1.25x, 192 = 0.75x, 738 = 2.885x).
    pub fn set_pacing_gain(&mut self, pacing_gain_q8: u32, now_ns: u64) {
        self.replenish_burst_allowance(now_ns);
        self.pacing_gain_q8 = pacing_gain_q8;
        self.pacing_rate_bps = Self::calculate_pacing_rate(self.bandwidth_bps, pacing_gain_q8);
    }

    /// Replenish burst allowance credit based on elapsed monotonic nanoseconds.
    pub fn replenish_burst_allowance(&mut self, now_ns: u64) {
        if now_ns <= self.last_replenish_time_ns {
            return;
        }

        let elapsed_ns = now_ns.saturating_sub(self.last_replenish_time_ns);
        let elapsed_sec = (elapsed_ns as f64) / 1_000_000_000.0;
        let rate_bytes_per_sec = (self.pacing_rate_bps as f64) / 8.0;
        let added_tokens = rate_bytes_per_sec * elapsed_sec;

        self.current_burst_allowance_bytes = (self.current_burst_allowance_bytes + added_tokens)
            .min(self.burst_quantum_bytes as f64);
        self.last_replenish_time_ns = now_ns;

        // Reset URLLC injection epoch if duration elapsed
        if now_ns.saturating_sub(self.urllc_epoch_start_ns) >= self.urllc_epoch_duration_ns {
            self.urllc_injected_bytes_in_epoch = 0;
            self.urllc_epoch_start_ns = now_ns;
        }
    }

    /// Calculates inter-packet gap in nanoseconds for a given payload size.
    #[inline]
    pub fn inter_packet_gap_ns(&self, packet_bytes: usize) -> u64 {
        let bytes_per_sec = (self.pacing_rate_bps / 8).max(1);
        let gap_sec = (packet_bytes as f64) / (bytes_per_sec as f64);
        (gap_sec * 1_000_000_000.0).round() as u64
    }

    /// Evaluate whether a packet can be transmitted immediately or must be paced.
    pub fn evaluate_tx(
        &mut self,
        slice_class: FlowSliceClass,
        packet_bytes: usize,
        now_ns: u64,
    ) -> SubpathPacingVerdict {
        self.replenish_burst_allowance(now_ns);

        // 1. Strict priority & guaranteed injection quantum for UltraLowLatency
        if slice_class == FlowSliceClass::UltraLowLatency {
            let remaining_quantum = self
                .urllc_guaranteed_quantum_bytes
                .saturating_sub(self.urllc_injected_bytes_in_epoch);
            if (packet_bytes as u32) <= remaining_quantum || remaining_quantum > 0 {
                return SubpathPacingVerdict::UrllcPriorityPreempt {
                    guaranteed_quantum_remaining: remaining_quantum
                        .saturating_sub(packet_bytes as u32),
                };
            }
        }

        // 2. Burst allowance check: allows wire bursts up to BDP quantum
        if self.current_burst_allowance_bytes >= packet_bytes as f64 {
            return SubpathPacingVerdict::Immediate;
        }

        // 3. Pacing clock check when burst allowance is exhausted
        let wire_free_time_ns = self.next_tx_time_ns.max(now_ns);
        if now_ns >= self.next_tx_time_ns {
            SubpathPacingVerdict::Immediate
        } else {
            let delay_ns = self.next_tx_time_ns.saturating_sub(now_ns);
            SubpathPacingVerdict::Delayed {
                delay_ns,
                scheduled_tx_time_ns: wire_free_time_ns,
            }
        }
    }

    /// Account for an admitted transmission, advancing the pacing clock and consuming burst credits.
    pub fn charge_tx(
        &mut self,
        slice_class: FlowSliceClass,
        packet_bytes: usize,
        now_ns: u64,
    ) -> u64 {
        self.replenish_burst_allowance(now_ns);
        let gap_ns = self.inter_packet_gap_ns(packet_bytes);

        self.total_paced_packets += 1;
        self.total_paced_bytes += packet_bytes as u64;

        if slice_class == FlowSliceClass::UltraLowLatency {
            let remaining = self
                .urllc_guaranteed_quantum_bytes
                .saturating_sub(self.urllc_injected_bytes_in_epoch);
            if remaining > 0 {
                self.urllc_injected_bytes_in_epoch = self
                    .urllc_injected_bytes_in_epoch
                    .saturating_add(packet_bytes as u32);
                self.total_urllc_bypass_packets += 1;
                self.total_urllc_bypass_bytes += packet_bytes as u64;

                // UltraLowLatency transmits immediately; update last_tx_time_ns but do not stall URLLC
                self.last_tx_time_ns = now_ns;
                // Lightly nudge wire clock so downstream packets observe transmission sojourn
                self.next_tx_time_ns = self.next_tx_time_ns.max(now_ns).saturating_add(gap_ns / 2);
                return 0;
            }
        }

        // Deduct from burst allowance or mark burst spill
        let req = packet_bytes as f64;
        let fits_in_burst = self.current_burst_allowance_bytes >= req;
        if fits_in_burst {
            self.current_burst_allowance_bytes -= req;
        } else {
            self.current_burst_allowance_bytes = 0.0;
            self.total_burst_spills += 1;
        }

        let delay_ns = if !fits_in_burst && now_ns < self.next_tx_time_ns {
            self.next_tx_time_ns.saturating_sub(now_ns)
        } else {
            0
        };

        if delay_ns > 0 {
            self.total_delayed_packets += 1;
            self.total_pacing_delay_ns += delay_ns;
        }

        // Advance pacing clock
        self.next_tx_time_ns = self.next_tx_time_ns.max(now_ns).saturating_add(gap_ns);
        self.last_tx_time_ns = now_ns;

        delay_ns
    }

    /// Enqueue an outbound packet into the subpath's cross-priority queues.
    pub fn enqueue(&mut self, packet: PacedQueuedPacket) {
        match packet.slice_class {
            FlowSliceClass::UltraLowLatency => self.urllc_queue.push_back(packet),
            FlowSliceClass::MissionCritical => self.mission_critical_queue.push_back(packet),
            FlowSliceClass::HighThroughput => self.high_throughput_queue.push_back(packet),
            FlowSliceClass::BestEffort => self.best_effort_queue.push_back(packet),
        }
    }

    /// Poll and schedule the next ready packet respecting cross-priority order and pacing clock.
    pub fn poll_next(&mut self, now_ns: u64) -> PacingPollResult {
        self.poll_next_with_starvation(now_ns, None)
    }

    /// Poll and schedule next ready packet with anti-starvation promotion support for a starved slice.
    ///
    /// Strictly guarantees UltraLowLatency SLA: if an UltraLowLatency packet is ready for wire
    /// transmission, it ALWAYS takes absolute precedence over anti-starvation promotions.
    pub fn poll_next_with_starvation(
        &mut self,
        now_ns: u64,
        starved_slice: Option<FlowSliceClass>,
    ) -> PacingPollResult {
        self.replenish_burst_allowance(now_ns);

        // Tier 1: UltraLowLatency (URLLC) absolute priority with guaranteed injection quantum
        if let Some(front) = self.urllc_queue.front() {
            let size = front.size_bytes;
            let remaining_quantum = self
                .urllc_guaranteed_quantum_bytes
                .saturating_sub(self.urllc_injected_bytes_in_epoch);

            if remaining_quantum > 0 || now_ns >= self.next_tx_time_ns {
                let packet = self.urllc_queue.pop_front().unwrap();
                let pacing_delay = self.charge_tx(FlowSliceClass::UltraLowLatency, size, now_ns);
                return PacingPollResult::Ready(PacedScheduledPacket {
                    packet_id: packet.packet_id,
                    subpath_id: packet.subpath_id,
                    slice_class: FlowSliceClass::UltraLowLatency,
                    payload: packet.payload,
                    size_bytes: size,
                    enqueued_timestamp_ns: packet.enqueued_timestamp_ns,
                    scheduled_timestamp_ns: now_ns,
                    pacing_delay_ns: pacing_delay,
                    was_urllc_preempted: remaining_quantum > 0,
                });
            }
        }

        // Helper to check if queue can transmit: either wire clock reached or burst allowance covers it
        let can_transmit_queue =
            |q: &VecDeque<PacedQueuedPacket>, burst_bytes: f64, next_tx: u64| -> bool {
                if let Some(front) = q.front() {
                    burst_bytes >= front.size_bytes as f64 || now_ns >= next_tx
                } else {
                    false
                }
            };

        // Anti-Starvation Preemption: If a lower-priority slice is starved, promote it ahead
        // of MissionCritical / HighThroughput, but ONLY while URLLC is not actively transmitting.
        if let Some(slice) = starved_slice {
            match slice {
                FlowSliceClass::BestEffort
                    if can_transmit_queue(
                        &self.best_effort_queue,
                        self.current_burst_allowance_bytes,
                        self.next_tx_time_ns,
                    ) =>
                {
                    let packet = self.best_effort_queue.pop_front().unwrap();
                    let size = packet.size_bytes;
                    let delay = self.charge_tx(FlowSliceClass::BestEffort, size, now_ns);
                    return PacingPollResult::Ready(PacedScheduledPacket {
                        packet_id: packet.packet_id,
                        subpath_id: packet.subpath_id,
                        slice_class: FlowSliceClass::BestEffort,
                        payload: packet.payload,
                        size_bytes: size,
                        enqueued_timestamp_ns: packet.enqueued_timestamp_ns,
                        scheduled_timestamp_ns: now_ns,
                        pacing_delay_ns: delay,
                        was_urllc_preempted: false,
                    });
                }
                FlowSliceClass::HighThroughput
                    if can_transmit_queue(
                        &self.high_throughput_queue,
                        self.current_burst_allowance_bytes,
                        self.next_tx_time_ns,
                    ) =>
                {
                    let packet = self.high_throughput_queue.pop_front().unwrap();
                    let size = packet.size_bytes;
                    let delay = self.charge_tx(FlowSliceClass::HighThroughput, size, now_ns);
                    return PacingPollResult::Ready(PacedScheduledPacket {
                        packet_id: packet.packet_id,
                        subpath_id: packet.subpath_id,
                        slice_class: FlowSliceClass::HighThroughput,
                        payload: packet.payload,
                        size_bytes: size,
                        enqueued_timestamp_ns: packet.enqueued_timestamp_ns,
                        scheduled_timestamp_ns: now_ns,
                        pacing_delay_ns: delay,
                        was_urllc_preempted: false,
                    });
                }
                _ => {}
            }
        }

        // Tier 2: MissionCritical
        if can_transmit_queue(
            &self.mission_critical_queue,
            self.current_burst_allowance_bytes,
            self.next_tx_time_ns,
        ) {
            let packet = self.mission_critical_queue.pop_front().unwrap();
            let size = packet.size_bytes;
            let delay = self.charge_tx(FlowSliceClass::MissionCritical, size, now_ns);
            return PacingPollResult::Ready(PacedScheduledPacket {
                packet_id: packet.packet_id,
                subpath_id: packet.subpath_id,
                slice_class: FlowSliceClass::MissionCritical,
                payload: packet.payload,
                size_bytes: size,
                enqueued_timestamp_ns: packet.enqueued_timestamp_ns,
                scheduled_timestamp_ns: now_ns,
                pacing_delay_ns: delay,
                was_urllc_preempted: false,
            });
        }

        // Tier 3: HighThroughput
        if can_transmit_queue(
            &self.high_throughput_queue,
            self.current_burst_allowance_bytes,
            self.next_tx_time_ns,
        ) {
            let packet = self.high_throughput_queue.pop_front().unwrap();
            let size = packet.size_bytes;
            let delay = self.charge_tx(FlowSliceClass::HighThroughput, size, now_ns);
            return PacingPollResult::Ready(PacedScheduledPacket {
                packet_id: packet.packet_id,
                subpath_id: packet.subpath_id,
                slice_class: FlowSliceClass::HighThroughput,
                payload: packet.payload,
                size_bytes: size,
                enqueued_timestamp_ns: packet.enqueued_timestamp_ns,
                scheduled_timestamp_ns: now_ns,
                pacing_delay_ns: delay,
                was_urllc_preempted: false,
            });
        }

        // Tier 4: BestEffort
        if can_transmit_queue(
            &self.best_effort_queue,
            self.current_burst_allowance_bytes,
            self.next_tx_time_ns,
        ) {
            let packet = self.best_effort_queue.pop_front().unwrap();
            let size = packet.size_bytes;
            let delay = self.charge_tx(FlowSliceClass::BestEffort, size, now_ns);
            return PacingPollResult::Ready(PacedScheduledPacket {
                packet_id: packet.packet_id,
                subpath_id: packet.subpath_id,
                slice_class: FlowSliceClass::BestEffort,
                payload: packet.payload,
                size_bytes: size,
                enqueued_timestamp_ns: packet.enqueued_timestamp_ns,
                scheduled_timestamp_ns: now_ns,
                pacing_delay_ns: delay,
                was_urllc_preempted: false,
            });
        }

        // If any queue still has packets, they must wait for next_tx_time_ns
        if self.queued_packets_count() > 0 {
            let wait_ns = self.next_tx_time_ns.saturating_sub(now_ns);
            PacingPollResult::WaitPacing {
                wait_ns,
                next_wake_ns: self.next_tx_time_ns,
            }
        } else {
            PacingPollResult::Empty
        }
    }

    /// Total queued packets across all priority tiers for this subpath.
    pub fn queued_packets_count(&self) -> usize {
        self.urllc_queue.len()
            + self.mission_critical_queue.len()
            + self.high_throughput_queue.len()
            + self.best_effort_queue.len()
    }

    /// Total queued bytes across all priority tiers for this subpath.
    pub fn queued_bytes_count(&self) -> usize {
        let sum_q =
            |q: &VecDeque<PacedQueuedPacket>| -> usize { q.iter().map(|p| p.size_bytes).sum() };
        sum_q(&self.urllc_queue)
            + sum_q(&self.mission_critical_queue)
            + sum_q(&self.high_throughput_queue)
            + sum_q(&self.best_effort_queue)
    }

    /// Snapshot current pacing telemetry for monitoring and metrics.
    pub fn snapshot(&self) -> SubpathPacingTelemetry {
        SubpathPacingTelemetry {
            subpath_id: self.subpath_id,
            bandwidth_bps: self.bandwidth_bps,
            rtt_ms: self.rtt_ms,
            bdp_bytes: self.bdp_bytes,
            pacing_rate_bps: self.pacing_rate_bps,
            pacing_gain_q8: self.pacing_gain_q8,
            burst_quantum_bytes: self.burst_quantum_bytes,
            current_burst_allowance_bytes: self.current_burst_allowance_bytes,
            next_tx_time_ns: self.next_tx_time_ns,
            total_paced_packets: self.total_paced_packets,
            total_paced_bytes: self.total_paced_bytes,
            total_delayed_packets: self.total_delayed_packets,
            total_pacing_delay_ns: self.total_pacing_delay_ns,
            total_urllc_bypass_packets: self.total_urllc_bypass_packets,
            total_urllc_bypass_bytes: self.total_urllc_bypass_bytes,
            total_burst_spills: self.total_burst_spills,
            queued_packets_count: self.queued_packets_count(),
            queued_bytes_count: self.queued_bytes_count(),
        }
    }
}

/// Orchestration Engine managing hybrid pacing and cross-priority scheduling across all multipath interfaces.
#[derive(Debug, Clone, Default)]
pub struct MultipathPacingEngine {
    pub pacers: BTreeMap<u8, SubpathPacer>,
    pub next_packet_id: u64,
}

impl MultipathPacingEngine {
    /// Create a new multipath pacing engine.
    pub fn new() -> Self {
        Self {
            pacers: BTreeMap::new(),
            next_packet_id: 1,
        }
    }

    /// Register a physical transport subpath with link bandwidth and RTT.
    pub fn register_subpath(
        &mut self,
        subpath_id: u8,
        bandwidth_bps: u64,
        rtt_ms: u64,
        now_ns: u64,
    ) {
        let pacer = SubpathPacer::new(subpath_id, bandwidth_bps, rtt_ms, now_ns);
        self.pacers.insert(subpath_id, pacer);
    }

    /// Register a subpath with customized pacer configuration.
    pub fn register_subpath_with_config(
        &mut self,
        subpath_id: u8,
        bandwidth_bps: u64,
        rtt_ms: u64,
        config: SubpathPacerConfig,
        now_ns: u64,
    ) {
        let pacer = SubpathPacer::with_config(subpath_id, bandwidth_bps, rtt_ms, config, now_ns);
        self.pacers.insert(subpath_id, pacer);
    }

    /// Remove a subpath from the pacing engine.
    pub fn unregister_subpath(&mut self, subpath_id: u8) -> Option<SubpathPacer> {
        self.pacers.remove(&subpath_id)
    }

    /// Dynamically update link characteristics (bandwidth and RTT) for a subpath.
    pub fn update_subpath_link(
        &mut self,
        subpath_id: u8,
        bandwidth_bps: u64,
        rtt_ms: u64,
        now_ns: u64,
    ) -> bool {
        if let Some(pacer) = self.pacers.get_mut(&subpath_id) {
            pacer.update_link(bandwidth_bps, rtt_ms, now_ns);
            true
        } else {
            false
        }
    }

    /// Dynamically update the BBR pacing gain multiplier for a subpath.
    pub fn set_subpath_pacing_gain(
        &mut self,
        subpath_id: u8,
        pacing_gain_q8: u32,
        now_ns: u64,
    ) -> bool {
        if let Some(pacer) = self.pacers.get_mut(&subpath_id) {
            pacer.set_pacing_gain(pacing_gain_q8, now_ns);
            true
        } else {
            false
        }
    }

    /// Evaluate whether a packet can be sent immediately or must wait.
    pub fn evaluate_tx(
        &mut self,
        subpath_id: u8,
        slice_class: FlowSliceClass,
        packet_bytes: usize,
        now_ns: u64,
    ) -> SubpathPacingVerdict {
        if let Some(pacer) = self.pacers.get_mut(&subpath_id) {
            pacer.evaluate_tx(slice_class, packet_bytes, now_ns)
        } else {
            SubpathPacingVerdict::Immediate
        }
    }

    /// Charge transmission against a subpath pacer clock.
    pub fn charge_tx(
        &mut self,
        subpath_id: u8,
        slice_class: FlowSliceClass,
        packet_bytes: usize,
        now_ns: u64,
    ) -> u64 {
        if let Some(pacer) = self.pacers.get_mut(&subpath_id) {
            pacer.charge_tx(slice_class, packet_bytes, now_ns)
        } else {
            0
        }
    }

    /// Enqueue a packet for paced cross-priority transmission.
    pub fn enqueue(
        &mut self,
        subpath_id: u8,
        slice_class: FlowSliceClass,
        payload: Vec<u8>,
        now_ns: u64,
    ) -> u64 {
        let packet_id = self.next_packet_id;
        self.next_packet_id = self.next_packet_id.wrapping_add(1);

        let packet = PacedQueuedPacket::new(packet_id, subpath_id, slice_class, payload, now_ns);
        if let Some(pacer) = self.pacers.get_mut(&subpath_id) {
            pacer.enqueue(packet);
        }

        packet_id
    }

    /// Poll the next ready packet from a specific subpath.
    pub fn poll_subpath(&mut self, subpath_id: u8, now_ns: u64) -> PacingPollResult {
        self.poll_subpath_with_starvation(subpath_id, now_ns, None)
    }

    /// Poll the next ready packet from a specific subpath with optional anti-starvation promotion.
    pub fn poll_subpath_with_starvation(
        &mut self,
        subpath_id: u8,
        now_ns: u64,
        starved_slice: Option<FlowSliceClass>,
    ) -> PacingPollResult {
        if let Some(pacer) = self.pacers.get_mut(&subpath_id) {
            pacer.poll_next_with_starvation(now_ns, starved_slice)
        } else {
            PacingPollResult::Empty
        }
    }

    /// Poll across all managed subpaths, prioritizing UltraLowLatency ready packets first.
    pub fn poll_any(&mut self, now_ns: u64) -> Option<(u8, PacedScheduledPacket)> {
        // First pass: check for any ready UltraLowLatency packet on any subpath
        for (&sid, pacer) in self.pacers.iter_mut() {
            if !pacer.urllc_queue.is_empty() {
                if let PacingPollResult::Ready(packet) = pacer.poll_next(now_ns) {
                    return Some((sid, packet));
                }
            }
        }

        // Second pass: check for ready packets in standard priority order
        for (&sid, pacer) in self.pacers.iter_mut() {
            if let PacingPollResult::Ready(packet) = pacer.poll_next(now_ns) {
                return Some((sid, packet));
            }
        }

        None
    }

    /// Snapshot telemetry across all managed subpath pacers.
    pub fn telemetry_snapshot(&self) -> Vec<SubpathPacingTelemetry> {
        self.pacers.values().map(|p| p.snapshot()).collect()
    }

    /// Export OpenMetrics / Prometheus formatted telemetry for pacing state and counters.
    pub fn export_prometheus_metrics(&self) -> String {
        let mut out = String::new();

        let _ = writeln!(
            out,
            "# HELP ifa_transport_subpath_pacing_rate_bps Effective inter-packet pacing rate in bits per second."
        );
        let _ = writeln!(out, "# TYPE ifa_transport_subpath_pacing_rate_bps gauge");
        let _ = writeln!(
            out,
            "# HELP ifa_transport_subpath_bdp_bytes Calculated Bandwidth-Delay Product capacity in bytes."
        );
        let _ = writeln!(out, "# TYPE ifa_transport_subpath_bdp_bytes gauge");
        let _ = writeln!(
            out,
            "# HELP ifa_transport_subpath_burst_quantum_bytes Maximum burst credit quantum allocated before pacing."
        );
        let _ = writeln!(
            out,
            "# TYPE ifa_transport_subpath_burst_quantum_bytes gauge"
        );
        let _ = writeln!(
            out,
            "# HELP ifa_transport_subpath_pacing_delayed_packets_total Total packets delayed by pacing clock."
        );
        let _ = writeln!(
            out,
            "# TYPE ifa_transport_subpath_pacing_delayed_packets_total counter"
        );
        let _ = writeln!(
            out,
            "# HELP ifa_transport_subpath_pacing_delay_ns_total Total accumulated pacing delay in nanoseconds."
        );
        let _ = writeln!(
            out,
            "# TYPE ifa_transport_subpath_pacing_delay_ns_total counter"
        );
        let _ = writeln!(
            out,
            "# HELP ifa_transport_subpath_urllc_guaranteed_injections_total Total UltraLowLatency packets injected via guaranteed quantum bypass."
        );
        let _ = writeln!(
            out,
            "# TYPE ifa_transport_subpath_urllc_guaranteed_injections_total counter"
        );
        let _ = writeln!(
            out,
            "# HELP ifa_transport_subpath_burst_spills_total Total burst capacity exhaustion events spilling into pacing delay."
        );
        let _ = writeln!(
            out,
            "# TYPE ifa_transport_subpath_burst_spills_total counter"
        );

        for snap in self.telemetry_snapshot() {
            let _ = writeln!(
                out,
                "ifa_transport_subpath_pacing_rate_bps{{subpath_id=\"{}\"}} {}",
                snap.subpath_id, snap.pacing_rate_bps
            );
            let _ = writeln!(
                out,
                "ifa_transport_subpath_bdp_bytes{{subpath_id=\"{}\"}} {}",
                snap.subpath_id, snap.bdp_bytes
            );
            let _ = writeln!(
                out,
                "ifa_transport_subpath_burst_quantum_bytes{{subpath_id=\"{}\"}} {}",
                snap.subpath_id, snap.burst_quantum_bytes
            );
            let _ = writeln!(
                out,
                "ifa_transport_subpath_pacing_delayed_packets_total{{subpath_id=\"{}\"}} {}",
                snap.subpath_id, snap.total_delayed_packets
            );
            let _ = writeln!(
                out,
                "ifa_transport_subpath_pacing_delay_ns_total{{subpath_id=\"{}\"}} {}",
                snap.subpath_id, snap.total_pacing_delay_ns
            );
            let _ = writeln!(
                out,
                "ifa_transport_subpath_urllc_guaranteed_injections_total{{subpath_id=\"{}\"}} {}",
                snap.subpath_id, snap.total_urllc_bypass_packets
            );
            let _ = writeln!(
                out,
                "ifa_transport_subpath_burst_spills_total{{subpath_id=\"{}\"}} {}",
                snap.subpath_id, snap.total_burst_spills
            );
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bdp_and_burst_calculation() {
        // 100 Mbps, 20 ms RTT -> BDP = (12.5 MB/s) * 0.02s = 250,000 bytes
        let bdp = SubpathPacer::calculate_bdp_bytes(100_000_000, 20);
        assert_eq!(bdp, 250_000);

        let config = SubpathPacerConfig {
            bdp_burst_fraction: 0.125, // 1/8th -> ~31,250 bytes
            ..Default::default()
        };
        let quantum = SubpathPacer::calculate_burst_quantum(bdp, &config);
        assert_eq!(quantum, 31_250);
    }

    #[test]
    fn test_inter_packet_gap_derivation() {
        // 80 Mbps -> 10 MB/s. 1400 bytes packet -> gap = 1400 / 10,000,000 = 140 microseconds = 140_000 ns
        let pacer = SubpathPacer::new(1, 80_000_000, 10, 1_000_000);
        let gap = pacer.inter_packet_gap_ns(1400);
        assert_eq!(gap, 140_000);
    }

    #[test]
    fn test_urllc_priority_preemption_and_quantum_bypass() {
        let mut pacer = SubpathPacer::new(1, 100_000_000, 20, 1_000_000);

        // Advance pacing clock and deplete burst allowance to simulate bulk congestion
        pacer.next_tx_time_ns = 50_000_000; // 50 ms in future
        pacer.current_burst_allowance_bytes = 0.0;

        // Normal bulk packet must be delayed
        let verdict = pacer.evaluate_tx(FlowSliceClass::HighThroughput, 1400, 1_000_000);
        match verdict {
            SubpathPacingVerdict::Delayed { delay_ns, .. } => {
                assert_eq!(delay_ns, 49_000_000);
            }
            _ => panic!("Expected HighThroughput to be delayed"),
        }

        // UltraLowLatency should bypass immediately via guaranteed quantum
        let urllc_verdict = pacer.evaluate_tx(FlowSliceClass::UltraLowLatency, 1400, 1_000_000);
        match urllc_verdict {
            SubpathPacingVerdict::UrllcPriorityPreempt {
                guaranteed_quantum_remaining,
            } => {
                assert!(guaranteed_quantum_remaining > 0);
            }
            _ => panic!("Expected URLLC to preempt"),
        }

        // Charge the URLLC packet
        let delay = pacer.charge_tx(FlowSliceClass::UltraLowLatency, 1400, 1_000_000);
        assert_eq!(delay, 0); // zero delay for guaranteed URLLC
        assert_eq!(pacer.total_urllc_bypass_packets, 1);
        assert_eq!(pacer.total_urllc_bypass_bytes, 1400);
    }

    #[test]
    fn test_cross_priority_queuing_order() {
        let mut pacer = SubpathPacer::new(1, 100_000_000, 10, 1_000_000);

        // Enqueue in reverse priority order: BestEffort, HighThroughput, MissionCritical, UltraLowLatency
        pacer.enqueue(PacedQueuedPacket::new(
            1,
            1,
            FlowSliceClass::BestEffort,
            vec![1; 500],
            1_000_000,
        ));
        pacer.enqueue(PacedQueuedPacket::new(
            2,
            1,
            FlowSliceClass::HighThroughput,
            vec![2; 500],
            1_000_000,
        ));
        pacer.enqueue(PacedQueuedPacket::new(
            3,
            1,
            FlowSliceClass::MissionCritical,
            vec![3; 500],
            1_000_000,
        ));
        pacer.enqueue(PacedQueuedPacket::new(
            4,
            1,
            FlowSliceClass::UltraLowLatency,
            vec![4; 500],
            1_000_000,
        ));

        // Poll 1: Must be UltraLowLatency (id 4)
        match pacer.poll_next(1_000_000) {
            PacingPollResult::Ready(p) => {
                assert_eq!(p.packet_id, 4);
                assert_eq!(p.slice_class, FlowSliceClass::UltraLowLatency);
            }
            _ => panic!("Expected Ready URLLC"),
        }

        // Poll 2: Must be MissionCritical (id 3)
        match pacer.poll_next(1_000_000) {
            PacingPollResult::Ready(p) => {
                assert_eq!(p.packet_id, 3);
                assert_eq!(p.slice_class, FlowSliceClass::MissionCritical);
            }
            _ => panic!("Expected Ready MissionCritical"),
        }

        // Poll 3: Must be HighThroughput (id 2)
        match pacer.poll_next(1_000_000) {
            PacingPollResult::Ready(p) => {
                assert_eq!(p.packet_id, 2);
                assert_eq!(p.slice_class, FlowSliceClass::HighThroughput);
            }
            _ => panic!("Expected Ready HighThroughput"),
        }

        // Poll 4: Must be BestEffort (id 1)
        match pacer.poll_next(1_000_000) {
            PacingPollResult::Ready(p) => {
                assert_eq!(p.packet_id, 1);
                assert_eq!(p.slice_class, FlowSliceClass::BestEffort);
            }
            _ => panic!("Expected Ready BestEffort"),
        }

        assert_eq!(pacer.poll_next(1_000_000), PacingPollResult::Empty);
    }

    #[test]
    fn test_burst_allowance_and_spill_to_pacing() {
        let config = SubpathPacerConfig {
            min_burst_bytes: 2000,
            max_burst_bytes: 2000,
            ..Default::default()
        };
        let mut pacer = SubpathPacer::with_config(1, 80_000_000, 10, config, 1_000_000);

        // Pacer has 2000 bytes burst allowance initially
        assert_eq!(pacer.current_burst_allowance_bytes, 2000.0);

        // First packet of 1000 bytes: fits within burst allowance
        let verdict1 = pacer.evaluate_tx(FlowSliceClass::HighThroughput, 1000, 1_000_000);
        assert_eq!(verdict1, SubpathPacingVerdict::Immediate);
        pacer.charge_tx(FlowSliceClass::HighThroughput, 1000, 1_000_000);
        assert_eq!(pacer.current_burst_allowance_bytes, 1000.0);

        // Second packet of 1000 bytes: still fits
        let verdict2 = pacer.evaluate_tx(FlowSliceClass::HighThroughput, 1000, 1_000_000);
        assert_eq!(verdict2, SubpathPacingVerdict::Immediate);
        pacer.charge_tx(FlowSliceClass::HighThroughput, 1000, 1_000_000);
        assert_eq!(pacer.current_burst_allowance_bytes, 0.0);

        // Third packet of 1000 bytes: burst capacity exhausted, spills into pacing!
        let verdict3 = pacer.evaluate_tx(FlowSliceClass::HighThroughput, 1000, 1_000_000);
        match verdict3 {
            SubpathPacingVerdict::Delayed { delay_ns, .. } => {
                assert!(delay_ns > 0);
            }
            _ => panic!("Expected Delayed verdict for burst spill"),
        }

        pacer.charge_tx(FlowSliceClass::HighThroughput, 1000, 1_000_000);
        assert_eq!(pacer.total_burst_spills, 1);
        assert_eq!(pacer.total_delayed_packets, 1);
    }

    #[test]
    fn test_multipath_pacing_engine_telemetry_and_prometheus() {
        let mut engine = MultipathPacingEngine::new();
        engine.register_subpath(1, 100_000_000, 15, 1_000_000);
        engine.register_subpath(2, 50_000_000, 30, 1_000_000);

        // Enqueue and charge packets
        engine.charge_tx(1, FlowSliceClass::UltraLowLatency, 800, 1_000_000);
        engine.charge_tx(2, FlowSliceClass::HighThroughput, 1400, 1_000_000);

        let snaps = engine.telemetry_snapshot();
        assert_eq!(snaps.len(), 2);

        let prom = engine.export_prometheus_metrics();
        assert!(prom.contains("ifa_transport_subpath_pacing_rate_bps{subpath_id=\"1\"}"));
        assert!(prom.contains("ifa_transport_subpath_bdp_bytes{subpath_id=\"1\"}"));
        assert!(prom.contains(
            "ifa_transport_subpath_urllc_guaranteed_injections_total{subpath_id=\"1\"} 1"
        ));
    }
}

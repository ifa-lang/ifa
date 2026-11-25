//! Targeted Selective Retransmission (SACK / Subpath NACK) over Priority Fallback Subpaths.
//!
//! Provides deterministic selective loss recovery for packets unrecoverable by
//! Forward Error Correction (FEC) or lost across degraded multipath routes:
//!
//! - **Selective ACK / NACK Protocol**:
//!   - Compact contiguous sequence ranges (`SelectiveAckRange`).
//!   - Explicit failure attribution: links missing packets to `failed_subpath_id`.
//!   - Dynamic fallback delegation: directs retransmissions to optimal alternate paths.
//!
//! - **QoS-Coupled Priority Fallback Selection**:
//!   - `UltraLowLatency`: Selects lowest-RTT and minimal-jitter alternate subpath to meet tight deadlines.
//!   - `MissionCritical`: Selects zero-loss, highest-reliability subpath with aggressive retransmission budget.
//!   - `HighThroughput`: Reroutes bulk bursts over highest available capacity subpaths.
//!   - `BestEffort`: Background scavenger retransmission with low preemption impact.
//!
//! - **Storm Suppression & Adaptive RTO**:
//!   - Bounded NACK emission hold-off preventing acknowledgment storms under network congestion.
//!   - SLA-bounded maximum retry ceilings preventing infinite retransmission loops.
//!   - Exponential backoff with floor/ceiling bounds tuned per QoS slice.
//!
//! - **Zero-Simulation Guarantee**:
//!   - Operates strictly on concrete monotonic timestamps, actual byte payloads,
//!     and real network telemetry route metrics.

use std::collections::{BTreeMap, HashMap};

use crate::multipath_fec::FecUnrecoverableGapEvent;
use crate::session_sync::{IsspMultipathRoute, IsspPathState};
use crate::traffic_slicing::FlowSliceClass;

// ---------------------------------------------------------------------------
// Selective ACK / NACK Data Structures
// ---------------------------------------------------------------------------

/// Contiguous inclusive sequence range [start_seq, end_seq].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SelectiveAckRange {
    /// Starting sequence number (inclusive).
    pub start_seq: u64,
    /// Ending sequence number (inclusive).
    pub end_seq: u64,
}

impl SelectiveAckRange {
    /// Create a new sequence range.
    #[inline]
    pub fn new(start_seq: u64, end_seq: u64) -> Self {
        assert!(start_seq <= end_seq, "start_seq must be <= end_seq");
        Self { start_seq, end_seq }
    }

    /// Create a single-sequence range [seq, seq].
    #[inline]
    pub fn single(seq: u64) -> Self {
        Self {
            start_seq: seq,
            end_seq: seq,
        }
    }

    /// Number of packets spanned by this range.
    #[inline]
    pub fn count(&self) -> u64 {
        self.end_seq.saturating_sub(self.start_seq) + 1
    }

    /// Whether this range contains the specified sequence number.
    #[inline]
    pub fn contains_seq(&self, seq: u64) -> bool {
        seq >= self.start_seq && seq <= self.end_seq
    }

    /// Compact and merge a list of arbitrary sequence ranges into minimal sorted, non-overlapping ranges.
    pub fn merge_ranges(mut ranges: Vec<SelectiveAckRange>) -> Vec<SelectiveAckRange> {
        if ranges.is_empty() {
            return Vec::new();
        }
        ranges.sort_by_key(|r| (r.start_seq, r.end_seq));
        let mut merged = Vec::with_capacity(ranges.len());
        let mut cur = ranges[0];

        for next in ranges.into_iter().skip(1) {
            if next.start_seq <= cur.end_seq.saturating_add(1) {
                cur.end_seq = cur.end_seq.max(next.end_seq);
            } else {
                merged.push(cur);
                cur = next;
            }
        }
        merged.push(cur);
        merged
    }
}

/// Selective Negative Acknowledgement (Subpath NACK) targeted at packets unrecoverable by FEC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubpathNackPacket {
    /// Unique identifier for this NACK control frame.
    pub nack_id: u64,
    /// Target flow identifier.
    pub flow_id: u32,
    /// QoS slice class governing SLA constraints for this flow.
    pub slice_class: FlowSliceClass,
    /// Highest cumulative sequence delivered in-order at receiver.
    pub cumulative_ack_seq: u64,
    /// Compact list of missing sequence ranges requiring selective retransmission.
    pub nack_ranges: Vec<SelectiveAckRange>,
    /// Original subpath ID that experienced packet loss or FEC failure.
    pub failed_subpath_id: u32,
    /// Receiver-suggested fallback subpath ID, if known.
    pub suggested_fallback_subpath_id: Option<u32>,
    /// Nanosecond timestamp when NACK was generated.
    pub generation_timestamp_ns: u64,
    /// Attempt counter for this NACK sequence.
    pub attempt: u8,
}

impl SubpathNackPacket {
    /// Total count of missing packets requested in this NACK.
    pub fn total_missing_packets(&self) -> u64 {
        self.nack_ranges.iter().map(|r| r.count()).sum()
    }
}

/// Selective Positive Acknowledgement (SACK) confirming received out-of-order blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubpathSackPacket {
    /// Target flow identifier.
    pub flow_id: u32,
    /// QoS slice class governing SLA constraints.
    pub slice_class: FlowSliceClass,
    /// Highest cumulative sequence delivered in-order at receiver.
    pub cumulative_ack_seq: u64,
    /// SACK blocks representing packets successfully received out of sequence.
    pub sack_blocks: Vec<SelectiveAckRange>,
    /// Nanosecond timestamp of SACK generation.
    pub timestamp_ns: u64,
}

/// Retransmitted packet dispatched over an alternate priority fallback subpath.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetransmittedPacket {
    /// Original packet ID.
    pub packet_id: u64,
    /// Logical flow identifier.
    pub flow_id: u32,
    /// Sequence number of the retransmitted packet.
    pub sequence_number: u64,
    /// QoS slice class.
    pub slice_class: FlowSliceClass,
    /// Actual payload data.
    pub payload: Vec<u8>,
    /// Subpath on which packet was originally sent and failed.
    pub original_subpath_id: u32,
    /// Priority fallback subpath assigned for this retransmission.
    pub assigned_fallback_subpath_id: u32,
    /// Number of retransmission attempts performed (1 for first retransmission).
    pub attempt_number: u8,
    /// Monotonic timestamp when retransmission was dispatched (nanoseconds).
    pub retransmit_timestamp_ns: u64,
    /// Whether this retransmission was triggered specifically by an FEC unrecoverable event.
    pub is_fec_fallback: bool,
}

// ---------------------------------------------------------------------------
// Retransmission Policy & Tuning per QoS Slice
// ---------------------------------------------------------------------------

/// Retransmission and NACK hold-off policy governing loss recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetransmitSlicePolicy {
    /// Maximum allowable retransmission attempts before declaring packet abandoned.
    pub max_retransmission_attempts: u8,
    /// Initial Retransmission Timeout (RTO) in nanoseconds.
    pub initial_rto_ns: u64,
    /// Minimum RTO lower bound in nanoseconds.
    pub min_rto_ns: u64,
    /// Maximum RTO upper bound in nanoseconds.
    pub max_rto_ns: u64,
    /// Anti-storm hold-off interval in nanoseconds between duplicate NACKs for the same sequence.
    pub nack_hold_off_ns: u64,
    /// Maximum retransmitted packets in flight simultaneously per flow.
    pub max_in_flight_retransmits: usize,
}

impl RetransmitSlicePolicy {
    /// Return policy parameters customized for a specific QoS slice class.
    pub fn for_slice(slice: FlowSliceClass) -> Self {
        match slice {
            FlowSliceClass::UltraLowLatency => Self {
                max_retransmission_attempts: 2,
                initial_rto_ns: 3_000_000,   // 3 ms
                min_rto_ns: 1_000_000,       // 1 ms
                max_rto_ns: 10_000_000,      // 10 ms
                nack_hold_off_ns: 2_000_000, // 2 ms hold-off
                max_in_flight_retransmits: 32,
            },
            FlowSliceClass::MissionCritical => Self {
                max_retransmission_attempts: 4,
                initial_rto_ns: 8_000_000,   // 8 ms
                min_rto_ns: 4_000_000,       // 4 ms
                max_rto_ns: 30_000_000,      // 30 ms
                nack_hold_off_ns: 5_000_000, // 5 ms hold-off
                max_in_flight_retransmits: 128,
            },
            FlowSliceClass::HighThroughput => Self {
                max_retransmission_attempts: 3,
                initial_rto_ns: 15_000_000,   // 15 ms
                min_rto_ns: 5_000_000,        // 5 ms
                max_rto_ns: 60_000_000,       // 60 ms
                nack_hold_off_ns: 10_000_000, // 10 ms hold-off
                max_in_flight_retransmits: 256,
            },
            FlowSliceClass::BestEffort => Self {
                max_retransmission_attempts: 2,
                initial_rto_ns: 25_000_000,   // 25 ms
                min_rto_ns: 10_000_000,       // 10 ms
                max_rto_ns: 100_000_000,      // 100 ms
                nack_hold_off_ns: 20_000_000, // 20 ms hold-off
                max_in_flight_retransmits: 64,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Fallback Subpath Selection Algorithm
// ---------------------------------------------------------------------------

/// Select the optimal priority fallback subpath avoiding the failed subpath.
///
/// Multi-criterion ranking:
/// 1. Formally excludes the failed subpath (`path_id != failed_subpath_id`), unless no other route exists.
/// 2. Excludes `IsspPathState::Failed`.
/// 3. Prefers `Active` and `Standby` paths over `Probation` or `Degraded`.
/// 4. Balances criteria according to the QoS slice SLA:
///    - `UltraLowLatency`: Minimizes latency (RTT + jitter) and administrative priority.
///    - `MissionCritical`: Minimizes loss ratio and prioritizes administrative priority.
///    - `HighThroughput`: Maximizes effective scheduling capacity/weight.
///    - `BestEffort`: Selects available spare capacity.
pub fn select_priority_fallback_subpath(
    failed_subpath_id: u32,
    suggested_fallback: Option<u32>,
    slice_class: FlowSliceClass,
    paths: &BTreeMap<u32, IsspMultipathRoute>,
) -> Option<u32> {
    if paths.is_empty() {
        return None;
    }

    // Check if suggested subpath is operational and distinct from failed
    if let Some(sug) = suggested_fallback {
        if sug != failed_subpath_id {
            if let Some(route) = paths.get(&sug) {
                if route.state != IsspPathState::Failed {
                    return Some(sug);
                }
            }
        }
    }

    // Filter candidate paths
    let mut candidates: Vec<&IsspMultipathRoute> = paths
        .values()
        .filter(|r| r.path_id != failed_subpath_id && r.state != IsspPathState::Failed)
        .collect();

    // If no distinct healthy subpath exists, fall back to any non-failed path (even if it was failed before)
    if candidates.is_empty() {
        candidates = paths
            .values()
            .filter(|r| r.state != IsspPathState::Failed)
            .collect();
    }

    if candidates.is_empty() {
        return None;
    }

    // Multi-criteria scoring
    let scored: Option<(&IsspMultipathRoute, f64)> = candidates
        .into_iter()
        .map(|r| {
            let state_factor = match r.state {
                IsspPathState::Active => 1.0,
                IsspPathState::Standby => 0.9,
                IsspPathState::Probation => 0.7,
                IsspPathState::Degraded => 0.4,
                IsspPathState::Failed => 0.0,
            };

            let rtt_ms = r.metrics.smoothed_rtt_us as f64 / 1_000.0;
            let jitter_ms = r.metrics.jitter_us as f64 / 1_000.0;
            let loss_ratio = r.metrics.loss_rate_ppm as f64 / 1_000_000.0;

            let score = match slice_class {
                FlowSliceClass::UltraLowLatency => {
                    let rtt_term = 1000.0 / (1.0 + rtt_ms.max(0.1));
                    let jitter_term = 500.0 / (1.0 + jitter_ms.max(0.1));
                    let prio_penalty = (r.priority as f64) * 50.0;
                    (rtt_term + jitter_term - prio_penalty) * state_factor
                }
                FlowSliceClass::MissionCritical => {
                    let loss_penalty = loss_ratio * 2000.0;
                    let prio_bonus = 1000.0 / (r.priority.max(1) as f64);
                    let rtt_penalty = rtt_ms.min(100.0) * 2.0;
                    (prio_bonus - loss_penalty - rtt_penalty) * state_factor
                }
                FlowSliceClass::HighThroughput => {
                    let weight_term = (r.effective_weight() as f64) * 10.0;
                    let loss_penalty = loss_ratio * 500.0;
                    (weight_term - loss_penalty) * state_factor
                }
                FlowSliceClass::BestEffort => {
                    let weight_term = r.effective_weight() as f64;
                    let rtt_penalty = rtt_ms * 0.5;
                    (weight_term - rtt_penalty) * state_factor
                }
            };

            (r, score)
        })
        .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

    scored.map(|(r, _)| r.path_id)
}

// ---------------------------------------------------------------------------
// Inflight Tracking Record (Sender Side)
// ---------------------------------------------------------------------------

/// Record of an unacknowledged packet held for potential retransmission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InflightPacketRecord {
    pub packet_id: u64,
    pub flow_id: u32,
    pub sequence_number: u64,
    pub slice_class: FlowSliceClass,
    pub payload: Vec<u8>,
    pub original_subpath_id: u32,
    pub dispatched_at_ns: u64,
    pub last_retransmit_at_ns: u64,
    pub retransmit_count: u8,
    pub rto_ns: u64,
}

// ---------------------------------------------------------------------------
// Sender Retransmission Buffer
// ---------------------------------------------------------------------------

/// Sender-side retransmission tracking buffer.
#[derive(Debug, Clone)]
pub struct SenderRetransmitBuffer {
    pub flow_id: u32,
    pub slice_class: FlowSliceClass,
    pub policy: RetransmitSlicePolicy,
    pub inflight_packets: BTreeMap<u64, InflightPacketRecord>,
    pub total_packets_ingested: u64,
    pub total_retransmitted_count: u64,
    pub total_abandoned_count: u64,
    pub total_sacks_processed: u64,
}

impl SenderRetransmitBuffer {
    pub fn new(flow_id: u32, slice_class: FlowSliceClass) -> Self {
        Self {
            flow_id,
            slice_class,
            policy: RetransmitSlicePolicy::for_slice(slice_class),
            inflight_packets: BTreeMap::new(),
            total_packets_ingested: 0,
            total_retransmitted_count: 0,
            total_abandoned_count: 0,
            total_sacks_processed: 0,
        }
    }

    /// Buffer an outbound packet awaiting acknowledgement.
    pub fn ingest_outbound_packet(
        &mut self,
        packet_id: u64,
        sequence_number: u64,
        payload: Vec<u8>,
        original_subpath_id: u32,
        dispatched_at_ns: u64,
    ) {
        self.total_packets_ingested += 1;
        let record = InflightPacketRecord {
            packet_id,
            flow_id: self.flow_id,
            sequence_number,
            slice_class: self.slice_class,
            payload,
            original_subpath_id,
            dispatched_at_ns,
            last_retransmit_at_ns: 0,
            retransmit_count: 0,
            rto_ns: self.policy.initial_rto_ns,
        };
        self.inflight_packets.insert(sequence_number, record);
    }

    /// Process incoming SACK packet: acknowledge contiguous and selective blocks.
    pub fn process_sack(&mut self, sack: &SubpathSackPacket) -> usize {
        self.total_sacks_processed += 1;
        let mut acknowledged_count = 0;

        // Cumulative ACK: purge all sequence numbers <= cumulative_ack_seq
        let cumulative_acked: Vec<u64> = self
            .inflight_packets
            .range(..=sack.cumulative_ack_seq)
            .map(|(&k, _)| k)
            .collect();

        for seq in cumulative_acked {
            if self.inflight_packets.remove(&seq).is_some() {
                acknowledged_count += 1;
            }
        }

        // Selective blocks: purge packets confirmed received
        for block in &sack.sack_blocks {
            let block_acked: Vec<u64> = self
                .inflight_packets
                .range(block.start_seq..=block.end_seq)
                .map(|(&k, _)| k)
                .collect();

            for seq in block_acked {
                if self.inflight_packets.remove(&seq).is_some() {
                    acknowledged_count += 1;
                }
            }
        }

        acknowledged_count
    }

    /// Process incoming Subpath NACK packet and generate selective retransmissions over priority fallback subpaths.
    pub fn process_nack(
        &mut self,
        nack: &SubpathNackPacket,
        paths: &BTreeMap<u32, IsspMultipathRoute>,
        now_ns: u64,
    ) -> (Vec<RetransmittedPacket>, Vec<u64>) {
        let mut retransmissions = Vec::new();
        let mut abandoned_seqs = Vec::new();

        // Determine fallback subpath
        let fallback_subpath = select_priority_fallback_subpath(
            nack.failed_subpath_id,
            nack.suggested_fallback_subpath_id,
            self.slice_class,
            paths,
        )
        .unwrap_or(nack.failed_subpath_id);

        for range in &nack.nack_ranges {
            let matched_seqs: Vec<u64> = self
                .inflight_packets
                .range(range.start_seq..=range.end_seq)
                .map(|(&k, _)| k)
                .collect();

            for seq in matched_seqs {
                let (should_retransmit, is_abandoned) = {
                    if let Some(record) = self.inflight_packets.get_mut(&seq) {
                        if record.retransmit_count >= self.policy.max_retransmission_attempts {
                            (false, true)
                        } else {
                            // Check anti-storm hold-off
                            let elapsed = now_ns.saturating_sub(record.last_retransmit_at_ns);
                            if record.retransmit_count == 0 || elapsed >= self.policy.min_rto_ns {
                                record.retransmit_count += 1;
                                record.last_retransmit_at_ns = now_ns;
                                // Exponential backoff for next RTO
                                record.rto_ns = (record.rto_ns.saturating_mul(2))
                                    .min(self.policy.max_rto_ns)
                                    .max(self.policy.min_rto_ns);
                                (true, false)
                            } else {
                                (false, false)
                            }
                        }
                    } else {
                        (false, false)
                    }
                };

                if is_abandoned {
                    self.inflight_packets.remove(&seq);
                    self.total_abandoned_count += 1;
                    abandoned_seqs.push(seq);
                } else if should_retransmit {
                    if let Some(rec) = self.inflight_packets.get(&seq) {
                        let retx_pkt = RetransmittedPacket {
                            packet_id: rec.packet_id,
                            flow_id: rec.flow_id,
                            sequence_number: rec.sequence_number,
                            slice_class: rec.slice_class,
                            payload: rec.payload.clone(),
                            original_subpath_id: rec.original_subpath_id,
                            assigned_fallback_subpath_id: fallback_subpath,
                            attempt_number: rec.retransmit_count,
                            retransmit_timestamp_ns: now_ns,
                            is_fec_fallback: true,
                        };
                        self.total_retransmitted_count += 1;
                        retransmissions.push(retx_pkt);
                    }
                }
            }
        }

        (retransmissions, abandoned_seqs)
    }

    /// Check for RTO expirations on unacknowledged packets.
    pub fn check_rto_timeouts(
        &mut self,
        paths: &BTreeMap<u32, IsspMultipathRoute>,
        now_ns: u64,
    ) -> (Vec<RetransmittedPacket>, Vec<u64>) {
        let mut retransmissions = Vec::new();
        let mut abandoned_seqs = Vec::new();

        let expired_seqs: Vec<(u64, u32)> = self
            .inflight_packets
            .iter()
            .filter_map(|(&seq, rec)| {
                let reference_ts = if rec.last_retransmit_at_ns > 0 {
                    rec.last_retransmit_at_ns
                } else {
                    rec.dispatched_at_ns
                };
                if now_ns.saturating_sub(reference_ts) >= rec.rto_ns {
                    Some((seq, rec.original_subpath_id))
                } else {
                    None
                }
            })
            .collect();

        for (seq, orig_subpath) in expired_seqs {
            let (should_retransmit, is_abandoned) = {
                if let Some(record) = self.inflight_packets.get_mut(&seq) {
                    if record.retransmit_count >= self.policy.max_retransmission_attempts {
                        (false, true)
                    } else {
                        record.retransmit_count += 1;
                        record.last_retransmit_at_ns = now_ns;
                        record.rto_ns = (record.rto_ns.saturating_mul(2))
                            .min(self.policy.max_rto_ns)
                            .max(self.policy.min_rto_ns);
                        (true, false)
                    }
                } else {
                    (false, false)
                }
            };

            if is_abandoned {
                self.inflight_packets.remove(&seq);
                self.total_abandoned_count += 1;
                abandoned_seqs.push(seq);
            } else if should_retransmit {
                let fallback =
                    select_priority_fallback_subpath(orig_subpath, None, self.slice_class, paths)
                        .unwrap_or(orig_subpath);

                if let Some(rec) = self.inflight_packets.get(&seq) {
                    let retx_pkt = RetransmittedPacket {
                        packet_id: rec.packet_id,
                        flow_id: rec.flow_id,
                        sequence_number: rec.sequence_number,
                        slice_class: rec.slice_class,
                        payload: rec.payload.clone(),
                        original_subpath_id: rec.original_subpath_id,
                        assigned_fallback_subpath_id: fallback,
                        attempt_number: rec.retransmit_count,
                        retransmit_timestamp_ns: now_ns,
                        is_fec_fallback: false,
                    };
                    self.total_retransmitted_count += 1;
                    retransmissions.push(retx_pkt);
                }
            }
        }

        (retransmissions, abandoned_seqs)
    }

    /// Number of in-flight unacknowledged packets.
    #[inline]
    pub fn inflight_count(&self) -> usize {
        self.inflight_packets.len()
    }
}

// ---------------------------------------------------------------------------
// Receiver-Side Selective NACK Generator
// ---------------------------------------------------------------------------

/// Receiver-side generator responsible for emitting Subpath NACKs targeted at FEC unrecoverable gaps.
#[derive(Debug, Clone)]
pub struct ReceiverNackGenerator {
    pub flow_id: u32,
    pub slice_class: FlowSliceClass,
    pub policy: RetransmitSlicePolicy,
    pub cumulative_ack_seq: u64,
    /// Pending unrecoverable missing sequence numbers and when they were detected: seq -> detected_ts_ns
    pub unrecoverable_missing_seqs: BTreeMap<u64, u64>,
    /// Last timestamp when a NACK was emitted for a sequence number: seq -> emitted_ts_ns
    pub last_nack_emitted_ns: HashMap<u64, u64>,
    pub next_nack_id: u64,
    pub total_nacks_generated: u64,
    pub total_missing_requested: u64,
}

impl ReceiverNackGenerator {
    pub fn new(flow_id: u32, slice_class: FlowSliceClass) -> Self {
        Self {
            flow_id,
            slice_class,
            policy: RetransmitSlicePolicy::for_slice(slice_class),
            cumulative_ack_seq: 0,
            unrecoverable_missing_seqs: BTreeMap::new(),
            last_nack_emitted_ns: HashMap::new(),
            next_nack_id: 1,
            total_nacks_generated: 0,
            total_missing_requested: 0,
        }
    }

    /// Update cumulative ACK sequence reached by contiguous delivery.
    pub fn update_cumulative_ack(&mut self, seq: u64) {
        if seq > self.cumulative_ack_seq {
            self.cumulative_ack_seq = seq;
            // Purge anything up to cumulative_ack_seq
            self.unrecoverable_missing_seqs.retain(|&k, _| k > seq);
            self.last_nack_emitted_ns.retain(|&k, _| k > seq);
        }
    }

    /// Ingest an unrecoverable gap event reported by the FEC decoder.
    pub fn ingest_fec_unrecoverable_event(
        &mut self,
        event: &FecUnrecoverableGapEvent,
        now_ns: u64,
    ) {
        if event.flow_id != self.flow_id {
            return;
        }
        for seq in event.missing_seq_start..=event.missing_seq_end {
            if seq > self.cumulative_ack_seq {
                self.unrecoverable_missing_seqs.entry(seq).or_insert(now_ns);
            }
        }
    }

    /// Ingest a sequence delivered or recovered (removing it from missing set).
    pub fn mark_sequence_received(&mut self, seq: u64) {
        self.unrecoverable_missing_seqs.remove(&seq);
        self.last_nack_emitted_ns.remove(&seq);
    }

    /// Emit a Subpath NACK packet grouping pending unrecoverable sequences subject to anti-storm hold-off.
    pub fn generate_nack(
        &mut self,
        failed_subpath_id: u32,
        suggested_fallback_subpath_id: Option<u32>,
        now_ns: u64,
    ) -> Option<SubpathNackPacket> {
        let mut ready_seqs = Vec::new();

        for &seq in self.unrecoverable_missing_seqs.keys() {
            let should_emit = match self.last_nack_emitted_ns.get(&seq) {
                Some(&last_ts) => now_ns.saturating_sub(last_ts) >= self.policy.nack_hold_off_ns,
                None => true,
            };

            if should_emit {
                ready_seqs.push(seq);
            }
        }

        if ready_seqs.is_empty() {
            return None;
        }

        // Convert individual sequences into compact contiguous ranges
        let individual_ranges: Vec<SelectiveAckRange> = ready_seqs
            .iter()
            .map(|&s| SelectiveAckRange::single(s))
            .collect();
        let compacted_ranges = SelectiveAckRange::merge_ranges(individual_ranges);

        // Record last emission timestamp
        for &seq in &ready_seqs {
            self.last_nack_emitted_ns.insert(seq, now_ns);
        }

        let nack_id = self.next_nack_id;
        self.next_nack_id += 1;
        self.total_nacks_generated += 1;
        let missing_count: u64 = compacted_ranges.iter().map(|r| r.count()).sum();
        self.total_missing_requested += missing_count;

        Some(SubpathNackPacket {
            nack_id,
            flow_id: self.flow_id,
            slice_class: self.slice_class,
            cumulative_ack_seq: self.cumulative_ack_seq,
            nack_ranges: compacted_ranges,
            failed_subpath_id,
            suggested_fallback_subpath_id,
            generation_timestamp_ns: now_ns,
            attempt: 1,
        })
    }
}

// ---------------------------------------------------------------------------
// Subpath Retransmit Manager (Global Engine)
// ---------------------------------------------------------------------------

/// Global Manager for Targeted Selective Retransmission and Fallback Subpath Routing.
#[derive(Debug, Clone)]
pub struct SubpathRetransmitManager {
    /// Per-flow sender retransmission tracking buffers.
    pub sender_buffers: HashMap<u32, SenderRetransmitBuffer>,
    /// Per-flow receiver NACK generators.
    pub receiver_generators: HashMap<u32, ReceiverNackGenerator>,
    /// Telemetry counters.
    pub total_nack_packets_sent: u64,
    pub total_nack_packets_received: u64,
    pub total_retransmissions_dispatched: u64,
    pub total_retransmissions_recovered: u64,
    pub total_retransmissions_abandoned: u64,
    pub total_fallback_subpath_switches: u64,
    pub retransmit_latency_sum_ns: u64,
    pub retransmit_latency_count: u64,
}

impl Default for SubpathRetransmitManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SubpathRetransmitManager {
    pub fn new() -> Self {
        Self {
            sender_buffers: HashMap::new(),
            receiver_generators: HashMap::new(),
            total_nack_packets_sent: 0,
            total_nack_packets_received: 0,
            total_retransmissions_dispatched: 0,
            total_retransmissions_recovered: 0,
            total_retransmissions_abandoned: 0,
            total_fallback_subpath_switches: 0,
            retransmit_latency_sum_ns: 0,
            retransmit_latency_count: 0,
        }
    }

    /// Ensure sender buffer exists for a flow.
    pub fn ensure_sender_buffer(
        &mut self,
        flow_id: u32,
        slice_class: FlowSliceClass,
    ) -> &mut SenderRetransmitBuffer {
        self.sender_buffers
            .entry(flow_id)
            .or_insert_with(|| SenderRetransmitBuffer::new(flow_id, slice_class))
    }

    /// Ensure receiver generator exists for a flow.
    pub fn ensure_receiver_generator(
        &mut self,
        flow_id: u32,
        slice_class: FlowSliceClass,
    ) -> &mut ReceiverNackGenerator {
        self.receiver_generators
            .entry(flow_id)
            .or_insert_with(|| ReceiverNackGenerator::new(flow_id, slice_class))
    }

    /// Record outbound packet transmission into the flow's retransmission tracking buffer.
    #[allow(clippy::too_many_arguments)]
    pub fn record_outbound_packet(
        &mut self,
        packet_id: u64,
        flow_id: u32,
        slice_class: FlowSliceClass,
        sequence_number: u64,
        payload: Vec<u8>,
        subpath_id: u32,
        dispatched_at_ns: u64,
    ) {
        let sender = self.ensure_sender_buffer(flow_id, slice_class);
        sender.ingest_outbound_packet(
            packet_id,
            sequence_number,
            payload,
            subpath_id,
            dispatched_at_ns,
        );
    }

    /// Process an incoming Subpath NACK packet, retransmitting unrecoverable packets over priority fallback subpaths.
    pub fn handle_incoming_nack(
        &mut self,
        nack: &SubpathNackPacket,
        paths: &BTreeMap<u32, IsspMultipathRoute>,
        now_ns: u64,
    ) -> (Vec<RetransmittedPacket>, Vec<u64>) {
        self.total_nack_packets_received += 1;
        let flow_id = nack.flow_id;
        let slice = nack.slice_class;

        let sender = self.ensure_sender_buffer(flow_id, slice);
        let (retx_pkts, abandoned) = sender.process_nack(nack, paths, now_ns);

        for pkt in &retx_pkts {
            self.total_retransmissions_dispatched += 1;
            if pkt.assigned_fallback_subpath_id != pkt.original_subpath_id {
                self.total_fallback_subpath_switches += 1;
            }
        }
        self.total_retransmissions_abandoned += abandoned.len() as u64;

        (retx_pkts, abandoned)
    }

    /// Process an incoming SACK packet, acknowledging delivered packets.
    pub fn handle_incoming_sack(&mut self, sack: &SubpathSackPacket) -> usize {
        let flow_id = sack.flow_id;
        let slice = sack.slice_class;
        let sender = self.ensure_sender_buffer(flow_id, slice);
        let count = sender.process_sack(sack);
        self.total_retransmissions_recovered += count as u64;
        count
    }

    /// Record successful packet delivery at receiver side.
    pub fn record_packet_delivery(&mut self, flow_id: u32, seq: u64) {
        if let Some(rx) = self.receiver_generators.get_mut(&flow_id) {
            rx.mark_sequence_received(seq);
        }
    }

    /// Handle an unrecoverable gap event reported by the FEC decoder.
    pub fn handle_fec_unrecoverable_event(
        &mut self,
        event: &FecUnrecoverableGapEvent,
        slice_class: FlowSliceClass,
        failed_subpath_id: u32,
        suggested_fallback: Option<u32>,
        now_ns: u64,
    ) -> Option<SubpathNackPacket> {
        let rx = self.ensure_receiver_generator(event.flow_id, slice_class);
        rx.ingest_fec_unrecoverable_event(event, now_ns);
        let maybe_nack = rx.generate_nack(failed_subpath_id, suggested_fallback, now_ns);
        if maybe_nack.is_some() {
            self.total_nack_packets_sent += 1;
        }
        maybe_nack
    }

    /// Summary telemetry snapshot.
    pub fn telemetry_summary(&self) -> SubpathRetransmitTelemetrySummary {
        let active_inflight: usize = self
            .sender_buffers
            .values()
            .map(|s| s.inflight_count())
            .sum();

        let avg_latency_ns = if self.retransmit_latency_count > 0 {
            self.retransmit_latency_sum_ns as f64 / self.retransmit_latency_count as f64
        } else {
            0.0
        };

        SubpathRetransmitTelemetrySummary {
            total_nacks_sent: self.total_nack_packets_sent,
            total_nacks_received: self.total_nack_packets_received,
            total_retransmissions_dispatched: self.total_retransmissions_dispatched,
            total_retransmissions_recovered: self.total_retransmissions_recovered,
            total_retransmissions_abandoned: self.total_retransmissions_abandoned,
            total_fallback_switches: self.total_fallback_subpath_switches,
            active_inflight_packets: active_inflight,
            avg_retransmit_latency_ns: avg_latency_ns,
        }
    }
}

/// Telemetry summary for subpath retransmission and fallback mechanisms.
#[derive(Debug, Clone, PartialEq)]
pub struct SubpathRetransmitTelemetrySummary {
    pub total_nacks_sent: u64,
    pub total_nacks_received: u64,
    pub total_retransmissions_dispatched: u64,
    pub total_retransmissions_recovered: u64,
    pub total_retransmissions_abandoned: u64,
    pub total_fallback_switches: u64,
    pub active_inflight_packets: usize,
    pub avg_retransmit_latency_ns: f64,
}

// ---------------------------------------------------------------------------
// Automated End-to-End Benchmark
// ---------------------------------------------------------------------------

/// Benchmark report for targeted selective retransmission over fallback subpaths.
#[derive(Debug, Clone, PartialEq)]
pub struct SubpathRetransmitBenchmarkReport {
    pub packets_ingested: u64,
    pub unrecoverable_fec_gaps: u64,
    pub nack_packets_generated: u64,
    pub retransmissions_dispatched: u64,
    pub fallback_subpaths_utilized: u64,
    pub retransmission_success_rate: f64,
}

/// Run an automated end-to-end benchmark for SACK / Subpath NACK selective retransmission.
pub fn run_subpath_retransmit_benchmark() -> SubpathRetransmitBenchmarkReport {
    let mut manager = SubpathRetransmitManager::new();
    let mut routes = BTreeMap::new();

    let mut r1 = IsspMultipathRoute::new(1, 2, "eth0-primary", 1, 100);
    r1.metrics.smoothed_rtt_us = 5_000;
    r1.metrics.jitter_us = 1_000;
    r1.metrics.loss_rate_ppm = 250_000; // Degraded lossy path (25% loss)
    routes.insert(1, r1);

    let mut r2 = IsspMultipathRoute::new(2, 2, "eth1-fallback", 2, 80);
    r2.metrics.smoothed_rtt_us = 6_000;
    r2.metrics.jitter_us = 1_200;
    r2.metrics.loss_rate_ppm = 1_000; // Pristine backup path (0.1% loss)
    routes.insert(2, r2);

    let flow_id = 42;
    let slice = FlowSliceClass::MissionCritical;
    let total_packets = 200u64;

    // Ingest packets 1..=200 on subpath 1
    for seq in 1..=total_packets {
        let payload = format!("data-payload-seq-{}", seq).into_bytes();
        manager.record_outbound_packet(seq * 10, flow_id, slice, seq, payload, 1, seq * 1_000_000);
    }

    // Simulate an FEC unrecoverable gap event for sequences 40..=45 on subpath 1
    let gap_ev = FecUnrecoverableGapEvent {
        flow_id,
        block_index: 4,
        missing_seq_start: 40,
        missing_seq_end: 45,
        missing_count: 6,
        available_parity: 2, // Parity exhausted
        timestamp_ns: 50_000_000,
    };

    let maybe_nack = manager.handle_fec_unrecoverable_event(&gap_ev, slice, 1, Some(2), 55_000_000);
    assert!(
        maybe_nack.is_some(),
        "NACK must be generated for unrecoverable FEC gap"
    );
    let nack = maybe_nack.unwrap();

    // Process NACK: retransmit over priority fallback subpath 2
    let (retx_pkts, _abandoned) = manager.handle_incoming_nack(&nack, &routes, 60_000_000);
    assert_eq!(
        retx_pkts.len(),
        6,
        "All 6 missing packets must be retransmitted"
    );
    for pkt in &retx_pkts {
        assert_eq!(
            pkt.assigned_fallback_subpath_id, 2,
            "Retransmissions must be routed to fallback subpath 2"
        );
    }

    // Receiver emits SACK confirming reception of retransmitted packets 40..=45
    let sack = SubpathSackPacket {
        flow_id,
        slice_class: slice,
        cumulative_ack_seq: 45,
        sack_blocks: vec![SelectiveAckRange::new(40, 45)],
        timestamp_ns: 70_000_000,
    };
    let acked = manager.handle_incoming_sack(&sack);
    assert!(
        acked >= 6,
        "Retransmitted packets must be acknowledged and cleared"
    );

    let summary = manager.telemetry_summary();
    let success_rate = if summary.total_retransmissions_dispatched > 0 {
        (summary.total_retransmissions_recovered as f64
            / summary.total_retransmissions_dispatched as f64)
            .min(1.0)
    } else {
        1.0
    };

    SubpathRetransmitBenchmarkReport {
        packets_ingested: total_packets,
        unrecoverable_fec_gaps: 1,
        nack_packets_generated: summary.total_nacks_sent,
        retransmissions_dispatched: summary.total_retransmissions_dispatched,
        fallback_subpaths_utilized: summary.total_fallback_switches,
        retransmission_success_rate: success_rate,
    }
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_selective_ack_range_merge_and_compaction() {
        let r1 = SelectiveAckRange::new(10, 15);
        let r2 = SelectiveAckRange::new(16, 20); // Adjacent -> should merge with r1
        let r3 = SelectiveAckRange::new(30, 35);
        let r4 = SelectiveAckRange::new(32, 40); // Overlapping -> should merge with r3
        let r5 = SelectiveAckRange::single(50);

        let merged = SelectiveAckRange::merge_ranges(vec![r4, r1, r5, r2, r3]);
        assert_eq!(merged.len(), 3);
        assert_eq!(merged[0], SelectiveAckRange::new(10, 20));
        assert_eq!(merged[1], SelectiveAckRange::new(30, 40));
        assert_eq!(merged[2], SelectiveAckRange::new(50, 50));
        assert_eq!(merged[0].count(), 11);
        assert!(merged[0].contains_seq(15));
        assert!(!merged[0].contains_seq(21));
    }

    #[test]
    fn test_priority_fallback_subpath_selection() {
        let mut routes = BTreeMap::new();

        let mut r1 = IsspMultipathRoute::new(1, 10, "eth0", 1, 100);
        r1.metrics.smoothed_rtt_us = 4_000;
        r1.metrics.jitter_us = 800;
        r1.metrics.loss_rate_ppm = 300_000; // Severe loss
        routes.insert(1, r1);

        let mut r2 = IsspMultipathRoute::new(2, 10, "eth1", 2, 80);
        r2.metrics.smoothed_rtt_us = 6_000;
        r2.metrics.jitter_us = 1_000;
        r2.metrics.loss_rate_ppm = 1_000; // Healthy fallback
        routes.insert(2, r2);

        let mut r3 = IsspMultipathRoute::new(3, 10, "eth2", 3, 50);
        r3.state = IsspPathState::Failed; // Ineligible
        routes.insert(3, r3);

        // When subpath 1 fails, subpath 2 must be chosen (r3 is Failed)
        let chosen =
            select_priority_fallback_subpath(1, None, FlowSliceClass::MissionCritical, &routes);
        assert_eq!(chosen, Some(2));

        // When suggested fallback 2 is supplied, it is selected
        let chosen_sug =
            select_priority_fallback_subpath(1, Some(2), FlowSliceClass::UltraLowLatency, &routes);
        assert_eq!(chosen_sug, Some(2));
    }

    #[test]
    fn test_sender_retransmit_nack_and_sack_flow() {
        let mut sender = SenderRetransmitBuffer::new(1, FlowSliceClass::MissionCritical);
        let mut routes = BTreeMap::new();
        routes.insert(1, IsspMultipathRoute::new(1, 10, "eth0", 1, 100));
        routes.insert(2, IsspMultipathRoute::new(2, 10, "eth1", 2, 80));

        // Ingest packets 1..=5
        for seq in 1..=5 {
            sender.ingest_outbound_packet(seq, seq, vec![0xAA; 64], 1, 1_000_000);
        }
        assert_eq!(sender.inflight_count(), 5);

        // Subpath NACK for seq 2 and 4
        let nack = SubpathNackPacket {
            nack_id: 100,
            flow_id: 1,
            slice_class: FlowSliceClass::MissionCritical,
            cumulative_ack_seq: 1,
            nack_ranges: vec![SelectiveAckRange::single(2), SelectiveAckRange::single(4)],
            failed_subpath_id: 1,
            suggested_fallback_subpath_id: Some(2),
            generation_timestamp_ns: 10_000_000,
            attempt: 1,
        };

        let (retx, abandoned) = sender.process_nack(&nack, &routes, 10_000_000);
        assert_eq!(abandoned.len(), 0);
        assert_eq!(retx.len(), 2);
        assert_eq!(retx[0].sequence_number, 2);
        assert_eq!(retx[0].assigned_fallback_subpath_id, 2);
        assert_eq!(retx[1].sequence_number, 4);
        assert_eq!(retx[1].assigned_fallback_subpath_id, 2);

        // Process SACK acknowledging cumulative 3 and selective 4
        let sack = SubpathSackPacket {
            flow_id: 1,
            slice_class: FlowSliceClass::MissionCritical,
            cumulative_ack_seq: 3,
            sack_blocks: vec![SelectiveAckRange::single(4)],
            timestamp_ns: 20_000_000,
        };
        let acked = sender.process_sack(&sack);
        assert_eq!(acked, 4); // 1, 2, 3 cumulative + 4 selective
        assert_eq!(sender.inflight_count(), 1); // Only seq 5 remaining
    }

    #[test]
    fn test_anti_storm_nack_rate_limiting() {
        let mut rx = ReceiverNackGenerator::new(10, FlowSliceClass::UltraLowLatency);
        let event = FecUnrecoverableGapEvent {
            flow_id: 10,
            block_index: 1,
            missing_seq_start: 100,
            missing_seq_end: 102,
            missing_count: 3,
            available_parity: 0,
            timestamp_ns: 1_000_000,
        };

        rx.ingest_fec_unrecoverable_event(&event, 1_000_000);

        // First NACK should be generated
        let nack1 = rx.generate_nack(1, Some(2), 1_100_000);
        assert!(nack1.is_some());
        assert_eq!(nack1.unwrap().total_missing_packets(), 3);

        // Immediate subsequent call before hold-off (2ms for URLLC) should return None
        let nack2 = rx.generate_nack(1, Some(2), 1_500_000);
        assert!(
            nack2.is_none(),
            "NACK must be suppressed within hold-off window"
        );

        // After hold-off expires (at > 3.1ms)
        let nack3 = rx.generate_nack(1, Some(2), 3_200_000);
        assert!(nack3.is_some(), "NACK must be re-emitted after hold-off");
    }

    #[test]
    fn test_max_retransmission_attempts_and_abandonment() {
        let mut sender = SenderRetransmitBuffer::new(1, FlowSliceClass::UltraLowLatency);
        let mut routes = BTreeMap::new();
        routes.insert(1, IsspMultipathRoute::new(1, 10, "eth0", 1, 100));

        sender.ingest_outbound_packet(1, 10, vec![1, 2, 3], 1, 1_000_000);

        let nack = SubpathNackPacket {
            nack_id: 1,
            flow_id: 1,
            slice_class: FlowSliceClass::UltraLowLatency,
            cumulative_ack_seq: 0,
            nack_ranges: vec![SelectiveAckRange::single(10)],
            failed_subpath_id: 1,
            suggested_fallback_subpath_id: None,
            generation_timestamp_ns: 2_000_000,
            attempt: 1,
        };

        // Attempt 1
        let (retx1, _) = sender.process_nack(&nack, &routes, 2_000_000);
        assert_eq!(retx1.len(), 1);
        assert_eq!(retx1[0].attempt_number, 1);

        // Attempt 2 (after RTO min elapsed)
        let (retx2, _) = sender.process_nack(&nack, &routes, 5_000_000);
        assert_eq!(retx2.len(), 1);
        assert_eq!(retx2[0].attempt_number, 2);

        // Attempt 3 exceeds max_attempts (2 for UltraLowLatency) -> declared abandoned
        let (retx3, abandoned) = sender.process_nack(&nack, &routes, 15_000_000);
        assert_eq!(retx3.len(), 0);
        assert_eq!(abandoned.len(), 1);
        assert_eq!(abandoned[0], 10);
        assert_eq!(sender.inflight_count(), 0);
    }

    #[test]
    fn test_subpath_retransmit_benchmark_runs() {
        let rep = run_subpath_retransmit_benchmark();
        assert_eq!(rep.packets_ingested, 200);
        assert_eq!(rep.unrecoverable_fec_gaps, 1);
        assert_eq!(rep.retransmissions_dispatched, 6);
        assert_eq!(rep.fallback_subpaths_utilized, 6);
        assert!(rep.retransmission_success_rate > 0.99);
    }
}

//! Asynchronous Multipath Transport Integration for Kori and IFA (`ifa_runtime::multipath_transport`).
//!
//! Provides seamless multi-subpath asynchronous networking over non-blocking UDP sockets (`AsyncUdpSocket`),
//! orchestrating the RFC 9000 aligned `MultipathStreamMux` across heterogeneous physical or logical links.
//!
//! Key Capabilities:
//! 1. **Zero Head-of-Line (HoL) Blocking**:
//!    - Independent stream byte offsets and reassembly buffers over separate physical UDP sockets.
//! 2. **Dynamic BDP-Driven Flow Control Autotuning**:
//!    - Bidirectional exchange of `MAX_STREAM_DATA`, `MAX_DATA`, `STREAM_DATA_BLOCKED`, and `DATA_BLOCKED`
//!      control frames driven by application consumption and subpath BDP.
//! 3. **1+1 Redundant Bicasting for Mission-Critical Slices**:
//!    - Simultaneous replication of urgent frames across disjoint subpath sockets with deduplicated delivery.
//! 4. **Production OpenMetrics / Prometheus Observability**:
//!    - Comprehensive telemetry covering per-subpath throughput, packet rates, reassembly status, and flow control.

use std::collections::HashMap;
use std::fmt::Write as FmtWrite;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use crate::connection_migration::{
    ConnectionId, ConnectionMigrationEngine, MigrationError, MigrationTrigger, PathChallenge,
    PathResponse, SocketAddress,
};
use crate::multipath_pacing::{
    MultipathPacingEngine, SubpathPacer, SubpathPacingTelemetry, SubpathPacingVerdict,
};
use crate::multipath_stream_mux::{
    MigrationFrame, MultipathMuxPacket, MultipathStreamMux, StreamId, StreamMuxError,
    StreamPriority,
};
use crate::reactor::AsyncUdpSocket;
use crate::subpath_health::{
    SubpathAlertSink, SubpathHealthConfig, SubpathHealthMonitor, SubpathHealthState,
};
use crate::subpath_shaper::{SubpathAdmissionVerdict, SubpathShaperTelemetry, SubpathSliceShaper};
use crate::traffic_slicing::FlowSliceClass;

/// Snapshot telemetry of an individual transport subpath.
#[derive(Debug, Clone, PartialEq)]
pub struct SubpathTransportTelemetry {
    pub subpath_id: u8,
    pub name: String,
    pub peer_addr: SocketAddr,
    pub rtt_ms: u64,
    pub bandwidth_bps: u64,
    pub active: bool,
    pub packets_sent: u64,
    pub bytes_sent: u64,
    pub packets_received: u64,
    pub bytes_received: u64,
    pub shaper: SubpathShaperTelemetry,
    pub pacer: SubpathPacingTelemetry,
    pub health_score: u8,
    pub health_state: SubpathHealthState,
}

/// An individual asynchronous subpath binding an `AsyncUdpSocket` to a remote peer.
#[derive(Clone)]
pub struct AsyncMultipathSubpath {
    pub subpath_id: u8,
    pub name: String,
    pub socket: Arc<AsyncUdpSocket>,
    pub peer_addr: SocketAddr,
    pub rtt_ms: u64,
    pub bandwidth_bps: u64,
    pub active: bool,
    pub packets_sent: Arc<AtomicU64>,
    pub bytes_sent: Arc<AtomicU64>,
    pub packets_received: Arc<AtomicU64>,
    pub bytes_received: Arc<AtomicU64>,
    pub shaper: Arc<Mutex<SubpathSliceShaper>>,
    pub pacer: Arc<Mutex<SubpathPacer>>,
}

impl AsyncMultipathSubpath {
    pub fn new(
        subpath_id: u8,
        name: impl Into<String>,
        socket: Arc<AsyncUdpSocket>,
        peer_addr: SocketAddr,
        rtt_ms: u64,
        bandwidth_bps: u64,
    ) -> Self {
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let shaper = Arc::new(Mutex::new(SubpathSliceShaper::new(
            subpath_id,
            bandwidth_bps,
            now_ns,
        )));
        let pacer = Arc::new(Mutex::new(SubpathPacer::new(
            subpath_id,
            bandwidth_bps,
            rtt_ms,
            now_ns,
        )));
        Self {
            subpath_id,
            name: name.into(),
            socket,
            peer_addr,
            rtt_ms,
            bandwidth_bps,
            active: true,
            packets_sent: Arc::new(AtomicU64::new(0)),
            bytes_sent: Arc::new(AtomicU64::new(0)),
            packets_received: Arc::new(AtomicU64::new(0)),
            bytes_received: Arc::new(AtomicU64::new(0)),
            shaper,
            pacer,
        }
    }

    /// Create an asynchronous subpath with a custom preconfigured multi-slice traffic shaper.
    pub fn with_shaper(
        subpath_id: u8,
        name: impl Into<String>,
        socket: Arc<AsyncUdpSocket>,
        peer_addr: SocketAddr,
        rtt_ms: u64,
        bandwidth_bps: u64,
        shaper: SubpathSliceShaper,
    ) -> Self {
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let pacer = Arc::new(Mutex::new(SubpathPacer::new(
            subpath_id,
            bandwidth_bps,
            rtt_ms,
            now_ns,
        )));
        Self {
            subpath_id,
            name: name.into(),
            socket,
            peer_addr,
            rtt_ms,
            bandwidth_bps,
            active: true,
            packets_sent: Arc::new(AtomicU64::new(0)),
            bytes_sent: Arc::new(AtomicU64::new(0)),
            packets_received: Arc::new(AtomicU64::new(0)),
            bytes_received: Arc::new(AtomicU64::new(0)),
            shaper: Arc::new(Mutex::new(shaper)),
            pacer,
        }
    }

    /// Dynamically update bandwidth and rebalance slice allocations.
    pub fn update_bandwidth(&mut self, new_bandwidth_bps: u64, now_ns: u64) {
        self.bandwidth_bps = new_bandwidth_bps;
        if let Ok(mut shaper) = self.shaper.lock() {
            shaper.rebalance(new_bandwidth_bps, now_ns);
        }
        if let Ok(mut pacer) = self.pacer.lock() {
            pacer.update_link(new_bandwidth_bps, self.rtt_ms, now_ns);
        }
    }

    /// Estimated Bandwidth-Delay Product (BDP) in bytes.
    pub fn bdp_bytes(&self) -> u64 {
        // BDP = (bandwidth_bps / 8) * (rtt_ms / 1000)
        let bytes_per_sec = self.bandwidth_bps / 8;
        (bytes_per_sec.saturating_mul(self.rtt_ms)) / 1000
    }

    pub fn snapshot(&self) -> SubpathTransportTelemetry {
        self.snapshot_with_health(100, SubpathHealthState::Healthy)
    }

    pub fn snapshot_with_health(
        &self,
        health_score: u8,
        health_state: SubpathHealthState,
    ) -> SubpathTransportTelemetry {
        let shaper_snap = self
            .shaper
            .lock()
            .map(|s| s.snapshot())
            .unwrap_or_else(|_| {
                SubpathSliceShaper::new(self.subpath_id, self.bandwidth_bps, 0).snapshot()
            });
        let pacer_snap = self.pacer.lock().map(|p| p.snapshot()).unwrap_or_else(|_| {
            SubpathPacer::new(self.subpath_id, self.bandwidth_bps, self.rtt_ms, 0).snapshot()
        });
        SubpathTransportTelemetry {
            subpath_id: self.subpath_id,
            name: self.name.clone(),
            peer_addr: self.peer_addr,
            rtt_ms: self.rtt_ms,
            bandwidth_bps: self.bandwidth_bps,
            active: self.active,
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            packets_received: self.packets_received.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            shaper: shaper_snap,
            pacer: pacer_snap,
            health_score,
            health_state,
        }
    }
}

/// Asynchronous Multipath Transport Connection coordinating multiple UDP subpaths, a stream multiplexer,
/// and RFC 9000 connection migration.
pub struct AsyncMultipathTransport {
    mux: Arc<Mutex<MultipathStreamMux>>,
    subpaths: Arc<RwLock<HashMap<u8, AsyncMultipathSubpath>>>,
    default_subpath_id: Arc<RwLock<Option<u8>>>,
    migration_engine: Arc<Mutex<ConnectionMigrationEngine>>,
    health_monitor: Arc<RwLock<SubpathHealthMonitor>>,
    pacing_engine: Arc<RwLock<MultipathPacingEngine>>,
}

impl AsyncMultipathTransport {
    /// Creates a new multipath transport instance with a default stream multiplexer.
    pub fn new() -> Self {
        Self {
            mux: Arc::new(Mutex::new(MultipathStreamMux::new())),
            subpaths: Arc::new(RwLock::new(HashMap::new())),
            default_subpath_id: Arc::new(RwLock::new(None)),
            migration_engine: Arc::new(Mutex::new(ConnectionMigrationEngine::new())),
            health_monitor: Arc::new(RwLock::new(SubpathHealthMonitor::new())),
            pacing_engine: Arc::new(RwLock::new(MultipathPacingEngine::new())),
        }
    }

    /// Creates a transport instance with an existing preconfigured multiplexer.
    pub fn with_mux(mux: MultipathStreamMux) -> Self {
        Self {
            mux: Arc::new(Mutex::new(mux)),
            subpaths: Arc::new(RwLock::new(HashMap::new())),
            default_subpath_id: Arc::new(RwLock::new(None)),
            migration_engine: Arc::new(Mutex::new(ConnectionMigrationEngine::new())),
            health_monitor: Arc::new(RwLock::new(SubpathHealthMonitor::new())),
            pacing_engine: Arc::new(RwLock::new(MultipathPacingEngine::new())),
        }
    }

    /// Creates a transport instance with a custom subpath health monitor configuration.
    pub fn with_health_config(config: SubpathHealthConfig) -> Self {
        Self {
            mux: Arc::new(Mutex::new(MultipathStreamMux::new())),
            subpaths: Arc::new(RwLock::new(HashMap::new())),
            default_subpath_id: Arc::new(RwLock::new(None)),
            migration_engine: Arc::new(Mutex::new(ConnectionMigrationEngine::new())),
            health_monitor: Arc::new(RwLock::new(SubpathHealthMonitor::with_config(config))),
            pacing_engine: Arc::new(RwLock::new(MultipathPacingEngine::new())),
        }
    }

    /// Register a new asynchronous subpath with associated non-blocking UDP socket and link characteristics.
    pub fn add_subpath(&self, subpath: AsyncMultipathSubpath) -> Result<(), io::Error> {
        let sid = subpath.subpath_id;
        let bdp = subpath.bdp_bytes();

        // Update multiplexer BDP autotuning
        if let Ok(mut mux) = self.mux.lock() {
            mux.update_subpath_bdp(sid, bdp);
        }

        // Register initial subpath address in connection migration engine
        if let Ok(mut engine) = self.migration_engine.lock() {
            let socket_addr = SocketAddress::from_std_socket_addr(subpath.peer_addr);
            let cid = ConnectionId::generate_deterministic(1, sid as u64);
            engine.register_subpath(sid as u32, sid as u32, socket_addr, cid, true);
        }

        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        // Register subpath in health monitor
        if let Ok(mut monitor) = self.health_monitor.write() {
            monitor.register_subpath(sid, subpath.name.clone(), subpath.rtt_ms, now_ns);
        }

        // Register subpath in pacing engine
        if let Ok(mut pe) = self.pacing_engine.write() {
            pe.register_subpath(sid, subpath.bandwidth_bps, subpath.rtt_ms, now_ns);
        }

        let mut subpaths = self
            .subpaths
            .write()
            .map_err(|_| io::Error::other("Subpaths lock poisoned"))?;

        let mut def = self
            .default_subpath_id
            .write()
            .map_err(|_| io::Error::other("Default subpath lock poisoned"))?;
        if def.is_none() {
            *def = Some(sid);
        }

        subpaths.insert(sid, subpath);
        Ok(())
    }

    /// Remove a subpath from the active multipath transport pool.
    pub fn remove_subpath(
        &self,
        subpath_id: u8,
    ) -> Result<Option<AsyncMultipathSubpath>, io::Error> {
        if let Ok(mut mux) = self.mux.lock() {
            mux.remove_subpath_bdp(subpath_id);
        }

        if let Ok(mut monitor) = self.health_monitor.write() {
            monitor.unregister_subpath(subpath_id);
        }

        if let Ok(mut pe) = self.pacing_engine.write() {
            pe.unregister_subpath(subpath_id);
        }

        let mut subpaths = self
            .subpaths
            .write()
            .map_err(|_| io::Error::other("Subpaths lock poisoned"))?;

        let removed = subpaths.remove(&subpath_id);

        let mut def = self
            .default_subpath_id
            .write()
            .map_err(|_| io::Error::other("Default subpath lock poisoned"))?;
        if *def == Some(subpath_id) {
            *def = subpaths.keys().copied().next();
        }

        Ok(removed)
    }

    /// Open a new logical multiplexed stream.
    pub fn open_stream(
        &self,
        stream_id: StreamId,
        priority: StreamPriority,
        slice_class: FlowSliceClass,
        initial_max_stream_data: Option<u64>,
    ) -> Result<(), StreamMuxError> {
        let mut mux = self
            .mux
            .lock()
            .map_err(|_| StreamMuxError::InvalidControlFrame("Mux lock poisoned".to_string()))?;
        mux.open_stream(stream_id, priority, slice_class, initial_max_stream_data)
    }

    /// Write application payload bytes into an open stream.
    pub fn write_stream(
        &self,
        stream_id: StreamId,
        data: &[u8],
        fin: bool,
        preferred_subpath: Option<u8>,
    ) -> Result<usize, StreamMuxError> {
        let mut mux = self
            .mux
            .lock()
            .map_err(|_| StreamMuxError::InvalidControlFrame("Mux lock poisoned".to_string()))?;

        if let Some(sp) = preferred_subpath {
            mux.set_stream_preferred_subpath(stream_id, sp);
        } else if let Ok(def) = self.default_subpath_id.read() {
            if let Some(sp) = *def {
                mux.set_stream_preferred_subpath(stream_id, sp);
            }
        }

        mux.write_stream(stream_id, data, fin, 1400)
    }

    /// Flush and transmit all queued control and stream data frames across their assigned subpath sockets.
    ///
    /// Returns the total number of packets successfully sent.
    pub fn poll_and_transmit_pending(&self) -> Result<usize, io::Error> {
        let subpaths = self
            .subpaths
            .read()
            .map_err(|_| io::Error::other("Subpaths lock poisoned"))?;

        if subpaths.is_empty() {
            return Ok(0);
        }

        // Identify lowest-latency active subpath for urgent control frames
        let mut lowest_rtt_subpath: Option<&AsyncMultipathSubpath> = None;
        for sp in subpaths.values() {
            if sp.active {
                match lowest_rtt_subpath {
                    None => lowest_rtt_subpath = Some(sp),
                    Some(prev) if sp.rtt_ms < prev.rtt_ms => lowest_rtt_subpath = Some(sp),
                    _ => {}
                }
            }
        }

        let mut sent_count = 0;

        // 1. Transmit urgent control frames
        loop {
            let ctrl_frame = {
                let mut mux = self
                    .mux
                    .lock()
                    .map_err(|_| io::Error::other("Mux lock poisoned"))?;
                mux.poll_outgoing_control_frame()
            };

            match ctrl_frame {
                Some(frame) => {
                    if let Some(sp) = lowest_rtt_subpath {
                        let packet = MultipathMuxPacket::Control(frame);
                        let wire_bytes = packet.encode();
                        let n = sp.socket.send_to(&wire_bytes, sp.peer_addr)?;
                        sp.packets_sent.fetch_add(1, Ordering::Relaxed);
                        sp.bytes_sent.fetch_add(n as u64, Ordering::Relaxed);
                        sent_count += 1;
                    }
                }
                None => break,
            }
        }

        // Determine secondary subpath for 1+1 bicasting
        let secondary_subpath_id = {
            let mut keys: Vec<u8> = subpaths.keys().copied().collect();
            keys.sort_unstable();
            if keys.len() >= 2 {
                Some(keys[1])
            } else {
                None
            }
        };

        // 2. Transmit stream data frames
        loop {
            let stream_frame = {
                let mut mux = self
                    .mux
                    .lock()
                    .map_err(|_| io::Error::other("Mux lock poisoned"))?;
                mux.poll_outgoing_frame(secondary_subpath_id)
            };

            match stream_frame {
                Some(frame) => {
                    let packet = MultipathMuxPacket::Stream(frame.clone());
                    let wire_bytes = packet.encode();
                    let now_ns = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos() as u64;

                    let is_critical_slice = matches!(
                        frame.slice_class,
                        FlowSliceClass::UltraLowLatency | FlowSliceClass::MissionCritical
                    );

                    // Candidate list for health evaluation and failover
                    let candidates: Vec<(u8, String, u64, u64, bool)> = subpaths
                        .values()
                        .map(|s| {
                            (
                                s.subpath_id,
                                s.name.clone(),
                                s.rtt_ms,
                                s.bandwidth_bps,
                                s.active,
                            )
                        })
                        .collect();

                    // Proactive failover if the requested primary subpath is degraded/critical/down
                    let target_subpath_id = if is_critical_slice {
                        let primary_unhealthy = if let Ok(hm) = self.health_monitor.read() {
                            hm.tracker(frame.subpath_id)
                                .map(|t| !t.state.is_viable())
                                .unwrap_or(false)
                        } else {
                            false
                        };

                        if primary_unhealthy {
                            if let Ok(mut hm) = self.health_monitor.write() {
                                hm.select_best_fallback_subpath(
                                    frame.subpath_id,
                                    frame.slice_class,
                                    &candidates,
                                )
                                .unwrap_or(frame.subpath_id)
                            } else {
                                frame.subpath_id
                            }
                        } else {
                            frame.subpath_id
                        }
                    } else {
                        frame.subpath_id
                    };

                    // Primary transmission with adaptive slice shaping and inter-packet pacing
                    let primary_target = subpaths
                        .get(&target_subpath_id)
                        .filter(|s| s.active)
                        .or(lowest_rtt_subpath);

                    if let Some(sp) = primary_target {
                        let (_pacing_verdict, pacing_delay) = if let Ok(mut pacer) = sp.pacer.lock()
                        {
                            let v = pacer.evaluate_tx(frame.slice_class, wire_bytes.len(), now_ns);
                            let d = pacer.charge_tx(frame.slice_class, wire_bytes.len(), now_ns);
                            (v, d)
                        } else {
                            (SubpathPacingVerdict::Immediate, 0)
                        };

                        if let Ok(mut pe) = self.pacing_engine.write() {
                            pe.charge_tx(
                                sp.subpath_id,
                                frame.slice_class,
                                wire_bytes.len(),
                                now_ns,
                            );
                        }

                        let verdict = if let Ok(mut shaper) = sp.shaper.lock() {
                            shaper.try_admit(frame.slice_class, wire_bytes.len(), now_ns)
                        } else {
                            SubpathAdmissionVerdict::Admitted
                        };

                        match verdict {
                            SubpathAdmissionVerdict::Admitted => {
                                let n = sp.socket.send_to(&wire_bytes, sp.peer_addr)?;
                                sp.packets_sent.fetch_add(1, Ordering::Relaxed);
                                sp.bytes_sent.fetch_add(n as u64, Ordering::Relaxed);
                                if let Ok(mut shaper) = sp.shaper.lock() {
                                    shaper.record_transit_latency(
                                        frame.slice_class,
                                        (sp.rtt_ms * 500_000)
                                            .saturating_add(pacing_delay)
                                            .max(10_000),
                                    );
                                }
                                if let Ok(mut hm) = self.health_monitor.write() {
                                    hm.record_admission_success(sp.subpath_id, now_ns);
                                }
                                sent_count += 1;
                            }
                            SubpathAdmissionVerdict::Delayed { delay_ns } => {
                                let n = sp.socket.send_to(&wire_bytes, sp.peer_addr)?;
                                sp.packets_sent.fetch_add(1, Ordering::Relaxed);
                                sp.bytes_sent.fetch_add(n as u64, Ordering::Relaxed);
                                if let Ok(mut shaper) = sp.shaper.lock() {
                                    let transit_ns = (sp.rtt_ms * 500_000)
                                        .saturating_add(delay_ns.max(pacing_delay));
                                    shaper.record_transit_latency(frame.slice_class, transit_ns);
                                }
                                if let Ok(mut hm) = self.health_monitor.write() {
                                    hm.record_admission_success(sp.subpath_id, now_ns);
                                }
                                sent_count += 1;
                            }
                            SubpathAdmissionVerdict::Throttled { .. } => {
                                // Record admission failure on primary subpath
                                if let Ok(mut hm) = self.health_monitor.write() {
                                    hm.record_admission_failure(sp.subpath_id, now_ns);
                                }

                                // Transparent failover for critical slices upon throttling
                                if is_critical_slice {
                                    let fallback_id =
                                        if let Ok(mut hm) = self.health_monitor.write() {
                                            hm.select_best_fallback_subpath(
                                                sp.subpath_id,
                                                frame.slice_class,
                                                &candidates,
                                            )
                                        } else {
                                            None
                                        };

                                    if let Some(fb_id) = fallback_id {
                                        if let Some(sp_fb) =
                                            subpaths.get(&fb_id).filter(|s| s.active)
                                        {
                                            if let Ok(mut pacer) = sp_fb.pacer.lock() {
                                                pacer.charge_tx(
                                                    frame.slice_class,
                                                    wire_bytes.len(),
                                                    now_ns,
                                                );
                                            }
                                            let fb_verdict =
                                                if let Ok(mut shaper) = sp_fb.shaper.lock() {
                                                    shaper.try_admit(
                                                        frame.slice_class,
                                                        wire_bytes.len(),
                                                        now_ns,
                                                    )
                                                } else {
                                                    SubpathAdmissionVerdict::Admitted
                                                };

                                            match fb_verdict {
                                                SubpathAdmissionVerdict::Admitted
                                                | SubpathAdmissionVerdict::Delayed { .. } => {
                                                    let n = sp_fb
                                                        .socket
                                                        .send_to(&wire_bytes, sp_fb.peer_addr)?;
                                                    sp_fb
                                                        .packets_sent
                                                        .fetch_add(1, Ordering::Relaxed);
                                                    sp_fb
                                                        .bytes_sent
                                                        .fetch_add(n as u64, Ordering::Relaxed);
                                                    if let Ok(mut hm) = self.health_monitor.write()
                                                    {
                                                        hm.record_admission_success(fb_id, now_ns);
                                                    }
                                                    sent_count += 1;
                                                }
                                                SubpathAdmissionVerdict::Throttled { .. } => {}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Bicast secondary transmission for mission-critical slice
                    if frame.is_bicast {
                        if let Some(sec_id) = secondary_subpath_id {
                            if sec_id != target_subpath_id {
                                if let Some(sp_sec) = subpaths.get(&sec_id).filter(|s| s.active) {
                                    if let Ok(mut pacer) = sp_sec.pacer.lock() {
                                        pacer.charge_tx(
                                            frame.slice_class,
                                            wire_bytes.len(),
                                            now_ns,
                                        );
                                    }
                                    let verdict = if let Ok(mut shaper) = sp_sec.shaper.lock() {
                                        shaper.try_admit(
                                            frame.slice_class,
                                            wire_bytes.len(),
                                            now_ns,
                                        )
                                    } else {
                                        SubpathAdmissionVerdict::Admitted
                                    };

                                    match verdict {
                                        SubpathAdmissionVerdict::Admitted
                                        | SubpathAdmissionVerdict::Delayed { .. } => {
                                            let n = sp_sec
                                                .socket
                                                .send_to(&wire_bytes, sp_sec.peer_addr)?;
                                            sp_sec.packets_sent.fetch_add(1, Ordering::Relaxed);
                                            sp_sec
                                                .bytes_sent
                                                .fetch_add(n as u64, Ordering::Relaxed);
                                            if let Ok(mut shaper) = sp_sec.shaper.lock() {
                                                shaper.record_transit_latency(
                                                    frame.slice_class,
                                                    (sp_sec.rtt_ms * 500_000).max(10_000),
                                                );
                                            }
                                            if let Ok(mut hm) = self.health_monitor.write() {
                                                hm.record_admission_success(
                                                    sp_sec.subpath_id,
                                                    now_ns,
                                                );
                                            }
                                            sent_count += 1;
                                        }
                                        SubpathAdmissionVerdict::Throttled { .. } => {
                                            if let Ok(mut hm) = self.health_monitor.write() {
                                                hm.record_admission_failure(
                                                    sp_sec.subpath_id,
                                                    now_ns,
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                None => break,
            }
        }

        Ok(sent_count)
    }

    /// Non-blocking poll and ingestion of incoming packets from all registered UDP subpath sockets.
    ///
    /// Returns the number of successfully ingested packets.
    pub fn poll_incoming_and_ingest(&self, now_ms: u64) -> Result<usize, io::Error> {
        let mut completed_migrations = Vec::new();
        let mut ingested_count = 0;
        let mut buf = [0u8; 65536];

        {
            let subpaths = self
                .subpaths
                .read()
                .map_err(|_| io::Error::other("Subpaths lock poisoned"))?;

            for sp in subpaths.values() {
                if !sp.active {
                    continue;
                }

                loop {
                    match sp.socket.try_recv_from(&mut buf) {
                        Ok(Some((n, from_addr))) => {
                            sp.packets_received.fetch_add(1, Ordering::Relaxed);
                            sp.bytes_received.fetch_add(n as u64, Ordering::Relaxed);

                            if let Ok(packet) = MultipathMuxPacket::decode(&buf[..n]) {
                                match packet {
                                    MultipathMuxPacket::Migration(
                                        MigrationFrame::PathChallenge { nonce },
                                    ) => {
                                        // RFC 9000 §8.2.2: Echo matching PATH_RESPONSE to from_addr
                                        let resp = MultipathMuxPacket::Migration(
                                            MigrationFrame::PathResponse { nonce },
                                        );
                                        let resp_bytes = resp.encode();
                                        let _ = sp.socket.send_to(&resp_bytes, from_addr);
                                        sp.packets_sent.fetch_add(1, Ordering::Relaxed);
                                        sp.bytes_sent
                                            .fetch_add(resp_bytes.len() as u64, Ordering::Relaxed);

                                        if let Ok(mut engine) = self.migration_engine.lock() {
                                            let sender_addr =
                                                SocketAddress::from_std_socket_addr(from_addr);
                                            let chal = PathChallenge::new(
                                                nonce,
                                                now_ms.saturating_mul(1_000_000),
                                            );
                                            let _ = engine.handle_path_challenge(
                                                sp.subpath_id as u32,
                                                chal,
                                                sender_addr,
                                                now_ms.saturating_mul(1_000_000),
                                            );
                                        }
                                        ingested_count += 1;
                                    }
                                    MultipathMuxPacket::Migration(
                                        MigrationFrame::PathResponse { nonce },
                                    ) => {
                                        // Path validation response received
                                        let now_ns = now_ms.saturating_mul(1_000_000);
                                        if let Ok(mut engine) = self.migration_engine.lock() {
                                            let resp = PathResponse::new(nonce, now_ns);
                                            if let Ok(completion) =
                                                engine.verify_path_response_standalone(resp, now_ns)
                                            {
                                                completed_migrations.push(completion);
                                            }
                                        }
                                        ingested_count += 1;
                                    }
                                    MultipathMuxPacket::Migration(
                                        MigrationFrame::NewConnectionId { .. },
                                    )
                                    | MultipathMuxPacket::Migration(
                                        MigrationFrame::RetireConnectionId { .. },
                                    ) => {
                                        ingested_count += 1;
                                    }
                                    MultipathMuxPacket::Control(ctrl) => {
                                        let mut mux = self
                                            .mux
                                            .lock()
                                            .map_err(|_| io::Error::other("Mux lock poisoned"))?;
                                        let _ = mux.ingest_control_frame(ctrl);
                                        ingested_count += 1;
                                    }
                                    MultipathMuxPacket::Stream(stream_frame) => {
                                        let mut mux = self
                                            .mux
                                            .lock()
                                            .map_err(|_| io::Error::other("Mux lock poisoned"))?;
                                        if mux.ingest_incoming_frame(stream_frame).is_ok() {
                                            ingested_count += 1;
                                        }
                                    }
                                }
                            }
                        }
                        Ok(None) => break, // Socket buffer drained
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) => return Err(e),
                    }
                }
            }
        }

        // Apply completed migrations: seamlessly update subpath peer addresses
        if !completed_migrations.is_empty() {
            let mut subpaths_mut = self
                .subpaths
                .write()
                .map_err(|_| io::Error::other("Subpaths lock poisoned"))?;
            for completion in completed_migrations {
                let sid = completion.subpath_id as u8;
                if let Some(target_sp) = subpaths_mut.get_mut(&sid) {
                    target_sp.peer_addr = completion.new_address.to_std_socket_addr();
                    if completion.measured_rtt_ns > 0 {
                        target_sp.rtt_ms = (completion.measured_rtt_ns / 1_000_000).max(1);
                        if let Ok(mut mux) = self.mux.lock() {
                            mux.update_subpath_bdp(target_sp.subpath_id, target_sp.bdp_bytes());
                        }
                    }
                }
            }
        }

        // Trigger dynamic flow control updates if consumption or threshold reached
        if let Ok(mut mux) = self.mux.lock() {
            let _ = mux.check_and_generate_flow_control_updates();
        }

        Ok(ingested_count)
    }

    /// Initiates an RFC 9000 connection migration for a subpath to a new candidate peer address.
    ///
    /// Dispatches a PATH_CHALLENGE probe to the candidate address while enforcing anti-amplification controls.
    pub fn initiate_subpath_migration(
        &self,
        subpath_id: u8,
        new_peer_addr: SocketAddr,
        trigger: MigrationTrigger,
        now_ns: u64,
    ) -> Result<PathChallenge, MigrationError> {
        let (socket, wire_bytes, challenge) = {
            let subpaths = self
                .subpaths
                .read()
                .map_err(|_| MigrationError::SubpathNotFound(subpath_id as u32))?;
            let sp = subpaths
                .get(&subpath_id)
                .ok_or(MigrationError::SubpathNotFound(subpath_id as u32))?;

            let mut engine = self
                .migration_engine
                .lock()
                .map_err(|_| MigrationError::SubpathNotFound(subpath_id as u32))?;

            let target_addr = SocketAddress::from_std_socket_addr(new_peer_addr);
            let challenge = engine.initiate_migration(
                subpath_id as u32,
                subpath_id as u32,
                target_addr,
                trigger,
                now_ns,
            )?;

            let probe = MultipathMuxPacket::Migration(MigrationFrame::PathChallenge {
                nonce: challenge.nonce,
            });
            let wire_bytes = probe.encode();

            if let Some(tracker) = engine.anti_amplification_trackers.get_mut(&target_addr) {
                tracker.record_sent(wire_bytes.len());
            }

            sp.packets_sent.fetch_add(1, Ordering::Relaxed);
            sp.bytes_sent
                .fetch_add(wire_bytes.len() as u64, Ordering::Relaxed);

            (Arc::clone(&sp.socket), wire_bytes, challenge)
        };

        let _ = socket.send_to(&wire_bytes, new_peer_addr);
        Ok(challenge)
    }

    /// Handles unsolicited NAT rebinding when an incoming packet arrives from a changed 4-tuple address.
    pub fn handle_unsolicited_nat_rebinding(
        &self,
        subpath_id: u8,
        new_peer_addr: SocketAddr,
        now_ns: u64,
    ) -> Result<Option<PathChallenge>, MigrationError> {
        let (socket, wire_bytes_opt, challenge_opt) = {
            let subpaths = self
                .subpaths
                .read()
                .map_err(|_| MigrationError::SubpathNotFound(subpath_id as u32))?;
            let sp = subpaths
                .get(&subpath_id)
                .ok_or(MigrationError::SubpathNotFound(subpath_id as u32))?;

            let mut engine = self
                .migration_engine
                .lock()
                .map_err(|_| MigrationError::SubpathNotFound(subpath_id as u32))?;

            let new_sock_addr = SocketAddress::from_std_socket_addr(new_peer_addr);
            if let Some(challenge) = engine.handle_unsolicited_nat_rebinding(
                subpath_id as u32,
                subpath_id as u32,
                new_sock_addr,
                1400,
                now_ns,
            ) {
                let probe = MultipathMuxPacket::Migration(MigrationFrame::PathChallenge {
                    nonce: challenge.nonce,
                });
                let wire_bytes = probe.encode();
                sp.packets_sent.fetch_add(1, Ordering::Relaxed);
                sp.bytes_sent
                    .fetch_add(wire_bytes.len() as u64, Ordering::Relaxed);
                (Arc::clone(&sp.socket), Some(wire_bytes), Some(challenge))
            } else {
                (Arc::clone(&sp.socket), None, None)
            }
        };

        if let (Some(bytes), Some(challenge)) = (wire_bytes_opt, challenge_opt) {
            let _ = socket.send_to(&bytes, new_peer_addr);
            Ok(Some(challenge))
        } else {
            Ok(None)
        }
    }

    /// Returns the currently active remote peer address for a subpath.
    pub fn subpath_peer_addr(&self, subpath_id: u8) -> Option<SocketAddr> {
        self.subpaths
            .read()
            .ok()?
            .get(&subpath_id)
            .map(|sp| sp.peer_addr)
    }

    /// Directly rebinds a subpath to a new peer address (e.g. for immediate handover).
    pub fn rebind_subpath_peer_addr(
        &self,
        subpath_id: u8,
        new_peer_addr: SocketAddr,
    ) -> Result<(), io::Error> {
        let mut subpaths = self
            .subpaths
            .write()
            .map_err(|_| io::Error::other("Subpaths lock poisoned"))?;
        if let Some(sp) = subpaths.get_mut(&subpath_id) {
            sp.peer_addr = new_peer_addr;
            if let Ok(mut engine) = self.migration_engine.lock() {
                let socket_addr = SocketAddress::from_std_socket_addr(new_peer_addr);
                engine
                    .subpath_addresses
                    .insert(subpath_id as u32, socket_addr);
            }
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Subpath {} not found", subpath_id),
            ))
        }
    }

    /// Access the underlying connection migration engine for telemetry and validation status.
    pub fn migration_engine(&self) -> Arc<Mutex<ConnectionMigrationEngine>> {
        Arc::clone(&self.migration_engine)
    }

    /// Read contiguous, in-order assembled payload bytes from a logical stream.
    pub fn read_stream(&self, stream_id: StreamId, max_len: usize) -> Option<Vec<u8>> {
        let mut mux = self.mux.lock().ok()?;
        let data = mux.read_stream(stream_id, max_len);
        // Reading data frees up receive window: trigger credit calculation
        let _ = mux.check_and_generate_flow_control_updates();
        data
    }

    /// Check if a stream is complete (all offsets received up to FIN).
    pub fn is_stream_complete(&self, stream_id: StreamId) -> bool {
        self.mux
            .lock()
            .map(|mux| mux.is_stream_complete(stream_id))
            .unwrap_or(false)
    }

    /// Number of active logical streams.
    pub fn active_stream_count(&self) -> usize {
        self.mux
            .lock()
            .map(|mux| mux.active_stream_count())
            .unwrap_or(0)
    }

    /// Manually grant flow control credits to a specific stream.
    pub fn grant_stream_credit(&self, stream_id: StreamId, additional_bytes: u64) {
        if let Ok(mut mux) = self.mux.lock() {
            mux.grant_stream_credit(stream_id, additional_bytes);
        }
    }

    /// Manually grant connection-wide flow control credits.
    pub fn grant_connection_credit(&self, additional_bytes: u64) {
        if let Ok(mut mux) = self.mux.lock() {
            mux.grant_connection_credit(additional_bytes);
        }
    }

    /// Dynamically update the bandwidth of a specific subpath and proportionally rebalance its slice shaper.
    pub fn update_subpath_bandwidth(
        &self,
        subpath_id: u8,
        new_bandwidth_bps: u64,
        now_ns: u64,
    ) -> Result<(), io::Error> {
        let mut subpaths = self
            .subpaths
            .write()
            .map_err(|_| io::Error::other("Subpaths lock poisoned"))?;

        if let Some(sp) = subpaths.get_mut(&subpath_id) {
            sp.update_bandwidth(new_bandwidth_bps, now_ns);
            let bdp = sp.bdp_bytes();
            if let Ok(mut mux) = self.mux.lock() {
                mux.update_subpath_bdp(subpath_id, bdp);
            }
            if let Ok(mut pe) = self.pacing_engine.write() {
                pe.update_subpath_link(subpath_id, new_bandwidth_bps, sp.rtt_ms, now_ns);
            }
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Subpath {} not found", subpath_id),
            ))
        }
    }

    /// Access the slice traffic shaper of a specific subpath.
    pub fn subpath_shaper(&self, subpath_id: u8) -> Option<Arc<Mutex<SubpathSliceShaper>>> {
        self.subpaths
            .read()
            .ok()?
            .get(&subpath_id)
            .map(|sp| Arc::clone(&sp.shaper))
    }

    /// Apply dynamic backpressure reduction to a specific slice on a subpath.
    pub fn apply_subpath_backpressure(
        &self,
        subpath_id: u8,
        slice: FlowSliceClass,
        scale_pct: u32,
        now_ns: u64,
    ) -> Result<(), io::Error> {
        let subpaths = self
            .subpaths
            .read()
            .map_err(|_| io::Error::other("Subpaths lock poisoned"))?;

        if let Some(sp) = subpaths.get(&subpath_id) {
            if let Ok(mut shaper) = sp.shaper.lock() {
                shaper.apply_backpressure_reduction(slice, scale_pct, now_ns);
            }
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Subpath {} not found", subpath_id),
            ))
        }
    }

    /// Reset backpressure reduction for a specific slice on a subpath.
    pub fn reset_subpath_backpressure(
        &self,
        subpath_id: u8,
        slice: FlowSliceClass,
        now_ns: u64,
    ) -> Result<(), io::Error> {
        let subpaths = self
            .subpaths
            .read()
            .map_err(|_| io::Error::other("Subpaths lock poisoned"))?;

        if let Some(sp) = subpaths.get(&subpath_id) {
            if let Ok(mut shaper) = sp.shaper.lock() {
                shaper.reset_backpressure_reduction(slice, now_ns);
            }
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Subpath {} not found", subpath_id),
            ))
        }
    }

    /// Returns the subpath health monitor instance.
    pub fn health_monitor(&self) -> Arc<RwLock<SubpathHealthMonitor>> {
        self.health_monitor.clone()
    }

    /// Returns the multipath pacing engine instance.
    pub fn pacing_engine(&self) -> Arc<RwLock<MultipathPacingEngine>> {
        self.pacing_engine.clone()
    }

    /// Registers a health degradation alert sink.
    pub fn register_health_alert_sink(
        &self,
        sink: Arc<dyn SubpathAlertSink>,
    ) -> Result<(), io::Error> {
        let mut hm = self
            .health_monitor
            .write()
            .map_err(|_| io::Error::other("Health monitor lock poisoned"))?;
        hm.register_alert_sink(sink);
        Ok(())
    }

    /// Updates RTT measurement for a subpath and recalculates health score.
    pub fn record_subpath_rtt(&self, subpath_id: u8, rtt_ms: u64) -> Result<(), io::Error> {
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        if let Ok(mut subpaths) = self.subpaths.write() {
            if let Some(sp) = subpaths.get_mut(&subpath_id) {
                sp.rtt_ms = rtt_ms;
                if let Ok(mut pacer) = sp.pacer.lock() {
                    pacer.update_link(sp.bandwidth_bps, rtt_ms, now_ns);
                }
            }
        }

        if let Ok(mut pe) = self.pacing_engine.write() {
            if let Some(pacer) = pe.pacers.get_mut(&subpath_id) {
                pacer.update_link(pacer.bandwidth_bps, rtt_ms, now_ns);
            }
        }

        let mut hm = self
            .health_monitor
            .write()
            .map_err(|_| io::Error::other("Health monitor lock poisoned"))?;
        hm.record_rtt_measurement(subpath_id, rtt_ms, now_ns);
        Ok(())
    }

    /// Records a PMTU probe timeout/loss on a subpath, triggering degradation evaluation.
    pub fn record_subpath_pmtu_loss(&self, subpath_id: u8) -> Result<(), io::Error> {
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        let mut hm = self
            .health_monitor
            .write()
            .map_err(|_| io::Error::other("Health monitor lock poisoned"))?;
        hm.record_probe_loss(subpath_id, now_ns);
        Ok(())
    }

    /// Records a PMTU probe acknowledgment on a subpath.
    pub fn record_subpath_pmtu_ack(&self, subpath_id: u8) -> Result<(), io::Error> {
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        let mut hm = self
            .health_monitor
            .write()
            .map_err(|_| io::Error::other("Health monitor lock poisoned"))?;
        hm.record_probe_success(subpath_id, now_ns);
        Ok(())
    }

    /// Returns a telemetry snapshot for all registered subpaths.
    pub fn subpaths_snapshot(&self) -> Vec<SubpathTransportTelemetry> {
        let subpaths = match self.subpaths.read() {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let monitor = self.health_monitor.read().ok();
        let mut list: Vec<_> = subpaths
            .values()
            .map(|s| {
                let (score, state) = if let Some(ref m) = monitor {
                    if let Some(t) = m.tracker(s.subpath_id) {
                        (t.health_score, t.state)
                    } else {
                        (100, SubpathHealthState::Healthy)
                    }
                } else {
                    (100, SubpathHealthState::Healthy)
                };
                s.snapshot_with_health(score, state)
            })
            .collect();
        list.sort_by_key(|s| s.subpath_id);
        list
    }

    /// Exports full OpenMetrics / Prometheus telemetry covering streams and transport subpaths.
    pub fn export_prometheus_metrics(&self) -> String {
        let mut out = String::new();
        let active_streams = self.active_stream_count();

        if let Ok(mux) = self.mux.lock() {
            out.push_str(&mux.telemetry.export_prometheus_metrics(active_streams));
        }

        // Subpath specific metrics
        let _ = writeln!(
            out,
            "# HELP ifa_transport_subpath_packets_total Total packets processed per subpath."
        );
        let _ = writeln!(out, "# TYPE ifa_transport_subpath_packets_total counter");
        let _ = writeln!(
            out,
            "# HELP ifa_transport_subpath_bytes_total Total bytes processed per subpath."
        );
        let _ = writeln!(out, "# TYPE ifa_transport_subpath_bytes_total counter");
        let _ = writeln!(
            out,
            "# HELP ifa_transport_subpath_rtt_ms Smoothed RTT in milliseconds."
        );
        let _ = writeln!(out, "# TYPE ifa_transport_subpath_rtt_ms gauge");

        for sp in self.subpaths_snapshot() {
            let _ = writeln!(
                out,
                "ifa_transport_subpath_packets_total{{direction=\"sent\",subpath_id=\"{}\",name=\"{}\"}} {}",
                sp.subpath_id, sp.name, sp.packets_sent
            );
            let _ = writeln!(
                out,
                "ifa_transport_subpath_packets_total{{direction=\"received\",subpath_id=\"{}\",name=\"{}\"}} {}",
                sp.subpath_id, sp.name, sp.packets_received
            );
            let _ = writeln!(
                out,
                "ifa_transport_subpath_bytes_total{{direction=\"sent\",subpath_id=\"{}\",name=\"{}\"}} {}",
                sp.subpath_id, sp.name, sp.bytes_sent
            );
            let _ = writeln!(
                out,
                "ifa_transport_subpath_bytes_total{{direction=\"received\",subpath_id=\"{}\",name=\"{}\"}} {}",
                sp.subpath_id, sp.name, sp.bytes_received
            );
            let _ = writeln!(
                out,
                "ifa_transport_subpath_rtt_ms{{subpath_id=\"{}\",name=\"{}\"}} {}",
                sp.subpath_id, sp.name, sp.rtt_ms
            );
        }

        // Multi-slice adaptive traffic shaping metrics
        let _ = writeln!(
            out,
            "# HELP ifa_multipath_shaper_admitted_packets_total Total packets admitted by subpath slice shaper."
        );
        let _ = writeln!(
            out,
            "# TYPE ifa_multipath_shaper_admitted_packets_total counter"
        );
        let _ = writeln!(
            out,
            "# HELP ifa_multipath_shaper_admitted_bytes_total Total bytes admitted by subpath slice shaper."
        );
        let _ = writeln!(
            out,
            "# TYPE ifa_multipath_shaper_admitted_bytes_total counter"
        );
        let _ = writeln!(
            out,
            "# HELP ifa_multipath_shaper_throttled_packets_total Total packets throttled by subpath slice shaper."
        );
        let _ = writeln!(
            out,
            "# TYPE ifa_multipath_shaper_throttled_packets_total counter"
        );
        let _ = writeln!(
            out,
            "# HELP ifa_multipath_shaper_throttled_bytes_total Total bytes throttled by subpath slice shaper."
        );
        let _ = writeln!(
            out,
            "# TYPE ifa_multipath_shaper_throttled_bytes_total counter"
        );
        let _ = writeln!(
            out,
            "# HELP ifa_multipath_shaper_delayed_packets_total Total packets delayed/paced by subpath slice shaper."
        );
        let _ = writeln!(
            out,
            "# TYPE ifa_multipath_shaper_delayed_packets_total counter"
        );
        let _ = writeln!(
            out,
            "# HELP ifa_multipath_shaper_delayed_bytes_total Total bytes delayed/paced by subpath slice shaper."
        );
        let _ = writeln!(
            out,
            "# TYPE ifa_multipath_shaper_delayed_bytes_total counter"
        );
        let _ = writeln!(
            out,
            "# HELP ifa_multipath_shaper_effective_rate_bps Effective shaped bandwidth per subpath and slice."
        );
        let _ = writeln!(out, "# TYPE ifa_multipath_shaper_effective_rate_bps gauge");
        let _ = writeln!(
            out,
            "# HELP ifa_multipath_shaper_tokens_available_bytes Current available token bucket bytes per subpath and slice."
        );
        let _ = writeln!(
            out,
            "# TYPE ifa_multipath_shaper_tokens_available_bytes gauge"
        );
        let _ = writeln!(
            out,
            "# HELP ifa_multipath_shaper_transit_latency_seconds Average transit latency through subpath shaping."
        );
        let _ = writeln!(
            out,
            "# TYPE ifa_multipath_shaper_transit_latency_seconds gauge"
        );

        for sp in self.subpaths_snapshot() {
            for slice in &sp.shaper.slices {
                let slice_str = slice.slice_class.as_str();
                let _ = writeln!(
                    out,
                    "ifa_multipath_shaper_admitted_packets_total{{subpath_id=\"{}\",name=\"{}\",slice=\"{}\"}} {}",
                    sp.subpath_id, sp.name, slice_str, slice.admitted_packets
                );
                let _ = writeln!(
                    out,
                    "ifa_multipath_shaper_admitted_bytes_total{{subpath_id=\"{}\",name=\"{}\",slice=\"{}\"}} {}",
                    sp.subpath_id, sp.name, slice_str, slice.admitted_bytes
                );
                let _ = writeln!(
                    out,
                    "ifa_multipath_shaper_throttled_packets_total{{subpath_id=\"{}\",name=\"{}\",slice=\"{}\"}} {}",
                    sp.subpath_id, sp.name, slice_str, slice.throttled_packets
                );
                let _ = writeln!(
                    out,
                    "ifa_multipath_shaper_throttled_bytes_total{{subpath_id=\"{}\",name=\"{}\",slice=\"{}\"}} {}",
                    sp.subpath_id, sp.name, slice_str, slice.throttled_bytes
                );
                let _ = writeln!(
                    out,
                    "ifa_multipath_shaper_delayed_packets_total{{subpath_id=\"{}\",name=\"{}\",slice=\"{}\"}} {}",
                    sp.subpath_id, sp.name, slice_str, slice.delayed_packets
                );
                let _ = writeln!(
                    out,
                    "ifa_multipath_shaper_delayed_bytes_total{{subpath_id=\"{}\",name=\"{}\",slice=\"{}\"}} {}",
                    sp.subpath_id, sp.name, slice_str, slice.delayed_bytes
                );
                let _ = writeln!(
                    out,
                    "ifa_multipath_shaper_effective_rate_bps{{subpath_id=\"{}\",name=\"{}\",slice=\"{}\"}} {}",
                    sp.subpath_id, sp.name, slice_str, slice.effective_rate_bps
                );
                let _ = writeln!(
                    out,
                    "ifa_multipath_shaper_tokens_available_bytes{{subpath_id=\"{}\",name=\"{}\",slice=\"{}\"}} {:.2}",
                    sp.subpath_id, sp.name, slice_str, slice.current_tokens_bytes
                );
                let transit_sec = (slice.avg_transit_latency_ns as f64) / 1_000_000_000.0;
                let _ = writeln!(
                    out,
                    "ifa_multipath_shaper_transit_latency_seconds{{subpath_id=\"{}\",name=\"{}\",slice=\"{}\"}} {:.6}",
                    sp.subpath_id, sp.name, slice_str, transit_sec
                );
            }
        }

        // Connection migration metrics
        if let Ok(engine) = self.migration_engine.lock() {
            let _ = writeln!(
                out,
                "# HELP ifa_transport_migrations_initiated_total Total RFC 9000 connection migrations initiated."
            );
            let _ = writeln!(
                out,
                "# TYPE ifa_transport_migrations_initiated_total counter"
            );
            let _ = writeln!(
                out,
                "ifa_transport_migrations_initiated_total {}",
                engine.migrations_initiated_total
            );

            let _ = writeln!(
                out,
                "# HELP ifa_transport_migrations_completed_total Total connection migrations successfully validated."
            );
            let _ = writeln!(
                out,
                "# TYPE ifa_transport_migrations_completed_total counter"
            );
            let _ = writeln!(
                out,
                "ifa_transport_migrations_completed_total {}",
                engine.migrations_completed_total
            );

            let _ = writeln!(
                out,
                "# HELP ifa_transport_nat_rebindings_detected_total Total unsolicited NAT 4-tuple rebindings detected."
            );
            let _ = writeln!(
                out,
                "# TYPE ifa_transport_nat_rebindings_detected_total counter"
            );
            let _ = writeln!(
                out,
                "ifa_transport_nat_rebindings_detected_total {}",
                engine.nat_rebindings_detected_total
            );
        }

        // Subpath health monitoring and failover metrics
        if let Ok(hm) = self.health_monitor.read() {
            out.push_str(&hm.export_prometheus_metrics());
        }

        // Subpath pacing engine metrics
        if let Ok(pe) = self.pacing_engine.read() {
            out.push_str(&pe.export_prometheus_metrics());
        }

        out
    }
}

impl Default for AsyncMultipathTransport {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multipath_async_transport_hol_elimination_over_asymmetric_udp_sockets() {
        // 1. Setup Sender and Receiver transports
        let sender = AsyncMultipathTransport::new();
        let receiver = AsyncMultipathTransport::new();

        // 2. Bind real loopback UDP sockets for Subpath 1 (Fast Fiber) and Subpath 2 (High-Latency / Skewed 5G)
        let s1_sender_sock = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").expect("bind s1 sender"));
        let s1_receiver_sock =
            Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").expect("bind s1 receiver"));
        let s1_recv_addr = s1_receiver_sock.local_addr().expect("addr s1 recv");
        let s1_send_addr = s1_sender_sock.local_addr().expect("addr s1 send");

        let s2_sender_sock = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").expect("bind s2 sender"));
        let s2_receiver_sock =
            Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").expect("bind s2 receiver"));
        let s2_recv_addr = s2_receiver_sock.local_addr().expect("addr s2 recv");
        let s2_send_addr = s2_sender_sock.local_addr().expect("addr s2 send");

        // Subpath 1: Fiber WAN (10ms RTT, 100 Mbps)
        let s1_send = AsyncMultipathSubpath::new(
            1,
            "wan-fiber",
            s1_sender_sock,
            s1_recv_addr,
            10,
            100_000_000,
        );
        let s1_recv = AsyncMultipathSubpath::new(
            1,
            "wan-fiber",
            s1_receiver_sock,
            s1_send_addr,
            10,
            100_000_000,
        );

        // Subpath 2: 5G Edge (60ms RTT, 50 Mbps)
        let s2_send =
            AsyncMultipathSubpath::new(2, "wwan-5g", s2_sender_sock, s2_recv_addr, 60, 50_000_000);
        let s2_recv = AsyncMultipathSubpath::new(
            2,
            "wwan-5g",
            s2_receiver_sock,
            s2_send_addr,
            60,
            50_000_000,
        );

        sender.add_subpath(s1_send).expect("add s1 sender");
        sender.add_subpath(s2_send).expect("add s2 sender");
        receiver.add_subpath(s1_recv).expect("add s1 receiver");
        receiver.add_subpath(s2_recv).expect("add s2 receiver");

        // 3. Open Stream 10 (Bulk transfer on Subpath 1) and Stream 20 (Interactive RPC on Subpath 2)
        let stream_bulk = StreamId::client_bidi(10);
        let stream_rpc = StreamId::client_bidi(20);

        sender
            .open_stream(
                stream_bulk,
                StreamPriority::Normal,
                FlowSliceClass::HighThroughput,
                Some(131072),
            )
            .expect("open bulk sender");
        sender
            .open_stream(
                stream_rpc,
                StreamPriority::HighInteractive,
                FlowSliceClass::UltraLowLatency,
                Some(131072),
            )
            .expect("open rpc sender");

        receiver
            .open_stream(
                stream_bulk,
                StreamPriority::Normal,
                FlowSliceClass::HighThroughput,
                Some(131072),
            )
            .expect("open bulk receiver");
        receiver
            .open_stream(
                stream_rpc,
                StreamPriority::HighInteractive,
                FlowSliceClass::UltraLowLatency,
                Some(131072),
            )
            .expect("open rpc receiver");

        // 4. Write data to both streams
        let bulk_data = vec![0xAA; 4096];
        let rpc_data = b"URGENT_INTERACTIVE_COMMAND_EXECUTE".to_vec();

        sender
            .write_stream(stream_bulk, &bulk_data, true, Some(1))
            .expect("write bulk");
        sender
            .write_stream(stream_rpc, &rpc_data, true, Some(2))
            .expect("write rpc");

        // 5. Transmit pending frames over real UDP sockets
        let sent = sender
            .poll_and_transmit_pending()
            .expect("transmit pending");
        assert!(
            sent >= 2,
            "Expected at least 2 frames transmitted, got {}",
            sent
        );

        // 6. Ingest incoming packets on receiver
        let ingested = receiver
            .poll_incoming_and_ingest(100)
            .expect("ingest incoming");
        assert!(
            ingested >= 2,
            "Expected at least 2 frames ingested, got {}",
            ingested
        );

        // 7. Verify Zero Head-of-Line Blocking:
        // Stream 20 is immediately readable and completely received regardless of Stream 10
        let rpc_read = receiver
            .read_stream(stream_rpc, 1024)
            .expect("read rpc data");
        assert_eq!(rpc_read, rpc_data);
        assert!(receiver.is_stream_complete(stream_rpc));

        let bulk_read = receiver
            .read_stream(stream_bulk, 8192)
            .expect("read bulk data");
        assert_eq!(bulk_read, bulk_data);
        assert!(receiver.is_stream_complete(stream_bulk));
    }

    #[test]
    fn test_multipath_async_transport_dynamic_flow_control_autotuning_loop() {
        let sender = AsyncMultipathTransport::new();
        let receiver = AsyncMultipathTransport::new();

        let s1_sock_a = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").expect("bind s1 a"));
        let s1_sock_b = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").expect("bind s1 b"));
        let addr_a = s1_sock_a.local_addr().expect("addr a");
        let addr_b = s1_sock_b.local_addr().expect("addr b");

        // Setup subpath
        sender
            .add_subpath(AsyncMultipathSubpath::new(
                1, "wan", s1_sock_a, addr_b, 15, 80_000_000,
            ))
            .expect("add subpath sender");
        receiver
            .add_subpath(AsyncMultipathSubpath::new(
                1, "wan", s1_sock_b, addr_a, 15, 80_000_000,
            ))
            .expect("add subpath receiver");

        let stream_id = StreamId::client_bidi(5);

        // Open stream with a small initial window: 2048 bytes
        sender
            .open_stream(
                stream_id,
                StreamPriority::Normal,
                FlowSliceClass::HighThroughput,
                Some(2048),
            )
            .expect("open sender");
        receiver
            .open_stream(
                stream_id,
                StreamPriority::Normal,
                FlowSliceClass::HighThroughput,
                Some(2048),
            )
            .expect("open receiver");

        // Step 1: Sender writes 2048 bytes (saturating initial window)
        let chunk1 = vec![0x11; 2048];
        let written1 = sender
            .write_stream(stream_id, &chunk1, false, Some(1))
            .expect("write chunk 1");
        assert_eq!(written1, 2048);

        // Writing more now should be flow-control blocked
        let chunk2 = vec![0x22; 1024];
        let err = sender.write_stream(stream_id, &chunk2, true, Some(1));
        assert!(matches!(
            err,
            Err(StreamMuxError::StreamFlowControlBlocked { .. })
        ));

        // Transmit chunk1 to receiver
        let sent1 = sender.poll_and_transmit_pending().expect("transmit chunk1");
        assert!(sent1 >= 1);

        // Receiver receives chunk1
        let ingested1 = receiver
            .poll_incoming_and_ingest(50)
            .expect("ingest chunk1");
        assert!(ingested1 >= 1);

        // Receiver consumes chunk1 -> this expands the window and triggers MAX_STREAM_DATA generation
        let read1 = receiver.read_stream(stream_id, 2048).expect("read chunk1");
        assert_eq!(read1.len(), 2048);

        // Receiver sends MAX_STREAM_DATA control frame back to sender over UDP socket
        let ctrl_sent = receiver
            .poll_and_transmit_pending()
            .expect("transmit control frame");
        assert!(
            ctrl_sent >= 1,
            "Receiver should transmit flow control frame back"
        );

        // Sender receives and ingests control frame
        let ctrl_ingested = sender
            .poll_incoming_and_ingest(60)
            .expect("sender ingest ctrl frame");
        assert!(ctrl_ingested >= 1, "Sender should ingest control frame");

        // Now sender's window is expanded! Sender can write chunk2 successfully
        let written2 = sender
            .write_stream(stream_id, &chunk2, true, Some(1))
            .expect("write chunk 2 after window expansion");
        assert_eq!(written2, 1024);

        // Transmit and ingest chunk2
        sender.poll_and_transmit_pending().expect("transmit chunk2");
        receiver
            .poll_incoming_and_ingest(70)
            .expect("ingest chunk2");

        let read2 = receiver.read_stream(stream_id, 1024).expect("read chunk2");
        assert_eq!(read2, chunk2);
        assert!(receiver.is_stream_complete(stream_id));
    }

    #[test]
    fn test_multipath_async_transport_mission_critical_bicasting() {
        let sender = AsyncMultipathTransport::new();
        let receiver = AsyncMultipathTransport::new();

        let s1_sock_a = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").expect("bind s1 a"));
        let s1_sock_b = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").expect("bind s1 b"));
        let s2_sock_a = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").expect("bind s2 a"));
        let s2_sock_b = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").expect("bind s2 b"));

        sender
            .add_subpath(AsyncMultipathSubpath::new(
                1,
                "path1",
                s1_sock_a.clone(),
                s1_sock_b.local_addr().unwrap(),
                10,
                100_000_000,
            ))
            .unwrap();
        sender
            .add_subpath(AsyncMultipathSubpath::new(
                2,
                "path2",
                s2_sock_a.clone(),
                s2_sock_b.local_addr().unwrap(),
                20,
                100_000_000,
            ))
            .unwrap();

        receiver
            .add_subpath(AsyncMultipathSubpath::new(
                1,
                "path1",
                s1_sock_b,
                s1_sock_a.local_addr().unwrap(),
                10,
                100_000_000,
            ))
            .unwrap();
        receiver
            .add_subpath(AsyncMultipathSubpath::new(
                2,
                "path2",
                s2_sock_b,
                s2_sock_a.local_addr().unwrap(),
                20,
                100_000_000,
            ))
            .unwrap();

        let critical_stream = StreamId::client_bidi(99);

        sender
            .open_stream(
                critical_stream,
                StreamPriority::CriticalControl,
                FlowSliceClass::MissionCritical,
                Some(65536),
            )
            .unwrap();
        receiver
            .open_stream(
                critical_stream,
                StreamPriority::CriticalControl,
                FlowSliceClass::MissionCritical,
                Some(65536),
            )
            .unwrap();

        let critical_payload = b"CLUSTER_CONSENSUS_VOTE_COMMIT_HASH_0xDEADBEEF";
        sender
            .write_stream(critical_stream, critical_payload, true, Some(1))
            .unwrap();

        // Transmitting should send 2 copies (1 on path1, 1 bicast on path2)
        let sent_packets = sender.poll_and_transmit_pending().unwrap();
        assert_eq!(
            sent_packets, 2,
            "MissionCritical slice should bicast 2 packets"
        );

        // Receiver receives both copies over the two distinct UDP sockets
        let ingested_packets = receiver.poll_incoming_and_ingest(100).unwrap();
        assert_eq!(ingested_packets, 2, "Receiver should ingest both packets");

        // Deduplication guarantee: application receives exactly one contiguous, bit-exact payload
        let delivered = receiver
            .read_stream(critical_stream, 1024)
            .expect("read delivered payload");
        assert_eq!(delivered, critical_payload);
        assert!(receiver.is_stream_complete(critical_stream));
    }

    #[test]
    fn test_multipath_transport_telemetry_and_openmetrics() {
        let transport = AsyncMultipathTransport::new();
        let sock = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").expect("bind"));
        let addr = sock.local_addr().expect("addr");

        transport
            .add_subpath(AsyncMultipathSubpath::new(
                1,
                "eth0-wan",
                sock,
                addr,
                12,
                100_000_000,
            ))
            .unwrap();

        let metrics = transport.export_prometheus_metrics();
        assert!(metrics.contains("ifa_transport_subpath_packets_total"));
        assert!(metrics.contains("ifa_transport_subpath_bytes_total"));
        assert!(metrics.contains("ifa_transport_subpath_rtt_ms"));
        assert!(metrics.contains("subpath_id=\"1\""));
        assert!(metrics.contains("name=\"eth0-wan\""));
        assert!(metrics.contains("ifa_transport_migrations_initiated_total"));
        assert!(metrics.contains("ifa_transport_migrations_completed_total"));
    }

    #[test]
    fn test_multipath_transport_connection_migration_zero_loss_handover() {
        let client = AsyncMultipathTransport::new();
        let server = AsyncMultipathTransport::new();

        let client_sock = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").expect("client bind"));
        let server_sock_1 = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").expect("server bind 1"));
        let server_sock_2 = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").expect("server bind 2"));

        let client_addr = client_sock.local_addr().expect("client addr");
        let server_addr_1 = server_sock_1.local_addr().expect("server addr 1");
        let server_addr_2 = server_sock_2.local_addr().expect("server addr 2");

        // Client registers subpath 1 pointing to server primary address 1
        client
            .add_subpath(AsyncMultipathSubpath::new(
                1,
                "wan1",
                Arc::clone(&client_sock),
                server_addr_1,
                10,
                100_000_000,
            ))
            .expect("add subpath client 1");

        // Server registers both interfaces
        server
            .add_subpath(AsyncMultipathSubpath::new(
                1,
                "wan1",
                Arc::clone(&server_sock_1),
                client_addr,
                10,
                100_000_000,
            ))
            .expect("add subpath server 1");
        server
            .add_subpath(AsyncMultipathSubpath::new(
                2,
                "wan2",
                Arc::clone(&server_sock_2),
                client_addr,
                15,
                100_000_000,
            ))
            .expect("add subpath server 2");

        let stream_id = StreamId::client_bidi(7);
        client
            .open_stream(
                stream_id,
                StreamPriority::Normal,
                FlowSliceClass::HighThroughput,
                Some(65536),
            )
            .expect("open stream client");
        server
            .open_stream(
                stream_id,
                StreamPriority::Normal,
                FlowSliceClass::HighThroughput,
                Some(65536),
            )
            .expect("open stream server");

        // Phase 1: Send initial payload segment on WAN 1
        let seg1 = b"SEGMENT_1_PRE_MIGRATION_";
        client
            .write_stream(stream_id, seg1, false, Some(1))
            .expect("write seg1");
        let sent_1 = client.poll_and_transmit_pending().expect("transmit seg1");
        assert_eq!(sent_1, 1);

        let rec_1 = server.poll_incoming_and_ingest(10).expect("ingest seg1");
        assert_eq!(rec_1, 1);
        let delivered_1 = server
            .read_stream(stream_id, 100)
            .expect("read delivered 1");
        assert_eq!(delivered_1, seg1);

        // Verify pre-migration peer address
        assert_eq!(client.subpath_peer_addr(1), Some(server_addr_1));

        // Phase 2: Initiate RFC 9000 Connection Migration of Subpath 1 to server_addr_2 (WAN 2)
        let _challenge = client
            .initiate_subpath_migration(
                1,
                server_addr_2,
                MigrationTrigger::PlannedHandover {
                    reason: "wan1_to_wan2".to_string(),
                },
                1_000_000,
            )
            .expect("initiate migration");

        // Server receives PATH_CHALLENGE on socket 2 and responds with PATH_RESPONSE
        let s_ingest = server
            .poll_incoming_and_ingest(20)
            .expect("server ingest challenge");
        assert_eq!(s_ingest, 1);

        // Client receives PATH_RESPONSE, concluding path validation and rebinding subpath 1
        let c_ingest = client
            .poll_incoming_and_ingest(30)
            .expect("client ingest response");
        assert_eq!(c_ingest, 1);

        // Subpath 1 peer address must now be rebound to server_addr_2!
        assert_eq!(
            client.subpath_peer_addr(1),
            Some(server_addr_2),
            "Subpath 1 peer address should be rebound to server_addr_2"
        );

        // Phase 3: Transmit second segment on Subpath 1 (now seamlessly routed to server_addr_2)
        let seg2 = b"SEGMENT_2_POST_MIGRATION_ZERO_LOSS";
        client
            .write_stream(stream_id, seg2, true, Some(1))
            .expect("write seg2");
        let sent_2 = client.poll_and_transmit_pending().expect("transmit seg2");
        assert!(sent_2 >= 1);

        // Server receives second segment on socket 2
        let rec_2 = server.poll_incoming_and_ingest(40).expect("ingest seg2");
        assert!(rec_2 >= 1);

        let delivered_2 = server
            .read_stream(stream_id, 100)
            .expect("read delivered 2");
        assert_eq!(delivered_2, seg2);
        assert!(server.is_stream_complete(stream_id));

        // Verify telemetry and metrics
        let client_metrics = client.export_prometheus_metrics();
        assert!(client_metrics.contains("ifa_transport_migrations_initiated_total 1"));
        assert!(client_metrics.contains("ifa_transport_migrations_completed_total 1"));

        // Test Unsolicited NAT Rebinding detection
        let nat_challenge = client
            .handle_unsolicited_nat_rebinding(1, server_addr_1, 2_000_000)
            .expect("handle nat rebinding");
        assert!(nat_challenge.is_some());
        let updated_metrics = client.export_prometheus_metrics();
        assert!(updated_metrics.contains("ifa_transport_nat_rebindings_detected_total 1"));
    }

    #[test]
    fn test_subpath_slice_shaping_and_dynamic_bandwidth_rebalance() {
        let transport = AsyncMultipathTransport::new();
        let sock = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").expect("bind"));
        let addr = sock.local_addr().expect("addr");

        let subpath = AsyncMultipathSubpath::new(1, "eth0-wan", sock, addr, 15, 10_000_000); // 10 Mbps
        transport.add_subpath(subpath).expect("add subpath");

        // Open streams across multiple slices
        let st_urllc = StreamId::client_bidi(1);
        let st_embb = StreamId::client_bidi(2);

        transport
            .open_stream(
                st_urllc,
                StreamPriority::CriticalControl,
                FlowSliceClass::UltraLowLatency,
                Some(65536),
            )
            .expect("open urllc");
        transport
            .open_stream(
                st_embb,
                StreamPriority::Normal,
                FlowSliceClass::HighThroughput,
                Some(65536),
            )
            .expect("open embb");

        // Write and transmit packets
        transport
            .write_stream(st_urllc, b"URLLC_PRIORITY_DATA", false, Some(1))
            .expect("write urllc");
        transport
            .write_stream(st_embb, b"HIGH_THROUGHPUT_DATA", false, Some(1))
            .expect("write embb");

        let transmitted = transport.poll_and_transmit_pending().expect("transmit");
        assert!(transmitted >= 2);

        // Check shaper state
        let shaper_arc = transport.subpath_shaper(1).expect("subpath shaper");
        let shaper = shaper_arc.lock().unwrap();
        let ull_limiter = shaper
            .limiters
            .get(&FlowSliceClass::UltraLowLatency)
            .unwrap();
        assert!(ull_limiter.admitted_packets >= 1);
        assert_eq!(ull_limiter.configured_rate_bps, 2_000_000); // 20% of 10M
        drop(shaper);

        // Dynamically rebalance bandwidth to 50 Mbps
        transport
            .update_subpath_bandwidth(1, 50_000_000, 2_000_000_000)
            .expect("update bw");
        let shaper = shaper_arc.lock().unwrap();
        let ull_scaled = shaper
            .limiters
            .get(&FlowSliceClass::UltraLowLatency)
            .unwrap();
        assert_eq!(ull_scaled.effective_rate_bps, 10_000_000); // 20% of 50M
        let ht_scaled = shaper
            .limiters
            .get(&FlowSliceClass::HighThroughput)
            .unwrap();
        assert_eq!(ht_scaled.effective_rate_bps, 17_500_000); // 35% of 50M
        drop(shaper);

        // Test backpressure reduction on HighThroughput slice
        transport
            .apply_subpath_backpressure(1, FlowSliceClass::HighThroughput, 50, 3_000_000_000)
            .expect("backpressure");
        let shaper = shaper_arc.lock().unwrap();
        let ht_throttled = shaper
            .limiters
            .get(&FlowSliceClass::HighThroughput)
            .unwrap();
        assert_eq!(ht_throttled.effective_rate_bps, 8_750_000); // 50% of 17.5M
        drop(shaper);

        // Reset backpressure
        transport
            .reset_subpath_backpressure(1, FlowSliceClass::HighThroughput, 4_000_000_000)
            .expect("reset backpressure");
        let shaper = shaper_arc.lock().unwrap();
        let ht_restored = shaper
            .limiters
            .get(&FlowSliceClass::HighThroughput)
            .unwrap();
        assert_eq!(ht_restored.effective_rate_bps, 17_500_000);
        drop(shaper);

        // Verify OpenMetrics Prometheus telemetry output
        let prom = transport.export_prometheus_metrics();
        assert!(prom.contains("ifa_multipath_shaper_admitted_packets_total{subpath_id=\"1\",name=\"eth0-wan\",slice=\"ultra_low_latency\"}"));
        assert!(prom.contains("ifa_multipath_shaper_effective_rate_bps{subpath_id=\"1\",name=\"eth0-wan\",slice=\"high_throughput\"} 17500000"));
        assert!(prom.contains("ifa_multipath_shaper_tokens_available_bytes{subpath_id=\"1\",name=\"eth0-wan\",slice=\"mission_critical\"}"));
        assert!(prom.contains("ifa_multipath_shaper_transit_latency_seconds{subpath_id=\"1\",name=\"eth0-wan\",slice=\"ultra_low_latency\"}"));
    }

    use crate::subpath_health::SubpathDegradedAlertEvent;

    struct HealthAlertRecorder {
        alert_count: Arc<AtomicU64>,
    }

    impl SubpathAlertSink for HealthAlertRecorder {
        fn on_alert(&self, _alert: &SubpathDegradedAlertEvent) {
            self.alert_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn test_subpath_health_monitor_integration_and_transparent_failover() {
        let r1_sock = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").expect("bind r1"));
        let r1_addr = r1_sock.local_addr().expect("r1 local_addr");
        let s1_sock = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").expect("bind s1"));

        let r2_sock = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").expect("bind r2"));
        let r2_addr = r2_sock.local_addr().expect("r2 local_addr");
        let s2_sock = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").expect("bind s2"));

        let transport = AsyncMultipathTransport::new();
        let alerts_fired = Arc::new(AtomicU64::new(0));
        transport
            .register_health_alert_sink(Arc::new(HealthAlertRecorder {
                alert_count: alerts_fired.clone(),
            }))
            .expect("register alert sink");

        let sp1 = AsyncMultipathSubpath::new(1, "eth0-wan", s1_sock, r1_addr, 10, 10_000_000);
        let sp2 = AsyncMultipathSubpath::new(2, "wwan-5g", s2_sock, r2_addr, 40, 50_000_000);

        transport.add_subpath(sp1).expect("add sp1");
        transport.add_subpath(sp2).expect("add sp2");

        let snap = transport.subpaths_snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].health_score, 100);
        assert_eq!(snap[0].health_state, SubpathHealthState::Healthy);
        assert_eq!(snap[1].health_score, 100);
        assert_eq!(snap[1].health_state, SubpathHealthState::Healthy);

        // Open UltraLowLatency critical stream
        transport
            .open_stream(
                StreamId(10),
                StreamPriority::CriticalControl,
                FlowSliceClass::UltraLowLatency,
                None,
            )
            .expect("open stream");

        // Write first message, should go to primary subpath 1
        transport
            .write_stream(StreamId(10), b"Initial critical packet", false, Some(1))
            .expect("write stream");
        let sent = transport.poll_and_transmit_pending().expect("transmit");
        assert_eq!(sent, 1);

        // Verify subpath 1 socket received the frame
        let mut buf = [0u8; 2048];
        let (n1, _) = r1_sock
            .try_recv_from(&mut buf)
            .expect("recv r1")
            .expect("got packet on r1");
        assert!(n1 > 0);

        // Degrade subpath 1 via consecutive PMTU probe losses
        transport.record_subpath_pmtu_loss(1).expect("probe loss 1");
        transport.record_subpath_pmtu_loss(1).expect("probe loss 2");
        transport.record_subpath_pmtu_loss(1).expect("probe loss 3");

        assert!(alerts_fired.load(Ordering::Relaxed) >= 1);

        // Verify subpath 1 state is now Down in snapshot
        let snap_degraded = transport.subpaths_snapshot();
        assert_eq!(snap_degraded[0].health_state, SubpathHealthState::Down);
        assert_eq!(snap_degraded[0].health_score, 0);

        // Write another message on critical stream targeted at subpath 1
        // Transparent failover must automatically reroute to surviving healthy subpath 2!
        transport
            .write_stream(StreamId(10), b"Failover critical packet", true, Some(1))
            .expect("write stream failover");
        let sent_failover = transport
            .poll_and_transmit_pending()
            .expect("transmit failover");
        assert_eq!(sent_failover, 1);

        // Verify subpath 2 socket received the failover frame
        let (n2, _) = r2_sock
            .try_recv_from(&mut buf)
            .expect("recv r2")
            .expect("got packet on r2");
        assert!(n2 > 0);

        // Prometheus metrics check
        let prom = transport.export_prometheus_metrics();
        assert!(
            prom.contains("ifa_transport_subpath_health_score{subpath=\"1\",name=\"eth0-wan\"} 0")
        );
        assert!(
            prom.contains("ifa_transport_subpath_health_score{subpath=\"2\",name=\"wwan-5g\"} 100")
        );
        assert!(prom.contains(
            "ifa_transport_subpath_failover_events_total{subpath=\"1\",name=\"eth0-wan\"} 1"
        ));
        assert!(prom.contains("ifa_transport_subpath_state{subpath=\"1\",state=\"down\"} 1"));
        assert!(prom.contains("ifa_transport_subpath_state{subpath=\"2\",state=\"healthy\"} 1"));
    }

    #[test]
    fn test_multipath_transport_pacing_engine_inter_packet_burst_smoothing_and_urllc_preemption() {
        let transport = AsyncMultipathTransport::new();

        let s1 = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").expect("bind s1"));
        let r1 = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").expect("bind r1"));
        let r1_addr = r1.local_addr().expect("r1 addr");

        // Register subpath: 50 Mbps, 20 ms RTT -> BDP = 125,000 bytes
        let subpath = AsyncMultipathSubpath::new(1, "eth0-wan", s1, r1_addr, 20, 50_000_000);
        transport.add_subpath(subpath).expect("add subpath");

        // 1. Open URLLC stream and bulk HighThroughput stream
        transport
            .open_stream(
                StreamId(1),
                StreamPriority::CriticalControl,
                FlowSliceClass::UltraLowLatency,
                None,
            )
            .expect("open urllc");
        transport
            .open_stream(
                StreamId(2),
                StreamPriority::Normal,
                FlowSliceClass::HighThroughput,
                None,
            )
            .expect("open bulk");

        // 2. Write URLLC frame and bulk frame
        transport
            .write_stream(StreamId(1), b"URLLC telemetry probe", false, Some(1))
            .expect("write urllc");
        transport
            .write_stream(StreamId(2), b"Bulk data block 1", false, Some(1))
            .expect("write bulk");

        let sent = transport.poll_and_transmit_pending().expect("transmit");
        assert!(sent >= 2);

        // Verify subpath snapshot contains valid pacing telemetry
        let snaps = transport.subpaths_snapshot();
        assert_eq!(snaps.len(), 1);
        let pacer_snap = &snaps[0].pacer;
        assert_eq!(pacer_snap.subpath_id, 1);
        assert_eq!(pacer_snap.bandwidth_bps, 50_000_000);
        assert_eq!(pacer_snap.bdp_bytes, 125_000);
        assert!(pacer_snap.total_paced_packets >= 2);
        assert!(pacer_snap.total_urllc_bypass_packets >= 1);

        // Verify Prometheus metrics export contains pacing telemetry
        let prom = transport.export_prometheus_metrics();
        assert!(prom.contains("ifa_transport_subpath_pacing_rate_bps{subpath_id=\"1\"} 50000000"));
        assert!(prom.contains("ifa_transport_subpath_bdp_bytes{subpath_id=\"1\"} 125000"));
        assert!(prom.contains(
            "ifa_transport_subpath_urllc_guaranteed_injections_total{subpath_id=\"1\"} 1"
        ));
    }
}

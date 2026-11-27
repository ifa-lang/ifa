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
use crate::multipath_stream_mux::{
    MigrationFrame, MultipathMuxPacket, MultipathStreamMux, StreamId, StreamMuxError,
    StreamPriority,
};
use crate::reactor::AsyncUdpSocket;
use crate::traffic_slicing::FlowSliceClass;

/// Snapshot telemetry of an individual transport subpath.
#[derive(Debug, Clone, PartialEq, Eq)]
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
        }
    }

    /// Estimated Bandwidth-Delay Product (BDP) in bytes.
    pub fn bdp_bytes(&self) -> u64 {
        // BDP = (bandwidth_bps / 8) * (rtt_ms / 1000)
        let bytes_per_sec = self.bandwidth_bps / 8;
        (bytes_per_sec.saturating_mul(self.rtt_ms)) / 1000
    }

    pub fn snapshot(&self) -> SubpathTransportTelemetry {
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
}

impl AsyncMultipathTransport {
    /// Creates a new multipath transport instance with a default stream multiplexer.
    pub fn new() -> Self {
        Self {
            mux: Arc::new(Mutex::new(MultipathStreamMux::new())),
            subpaths: Arc::new(RwLock::new(HashMap::new())),
            default_subpath_id: Arc::new(RwLock::new(None)),
            migration_engine: Arc::new(Mutex::new(ConnectionMigrationEngine::new())),
        }
    }

    /// Creates a transport instance with an existing preconfigured multiplexer.
    pub fn with_mux(mux: MultipathStreamMux) -> Self {
        Self {
            mux: Arc::new(Mutex::new(mux)),
            subpaths: Arc::new(RwLock::new(HashMap::new())),
            default_subpath_id: Arc::new(RwLock::new(None)),
            migration_engine: Arc::new(Mutex::new(ConnectionMigrationEngine::new())),
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

                    // Primary transmission
                    if let Some(sp) = subpaths.get(&frame.subpath_id).filter(|s| s.active) {
                        let n = sp.socket.send_to(&wire_bytes, sp.peer_addr)?;
                        sp.packets_sent.fetch_add(1, Ordering::Relaxed);
                        sp.bytes_sent.fetch_add(n as u64, Ordering::Relaxed);
                        sent_count += 1;
                    } else if let Some(fallback) = lowest_rtt_subpath {
                        let n = fallback.socket.send_to(&wire_bytes, fallback.peer_addr)?;
                        fallback.packets_sent.fetch_add(1, Ordering::Relaxed);
                        fallback.bytes_sent.fetch_add(n as u64, Ordering::Relaxed);
                        sent_count += 1;
                    }

                    // Bicast secondary transmission for mission-critical slice
                    if frame.is_bicast {
                        if let Some(sec_id) = secondary_subpath_id {
                            if sec_id != frame.subpath_id {
                                if let Some(sp_sec) = subpaths.get(&sec_id).filter(|s| s.active) {
                                    let n = sp_sec.socket.send_to(&wire_bytes, sp_sec.peer_addr)?;
                                    sp_sec.packets_sent.fetch_add(1, Ordering::Relaxed);
                                    sp_sec.bytes_sent.fetch_add(n as u64, Ordering::Relaxed);
                                    sent_count += 1;
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
                                    MultipathMuxPacket::Migration(MigrationFrame::PathChallenge {
                                        nonce,
                                    }) => {
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
                                    MultipathMuxPacket::Migration(MigrationFrame::PathResponse {
                                        nonce,
                                    }) => {
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

    /// Returns a telemetry snapshot for all registered subpaths.
    pub fn subpaths_snapshot(&self) -> Vec<SubpathTransportTelemetry> {
        let subpaths = match self.subpaths.read() {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let mut list: Vec<_> = subpaths.values().map(|s| s.snapshot()).collect();
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
}

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

use crate::multipath_stream_mux::{
    MultipathMuxPacket, MultipathStreamMux, StreamId, StreamMuxError, StreamPriority,
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

/// Asynchronous Multipath Transport Connection coordinating multiple UDP subpaths and a stream multiplexer.
pub struct AsyncMultipathTransport {
    mux: Arc<Mutex<MultipathStreamMux>>,
    subpaths: Arc<RwLock<HashMap<u8, AsyncMultipathSubpath>>>,
    default_subpath_id: Arc<RwLock<Option<u8>>>,
}

impl AsyncMultipathTransport {
    /// Creates a new multipath transport instance with a default stream multiplexer.
    pub fn new() -> Self {
        Self {
            mux: Arc::new(Mutex::new(MultipathStreamMux::new())),
            subpaths: Arc::new(RwLock::new(HashMap::new())),
            default_subpath_id: Arc::new(RwLock::new(None)),
        }
    }

    /// Creates a transport instance with an existing preconfigured multiplexer.
    pub fn with_mux(mux: MultipathStreamMux) -> Self {
        Self {
            mux: Arc::new(Mutex::new(mux)),
            subpaths: Arc::new(RwLock::new(HashMap::new())),
            default_subpath_id: Arc::new(RwLock::new(None)),
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
    pub fn poll_incoming_and_ingest(&self, _now_ms: u64) -> Result<usize, io::Error> {
        let subpaths = self
            .subpaths
            .read()
            .map_err(|_| io::Error::other("Subpaths lock poisoned"))?;

        let mut ingested_count = 0;
        let mut buf = [0u8; 65536];

        for sp in subpaths.values() {
            if !sp.active {
                continue;
            }

            loop {
                match sp.socket.try_recv_from(&mut buf) {
                    Ok(Some((n, _from_addr))) => {
                        sp.packets_received.fetch_add(1, Ordering::Relaxed);
                        sp.bytes_received.fetch_add(n as u64, Ordering::Relaxed);

                        if let Ok(packet) = MultipathMuxPacket::decode(&buf[..n]) {
                            let mut mux = self
                                .mux
                                .lock()
                                .map_err(|_| io::Error::other("Mux lock poisoned"))?;

                            match packet {
                                MultipathMuxPacket::Control(ctrl) => {
                                    let _ = mux.ingest_control_frame(ctrl);
                                    ingested_count += 1;
                                }
                                MultipathMuxPacket::Stream(stream_frame) => {
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

        // Trigger dynamic flow control updates if consumption or threshold reached
        if let Ok(mut mux) = self.mux.lock() {
            let _ = mux.check_and_generate_flow_control_updates();
        }

        Ok(ingested_count)
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
    }
}

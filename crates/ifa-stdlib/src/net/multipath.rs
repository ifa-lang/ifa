//! Idiomatic Multipath Transport Bindings for IFA Standard Library (`std::net::multipath`).
//!
//! Provides a unified, high-level, production-ready interface for multi-homed,
//! resilient client/server sessions.
//!
//! # Core Capabilities
//! - **Unified Multipath Session**: `MultipathSession` handles both client and server roles,
//!   abstracting over `MultipathSessionController` with zero simulation overhead.
//! - **Dynamic Interface Management**: Hot-plug and hot-unplug physical UDP interfaces
//!   (`add_subpath`, `remove_subpath`, `set_subpath_active`).
//! - **Non-blocking Event-Driven Lifecycle**: Receive granular session events
//!   (`Connected`, `SubpathStatusChanged`, `DynamicMigration`, `PayloadReceived`, `Closed`).
//! - **Quality of Service (QoS) Traffic Slicing**: Route traffic across `MissionCritical`,
//!   `UltraLowLatency`, `HighThroughput`, and `BestEffort` network slices.
//! - **Production Observability**: Direct OpenMetrics/Prometheus export and JSON audit trails.

#![allow(
    clippy::manual_is_multiple_of,
    clippy::too_many_arguments,
    clippy::field_reassign_with_default
)]

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub use ifa_runtime::async_multipath_egress_gateway::{
    AsyncMultipathEgressGatewayConfig, EgressCycleReport, EgressGatewayError,
    PhysicalEgressInterface,
};
pub use ifa_runtime::async_multipath_ingress_gateway::{
    AsyncMultipathIngressGatewayConfig, IngressCycleReport, IngressGatewayError,
    PhysicalIngressInterface, ValidatedIngressPacket,
};
pub use ifa_runtime::multipath_session_controller::{
    MultipathSessionBenchmarkReport, MultipathSessionConfig, MultipathSessionController,
    MultipathSessionTelemetry, SessionCapabilities, SessionControlFrame, SessionCycleReport,
    SessionError, SessionState, SubpathAdvertisement, SubpathHealthStatus, SubpathSessionState,
    DEFAULT_DRAIN_TIMEOUT_NS, DEFAULT_HANDSHAKE_TIMEOUT_NS, DEFAULT_INACTIVITY_TIMEOUT_NS,
    DEFAULT_KEEPALIVE_INTERVAL_NS, IFA_SESSION_CTRL_MAGIC, IFA_SESSION_CTRL_VERSION,
};
pub use ifa_runtime::multipath_stream_mux::{StreamId, StreamPriority};
pub use ifa_runtime::reactor::AsyncUdpSocket;
pub use ifa_runtime::FlowSliceClass;

/// Role of a multipath session (Client initiates handshake, Server waits for incoming handshake).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultipathSessionRole {
    Client,
    Server,
}

/// High-level events emitted by the multipath session runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultipathSessionEvent {
    /// Handshake completed successfully, session is established.
    Connected {
        session_id: u64,
        peer_capabilities: SessionCapabilities,
    },
    /// A new physical subpath was successfully registered.
    SubpathAdded {
        subpath_id: u32,
        interface_name: String,
        peer_addr: SocketAddr,
    },
    /// A physical subpath was deregistered.
    SubpathRemoved {
        subpath_id: u32,
    },
    /// Health status of a subpath has transitioned.
    SubpathStatusChanged {
        subpath_id: u32,
        old_status: SubpathHealthStatus,
        new_status: SubpathHealthStatus,
        reason: String,
    },
    /// Dynamic path migration triggered across available active subpaths.
    DynamicMigration {
        session_id: u64,
        active_subpaths: Vec<u32>,
        preferred_subpath: u32,
    },
    /// Application datagram payload received.
    PayloadReceived {
        subpath_id: u32,
        slice_class: FlowSliceClass,
        bytes: usize,
    },
    /// Multiplexed stream data chunk received.
    StreamDataReceived {
        stream_id: StreamId,
        bytes: usize,
    },
    /// Session initiated graceful drainage before closure.
    Draining {
        reason: String,
    },
    /// Session is fully closed and all resources are released.
    Closed {
        graceful: bool,
        reason: String,
    },
}

/// Fluent builder for constructing and tuning a `MultipathSession`.
#[derive(Debug, Clone)]
pub struct MultipathSessionBuilder {
    config: MultipathSessionConfig,
    role: MultipathSessionRole,
}

impl MultipathSessionBuilder {
    /// Create a new builder for the given role and session ID.
    pub fn new(role: MultipathSessionRole, session_id: u64) -> Self {
        let is_server = role == MultipathSessionRole::Server;
        let config = MultipathSessionConfig {
            session_id,
            is_server,
            ..Default::default()
        };
        Self { config, role }
    }

    /// Shortcut to construct a client session builder.
    pub fn client(session_id: u64) -> Self {
        Self::new(MultipathSessionRole::Client, session_id)
    }

    /// Shortcut to construct a server session builder.
    pub fn server(session_id: u64) -> Self {
        Self::new(MultipathSessionRole::Server, session_id)
    }

    /// Set local session capabilities.
    pub fn capabilities(mut self, caps: SessionCapabilities) -> Self {
        self.config.local_capabilities = caps;
        self
    }

    /// Configure handshake timeout.
    pub fn handshake_timeout(mut self, timeout: Duration) -> Self {
        self.config.handshake_timeout_ns = timeout.as_nanos() as u64;
        self
    }

    /// Configure graceful drain timeout.
    pub fn drain_timeout(mut self, timeout: Duration) -> Self {
        self.config.drain_timeout_ns = timeout.as_nanos() as u64;
        self
    }

    /// Configure max handshake retries.
    pub fn max_handshake_retries(mut self, retries: u32) -> Self {
        self.config.max_handshake_retries = retries;
        self
    }

    /// Configure max missed keepalives before marking subpath dead.
    pub fn max_missed_keepalives(mut self, missed: u32) -> Self {
        self.config.max_missed_keepalives = missed;
        self
    }

    /// Enable or disable pacing.
    pub fn enable_pacing(mut self, enabled: bool) -> Self {
        self.config.local_capabilities.enable_pacing = enabled;
        self
    }

    /// Enable or disable bicasting / redundant transmission.
    pub fn enable_bicasting(mut self, enabled: bool) -> Self {
        self.config.local_capabilities.enable_bicasting = enabled;
        self
    }

    /// Enable or disable forward error correction (FEC).
    pub fn enable_fec(mut self, enabled: bool) -> Self {
        self.config.local_capabilities.enable_fec = enabled;
        self
    }

    /// Set keepalive heartbeat interval.
    pub fn keepalive_interval(mut self, interval: Duration) -> Self {
        self.config.local_capabilities.keepalive_interval_ns = interval.as_nanos() as u64;
        self
    }

    /// Finalize and instantiate the `MultipathSession`.
    pub fn build(self) -> MultipathSession {
        MultipathSession::from_config(self.role, self.config)
    }
}

/// Idiomatic high-level Multipath Session for IFA.
pub struct MultipathSession {
    inner: MultipathSessionController,
    role: MultipathSessionRole,
    start_instant: Instant,
    event_queue: VecDeque<MultipathSessionEvent>,
    last_known_subpath_statuses: HashMap<u32, SubpathHealthStatus>,
    last_known_state_tag: &'static str,
    last_reported_preferred_subpath: Option<u32>,
}

impl MultipathSession {
    /// Construct a new client multipath session with default configuration.
    pub fn open_client(session_id: u64) -> Self {
        MultipathSessionBuilder::client(session_id).build()
    }

    /// Construct a new server multipath session with default configuration.
    pub fn open_server(session_id: u64) -> Self {
        MultipathSessionBuilder::server(session_id).build()
    }

    /// Start configuring a session with a builder.
    pub fn builder(role: MultipathSessionRole, session_id: u64) -> MultipathSessionBuilder {
        MultipathSessionBuilder::new(role, session_id)
    }

    /// Construct from explicit configuration.
    pub fn from_config(role: MultipathSessionRole, config: MultipathSessionConfig) -> Self {
        let inner = MultipathSessionController::new(config);
        Self {
            inner,
            role,
            start_instant: Instant::now(),
            event_queue: VecDeque::new(),
            last_known_subpath_statuses: HashMap::new(),
            last_known_state_tag: "Idle",
            last_reported_preferred_subpath: None,
        }
    }

    /// Return the role of this session.
    pub fn role(&self) -> MultipathSessionRole {
        self.role
    }

    /// Access session identifier.
    pub fn session_id(&self) -> u64 {
        self.inner.session_id()
    }

    /// Access current session state.
    pub fn state(&self) -> &SessionState {
        self.inner.state()
    }

    /// Check if session is actively connected and ready for bidirectional transport.
    pub fn is_active(&self) -> bool {
        self.inner.state().is_active()
    }

    /// Check if session is closed.
    pub fn is_closed(&self) -> bool {
        self.inner.state().is_closed()
    }

    /// Access negotiated capabilities once handshake has completed.
    pub fn negotiated_capabilities(&self) -> Option<&SessionCapabilities> {
        self.inner.negotiated_capabilities()
    }

    /// Access registered subpath state by identifier.
    pub fn subpath_state(&self, subpath_id: u32) -> Option<&SubpathSessionState> {
        self.inner.subpath_state(subpath_id)
    }

    /// Number of active registered subpaths.
    pub fn active_subpaths_count(&self) -> usize {
        self.inner.active_subpaths_count()
    }

    /// Access performance and audit telemetry.
    pub fn telemetry(&self) -> &MultipathSessionTelemetry {
        self.inner.telemetry()
    }

    /// Register a physical network interface for bidirectional multipath transport.
    pub fn add_subpath(
        &mut self,
        subpath_id: u32,
        interface_name: impl Into<String>,
        socket: Arc<AsyncUdpSocket>,
        peer_addr: SocketAddr,
        bandwidth_bps: u64,
        rtt: Duration,
        pmtu: u32,
    ) -> Result<(), SessionError> {
        let now_ns = self.current_now_ns();
        self.add_subpath_at(
            subpath_id,
            interface_name,
            socket,
            peer_addr,
            bandwidth_bps,
            rtt.as_nanos() as u64,
            pmtu,
            now_ns,
        )
    }

    /// Register a physical network interface with an explicit timestamp (for testing/replay).
    pub fn add_subpath_at(
        &mut self,
        subpath_id: u32,
        interface_name: impl Into<String>,
        socket: Arc<AsyncUdpSocket>,
        peer_addr: SocketAddr,
        bandwidth_bps: u64,
        rtt_ns: u64,
        pmtu: u32,
        now_ns: u64,
    ) -> Result<(), SessionError> {
        let iface_name = interface_name.into();
        self.inner.add_subpath(
            subpath_id,
            iface_name.clone(),
            socket,
            peer_addr,
            bandwidth_bps,
            rtt_ns,
            pmtu,
            now_ns,
        )?;

        self.last_known_subpath_statuses
            .insert(subpath_id, SubpathHealthStatus::Healthy);

        self.event_queue
            .push_back(MultipathSessionEvent::SubpathAdded {
                subpath_id,
                interface_name: iface_name,
                peer_addr,
            });

        Ok(())
    }

    /// Deregister a subpath by identifier.
    pub fn remove_subpath(&mut self, subpath_id: u32) -> Result<(), SessionError> {
        self.inner.remove_subpath(subpath_id)?;
        self.last_known_subpath_statuses.remove(&subpath_id);
        self.event_queue
            .push_back(MultipathSessionEvent::SubpathRemoved { subpath_id });
        Ok(())
    }

    /// Enable or disable a subpath dynamically.
    pub fn set_subpath_active(&mut self, subpath_id: u32, active: bool) {
        self.inner.set_subpath_active(subpath_id, active);
    }

    /// Initiate connection handshake (client only).
    pub fn connect(&mut self) -> Result<(), SessionError> {
        let now_ns = self.current_now_ns();
        self.connect_at(now_ns)
    }

    /// Initiate connection handshake at a specific timestamp.
    pub fn connect_at(&mut self, now_ns: u64) -> Result<(), SessionError> {
        self.inner.initiate_handshake(now_ns)
    }

    /// Enqueue application payload for transmission with standard BestEffort priority.
    pub fn send(&mut self, payload: &[u8]) -> Result<u64, SessionError> {
        let now_ns = self.current_now_ns();
        self.send_at(payload, FlowSliceClass::BestEffort, None, now_ns)
    }

    /// Enqueue application payload with a specific traffic slice QoS class.
    pub fn send_with_slice(
        &mut self,
        payload: &[u8],
        slice_class: FlowSliceClass,
    ) -> Result<u64, SessionError> {
        let now_ns = self.current_now_ns();
        self.send_at(payload, slice_class, None, now_ns)
    }

    /// Enqueue application payload with full options (slice class, optional subpath pin, timestamp).
    pub fn send_at(
        &mut self,
        payload: &[u8],
        slice_class: FlowSliceClass,
        pinned_subpath: Option<u64>,
        now_ns: u64,
    ) -> Result<u64, SessionError> {
        self.inner
            .send_payload(slice_class, payload.to_vec(), pinned_subpath, now_ns)
    }

    /// Enqueue multiplexed stream data.
    pub fn send_stream(
        &mut self,
        stream_id: StreamId,
        data: &[u8],
        fin: bool,
        priority: StreamPriority,
    ) -> Result<u64, SessionError> {
        let now_ns = self.current_now_ns();
        self.send_stream_at(stream_id, data, fin, priority, now_ns)
    }

    /// Enqueue multiplexed stream data at a specific timestamp.
    pub fn send_stream_at(
        &mut self,
        stream_id: StreamId,
        data: &[u8],
        fin: bool,
        priority: StreamPriority,
        now_ns: u64,
    ) -> Result<u64, SessionError> {
        self.inner
            .send_stream_data(stream_id, data, fin, priority, now_ns)
    }

    /// Non-blocking receive of next available deduplicated application payload bytes.
    pub fn recv(&mut self) -> Option<Vec<u8>> {
        self.recv_packet().map(|pkt| pkt.payload)
    }

    /// Non-blocking receive of next validated ingress packet with metadata.
    pub fn recv_packet(&mut self) -> Option<ValidatedIngressPacket> {
        self.inner.recv_payload()
    }

    /// Non-blocking receive of reassembled stream data for a stream ID.
    pub fn recv_stream(&mut self, stream_id: StreamId, max_len: usize) -> Option<Vec<u8>> {
        self.inner.recv_stream_data(stream_id, max_len)
    }

    /// Execute a non-blocking poll cycle using the current monotonic wall clock.
    pub fn poll(&mut self) -> SessionCycleReport {
        let now_ns = self.current_now_ns();
        self.poll_at(now_ns)
    }

    /// Execute a non-blocking poll cycle at a specific nanosecond timestamp.
    pub fn poll_at(&mut self, now_ns: u64) -> SessionCycleReport {
        let prev_state_tag = self.inner.state().name();
        let report = self.inner.poll_cycle(now_ns);
        let curr_state = self.inner.state().clone();
        let curr_state_tag = curr_state.name();

        // Detect State Transitions
        if prev_state_tag != curr_state_tag {
            match &curr_state {
                SessionState::Active { .. } => {
                    if let Some(caps) = self.inner.negotiated_capabilities().cloned() {
                        self.event_queue
                            .push_back(MultipathSessionEvent::Connected {
                                session_id: self.inner.session_id(),
                                peer_capabilities: caps,
                            });
                    }
                }
                SessionState::Draining { .. } => {
                    self.event_queue.push_back(MultipathSessionEvent::Draining {
                        reason: "DrainInitiated".to_string(),
                    });
                }
                SessionState::Closed { reason, .. } => {
                    self.event_queue.push_back(MultipathSessionEvent::Closed {
                        graceful: true,
                        reason: reason.clone(),
                    });
                }
                SessionState::Failed { reason, .. } => {
                    self.event_queue.push_back(MultipathSessionEvent::Closed {
                        graceful: false,
                        reason: reason.clone(),
                    });
                }
                _ => {}
            }
            self.last_known_state_tag = curr_state_tag;
        }

        // Detect Subpath Status Transitions & Health Alerts
        let subpath_ids: Vec<u32> = self.last_known_subpath_statuses.keys().copied().collect();
        let mut active_subpaths = Vec::new();
        for subpath_id in subpath_ids {
            if let Some(state) = self.inner.subpath_state(subpath_id) {
                if state.active && state.status == SubpathHealthStatus::Healthy {
                    active_subpaths.push(subpath_id);
                }
                let old_status = self
                    .last_known_subpath_statuses
                    .get(&subpath_id)
                    .copied()
                    .unwrap_or(SubpathHealthStatus::Healthy);

                if old_status != state.status {
                    self.last_known_subpath_statuses
                        .insert(subpath_id, state.status);
                    self.event_queue
                        .push_back(MultipathSessionEvent::SubpathStatusChanged {
                            subpath_id,
                            old_status,
                            new_status: state.status,
                            reason: format!(
                                "RTT: {}ms, missed keepalives: {}",
                                state.rtt_ns / 1_000_000,
                                state.consecutive_missed_pings
                            ),
                        });
                }
            }
        }

        // Detect Dynamic Subpath Selection / Migration
        if !active_subpaths.is_empty() {
            let preferred = active_subpaths[0];
            if self.last_reported_preferred_subpath != Some(preferred) {
                self.last_reported_preferred_subpath = Some(preferred);
                self.event_queue
                    .push_back(MultipathSessionEvent::DynamicMigration {
                        session_id: self.inner.session_id(),
                        active_subpaths,
                        preferred_subpath: preferred,
                    });
            }
        }

        report
    }

    /// Process a cycle and drain all newly generated session events.
    pub fn poll_events(&mut self) -> Vec<MultipathSessionEvent> {
        let now_ns = self.current_now_ns();
        self.poll_events_at(now_ns)
    }

    /// Process a cycle at specific timestamp and drain all generated session events.
    pub fn poll_events_at(&mut self, now_ns: u64) -> Vec<MultipathSessionEvent> {
        self.poll_at(now_ns);
        self.drain_events()
    }

    /// Drain all pending events from the internal event queue.
    pub fn drain_events(&mut self) -> Vec<MultipathSessionEvent> {
        self.event_queue.drain(..).collect()
    }

    /// Initiate graceful session closure.
    pub fn close(&mut self, reason: &str) -> Result<(), SessionError> {
        let now_ns = self.current_now_ns();
        self.close_at(reason, now_ns)
    }

    /// Initiate graceful session closure at specific timestamp.
    pub fn close_at(&mut self, reason: &str, now_ns: u64) -> Result<(), SessionError> {
        self.inner.initiate_graceful_close(reason, now_ns)
    }

    /// Export OpenMetrics / Prometheus metrics text.
    pub fn export_prometheus_metrics(&self) -> String {
        self.inner.export_prometheus_metrics()
    }

    /// Generate structured JSON audit trail.
    pub fn generate_json_audit_trail(&self) -> String {
        self.inner.generate_json_audit_trail()
    }

    /// Current monotonic timestamp in nanoseconds relative to session start.
    #[inline]
    fn current_now_ns(&self) -> u64 {
        self.start_instant.elapsed().as_nanos() as u64
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_and_client_server_initialization() {
        let client = MultipathSession::builder(MultipathSessionRole::Client, 42)
            .enable_pacing(true)
            .enable_bicasting(true)
            .enable_fec(true)
            .handshake_timeout(Duration::from_secs(2))
            .drain_timeout(Duration::from_secs(1))
            .build();

        assert_eq!(client.session_id(), 42);
        assert_eq!(client.role(), MultipathSessionRole::Client);
        assert_eq!(client.state(), &SessionState::Idle);
        assert!(!client.is_active());
        assert!(!client.is_closed());

        let server = MultipathSession::open_server(42);
        assert_eq!(server.session_id(), 42);
        assert_eq!(server.role(), MultipathSessionRole::Server);
        assert_eq!(server.state(), &SessionState::Idle);
    }

    #[test]
    fn test_multipath_session_bidirectional_exchange_and_events() {
        let base_now = 5_000_000_000u64;

        let sock_client = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").expect("client socket"));
        let sock_server = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").expect("server socket"));

        let client_addr = sock_client.local_addr().expect("client addr");
        let server_addr = sock_server.local_addr().expect("server addr");

        let mut client = MultipathSession::open_client(999);
        let mut server = MultipathSession::open_server(999);

        // Add subpaths
        client
            .add_subpath_at(
                1,
                "eth0_client",
                sock_client,
                server_addr,
                50_000_000,
                10_000_000,
                1420,
                base_now,
            )
            .expect("add client subpath");

        server
            .add_subpath_at(
                1,
                "eth0_server",
                sock_server,
                client_addr,
                50_000_000,
                10_000_000,
                1420,
                base_now,
            )
            .expect("add server subpath");

        assert_eq!(client.active_subpaths_count(), 1);
        assert_eq!(server.active_subpaths_count(), 1);

        // Verify subpath added event
        let client_events = client.drain_events();
        assert_eq!(client_events.len(), 1);
        assert!(matches!(
            client_events[0],
            MultipathSessionEvent::SubpathAdded { subpath_id: 1, .. }
        ));

        // 1. Connect Handshake
        client.connect_at(base_now).expect("client connect");

        // Client step 1: emits SYN to socket
        client.poll_at(base_now);

        // Server step 1: processes incoming SYN and sends ACK
        let server_events = server.poll_events_at(base_now + 1_000_000);
        assert!(server.is_active());
        assert!(server_events
            .iter()
            .any(|e| matches!(e, MultipathSessionEvent::Connected { session_id: 999, .. })));

        // Client step 2: processes server ACK
        let client_events2 = client.poll_events_at(base_now + 2_000_000);
        assert!(client.is_active());
        assert!(client_events2
            .iter()
            .any(|e| matches!(e, MultipathSessionEvent::Connected { session_id: 999, .. })));

        // 2. Application Data Exchange
        let test_message = b"IFA System Language - High Resilience Multipath".to_vec();
        client
            .send_at(
                &test_message,
                FlowSliceClass::MissionCritical,
                None,
                base_now + 3_000_000,
            )
            .expect("send payload");

        client.poll_at(base_now + 3_000_000);
        server.poll_at(base_now + 4_000_000);

        let received = server.recv().expect("server receives message");
        assert_eq!(received, test_message);

        // 3. Graceful Termination
        client
            .close_at("normal_shutdown", base_now + 10_000_000)
            .expect("initiate close");

        client.poll_at(base_now + 10_000_000);
        server.poll_at(base_now + 11_000_000);
        let final_events = client.poll_events_at(base_now + 12_000_000);

        assert!(client.is_closed());
        assert!(final_events
            .iter()
            .any(|e| matches!(e, MultipathSessionEvent::Closed { graceful: true, .. })));

        // Verify Observability
        let metrics = client.export_prometheus_metrics();
        assert!(metrics.contains("ifa_session_state"));
        let json_audit = client.generate_json_audit_trail();
        assert!(json_audit.contains("\"session_id\":999"));
    }

    #[test]
    fn test_subpath_status_degradation_and_events() {
        let base_now = 10_000_000_000u64;
        let sock_c = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").expect("client sock"));
        let sock_s = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").expect("server sock"));

        let addr_c = sock_c.local_addr().expect("client addr");
        let addr_s = sock_s.local_addr().expect("server addr");

        let mut client = MultipathSession::builder(MultipathSessionRole::Client, 888)
            .keepalive_interval(Duration::from_secs(1))
            .max_missed_keepalives(2)
            .build();

        let mut server = MultipathSession::open_server(888);

        client
            .add_subpath_at(
                1,
                "cellular0",
                sock_c,
                addr_s,
                20_000_000,
                15_000_000,
                1380,
                base_now,
            )
            .expect("add subpath c");

        server
            .add_subpath_at(
                1,
                "cellular0",
                sock_s,
                addr_c,
                20_000_000,
                15_000_000,
                1380,
                base_now,
            )
            .expect("add subpath s");

        // Establish connection via handshake
        client.connect_at(base_now).expect("connect");
        client.poll_at(base_now);
        server.poll_at(base_now + 1_000_000);
        client.poll_at(base_now + 2_000_000);
        assert!(client.is_active());

        // Drain initial events
        let _ = client.drain_events();

        // Server is now silent (simulate physical link interruption)
        // Sweep 1: Client keepalive ping is dispatched
        client.poll_at(base_now + 1_200_000_000);

        // Sweep 2: Inactivity timeout reached -> Degraded / Stalled
        let events = client.poll_events_at(base_now + 3_600_000_000);
        let degraded = events.iter().any(|e| {
            matches!(
                e,
                MultipathSessionEvent::SubpathStatusChanged {
                    subpath_id: 1,
                    new_status: SubpathHealthStatus::Degraded | SubpathHealthStatus::Stalled,
                    ..
                }
            )
        });
        assert!(degraded);

        // Sweep 3: Timeout exceeded with missed keepalives -> Dead
        let events_dead = client.poll_events_at(base_now + 7_000_000_000);
        let dead = events_dead.iter().any(|e| {
            matches!(
                e,
                MultipathSessionEvent::SubpathStatusChanged {
                    subpath_id: 1,
                    new_status: SubpathHealthStatus::Dead,
                    ..
                }
            )
        });
        assert!(dead);
    }
}

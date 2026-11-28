//! Kori Multipath Transport Bindings and Runtime Orchestration (`kori::multipath`).
//!
//! Provides idiomatic bindings, service profile presets, and local orchestration
//! helpers for multipath connection sessions in the IFA ecosystem.

#![allow(
    clippy::manual_is_multiple_of,
    clippy::too_many_arguments,
    clippy::field_reassign_with_default
)]

use std::io;
use std::sync::Arc;
use std::time::Duration;

pub use ifa_stdlib::net::multipath::{
    AsyncMultipathEgressGatewayConfig, AsyncMultipathIngressGatewayConfig, AsyncUdpSocket,
    EgressCycleReport, EgressGatewayError, FlowSliceClass, IngressCycleReport, IngressGatewayError,
    MultipathSession, MultipathSessionBenchmarkReport, MultipathSessionBuilder,
    MultipathSessionConfig, MultipathSessionController, MultipathSessionEvent,
    MultipathSessionRole, MultipathSessionTelemetry, PhysicalEgressInterface,
    PhysicalIngressInterface, SessionCapabilities, SessionControlFrame, SessionCycleReport,
    SessionError, SessionState, StreamId, StreamPriority, SubpathAdvertisement,
    SubpathHealthStatus, SubpathSessionState, ValidatedIngressPacket, DEFAULT_DRAIN_TIMEOUT_NS,
    DEFAULT_HANDSHAKE_TIMEOUT_NS, DEFAULT_INACTIVITY_TIMEOUT_NS, DEFAULT_KEEPALIVE_INTERVAL_NS,
    IFA_SESSION_CTRL_MAGIC, IFA_SESSION_CTRL_VERSION,
};

/// Preset transport profiles for configuring multipath sessions in Kori.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultipathProfileKind {
    /// Zero-loss, highly redundant configuration (bicasting + FEC enabled).
    HighAvailability,
    /// Maximum aggregate bandwidth across distinct physical links (pacing + autotuning enabled).
    HighThroughputAggregate,
    /// Ultra-low latency routing over lowest-RTT link with instant failover.
    UltraLowLatency,
}

/// Service profile containing configuration presets for a target network workload.
#[derive(Debug, Clone)]
pub struct MultipathServiceProfile {
    pub kind: MultipathProfileKind,
    pub pacing: bool,
    pub bicasting: bool,
    pub fec: bool,
    pub keepalive_interval: Duration,
    pub drain_timeout: Duration,
}

impl MultipathServiceProfile {
    /// Create a profile for the desired transport characteristics.
    pub fn new(kind: MultipathProfileKind) -> Self {
        match kind {
            MultipathProfileKind::HighAvailability => Self {
                kind,
                pacing: true,
                bicasting: true,
                fec: true,
                keepalive_interval: Duration::from_millis(500),
                drain_timeout: Duration::from_secs(2),
            },
            MultipathProfileKind::HighThroughputAggregate => Self {
                kind,
                pacing: true,
                bicasting: false,
                fec: false,
                keepalive_interval: Duration::from_secs(1),
                drain_timeout: Duration::from_secs(3),
            },
            MultipathProfileKind::UltraLowLatency => Self {
                kind,
                pacing: false,
                bicasting: true,
                fec: false,
                keepalive_interval: Duration::from_millis(250),
                drain_timeout: Duration::from_secs(1),
            },
        }
    }

    /// Apply this profile to a session builder.
    pub fn apply_to_builder(&self, builder: MultipathSessionBuilder) -> MultipathSessionBuilder {
        builder
            .enable_pacing(self.pacing)
            .enable_bicasting(self.bicasting)
            .enable_fec(self.fec)
            .keepalive_interval(self.keepalive_interval)
            .drain_timeout(self.drain_timeout)
    }

    /// Instantiate a configured client session using this profile.
    pub fn create_client_session(&self, session_id: u64) -> MultipathSession {
        self.apply_to_builder(MultipathSession::builder(
            MultipathSessionRole::Client,
            session_id,
        ))
        .build()
    }

    /// Instantiate a configured server session using this profile.
    pub fn create_server_session(&self, session_id: u64) -> MultipathSession {
        self.apply_to_builder(MultipathSession::builder(
            MultipathSessionRole::Server,
            session_id,
        ))
        .build()
    }
}

/// Spawns a pair of interconnected loopback `MultipathSession` instances with N subpaths.
///
/// Designed for zero-simulation integration tests, micro-benchmarks, and local
/// verification of multipath failover and bicasting scenarios.
pub fn spawn_loopback_multipath_pair(
    session_id: u64,
    subpaths_count: usize,
    bandwidth_bps: u64,
    rtt: Duration,
) -> io::Result<(MultipathSession, MultipathSession)> {
    let mut client = MultipathSession::open_client(session_id);
    let mut server = MultipathSession::open_server(session_id);

    let count = subpaths_count.max(1);
    for idx in 1..=count {
        let subpath_id = idx as u32;

        let sock_c = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0")?);
        let sock_s = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0")?);

        let addr_c = sock_c.local_addr()?;
        let addr_s = sock_s.local_addr()?;

        client
            .add_subpath(
                subpath_id,
                format!("lo_client_{}", subpath_id),
                sock_c,
                addr_s,
                bandwidth_bps,
                rtt,
                1420,
            )
            .map_err(|e| io::Error::other(format!("{:?}", e)))?;

        server
            .add_subpath(
                subpath_id,
                format!("lo_server_{}", subpath_id),
                sock_s,
                addr_c,
                bandwidth_bps,
                rtt,
                1420,
            )
            .map_err(|e| io::Error::other(format!("{:?}", e)))?;
    }

    Ok((client, server))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_profiles() {
        let ha = MultipathServiceProfile::new(MultipathProfileKind::HighAvailability);
        assert!(ha.bicasting);
        assert!(ha.fec);
        let client_ha = ha.create_client_session(101);
        assert_eq!(client_ha.session_id(), 101);
        assert_eq!(client_ha.role(), MultipathSessionRole::Client);

        let agg = MultipathServiceProfile::new(MultipathProfileKind::HighThroughputAggregate);
        assert!(agg.pacing);
        assert!(!agg.bicasting);

        let ull = MultipathServiceProfile::new(MultipathProfileKind::UltraLowLatency);
        assert!(ull.bicasting);
        assert!(!ull.pacing);
    }

    #[test]
    fn test_spawn_loopback_multipath_pair_multi_link_exchange() {
        let (mut client, mut server) = spawn_loopback_multipath_pair(
            202,
            3, // 3 physical links
            100_000_000,
            Duration::from_millis(10),
        )
        .expect("spawn loopback pair");

        assert_eq!(client.active_subpaths_count(), 3);
        assert_eq!(server.active_subpaths_count(), 3);

        // Handshake
        client.connect().expect("connect client");
        client.poll();
        server.poll();
        client.poll();

        assert!(client.is_active());
        assert!(server.is_active());

        // Transmit multi-packet burst
        let payload = b"Kori Multipath Pipeline Verified";
        client
            .send_with_slice(payload, FlowSliceClass::UltraLowLatency)
            .expect("send burst");

        client.poll();
        server.poll();

        let received = server.recv().expect("server receives message");
        assert_eq!(received, payload);

        // Graceful termination
        client.close("test_complete").expect("close client");
        client.poll();
        server.poll();
        client.poll();

        assert!(client.is_closed());
    }
}

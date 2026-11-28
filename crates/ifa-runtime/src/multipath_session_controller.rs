//! End-to-End Multipath Connection Session Controller (`MultipathSessionController`).
//!
//! Orchestrates the complete end-to-end multipath session lifecycle:
//! 1. **Initial Handshake & Capabilities Negotiation**:
//!    - RFC 9000 aligned multipath connection setup (`HandshakeSyn` / `HandshakeAck`).
//!    - Bidirectional negotiation of transport capabilities (pacing, bicasting, FEC, reorder windows).
//! 2. **Dynamic Subpath Discovery & Synchronization**:
//!    - Runtime advertisement, verification, and teardown of heterogeneous physical subpaths.
//!    - Real-time binding and synchronized registration across ingress and egress gateways.
//! 3. **Bidirectional Gateway Coupling**:
//!    - Unified interface binding `AsyncMultipathEgressGateway` and `AsyncMultipathIngressGateway`.
//!    - Direct zero-copy wire serialization, ingress bitset deduplication, and RTT/jitter feedback.
//! 4. **Subpath Keep-Alive & Dead-Link Detection**:
//!    - High-frequency heartbeat ping/pong probing per subpath.
//!    - Instantaneous degradation tracking (`Healthy` -> `Degraded` -> `Dead`) with automated egress rerouting.
//! 5. **Graceful Session Termination**:
//!    - Clean drain handshake (`GracefulFin` / `GracefulFinAck`).
//!    - In-flight packet and backpressure queue draining before closing sockets.
//! 6. **Production Observability & Audit**:
//!    - OpenMetrics / Prometheus exposition format (`export_prometheus_metrics`).
//!    - Structured JSON audit trail (`generate_json_audit_trail`).
//!    - Integrated micro-benchmark suite (`run_multipath_session_controller_benchmark`).
//!
//! Zero-simulation guarantee: operates strictly on concrete non-blocking sockets,
//! real monotonic nanosecond clocks, and binary wire framing.

#![allow(
    clippy::manual_is_multiple_of,
    clippy::too_many_arguments,
    clippy::field_reassign_with_default
)]

use std::collections::{BTreeMap, VecDeque};
use std::fmt::Write as FmtWrite;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use crate::async_multipath_egress_gateway::{
    AsyncMultipathEgressGateway, AsyncMultipathEgressGatewayConfig, EgressCycleReport,
    EgressGatewayError, PhysicalEgressInterface,
};
use crate::async_multipath_ingress_gateway::{
    AsyncMultipathIngressGateway, AsyncMultipathIngressGatewayConfig, IngressCycleReport,
    IngressGatewayError, PhysicalIngressInterface, ValidatedIngressPacket,
};
use crate::multipath_stream_mux::{StreamFrame, StreamId, StreamPriority};
use crate::reactor::AsyncUdpSocket;
use crate::subpath_pmtud::calculate_crc32;
use crate::traffic_slicing::FlowSliceClass;

// ---------------------------------------------------------------------------
// Protocol Constants & Wire Framing Layout
// ---------------------------------------------------------------------------

/// Magic tag identifying IFA Session Control frames ("ISCT" in ASCII).
pub const IFA_SESSION_CTRL_MAGIC: u32 = 0x4953_4354;

/// Protocol version for IFA Session Control framing.
pub const IFA_SESSION_CTRL_VERSION: u8 = 1;

/// Minimum header size for session control wire frames (16 bytes prefix + 4 bytes CRC32 = 20 bytes).
pub const SESSION_CTRL_MIN_HEADER_SIZE: usize = 20;

/// Default heartbeat keepalive interval in nanoseconds (1 second).
pub const DEFAULT_KEEPALIVE_INTERVAL_NS: u64 = 1_000_000_000;

/// Default subpath inactivity timeout in nanoseconds (3 seconds).
pub const DEFAULT_INACTIVITY_TIMEOUT_NS: u64 = 3_000_000_000;

/// Default handshake negotiation timeout in nanoseconds (3 seconds).
pub const DEFAULT_HANDSHAKE_TIMEOUT_NS: u64 = 3_000_000_000;

/// Default graceful drain timeout in nanoseconds (2 seconds).
pub const DEFAULT_DRAIN_TIMEOUT_NS: u64 = 2_000_000_000;

// ---------------------------------------------------------------------------
// Error Types
// ---------------------------------------------------------------------------

/// Errors encountered during session lifecycle, handshake, or packet dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    /// Session is not in a valid state for the requested operation.
    InvalidState {
        current: String,
        expected: &'static str,
    },
    /// Wire packet too short to contain a valid session control frame.
    BufferTooShort { required: usize, provided: usize },
    /// Magic constant mismatch.
    InvalidMagic { expected: u32, received: u32 },
    /// Protocol version mismatch.
    UnsupportedVersion { version: u8 },
    /// Unknown session frame type discriminator.
    UnknownFrameType(u8),
    /// Integrity CRC32 checksum mismatch.
    CrcMismatch { computed: u32, embedded: u32 },
    /// Error encoding or decoding subpath socket address.
    AddressEncodingError(String),
    /// Error propagated from underlying egress gateway.
    EgressError(EgressGatewayError),
    /// Error propagated from underlying ingress gateway.
    IngressError(IngressGatewayError),
    /// Subpath interface not found.
    SubpathNotFound(u32),
    /// Session handshake timed out.
    HandshakeTimeout,
    /// Specified capacity or limit exceeded.
    CapacityExceeded(String),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidState { current, expected } => {
                write!(
                    f,
                    "Invalid session state: current '{}', expected '{}'",
                    current, expected
                )
            }
            Self::BufferTooShort { required, provided } => {
                write!(
                    f,
                    "Session control buffer too short: required {}, provided {}",
                    required, provided
                )
            }
            Self::InvalidMagic { expected, received } => {
                write!(
                    f,
                    "Session control invalid magic: expected 0x{:08X}, received 0x{:08X}",
                    expected, received
                )
            }
            Self::UnsupportedVersion { version } => {
                write!(f, "Unsupported session protocol version: {}", version)
            }
            Self::UnknownFrameType(tag) => {
                write!(f, "Unknown session control frame type: 0x{:02X}", tag)
            }
            Self::CrcMismatch { computed, embedded } => {
                write!(
                    f,
                    "Session control CRC32 mismatch: computed 0x{:08X}, embedded 0x{:08X}",
                    computed, embedded
                )
            }
            Self::AddressEncodingError(msg) => write!(f, "Socket address encoding error: {}", msg),
            Self::EgressError(err) => write!(f, "Egress gateway error: {}", err),
            Self::IngressError(err) => write!(f, "Ingress gateway error: {}", err),
            Self::SubpathNotFound(id) => write!(f, "Subpath interface {} not found", id),
            Self::HandshakeTimeout => write!(f, "Session handshake timed out"),
            Self::CapacityExceeded(msg) => write!(f, "Session capacity exceeded: {}", msg),
        }
    }
}

impl std::error::Error for SessionError {}

impl From<EgressGatewayError> for SessionError {
    fn from(err: EgressGatewayError) -> Self {
        SessionError::EgressError(err)
    }
}

impl From<IngressGatewayError> for SessionError {
    fn from(err: IngressGatewayError) -> Self {
        SessionError::IngressError(err)
    }
}

// ---------------------------------------------------------------------------
// Session Capabilities & Subpath Advertisement
// ---------------------------------------------------------------------------

/// Transport capabilities negotiated during initial session handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionCapabilities {
    /// Wire protocol version.
    pub version: u8,
    /// Maximum number of active concurrent subpaths.
    pub max_subpaths: u8,
    /// Whether pacing coordination is active.
    pub enable_pacing: bool,
    /// Whether 1+1 redundant bicasting is enabled for critical traffic.
    pub enable_bicasting: bool,
    /// Whether forward error correction (FEC) is enabled.
    pub enable_fec: bool,
    /// Ingress sliding window deduplication and reordering capacity.
    pub reorder_window_size: u32,
    /// Heartbeat ping interval in nanoseconds.
    pub keepalive_interval_ns: u64,
    /// Inactivity threshold before declaring a subpath dead in nanoseconds.
    pub inactivity_timeout_ns: u64,
}

impl Default for SessionCapabilities {
    fn default() -> Self {
        Self {
            version: IFA_SESSION_CTRL_VERSION,
            max_subpaths: 8,
            enable_pacing: true,
            enable_bicasting: true,
            enable_fec: true,
            reorder_window_size: 2048,
            keepalive_interval_ns: DEFAULT_KEEPALIVE_INTERVAL_NS,
            inactivity_timeout_ns: DEFAULT_INACTIVITY_TIMEOUT_NS,
        }
    }
}

impl SessionCapabilities {
    /// Negotiate common capabilities between local preferences and remote peer's advertised offer.
    pub fn negotiate(&self, peer: &SessionCapabilities) -> Self {
        Self {
            version: self.version.min(peer.version),
            max_subpaths: self.max_subpaths.min(peer.max_subpaths),
            enable_pacing: self.enable_pacing && peer.enable_pacing,
            enable_bicasting: self.enable_bicasting && peer.enable_bicasting,
            enable_fec: self.enable_fec && peer.enable_fec,
            reorder_window_size: self.reorder_window_size.min(peer.reorder_window_size),
            keepalive_interval_ns: self.keepalive_interval_ns.max(peer.keepalive_interval_ns),
            inactivity_timeout_ns: self.inactivity_timeout_ns.max(peer.inactivity_timeout_ns),
        }
    }

    /// Serialize capabilities into fixed 23-byte binary layout.
    pub fn encode_to(&self, out: &mut [u8]) -> Result<(), SessionError> {
        if out.len() < 23 {
            return Err(SessionError::BufferTooShort {
                required: 23,
                provided: out.len(),
            });
        }

        out[0] = self.version;
        out[1] = self.max_subpaths;
        let mut flags = 0u8;
        if self.enable_pacing {
            flags |= 0x01;
        }
        if self.enable_bicasting {
            flags |= 0x02;
        }
        if self.enable_fec {
            flags |= 0x04;
        }
        out[2] = flags;
        out[3..7].copy_from_slice(&self.reorder_window_size.to_be_bytes());
        out[7..15].copy_from_slice(&self.keepalive_interval_ns.to_be_bytes());
        out[15..23].copy_from_slice(&self.inactivity_timeout_ns.to_be_bytes());
        Ok(())
    }

    /// Decode capabilities from 23-byte binary layout.
    pub fn decode_from(buf: &[u8]) -> Result<Self, SessionError> {
        if buf.len() < 23 {
            return Err(SessionError::BufferTooShort {
                required: 23,
                provided: buf.len(),
            });
        }

        let version = buf[0];
        let max_subpaths = buf[1];
        let flags = buf[2];
        let enable_pacing = (flags & 0x01) != 0;
        let enable_bicasting = (flags & 0x02) != 0;
        let enable_fec = (flags & 0x04) != 0;

        let reorder_window_size = u32::from_be_bytes([buf[3], buf[4], buf[5], buf[6]]);
        let keepalive_interval_ns = u64::from_be_bytes([
            buf[7], buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14],
        ]);
        let inactivity_timeout_ns = u64::from_be_bytes([
            buf[15], buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22],
        ]);

        Ok(Self {
            version,
            max_subpaths,
            enable_pacing,
            enable_bicasting,
            enable_fec,
            reorder_window_size,
            keepalive_interval_ns,
            inactivity_timeout_ns,
        })
    }
}

/// Dynamic subpath advertisement payload exchanged during handshake or dynamic migration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubpathAdvertisement {
    pub subpath_id: u32,
    pub peer_addr: SocketAddr,
    pub bandwidth_bps: u64,
    pub pmtu: u32,
}

impl SubpathAdvertisement {
    /// Encode subpath advertisement into byte vector.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32);
        buf.extend_from_slice(&self.subpath_id.to_be_bytes());
        match self.peer_addr {
            SocketAddr::V4(v4) => {
                buf.push(4);
                buf.extend_from_slice(&v4.ip().octets());
                buf.extend_from_slice(&v4.port().to_be_bytes());
            }
            SocketAddr::V6(v6) => {
                buf.push(6);
                buf.extend_from_slice(&v6.ip().octets());
                buf.extend_from_slice(&v6.port().to_be_bytes());
            }
        }
        buf.extend_from_slice(&self.bandwidth_bps.to_be_bytes());
        buf.extend_from_slice(&self.pmtu.to_be_bytes());
        buf
    }

    /// Decode subpath advertisement from byte slice, returning (record, bytes_consumed).
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), SessionError> {
        if buf.len() < 5 {
            return Err(SessionError::BufferTooShort {
                required: 5,
                provided: buf.len(),
            });
        }

        let subpath_id = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let family = buf[4];
        let mut offset = 5;

        let peer_addr = match family {
            4 => {
                if buf.len() < offset + 4 + 2 {
                    return Err(SessionError::BufferTooShort {
                        required: offset + 6,
                        provided: buf.len(),
                    });
                }
                let octets = [
                    buf[offset],
                    buf[offset + 1],
                    buf[offset + 2],
                    buf[offset + 3],
                ];
                offset += 4;
                let port = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
                offset += 2;
                SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port)
            }
            6 => {
                if buf.len() < offset + 16 + 2 {
                    return Err(SessionError::BufferTooShort {
                        required: offset + 18,
                        provided: buf.len(),
                    });
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[offset..offset + 16]);
                offset += 16;
                let port = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
                offset += 2;
                SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port)
            }
            other => {
                return Err(SessionError::AddressEncodingError(format!(
                    "Unsupported address family byte: {}",
                    other
                )));
            }
        };

        if buf.len() < offset + 8 + 4 {
            return Err(SessionError::BufferTooShort {
                required: offset + 12,
                provided: buf.len(),
            });
        }

        let bandwidth_bps = u64::from_be_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
            buf[offset + 4],
            buf[offset + 5],
            buf[offset + 6],
            buf[offset + 7],
        ]);
        offset += 8;
        let pmtu = u32::from_be_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ]);
        offset += 4;

        Ok((
            Self {
                subpath_id,
                peer_addr,
                bandwidth_bps,
                pmtu,
            },
            offset,
        ))
    }
}

// ---------------------------------------------------------------------------
// Session Control Frames
// ---------------------------------------------------------------------------

/// Discriminator tags for session control wire frames.
pub mod frame_types {
    pub const HANDSHAKE_SYN: u8 = 0x01;
    pub const HANDSHAKE_ACK: u8 = 0x02;
    pub const SUBPATH_ANNOUNCE: u8 = 0x03;
    pub const SUBPATH_ACK: u8 = 0x04;
    pub const SUBPATH_TEARDOWN: u8 = 0x05;
    pub const KEEPALIVE_PING: u8 = 0x06;
    pub const KEEPALIVE_PONG: u8 = 0x07;
    pub const GRACEFUL_FIN: u8 = 0x08;
    pub const GRACEFUL_FIN_ACK: u8 = 0x09;
    pub const SESSION_RESET: u8 = 0x0A;
}

/// Dedicated control signaling frames governing multipath connection lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionControlFrame {
    /// Initial client handshake initiation.
    HandshakeSyn {
        session_id: u64,
        client_nonce: u64,
        capabilities: SessionCapabilities,
        advertised_subpaths: Vec<SubpathAdvertisement>,
    },
    /// Server handshake acceptance and capabilities negotiation response.
    HandshakeAck {
        session_id: u64,
        server_nonce: u64,
        echo_nonce: u64,
        negotiated_capabilities: SessionCapabilities,
        accepted_subpaths: Vec<u32>,
    },
    /// Dynamic announcement of a newly discovered or migrated subpath.
    SubpathAnnounce {
        session_id: u64,
        advertisement: SubpathAdvertisement,
    },
    /// Acknowledgment of subpath registration or verification.
    SubpathAck {
        session_id: u64,
        subpath_id: u32,
        accepted: bool,
    },
    /// Explicit teardown of an individual subpath.
    SubpathTeardown {
        session_id: u64,
        subpath_id: u32,
        reason: String,
    },
    /// Subpath heartbeat probe measuring round-trip latency and validating liveness.
    KeepAlivePing {
        session_id: u64,
        nonce: u64,
        subpath_id: u32,
        departure_time_ns: u64,
    },
    /// Subpath heartbeat response echoing probe parameters.
    KeepAlivePong {
        session_id: u64,
        nonce: u64,
        subpath_id: u32,
        ping_departure_ns: u64,
    },
    /// Graceful connection teardown initiation (FIN).
    GracefulFin {
        session_id: u64,
        last_sequence: u64,
        reason: String,
    },
    /// Graceful connection teardown acknowledgment (FIN-ACK).
    GracefulFinAck { session_id: u64 },
    /// Immediate connection reset or rejection.
    SessionReset {
        session_id: u64,
        error_code: u32,
        reason: String,
    },
}

impl SessionControlFrame {
    /// Return the session identifier associated with this frame.
    pub fn session_id(&self) -> u64 {
        match self {
            Self::HandshakeSyn { session_id, .. } => *session_id,
            Self::HandshakeAck { session_id, .. } => *session_id,
            Self::SubpathAnnounce { session_id, .. } => *session_id,
            Self::SubpathAck { session_id, .. } => *session_id,
            Self::SubpathTeardown { session_id, .. } => *session_id,
            Self::KeepAlivePing { session_id, .. } => *session_id,
            Self::KeepAlivePong { session_id, .. } => *session_id,
            Self::GracefulFin { session_id, .. } => *session_id,
            Self::GracefulFinAck { session_id } => *session_id,
            Self::SessionReset { session_id, .. } => *session_id,
        }
    }

    /// Encode the session control frame into a self-contained, CRC32-verified byte buffer.
    pub fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(128);

        let (frame_type, session_id) = match self {
            Self::HandshakeSyn {
                session_id,
                client_nonce,
                capabilities,
                advertised_subpaths,
            } => {
                payload.extend_from_slice(&client_nonce.to_be_bytes());
                let mut cap_bytes = [0u8; 23];
                let _ = capabilities.encode_to(&mut cap_bytes);
                payload.extend_from_slice(&cap_bytes);
                payload.push(advertised_subpaths.len() as u8);
                for sub in advertised_subpaths {
                    let encoded = sub.encode();
                    payload.extend_from_slice(&encoded);
                }
                (frame_types::HANDSHAKE_SYN, *session_id)
            }
            Self::HandshakeAck {
                session_id,
                server_nonce,
                echo_nonce,
                negotiated_capabilities,
                accepted_subpaths,
            } => {
                payload.extend_from_slice(&server_nonce.to_be_bytes());
                payload.extend_from_slice(&echo_nonce.to_be_bytes());
                let mut cap_bytes = [0u8; 23];
                let _ = negotiated_capabilities.encode_to(&mut cap_bytes);
                payload.extend_from_slice(&cap_bytes);
                payload.push(accepted_subpaths.len() as u8);
                for &sid in accepted_subpaths {
                    payload.extend_from_slice(&sid.to_be_bytes());
                }
                (frame_types::HANDSHAKE_ACK, *session_id)
            }
            Self::SubpathAnnounce {
                session_id,
                advertisement,
            } => {
                let encoded = advertisement.encode();
                payload.extend_from_slice(&encoded);
                (frame_types::SUBPATH_ANNOUNCE, *session_id)
            }
            Self::SubpathAck {
                session_id,
                subpath_id,
                accepted,
            } => {
                payload.extend_from_slice(&subpath_id.to_be_bytes());
                payload.push(if *accepted { 1 } else { 0 });
                (frame_types::SUBPATH_ACK, *session_id)
            }
            Self::SubpathTeardown {
                session_id,
                subpath_id,
                reason,
            } => {
                payload.extend_from_slice(&subpath_id.to_be_bytes());
                let reason_bytes = reason.as_bytes();
                payload.extend_from_slice(&(reason_bytes.len() as u16).to_be_bytes());
                payload.extend_from_slice(reason_bytes);
                (frame_types::SUBPATH_TEARDOWN, *session_id)
            }
            Self::KeepAlivePing {
                session_id,
                nonce,
                subpath_id,
                departure_time_ns,
            } => {
                payload.extend_from_slice(&nonce.to_be_bytes());
                payload.extend_from_slice(&subpath_id.to_be_bytes());
                payload.extend_from_slice(&departure_time_ns.to_be_bytes());
                (frame_types::KEEPALIVE_PING, *session_id)
            }
            Self::KeepAlivePong {
                session_id,
                nonce,
                subpath_id,
                ping_departure_ns,
            } => {
                payload.extend_from_slice(&nonce.to_be_bytes());
                payload.extend_from_slice(&subpath_id.to_be_bytes());
                payload.extend_from_slice(&ping_departure_ns.to_be_bytes());
                (frame_types::KEEPALIVE_PONG, *session_id)
            }
            Self::GracefulFin {
                session_id,
                last_sequence,
                reason,
            } => {
                payload.extend_from_slice(&last_sequence.to_be_bytes());
                let reason_bytes = reason.as_bytes();
                payload.extend_from_slice(&(reason_bytes.len() as u16).to_be_bytes());
                payload.extend_from_slice(reason_bytes);
                (frame_types::GRACEFUL_FIN, *session_id)
            }
            Self::GracefulFinAck { session_id } => (frame_types::GRACEFUL_FIN_ACK, *session_id),
            Self::SessionReset {
                session_id,
                error_code,
                reason,
            } => {
                payload.extend_from_slice(&error_code.to_be_bytes());
                let reason_bytes = reason.as_bytes();
                payload.extend_from_slice(&(reason_bytes.len() as u16).to_be_bytes());
                payload.extend_from_slice(reason_bytes);
                (frame_types::SESSION_RESET, *session_id)
            }
        };

        let mut out = Vec::with_capacity(SESSION_CTRL_MIN_HEADER_SIZE + payload.len());
        out.extend_from_slice(&IFA_SESSION_CTRL_MAGIC.to_be_bytes());
        out.push(IFA_SESSION_CTRL_VERSION);
        out.push(frame_type);
        out.extend_from_slice(&session_id.to_be_bytes());
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(&payload);

        let crc = calculate_crc32(&out);
        out.extend_from_slice(&crc.to_be_bytes());

        out
    }

    /// Decode a session control frame from a binary slice.
    pub fn decode(buf: &[u8]) -> Result<Self, SessionError> {
        if buf.len() < SESSION_CTRL_MIN_HEADER_SIZE {
            return Err(SessionError::BufferTooShort {
                required: SESSION_CTRL_MIN_HEADER_SIZE,
                provided: buf.len(),
            });
        }

        let magic = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if magic != IFA_SESSION_CTRL_MAGIC {
            return Err(SessionError::InvalidMagic {
                expected: IFA_SESSION_CTRL_MAGIC,
                received: magic,
            });
        }

        let version = buf[4];
        if version != IFA_SESSION_CTRL_VERSION {
            return Err(SessionError::UnsupportedVersion { version });
        }

        let frame_type = buf[5];
        let session_id = u64::from_be_bytes([
            buf[6], buf[7], buf[8], buf[9], buf[10], buf[11], buf[12], buf[13],
        ]);
        let payload_len = u16::from_be_bytes([buf[14], buf[15]]) as usize;

        let total_required = 16 + payload_len + 4;
        if buf.len() < total_required {
            return Err(SessionError::BufferTooShort {
                required: total_required,
                provided: buf.len(),
            });
        }

        let computed_crc = calculate_crc32(&buf[0..16 + payload_len]);
        let embedded_crc = u32::from_be_bytes([
            buf[16 + payload_len],
            buf[16 + payload_len + 1],
            buf[16 + payload_len + 2],
            buf[16 + payload_len + 3],
        ]);

        if computed_crc != embedded_crc {
            return Err(SessionError::CrcMismatch {
                computed: computed_crc,
                embedded: embedded_crc,
            });
        }

        let payload = &buf[16..16 + payload_len];

        match frame_type {
            frame_types::HANDSHAKE_SYN => {
                if payload.len() < 8 + 23 + 1 {
                    return Err(SessionError::BufferTooShort {
                        required: 32,
                        provided: payload.len(),
                    });
                }
                let client_nonce = u64::from_be_bytes([
                    payload[0], payload[1], payload[2], payload[3], payload[4], payload[5],
                    payload[6], payload[7],
                ]);
                let capabilities = SessionCapabilities::decode_from(&payload[8..31])?;
                let count = payload[31] as usize;
                let mut offset = 32;
                let mut advertised_subpaths = Vec::with_capacity(count);
                for _ in 0..count {
                    let (ad, consumed) = SubpathAdvertisement::decode(&payload[offset..])?;
                    advertised_subpaths.push(ad);
                    offset += consumed;
                }
                Ok(Self::HandshakeSyn {
                    session_id,
                    client_nonce,
                    capabilities,
                    advertised_subpaths,
                })
            }
            frame_types::HANDSHAKE_ACK => {
                if payload.len() < 16 + 23 + 1 {
                    return Err(SessionError::BufferTooShort {
                        required: 40,
                        provided: payload.len(),
                    });
                }
                let server_nonce = u64::from_be_bytes([
                    payload[0], payload[1], payload[2], payload[3], payload[4], payload[5],
                    payload[6], payload[7],
                ]);
                let echo_nonce = u64::from_be_bytes([
                    payload[8],
                    payload[9],
                    payload[10],
                    payload[11],
                    payload[12],
                    payload[13],
                    payload[14],
                    payload[15],
                ]);
                let negotiated_capabilities = SessionCapabilities::decode_from(&payload[16..39])?;
                let count = payload[39] as usize;
                let mut offset = 40;
                let mut accepted_subpaths = Vec::with_capacity(count);
                for _ in 0..count {
                    if payload.len() < offset + 4 {
                        return Err(SessionError::BufferTooShort {
                            required: offset + 4,
                            provided: payload.len(),
                        });
                    }
                    let sid = u32::from_be_bytes([
                        payload[offset],
                        payload[offset + 1],
                        payload[offset + 2],
                        payload[offset + 3],
                    ]);
                    offset += 4;
                    accepted_subpaths.push(sid);
                }
                Ok(Self::HandshakeAck {
                    session_id,
                    server_nonce,
                    echo_nonce,
                    negotiated_capabilities,
                    accepted_subpaths,
                })
            }
            frame_types::SUBPATH_ANNOUNCE => {
                let (advertisement, _) = SubpathAdvertisement::decode(payload)?;
                Ok(Self::SubpathAnnounce {
                    session_id,
                    advertisement,
                })
            }
            frame_types::SUBPATH_ACK => {
                if payload.len() < 5 {
                    return Err(SessionError::BufferTooShort {
                        required: 5,
                        provided: payload.len(),
                    });
                }
                let subpath_id =
                    u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                let accepted = payload[4] != 0;
                Ok(Self::SubpathAck {
                    session_id,
                    subpath_id,
                    accepted,
                })
            }
            frame_types::SUBPATH_TEARDOWN => {
                if payload.len() < 6 {
                    return Err(SessionError::BufferTooShort {
                        required: 6,
                        provided: payload.len(),
                    });
                }
                let subpath_id =
                    u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                let rlen = u16::from_be_bytes([payload[4], payload[5]]) as usize;
                if payload.len() < 6 + rlen {
                    return Err(SessionError::BufferTooShort {
                        required: 6 + rlen,
                        provided: payload.len(),
                    });
                }
                let reason = String::from_utf8_lossy(&payload[6..6 + rlen]).to_string();
                Ok(Self::SubpathTeardown {
                    session_id,
                    subpath_id,
                    reason,
                })
            }
            frame_types::KEEPALIVE_PING => {
                if payload.len() < 20 {
                    return Err(SessionError::BufferTooShort {
                        required: 20,
                        provided: payload.len(),
                    });
                }
                let nonce = u64::from_be_bytes([
                    payload[0], payload[1], payload[2], payload[3], payload[4], payload[5],
                    payload[6], payload[7],
                ]);
                let subpath_id =
                    u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
                let departure_time_ns = u64::from_be_bytes([
                    payload[12],
                    payload[13],
                    payload[14],
                    payload[15],
                    payload[16],
                    payload[17],
                    payload[18],
                    payload[19],
                ]);
                Ok(Self::KeepAlivePing {
                    session_id,
                    nonce,
                    subpath_id,
                    departure_time_ns,
                })
            }
            frame_types::KEEPALIVE_PONG => {
                if payload.len() < 20 {
                    return Err(SessionError::BufferTooShort {
                        required: 20,
                        provided: payload.len(),
                    });
                }
                let nonce = u64::from_be_bytes([
                    payload[0], payload[1], payload[2], payload[3], payload[4], payload[5],
                    payload[6], payload[7],
                ]);
                let subpath_id =
                    u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
                let ping_departure_ns = u64::from_be_bytes([
                    payload[12],
                    payload[13],
                    payload[14],
                    payload[15],
                    payload[16],
                    payload[17],
                    payload[18],
                    payload[19],
                ]);
                Ok(Self::KeepAlivePong {
                    session_id,
                    nonce,
                    subpath_id,
                    ping_departure_ns,
                })
            }
            frame_types::GRACEFUL_FIN => {
                if payload.len() < 10 {
                    return Err(SessionError::BufferTooShort {
                        required: 10,
                        provided: payload.len(),
                    });
                }
                let last_sequence = u64::from_be_bytes([
                    payload[0], payload[1], payload[2], payload[3], payload[4], payload[5],
                    payload[6], payload[7],
                ]);
                let rlen = u16::from_be_bytes([payload[8], payload[9]]) as usize;
                if payload.len() < 10 + rlen {
                    return Err(SessionError::BufferTooShort {
                        required: 10 + rlen,
                        provided: payload.len(),
                    });
                }
                let reason = String::from_utf8_lossy(&payload[10..10 + rlen]).to_string();
                Ok(Self::GracefulFin {
                    session_id,
                    last_sequence,
                    reason,
                })
            }
            frame_types::GRACEFUL_FIN_ACK => Ok(Self::GracefulFinAck { session_id }),
            frame_types::SESSION_RESET => {
                if payload.len() < 6 {
                    return Err(SessionError::BufferTooShort {
                        required: 6,
                        provided: payload.len(),
                    });
                }
                let error_code =
                    u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                let rlen = u16::from_be_bytes([payload[4], payload[5]]) as usize;
                if payload.len() < 6 + rlen {
                    return Err(SessionError::BufferTooShort {
                        required: 6 + rlen,
                        provided: payload.len(),
                    });
                }
                let reason = String::from_utf8_lossy(&payload[6..6 + rlen]).to_string();
                Ok(Self::SessionReset {
                    session_id,
                    error_code,
                    reason,
                })
            }
            other => Err(SessionError::UnknownFrameType(other)),
        }
    }
}

// ---------------------------------------------------------------------------
// Subpath Session Health & State Tracking
// ---------------------------------------------------------------------------

/// Health status classification of an individual transport subpath within a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubpathHealthStatus {
    /// Subpath is operating nominally with regular heartbeat confirmations.
    Healthy,
    /// Subpath experienced isolated packet loss or missed a single heartbeat ping.
    Degraded,
    /// Subpath is unresponsive but not yet declared dead.
    Stalled,
    /// Subpath exceeded inactivity threshold and is administratively disabled.
    Dead,
}

impl std::fmt::Display for SubpathHealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Healthy => write!(f, "Healthy"),
            Self::Degraded => write!(f, "Degraded"),
            Self::Stalled => write!(f, "Stalled"),
            Self::Dead => write!(f, "Dead"),
        }
    }
}

/// Operational state context maintained per subpath in the session controller.
#[derive(Debug, Clone)]
pub struct SubpathSessionState {
    pub subpath_id: u32,
    pub interface_name: String,
    pub peer_addr: SocketAddr,
    pub bandwidth_bps: u64,
    pub rtt_ns: u64,
    pub effective_pmtu: u32,
    pub active: bool,
    pub status: SubpathHealthStatus,
    pub last_sent_ns: u64,
    pub last_recv_ns: u64,
    pub pings_sent: u64,
    pub pongs_received: u64,
    pub consecutive_missed_pings: u32,
}

// ---------------------------------------------------------------------------
// Session State Machine
// ---------------------------------------------------------------------------

/// State machine governing the end-to-end multipath connection lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    /// Initial unestablished state.
    Idle,
    /// Handshake negotiation actively in progress.
    Connecting { initiated_ns: u64, attempts: u32 },
    /// Session fully established and actively forwarding application traffic.
    Active { established_ns: u64 },
    /// Graceful session termination in progress (FIN exchanged, draining queues).
    Draining { initiated_ns: u64, fin_sent: bool },
    /// Session closed cleanly.
    Closed { closed_ns: u64, reason: String },
    /// Session terminated abruptly due to fatal error or timeout.
    Failed { failed_ns: u64, reason: String },
}

impl SessionState {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Idle => "Idle",
            Self::Connecting { .. } => "Connecting",
            Self::Active { .. } => "Active",
            Self::Draining { .. } => "Draining",
            Self::Closed { .. } => "Closed",
            Self::Failed { .. } => "Failed",
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active { .. })
    }

    pub fn is_closed(&self) -> bool {
        matches!(self, Self::Closed { .. } | Self::Failed { .. })
    }
}

// ---------------------------------------------------------------------------
// Telemetry & Benchmarks
// ---------------------------------------------------------------------------

/// Real-time operational telemetry for `MultipathSessionController`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MultipathSessionTelemetry {
    pub state_transitions_count: u64,
    pub handshakes_initiated: u64,
    pub handshakes_completed: u64,
    pub keepalive_pings_sent: u64,
    pub keepalive_pongs_received: u64,
    pub keepalive_failures: u64,
    pub subpaths_discovered: u64,
    pub subpaths_degraded: u64,
    pub subpaths_dead: u64,
    pub app_packets_sent: u64,
    pub app_bytes_sent: u64,
    pub app_packets_received: u64,
    pub app_bytes_received: u64,
    pub graceful_fins_sent: u64,
    pub graceful_fins_received: u64,
}

/// Cycle processing summary returned by `poll_cycle`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SessionCycleReport {
    pub current_state: String,
    pub active_subpaths_count: usize,
    pub egress_report: EgressCycleReport,
    pub ingress_report: IngressCycleReport,
    pub control_frames_processed: usize,
    pub app_packets_delivered: usize,
    pub keepalives_dispatched: usize,
    pub subpaths_state_changes: usize,
}

/// Configuration options for `MultipathSessionController`.
#[derive(Debug, Clone, PartialEq)]
pub struct MultipathSessionConfig {
    pub session_id: u64,
    pub is_server: bool,
    pub local_capabilities: SessionCapabilities,
    pub egress_config: AsyncMultipathEgressGatewayConfig,
    pub ingress_config: AsyncMultipathIngressGatewayConfig,
    pub handshake_timeout_ns: u64,
    pub drain_timeout_ns: u64,
    pub max_handshake_retries: u32,
    pub max_missed_keepalives: u32,
}

impl Default for MultipathSessionConfig {
    fn default() -> Self {
        Self {
            session_id: 1,
            is_server: false,
            local_capabilities: SessionCapabilities::default(),
            egress_config: AsyncMultipathEgressGatewayConfig::default(),
            ingress_config: AsyncMultipathIngressGatewayConfig::default(),
            handshake_timeout_ns: DEFAULT_HANDSHAKE_TIMEOUT_NS,
            drain_timeout_ns: DEFAULT_DRAIN_TIMEOUT_NS,
            max_handshake_retries: 3,
            max_missed_keepalives: 3,
        }
    }
}

// ---------------------------------------------------------------------------
// Multipath Session Controller Implementation
// ---------------------------------------------------------------------------

/// Unified End-to-End Multipath Connection Session Controller.
pub struct MultipathSessionController {
    config: MultipathSessionConfig,
    state: SessionState,
    local_nonce: u64,
    peer_nonce: Option<u64>,
    negotiated_capabilities: Option<SessionCapabilities>,
    egress_gateway: AsyncMultipathEgressGateway,
    ingress_gateway: AsyncMultipathIngressGateway,
    subpaths: BTreeMap<u32, SubpathSessionState>,
    pending_app_inbound: VecDeque<ValidatedIngressPacket>,
    next_ping_nonce: u64,
    last_keepalive_sweep_ns: u64,
    telemetry: MultipathSessionTelemetry,
}

impl MultipathSessionController {
    /// Construct a new `MultipathSessionController` instance.
    pub fn new(config: MultipathSessionConfig) -> Self {
        let egress_gateway = AsyncMultipathEgressGateway::new(config.egress_config.clone());
        let ingress_gateway = AsyncMultipathIngressGateway::new(config.ingress_config.clone());

        // Deterministic pseudo-random seed based on session ID and timestamp
        let local_nonce = config.session_id ^ 0x55AA_55AA_1234_5678;

        Self {
            config,
            state: SessionState::Idle,
            local_nonce,
            peer_nonce: None,
            negotiated_capabilities: None,
            egress_gateway,
            ingress_gateway,
            subpaths: BTreeMap::new(),
            pending_app_inbound: VecDeque::new(),
            next_ping_nonce: 1,
            last_keepalive_sweep_ns: 0,
            telemetry: MultipathSessionTelemetry::default(),
        }
    }

    /// Access current session state.
    pub fn state(&self) -> &SessionState {
        &self.state
    }

    /// Access session ID.
    pub fn session_id(&self) -> u64 {
        self.config.session_id
    }

    /// Access negotiated capabilities if handshake succeeded.
    pub fn negotiated_capabilities(&self) -> Option<&SessionCapabilities> {
        self.negotiated_capabilities.as_ref()
    }

    /// Access subpath state by identifier.
    pub fn subpath_state(&self, subpath_id: u32) -> Option<&SubpathSessionState> {
        self.subpaths.get(&subpath_id)
    }

    /// Total number of active registered subpaths.
    pub fn active_subpaths_count(&self) -> usize {
        self.subpaths.values().filter(|s| s.active).count()
    }

    /// Timestamp in nanoseconds of the most recent keepalive sweep.
    pub fn last_keepalive_sweep_ns(&self) -> u64 {
        self.last_keepalive_sweep_ns
    }

    /// Register a physical network interface for bidirectional transport on this session.
    pub fn add_subpath(
        &mut self,
        subpath_id: u32,
        interface_name: impl Into<String>,
        socket: Arc<AsyncUdpSocket>,
        peer_addr: SocketAddr,
        bandwidth_bps: u64,
        rtt_ns: u64,
        effective_pmtu: u32,
        now_ns: u64,
    ) -> Result<(), SessionError> {
        let name_str = interface_name.into();

        // 1. Register in Egress Gateway
        let egress_iface = PhysicalEgressInterface::new(
            subpath_id,
            name_str.clone(),
            Arc::clone(&socket),
            peer_addr,
            bandwidth_bps,
            rtt_ns,
            effective_pmtu,
            now_ns,
        );
        self.egress_gateway
            .register_interface(egress_iface, now_ns)?;

        // 2. Register in Ingress Gateway
        let ingress_iface =
            PhysicalIngressInterface::new(subpath_id, name_str.clone(), socket, peer_addr, now_ns);
        self.ingress_gateway.register_interface(ingress_iface)?;

        // 3. Register in Session Subpath tracker
        let subpath_state = SubpathSessionState {
            subpath_id,
            interface_name: name_str,
            peer_addr,
            bandwidth_bps,
            rtt_ns,
            effective_pmtu,
            active: true,
            status: SubpathHealthStatus::Healthy,
            last_sent_ns: now_ns,
            last_recv_ns: now_ns,
            pings_sent: 0,
            pongs_received: 0,
            consecutive_missed_pings: 0,
        };
        self.subpaths.insert(subpath_id, subpath_state);
        self.telemetry.subpaths_discovered += 1;

        // If session is active and not during initial handshake, announce to remote peer
        if self.state.is_active() {
            let ad = SubpathAdvertisement {
                subpath_id,
                peer_addr,
                bandwidth_bps,
                pmtu: effective_pmtu,
            };
            self.send_control_frame(
                SessionControlFrame::SubpathAnnounce {
                    session_id: self.config.session_id,
                    advertisement: ad,
                },
                Some(subpath_id),
                now_ns,
            )?;
        }

        Ok(())
    }

    /// Administratively enable or disable a subpath interface.
    pub fn set_subpath_active(&mut self, subpath_id: u32, active: bool) {
        if let Some(s) = self.subpaths.get_mut(&subpath_id) {
            s.active = active;
        }
        self.egress_gateway.set_interface_active(subpath_id, active);
        self.ingress_gateway
            .set_interface_active(subpath_id, active);
    }

    /// Remove a subpath interface entirely from session.
    pub fn remove_subpath(&mut self, subpath_id: u32) -> Result<(), SessionError> {
        let _ = self.egress_gateway.unregister_interface(subpath_id);
        self.subpaths.remove(&subpath_id);
        Ok(())
    }

    /// Initiate handshake to establish multipath connection with remote peer.
    pub fn initiate_handshake(&mut self, now_ns: u64) -> Result<(), SessionError> {
        if !matches!(self.state, SessionState::Idle) {
            return Err(SessionError::InvalidState {
                current: self.state.name().to_string(),
                expected: "Idle",
            });
        }

        self.state = SessionState::Connecting {
            initiated_ns: now_ns,
            attempts: 1,
        };
        self.telemetry.state_transitions_count += 1;
        self.telemetry.handshakes_initiated += 1;

        // Collect subpath advertisements
        let ads: Vec<SubpathAdvertisement> = self
            .subpaths
            .values()
            .map(|s| SubpathAdvertisement {
                subpath_id: s.subpath_id,
                peer_addr: s.peer_addr,
                bandwidth_bps: s.bandwidth_bps,
                pmtu: s.effective_pmtu,
            })
            .collect();

        let syn = SessionControlFrame::HandshakeSyn {
            session_id: self.config.session_id,
            client_nonce: self.local_nonce,
            capabilities: self.config.local_capabilities,
            advertised_subpaths: ads,
        };

        // Broadcast SYN on all registered active subpaths
        self.broadcast_control_frame(syn, now_ns)?;
        Ok(())
    }

    /// Submit un-framed application payload for transmission across the multipath connection.
    pub fn send_payload(
        &mut self,
        slice: FlowSliceClass,
        payload: Vec<u8>,
        deadline_ns: Option<u64>,
        now_ns: u64,
    ) -> Result<u64, SessionError> {
        if !self.state.is_active() && !matches!(self.state, SessionState::Draining { .. }) {
            return Err(SessionError::InvalidState {
                current: self.state.name().to_string(),
                expected: "Active",
            });
        }

        let p_len = payload.len();
        let flow_id = self.config.session_id;
        let pkt_id =
            self.egress_gateway
                .submit_payload(flow_id, slice, payload, deadline_ns, now_ns)?;

        self.telemetry.app_packets_sent += 1;
        self.telemetry.app_bytes_sent += p_len as u64;

        Ok(pkt_id)
    }

    /// Submit a stream frame through the integrated stream multiplexer.
    pub fn send_stream_data(
        &mut self,
        stream_id: StreamId,
        data: &[u8],
        fin: bool,
        priority: StreamPriority,
        now_ns: u64,
    ) -> Result<u64, SessionError> {
        if !self.state.is_active() {
            return Err(SessionError::InvalidState {
                current: self.state.name().to_string(),
                expected: "Active",
            });
        }

        let frame = StreamFrame {
            stream_id,
            offset: 0,
            payload: data.to_vec(),
            fin,
            slice_class: FlowSliceClass::HighThroughput,
            priority,
            subpath_id: 0,
            seq_num: 0,
            is_bicast: false,
        };

        let p_len = data.len();
        let pkt_id = self.egress_gateway.submit_stream_frame(frame, now_ns)?;

        self.telemetry.app_packets_sent += 1;
        self.telemetry.app_bytes_sent += p_len as u64;

        Ok(pkt_id)
    }

    /// Retrieve the next received application payload.
    pub fn recv_payload(&mut self) -> Option<ValidatedIngressPacket> {
        self.pending_app_inbound.pop_front()
    }

    /// Read reassembled stream data from the coupled ingress stream multiplexer.
    pub fn recv_stream_data(&mut self, stream_id: StreamId, max_len: usize) -> Option<Vec<u8>> {
        self.ingress_gateway.read_stream_data(stream_id, max_len)
    }

    /// Initiate graceful session closure (FIN handshake and queue drainage).
    pub fn initiate_graceful_close(
        &mut self,
        reason: &str,
        now_ns: u64,
    ) -> Result<(), SessionError> {
        if !self.state.is_active() {
            return Err(SessionError::InvalidState {
                current: self.state.name().to_string(),
                expected: "Active",
            });
        }

        self.state = SessionState::Draining {
            initiated_ns: now_ns,
            fin_sent: true,
        };
        self.telemetry.state_transitions_count += 1;
        self.telemetry.graceful_fins_sent += 1;

        let fin = SessionControlFrame::GracefulFin {
            session_id: self.config.session_id,
            last_sequence: self.egress_gateway.next_packet_id,
            reason: reason.to_string(),
        };

        self.broadcast_control_frame(fin, now_ns)?;
        Ok(())
    }

    /// Execute a non-blocking execution cycle:
    /// 1. Poll incoming packets from all physical sockets via ingress gateway.
    /// 2. Extract and handle session control signaling (Handshake, Pings, Announce, FIN).
    /// 3. Synchronize subpath RTT and jitter metrics back into egress pacing scheduler.
    /// 4. Dispatch periodic heartbeat pings and audit subpath degradation/death.
    /// 5. Advance handshake timeouts and graceful closure drainage.
    /// 6. Drain outbound backpressure queues and pace wire departures via egress gateway.
    pub fn poll_cycle(&mut self, now_ns: u64) -> SessionCycleReport {
        // 1. Ingress polling cycle
        let ingress_report = self.ingress_gateway.process_ingress_cycle(now_ns, None);
        let mut report = SessionCycleReport {
            ingress_report,
            ..Default::default()
        };

        // 2. Process all raw ingress packets (control frames vs application payload)
        while let Some(packet) = self.ingress_gateway.pop_raw_packet() {
            if packet.payload.len() >= SESSION_CTRL_MIN_HEADER_SIZE
                && packet
                    .payload
                    .starts_with(&IFA_SESSION_CTRL_MAGIC.to_be_bytes())
            {
                if let Ok(ctrl_frame) = SessionControlFrame::decode(&packet.payload) {
                    report.control_frames_processed += 1;
                    self.handle_incoming_control_frame(ctrl_frame, packet.subpath_id, now_ns);
                    continue;
                }
            }

            // Not a control frame: deliver to application inbound queue
            self.telemetry.app_packets_received += 1;
            self.telemetry.app_bytes_received += packet.payload.len() as u64;
            report.app_packets_delivered += 1;
            self.pending_app_inbound.push_back(packet);
        }

        // 3. Synchronize subpath metrics from ingress tracker into egress scheduler
        let sids: Vec<u32> = self.subpaths.keys().copied().collect();
        for sid in sids {
            if let Some(metrics) = self.ingress_gateway.subpath_metrics(sid) {
                let bw = self
                    .subpaths
                    .get(&sid)
                    .map(|s| s.bandwidth_bps)
                    .unwrap_or(10_000_000);
                self.egress_gateway.feed_subpath_metrics(
                    sid,
                    metrics.srtt_ns,
                    metrics.jitter_ns,
                    0.0,
                    bw,
                    now_ns,
                );
            }
        }

        // 4. Subpath keepalive heartbeat checks and dead-path detection
        self.last_keepalive_sweep_ns = now_ns;
        let (dispatched, state_changes) = self.audit_subpaths_keepalive(now_ns);
        report.keepalives_dispatched += dispatched;
        report.subpaths_state_changes += state_changes;

        // 5. Lifecycle machine updates (Handshake timeouts & Graceful drain completion)
        self.update_lifecycle_state(now_ns);

        // 6. Egress processing cycle
        report.egress_report = self.egress_gateway.process_egress_cycle(now_ns, None);

        report.current_state = self.state.name().to_string();
        report.active_subpaths_count = self.active_subpaths_count();

        report
    }

    /// Handle decoded incoming session control frame.
    fn handle_incoming_control_frame(
        &mut self,
        frame: SessionControlFrame,
        received_subpath_id: u32,
        now_ns: u64,
    ) {
        if let Some(s) = self.subpaths.get_mut(&received_subpath_id) {
            s.last_recv_ns = now_ns;
            s.consecutive_missed_pings = 0;
            if s.status != SubpathHealthStatus::Healthy {
                s.status = SubpathHealthStatus::Healthy;
            }
        }

        match frame {
            SessionControlFrame::HandshakeSyn {
                session_id,
                client_nonce,
                capabilities,
                advertised_subpaths,
            } => {
                if self.config.is_server && matches!(self.state, SessionState::Idle) {
                    let negotiated = self.config.local_capabilities.negotiate(&capabilities);
                    self.negotiated_capabilities = Some(negotiated);
                    self.peer_nonce = Some(client_nonce);
                    self.state = SessionState::Active {
                        established_ns: now_ns,
                    };
                    self.telemetry.state_transitions_count += 1;
                    self.telemetry.handshakes_completed += 1;

                    // Accept advertised subpaths
                    let mut accepted_sids = Vec::new();
                    for ad in advertised_subpaths {
                        accepted_sids.push(ad.subpath_id);
                    }

                    let ack = SessionControlFrame::HandshakeAck {
                        session_id,
                        server_nonce: self.local_nonce,
                        echo_nonce: client_nonce,
                        negotiated_capabilities: negotiated,
                        accepted_subpaths: accepted_sids,
                    };
                    let _ = self.send_control_frame(ack, Some(received_subpath_id), now_ns);
                }
            }
            SessionControlFrame::HandshakeAck {
                session_id: _,
                server_nonce,
                echo_nonce,
                negotiated_capabilities,
                accepted_subpaths: _,
            } => {
                if let SessionState::Connecting { .. } = self.state {
                    if echo_nonce == self.local_nonce {
                        self.peer_nonce = Some(server_nonce);
                        self.negotiated_capabilities = Some(negotiated_capabilities);
                        self.state = SessionState::Active {
                            established_ns: now_ns,
                        };
                        self.telemetry.state_transitions_count += 1;
                        self.telemetry.handshakes_completed += 1;
                    }
                }
            }
            SessionControlFrame::SubpathAnnounce {
                session_id,
                advertisement,
            } => {
                let sid = advertisement.subpath_id;
                let ack = SessionControlFrame::SubpathAck {
                    session_id,
                    subpath_id: sid,
                    accepted: true,
                };
                let _ = self.send_control_frame(ack, Some(received_subpath_id), now_ns);
            }
            SessionControlFrame::SubpathAck {
                subpath_id,
                accepted,
                ..
            } => {
                if !accepted {
                    self.set_subpath_active(subpath_id, false);
                }
            }
            SessionControlFrame::SubpathTeardown { subpath_id, .. } => {
                self.set_subpath_active(subpath_id, false);
            }
            SessionControlFrame::KeepAlivePing {
                session_id,
                nonce,
                subpath_id,
                departure_time_ns,
            } => {
                self.telemetry.keepalive_pongs_received += 1;
                let pong = SessionControlFrame::KeepAlivePong {
                    session_id,
                    nonce,
                    subpath_id,
                    ping_departure_ns: departure_time_ns,
                };
                let _ = self.send_control_frame(pong, Some(received_subpath_id), now_ns);
            }
            SessionControlFrame::KeepAlivePong {
                nonce: _,
                subpath_id,
                ping_departure_ns,
                ..
            } => {
                self.telemetry.keepalive_pongs_received += 1;
                let rtt_sample = now_ns.saturating_sub(ping_departure_ns);
                if let Some(s) = self.subpaths.get_mut(&subpath_id) {
                    s.pongs_received += 1;
                    s.rtt_ns = rtt_sample;
                    s.status = SubpathHealthStatus::Healthy;
                    s.consecutive_missed_pings = 0;
                }
            }
            SessionControlFrame::GracefulFin { session_id, .. } => {
                self.telemetry.graceful_fins_received += 1;
                if self.state.is_active() {
                    self.state = SessionState::Draining {
                        initiated_ns: now_ns,
                        fin_sent: false,
                    };
                    self.telemetry.state_transitions_count += 1;
                }
                let fin_ack = SessionControlFrame::GracefulFinAck { session_id };
                let _ = self.send_control_frame(fin_ack, Some(received_subpath_id), now_ns);
            }
            SessionControlFrame::GracefulFinAck { .. } => {
                if let SessionState::Draining { .. } = self.state {
                    self.state = SessionState::Closed {
                        closed_ns: now_ns,
                        reason: "Graceful FIN handshake concluded".to_string(),
                    };
                    self.telemetry.state_transitions_count += 1;
                }
            }
            SessionControlFrame::SessionReset { reason, .. } => {
                self.state = SessionState::Failed {
                    failed_ns: now_ns,
                    reason,
                };
                self.telemetry.state_transitions_count += 1;
            }
        }
    }

    /// Audit subpaths for heartbeat keepalives and detect dead paths.
    fn audit_subpaths_keepalive(&mut self, now_ns: u64) -> (usize, usize) {
        let caps = self
            .negotiated_capabilities
            .unwrap_or(self.config.local_capabilities);
        let ping_interval = caps.keepalive_interval_ns;
        let timeout_thresh = caps.inactivity_timeout_ns;

        let mut pings_sent = 0;
        let mut degraded_count = 0;
        let mut dead_count = 0;

        let sids: Vec<u32> = self.subpaths.keys().copied().collect();

        for sid in sids {
            let (should_ping, is_stalled, is_dead) = {
                let s = match self.subpaths.get_mut(&sid) {
                    Some(state) => state,
                    None => continue,
                };

                if !s.active {
                    continue;
                }

                let elapsed_since_send = now_ns.saturating_sub(s.last_sent_ns);
                let elapsed_since_recv = now_ns.saturating_sub(s.last_recv_ns);

                let should_ping = elapsed_since_send >= ping_interval;

                let mut is_stalled = false;
                let mut is_dead = false;

                if elapsed_since_recv >= timeout_thresh {
                    s.consecutive_missed_pings += 1;
                    if s.consecutive_missed_pings >= self.config.max_missed_keepalives {
                        s.status = SubpathHealthStatus::Dead;
                        is_dead = true;
                    } else {
                        s.status = SubpathHealthStatus::Stalled;
                        is_stalled = true;
                    }
                } else if elapsed_since_recv >= timeout_thresh / 2 {
                    s.status = SubpathHealthStatus::Degraded;
                }

                (should_ping, is_stalled, is_dead)
            };

            if is_dead {
                dead_count += 1;
                self.telemetry.keepalive_failures += 1;
                self.telemetry.subpaths_dead += 1;
                // Administratively take subpath offline in egress gateway to trigger reroute
                self.egress_gateway.set_interface_active(sid, false);
            } else if is_stalled {
                degraded_count += 1;
                self.telemetry.subpaths_degraded += 1;
            }

            if should_ping && !is_dead {
                let nonce = self.next_ping_nonce;
                self.next_ping_nonce = self.next_ping_nonce.wrapping_add(1).max(1);

                let ping = SessionControlFrame::KeepAlivePing {
                    session_id: self.config.session_id,
                    nonce,
                    subpath_id: sid,
                    departure_time_ns: now_ns,
                };

                if self.send_control_frame(ping, Some(sid), now_ns).is_ok() {
                    if let Some(s) = self.subpaths.get_mut(&sid) {
                        s.last_sent_ns = now_ns;
                        s.pings_sent += 1;
                    }
                    self.telemetry.keepalive_pings_sent += 1;
                    pings_sent += 1;
                }
            }
        }

        (pings_sent, degraded_count + dead_count)
    }

    /// Advance session lifecycle timers.
    fn update_lifecycle_state(&mut self, now_ns: u64) {
        match &self.state {
            SessionState::Connecting {
                initiated_ns,
                attempts,
            } => {
                if now_ns.saturating_sub(*initiated_ns) >= self.config.handshake_timeout_ns {
                    if *attempts < self.config.max_handshake_retries {
                        let new_attempts = attempts + 1;
                        self.state = SessionState::Connecting {
                            initiated_ns: now_ns,
                            attempts: new_attempts,
                        };
                        let ads: Vec<SubpathAdvertisement> = self
                            .subpaths
                            .values()
                            .map(|s| SubpathAdvertisement {
                                subpath_id: s.subpath_id,
                                peer_addr: s.peer_addr,
                                bandwidth_bps: s.bandwidth_bps,
                                pmtu: s.effective_pmtu,
                            })
                            .collect();
                        let syn = SessionControlFrame::HandshakeSyn {
                            session_id: self.config.session_id,
                            client_nonce: self.local_nonce,
                            capabilities: self.config.local_capabilities,
                            advertised_subpaths: ads,
                        };
                        let _ = self.broadcast_control_frame(syn, now_ns);
                    } else {
                        self.state = SessionState::Failed {
                            failed_ns: now_ns,
                            reason: "Handshake negotiation timeout".to_string(),
                        };
                        self.telemetry.state_transitions_count += 1;
                    }
                }
            }
            SessionState::Draining {
                initiated_ns,
                fin_sent: _,
            } => {
                let elapsed = now_ns.saturating_sub(*initiated_ns);
                let queues_empty = self.egress_gateway.pending_backpressure.is_empty();
                if elapsed >= self.config.drain_timeout_ns || queues_empty {
                    self.state = SessionState::Closed {
                        closed_ns: now_ns,
                        reason: "Session drained and closed cleanly".to_string(),
                    };
                    self.telemetry.state_transitions_count += 1;
                }
            }
            _ => {}
        }
    }

    /// Transmit a control frame across a specific subpath interface.
    fn send_control_frame(
        &mut self,
        frame: SessionControlFrame,
        target_subpath: Option<u32>,
        now_ns: u64,
    ) -> Result<u64, SessionError> {
        let bytes = frame.encode();
        if let Some(sid) = target_subpath {
            self.egress_gateway
                .bind_slice_to_subpath(FlowSliceClass::UltraLowLatency, sid);
        }
        let pkt_id = self.egress_gateway.submit_payload(
            self.config.session_id,
            FlowSliceClass::UltraLowLatency,
            bytes,
            Some(now_ns + 10_000_000), // High priority deadline 10ms
            now_ns,
        )?;
        Ok(pkt_id)
    }

    /// Broadcast a control frame over all active registered subpaths.
    fn broadcast_control_frame(
        &mut self,
        frame: SessionControlFrame,
        now_ns: u64,
    ) -> Result<(), SessionError> {
        let sids: Vec<u32> = self
            .subpaths
            .values()
            .filter(|s| s.active)
            .map(|s| s.subpath_id)
            .collect();
        for sid in sids {
            let _ = self.send_control_frame(frame.clone(), Some(sid), now_ns);
        }
        Ok(())
    }

    /// Access live operational telemetry.
    pub fn telemetry(&self) -> &MultipathSessionTelemetry {
        &self.telemetry
    }

    /// Export operational metrics in OpenMetrics / Prometheus exposition format.
    pub fn export_prometheus_metrics(&self) -> String {
        let mut out = String::with_capacity(2048);
        let t = &self.telemetry;
        let sid = self.config.session_id;

        let _ = writeln!(out, "# HELP ifa_session_state Multipath session state (0=Idle, 1=Connecting, 2=Active, 3=Draining, 4=Closed, 5=Failed).");
        let _ = writeln!(out, "# TYPE ifa_session_state gauge");
        let state_val = match self.state {
            SessionState::Idle => 0,
            SessionState::Connecting { .. } => 1,
            SessionState::Active { .. } => 2,
            SessionState::Draining { .. } => 3,
            SessionState::Closed { .. } => 4,
            SessionState::Failed { .. } => 5,
        };
        let _ = writeln!(
            out,
            "ifa_session_state{{session_id=\"{}\"}} {}",
            sid, state_val
        );

        let _ = writeln!(
            out,
            "# HELP ifa_session_active_subpaths Number of active registered subpaths."
        );
        let _ = writeln!(out, "# TYPE ifa_session_active_subpaths gauge");
        let _ = writeln!(
            out,
            "ifa_session_active_subpaths{{session_id=\"{}\"}} {}",
            sid,
            self.active_subpaths_count()
        );

        let _ = writeln!(
            out,
            "# HELP ifa_session_app_packets_sent_total Total application packets sent."
        );
        let _ = writeln!(out, "# TYPE ifa_session_app_packets_sent_total counter");
        let _ = writeln!(
            out,
            "ifa_session_app_packets_sent_total{{session_id=\"{}\"}} {}",
            sid, t.app_packets_sent
        );

        let _ = writeln!(
            out,
            "# HELP ifa_session_app_bytes_sent_total Total application bytes sent."
        );
        let _ = writeln!(out, "# TYPE ifa_session_app_bytes_sent_total counter");
        let _ = writeln!(
            out,
            "ifa_session_app_bytes_sent_total{{session_id=\"{}\"}} {}",
            sid, t.app_bytes_sent
        );

        let _ = writeln!(
            out,
            "# HELP ifa_session_app_packets_recv_total Total application packets received."
        );
        let _ = writeln!(out, "# TYPE ifa_session_app_packets_recv_total counter");
        let _ = writeln!(
            out,
            "ifa_session_app_packets_recv_total{{session_id=\"{}\"}} {}",
            sid, t.app_packets_received
        );

        let _ = writeln!(
            out,
            "# HELP ifa_session_app_bytes_recv_total Total application bytes received."
        );
        let _ = writeln!(out, "# TYPE ifa_session_app_bytes_recv_total counter");
        let _ = writeln!(
            out,
            "ifa_session_app_bytes_recv_total{{session_id=\"{}\"}} {}",
            sid, t.app_bytes_received
        );

        let _ = writeln!(
            out,
            "# HELP ifa_session_keepalive_pings_sent_total Total keepalive pings dispatched."
        );
        let _ = writeln!(out, "# TYPE ifa_session_keepalive_pings_sent_total counter");
        let _ = writeln!(
            out,
            "ifa_session_keepalive_pings_sent_total{{session_id=\"{}\"}} {}",
            sid, t.keepalive_pings_sent
        );

        let _ = writeln!(
            out,
            "# HELP ifa_session_keepalive_failures_total Total subpath keepalive failures."
        );
        let _ = writeln!(out, "# TYPE ifa_session_keepalive_failures_total counter");
        let _ = writeln!(
            out,
            "ifa_session_keepalive_failures_total{{session_id=\"{}\"}} {}",
            sid, t.keepalive_failures
        );

        out
    }

    /// Generate structured JSON audit trail.
    pub fn generate_json_audit_trail(&self) -> String {
        let mut out = String::with_capacity(2048);
        let t = &self.telemetry;

        let _ = write!(
            out,
            "{{\"session_id\":{},\"state\":\"{}\",\"is_server\":{},\"active_subpaths\":{},\"telemetry\":{{\"transitions\":{},\"app_packets_sent\":{},\"app_bytes_sent\":{},\"app_packets_recv\":{},\"app_bytes_recv\":{},\"pings_sent\":{},\"pongs_recv\":{},\"keepalive_failures\":{}}},\"subpaths\":[",
            self.config.session_id,
            self.state.name(),
            self.config.is_server,
            self.active_subpaths_count(),
            t.state_transitions_count,
            t.app_packets_sent,
            t.app_bytes_sent,
            t.app_packets_received,
            t.app_bytes_received,
            t.keepalive_pings_sent,
            t.keepalive_pongs_received,
            t.keepalive_failures
        );

        let mut first = true;
        for s in self.subpaths.values() {
            if !first {
                out.push(',');
            }
            first = false;
            let _ = write!(
                out,
                "{{\"subpath_id\":{},\"name\":\"{}\",\"peer_addr\":\"{}\",\"rtt_ns\":{},\"status\":\"{}\",\"active\":{}}}",
                s.subpath_id, s.interface_name, s.peer_addr, s.rtt_ns, s.status, s.active
            );
        }
        out.push_str("]}");

        out
    }
}

// ---------------------------------------------------------------------------
// In-Memory Micro-Benchmark Suite
// ---------------------------------------------------------------------------

/// Performance and throughput report for `MultipathSessionController`.
#[derive(Debug, Clone, PartialEq)]
pub struct MultipathSessionBenchmarkReport {
    pub session_id: u64,
    pub handshake_duration_ns: u64,
    pub total_cycles_executed: usize,
    pub total_app_packets_sent: u64,
    pub total_app_bytes_sent: u64,
    pub total_pings_exchanged: u64,
    pub throughput_mbps: f64,
    pub is_gracefully_closed: bool,
}

/// Run micro-benchmark verifying full session lifecycle: handshake, data exchange,
/// heartbeat keepalive, and graceful termination.
pub fn run_multipath_session_controller_benchmark() -> MultipathSessionBenchmarkReport {
    let now_base = 1_000_000_000u64;

    let s1 = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").unwrap());
    let s2 = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").unwrap());
    let a1 = s1.local_addr().unwrap();
    let a2 = s2.local_addr().unwrap();

    let client_cfg = MultipathSessionConfig {
        session_id: 1001,
        is_server: false,
        ..Default::default()
    };
    let server_cfg = MultipathSessionConfig {
        session_id: 1001,
        is_server: true,
        ..Default::default()
    };

    let mut client = MultipathSessionController::new(client_cfg);
    let mut server = MultipathSessionController::new(server_cfg);

    client
        .add_subpath(
            1,
            "client_subpath1",
            s1,
            a2,
            100_000_000,
            5_000_000,
            1400,
            now_base,
        )
        .unwrap();
    server
        .add_subpath(
            1,
            "server_subpath1",
            s2,
            a1,
            100_000_000,
            5_000_000,
            1400,
            now_base,
        )
        .unwrap();

    // 1. Initiate handshake
    client.initiate_handshake(now_base).unwrap();

    let mut current_ns = now_base;
    let mut cycles = 0;

    // Run client egress -> server ingress
    client.poll_cycle(current_ns);
    current_ns += 5_000_000;
    server.poll_cycle(current_ns);

    // Server should be Active, replied with ACK
    current_ns += 5_000_000;
    client.poll_cycle(current_ns);

    let handshake_duration_ns = current_ns - now_base;

    // 2. Transmit application datagrams
    for i in 0..10 {
        current_ns += 1_000_000;
        let payload = format!("benchmark_session_packet_{}", i).into_bytes();
        let _ = client.send_payload(FlowSliceClass::MissionCritical, payload, None, current_ns);
        client.poll_cycle(current_ns);
        server.poll_cycle(current_ns);
        cycles += 2;
    }

    // 3. Graceful termination
    current_ns += 1_000_000;
    client
        .initiate_graceful_close("benchmark_done", current_ns)
        .unwrap();
    client.poll_cycle(current_ns);
    server.poll_cycle(current_ns);
    client.poll_cycle(current_ns + 10_000_000);

    let t = client.telemetry();
    let elapsed_sec = (current_ns - now_base) as f64 / 1_000_000_000.0;
    let throughput_mbps = (t.app_bytes_sent as f64 * 8.0) / (elapsed_sec * 1_000_000.0);

    MultipathSessionBenchmarkReport {
        session_id: 1001,
        handshake_duration_ns,
        total_cycles_executed: cycles,
        total_app_packets_sent: t.app_packets_sent,
        total_app_bytes_sent: t.app_bytes_sent,
        total_pings_exchanged: t.keepalive_pings_sent,
        throughput_mbps,
        is_gracefully_closed: client.state().is_closed(),
    }
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capabilities_negotiation_and_serialization() {
        let c1 = SessionCapabilities {
            version: 1,
            max_subpaths: 4,
            enable_pacing: true,
            enable_bicasting: true,
            enable_fec: false,
            reorder_window_size: 1024,
            keepalive_interval_ns: 2_000_000_000,
            inactivity_timeout_ns: 6_000_000_000,
        };

        let c2 = SessionCapabilities {
            version: 2,
            max_subpaths: 8,
            enable_pacing: true,
            enable_bicasting: false,
            enable_fec: true,
            reorder_window_size: 4096,
            keepalive_interval_ns: 1_000_000_000,
            inactivity_timeout_ns: 4_000_000_000,
        };

        let negotiated = c1.negotiate(&c2);
        assert_eq!(negotiated.version, 1);
        assert_eq!(negotiated.max_subpaths, 4);
        assert!(negotiated.enable_pacing);
        assert!(!negotiated.enable_bicasting);
        assert!(!negotiated.enable_fec);
        assert_eq!(negotiated.reorder_window_size, 1024);
        assert_eq!(negotiated.keepalive_interval_ns, 2_000_000_000);
        assert_eq!(negotiated.inactivity_timeout_ns, 6_000_000_000);

        let mut buf = [0u8; 23];
        negotiated.encode_to(&mut buf).unwrap();
        let decoded = SessionCapabilities::decode_from(&buf).unwrap();
        assert_eq!(negotiated, decoded);
    }

    #[test]
    fn test_subpath_advertisement_wire_roundtrip() {
        let ad = SubpathAdvertisement {
            subpath_id: 42,
            peer_addr: "192.168.1.100:8443".parse().unwrap(),
            bandwidth_bps: 1_000_000_000,
            pmtu: 1500,
        };

        let bytes = ad.encode();
        let (decoded, consumed) = SubpathAdvertisement::decode(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(ad, decoded);
    }

    #[test]
    fn test_session_control_frames_roundtrip() {
        let syn = SessionControlFrame::HandshakeSyn {
            session_id: 9999,
            client_nonce: 0x1122334455667788,
            capabilities: SessionCapabilities::default(),
            advertised_subpaths: vec![SubpathAdvertisement {
                subpath_id: 1,
                peer_addr: "10.0.0.1:5000".parse().unwrap(),
                bandwidth_bps: 50_000_000,
                pmtu: 1400,
            }],
        };

        let bytes = syn.encode();
        let decoded = SessionControlFrame::decode(&bytes).unwrap();
        assert_eq!(syn, decoded);

        let ping = SessionControlFrame::KeepAlivePing {
            session_id: 9999,
            nonce: 12345,
            subpath_id: 2,
            departure_time_ns: 88888888,
        };
        let p_bytes = ping.encode();
        let p_dec = SessionControlFrame::decode(&p_bytes).unwrap();
        assert_eq!(ping, p_dec);

        let fin = SessionControlFrame::GracefulFin {
            session_id: 9999,
            last_sequence: 500,
            reason: "Client disconnect".to_string(),
        };
        let f_bytes = fin.encode();
        let f_dec = SessionControlFrame::decode(&f_bytes).unwrap();
        assert_eq!(fin, f_dec);
    }

    #[test]
    fn test_end_to_end_handshake_and_data_exchange() {
        let now = 10_000_000_000u64;

        let sock_c = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").unwrap());
        let sock_s = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").unwrap());
        let addr_c = sock_c.local_addr().unwrap();
        let addr_s = sock_s.local_addr().unwrap();

        let client_cfg = MultipathSessionConfig {
            session_id: 555,
            is_server: false,
            ..Default::default()
        };
        let server_cfg = MultipathSessionConfig {
            session_id: 555,
            is_server: true,
            ..Default::default()
        };

        let mut client = MultipathSessionController::new(client_cfg);
        let mut server = MultipathSessionController::new(server_cfg);

        client
            .add_subpath(
                1, "c_iface1", sock_c, addr_s, 10_000_000, 10_000_000, 1400, now,
            )
            .unwrap();
        server
            .add_subpath(
                1, "s_iface1", sock_s, addr_c, 10_000_000, 10_000_000, 1400, now,
            )
            .unwrap();

        assert_eq!(client.state(), &SessionState::Idle);
        assert_eq!(server.state(), &SessionState::Idle);

        // 1. Client initiates handshake
        client.initiate_handshake(now).unwrap();
        assert!(matches!(client.state(), SessionState::Connecting { .. }));

        // Client egress -> socket
        client.poll_cycle(now);

        // Server ingress <- socket
        server.poll_cycle(now + 2_000_000);
        assert!(server.state().is_active());

        // Client ingress <- server ACK
        client.poll_cycle(now + 4_000_000);
        assert!(client.state().is_active());
        assert!(client.negotiated_capabilities().is_some());

        // 2. Exchange application payload
        let app_data = b"Hello Multipath IFA!".to_vec();
        client
            .send_payload(
                FlowSliceClass::MissionCritical,
                app_data.clone(),
                None,
                now + 5_000_000,
            )
            .unwrap();

        client.poll_cycle(now + 5_000_000);
        server.poll_cycle(now + 7_000_000);

        let received = server.recv_payload().expect("Should receive payload");
        assert_eq!(received.payload, app_data);

        // 3. Graceful termination
        client
            .initiate_graceful_close("normal_closure", now + 10_000_000)
            .unwrap();
        assert!(matches!(client.state(), SessionState::Draining { .. }));

        client.poll_cycle(now + 10_000_000);
        server.poll_cycle(now + 12_000_000);
        client.poll_cycle(now + 14_000_000);

        assert!(client.state().is_closed());
    }

    #[test]
    fn test_subpath_keepalive_and_dead_path_detection() {
        let now = 20_000_000_000u64;

        let sock_c = Arc::new(AsyncUdpSocket::bind("127.0.0.1:0").unwrap());
        let _addr_c = sock_c.local_addr().unwrap();
        let dummy_peer: SocketAddr = "127.0.0.1:45678".parse().unwrap();

        let cfg = MultipathSessionConfig {
            session_id: 777,
            is_server: false,
            local_capabilities: SessionCapabilities {
                keepalive_interval_ns: 1_000_000_000, // 1s
                inactivity_timeout_ns: 3_000_000_000, // 3s
                ..Default::default()
            },
            max_missed_keepalives: 2,
            ..Default::default()
        };

        let mut controller = MultipathSessionController::new(cfg);
        controller
            .add_subpath(
                1,
                "test_iface",
                sock_c,
                dummy_peer,
                10_000_000,
                5_000_000,
                1400,
                now,
            )
            .unwrap();

        // Artificially transition to active
        controller.state = SessionState::Active {
            established_ns: now,
        };

        // At t = now + 1.1s: should dispatch KeepAlivePing
        let report1 = controller.poll_cycle(now + 1_100_000_000);
        assert_eq!(report1.keepalives_dispatched, 1);
        let s_state = controller.subpath_state(1).unwrap();
        assert_eq!(s_state.pings_sent, 1);
        assert_eq!(s_state.status, SubpathHealthStatus::Healthy);

        // At t = now + 3.5s (no recv): should become Degraded/Stalled
        controller.poll_cycle(now + 3_500_000_000);
        let s_state = controller.subpath_state(1).unwrap();
        assert!(
            s_state.status == SubpathHealthStatus::Stalled
                || s_state.status == SubpathHealthStatus::Degraded
        );

        // At t = now + 7s: exceeded missed keepalives -> Dead
        controller.poll_cycle(now + 7_000_000_000);
        let s_state = controller.subpath_state(1).unwrap();
        assert_eq!(s_state.status, SubpathHealthStatus::Dead);
        assert!(!controller.egress_gateway.interfaces.get(&1).unwrap().active);
    }

    #[test]
    fn test_session_observability_and_benchmark() {
        let b = run_multipath_session_controller_benchmark();
        assert_eq!(b.session_id, 1001);
        assert!(b.total_app_packets_sent >= 10);
        assert!(b.is_gracefully_closed);

        let cfg = MultipathSessionConfig::default();
        let controller = MultipathSessionController::new(cfg);
        let metrics = controller.export_prometheus_metrics();
        assert!(metrics.contains("ifa_session_state"));
        assert!(metrics.contains("ifa_session_active_subpaths"));

        let audit = controller.generate_json_audit_trail();
        assert!(audit.contains("\"session_id\":1"));
        assert!(audit.contains("\"state\":\"Idle\""));
    }
}

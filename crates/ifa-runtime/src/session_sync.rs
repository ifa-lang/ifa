//! Multi-node session state synchronization and transparent datagram stream migration.
//!
//! This module implements the **IFA Session Synchronization Protocol (ISSP)** for
//! distributed MASQUE gateway clusters. It provides:
//!
//! - **Session State Snapshot** — serializable, opaque, versioned snapshot of a live
//!   datagram tunnel session (flow hash, sequence counters, AQM state, FEC context, key
//!   epoch, rate-limiter token bucket).
//! - **Gossip-based State Distribution** — lightweight CRC32-guarded gossip messages
//!   exchanged over a dedicated control UDP channel to replicate snapshots to peer nodes.
//! - **Transparent Migration** — when a primary node becomes unreachable, any peer
//!   holding a fresh enough snapshot can resume the session without renegotiation,
//!   providing continuity of sequence counters and crypto epoch to the remote endpoint.
//! - **Fencing & Epoch Guard** — a monotonic `migration_epoch` counter prevents split-brain
//!   double-serving of the same session on two nodes simultaneously.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum age of a session snapshot before it is considered stale for migration.
pub const SNAPSHOT_MAX_AGE: Duration = Duration::from_secs(5);

/// Maximum number of peer nodes tracked per local node.
pub const MAX_PEER_NODES: usize = 32;

/// Maximum number of live sessions per node.
pub const MAX_SESSIONS: usize = 1024;

/// Gossip message magic tag for ISSP frames.
pub const ISSP_MAGIC: u32 = 0x4953_5350; // 'ISSP'

/// ISSP gossip wire protocol version 1 (unencrypted with CRC32).
pub const ISSP_VERSION_V1: u32 = 1;

/// ISSP gossip wire protocol version 2 (ChaCha20-Poly1305 AEAD encrypted with PSK).
pub const ISSP_VERSION_V2_ENCRYPTED: u32 = 2;

/// Wire size of a serialised plaintext `GossipFrame` (v1) in bytes.
pub const GOSSIP_FRAME_SIZE: usize = 112;

/// Wire size of a serialised encrypted `SecureGossipFrame` (v2) in bytes.
pub const SECURE_GOSSIP_FRAME_SIZE: usize = 136;

/// Capsule header magic tag for ISSP capsules transmitted inside RFC 9297 HTTP tunnels.
pub const ISSP_CAPSULE_MAGIC: u32 = 0x4953_4350; // 'ISCP'

/// Wire size of the ISSP capsule container header in bytes.
pub const ISSP_CAPSULE_HEADER_SIZE: usize = 12;

/// State dump magic tag for ISSP cluster registry snapshots.
pub const ISSP_DUMP_MAGIC: u32 = 0x4953_4450; // 'ISDP'

/// State dump format version 1.
pub const ISSP_DUMP_VERSION_V1: u32 = 1;

/// Header size of an ISSP state dump file.
pub const ISSP_DUMP_HEADER_SIZE: usize = 32;

/// Magic tag for ISSP session packets ('ISSH').
pub const ISSP_SESSION_MAGIC: u32 = 0x4953_5348;

/// Magic tag for encapsulated ISSP subpath packets ('ISPK').
pub const ISSP_SUBPATH_PACKET_MAGIC: u32 = 0x4953_504b;

/// Wire size of an uncompressed session header in bytes.
pub const ISSP_SESSION_HEADER_UNCOMPRESSED_SIZE: usize = 50;

/// Wire flag indicating packet payload is AEAD encrypted.
pub const ISSP_PKT_FLAG_ENCRYPTED: u16 = 0x0001;

/// Wire flag indicating session header is compressed.
pub const ISSP_PKT_FLAG_COMPRESSED: u16 = 0x0002;

/// Wire flag indicating full header refresh frame.
pub const ISSP_PKT_FLAG_FULL_HEADER: u16 = 0x0004;

// ---------------------------------------------------------------------------
// Session identifier
// ---------------------------------------------------------------------------

/// Globally unique identifier for a tunnel session, derived from the 5-tuple
/// flow hash and the originating node ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId {
    /// 64-bit flow hash (src_ip XOR dst_ip XOR ports XOR proto).
    pub flow_hash: u64,
    /// Node that originally created this session.
    pub origin_node: u32,
    /// Session creation nonce (randomised to prevent collisions on hash).
    pub nonce: u32,
}

impl SessionId {
    /// Construct a new session ID.
    pub fn new(flow_hash: u64, origin_node: u32, nonce: u32) -> Self {
        Self {
            flow_hash,
            origin_node,
            nonce,
        }
    }

    /// Encode as a compact 16-byte array for wire transmission.
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&self.flow_hash.to_be_bytes());
        b[8..12].copy_from_slice(&self.origin_node.to_be_bytes());
        b[12..16].copy_from_slice(&self.nonce.to_be_bytes());
        b
    }

    /// Decode from a compact 16-byte array.
    pub fn from_bytes(b: &[u8; 16]) -> Self {
        let flow_hash = u64::from_be_bytes(b[..8].try_into().unwrap());
        let origin_node = u32::from_be_bytes(b[8..12].try_into().unwrap());
        let nonce = u32::from_be_bytes(b[12..16].try_into().unwrap());
        Self {
            flow_hash,
            origin_node,
            nonce,
        }
    }

    /// Format as canonical string "01a2b3c4d5e6f708:0001:0042".
    pub fn to_canonical_string(&self) -> String {
        format!(
            "{:016x}:{:04x}:{:04x}",
            self.flow_hash, self.origin_node, self.nonce
        )
    }

    /// Parse from canonical format ("flow_hash:origin_node:nonce") or hex flow hash.
    pub fn parse_str(s: &str) -> Result<Self, String> {
        let trimmed = s.trim();
        let parts: Vec<&str> = trimmed.split(':').collect();
        if parts.len() == 3 {
            let flow_str = parts[0].strip_prefix("0x").unwrap_or(parts[0]);
            let node_str = parts[1].strip_prefix("0x").unwrap_or(parts[1]);
            let nonce_str = parts[2].strip_prefix("0x").unwrap_or(parts[2]);

            let flow_hash = u64::from_str_radix(flow_str, 16)
                .map_err(|e| format!("invalid flow_hash hex '{}': {}", flow_str, e))?;
            let origin_node = u32::from_str_radix(node_str, 16)
                .or_else(|_| node_str.parse::<u32>())
                .map_err(|e| format!("invalid origin_node '{}': {}", node_str, e))?;
            let nonce = u32::from_str_radix(nonce_str, 16)
                .or_else(|_| nonce_str.parse::<u32>())
                .map_err(|e| format!("invalid nonce '{}': {}", nonce_str, e))?;

            Ok(Self::new(flow_hash, origin_node, nonce))
        } else if parts.len() == 1 {
            let s_clean = parts[0].strip_prefix("0x").unwrap_or(parts[0]);
            let flow_hash = u64::from_str_radix(s_clean, 16)
                .or_else(|_| s_clean.parse::<u64>())
                .map_err(|e| format!("invalid flow hash identifier '{}': {}", s, e))?;
            Ok(Self::new(flow_hash, 0, 0))
        } else {
            Err(format!(
                "invalid session format '{}' (expected <flow_hash>:<node>:<nonce>)",
                s
            ))
        }
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:016x}:{:04x}:{:04x}",
            self.flow_hash, self.origin_node, self.nonce
        )
    }
}

// ---------------------------------------------------------------------------
// Session State Snapshot
// ---------------------------------------------------------------------------

/// Datagram-stream state captured at a point in time for replication or migration.
///
/// All fields are `Copy` / primitive so the snapshot can be serialised cheaply
/// without heap allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionSnapshot {
    /// Session identifier.
    pub id: SessionId,

    /// Monotonic migration epoch.  Incremented by one each time ownership of
    /// this session is transferred.  A receiving node MUST reject any snapshot
    /// with `migration_epoch` ≤ its locally recorded epoch for this session.
    pub migration_epoch: u64,

    // --- Sequence / ordering state ---
    /// Highest sequence number sent by the local side.
    pub tx_seq: u64,
    /// Highest contiguous sequence number received (for reorder buffer).
    pub rx_seq_high: u64,
    /// Reorder window bitmap (64 slots).  Bit i is set if seq rx_seq_high - i
    /// was already received.
    pub reorder_bitmap: u64,

    // --- Rate-limiter token bucket state ---
    /// Current token count (scaled ×1000 to avoid float).
    pub token_bucket_scaled: u64,
    /// Configured token refill rate in tokens/ms (scaled ×1000).
    pub token_rate_scaled: u64,

    // --- AQM / CoDel sojourn state ---
    /// CoDel target sojourn (nanoseconds).
    pub codel_target_ns: u64,
    /// CoDel interval (nanoseconds).
    pub codel_interval_ns: u64,
    /// Number of consecutive CoDel drop intervals.
    pub codel_drop_count: u32,

    // --- FEC context ---
    /// Current FEC block index.
    pub fec_block_idx: u32,
    /// Number of source packets in the current FEC block.
    pub fec_src_count: u8,
    /// Number of repair packets already emitted in the current FEC block.
    pub fec_repair_count: u8,

    // --- Crypto epoch ---
    /// Current key epoch identifier (matches HPKE/PQC key rotation counter).
    pub crypto_epoch: u32,

    // --- Timestamp ---
    /// Wall-clock snapshot capture time as Unix seconds (for staleness check).
    pub captured_unix_secs: u64,
}

impl SessionSnapshot {
    /// Create a zeroed snapshot for a new session.
    pub fn new(id: SessionId, crypto_epoch: u32, captured_unix_secs: u64) -> Self {
        Self {
            id,
            migration_epoch: 0,
            tx_seq: 0,
            rx_seq_high: 0,
            reorder_bitmap: 0,
            token_bucket_scaled: 1_000_000,
            token_rate_scaled: 10_000,
            codel_target_ns: 5_000_000,
            codel_interval_ns: 100_000_000,
            codel_drop_count: 0,
            fec_block_idx: 0,
            fec_src_count: 0,
            fec_repair_count: 0,
            crypto_epoch,
            captured_unix_secs,
        }
    }

    /// Serialise into a 96-byte wire buffer (little-endian).
    pub fn to_wire(&self) -> [u8; 96] {
        let mut buf = [0u8; 96];
        let id_b = self.id.to_bytes();
        buf[0..16].copy_from_slice(&id_b);
        buf[16..24].copy_from_slice(&self.migration_epoch.to_le_bytes());
        buf[24..32].copy_from_slice(&self.tx_seq.to_le_bytes());
        buf[32..40].copy_from_slice(&self.rx_seq_high.to_le_bytes());
        buf[40..48].copy_from_slice(&self.reorder_bitmap.to_le_bytes());
        buf[48..56].copy_from_slice(&self.token_bucket_scaled.to_le_bytes());
        buf[56..64].copy_from_slice(&self.token_rate_scaled.to_le_bytes());
        buf[64..68].copy_from_slice(&(self.codel_target_ns as u32).to_le_bytes());
        buf[68..72].copy_from_slice(&(self.codel_interval_ns as u32).to_le_bytes());
        buf[72..80].copy_from_slice(&self.captured_unix_secs.to_le_bytes());
        let mut misc = [0u8; 16];
        misc[0..4].copy_from_slice(&self.codel_drop_count.to_le_bytes());
        misc[4..8].copy_from_slice(&self.fec_block_idx.to_le_bytes());
        misc[8] = self.fec_src_count;
        misc[9] = self.fec_repair_count;
        misc[10..14].copy_from_slice(&self.crypto_epoch.to_le_bytes());
        buf[80..96].copy_from_slice(&misc);
        buf
    }

    /// Deserialise from a 96-byte wire buffer.
    pub fn from_wire(buf: &[u8; 96]) -> Self {
        let id = SessionId::from_bytes(buf[0..16].try_into().unwrap());
        let migration_epoch = u64::from_le_bytes(buf[16..24].try_into().unwrap());
        let tx_seq = u64::from_le_bytes(buf[24..32].try_into().unwrap());
        let rx_seq_high = u64::from_le_bytes(buf[32..40].try_into().unwrap());
        let reorder_bitmap = u64::from_le_bytes(buf[40..48].try_into().unwrap());
        let token_bucket_scaled = u64::from_le_bytes(buf[48..56].try_into().unwrap());
        let token_rate_scaled = u64::from_le_bytes(buf[56..64].try_into().unwrap());
        let codel_target_ns = u32::from_le_bytes(buf[64..68].try_into().unwrap()) as u64;
        let codel_interval_ns = u32::from_le_bytes(buf[68..72].try_into().unwrap()) as u64;
        let captured_unix_secs = u64::from_le_bytes(buf[72..80].try_into().unwrap());
        let misc = &buf[80..96];
        let codel_drop_count = u32::from_le_bytes(misc[0..4].try_into().unwrap());
        let fec_block_idx = u32::from_le_bytes(misc[4..8].try_into().unwrap());
        let fec_src_count = misc[8];
        let fec_repair_count = misc[9];
        let crypto_epoch = u32::from_le_bytes(misc[10..14].try_into().unwrap());
        Self {
            id,
            migration_epoch,
            tx_seq,
            rx_seq_high,
            reorder_bitmap,
            token_bucket_scaled,
            token_rate_scaled,
            codel_target_ns,
            codel_interval_ns,
            codel_drop_count,
            fec_block_idx,
            fec_src_count,
            fec_repair_count,
            crypto_epoch,
            captured_unix_secs,
        }
    }
}

// ---------------------------------------------------------------------------
// Gossip wire frame
// ---------------------------------------------------------------------------

/// ISSP gossip frame transmitted between nodes over the control UDP channel.
///
/// Wire layout (total = **112 bytes**):
/// ```text
///  0-  3  magic   = ISSP_MAGIC (0x49535350)
///  4-  7  version = 1
///  8- 11  sender_node_id
/// 12- 15  crc32   (computed over snapshot bytes at [16..112])
/// 16-111  snapshot (96 bytes)
/// ```
#[derive(Debug, Clone, Copy)]
pub struct GossipFrame {
    pub sender_node_id: u32,
    pub snapshot: SessionSnapshot,
}

impl GossipFrame {
    /// Encode to a 112-byte wire buffer with CRC32 integrity protection.
    pub fn encode(&self) -> [u8; GOSSIP_FRAME_SIZE] {
        let mut buf = [0u8; GOSSIP_FRAME_SIZE];
        buf[0..4].copy_from_slice(&ISSP_MAGIC.to_be_bytes());
        buf[4..8].copy_from_slice(&1u32.to_le_bytes()); // version = 1
        buf[8..12].copy_from_slice(&self.sender_node_id.to_le_bytes());
        // reserve [12..16] for CRC32 — computed after snapshot is written
        let snap = self.snapshot.to_wire();
        buf[16..112].copy_from_slice(&snap);
        let crc = crc32_ieee(&buf[16..112]);
        buf[12..16].copy_from_slice(&crc.to_le_bytes());
        buf
    }

    /// Decode and validate a 112-byte wire buffer.  Returns `None` on magic or
    /// CRC32 mismatch.
    pub fn decode(raw: &[u8; GOSSIP_FRAME_SIZE]) -> Option<Self> {
        let magic = u32::from_be_bytes(raw[0..4].try_into().unwrap());
        if magic != ISSP_MAGIC {
            return None;
        }
        let stored_crc = u32::from_le_bytes(raw[12..16].try_into().unwrap());
        let computed_crc = crc32_ieee(&raw[16..112]);
        if stored_crc != computed_crc {
            return None;
        }
        let sender_node_id = u32::from_le_bytes(raw[8..12].try_into().unwrap());
        let snap_buf: &[u8; 96] = raw[16..112].try_into().unwrap();
        let snapshot = SessionSnapshot::from_wire(snap_buf);
        Some(Self {
            sender_node_id,
            snapshot,
        })
    }
}

/// Software CRC32 (IEEE polynomial) without external dependency.
fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        let idx = ((crc ^ (byte as u32)) & 0xFF) as usize;
        crc = CRC32_TABLE[idx] ^ (crc >> 8);
    }
    !crc
}

/// Pre-computed CRC32/IEEE look-up table.
static CRC32_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            if c & 1 != 0 {
                c = 0xEDB8_8320 ^ (c >> 1);
            } else {
                c >>= 1;
            }
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
};

// ---------------------------------------------------------------------------
// RFC 8439 Deterministic Zero-GC ChaCha20-Poly1305 Engine
// ---------------------------------------------------------------------------

#[inline(always)]
fn chacha20_quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut state = [
        0x61707865,
        0x3320646e,
        0x79622d32,
        0x6b206574,
        u32::from_le_bytes(key[0..4].try_into().unwrap()),
        u32::from_le_bytes(key[4..8].try_into().unwrap()),
        u32::from_le_bytes(key[8..12].try_into().unwrap()),
        u32::from_le_bytes(key[12..16].try_into().unwrap()),
        u32::from_le_bytes(key[16..20].try_into().unwrap()),
        u32::from_le_bytes(key[20..24].try_into().unwrap()),
        u32::from_le_bytes(key[24..28].try_into().unwrap()),
        u32::from_le_bytes(key[28..32].try_into().unwrap()),
        counter,
        u32::from_le_bytes(nonce[0..4].try_into().unwrap()),
        u32::from_le_bytes(nonce[4..8].try_into().unwrap()),
        u32::from_le_bytes(nonce[8..12].try_into().unwrap()),
    ];

    let initial = state;

    for _ in 0..10 {
        chacha20_quarter_round(&mut state, 0, 4, 8, 12);
        chacha20_quarter_round(&mut state, 1, 5, 9, 13);
        chacha20_quarter_round(&mut state, 2, 6, 10, 14);
        chacha20_quarter_round(&mut state, 3, 7, 11, 15);

        chacha20_quarter_round(&mut state, 0, 5, 10, 15);
        chacha20_quarter_round(&mut state, 1, 6, 11, 12);
        chacha20_quarter_round(&mut state, 2, 7, 8, 13);
        chacha20_quarter_round(&mut state, 3, 4, 9, 14);
    }

    let mut out = [0u8; 64];
    for i in 0..16 {
        let val = state[i].wrapping_add(initial[i]);
        out[i * 4..(i + 1) * 4].copy_from_slice(&val.to_le_bytes());
    }
    out
}

fn chacha20_xor_slice(key: &[u8; 32], nonce: &[u8; 12], counter: u32, data: &mut [u8]) {
    let mut curr_counter = counter;
    for chunk in data.chunks_mut(64) {
        let block = chacha20_block(key, curr_counter, nonce);
        for (b, k) in chunk.iter_mut().zip(block.iter()) {
            *b ^= *k;
        }
        curr_counter = curr_counter.wrapping_add(1);
    }
}

struct Poly1305Accumulator {
    r0: u64,
    r1: u64,
    s0: u64,
    s1: u64,
    h0: u128,
    h1: u128,
    h2: u128,
}

impl Poly1305Accumulator {
    fn new(key: &[u8; 32]) -> Self {
        let r0 = u64::from_le_bytes(key[0..8].try_into().unwrap()) & 0x0ffffffc0fffffff;
        let r1 = u64::from_le_bytes(key[8..16].try_into().unwrap()) & 0x0ffffffc0ffffffc;
        let s0 = u64::from_le_bytes(key[16..24].try_into().unwrap());
        let s1 = u64::from_le_bytes(key[24..32].try_into().unwrap());
        Self {
            r0,
            r1,
            s0,
            s1,
            h0: 0,
            h1: 0,
            h2: 0,
        }
    }

    fn update_chunk(&mut self, chunk: &[u8]) {
        let mut block = [0u8; 17];
        block[..chunk.len()].copy_from_slice(chunk);
        block[chunk.len()] = 0x01;

        let n0 = u128::from_le_bytes(block[0..16].try_into().unwrap());
        let n1 = block[16] as u128;

        self.h0 += n0 & 0xffffffffffffffff;
        self.h1 += n0 >> 64;
        self.h2 += n1;

        let d0 = self.h0 * (self.r0 as u128);
        let d1 = self.h0 * (self.r1 as u128) + self.h1 * (self.r0 as u128);
        let d2 = self.h1 * (self.r1 as u128) + self.h2 * (self.r0 as u128) * 5;
        let d3 = self.h2 * (self.r1 as u128) * 5;

        let mut c = d0;
        self.h0 = c & 0xffffffffffffffff;
        c = (c >> 64) + d1;
        self.h1 = c & 0xffffffffffffffff;
        c = (c >> 64) + d2;
        self.h2 = c & 0x03;
        let carry = (c >> 2) + d3;
        let c_mod = carry * 5;
        self.h0 += c_mod;
        if self.h0 > 0xffffffffffffffff {
            let carry_h0 = self.h0 >> 64;
            self.h0 &= 0xffffffffffffffff;
            self.h1 += carry_h0;
            if self.h1 > 0xffffffffffffffff {
                self.h2 += self.h1 >> 64;
                self.h1 &= 0xffffffffffffffff;
            }
        }
    }

    fn update(&mut self, data: &[u8]) {
        for chunk in data.chunks(16) {
            self.update_chunk(chunk);
        }
    }

    fn update_padded_16(&mut self, data: &[u8]) {
        for chunk in data.chunks(16) {
            if chunk.len() == 16 {
                self.update_chunk(chunk);
            } else {
                let mut padded = [0u8; 16];
                padded[..chunk.len()].copy_from_slice(chunk);
                self.update_chunk(&padded);
            }
        }
    }

    fn finalize(self) -> [u8; 16] {
        let total_lo = self.h0 | (self.h1 << 64);
        let total_hi = self.h2 as u64;

        let (sub_lo, borrow) = total_lo.overflowing_sub(0xfffffffffffffffffffffffffffffffb);
        let sub_hi = total_hi.wrapping_sub(3).wrapping_sub(borrow as u64);

        let res_lo = if sub_hi == 0 { sub_lo } else { total_lo };

        let s = (self.s0 as u128) | ((self.s1 as u128) << 64);
        let out = res_lo.wrapping_add(s);
        out.to_le_bytes()
    }
}

fn poly1305_aead_tag(poly_key: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut acc = Poly1305Accumulator::new(poly_key);
    acc.update_padded_16(aad);
    acc.update_padded_16(ciphertext);
    let mut lengths = [0u8; 16];
    lengths[0..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    lengths[8..16].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    acc.update(&lengths);
    acc.finalize()
}

/// Constant-time slice comparison to prevent timing side-channels.
#[inline]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut res = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        res |= x ^ y;
    }
    res == 0
}

// ---------------------------------------------------------------------------
// Cluster Authentication Key (PSK)
// ---------------------------------------------------------------------------

/// 256-bit Pre-Shared Key (PSK) for authenticating cluster members and
/// encrypting ISSP gossip frames via ChaCha20-Poly1305.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ClusterPsk([u8; 32]);

impl std::fmt::Debug for ClusterPsk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ClusterPsk(***REDACTED***)")
    }
}

impl ClusterPsk {
    /// Construct a cluster key directly from 32 bytes of raw cryptographic material.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Access the underlying 32-byte key slice.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Deterministically derive a 256-bit PSK from a shared passphrase or cluster secret token.
    pub fn from_passphrase(passphrase: &[u8]) -> Self {
        let mut state = [0u8; 32];
        let salt = b"IFA-ISSP-CLUSTER-AUTH-PSK-v2\0\0\0\0";
        state.copy_from_slice(salt);
        for (i, &b) in passphrase.iter().enumerate() {
            state[i % 32] ^= b;
        }
        let nonce = [
            0x50, 0x53, 0x4b, 0x5f, 0x49, 0x53, 0x53, 0x50, 0x5f, 0x4b, 0x44, 0x46,
        ]; // "PSK_ISSP_KDF"
        let block = chacha20_block(&state, 1, &nonce);
        let mut key = [0u8; 32];
        key.copy_from_slice(&block[0..32]);
        Self(key)
    }
}

// ---------------------------------------------------------------------------
// Secure Gossip Frame (v2)
// ---------------------------------------------------------------------------

/// Encrypted, authenticated gossip frame for ISSP v2 (ChaCha20-Poly1305 AEAD).
///
/// Wire layout (total = **136 bytes**):
/// ```text
///   0.. 4   magic = ISSP_MAGIC (0x49535350)
///   4.. 8   version = ISSP_VERSION_V2_ENCRYPTED (2)
///   8..12   sender_node_id (u32 LE)
///  12..20   nonce_seq (u64 LE, monotonic anti-replay counter)
///  20..24   reserved = 0 (u32 LE)
///  24..40   auth_tag (16 bytes, Poly1305 MAC)
///  40..136  ciphertext (96 bytes, ChaCha20 encrypted SessionSnapshot)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecureGossipFrame {
    pub sender_node_id: u32,
    pub nonce_seq: u64,
    pub snapshot: SessionSnapshot,
}

impl SecureGossipFrame {
    /// Encode and encrypt into a 136-byte wire buffer using ChaCha20-Poly1305 AEAD.
    pub fn encode(&self, psk: &ClusterPsk) -> [u8; SECURE_GOSSIP_FRAME_SIZE] {
        let mut buf = [0u8; SECURE_GOSSIP_FRAME_SIZE];
        buf[0..4].copy_from_slice(&ISSP_MAGIC.to_be_bytes());
        buf[4..8].copy_from_slice(&ISSP_VERSION_V2_ENCRYPTED.to_le_bytes());
        buf[8..12].copy_from_slice(&self.sender_node_id.to_le_bytes());
        buf[12..20].copy_from_slice(&self.nonce_seq.to_le_bytes());
        buf[20..24].fill(0);

        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&self.sender_node_id.to_le_bytes());
        nonce[4..12].copy_from_slice(&self.nonce_seq.to_le_bytes());

        let snap_bytes = self.snapshot.to_wire();
        buf[40..136].copy_from_slice(&snap_bytes);

        chacha20_xor_slice(psk.as_bytes(), &nonce, 1, &mut buf[40..136]);

        let poly_block = chacha20_block(psk.as_bytes(), 0, &nonce);
        let mut poly_key = [0u8; 32];
        poly_key.copy_from_slice(&poly_block[0..32]);

        let tag = poly1305_aead_tag(&poly_key, &buf[0..24], &buf[40..136]);
        buf[24..40].copy_from_slice(&tag);

        buf
    }

    /// Decode and authenticate a 136-byte wire buffer using ChaCha20-Poly1305 AEAD.
    pub fn decode(
        raw: &[u8; SECURE_GOSSIP_FRAME_SIZE],
        psk: &ClusterPsk,
    ) -> Result<Self, SecurityError> {
        let magic = u32::from_be_bytes(raw[0..4].try_into().unwrap());
        if magic != ISSP_MAGIC {
            return Err(SecurityError::BadMagic);
        }
        let version = u32::from_le_bytes(raw[4..8].try_into().unwrap());
        if version != ISSP_VERSION_V2_ENCRYPTED {
            return Err(SecurityError::UnsupportedVersion(version));
        }

        let sender_node_id = u32::from_le_bytes(raw[8..12].try_into().unwrap());
        let nonce_seq = u64::from_le_bytes(raw[12..20].try_into().unwrap());

        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&raw[8..12]);
        nonce[4..12].copy_from_slice(&raw[12..20]);

        let poly_block = chacha20_block(psk.as_bytes(), 0, &nonce);
        let mut poly_key = [0u8; 32];
        poly_key.copy_from_slice(&poly_block[0..32]);

        let expected_tag = poly1305_aead_tag(&poly_key, &raw[0..24], &raw[40..136]);
        let stored_tag: &[u8; 16] = raw[24..40].try_into().unwrap();

        if !constant_time_eq(&expected_tag, stored_tag) {
            return Err(SecurityError::AuthenticationFailed);
        }

        let mut snap_buf = [0u8; 96];
        snap_buf.copy_from_slice(&raw[40..136]);
        chacha20_xor_slice(psk.as_bytes(), &nonce, 1, &mut snap_buf);

        let snapshot = SessionSnapshot::from_wire(&snap_buf);
        Ok(Self {
            sender_node_id,
            nonce_seq,
            snapshot,
        })
    }
}

// ---------------------------------------------------------------------------
// ISSP Capsule Transport Frame
// ---------------------------------------------------------------------------

/// ISSP Capsule wire container for encapsulating gossip frames inside RFC 9297 HTTP tunnels.
///
/// Contains either a plaintext v1 GossipFrame (112 bytes) or an AEAD-encrypted v2
/// SecureGossipFrame (136 bytes), prefixed by an ISSP capsule subheader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsspCapsule {
    /// Capsule wire protocol version (`ISSP_VERSION_V1` or `ISSP_VERSION_V2_ENCRYPTED`).
    pub version: u32,
    /// Identifier of the gateway node originating or transmitting this capsule.
    pub origin_node_id: u32,
    /// Wire payload containing the gossip frame.
    pub payload: Vec<u8>,
}

impl IsspCapsule {
    /// Create an ISSP capsule wrapping a plaintext v1 GossipFrame.
    pub fn from_gossip_frame(frame: &GossipFrame) -> Self {
        Self {
            version: ISSP_VERSION_V1,
            origin_node_id: frame.sender_node_id,
            payload: frame.encode().to_vec(),
        }
    }

    /// Create an ISSP capsule wrapping an AEAD-encrypted v2 SecureGossipFrame.
    pub fn from_secure_frame(
        origin_node_id: u32,
        frame_bytes: &[u8; SECURE_GOSSIP_FRAME_SIZE],
    ) -> Self {
        Self {
            version: ISSP_VERSION_V2_ENCRYPTED,
            origin_node_id,
            payload: frame_bytes.to_vec(),
        }
    }

    /// Encode into a compact binary representation for transport within an RFC 9297 capsule.
    /// Layout:
    ///   0..4  : magic (0x49534350)
    ///   4..8  : version (u32 LE)
    ///   8..12 : origin_node_id (u32 LE)
    ///   12..  : frame payload (112 or 136 bytes)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(ISSP_CAPSULE_HEADER_SIZE + self.payload.len());
        buf.extend_from_slice(&ISSP_CAPSULE_MAGIC.to_be_bytes());
        buf.extend_from_slice(&self.version.to_le_bytes());
        buf.extend_from_slice(&self.origin_node_id.to_le_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Decode from raw RFC 9297 capsule payload bytes.
    pub fn from_bytes(slice: &[u8]) -> Result<Self, SyncError> {
        if slice.len() < ISSP_CAPSULE_HEADER_SIZE {
            return Err(SyncError::InvalidCapsuleLength(slice.len()));
        }
        let magic = u32::from_be_bytes(slice[0..4].try_into().unwrap());
        if magic != ISSP_CAPSULE_MAGIC {
            return Err(SyncError::BadCapsuleMagic);
        }
        let version = u32::from_le_bytes(slice[4..8].try_into().unwrap());
        let origin_node_id = u32::from_le_bytes(slice[8..12].try_into().unwrap());
        let payload = slice[ISSP_CAPSULE_HEADER_SIZE..].to_vec();
        Ok(Self {
            version,
            origin_node_id,
            payload,
        })
    }
}

// ---------------------------------------------------------------------------
// Dynamic Multipath Routing & Automatic Heartbeat Failover
// ---------------------------------------------------------------------------

/// ISSP keep-alive heartbeat probe magic tag ('ISHP').
pub const ISSP_HEARTBEAT_MAGIC: u32 = 0x4953_4850;

/// Wire size of an ISSP heartbeat probe frame in bytes.
pub const ISSP_HEARTBEAT_SIZE: usize = 40;

/// Operational state of a dynamic transport path in an ISSP multipath route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsspPathState {
    /// Actively carrying traffic and serving sessions.
    Active,
    /// Fully synchronized standby path ready for instantaneous failover.
    Standby,
    /// Experiencing elevated packet loss or latency jitter, but still functional.
    Degraded,
    /// In progressive probation phase following recovery, receiving ramping traffic.
    Probation,
    /// Heartbeat timed out, link severed, or suppressed by flap damping; excluded from routing.
    Failed,
}

impl IsspPathState {
    /// Whether this path is operational and eligible to carry datagram sessions.
    pub fn is_usable(&self) -> bool {
        matches!(self, Self::Active | Self::Degraded | Self::Probation)
    }
}

/// Dynamic telemetry and health metrics tracked per ISSP multipath link.
#[derive(Debug, Clone, PartialEq)]
pub struct IsspPathMetrics {
    /// Smoothed round-trip time in microseconds (EWMA, RFC 6298 / RFC 9002).
    pub smoothed_rtt_us: u64,
    /// Round-trip time variation / jitter in microseconds.
    pub rtt_variance_us: u64,
    /// Estimated packet loss rate in parts per million (e.g. 10_000 = 1.0%).
    pub loss_rate_ppm: u32,
    /// Instantaneous jitter in microseconds.
    pub jitter_us: u64,
    /// Monotonic wall-clock timestamp of last dispatched heartbeat probe in unix ms.
    pub last_heartbeat_sent_unix_ms: u64,
    /// Monotonic wall-clock timestamp of last received heartbeat reply/pong in unix ms.
    pub last_heartbeat_recv_unix_ms: u64,
    /// Number of consecutive missed heartbeat probes without reply.
    pub consecutive_missed_heartbeats: u32,
    /// Total heartbeat ping probes dispatched.
    pub total_heartbeats_sent: u64,
    /// Total heartbeat pong replies received.
    pub total_heartbeats_received: u64,
    /// Cumulative count of data frames transmitted over this path.
    pub total_frames_sent: u64,
    /// Cumulative count of data frames received over this path.
    pub total_frames_received: u64,
    /// Cumulative bytes transmitted over this path.
    pub total_bytes_sent: u64,
    /// Cumulative bytes received over this path.
    pub total_bytes_received: u64,
}

impl Default for IsspPathMetrics {
    fn default() -> Self {
        Self {
            smoothed_rtt_us: 10_000,
            rtt_variance_us: 2_000,
            loss_rate_ppm: 0,
            jitter_us: 1_000,
            last_heartbeat_sent_unix_ms: 0,
            last_heartbeat_recv_unix_ms: 0,
            consecutive_missed_heartbeats: 0,
            total_heartbeats_sent: 0,
            total_heartbeats_received: 0,
            total_frames_sent: 0,
            total_frames_received: 0,
            total_bytes_sent: 0,
            total_bytes_received: 0,
        }
    }
}

impl IsspPathMetrics {
    /// Calculate composite path quality score (higher is better).
    pub fn quality_score(&self, state: IsspPathState, weight: u32) -> f64 {
        let state_mult = match state {
            IsspPathState::Active => 1.0,
            IsspPathState::Degraded => 0.35,
            IsspPathState::Probation => 0.40,
            IsspPathState::Standby => 0.1,
            IsspPathState::Failed => 0.0,
        };
        if state_mult == 0.0 {
            return 0.0;
        }

        let rtt_ms = (self.smoothed_rtt_us as f64) / 1000.0;
        let latency_factor = 1.0 / (1.0 + (rtt_ms / 50.0));
        let loss_fraction = (self.loss_rate_ppm as f64) / 1_000_000.0;
        let loss_factor = (1.0 - loss_fraction).max(0.01);

        (weight.max(1) as f64) * latency_factor * loss_factor * state_mult
    }

    /// Record a round-trip time measurement from a heartbeat pong response.
    pub fn update_rtt(&mut self, sample_rtt_us: u64) {
        if self.smoothed_rtt_us == 0 {
            self.smoothed_rtt_us = sample_rtt_us;
            self.rtt_variance_us = sample_rtt_us / 2;
        } else {
            let diff = (sample_rtt_us as i64 - self.smoothed_rtt_us as i64).unsigned_abs();
            self.rtt_variance_us = (3 * self.rtt_variance_us + diff) / 4;
            self.smoothed_rtt_us = (7 * self.smoothed_rtt_us + sample_rtt_us) / 8;
        }
    }
}

/// Configuration for Route Flapping Damping (RFC 2439 adapted for multipath transport).
#[derive(Debug, Clone, PartialEq)]
pub struct IsspFlapDampingConfig {
    /// Whether route flap damping is active. Default: true.
    pub enabled: bool,
    /// Penalty points added on each path failure / flap. Default: 1000.0.
    pub flap_penalty: f64,
    /// Penalty threshold above which the route is suppressed/damped. Default: 2000.0.
    pub suppress_threshold: f64,
    /// Penalty threshold below which a suppressed route is eligible for reuse/probation. Default: 750.0.
    pub reuse_threshold: f64,
    /// Half-life in milliseconds for exponential penalty decay. Default: 15_000 ms.
    pub half_life_ms: u64,
    /// Maximum penalty ceiling to avoid indefinite suppression. Default: 6000.0.
    pub max_suppress_penalty: f64,
}

impl Default for IsspFlapDampingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            flap_penalty: 1000.0,
            suppress_threshold: 2000.0,
            reuse_threshold: 750.0,
            half_life_ms: 15_000,
            max_suppress_penalty: 6000.0,
        }
    }
}

/// Dynamic flap damping tracking state per member path.
#[derive(Debug, Clone, PartialEq)]
pub struct IsspRouteFlapState {
    /// Total cumulative route failover flap events recorded.
    pub flap_count: u32,
    /// Current decayed flapping penalty score.
    pub penalty: f64,
    /// Timestamp of the most recent flap event in unix ms.
    pub last_flap_unix_ms: u64,
    /// Timestamp of the last exponential decay evaluation in unix ms.
    pub last_decay_unix_ms: u64,
    /// Whether the route is currently suppressed/damped due to excessive flapping.
    pub is_suppressed: bool,
}

impl Default for IsspRouteFlapState {
    fn default() -> Self {
        Self {
            flap_count: 0,
            penalty: 0.0,
            last_flap_unix_ms: 0,
            last_decay_unix_ms: 0,
            is_suppressed: false,
        }
    }
}

impl IsspRouteFlapState {
    /// Apply exponential decay to the flapping penalty based on elapsed time.
    pub fn decay(&mut self, now_ms: u64, config: &IsspFlapDampingConfig) {
        if !config.enabled || self.penalty <= 0.0 {
            self.last_decay_unix_ms = now_ms;
            return;
        }
        if self.last_decay_unix_ms == 0 {
            self.last_decay_unix_ms = now_ms;
            return;
        }
        if now_ms <= self.last_decay_unix_ms {
            return;
        }

        let elapsed_ms = (now_ms - self.last_decay_unix_ms) as f64;
        let half_life_ms = config.half_life_ms.max(1) as f64;
        let decay_factor = (0.5f64).powf(elapsed_ms / half_life_ms);
        self.penalty *= decay_factor;
        self.last_decay_unix_ms = now_ms;

        // If suppressed and penalty falls below reuse threshold, clear suppression
        if self.is_suppressed && self.penalty <= config.reuse_threshold {
            self.is_suppressed = false;
        }
    }

    /// Record a new route flap (failure event) and update penalty and suppression state.
    pub fn record_flap(&mut self, now_ms: u64, config: &IsspFlapDampingConfig) {
        self.decay(now_ms, config);
        if !config.enabled {
            self.flap_count += 1;
            self.last_flap_unix_ms = now_ms;
            self.last_decay_unix_ms = now_ms;
            return;
        }

        self.flap_count += 1;
        self.penalty = (self.penalty + config.flap_penalty).min(config.max_suppress_penalty);
        self.last_flap_unix_ms = now_ms;
        self.last_decay_unix_ms = now_ms;

        if self.penalty >= config.suppress_threshold {
            self.is_suppressed = true;
        }
    }
}

/// Configuration for path probation and progressive traffic reintegration.
#[derive(Debug, Clone, PartialEq)]
pub struct IsspProbationConfig {
    /// Whether progressive probation is enabled.
    pub enabled: bool,
    /// Duration in milliseconds a recovered path must spend in probation before full reintegration.
    pub probation_duration_ms: u64,
    /// Minimum consecutive successful heartbeat pongs required to graduate from probation.
    pub min_successful_probes: u32,
    /// Initial traffic weight ratio allocated upon entering probation (e.g. 0.20 = 20%).
    pub initial_weight_ratio: f64,
    /// Maximum tolerated packet loss rate (ppm) during probation. Default: 20_000 (2.0%).
    pub max_loss_ppm_tolerance: u32,
}

impl Default for IsspProbationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            probation_duration_ms: 5_000,
            min_successful_probes: 5,
            initial_weight_ratio: 0.20,
            max_loss_ppm_tolerance: 20_000,
        }
    }
}

/// Dynamic probation tracking state per member path.
#[derive(Debug, Clone, PartialEq)]
pub struct IsspProbationState {
    /// Whether the path is actively undergoing progressive probation.
    pub in_probation: bool,
    /// Timestamp when probation started in unix ms.
    pub entered_unix_ms: u64,
    /// Timestamp of most recent successful probe in unix ms.
    pub last_probe_unix_ms: u64,
    /// Number of consecutive successful probes during this probation window.
    pub successful_probes: u32,
    /// Current progressive traffic weight ratio (ramping from initial_weight_ratio up to 1.0).
    pub weight_ratio: f64,
    /// Whether probation was successfully completed and graduated.
    pub is_graduated: bool,
}

impl Default for IsspProbationState {
    fn default() -> Self {
        Self {
            in_probation: false,
            entered_unix_ms: 0,
            last_probe_unix_ms: 0,
            successful_probes: 0,
            weight_ratio: 1.0,
            is_graduated: false,
        }
    }
}

impl IsspProbationState {
    /// Start progressive probation on a recovered path.
    pub fn start(&mut self, now_ms: u64, initial_ratio: f64) {
        self.in_probation = true;
        self.entered_unix_ms = now_ms;
        self.last_probe_unix_ms = now_ms;
        self.successful_probes = 1;
        self.weight_ratio = initial_ratio.clamp(0.05, 1.0);
        self.is_graduated = false;
    }

    /// Record a successful heartbeat pong during probation and compute updated weight ratio.
    pub fn record_success(&mut self, now_ms: u64, config: &IsspProbationConfig) {
        if !self.in_probation {
            return;
        }
        self.last_probe_unix_ms = now_ms;
        self.successful_probes += 1;

        let elapsed = now_ms.saturating_sub(self.entered_unix_ms);
        let duration = config.probation_duration_ms.max(1);
        let time_progress = (elapsed as f64 / duration as f64).min(1.0);
        let probe_progress =
            (self.successful_probes as f64 / config.min_successful_probes.max(1) as f64).min(1.0);
        let progress = (time_progress * 0.6 + probe_progress * 0.4).min(1.0);

        let start_ratio = config.initial_weight_ratio.clamp(0.05, 1.0);
        self.weight_ratio = start_ratio + (1.0 - start_ratio) * progress;
    }

    /// Check if probation criteria are satisfied for graduation back to nominal status.
    pub fn can_graduate(&self, now_ms: u64, config: &IsspProbationConfig, loss_ppm: u32) -> bool {
        if !self.in_probation {
            return false;
        }
        let elapsed = now_ms.saturating_sub(self.entered_unix_ms);
        elapsed >= config.probation_duration_ms
            && self.successful_probes >= config.min_successful_probes
            && loss_ppm <= config.max_loss_ppm_tolerance
    }

    /// Mark probation as graduated.
    pub fn graduate(&mut self) {
        self.in_probation = false;
        self.weight_ratio = 1.0;
        self.is_graduated = true;
    }

    /// Reset probation state upon new failure.
    pub fn reset(&mut self) {
        self.in_probation = false;
        self.entered_unix_ms = 0;
        self.last_probe_unix_ms = 0;
        self.successful_probes = 0;
        self.weight_ratio = 1.0;
        self.is_graduated = false;
    }
}

/// Telemetry record of a route flapping event and penalty adjustment.
#[derive(Debug, Clone, PartialEq)]
pub struct IsspFlapEvent {
    pub timestamp_unix_ms: u64,
    pub path_id: u32,
    pub flap_count: u32,
    pub penalty: f64,
    pub is_suppressed: bool,
}

/// Telemetry record of a path graduating from probation and being fully reintegrated.
#[derive(Debug, Clone, PartialEq)]
pub struct IsspReintegrationEvent {
    pub timestamp_unix_ms: u64,
    pub path_id: u32,
    pub probation_duration_ms: u64,
    pub successful_probes: u32,
    pub final_rtt_us: u64,
    pub restored_state: IsspPathState,
}

/// Subpath opportunistic encryption policy level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OpportunisticSecurityLevel {
    /// No subpath encryption applied (e.g. underlying secure link or trusted VLAN).
    #[default]
    Plaintext,
    /// Opportunistic AEAD: encrypts if a subpath key is configured; falls back to plaintext if missing.
    Opportunistic,
    /// Mandatory AEAD encryption: packet transmission fails if no subpath key is present.
    Required,
}

// ─── Congestion Control: BBR / LEDBAT ────────────────────────────────────────

/// High-level congestion phase that governs pacing and window scaling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IsspCongestionPhase {
    /// Slow-start: exponential growth until first congestion signal.
    #[default]
    SlowStart,
    /// Steady-state bandwidth probing and congestion avoidance.
    CongestionAvoidance,
    /// Loss recovery: retransmission without bandwidth probing.
    Recovery,
}

/// Per-subpath congestion state: phase + unified bandwidth estimate.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct IsspCongestionState {
    /// Current congestion phase.
    pub phase: IsspCongestionPhase,
    /// BBR model for this subpath.
    pub bbr: IsspBbrState,
    /// LEDBAT model for this subpath.
    pub ledbat: IsspLedbatState,
    /// Bytes transmitted since last congestion feedback update.
    pub bytes_in_flight: u64,
    /// Number of congestion events observed on this subpath.
    pub congestion_events: u64,
}

impl IsspCongestionState {
    /// Feed a new RTT sample (µs) and optional loss signal.
    /// Returns the updated bandwidth-weighted route weight adjustment factor
    /// in [0.0, 1.0] — 1.0 means no congestion, 0.0 means path fully blocked.
    pub fn update(&mut self, rtt_us: u64, lost_bytes: u64, delivered_bytes: u64) -> f64 {
        self.bbr.update(rtt_us, delivered_bytes);
        self.ledbat.update(rtt_us);

        if lost_bytes > 0 || self.ledbat.is_congested() {
            self.congestion_events += 1;
            self.phase = IsspCongestionPhase::Recovery;
        } else if matches!(
            self.phase,
            IsspCongestionPhase::Recovery | IsspCongestionPhase::SlowStart
        ) && (self.phase == IsspCongestionPhase::Recovery
            || self.bbr.estimated_bandwidth_bps > 0)
        {
            self.phase = IsspCongestionPhase::CongestionAvoidance;
        }

        self.congestion_weight_factor()
    }

    /// Compute a [0.0, 1.0] weight factor based on current congestion state.
    pub fn congestion_weight_factor(&self) -> f64 {
        let phase_factor = match self.phase {
            // SlowStart with no data yet → neutral (1.0); once BBR has estimate → 0.85
            IsspCongestionPhase::SlowStart => {
                if self.bbr.estimated_bandwidth_bps == 0 {
                    1.0
                } else {
                    0.85
                }
            }
            IsspCongestionPhase::CongestionAvoidance => 1.00,
            IsspCongestionPhase::Recovery => 0.40,
        };
        // LEDBAT queuing pressure: reduce weight when queuing delay is large
        let ledbat_factor = self.ledbat.weight_factor();
        // BBR: if no bandwidth estimate yet, stay neutral
        let bbr_factor = self.bbr.weight_factor();
        (phase_factor * ledbat_factor * bbr_factor).clamp(0.05, 1.0)
    }
}

// ─── BBR State ────────────────────────────────────────────────────────────────

/// Simplified BBR (Bottleneck Bandwidth and RTT) model for per-subpath pacing.
///
/// Tracks `BtlBw` (bottleneck bandwidth) using a max-filter over a delivery
/// window and `RTprop` (minimum propagation RTT) using a min-filter.
#[derive(Debug, Clone, PartialEq)]
pub struct IsspBbrState {
    /// Estimated bottleneck bandwidth in bits per second.
    pub estimated_bandwidth_bps: u64,
    /// Minimum observed RTT (propagation delay) in microseconds.
    pub rt_prop_us: u64,
    /// Total bytes delivered since last estimate refresh.
    delivered_bytes: u64,
    /// Last RTT sample used for pacing gain calculation.
    last_rtt_us: u64,
    /// Sliding window of recent bandwidth samples (bytes/µs × 1e6 = bps).
    bw_window: [u64; 8],
    /// Current position in the sliding window.
    bw_window_pos: usize,
    /// Pacing gain (Q8.8 fixed-point: 256 = 1.0×, 288 = 1.125×, 204 = 0.8×).
    pub pacing_gain_q8: u32,
}

impl Default for IsspBbrState {
    fn default() -> Self {
        Self {
            estimated_bandwidth_bps: 0,
            rt_prop_us: u64::MAX,
            delivered_bytes: 0,
            last_rtt_us: 0,
            bw_window: [0u64; 8],
            bw_window_pos: 0,
            pacing_gain_q8: 288, // 1.125× — startup / slow-start pacing
        }
    }
}

impl IsspBbrState {
    /// Update the BBR model with a new RTT sample and delivered byte count.
    pub fn update(&mut self, rtt_us: u64, newly_delivered_bytes: u64) {
        if rtt_us == 0 {
            return;
        }
        self.last_rtt_us = rtt_us;
        // Update RTprop (minimum RTT)
        if rtt_us < self.rt_prop_us {
            self.rt_prop_us = rtt_us;
        }
        self.delivered_bytes += newly_delivered_bytes;
        // Bandwidth sample: bytes/µs → bps (× 8 × 1e6 / rtt_us)
        if newly_delivered_bytes > 0 {
            // bps = bytes * 8 * 1_000_000 / rtt_us
            let bps = newly_delivered_bytes.saturating_mul(8_000_000) / rtt_us;
            self.bw_window[self.bw_window_pos % 8] = bps;
            self.bw_window_pos = self.bw_window_pos.wrapping_add(1);
            // BtlBw = max over window
            self.estimated_bandwidth_bps = *self.bw_window.iter().max().unwrap_or(&0);
        }
        // After gaining enough BW info, switch to 1.0× pacing
        if self.estimated_bandwidth_bps > 0 {
            self.pacing_gain_q8 = 256;
        }
    }

    /// Weight factor based on BBR pacing gain: low gain → lower weight.
    pub fn weight_factor(&self) -> f64 {
        if self.estimated_bandwidth_bps == 0 {
            return 1.0; // no info yet — neutral
        }
        // Normalise pacing gain: 256 (1.0) → 1.0, 204 (0.8) → 0.8
        (self.pacing_gain_q8 as f64 / 256.0).clamp(0.5, 1.5)
    }
}

// ─── LEDBAT State ─────────────────────────────────────────────────────────────

/// LEDBAT (Low Extra Delay Background Transport, RFC 6817) delay-based
/// congestion controller for per-subpath queuing estimation.
#[derive(Debug, Clone, PartialEq)]
pub struct IsspLedbatState {
    /// Base one-way delay (minimum observed RTT/2), in microseconds.
    pub base_delay_us: u64,
    /// Current one-way delay estimate (RTT/2), in microseconds.
    pub current_delay_us: u64,
    /// Queuing delay = current_delay − base_delay (µs).
    pub queuing_delay_us: u64,
    /// LEDBAT target queuing delay (default: 25 ms per RFC 6817).
    pub target_delay_us: u64,
    /// CWND estimate in bytes.
    pub cwnd_bytes: u64,
    /// Gain factor for CWND adjustment (default: 1.0).
    pub gain: f64,
}

impl Default for IsspLedbatState {
    fn default() -> Self {
        Self {
            base_delay_us: u64::MAX,
            current_delay_us: 0,
            queuing_delay_us: 0,
            target_delay_us: 25_000, // 25 ms
            cwnd_bytes: 65_536,      // 64 KiB initial CWND
            gain: 1.0,
        }
    }
}

impl IsspLedbatState {
    /// Feed a new RTT sample and update queuing delay / CWND.
    pub fn update(&mut self, rtt_us: u64) {
        if rtt_us == 0 {
            return;
        }
        // One-way delay approximation: RTT/2
        let owd = rtt_us / 2;
        self.current_delay_us = owd;

        // Update base delay (min filter)
        if owd < self.base_delay_us {
            self.base_delay_us = owd;
        }

        // Queuing delay
        self.queuing_delay_us = self.current_delay_us.saturating_sub(self.base_delay_us);

        // CWND adjustment: RFC 6817 §5
        //   off_target = (TARGET - queuing_delay) / TARGET
        //   cwnd += GAIN * off_target * MSS
        let mss: i64 = 1460; // bytes
        let off_target = (self.target_delay_us as i64 - self.queuing_delay_us as i64) as f64
            / self.target_delay_us as f64;
        let delta = (self.gain * off_target * mss as f64).round() as i64;
        self.cwnd_bytes = ((self.cwnd_bytes as i64).saturating_add(delta)).max(mss) as u64;
    }

    /// True when queuing delay exceeds the LEDBAT target — congestion signal.
    pub fn is_congested(&self) -> bool {
        self.queuing_delay_us > self.target_delay_us
    }

    /// Weight factor: 1.0 when no queuing, decreases towards 0 as queuing grows.
    pub fn weight_factor(&self) -> f64 {
        if self.base_delay_us == u64::MAX {
            return 1.0; // not yet initialised
        }
        let ratio = self.queuing_delay_us as f64 / self.target_delay_us as f64;
        // Smooth penalisation: 0 queuing → 1.0, 2× target → ~0.33
        (1.0 / (1.0 + ratio)).clamp(0.1, 1.0)
    }
}

// ─── Bandwidth Estimate ───────────────────────────────────────────────────────

/// Aggregated per-subpath bandwidth and congestion estimate exposed to the router.
#[derive(Debug, Clone, PartialEq)]
pub struct IsspBandwidthEstimate {
    /// Estimated available bandwidth in bits per second (BBR BtlBw).
    pub available_bps: u64,
    /// Queuing delay estimate from LEDBAT (µs).
    pub queuing_delay_us: u64,
    /// Congestion weight factor in [0.05, 1.0].
    pub weight_factor: f64,
    /// Current congestion phase.
    pub phase: IsspCongestionPhase,
}

// ─── IsspMultipathRoute (now includes congestion state) ───────────────────────

/// A member transport path within an ISSP dynamic multipath routing table.
#[derive(Debug, Clone, PartialEq)]
pub struct IsspMultipathRoute {
    /// Unique identifier for this path.
    pub path_id: u32,
    /// Remote destination peer node ID.
    pub peer_node_id: u32,
    /// Physical or virtual network interface name (e.g. "eth0-wan", "wwan0-5g").
    pub interface_name: String,
    /// Administrative route priority (lower is higher priority: 1 = primary, 2 = secondary, etc.).
    pub priority: u32,
    /// Bandwidth/capacity scheduling weight (e.g. 100 for 1Gbps, 10 for 100Mbps).
    pub weight: u32,
    /// Current operational state.
    pub state: IsspPathState,
    /// Real-time path telemetry metrics.
    pub metrics: IsspPathMetrics,
    /// Interval in milliseconds between keep-alive heartbeat probes.
    pub heartbeat_interval_ms: u64,
    /// Maximum elapsed milliseconds without a heartbeat pong before marking path Failed.
    pub heartbeat_timeout_ms: u64,
    /// Maximum consecutive missed heartbeat probes allowed before marking path Failed.
    pub max_missed_heartbeats: u32,
    /// Dynamic route flapping damping tracking state.
    pub flap_state: IsspRouteFlapState,
    /// Dynamic progressive probation state following recovery.
    pub probation_state: IsspProbationState,
    /// Subpath opportunistic encryption level.
    pub security_level: OpportunisticSecurityLevel,
    /// Per-subpath congestion control state (BBR + LEDBAT).
    pub congestion: IsspCongestionState,
}

impl IsspMultipathRoute {
    pub fn new(
        path_id: u32,
        peer_node_id: u32,
        interface_name: impl Into<String>,
        priority: u32,
        weight: u32,
    ) -> Self {
        Self {
            path_id,
            peer_node_id,
            interface_name: interface_name.into(),
            priority,
            weight: weight.max(1),
            state: IsspPathState::Active,
            metrics: IsspPathMetrics::default(),
            heartbeat_interval_ms: 1_000,
            heartbeat_timeout_ms: 3_000,
            max_missed_heartbeats: 3,
            flap_state: IsspRouteFlapState::default(),
            probation_state: IsspProbationState::default(),
            security_level: OpportunisticSecurityLevel::Plaintext,
            congestion: IsspCongestionState::default(),
        }
    }

    /// Calculate current effective scheduling weight considering degradation and probation ramp.
    pub fn effective_weight(&self) -> u32 {
        if self.state == IsspPathState::Failed {
            return 0;
        }
        let base = match self.state {
            IsspPathState::Active => self.weight.max(1) as f64,
            IsspPathState::Standby => self.weight.max(1) as f64,
            IsspPathState::Degraded => (self.weight / 2).max(1) as f64,
            IsspPathState::Probation => {
                let scaled = (self.weight as f64) * self.probation_state.weight_ratio;
                scaled.round().max(1.0)
            }
            IsspPathState::Failed => 0.0,
        };
        // Apply congestion weight factor (BBR+LEDBAT) — clamp to at least 1
        let cw = self.congestion.congestion_weight_factor();
        ((base * cw).round() as u32).max(1)
    }

    /// Retrieve an aggregated bandwidth estimate for this subpath.
    pub fn bandwidth_estimate(&self) -> IsspBandwidthEstimate {
        IsspBandwidthEstimate {
            available_bps: self.congestion.bbr.estimated_bandwidth_bps,
            queuing_delay_us: self.congestion.ledbat.queuing_delay_us,
            weight_factor: self.congestion.congestion_weight_factor(),
            phase: self.congestion.phase,
        }
    }

    pub fn with_state(mut self, state: IsspPathState) -> Self {
        self.state = state;
        self
    }

    pub fn with_security_level(mut self, security_level: OpportunisticSecurityLevel) -> Self {
        self.security_level = security_level;
        self
    }

    pub fn with_heartbeat_config(
        mut self,
        interval_ms: u64,
        timeout_ms: u64,
        max_missed: u32,
    ) -> Self {
        self.heartbeat_interval_ms = interval_ms;
        self.heartbeat_timeout_ms = timeout_ms;
        self.max_missed_heartbeats = max_missed;
        self
    }
}

/// Heartbeat ping/pong probe exchanged between ISSP nodes/paths for RTT measurement and liveness detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IsspHeartbeatProbe {
    pub sender_node_id: u32,
    pub path_id: u32,
    pub probe_seq: u64,
    pub timestamp_unix_ms: u64,
    pub is_response: bool,
}

impl IsspHeartbeatProbe {
    pub fn new(
        sender_node_id: u32,
        path_id: u32,
        probe_seq: u64,
        timestamp_unix_ms: u64,
        is_response: bool,
    ) -> Self {
        Self {
            sender_node_id,
            path_id,
            probe_seq,
            timestamp_unix_ms,
            is_response,
        }
    }

    /// Encode probe to a 40-byte wire buffer with CRC32 integrity check.
    pub fn encode(&self) -> [u8; ISSP_HEARTBEAT_SIZE] {
        let mut buf = [0u8; ISSP_HEARTBEAT_SIZE];
        buf[0..4].copy_from_slice(&ISSP_HEARTBEAT_MAGIC.to_be_bytes());
        buf[4..8].copy_from_slice(&self.sender_node_id.to_le_bytes());
        buf[8..12].copy_from_slice(&self.path_id.to_le_bytes());
        buf[12..20].copy_from_slice(&self.probe_seq.to_le_bytes());
        buf[20..28].copy_from_slice(&self.timestamp_unix_ms.to_le_bytes());
        let flags: u32 = if self.is_response { 1 } else { 0 };
        buf[28..32].copy_from_slice(&flags.to_le_bytes());
        let crc = crc32_ieee(&buf[0..32]);
        buf[32..36].copy_from_slice(&crc.to_le_bytes());
        buf
    }

    /// Decode probe from wire buffer with magic and CRC validation.
    pub fn decode(raw: &[u8; ISSP_HEARTBEAT_SIZE]) -> Option<Self> {
        let magic = u32::from_be_bytes(raw[0..4].try_into().unwrap());
        if magic != ISSP_HEARTBEAT_MAGIC {
            return None;
        }
        let stored_crc = u32::from_le_bytes(raw[32..36].try_into().unwrap());
        let computed_crc = crc32_ieee(&raw[0..32]);
        if stored_crc != computed_crc {
            return None;
        }
        let sender_node_id = u32::from_le_bytes(raw[4..8].try_into().unwrap());
        let path_id = u32::from_le_bytes(raw[8..12].try_into().unwrap());
        let probe_seq = u64::from_le_bytes(raw[12..20].try_into().unwrap());
        let timestamp_unix_ms = u64::from_le_bytes(raw[20..28].try_into().unwrap());
        let flags = u32::from_le_bytes(raw[28..32].try_into().unwrap());
        let is_response = (flags & 1) != 0;
        Some(Self {
            sender_node_id,
            path_id,
            probe_seq,
            timestamp_unix_ms,
            is_response,
        })
    }
}

/// Trigger reason for an automatic dynamic multipath failover event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsspFailoverReason {
    /// Heartbeat timeout exceeded (peer silent).
    HeartbeatTimeout,
    /// Maximum consecutive missed heartbeats reached.
    ConsecutiveHeartbeatsExceeded,
    /// Administrative or manual trigger.
    Administrative,
    /// Elevated packet loss or latency jitter degradation.
    QualityDegradation,
}

/// Detailed record of an automatic failover event caused by path degradation or heartbeat expiration.
#[derive(Debug, Clone, PartialEq)]
pub struct IsspFailoverEvent {
    /// Timestamp when failover occurred (unix ms).
    pub timestamp_unix_ms: u64,
    /// Path ID that failed or expired.
    pub failed_path_id: u32,
    /// Target path ID selected for takeover.
    pub target_path_id: u32,
    /// Trigger reason for failover.
    pub reason: IsspFailoverReason,
    /// Number of live sessions rerouted to the new path.
    pub sessions_rerouted: usize,
    /// Cutover latency in microseconds (from failure detection to routing update).
    pub cutover_latency_us: f64,
    /// Session IDs that were migrated during this cutover.
    pub rerouted_session_ids: Vec<SessionId>,
}

/// Traffic steering and load-balancing strategy across dynamic multipath links.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IsspRoutingPolicy {
    /// Priority-based active-standby routing with instantaneous cutover upon failure.
    #[default]
    ActiveStandby,
    /// Select path with lowest smoothed round-trip time.
    LowestLatency,
    /// Select path with highest composite quality score.
    BestQuality,
    /// Consistent flow hashing across usable paths.
    FlowHashing,
    /// Capacity-weighted packet striping and bandwidth aggregation across all usable paths.
    BandwidthAggregation,
}

/// Scheduled packet for multipath transmission across aggregated interfaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsspScheduledPacket {
    /// Monotonically increasing multipath sequence number assigned by the aggregation scheduler.
    pub multipath_seq: u64,
    /// Identifier of the path selected for transmission.
    pub path_id: u32,
    /// Identifier of the session originating this packet.
    pub session_id: SessionId,
    /// Packet payload.
    pub payload: Vec<u8>,
    /// Transmission timestamp (unix ms).
    pub scheduled_timestamp_unix_ms: u64,
    /// Estimated arrival timestamp (unix ms) based on path RTT.
    pub estimated_arrival_unix_ms: u64,
}

/// In-order or resequenced packet delivered to application/session consumer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsspDeliveredPacket {
    pub packet: IsspScheduledPacket,
    /// Delay in milliseconds spent inside the resequencing buffer (0 if received in order).
    pub reorder_delay_ms: u64,
    /// Whether the packet arrived out of sequence and was resequenced.
    pub was_reordered: bool,
}

/// Result of ingesting a packet into the resequencing buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IsspResequenceStatus {
    /// Packet arrived in sequence and was delivered immediately.
    InOrderDelivered,
    /// Packet arrived out of order and was buffered waiting for missing preceding packets.
    Buffered {
        buffered_seq: u64,
        expected_seq: u64,
        buffer_depth: usize,
    },
    /// Duplicate or obsolete sequence number discarded.
    DuplicateOrStale { seq: u64, expected_seq: u64 },
    /// Arrival of missing packet triggered in-order drain of one or more buffered packets.
    ResequencedDelivered { delivered_count: usize },
    /// Gap timeout expired waiting for missing packet; window advanced to prevent HoL blocking.
    GapExpired {
        skipped_seq: u64,
        new_expected_seq: u64,
        flushed_count: usize,
    },
}

/// Telemetry metrics for multipath packet resequencing.
#[derive(Debug, Clone, PartialEq)]
pub struct IsspResequencingTelemetry {
    pub expected_seq: u64,
    pub buffer_depth: usize,
    pub buffer_capacity: usize,
    pub gap_timeout_ms: u64,
    pub total_received: u64,
    pub in_order_count: u64,
    pub reordered_count: u64,
    pub duplicate_count: u64,
    pub gaps_expired_count: u64,
    pub average_reorder_delay_ms: f64,
    pub max_reorder_delay_ms: u64,
    pub reorder_rate_percent: f64,
}

/// Sliding window resequencing buffer providing out-of-order packet compensation
/// with adaptive gap timeout to eliminate Head-of-Line blocking over asymmetric multipath links.
#[derive(Debug, Clone)]
pub struct IsspResequencingBuffer {
    pub expected_seq: u64,
    pub capacity: usize,
    pub gap_timeout_ms: u64,
    pub gap_wait_start_unix_ms: u64,
    pub buffer: BTreeMap<u64, (IsspScheduledPacket, u64)>,
    pub total_received: u64,
    pub in_order_count: u64,
    pub reordered_count: u64,
    pub duplicate_count: u64,
    pub gaps_expired_count: u64,
    pub total_reorder_delay_ms: u64,
    pub max_reorder_delay_ms: u64,
}

impl IsspResequencingBuffer {
    /// Create a new resequencing buffer with specified capacity and gap timeout.
    pub fn new(initial_seq: u64, capacity: usize, gap_timeout_ms: u64) -> Self {
        Self {
            expected_seq: initial_seq,
            capacity: capacity.max(16),
            gap_timeout_ms: gap_timeout_ms.max(10),
            gap_wait_start_unix_ms: 0,
            buffer: BTreeMap::new(),
            total_received: 0,
            in_order_count: 0,
            reordered_count: 0,
            duplicate_count: 0,
            gaps_expired_count: 0,
            total_reorder_delay_ms: 0,
            max_reorder_delay_ms: 0,
        }
    }

    /// Ingest a packet, returning delivered in-order packets and resequencing status.
    pub fn ingest(
        &mut self,
        packet: IsspScheduledPacket,
        now_ms: u64,
    ) -> (Vec<IsspDeliveredPacket>, IsspResequenceStatus) {
        self.total_received += 1;
        let seq = packet.multipath_seq;

        // Auto-initialize base expected sequence on first packet if initial was 0
        if self.expected_seq == 0 {
            self.expected_seq = seq;
        }

        if seq < self.expected_seq {
            self.duplicate_count += 1;
            return (
                Vec::new(),
                IsspResequenceStatus::DuplicateOrStale {
                    seq,
                    expected_seq: self.expected_seq,
                },
            );
        }

        if seq == self.expected_seq {
            let mut delivered = Vec::new();
            self.in_order_count += 1;
            delivered.push(IsspDeliveredPacket {
                packet,
                reorder_delay_ms: 0,
                was_reordered: false,
            });
            self.expected_seq += 1;

            // Drain contiguous buffered packets
            while let Some(&first_buffered_seq) = self.buffer.keys().next() {
                if first_buffered_seq == self.expected_seq {
                    let (buffered_pkt, arrival_ms) =
                        self.buffer.remove(&first_buffered_seq).unwrap();
                    let delay = now_ms.saturating_sub(arrival_ms);
                    self.total_reorder_delay_ms += delay;
                    self.max_reorder_delay_ms = self.max_reorder_delay_ms.max(delay);
                    self.reordered_count += 1;
                    delivered.push(IsspDeliveredPacket {
                        packet: buffered_pkt,
                        reorder_delay_ms: delay,
                        was_reordered: true,
                    });
                    self.expected_seq += 1;
                } else {
                    break;
                }
            }

            if self.buffer.is_empty() {
                self.gap_wait_start_unix_ms = 0;
            } else {
                self.gap_wait_start_unix_ms = now_ms;
            }

            let status = if delivered.len() > 1 {
                IsspResequenceStatus::ResequencedDelivered {
                    delivered_count: delivered.len(),
                }
            } else {
                IsspResequenceStatus::InOrderDelivered
            };

            return (delivered, status);
        }

        // Out-of-order packet: seq > expected_seq
        if self.buffer.contains_key(&seq) {
            self.duplicate_count += 1;
            return (
                Vec::new(),
                IsspResequenceStatus::DuplicateOrStale {
                    seq,
                    expected_seq: self.expected_seq,
                },
            );
        }

        // Buffer full / gap overflow protection: force advance to prevent Head-of-Line deadlock
        if (seq - self.expected_seq) as usize >= self.capacity || self.buffer.len() >= self.capacity
        {
            let skipped = self.expected_seq;
            let mut delivered = Vec::new();

            let next_target = if let Some(&lowest) = self.buffer.keys().next() {
                lowest
            } else {
                seq
            };
            self.gaps_expired_count += next_target.saturating_sub(self.expected_seq);
            self.expected_seq = next_target;

            // Drain contiguous from new expected
            while let Some(&cand_seq) = self.buffer.keys().next() {
                if cand_seq == self.expected_seq {
                    let (buffered_pkt, arrival_ms) = self.buffer.remove(&cand_seq).unwrap();
                    let delay = now_ms.saturating_sub(arrival_ms);
                    self.total_reorder_delay_ms += delay;
                    self.max_reorder_delay_ms = self.max_reorder_delay_ms.max(delay);
                    self.reordered_count += 1;
                    delivered.push(IsspDeliveredPacket {
                        packet: buffered_pkt,
                        reorder_delay_ms: delay,
                        was_reordered: true,
                    });
                    self.expected_seq += 1;
                } else {
                    break;
                }
            }

            if seq == self.expected_seq {
                delivered.push(IsspDeliveredPacket {
                    packet,
                    reorder_delay_ms: 0,
                    was_reordered: false,
                });
                self.expected_seq += 1;
            } else if seq > self.expected_seq {
                self.buffer.insert(seq, (packet, now_ms));
            }

            self.gap_wait_start_unix_ms = if self.buffer.is_empty() { 0 } else { now_ms };

            let flushed_count = delivered.len();
            return (
                delivered,
                IsspResequenceStatus::GapExpired {
                    skipped_seq: skipped,
                    new_expected_seq: self.expected_seq,
                    flushed_count,
                },
            );
        }

        // Buffer out-of-order packet
        if self.gap_wait_start_unix_ms == 0 {
            self.gap_wait_start_unix_ms = now_ms;
        }
        self.buffer.insert(seq, (packet, now_ms));

        (
            Vec::new(),
            IsspResequenceStatus::Buffered {
                buffered_seq: seq,
                expected_seq: self.expected_seq,
                buffer_depth: self.buffer.len(),
            },
        )
    }

    /// Check if gap timeout expired and force window forward to drain buffered packets.
    pub fn check_gap_timeout(
        &mut self,
        now_ms: u64,
    ) -> (Vec<IsspDeliveredPacket>, Option<IsspResequenceStatus>) {
        if self.buffer.is_empty() || self.gap_wait_start_unix_ms == 0 {
            return (Vec::new(), None);
        }

        let elapsed = now_ms.saturating_sub(self.gap_wait_start_unix_ms);
        if elapsed < self.gap_timeout_ms {
            return (Vec::new(), None);
        }

        let skipped = self.expected_seq;
        let next_seq = *self.buffer.keys().next().unwrap();
        self.gaps_expired_count += next_seq.saturating_sub(self.expected_seq);
        self.expected_seq = next_seq;

        let mut delivered = Vec::new();
        while let Some(&cand_seq) = self.buffer.keys().next() {
            if cand_seq == self.expected_seq {
                let (buffered_pkt, arrival_ms) = self.buffer.remove(&cand_seq).unwrap();
                let delay = now_ms.saturating_sub(arrival_ms);
                self.total_reorder_delay_ms += delay;
                self.max_reorder_delay_ms = self.max_reorder_delay_ms.max(delay);
                self.reordered_count += 1;
                delivered.push(IsspDeliveredPacket {
                    packet: buffered_pkt,
                    reorder_delay_ms: delay,
                    was_reordered: true,
                });
                self.expected_seq += 1;
            } else {
                break;
            }
        }

        self.gap_wait_start_unix_ms = if self.buffer.is_empty() { 0 } else { now_ms };

        let status = IsspResequenceStatus::GapExpired {
            skipped_seq: skipped,
            new_expected_seq: self.expected_seq,
            flushed_count: delivered.len(),
        };

        (delivered, Some(status))
    }

    /// Resequencing telemetry summary.
    pub fn telemetry(&self) -> IsspResequencingTelemetry {
        let avg_delay = if self.reordered_count > 0 {
            self.total_reorder_delay_ms as f64 / self.reordered_count as f64
        } else {
            0.0
        };
        let reorder_rate = if self.total_received > 0 {
            (self.reordered_count as f64 / self.total_received as f64) * 100.0
        } else {
            0.0
        };

        IsspResequencingTelemetry {
            expected_seq: self.expected_seq,
            buffer_depth: self.buffer.len(),
            buffer_capacity: self.capacity,
            gap_timeout_ms: self.gap_timeout_ms,
            total_received: self.total_received,
            in_order_count: self.in_order_count,
            reordered_count: self.reordered_count,
            duplicate_count: self.duplicate_count,
            gaps_expired_count: self.gaps_expired_count,
            average_reorder_delay_ms: avg_delay,
            max_reorder_delay_ms: self.max_reorder_delay_ms,
            reorder_rate_percent: reorder_rate,
        }
    }
}

/// Aggregated telemetry across all multipath links in the router.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct IsspMultipathTelemetry {
    pub total_paths: usize,
    pub active_paths: usize,
    pub standby_paths: usize,
    pub degraded_paths: usize,
    pub failed_paths: usize,
    pub probation_paths: usize,
    pub suppressed_paths: usize,
    pub total_failovers: u64,
    pub total_flaps: u64,
    pub total_reintegrations: u64,
    pub total_heartbeats_sent: u64,
    pub total_heartbeats_received: u64,
    pub total_sessions_bound: usize,
    pub routes: Vec<IsspMultipathRoute>,
}

/// Dynamic multipath routing engine with automatic heartbeat failover and session remapping.
pub struct IsspDynamicMultipathRouter {
    pub local_node_id: u32,
    paths: BTreeMap<u32, IsspMultipathRoute>,
    session_bindings: HashMap<SessionId, u32>,
    pub policy: IsspRoutingPolicy,
    next_probe_seq: u64,
    next_multipath_seq: u64,
    path_deficits: HashMap<u32, i64>,
    resequencers: HashMap<SessionId, IsspResequencingBuffer>,
    pub total_failovers: u64,
    failover_history: Vec<IsspFailoverEvent>,
    pub flap_damping_config: IsspFlapDampingConfig,
    pub probation_config: IsspProbationConfig,
    pub total_flaps: u64,
    pub total_reintegrations: u64,
    flap_history: Vec<IsspFlapEvent>,
    reintegration_history: Vec<IsspReintegrationEvent>,
    subpath_crypto: HashMap<u32, IsspSubpathCryptoTunnel>,
    header_compressor: IsspAdaptiveHeaderCompressor,
    header_decompressor: IsspAdaptiveHeaderCompressor,
    subpath_seqs: HashMap<u32, u64>,
}

impl IsspDynamicMultipathRouter {
    pub fn new(local_node_id: u32, policy: IsspRoutingPolicy) -> Self {
        Self {
            local_node_id,
            paths: BTreeMap::new(),
            session_bindings: HashMap::new(),
            policy,
            next_probe_seq: 1,
            next_multipath_seq: 1,
            path_deficits: HashMap::new(),
            resequencers: HashMap::new(),
            total_failovers: 0,
            failover_history: Vec::new(),
            flap_damping_config: IsspFlapDampingConfig::default(),
            probation_config: IsspProbationConfig::default(),
            total_flaps: 0,
            total_reintegrations: 0,
            flap_history: Vec::new(),
            reintegration_history: Vec::new(),
            subpath_crypto: HashMap::new(),
            header_compressor: IsspAdaptiveHeaderCompressor::new(64),
            header_decompressor: IsspAdaptiveHeaderCompressor::new(64),
            subpath_seqs: HashMap::new(),
        }
    }

    /// Configure route flap damping parameters.
    pub fn with_flap_damping_config(mut self, config: IsspFlapDampingConfig) -> Self {
        self.flap_damping_config = config;
        self
    }

    /// Configure path probation parameters.
    pub fn with_probation_config(mut self, config: IsspProbationConfig) -> Self {
        self.probation_config = config;
        self
    }

    /// Register a new multipath route.
    pub fn add_route(&mut self, route: IsspMultipathRoute) {
        self.paths.insert(route.path_id, route);
    }

    /// Remove a multipath route by path ID.
    pub fn remove_route(&mut self, path_id: u32) -> Option<IsspMultipathRoute> {
        self.session_bindings.retain(|_, &mut pid| pid != path_id);
        self.paths.remove(&path_id)
    }

    pub fn get_route(&self, path_id: u32) -> Option<&IsspMultipathRoute> {
        self.paths.get(&path_id)
    }

    pub fn get_route_mut(&mut self, path_id: u32) -> Option<&mut IsspMultipathRoute> {
        self.paths.get_mut(&path_id)
    }

    pub fn list_routes(&self) -> Vec<IsspMultipathRoute> {
        self.paths.values().cloned().collect()
    }

    pub fn bind_session(&mut self, session_id: SessionId, path_id: u32) -> Result<(), SyncError> {
        if !self.paths.contains_key(&path_id) {
            return Err(SyncError::PathNotFound(path_id));
        }
        self.session_bindings.insert(session_id, path_id);
        Ok(())
    }

    pub fn get_session_path(&self, session_id: &SessionId) -> Option<u32> {
        self.session_bindings.get(session_id).copied()
    }

    /// Resolve or choose optimal operational path for a session.
    pub fn resolve_path_for_session(
        &mut self,
        session_id: &SessionId,
        _now_ms: u64,
    ) -> Result<u32, SyncError> {
        // If already bound to a usable path, maintain affinity
        if let Some(&pid) = self.session_bindings.get(session_id) {
            if let Some(route) = self.paths.get(&pid) {
                if route.state.is_usable() {
                    return Ok(pid);
                }
            }
        }

        // Find candidate path according to policy
        let candidate_id = self.select_best_candidate_path(None)?;

        // If candidate was in Standby state, promote it to Active
        if let Some(r) = self.paths.get_mut(&candidate_id) {
            if r.state == IsspPathState::Standby {
                r.state = IsspPathState::Active;
            }
        }

        self.session_bindings.insert(*session_id, candidate_id);
        Ok(candidate_id)
    }

    /// Helper to find best available path, excluding optional excluded_id.
    fn select_best_candidate_path(&self, exclude_id: Option<u32>) -> Result<u32, SyncError> {
        let usable: Vec<&IsspMultipathRoute> = self
            .paths
            .values()
            .filter(|r| Some(r.path_id) != exclude_id && r.state.is_usable())
            .collect();

        if !usable.is_empty() {
            let chosen = match self.policy {
                IsspRoutingPolicy::ActiveStandby => usable
                    .iter()
                    .min_by_key(|r| r.priority)
                    .map(|r| r.path_id)
                    .unwrap(),
                IsspRoutingPolicy::LowestLatency => usable
                    .iter()
                    .min_by_key(|r| r.metrics.smoothed_rtt_us)
                    .map(|r| r.path_id)
                    .unwrap(),
                IsspRoutingPolicy::BestQuality => usable
                    .iter()
                    .max_by(|a, b| {
                        let score_a = a.metrics.quality_score(a.state, a.effective_weight());
                        let score_b = b.metrics.quality_score(b.state, b.effective_weight());
                        score_a
                            .partial_cmp(&score_b)
                            .unwrap_or(std::cmp::Ordering::Equal)
                    })
                    .map(|r| r.path_id)
                    .unwrap(),
                IsspRoutingPolicy::FlowHashing => usable
                    .iter()
                    .min_by_key(|r| r.priority)
                    .map(|r| r.path_id)
                    .unwrap(),
                IsspRoutingPolicy::BandwidthAggregation => usable
                    .iter()
                    .max_by_key(|r| r.effective_weight())
                    .map(|r| r.path_id)
                    .unwrap(),
            };
            return Ok(chosen);
        }

        // If no usable paths, look for a Standby path to promote
        let standby: Vec<&IsspMultipathRoute> = self
            .paths
            .values()
            .filter(|r| Some(r.path_id) != exclude_id && r.state == IsspPathState::Standby)
            .collect();

        if let Some(first_sb) = standby.iter().min_by_key(|r| r.priority) {
            return Ok(first_sb.path_id);
        }

        Err(SyncError::NoUsablePaths)
    }

    /// Construct a heartbeat ping probe for the specified path.
    pub fn create_heartbeat_ping(
        &mut self,
        path_id: u32,
        now_ms: u64,
    ) -> Result<IsspHeartbeatProbe, SyncError> {
        let route = self
            .paths
            .get_mut(&path_id)
            .ok_or(SyncError::PathNotFound(path_id))?;
        let seq = self.next_probe_seq;
        self.next_probe_seq = self.next_probe_seq.wrapping_add(1);

        route.metrics.last_heartbeat_sent_unix_ms = now_ms;
        route.metrics.total_heartbeats_sent += 1;
        route.metrics.consecutive_missed_heartbeats += 1;

        Ok(IsspHeartbeatProbe::new(
            self.local_node_id,
            path_id,
            seq,
            now_ms,
            false,
        ))
    }

    /// Ingest and process a heartbeat probe.
    /// If Ping: returns generated Pong response probe.
    /// If Pong: updates RTT and liveness metrics, resetting missed counter.
    pub fn process_heartbeat_probe(
        &mut self,
        probe: &IsspHeartbeatProbe,
        now_ms: u64,
    ) -> Result<Option<IsspHeartbeatProbe>, SyncError> {
        if !probe.is_response {
            // Received ping -> generate pong reply
            let pong = IsspHeartbeatProbe::new(
                self.local_node_id,
                probe.path_id,
                probe.probe_seq,
                probe.timestamp_unix_ms,
                true,
            );
            Ok(Some(pong))
        } else {
            // Received pong -> update path telemetry
            let route = self
                .paths
                .get_mut(&probe.path_id)
                .ok_or(SyncError::PathNotFound(probe.path_id))?;
            route.metrics.last_heartbeat_recv_unix_ms = now_ms;
            route.metrics.consecutive_missed_heartbeats = 0;
            route.metrics.total_heartbeats_received += 1;

            if now_ms >= probe.timestamp_unix_ms {
                let rtt_sample_us = (now_ms - probe.timestamp_unix_ms) * 1000;
                route.metrics.update_rtt(rtt_sample_us);
            }

            // Flap damping exponential penalty decay on pong
            route.flap_state.decay(now_ms, &self.flap_damping_config);

            // Path recovery & probation logic
            if route.state == IsspPathState::Failed {
                // If route is damped/suppressed due to excessive flapping, it cannot recover yet
                if !route.flap_state.is_suppressed {
                    if self.probation_config.enabled
                        && self.probation_config.probation_duration_ms > 0
                    {
                        route.state = IsspPathState::Probation;
                        route
                            .probation_state
                            .start(now_ms, self.probation_config.initial_weight_ratio);
                    } else {
                        route.state = IsspPathState::Standby;
                    }
                }
            } else if route.state == IsspPathState::Probation {
                route
                    .probation_state
                    .record_success(now_ms, &self.probation_config);
                if route.probation_state.can_graduate(
                    now_ms,
                    &self.probation_config,
                    route.metrics.loss_rate_ppm,
                ) {
                    route.probation_state.graduate();
                    let restored_state = if route.priority == 1 {
                        IsspPathState::Active
                    } else {
                        IsspPathState::Standby
                    };
                    route.state = restored_state;
                    self.total_reintegrations += 1;
                    self.reintegration_history.push(IsspReintegrationEvent {
                        timestamp_unix_ms: now_ms,
                        path_id: route.path_id,
                        probation_duration_ms: self.probation_config.probation_duration_ms,
                        successful_probes: route.probation_state.successful_probes,
                        final_rtt_us: route.metrics.smoothed_rtt_us,
                        restored_state,
                    });
                }
            }
            Ok(None)
        }
    }

    /// Scan all paths for heartbeat timeout or consecutive missed heartbeats,
    /// transition expired paths to Failed, and automatically trigger dynamic failover.
    pub fn evaluate_heartbeats_and_failover(&mut self, now_ms: u64) -> Vec<IsspFailoverEvent> {
        let mut failovers = Vec::new();
        let mut failed_paths = Vec::new();

        for route in self.paths.values_mut() {
            if route.state != IsspPathState::Failed {
                let mut expired = false;
                let mut reason = IsspFailoverReason::HeartbeatTimeout;

                // Check consecutive missed probes
                if route.metrics.consecutive_missed_heartbeats >= route.max_missed_heartbeats {
                    expired = true;
                    reason = IsspFailoverReason::ConsecutiveHeartbeatsExceeded;
                }
                // Check silence elapsed since last received heartbeat
                else if route.metrics.last_heartbeat_recv_unix_ms > 0 {
                    let elapsed = now_ms.saturating_sub(route.metrics.last_heartbeat_recv_unix_ms);
                    if elapsed >= route.heartbeat_timeout_ms {
                        expired = true;
                        reason = IsspFailoverReason::HeartbeatTimeout;
                    }
                }

                if expired {
                    route.state = IsspPathState::Failed;
                    route.probation_state.reset();
                    route
                        .flap_state
                        .record_flap(now_ms, &self.flap_damping_config);
                    self.total_flaps += 1;
                    self.flap_history.push(IsspFlapEvent {
                        timestamp_unix_ms: now_ms,
                        path_id: route.path_id,
                        flap_count: route.flap_state.flap_count,
                        penalty: route.flap_state.penalty,
                        is_suppressed: route.flap_state.is_suppressed,
                    });
                    failed_paths.push((route.path_id, reason));
                }
            }
        }

        for (failed_id, reason) in failed_paths {
            let cutover_start = Instant::now();
            if let Ok(target_id) = self.select_best_candidate_path(Some(failed_id)) {
                // Promote candidate if it was Standby
                if let Some(target) = self.paths.get_mut(&target_id) {
                    if target.state == IsspPathState::Standby {
                        target.state = IsspPathState::Active;
                    }
                }

                // Reroute all sessions bound to failed path
                let mut rerouted_ids = Vec::new();
                for (s_id, bound_path) in self.session_bindings.iter_mut() {
                    if *bound_path == failed_id {
                        *bound_path = target_id;
                        rerouted_ids.push(*s_id);
                    }
                }

                let cutover_us = cutover_start.elapsed().as_secs_f64() * 1_000_000.0;
                let event = IsspFailoverEvent {
                    timestamp_unix_ms: now_ms,
                    failed_path_id: failed_id,
                    target_path_id: target_id,
                    reason,
                    sessions_rerouted: rerouted_ids.len(),
                    cutover_latency_us: cutover_us,
                    rerouted_session_ids: rerouted_ids,
                };
                self.total_failovers += 1;
                self.failover_history.push(event.clone());
                failovers.push(event);
            }
        }

        failovers
    }

    /// Retrieve failover events history.
    pub fn failover_history(&self) -> &[IsspFailoverEvent] {
        &self.failover_history
    }

    /// Retrieve flap events history.
    pub fn flap_history(&self) -> &[IsspFlapEvent] {
        &self.flap_history
    }

    /// Retrieve reintegration events history.
    pub fn reintegration_history(&self) -> &[IsspReintegrationEvent] {
        &self.reintegration_history
    }

    // ─── Congestion feedback API ──────────────────────────────────────────────

    /// Feed a congestion measurement for a specific subpath.
    ///
    /// `rtt_us`             — latest RTT sample in microseconds  
    /// `lost_bytes`         — bytes confirmed lost in this feedback interval  
    /// `delivered_bytes`    — bytes confirmed delivered in this feedback interval  
    ///
    /// Updates BBR and LEDBAT models, advances the congestion phase, and
    /// adjusts the route's dynamic weight accordingly.
    /// Returns the new congestion weight factor in [0.05, 1.0].
    pub fn update_congestion_feedback(
        &mut self,
        path_id: u32,
        rtt_us: u64,
        lost_bytes: u64,
        delivered_bytes: u64,
    ) -> Result<f64, SyncError> {
        let route = self
            .paths
            .get_mut(&path_id)
            .ok_or(SyncError::PathNotFound(path_id))?;
        // Also update path RTT metrics for unified visibility
        route.metrics.update_rtt(rtt_us);
        let factor = route.congestion.update(rtt_us, lost_bytes, delivered_bytes);
        Ok(factor)
    }

    /// Return per-subpath bandwidth estimates for all registered paths.
    pub fn bandwidth_estimates(&self) -> Vec<(u32, IsspBandwidthEstimate)> {
        self.paths
            .values()
            .map(|r| (r.path_id, r.bandwidth_estimate()))
            .collect()
    }

    /// Return the bandwidth estimate for a single path.
    pub fn path_bandwidth_estimate(
        &self,
        path_id: u32,
    ) -> Result<IsspBandwidthEstimate, SyncError> {
        self.paths
            .get(&path_id)
            .map(|r| r.bandwidth_estimate())
            .ok_or(SyncError::PathNotFound(path_id))
    }

    /// Return an iterator over all registered routes.
    pub fn routes(&self) -> impl Iterator<Item = &IsspMultipathRoute> {
        self.paths.values()
    }

    /// Return the local cluster node identifier.
    pub fn node_id(&self) -> u32 {
        self.local_node_id
    }

    /// Return the active routing policy.
    pub fn policy(&self) -> IsspRoutingPolicy {
        self.policy
    }

    /// Capture a real-time telemetry snapshot of dynamic multipath bandwidth balancing,
    /// traffic allocations, RTT gradient, BBR bottleneck bandwidth, and LEDBAT CWND.
    pub fn balancing_snapshot(
        &self,
        timestamp_unix_ns: u64,
    ) -> crate::telemetry::IsspMultipathBalancingSnapshot {
        crate::telemetry::IsspMultipathBalancingSnapshot::from_router(self, timestamp_unix_ns)
    }

    /// Generate an aggregated telemetry report across all paths.
    pub fn telemetry(&self) -> IsspMultipathTelemetry {
        let mut active = 0;
        let mut standby = 0;
        let mut degraded = 0;
        let mut failed = 0;
        let mut probation = 0;
        let mut suppressed = 0;
        let mut hb_sent = 0;
        let mut hb_recv = 0;

        for r in self.paths.values() {
            match r.state {
                IsspPathState::Active => active += 1,
                IsspPathState::Standby => standby += 1,
                IsspPathState::Degraded => degraded += 1,
                IsspPathState::Probation => probation += 1,
                IsspPathState::Failed => failed += 1,
            }
            if r.flap_state.is_suppressed {
                suppressed += 1;
            }
            hb_sent += r.metrics.total_heartbeats_sent;
            hb_recv += r.metrics.total_heartbeats_received;
        }

        IsspMultipathTelemetry {
            total_paths: self.paths.len(),
            active_paths: active,
            standby_paths: standby,
            degraded_paths: degraded,
            failed_paths: failed,
            probation_paths: probation,
            suppressed_paths: suppressed,
            total_failovers: self.total_failovers,
            total_flaps: self.total_flaps,
            total_reintegrations: self.total_reintegrations,
            total_heartbeats_sent: hb_sent,
            total_heartbeats_received: hb_recv,
            total_sessions_bound: self.session_bindings.len(),
            routes: self.paths.values().cloned().collect(),
        }
    }

    /// Schedule a packet for multipath transmission according to current routing and aggregation policy.
    pub fn schedule_packet(
        &mut self,
        session_id: &SessionId,
        payload: Vec<u8>,
        now_ms: u64,
    ) -> Result<IsspScheduledPacket, SyncError> {
        let payload_len = payload.len();
        let selected_path_id = match self.policy {
            IsspRoutingPolicy::BandwidthAggregation => {
                let usable_ids: Vec<u32> = self
                    .paths
                    .values()
                    .filter(|r| r.state.is_usable())
                    .map(|r| r.path_id)
                    .collect();

                if usable_ids.is_empty() {
                    if let Ok(cand) = self.select_best_candidate_path(None) {
                        if let Some(r) = self.paths.get_mut(&cand) {
                            r.state = IsspPathState::Active;
                        }
                        cand
                    } else {
                        return Err(SyncError::NoUsablePaths);
                    }
                } else if usable_ids.len() == 1 {
                    usable_ids[0]
                } else {
                    // Smooth Weighted Round-Robin (SWRR) packet scheduling
                    let total_weight: i64 = usable_ids
                        .iter()
                        .map(|&pid| {
                            self.paths
                                .get(&pid)
                                .map(|r| r.effective_weight() as i64)
                                .unwrap_or(1)
                        })
                        .sum();

                    let mut best_pid = usable_ids[0];
                    let mut max_current = i64::MIN;

                    for &pid in &usable_ids {
                        let eff_w = self
                            .paths
                            .get(&pid)
                            .map(|r| r.effective_weight() as i64)
                            .unwrap_or(1);
                        let cur = self.path_deficits.entry(pid).or_insert(0);
                        *cur += eff_w;
                        if *cur > max_current {
                            max_current = *cur;
                            best_pid = pid;
                        }
                    }

                    if let Some(best_cur) = self.path_deficits.get_mut(&best_pid) {
                        *best_cur -= total_weight;
                    }

                    best_pid
                }
            }
            _ => self.resolve_path_for_session(session_id, now_ms)?,
        };

        let seq = self.next_multipath_seq;
        self.next_multipath_seq += 1;

        self.resequencers
            .entry(*session_id)
            .or_insert_with(|| IsspResequencingBuffer::new(seq, 256, 150));

        let route = self
            .paths
            .get_mut(&selected_path_id)
            .ok_or(SyncError::PathNotFound(selected_path_id))?;
        route.metrics.total_frames_sent += 1;
        route.metrics.total_bytes_sent += payload_len as u64;

        let one_way_delay_ms = (route.metrics.smoothed_rtt_us / 2_000).max(1);
        let estimated_arrival = now_ms + one_way_delay_ms;

        Ok(IsspScheduledPacket {
            multipath_seq: seq,
            path_id: selected_path_id,
            session_id: *session_id,
            payload,
            scheduled_timestamp_unix_ms: now_ms,
            estimated_arrival_unix_ms: estimated_arrival,
        })
    }

    /// Ingest a received packet into the per-session resequencing buffer.
    pub fn ingest_multipath_packet(
        &mut self,
        packet: IsspScheduledPacket,
        now_ms: u64,
    ) -> (Vec<IsspDeliveredPacket>, IsspResequenceStatus) {
        if let Some(route) = self.paths.get_mut(&packet.path_id) {
            route.metrics.total_frames_received += 1;
            route.metrics.total_bytes_received += packet.payload.len() as u64;
        }
        let s_id = packet.session_id;
        let seq = packet.multipath_seq;
        let resequencer = self
            .resequencers
            .entry(s_id)
            .or_insert_with(|| IsspResequencingBuffer::new(seq, 256, 150));
        resequencer.ingest(packet, now_ms)
    }

    /// Evaluate resequencing gap timeouts across all active session buffers and drain unblocked packets.
    pub fn check_resequencing_timeouts(
        &mut self,
        now_ms: u64,
    ) -> Vec<(SessionId, Vec<IsspDeliveredPacket>, IsspResequenceStatus)> {
        let mut results = Vec::new();
        for (s_id, reseq) in &mut self.resequencers {
            let (del, status_opt) = reseq.check_gap_timeout(now_ms);
            if let Some(status) = status_opt {
                results.push((*s_id, del, status));
            }
        }
        results
    }

    /// Retrieve resequencing telemetry report for a specific session or aggregated across all sessions.
    pub fn resequencing_telemetry(
        &self,
        session_id: Option<&SessionId>,
    ) -> Option<IsspResequencingTelemetry> {
        if let Some(s_id) = session_id {
            self.resequencers.get(s_id).map(|r| r.telemetry())
        } else {
            if self.resequencers.is_empty() {
                return None;
            }
            let mut total_recv = 0;
            let mut in_order = 0;
            let mut reordered = 0;
            let mut duplicates = 0;
            let mut gaps = 0;
            let mut total_delay = 0;
            let mut max_delay = 0;
            let mut total_depth = 0;

            for r in self.resequencers.values() {
                total_recv += r.total_received;
                in_order += r.in_order_count;
                reordered += r.reordered_count;
                duplicates += r.duplicate_count;
                gaps += r.gaps_expired_count;
                total_delay += r.total_reorder_delay_ms;
                max_delay = max_delay.max(r.max_reorder_delay_ms);
                total_depth += r.buffer.len();
            }

            let avg_delay = if reordered > 0 {
                total_delay as f64 / reordered as f64
            } else {
                0.0
            };
            let reorder_rate = if total_recv > 0 {
                (reordered as f64 / total_recv as f64) * 100.0
            } else {
                0.0
            };

            Some(IsspResequencingTelemetry {
                expected_seq: 0,
                buffer_depth: total_depth,
                buffer_capacity: 256,
                gap_timeout_ms: 150,
                total_received: total_recv,
                in_order_count: in_order,
                reordered_count: reordered,
                duplicate_count: duplicates,
                gaps_expired_count: gaps,
                average_reorder_delay_ms: avg_delay,
                max_reorder_delay_ms: max_delay,
                reorder_rate_percent: reorder_rate,
            })
        }
    }

    /// Configure opportunistic security level and optional key on a subpath tunnel.
    pub fn configure_subpath_security(
        &mut self,
        path_id: u32,
        level: OpportunisticSecurityLevel,
        key: Option<IsspSubpathKey>,
    ) {
        if let Some(route) = self.paths.get_mut(&path_id) {
            route.security_level = level;
        }
        self.subpath_crypto
            .insert(path_id, IsspSubpathCryptoTunnel::new(path_id, level, key));
    }

    /// Configure adaptive header compressor parameters.
    pub fn configure_header_compression(&mut self, refresh_interval: u32) {
        self.header_compressor.refresh_interval = refresh_interval.max(1);
        self.header_decompressor.refresh_interval = refresh_interval.max(1);
    }

    /// Encapsulate a session packet with adaptive header compression and subpath opportunistic encryption.
    pub fn encapsulate_subpath_packet(
        &mut self,
        path_id: u32,
        session_id: &SessionId,
        flags: u16,
        payload: &[u8],
        now_ms: u64,
    ) -> Result<Vec<u8>, SyncError> {
        let route = self
            .paths
            .get_mut(&path_id)
            .ok_or(SyncError::PathNotFound(path_id))?;
        let loss_rate = route.metrics.loss_rate_ppm;

        let sub_seq = self.subpath_seqs.entry(path_id).or_insert(1);
        let curr_sub_seq = *sub_seq;
        *sub_seq += 1;

        let multi_seq = self.next_multipath_seq;
        self.next_multipath_seq += 1;

        let header =
            IsspSessionHeader::new(*session_id, multi_seq, curr_sub_seq, now_ms, flags, path_id);

        let (is_full, header_wire) = self.header_compressor.compress_header(&header, loss_rate);

        let crypto = self
            .subpath_crypto
            .entry(path_id)
            .or_insert_with(|| IsspSubpathCryptoTunnel::new(path_id, route.security_level, None));

        let mut aad = [0u8; 22];
        aad[0..4].copy_from_slice(&path_id.to_le_bytes());
        aad[4..12].copy_from_slice(&multi_seq.to_le_bytes());
        aad[12..20].copy_from_slice(&curr_sub_seq.to_le_bytes());
        aad[20..22].copy_from_slice(&flags.to_le_bytes());

        let (is_enc, nonce_seq, final_payload, auth_tag) = crypto.encrypt_payload(&aad, payload)?;

        route.metrics.total_frames_sent += 1;
        route.metrics.total_bytes_sent += (header_wire.len() + final_payload.len()) as u64;

        let packet = IsspSubpathPacket {
            path_id,
            is_encrypted: is_enc,
            is_compressed: true,
            is_full_header: is_full,
            nonce_seq,
            auth_tag,
            header_wire,
            payload: final_payload,
        };

        Ok(packet.to_bytes())
    }

    /// Decapsulate and decrypt a subpath wire packet, decompressing its session header.
    pub fn decapsulate_subpath_packet(
        &mut self,
        path_id: u32,
        wire_bytes: &[u8],
    ) -> Result<(IsspSessionHeader, Vec<u8>), SyncError> {
        let packet = IsspSubpathPacket::from_bytes(wire_bytes)?;
        if packet.path_id != path_id {
            return Err(SyncError::PathNotFound(packet.path_id));
        }

        let header = self
            .header_decompressor
            .decompress_header(&packet.header_wire)?;

        let route_sec = self
            .paths
            .get(&path_id)
            .map(|r| r.security_level)
            .unwrap_or(OpportunisticSecurityLevel::Plaintext);

        let crypto = self
            .subpath_crypto
            .entry(path_id)
            .or_insert_with(|| IsspSubpathCryptoTunnel::new(path_id, route_sec, None));

        let mut aad = [0u8; 22];
        aad[0..4].copy_from_slice(&path_id.to_le_bytes());
        aad[4..12].copy_from_slice(&header.multipath_seq.to_le_bytes());
        aad[12..20].copy_from_slice(&header.subpath_seq.to_le_bytes());
        aad[20..22].copy_from_slice(&header.flags.to_le_bytes());

        let decrypted_payload = crypto.decrypt_payload(
            packet.is_encrypted,
            packet.nonce_seq,
            &aad,
            &packet.payload,
            packet.auth_tag.as_ref(),
        )?;

        if let Some(route) = self.paths.get_mut(&path_id) {
            route.metrics.total_frames_received += 1;
            route.metrics.total_bytes_received += wire_bytes.len() as u64;
        }

        Ok((header, decrypted_payload))
    }

    /// Retrieve subpath crypto telemetry for a given path ID.
    pub fn subpath_crypto_telemetry(&self, path_id: u32) -> Option<SubpathCryptoTelemetry> {
        self.subpath_crypto
            .get(&path_id)
            .map(|c| SubpathCryptoTelemetry {
                path_id: c.path_id,
                security_level: c.security_level,
                has_key: c.key.is_some(),
                tx_nonce_seq: c.tx_nonce_seq,
                rx_nonce_seq: c.rx_nonce_seq,
                packets_encrypted: c.packets_encrypted,
                packets_decrypted: c.packets_decrypted,
                bytes_encrypted: c.bytes_encrypted,
                auth_failures: c.auth_failures,
                replay_drops: c.replay_drops,
                plain_transmissions: c.plain_transmissions,
            })
    }

    /// Retrieve adaptive header compression telemetry report.
    pub fn header_compression_telemetry(&self) -> IsspHeaderCompressionTelemetry {
        self.header_compressor.telemetry()
    }
}

// ---------------------------------------------------------------------------
// Session Tick Configuration & Outcome
// ---------------------------------------------------------------------------

/// Configuration for periodic session tick processing in the ISSP pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionTickConfig {
    /// Interval in seconds between periodic snapshot broadcasts for primary sessions.
    /// Default: 1 second.
    pub snapshot_interval_secs: u64,
    /// Threshold of silence in seconds from the primary node before a standby replica
    /// initiates automatic transparent migration.
    /// Default: 2 seconds.
    pub primary_silence_threshold_secs: u64,
    /// Whether standby nodes should automatically trigger migration when the primary is silent.
    /// Default: true.
    pub auto_migrate_on_silence: bool,
    /// Threshold in seconds after which completely abandoned/unmigratable sessions are pruned.
    /// Default: 10 seconds.
    pub stale_eviction_secs: u64,
}

impl Default for SessionTickConfig {
    fn default() -> Self {
        Self {
            snapshot_interval_secs: 1,
            primary_silence_threshold_secs: 2,
            auto_migrate_on_silence: true,
            stale_eviction_secs: 10,
        }
    }
}

/// Outcome produced during an ISSP session tick cycle.
#[derive(Debug, Clone)]
pub struct SessionTickOutcome {
    /// Outbound plaintext gossip frames generated for primary sessions requiring sync.
    pub outbound_plaintext_frames: Vec<GossipFrame>,
    /// Outbound secure AEAD gossip frames generated (if PSK is configured).
    pub outbound_secure_frames: Vec<[u8; SECURE_GOSSIP_FRAME_SIZE]>,
    /// Outbound capsules ready for transmission over the capsule transport pipeline.
    pub outbound_capsules: Vec<IsspCapsule>,
    /// Sessions that were automatically migrated to this node due to primary silence.
    pub auto_migrated_sessions: Vec<SessionSnapshot>,
    /// Stale session IDs evicted from the registry during this tick.
    pub evicted_sessions: Vec<SessionId>,
    /// Multipath path failover events triggered by heartbeat timeouts.
    pub multipath_failover_events: Vec<IsspFailoverEvent>,
}

// ---------------------------------------------------------------------------
// Local session registry
// ---------------------------------------------------------------------------

/// Per-session live record tracked by the local node.
#[derive(Debug, Clone)]
pub struct SessionRecord {
    /// Most recent snapshot of this session.
    pub snapshot: SessionSnapshot,
    /// Monotonic instant of last snapshot capture.
    pub last_captured: Instant,
    /// Whether this session is currently owned (primary) or shadow-replicated.
    pub is_primary: bool,
}

/// Global session state registry for a single node in the cluster.
pub struct SessionRegistry {
    /// Node's own identifier.
    pub node_id: u32,
    /// Live sessions keyed by SessionId.
    sessions: Mutex<HashMap<SessionId, SessionRecord>>,
    /// Configured cluster pre-shared key for encryption/auth.
    pub psk: Option<ClusterPsk>,
    /// Cluster security enforcement policy.
    pub policy: SecurityPolicy,
    /// Sequence counter for outgoing secure gossip frames.
    tx_nonce_seq: AtomicU64,
    /// Highest sequence number observed per peer node (anti-replay).
    peer_last_seq: Mutex<HashMap<u32, u64>>,
    /// Count of migrations performed by this node (exported to telemetry).
    pub migration_count: AtomicU64,
    /// Count of snapshot gossip messages received.
    pub gossip_rx_count: AtomicU64,
    /// Count of stale / rejected gossip messages (CRC fail or old epoch).
    pub gossip_rejected_count: AtomicU64,
    /// Count of frames rejected due to authentication/crypto failure.
    pub gossip_auth_failed_count: AtomicU64,
    /// Count of frames rejected due to replay detection.
    pub gossip_replay_failed_count: AtomicU64,
    /// Dynamic multipath routing engine managing multiple candidate paths and heartbeat failovers.
    pub multipath_router: Mutex<IsspDynamicMultipathRouter>,
}

impl SessionRegistry {
    /// Create a new registry for the given node with default permissive policy and no PSK.
    pub fn new(node_id: u32) -> Arc<Self> {
        Arc::new(Self {
            node_id,
            sessions: Mutex::new(HashMap::new()),
            psk: None,
            policy: SecurityPolicy::Permissive,
            tx_nonce_seq: AtomicU64::new(1),
            peer_last_seq: Mutex::new(HashMap::new()),
            migration_count: AtomicU64::new(0),
            gossip_rx_count: AtomicU64::new(0),
            gossip_rejected_count: AtomicU64::new(0),
            gossip_auth_failed_count: AtomicU64::new(0),
            gossip_replay_failed_count: AtomicU64::new(0),
            multipath_router: Mutex::new(IsspDynamicMultipathRouter::new(
                node_id,
                IsspRoutingPolicy::ActiveStandby,
            )),
        })
    }

    /// Create a new registry hardened with a cluster Pre-Shared Key (PSK) and security policy.
    pub fn with_psk(node_id: u32, psk: ClusterPsk, policy: SecurityPolicy) -> Arc<Self> {
        Arc::new(Self {
            node_id,
            sessions: Mutex::new(HashMap::new()),
            psk: Some(psk),
            policy,
            tx_nonce_seq: AtomicU64::new(1),
            peer_last_seq: Mutex::new(HashMap::new()),
            migration_count: AtomicU64::new(0),
            gossip_rx_count: AtomicU64::new(0),
            gossip_rejected_count: AtomicU64::new(0),
            gossip_auth_failed_count: AtomicU64::new(0),
            gossip_replay_failed_count: AtomicU64::new(0),
            multipath_router: Mutex::new(IsspDynamicMultipathRouter::new(
                node_id,
                IsspRoutingPolicy::ActiveStandby,
            )),
        })
    }

    /// Register or update a primary session owned by this node.
    pub fn upsert_primary(&self, snapshot: SessionSnapshot) -> Result<(), SyncError> {
        let mut guard = self.sessions.lock().map_err(|_| SyncError::LockPoisoned)?;
        if guard.len() >= MAX_SESSIONS && !guard.contains_key(&snapshot.id) {
            return Err(SyncError::RegistryFull);
        }
        guard.insert(
            snapshot.id,
            SessionRecord {
                snapshot,
                last_captured: Instant::now(),
                is_primary: true,
            },
        );
        Ok(())
    }

    /// Apply a received gossip snapshot from a peer.  The snapshot is accepted
    /// only if its `migration_epoch` is strictly greater than the locally known
    /// epoch for that session (or the session is unknown).
    pub fn apply_gossip(&self, frame: &GossipFrame) -> GossipResult {
        self.gossip_rx_count.fetch_add(1, Ordering::Relaxed);

        if frame.sender_node_id == self.node_id {
            // Ignore self-gossip (loop-back prevention).
            return GossipResult::Ignored;
        }

        let mut guard = match self.sessions.lock() {
            Ok(g) => g,
            Err(_) => {
                self.gossip_rejected_count.fetch_add(1, Ordering::Relaxed);
                return GossipResult::Rejected(RejectReason::LockFailed);
            }
        };

        let snap = &frame.snapshot;

        if let Some(record) = guard.get_mut(&snap.id) {
            if snap.migration_epoch < record.snapshot.migration_epoch {
                self.gossip_rejected_count.fetch_add(1, Ordering::Relaxed);
                return GossipResult::Rejected(RejectReason::StaleEpoch {
                    local: record.snapshot.migration_epoch,
                    received: snap.migration_epoch,
                });
            }

            if snap.migration_epoch == record.snapshot.migration_epoch {
                if record.is_primary {
                    // Local node is primary for this epoch: reject conflicting gossip for same epoch
                    self.gossip_rejected_count.fetch_add(1, Ordering::Relaxed);
                    return GossipResult::Rejected(RejectReason::StaleEpoch {
                        local: record.snapshot.migration_epoch,
                        received: snap.migration_epoch,
                    });
                }

                // Shadow replica tracking primary progress: update snapshot on non-decreasing sequence / time
                if snap.tx_seq >= record.snapshot.tx_seq
                    || snap.captured_unix_secs >= record.snapshot.captured_unix_secs
                {
                    record.snapshot = *snap;
                    record.last_captured = Instant::now();
                    return GossipResult::Updated;
                }
                return GossipResult::Ignored;
            }

            // Accept fresher epoch — demote ourselves to shadow.
            record.snapshot = *snap;
            record.last_captured = Instant::now();
            record.is_primary = false;
            GossipResult::Updated
        } else {
            // New session seen for the first time.
            if guard.len() >= MAX_SESSIONS {
                self.gossip_rejected_count.fetch_add(1, Ordering::Relaxed);
                return GossipResult::Rejected(RejectReason::RegistryFull);
            }
            guard.insert(
                snap.id,
                SessionRecord {
                    snapshot: *snap,
                    last_captured: Instant::now(),
                    is_primary: false,
                },
            );
            GossipResult::Inserted
        }
    }

    /// Trigger a **transparent migration**: take ownership of a shadow session.
    ///
    /// The caller supplies the `session_id` of the session to migrate and the
    /// current Unix epoch seconds for staleness validation.  On success, returns
    /// the updated snapshot with an incremented `migration_epoch` that the caller
    /// must immediately propagate to peers.
    pub fn migrate_session(
        &self,
        session_id: SessionId,
        now_unix_secs: u64,
    ) -> Result<SessionSnapshot, SyncError> {
        let mut guard = self.sessions.lock().map_err(|_| SyncError::LockPoisoned)?;

        let record = guard
            .get_mut(&session_id)
            .ok_or(SyncError::SessionNotFound)?;

        // Reject stale snapshots — do not resume a session with ancient state.
        let age_secs = now_unix_secs.saturating_sub(record.snapshot.captured_unix_secs);
        if age_secs > SNAPSHOT_MAX_AGE.as_secs() {
            return Err(SyncError::SnapshotStale { age_secs });
        }

        if record.is_primary {
            return Err(SyncError::AlreadyPrimary);
        }

        // Bump migration epoch — this acts as a fencing token.
        record.snapshot.migration_epoch += 1;
        record.snapshot.captured_unix_secs = now_unix_secs;
        record.is_primary = true;
        self.migration_count.fetch_add(1, Ordering::Relaxed);

        Ok(record.snapshot)
    }

    /// Produce a gossip frame for the given session (primary or shadow) for
    /// broadcasting to peers.
    pub fn build_gossip_frame(&self, session_id: &SessionId) -> Option<GossipFrame> {
        let guard = self.sessions.lock().ok()?;
        let record = guard.get(session_id)?;
        Some(GossipFrame {
            sender_node_id: self.node_id,
            snapshot: record.snapshot,
        })
    }

    /// Collect IDs of sessions whose snapshot is older than `max_age` for
    /// eviction or re-gossip triggering.
    pub fn stale_sessions(&self, max_age: Duration) -> Vec<SessionId> {
        let guard = match self.sessions.lock() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };
        let now = Instant::now();
        guard
            .iter()
            .filter(|(_, r)| now.duration_since(r.last_captured) > max_age)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Remove a session that has been fully torn down.
    pub fn remove_session(&self, session_id: &SessionId) -> bool {
        let mut guard = match self.sessions.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        guard.remove(session_id).is_some()
    }

    /// Count of active sessions (primary + shadow).
    pub fn session_count(&self) -> usize {
        self.sessions.lock().map(|g| g.len()).unwrap_or(0)
    }

    /// Produce an encrypted, authenticated gossip frame (v2) for the given session.
    ///
    /// Returns `None` if the session is not found or if no PSK is configured.
    pub fn build_secure_gossip_frame(
        &self,
        session_id: &SessionId,
    ) -> Option<[u8; SECURE_GOSSIP_FRAME_SIZE]> {
        let psk = self.psk.as_ref()?;
        let guard = self.sessions.lock().ok()?;
        let record = guard.get(session_id)?;
        let nonce_seq = self.tx_nonce_seq.fetch_add(1, Ordering::Relaxed);
        let frame = SecureGossipFrame {
            sender_node_id: self.node_id,
            nonce_seq,
            snapshot: record.snapshot,
        };
        Some(frame.encode(psk))
    }

    /// Apply an encrypted gossip frame received from a peer node.
    pub fn apply_secure_gossip(
        &self,
        raw: &[u8; SECURE_GOSSIP_FRAME_SIZE],
    ) -> Result<GossipResult, SecurityError> {
        let psk = self.psk.as_ref().ok_or(SecurityError::PolicyViolation)?;
        let frame = match SecureGossipFrame::decode(raw, psk) {
            Ok(f) => f,
            Err(e) => {
                self.gossip_auth_failed_count
                    .fetch_add(1, Ordering::Relaxed);
                return Err(e);
            }
        };

        if frame.sender_node_id == self.node_id {
            return Ok(GossipResult::Ignored);
        }

        // Anti-replay check
        {
            let mut peer_map = self
                .peer_last_seq
                .lock()
                .map_err(|_| SecurityError::LockFailed)?;
            if let Some(&last_seq) = peer_map.get(&frame.sender_node_id) {
                if frame.nonce_seq <= last_seq {
                    self.gossip_replay_failed_count
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(SecurityError::ReplayDetected {
                        last_seq,
                        received_seq: frame.nonce_seq,
                    });
                }
            }
            peer_map.insert(frame.sender_node_id, frame.nonce_seq);
        }

        let unencrypted = GossipFrame {
            sender_node_id: frame.sender_node_id,
            snapshot: frame.snapshot,
        };
        Ok(self.apply_gossip(&unencrypted))
    }

    /// Universal ingest for raw gossip datagrams received over the control UDP socket.
    /// Automatically distinguishes v1 plaintext (112 bytes) and v2 encrypted (136 bytes) frames,
    /// enforcing the configured cluster security policy.
    pub fn apply_raw_gossip(&self, slice: &[u8]) -> Result<GossipResult, RawGossipError> {
        match slice.len() {
            SECURE_GOSSIP_FRAME_SIZE => {
                let raw_arr: &[u8; SECURE_GOSSIP_FRAME_SIZE] = slice.try_into().unwrap();
                if self.psk.is_none() {
                    return Err(RawGossipError::NoPskConfigured);
                }
                self.apply_secure_gossip(raw_arr)
                    .map_err(RawGossipError::Security)
            }
            GOSSIP_FRAME_SIZE => {
                if self.policy == SecurityPolicy::StrictPsk {
                    return Err(RawGossipError::Security(SecurityError::PolicyViolation));
                }
                let raw_arr: &[u8; GOSSIP_FRAME_SIZE] = slice.try_into().unwrap();
                let frame =
                    GossipFrame::decode(raw_arr).ok_or(RawGossipError::CorruptedPlaintext)?;
                let res = self.apply_gossip(&frame);
                match res {
                    GossipResult::Rejected(r) => Err(RawGossipError::Registry(r)),
                    other => Ok(other),
                }
            }
            other_len => Err(RawGossipError::InvalidLength(other_len)),
        }
    }

    /// Export telemetry snapshot for Prometheus / OpenTelemetry exporters.
    pub fn telemetry_snapshot(&self) -> SyncTelemetry {
        SyncTelemetry {
            node_id: self.node_id,
            session_count: self.session_count() as u64,
            migration_count: self.migration_count.load(Ordering::Relaxed),
            gossip_rx_count: self.gossip_rx_count.load(Ordering::Relaxed),
            gossip_rejected_count: self.gossip_rejected_count.load(Ordering::Relaxed),
            gossip_auth_failed_count: self.gossip_auth_failed_count.load(Ordering::Relaxed),
            gossip_replay_failed_count: self.gossip_replay_failed_count.load(Ordering::Relaxed),
        }
    }

    /// Produce an ISSP capsule frame for encapsulation in RFC 9297 HTTP tunnels.
    ///
    /// Encapsulates a v2 encrypted frame if a PSK is configured, otherwise falls back to a v1 plaintext frame.
    pub fn build_issp_capsule(&self, session_id: &SessionId) -> Option<IsspCapsule> {
        if self.psk.is_some() {
            let enc = self.build_secure_gossip_frame(session_id)?;
            Some(IsspCapsule::from_secure_frame(self.node_id, &enc))
        } else {
            let plain = self.build_gossip_frame(session_id)?;
            Some(IsspCapsule::from_gossip_frame(&plain))
        }
    }

    /// Ingest an ISSP capsule received from an RFC 9297 HTTP tunnel, enforcing security policies.
    pub fn ingest_issp_capsule(
        &self,
        capsule: &IsspCapsule,
    ) -> Result<GossipResult, RawGossipError> {
        self.apply_raw_gossip(&capsule.payload)
    }

    /// Periodic tick hook evaluating session progress, triggering auto-migration upon primary silence,
    /// and generating snapshots for active primary sessions.
    ///
    /// - For primary sessions: generates periodic snapshot gossip frames and capsules whenever
    ///   `elapsed >= config.snapshot_interval_secs`.
    /// - For shadow/standby sessions: detects silence of the primary node (`silence_age >= config.primary_silence_threshold_secs`).
    ///   If `config.auto_migrate_on_silence` is true and the snapshot is not stale (< `config.stale_eviction_secs`),
    ///   the session is transparently promoted to primary with an incremented migration epoch,
    ///   and an immediate cutover frame/capsule is generated for cluster broadcast.
    /// - Stale sessions exceeding `config.stale_eviction_secs` are pruned.
    pub fn on_session_tick(
        &self,
        now_unix_secs: u64,
        config: &SessionTickConfig,
    ) -> Result<SessionTickOutcome, SyncError> {
        let mut guard = self.sessions.lock().map_err(|_| SyncError::LockPoisoned)?;

        let mut outbound_plaintext_frames = Vec::new();
        let mut outbound_secure_frames = Vec::new();
        let mut outbound_capsules = Vec::new();
        let mut auto_migrated_sessions = Vec::new();
        let mut to_evict = Vec::new();

        for (&session_id, record) in guard.iter_mut() {
            if record.is_primary {
                // Periodic snapshot for primary sessions
                let elapsed = now_unix_secs.saturating_sub(record.snapshot.captured_unix_secs);
                if elapsed >= config.snapshot_interval_secs {
                    record.snapshot.captured_unix_secs = now_unix_secs;
                    record.last_captured = Instant::now();

                    if let Some(psk) = self.psk.as_ref() {
                        let nonce_seq = self.tx_nonce_seq.fetch_add(1, Ordering::Relaxed);
                        let frame = SecureGossipFrame {
                            sender_node_id: self.node_id,
                            nonce_seq,
                            snapshot: record.snapshot,
                        };
                        let enc = frame.encode(psk);
                        outbound_secure_frames.push(enc);
                        outbound_capsules.push(IsspCapsule::from_secure_frame(self.node_id, &enc));
                    } else {
                        let frame = GossipFrame {
                            sender_node_id: self.node_id,
                            snapshot: record.snapshot,
                        };
                        outbound_plaintext_frames.push(frame);
                        outbound_capsules.push(IsspCapsule::from_gossip_frame(&frame));
                    }
                }
            } else {
                // Standby / shadow session: check for primary silence
                let silence_age = now_unix_secs.saturating_sub(record.snapshot.captured_unix_secs);
                if config.auto_migrate_on_silence
                    && silence_age >= config.primary_silence_threshold_secs
                    && silence_age < config.stale_eviction_secs
                {
                    // Primary is silent: trigger automatic transparent migration
                    record.snapshot.migration_epoch += 1;
                    record.snapshot.captured_unix_secs = now_unix_secs;
                    record.is_primary = true;
                    record.last_captured = Instant::now();
                    self.migration_count.fetch_add(1, Ordering::Relaxed);

                    auto_migrated_sessions.push(record.snapshot);

                    // Immediately broadcast cutover / takeover announcement to cluster
                    if let Some(psk) = self.psk.as_ref() {
                        let nonce_seq = self.tx_nonce_seq.fetch_add(1, Ordering::Relaxed);
                        let frame = SecureGossipFrame {
                            sender_node_id: self.node_id,
                            nonce_seq,
                            snapshot: record.snapshot,
                        };
                        let enc = frame.encode(psk);
                        outbound_secure_frames.push(enc);
                        outbound_capsules.push(IsspCapsule::from_secure_frame(self.node_id, &enc));
                    } else {
                        let frame = GossipFrame {
                            sender_node_id: self.node_id,
                            snapshot: record.snapshot,
                        };
                        outbound_plaintext_frames.push(frame);
                        outbound_capsules.push(IsspCapsule::from_gossip_frame(&frame));
                    }
                } else if silence_age >= config.stale_eviction_secs {
                    to_evict.push(session_id);
                }
            }
        }

        for id in &to_evict {
            guard.remove(id);
        }

        let multipath_failover_events = if let Ok(mut router) = self.multipath_router.lock() {
            router.evaluate_heartbeats_and_failover(now_unix_secs * 1000)
        } else {
            Vec::new()
        };

        Ok(SessionTickOutcome {
            outbound_plaintext_frames,
            outbound_secure_frames,
            outbound_capsules,
            auto_migrated_sessions,
            evicted_sessions: to_evict,
            multipath_failover_events,
        })
    }

    /// List all registered sessions (both primary and standby), sorted deterministically by flow hash.
    pub fn list_sessions(&self) -> Vec<SessionRecord> {
        let guard = match self.sessions.lock() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };
        let mut list: Vec<SessionRecord> = guard.values().cloned().collect();
        list.sort_by_key(|a| a.snapshot.id.flow_hash);
        list
    }

    /// Retrieve a specific session record by its exact `SessionId`.
    pub fn get_session(&self, id: &SessionId) -> Option<SessionRecord> {
        let guard = self.sessions.lock().ok()?;
        guard.get(id).cloned()
    }

    /// Find a session by string query (exact canonical ID, flow hash hex, or flow hash decimal).
    pub fn find_session(&self, query: &str) -> Option<SessionRecord> {
        let trimmed = query.trim();
        let guard = self.sessions.lock().ok()?;

        // 1. Try canonical parse
        if let Ok(parsed_id) = SessionId::parse_str(trimmed) {
            if let Some(rec) = guard.get(&parsed_id) {
                return Some(rec.clone());
            }
        }

        let s_clean = trimmed.strip_prefix("0x").unwrap_or(trimmed);
        let parsed_hex_hash = u64::from_str_radix(s_clean, 16).ok();
        let parsed_dec_hash = trimmed.parse::<u64>().ok();

        // 2. Try match on string display, flow hash value, or prefix/suffix
        for (id, rec) in guard.iter() {
            let canon = id.to_canonical_string();
            if canon.eq_ignore_ascii_case(trimmed) {
                return Some(rec.clone());
            }
            if let Some(target) = parsed_hex_hash {
                if id.flow_hash == target {
                    return Some(rec.clone());
                }
            }
            if let Some(target) = parsed_dec_hash {
                if id.flow_hash == target {
                    return Some(rec.clone());
                }
            }
            let hex_hash = format!("{:016x}", id.flow_hash);
            if hex_hash.eq_ignore_ascii_case(s_clean) || hex_hash.ends_with(s_clean) {
                return Some(rec.clone());
            }
        }

        None
    }

    /// Export all sessions and registry state into a deterministic binary state dump.
    pub fn export_state_dump(&self) -> Vec<u8> {
        let guard = match self.sessions.lock() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };

        let mut out = Vec::with_capacity(ISSP_DUMP_HEADER_SIZE + guard.len() * 97);
        // Header
        out.extend_from_slice(&ISSP_DUMP_MAGIC.to_be_bytes());
        out.extend_from_slice(&ISSP_DUMP_VERSION_V1.to_be_bytes());
        out.extend_from_slice(&self.node_id.to_be_bytes());
        let policy_byte = match self.policy {
            SecurityPolicy::StrictPsk => 0u8,
            SecurityPolicy::Permissive => 1u8,
            SecurityPolicy::PlaintextOnly => 2u8,
        };
        out.push(policy_byte);
        out.extend_from_slice(&(guard.len() as u32).to_be_bytes());
        out.extend_from_slice(&[0u8; 15]); // Reserved padding

        // Sessions sorted by flow_hash for determinism
        let mut records: Vec<&SessionRecord> = guard.values().collect();
        records.sort_by_key(|a| a.snapshot.id.flow_hash);

        for r in records {
            out.push(if r.is_primary { 1 } else { 0 });
            out.extend_from_slice(&r.snapshot.to_wire());
        }

        out
    }

    /// Import and reconstruct a `SessionRegistry` from a binary state dump.
    pub fn import_state_dump(bytes: &[u8]) -> Result<Arc<Self>, SyncError> {
        if bytes.len() < ISSP_DUMP_HEADER_SIZE {
            return Err(SyncError::InvalidDumpLength(bytes.len()));
        }

        let magic = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
        if magic != ISSP_DUMP_MAGIC {
            return Err(SyncError::BadDumpMagic);
        }

        let version = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
        if version != ISSP_DUMP_VERSION_V1 {
            return Err(SyncError::UnsupportedDumpVersion(version));
        }

        let node_id = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
        let policy = match bytes[12] {
            0 => SecurityPolicy::StrictPsk,
            1 => SecurityPolicy::Permissive,
            _ => SecurityPolicy::PlaintextOnly,
        };
        let count = u32::from_be_bytes(bytes[13..17].try_into().unwrap()) as usize;

        let expected_len = ISSP_DUMP_HEADER_SIZE + count * 97;
        if bytes.len() < expected_len {
            return Err(SyncError::InvalidDumpLength(bytes.len()));
        }

        let registry = Arc::new(Self {
            node_id,
            sessions: Mutex::new(HashMap::new()),
            psk: None,
            policy,
            tx_nonce_seq: AtomicU64::new(1),
            peer_last_seq: Mutex::new(HashMap::new()),
            migration_count: AtomicU64::new(0),
            gossip_rx_count: AtomicU64::new(0),
            gossip_rejected_count: AtomicU64::new(0),
            gossip_auth_failed_count: AtomicU64::new(0),
            gossip_replay_failed_count: AtomicU64::new(0),
            multipath_router: Mutex::new(IsspDynamicMultipathRouter::new(
                node_id,
                IsspRoutingPolicy::ActiveStandby,
            )),
        });
        let mut reg_guard = registry
            .sessions
            .lock()
            .map_err(|_| SyncError::LockPoisoned)?;

        let mut offset = ISSP_DUMP_HEADER_SIZE;
        for _ in 0..count {
            let is_primary = bytes[offset] != 0;
            offset += 1;
            let wire_bytes: &[u8; 96] = bytes[offset..offset + 96].try_into().unwrap();
            offset += 96;
            let snap = SessionSnapshot::from_wire(wire_bytes);
            reg_guard.insert(
                snap.id,
                SessionRecord {
                    snapshot: snap,
                    last_captured: Instant::now(),
                    is_primary,
                },
            );
        }

        drop(reg_guard);
        Ok(registry)
    }

    /// Save state dump atomically to file on disk.
    pub fn save_to_file(&self, path: &std::path::Path) -> std::io::Result<()> {
        let data = self.export_state_dump();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, data)
    }

    /// Load registry state dump from file.
    pub fn load_from_file(path: &std::path::Path) -> Result<Arc<Self>, SyncError> {
        let bytes = std::fs::read(path).map_err(|_| SyncError::SessionNotFound)?;
        Self::import_state_dump(&bytes)
    }

    /// Register a transport path into the dynamic multipath router.
    pub fn add_multipath_route(&self, route: IsspMultipathRoute) -> Result<(), SyncError> {
        let mut router = self
            .multipath_router
            .lock()
            .map_err(|_| SyncError::LockPoisoned)?;
        router.add_route(route);
        Ok(())
    }

    /// List all registered transport paths and their real-time telemetry.
    pub fn list_multipath_routes(&self) -> Result<Vec<IsspMultipathRoute>, SyncError> {
        let router = self
            .multipath_router
            .lock()
            .map_err(|_| SyncError::LockPoisoned)?;
        Ok(router.list_routes())
    }

    /// Resolve optimal transport path for a session according to current multipath routing policy.
    pub fn resolve_session_path(
        &self,
        session_id: &SessionId,
        now_ms: u64,
    ) -> Result<u32, SyncError> {
        let mut router = self
            .multipath_router
            .lock()
            .map_err(|_| SyncError::LockPoisoned)?;
        router.resolve_path_for_session(session_id, now_ms)
    }

    /// Generate a keep-alive heartbeat probe ping for a specific path.
    pub fn create_heartbeat_probe(
        &self,
        path_id: u32,
        now_ms: u64,
    ) -> Result<IsspHeartbeatProbe, SyncError> {
        let mut router = self
            .multipath_router
            .lock()
            .map_err(|_| SyncError::LockPoisoned)?;
        router.create_heartbeat_ping(path_id, now_ms)
    }

    /// Ingest a heartbeat probe (ping or pong) and update path RTT / liveness telemetry.
    pub fn handle_heartbeat_probe(
        &self,
        probe: &IsspHeartbeatProbe,
        now_ms: u64,
    ) -> Result<Option<IsspHeartbeatProbe>, SyncError> {
        let mut router = self
            .multipath_router
            .lock()
            .map_err(|_| SyncError::LockPoisoned)?;
        router.process_heartbeat_probe(probe, now_ms)
    }

    /// Retrieve full multipath routing telemetry report.
    pub fn multipath_telemetry(&self) -> Result<IsspMultipathTelemetry, SyncError> {
        let router = self
            .multipath_router
            .lock()
            .map_err(|_| SyncError::LockPoisoned)?;
        Ok(router.telemetry())
    }

    /// Schedule a packet for multipath transmission according to current routing and aggregation policy.
    pub fn schedule_multipath_packet(
        &self,
        session_id: &SessionId,
        payload: Vec<u8>,
        now_ms: u64,
    ) -> Result<IsspScheduledPacket, SyncError> {
        let mut router = self
            .multipath_router
            .lock()
            .map_err(|_| SyncError::LockPoisoned)?;
        router.schedule_packet(session_id, payload, now_ms)
    }

    /// Ingest an incoming multipath packet into the per-session resequencing buffer.
    pub fn ingest_multipath_packet(
        &self,
        packet: IsspScheduledPacket,
        now_ms: u64,
    ) -> Result<(Vec<IsspDeliveredPacket>, IsspResequenceStatus), SyncError> {
        let mut router = self
            .multipath_router
            .lock()
            .map_err(|_| SyncError::LockPoisoned)?;
        Ok(router.ingest_multipath_packet(packet, now_ms))
    }

    /// Check resequencing gap timeouts and return flushed packets.
    pub fn check_resequencing_timeouts(
        &self,
        now_ms: u64,
    ) -> Result<Vec<(SessionId, Vec<IsspDeliveredPacket>, IsspResequenceStatus)>, SyncError> {
        let mut router = self
            .multipath_router
            .lock()
            .map_err(|_| SyncError::LockPoisoned)?;
        Ok(router.check_resequencing_timeouts(now_ms))
    }

    /// Retrieve resequencing telemetry metrics for a specific session or cluster aggregated.
    pub fn resequencing_telemetry(
        &self,
        session_id: Option<&SessionId>,
    ) -> Result<Option<IsspResequencingTelemetry>, SyncError> {
        let router = self
            .multipath_router
            .lock()
            .map_err(|_| SyncError::LockPoisoned)?;
        Ok(router.resequencing_telemetry(session_id))
    }

    /// Configure route flap damping parameters.
    pub fn configure_multipath_flap_damping(
        &self,
        config: IsspFlapDampingConfig,
    ) -> Result<(), SyncError> {
        let mut router = self
            .multipath_router
            .lock()
            .map_err(|_| SyncError::LockPoisoned)?;
        router.flap_damping_config = config;
        Ok(())
    }

    /// Configure path probation parameters.
    pub fn configure_multipath_probation(
        &self,
        config: IsspProbationConfig,
    ) -> Result<(), SyncError> {
        let mut router = self
            .multipath_router
            .lock()
            .map_err(|_| SyncError::LockPoisoned)?;
        router.probation_config = config;
        Ok(())
    }

    /// Retrieve flap history events.
    pub fn multipath_flap_history(&self) -> Result<Vec<IsspFlapEvent>, SyncError> {
        let router = self
            .multipath_router
            .lock()
            .map_err(|_| SyncError::LockPoisoned)?;
        Ok(router.flap_history().to_vec())
    }

    /// Retrieve path reintegration history events.
    pub fn multipath_reintegration_history(
        &self,
    ) -> Result<Vec<IsspReintegrationEvent>, SyncError> {
        let router = self
            .multipath_router
            .lock()
            .map_err(|_| SyncError::LockPoisoned)?;
        Ok(router.reintegration_history().to_vec())
    }

    /// Configure the active multipath routing and load-balancing policy.
    pub fn set_multipath_routing_policy(&self, policy: IsspRoutingPolicy) -> Result<(), SyncError> {
        let mut router = self
            .multipath_router
            .lock()
            .map_err(|_| SyncError::LockPoisoned)?;
        router.policy = policy;
        Ok(())
    }

    /// Update congestion feedback for a multipath route (BBR bottleneck estimation + LEDBAT gradient delay).
    pub fn update_congestion_feedback(
        &self,
        path_id: u32,
        rtt_us: u64,
        lost_bytes: u64,
        delivered_bytes: u64,
    ) -> Result<f64, SyncError> {
        let mut router = self
            .multipath_router
            .lock()
            .map_err(|_| SyncError::LockPoisoned)?;
        router.update_congestion_feedback(path_id, rtt_us, lost_bytes, delivered_bytes)
    }

    /// Retrieve per-subpath bandwidth estimates for all registered routes.
    pub fn bandwidth_estimates(&self) -> Result<Vec<(u32, IsspBandwidthEstimate)>, SyncError> {
        let router = self
            .multipath_router
            .lock()
            .map_err(|_| SyncError::LockPoisoned)?;
        Ok(router.bandwidth_estimates())
    }

    /// Retrieve bandwidth estimate for a specific route.
    pub fn path_bandwidth_estimate(
        &self,
        path_id: u32,
    ) -> Result<IsspBandwidthEstimate, SyncError> {
        let router = self
            .multipath_router
            .lock()
            .map_err(|_| SyncError::LockPoisoned)?;
        router.path_bandwidth_estimate(path_id)
    }

    /// Retrieve real-time dynamic multipath balancing telemetry snapshot.
    pub fn multipath_balancing_snapshot(
        &self,
        timestamp_unix_ns: u64,
    ) -> Result<crate::telemetry::IsspMultipathBalancingSnapshot, SyncError> {
        let router = self
            .multipath_router
            .lock()
            .map_err(|_| SyncError::LockPoisoned)?;
        Ok(router.balancing_snapshot(timestamp_unix_ns))
    }

    /// Handle an HTTP metrics endpoint request (`/metrics`, `/v1/metrics`, `/healthz`) for dynamic multipath balancing telemetry.
    ///
    /// Returns `(http_status_code, content_type_header, response_body_string)`.
    pub fn handle_multipath_http_metrics(
        &self,
        path: &str,
        accept_header: &str,
        service_name: &str,
        timestamp_unix_ns: u64,
    ) -> (u16, &'static str, String) {
        let handler = crate::telemetry::IsspTelemetryHttpHandler::new(service_name);
        match self.multipath_balancing_snapshot(timestamp_unix_ns) {
            Ok(snap) => handler.handle_snapshot(path, accept_header, &snap),
            Err(_) => (
                500,
                "text/plain; charset=utf-8",
                "Error collecting multipath balancing telemetry\n".to_string(),
            ),
        }
    }

    /// Create and bind a lightweight HTTP telemetry server exposing multipath balancing metrics.
    pub fn create_telemetry_server(
        self: &std::sync::Arc<Self>,
        bind_addr: &str,
        service_name: &str,
    ) -> std::io::Result<crate::telemetry::IsspTelemetryServer> {
        crate::telemetry::IsspTelemetryServer::bind(
            bind_addr,
            service_name,
            std::sync::Arc::clone(self),
        )
    }
}

// ---------------------------------------------------------------------------
// Result types & Security definitions
// ---------------------------------------------------------------------------

/// Security enforcement policy for ISSP cluster gossip frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SecurityPolicy {
    /// Strict: only encrypted/authenticated v2 frames are accepted and emitted.
    StrictPsk,
    /// Permissive: accepts both encrypted v2 and unencrypted v1 frames (for rolling cluster upgrades).
    #[default]
    Permissive,
    /// PlaintextOnly: legacy mode without encryption or authentication.
    PlaintextOnly,
}

/// Cryptographic or authentication error during ISSP gossip processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityError {
    /// Frame magic does not match ISSP_MAGIC.
    BadMagic,
    /// Wire protocol version is not recognized.
    UnsupportedVersion(u32),
    /// Authentication tag mismatch (wrong PSK, tampered header, or corrupted ciphertext).
    AuthenticationFailed,
    /// Detected replayed gossip frame with non-increasing sequence number.
    ReplayDetected { last_seq: u64, received_seq: u64 },
    /// Operation violated configured cluster security policy.
    PolicyViolation,
    /// Internal lock poisoned.
    LockFailed,
}

impl std::fmt::Display for SecurityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecurityError::BadMagic => write!(f, "invalid ISSP magic tag"),
            SecurityError::UnsupportedVersion(v) => write!(f, "unsupported ISSP version {v}"),
            SecurityError::AuthenticationFailed => write!(f, "cluster PSK authentication failed"),
            SecurityError::ReplayDetected {
                last_seq,
                received_seq,
            } => {
                write!(
                    f,
                    "gossip replay detected: received seq {received_seq} <= last seen {last_seq}"
                )
            }
            SecurityError::PolicyViolation => {
                write!(f, "cluster security policy rejected unencrypted frame")
            }
            SecurityError::LockFailed => write!(f, "internal security state lock poisoned"),
        }
    }
}

impl std::error::Error for SecurityError {}

/// Error returned when processing raw wire gossip bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawGossipError {
    /// Security or authentication error.
    Security(SecurityError),
    /// No PSK configured on this node, but an encrypted v2 frame was received.
    NoPskConfigured,
    /// Length of the raw buffer matches neither v1 (112) nor v2 (136).
    InvalidLength(usize),
    /// Plaintext frame CRC check failed.
    CorruptedPlaintext,
    /// Registry operation rejected the frame.
    Registry(RejectReason),
}

impl std::fmt::Display for RawGossipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RawGossipError::Security(e) => write!(f, "security error: {e}"),
            RawGossipError::NoPskConfigured => {
                write!(f, "received encrypted frame but no PSK configured")
            }
            RawGossipError::InvalidLength(len) => {
                write!(f, "invalid gossip frame length: {len} bytes")
            }
            RawGossipError::CorruptedPlaintext => {
                write!(f, "corrupted plaintext frame (CRC mismatch)")
            }
            RawGossipError::Registry(_) => write!(f, "registry rejected snapshot"),
        }
    }
}

impl std::error::Error for RawGossipError {}

/// Outcome of applying a gossip frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GossipResult {
    /// Frame was applied and updated an existing shadow session.
    Updated,
    /// Frame introduced a brand-new session into the shadow registry.
    Inserted,
    /// Frame was silently ignored (self-loop or no-op).
    Ignored,
    /// Frame was rejected.
    Rejected(RejectReason),
}

/// Reason a gossip frame was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// Received epoch ≤ locally known epoch.
    StaleEpoch { local: u64, received: u64 },
    /// Registry is at capacity.
    RegistryFull,
    /// Mutex was poisoned.
    LockFailed,
}

/// Errors returned by registry operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncError {
    /// Session was not found in the registry.
    SessionNotFound,
    /// This node is already the primary owner — no migration needed.
    AlreadyPrimary,
    /// Snapshot is too old to safely restore session state.
    SnapshotStale { age_secs: u64 },
    /// Registry is full — cannot insert more sessions.
    RegistryFull,
    /// Internal mutex was poisoned.
    LockPoisoned,
    /// ISSP capsule magic does not match ISSP_CAPSULE_MAGIC.
    BadCapsuleMagic,
    /// ISSP capsule buffer length is invalid.
    InvalidCapsuleLength(usize),
    /// ISSP dump magic does not match ISSP_DUMP_MAGIC.
    BadDumpMagic,
    /// ISSP dump version is unsupported.
    UnsupportedDumpVersion(u32),
    /// ISSP dump buffer length is invalid.
    InvalidDumpLength(usize),
    /// Transport path with the given ID was not found in the multipath routing table.
    PathNotFound(u32),
    /// No usable (active or degraded) transport path available.
    NoUsablePaths,
    /// ISSP heartbeat probe packet wire format or CRC32 was invalid.
    InvalidHeartbeatProbe,
    /// Encryption was required on this subpath, but no key was available or configured.
    EncryptionRequired,
    /// Cryptographic AEAD authentication or tag verification failed.
    AuthenticationFailed,
    /// Duplicate or out-of-window packet dropped by anti-replay protection.
    ReplayPacketDropped,
    /// Session header decompression failed or context was unknown.
    HeaderDecompressionFailed,
    /// ISSP session packet header magic does not match ISSP_SESSION_MAGIC.
    BadHeaderMagic,
    /// ISSP session header buffer length is invalid.
    InvalidHeaderLength(usize),
    /// ISSP subpath packet magic does not match ISSP_SUBPATH_PACKET_MAGIC.
    BadSubpathPacketMagic,
    /// ISSP subpath packet buffer length is invalid.
    InvalidSubpathPacketLength(usize),
}

impl std::fmt::Display for SyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncError::SessionNotFound => write!(f, "session not found in registry"),
            SyncError::AlreadyPrimary => write!(f, "node already holds primary ownership"),
            SyncError::SnapshotStale { age_secs } => {
                write!(
                    f,
                    "snapshot is stale ({age_secs}s old, max {}s)",
                    SNAPSHOT_MAX_AGE.as_secs()
                )
            }
            SyncError::RegistryFull => write!(f, "registry capacity ({MAX_SESSIONS}) reached"),
            SyncError::LockPoisoned => write!(f, "internal mutex poisoned"),
            SyncError::BadCapsuleMagic => write!(f, "invalid ISSP capsule magic tag"),
            SyncError::InvalidCapsuleLength(len) => {
                write!(f, "invalid ISSP capsule length: {len} bytes")
            }
            SyncError::BadDumpMagic => write!(f, "invalid ISSP state dump magic tag"),
            SyncError::UnsupportedDumpVersion(v) => write!(f, "unsupported ISSP dump version {v}"),
            SyncError::InvalidDumpLength(len) => write!(f, "invalid ISSP dump length: {len} bytes"),
            SyncError::PathNotFound(id) => {
                write!(f, "transport path {id} not found in routing table")
            }
            SyncError::NoUsablePaths => {
                write!(f, "no usable transport paths available for routing")
            }
            SyncError::InvalidHeartbeatProbe => {
                write!(f, "invalid ISSP heartbeat probe wire packet")
            }
            SyncError::EncryptionRequired => {
                write!(
                    f,
                    "encryption required on subpath tunnel but no key configured"
                )
            }
            SyncError::AuthenticationFailed => {
                write!(f, "subpath AEAD authentication verification failed")
            }
            SyncError::ReplayPacketDropped => {
                write!(f, "subpath packet rejected by anti-replay sliding window")
            }
            SyncError::HeaderDecompressionFailed => {
                write!(
                    f,
                    "session header decompression failed or context desynchronized"
                )
            }
            SyncError::BadHeaderMagic => write!(f, "invalid ISSP session header magic tag"),
            SyncError::InvalidHeaderLength(len) => {
                write!(f, "invalid ISSP session header length: {len} bytes")
            }
            SyncError::BadSubpathPacketMagic => {
                write!(f, "invalid ISSP subpath packet magic tag")
            }
            SyncError::InvalidSubpathPacketLength(len) => {
                write!(f, "invalid ISSP subpath packet length: {len} bytes")
            }
        }
    }
}

impl std::error::Error for SyncError {}

// ---------------------------------------------------------------------------
// Subpath Opportunistic Encryption & Adaptive Session Header Compression
// ---------------------------------------------------------------------------

/// Result type for subpath AEAD encrypt operations: (is_encrypted, nonce_seq, ciphertext, auth_tag).
pub type SubpathEncryptResult = Result<(bool, u64, Vec<u8>, Option<[u8; 16]>), SyncError>;

/// Cryptographic symmetric key associated with a specific subpath tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsspSubpathKey(pub [u8; 32]);

impl IsspSubpathKey {
    pub fn new(key: [u8; 32]) -> Self {
        Self(key)
    }

    pub fn from_passphrase(passphrase: &str) -> Self {
        let mut key = [0u8; 32];
        let bytes = passphrase.as_bytes();
        let mut h: u64 = 0xcbf29ce484222325;
        for (i, &b) in bytes.iter().enumerate() {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
            key[i % 32] ^= b.wrapping_add((h & 0xff) as u8);
        }
        for (i, byte) in key.iter_mut().enumerate() {
            h ^= *byte as u64;
            h = h.wrapping_mul(0x100000001b3);
            *byte ^= ((h >> (i % 8)) & 0xff) as u8;
        }
        Self(key)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Cryptographic state and AEAD ChaCha20-Poly1305 engine for a subpath tunnel.
#[derive(Debug, Clone, PartialEq)]
pub struct IsspSubpathCryptoTunnel {
    pub path_id: u32,
    pub security_level: OpportunisticSecurityLevel,
    pub key: Option<IsspSubpathKey>,
    pub tx_nonce_seq: u64,
    pub rx_nonce_seq: u64,
    pub rx_replay_window: u64,
    pub packets_encrypted: u64,
    pub packets_decrypted: u64,
    pub bytes_encrypted: u64,
    pub auth_failures: u64,
    pub replay_drops: u64,
    pub plain_transmissions: u64,
}

impl IsspSubpathCryptoTunnel {
    pub fn new(
        path_id: u32,
        security_level: OpportunisticSecurityLevel,
        key: Option<IsspSubpathKey>,
    ) -> Self {
        Self {
            path_id,
            security_level,
            key,
            tx_nonce_seq: 1,
            rx_nonce_seq: 0,
            rx_replay_window: 0,
            packets_encrypted: 0,
            packets_decrypted: 0,
            bytes_encrypted: 0,
            auth_failures: 0,
            replay_drops: 0,
            plain_transmissions: 0,
        }
    }

    /// Check and update 64-bit anti-replay sliding window.
    pub fn check_and_update_replay(&mut self, seq: u64) -> bool {
        if self.rx_nonce_seq == 0 {
            self.rx_nonce_seq = seq;
            self.rx_replay_window = 1;
            return true;
        }
        if seq > self.rx_nonce_seq {
            let diff = seq - self.rx_nonce_seq;
            if diff < 64 {
                self.rx_replay_window = (self.rx_replay_window << diff) | 1;
            } else {
                self.rx_replay_window = 1;
            }
            self.rx_nonce_seq = seq;
            true
        } else {
            let diff = self.rx_nonce_seq - seq;
            if diff >= 64 {
                return false;
            }
            if (self.rx_replay_window & (1 << diff)) != 0 {
                return false;
            }
            self.rx_replay_window |= 1 << diff;
            true
        }
    }

    /// Encrypt payload with AEAD ChaCha20-Poly1305 if subpath key is present.
    pub fn encrypt_payload(&mut self, aad: &[u8], plaintext: &[u8]) -> SubpathEncryptResult {
        match (&self.key, self.security_level) {
            (Some(k), _) => {
                let seq = self.tx_nonce_seq;
                self.tx_nonce_seq += 1;

                let mut nonce = [0u8; 12];
                nonce[0..4].copy_from_slice(&self.path_id.to_le_bytes());
                nonce[4..12].copy_from_slice(&seq.to_le_bytes());

                let poly_block = chacha20_block(k.as_bytes(), 0, &nonce);
                let mut poly_key = [0u8; 32];
                poly_key.copy_from_slice(&poly_block[0..32]);

                let mut ciphertext = plaintext.to_vec();
                chacha20_xor_slice(k.as_bytes(), &nonce, 1, &mut ciphertext);

                let tag = poly1305_aead_tag(&poly_key, aad, &ciphertext);

                self.packets_encrypted += 1;
                self.bytes_encrypted += plaintext.len() as u64;

                Ok((true, seq, ciphertext, Some(tag)))
            }
            (None, OpportunisticSecurityLevel::Required) => Err(SyncError::EncryptionRequired),
            (None, _) => {
                let seq = self.tx_nonce_seq;
                self.tx_nonce_seq += 1;
                self.plain_transmissions += 1;
                Ok((false, seq, plaintext.to_vec(), None))
            }
        }
    }

    /// Decrypt payload verifying AEAD Poly1305 tag if encrypted.
    pub fn decrypt_payload(
        &mut self,
        is_encrypted: bool,
        seq: u64,
        aad: &[u8],
        ciphertext: &[u8],
        tag: Option<&[u8; 16]>,
    ) -> Result<Vec<u8>, SyncError> {
        if is_encrypted {
            let key_bytes = match &self.key {
                Some(k) => *k.as_bytes(),
                None => {
                    self.auth_failures += 1;
                    return Err(SyncError::AuthenticationFailed);
                }
            };
            let stored_tag = tag.ok_or(SyncError::AuthenticationFailed)?;

            if !self.check_and_update_replay(seq) {
                self.replay_drops += 1;
                return Err(SyncError::ReplayPacketDropped);
            }

            let mut nonce = [0u8; 12];
            nonce[0..4].copy_from_slice(&self.path_id.to_le_bytes());
            nonce[4..12].copy_from_slice(&seq.to_le_bytes());

            let poly_block = chacha20_block(&key_bytes, 0, &nonce);
            let mut poly_key = [0u8; 32];
            poly_key.copy_from_slice(&poly_block[0..32]);

            let expected_tag = poly1305_aead_tag(&poly_key, aad, ciphertext);
            if !constant_time_eq(&expected_tag, stored_tag) {
                self.auth_failures += 1;
                return Err(SyncError::AuthenticationFailed);
            }

            let mut plaintext = ciphertext.to_vec();
            chacha20_xor_slice(&key_bytes, &nonce, 1, &mut plaintext);

            self.packets_decrypted += 1;
            Ok(plaintext)
        } else {
            if self.security_level == OpportunisticSecurityLevel::Required {
                self.auth_failures += 1;
                return Err(SyncError::EncryptionRequired);
            }
            self.plain_transmissions += 1;
            Ok(ciphertext.to_vec())
        }
    }
}

/// Telemetry metrics for subpath crypto operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubpathCryptoTelemetry {
    pub path_id: u32,
    pub security_level: OpportunisticSecurityLevel,
    pub has_key: bool,
    pub tx_nonce_seq: u64,
    pub rx_nonce_seq: u64,
    pub packets_encrypted: u64,
    pub packets_decrypted: u64,
    pub bytes_encrypted: u64,
    pub auth_failures: u64,
    pub replay_drops: u64,
    pub plain_transmissions: u64,
}

/// Full session header for ISSP multipath packets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsspSessionHeader {
    pub magic: u32,
    pub session_id: SessionId,
    pub multipath_seq: u64,
    pub subpath_seq: u64,
    pub timestamp_unix_ms: u64,
    pub flags: u16,
    pub path_id: u32,
}

impl IsspSessionHeader {
    pub fn new(
        session_id: SessionId,
        multipath_seq: u64,
        subpath_seq: u64,
        timestamp_unix_ms: u64,
        flags: u16,
        path_id: u32,
    ) -> Self {
        Self {
            magic: ISSP_SESSION_MAGIC,
            session_id,
            multipath_seq,
            subpath_seq,
            timestamp_unix_ms,
            flags,
            path_id,
        }
    }

    pub fn encode_uncompressed(&self) -> [u8; ISSP_SESSION_HEADER_UNCOMPRESSED_SIZE] {
        let mut buf = [0u8; ISSP_SESSION_HEADER_UNCOMPRESSED_SIZE];
        buf[0..4].copy_from_slice(&self.magic.to_be_bytes());
        buf[4..20].copy_from_slice(&self.session_id.to_bytes());
        buf[20..28].copy_from_slice(&self.multipath_seq.to_le_bytes());
        buf[28..36].copy_from_slice(&self.subpath_seq.to_le_bytes());
        buf[36..44].copy_from_slice(&self.timestamp_unix_ms.to_le_bytes());
        buf[44..46].copy_from_slice(&self.flags.to_le_bytes());
        buf[46..50].copy_from_slice(&self.path_id.to_le_bytes());
        buf
    }

    pub fn decode_uncompressed(buf: &[u8]) -> Result<Self, SyncError> {
        if buf.len() < ISSP_SESSION_HEADER_UNCOMPRESSED_SIZE {
            return Err(SyncError::InvalidHeaderLength(buf.len()));
        }
        let magic = u32::from_be_bytes(buf[0..4].try_into().unwrap());
        if magic != ISSP_SESSION_MAGIC {
            return Err(SyncError::BadHeaderMagic);
        }
        let s_id_bytes: [u8; 16] = buf[4..20].try_into().unwrap();
        let session_id = SessionId::from_bytes(&s_id_bytes);
        let multipath_seq = u64::from_le_bytes(buf[20..28].try_into().unwrap());
        let subpath_seq = u64::from_le_bytes(buf[28..36].try_into().unwrap());
        let timestamp_unix_ms = u64::from_le_bytes(buf[36..44].try_into().unwrap());
        let flags = u16::from_le_bytes(buf[44..46].try_into().unwrap());
        let path_id = u32::from_le_bytes(buf[46..50].try_into().unwrap());
        Ok(Self {
            magic,
            session_id,
            multipath_seq,
            subpath_seq,
            timestamp_unix_ms,
            flags,
            path_id,
        })
    }
}

/// Dynamic compression context entry for an active session.
#[derive(Debug, Clone, PartialEq)]
pub struct IsspHeaderContextEntry {
    pub context_id: u8,
    pub session_id: SessionId,
    pub last_multipath_seq: u64,
    pub last_subpath_seq: u64,
    pub last_timestamp_ms: u64,
    pub last_flags: u16,
    pub path_id: u32,
    pub packets_since_refresh: u32,
}

/// Telemetry metrics for adaptive session header compression.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct IsspHeaderCompressionTelemetry {
    pub total_packets: u64,
    pub full_headers_count: u64,
    pub compressed_headers_count: u64,
    pub uncompressed_bytes: u64,
    pub compressed_bytes: u64,
    pub bytes_saved: u64,
    pub compression_ratio_percent: f64,
    pub decompression_resyncs: u64,
}

/// Adaptive session header compression engine.
#[derive(Debug, Clone, PartialEq)]
pub struct IsspAdaptiveHeaderCompressor {
    pub refresh_interval: u32,
    pub session_to_context: HashMap<SessionId, u8>,
    pub entries: HashMap<u8, IsspHeaderContextEntry>,
    next_context_id: u8,
    pub total_packets: u64,
    pub full_headers_count: u64,
    pub compressed_headers_count: u64,
    pub uncompressed_bytes: u64,
    pub compressed_bytes: u64,
    pub decompression_resyncs: u64,
}

impl IsspAdaptiveHeaderCompressor {
    pub fn new(refresh_interval: u32) -> Self {
        Self {
            refresh_interval: refresh_interval.max(1),
            session_to_context: HashMap::new(),
            entries: HashMap::new(),
            next_context_id: 1,
            total_packets: 0,
            full_headers_count: 0,
            compressed_headers_count: 0,
            uncompressed_bytes: 0,
            compressed_bytes: 0,
            decompression_resyncs: 0,
        }
    }

    pub fn compress_header(
        &mut self,
        header: &IsspSessionHeader,
        path_loss_ppm: u32,
    ) -> (bool, Vec<u8>) {
        self.total_packets += 1;
        self.uncompressed_bytes += ISSP_SESSION_HEADER_UNCOMPRESSED_SIZE as u64;

        let eff_refresh = if path_loss_ppm > 20_000 {
            (self.refresh_interval / 4).max(8)
        } else {
            self.refresh_interval
        };

        let context_id = if let Some(&cid) = self.session_to_context.get(&header.session_id) {
            cid
        } else {
            let cid = self.next_context_id;
            self.next_context_id = self.next_context_id.wrapping_add(1);
            if self.next_context_id == 0 {
                self.next_context_id = 1;
            }
            self.session_to_context.insert(header.session_id, cid);
            cid
        };

        let needs_full = match self.entries.get(&context_id) {
            None => true,
            Some(entry) => entry.packets_since_refresh >= eff_refresh,
        };

        if needs_full {
            let mut buf = Vec::with_capacity(47);
            let ctrl = 0x80 | (context_id & 0x7f);
            buf.push(ctrl);
            buf.extend_from_slice(&header.session_id.to_bytes());
            buf.extend_from_slice(&header.multipath_seq.to_le_bytes());
            buf.extend_from_slice(&header.subpath_seq.to_le_bytes());
            buf.extend_from_slice(&header.timestamp_unix_ms.to_le_bytes());
            buf.extend_from_slice(&header.flags.to_le_bytes());
            buf.extend_from_slice(&header.path_id.to_le_bytes());

            self.entries.insert(
                context_id,
                IsspHeaderContextEntry {
                    context_id,
                    session_id: header.session_id,
                    last_multipath_seq: header.multipath_seq,
                    last_subpath_seq: header.subpath_seq,
                    last_timestamp_ms: header.timestamp_unix_ms,
                    last_flags: header.flags,
                    path_id: header.path_id,
                    packets_since_refresh: 0,
                },
            );

            self.full_headers_count += 1;
            self.compressed_bytes += buf.len() as u64;
            (true, buf)
        } else {
            let entry = self.entries.get_mut(&context_id).unwrap();
            let seq_incr_1 = header.multipath_seq == entry.last_multipath_seq.wrapping_add(1);
            let sub_incr_1 = header.subpath_seq == entry.last_subpath_seq.wrapping_add(1);
            let ts_diff = header
                .timestamp_unix_ms
                .saturating_sub(entry.last_timestamp_ms);
            let ts_delta_u8 = ts_diff <= 255;
            let flags_same = header.flags == entry.last_flags;

            let mut ctrl = 0x00u8;
            if seq_incr_1 {
                ctrl |= 0x40;
            }
            if sub_incr_1 {
                ctrl |= 0x20;
            }
            if ts_delta_u8 {
                ctrl |= 0x10;
            }
            if flags_same {
                ctrl |= 0x08;
            }

            let mut buf = Vec::with_capacity(16);
            buf.push(ctrl);
            buf.push(context_id);

            if !seq_incr_1 {
                buf.extend_from_slice(&header.multipath_seq.to_le_bytes());
            }
            if !sub_incr_1 {
                buf.extend_from_slice(&header.subpath_seq.to_le_bytes());
            }
            if ts_delta_u8 {
                buf.push(ts_diff as u8);
            } else {
                buf.extend_from_slice(&header.timestamp_unix_ms.to_le_bytes());
            }
            if !flags_same {
                buf.extend_from_slice(&header.flags.to_le_bytes());
            }

            entry.last_multipath_seq = header.multipath_seq;
            entry.last_subpath_seq = header.subpath_seq;
            entry.last_timestamp_ms = header.timestamp_unix_ms;
            entry.last_flags = header.flags;
            entry.packets_since_refresh += 1;

            self.compressed_headers_count += 1;
            self.compressed_bytes += buf.len() as u64;
            (false, buf)
        }
    }

    pub fn decompress_header(&mut self, buf: &[u8]) -> Result<IsspSessionHeader, SyncError> {
        if buf.is_empty() {
            return Err(SyncError::HeaderDecompressionFailed);
        }
        let ctrl = buf[0];
        if (ctrl & 0x80) != 0 {
            // Full Header
            let context_id = ctrl & 0x7f;
            if buf.len() < 47 {
                return Err(SyncError::InvalidHeaderLength(buf.len()));
            }
            let s_id_bytes: [u8; 16] = buf[1..17].try_into().unwrap();
            let session_id = SessionId::from_bytes(&s_id_bytes);
            let multipath_seq = u64::from_le_bytes(buf[17..25].try_into().unwrap());
            let subpath_seq = u64::from_le_bytes(buf[25..33].try_into().unwrap());
            let timestamp_unix_ms = u64::from_le_bytes(buf[33..41].try_into().unwrap());
            let flags = u16::from_le_bytes(buf[41..43].try_into().unwrap());
            let path_id = u32::from_le_bytes(buf[43..47].try_into().unwrap());

            self.entries.insert(
                context_id,
                IsspHeaderContextEntry {
                    context_id,
                    session_id,
                    last_multipath_seq: multipath_seq,
                    last_subpath_seq: subpath_seq,
                    last_timestamp_ms: timestamp_unix_ms,
                    last_flags: flags,
                    path_id,
                    packets_since_refresh: 0,
                },
            );
            self.full_headers_count += 1;

            Ok(IsspSessionHeader::new(
                session_id,
                multipath_seq,
                subpath_seq,
                timestamp_unix_ms,
                flags,
                path_id,
            ))
        } else {
            // Compressed Header
            if buf.len() < 2 {
                return Err(SyncError::InvalidHeaderLength(buf.len()));
            }
            let context_id = buf[1];
            let entry = match self.entries.get_mut(&context_id) {
                Some(e) => e,
                None => {
                    self.decompression_resyncs += 1;
                    return Err(SyncError::HeaderDecompressionFailed);
                }
            };

            let seq_incr_1 = (ctrl & 0x40) != 0;
            let sub_incr_1 = (ctrl & 0x20) != 0;
            let ts_delta_u8 = (ctrl & 0x10) != 0;
            let flags_same = (ctrl & 0x08) != 0;

            let mut offset = 2;
            let multipath_seq = if seq_incr_1 {
                entry.last_multipath_seq.wrapping_add(1)
            } else {
                if buf.len() < offset + 8 {
                    return Err(SyncError::InvalidHeaderLength(buf.len()));
                }
                let val = u64::from_le_bytes(buf[offset..offset + 8].try_into().unwrap());
                offset += 8;
                val
            };

            let subpath_seq = if sub_incr_1 {
                entry.last_subpath_seq.wrapping_add(1)
            } else {
                if buf.len() < offset + 8 {
                    return Err(SyncError::InvalidHeaderLength(buf.len()));
                }
                let val = u64::from_le_bytes(buf[offset..offset + 8].try_into().unwrap());
                offset += 8;
                val
            };

            let timestamp_unix_ms = if ts_delta_u8 {
                if buf.len() < offset + 1 {
                    return Err(SyncError::InvalidHeaderLength(buf.len()));
                }
                let delta = buf[offset] as u64;
                offset += 1;
                entry.last_timestamp_ms.wrapping_add(delta)
            } else {
                if buf.len() < offset + 8 {
                    return Err(SyncError::InvalidHeaderLength(buf.len()));
                }
                let val = u64::from_le_bytes(buf[offset..offset + 8].try_into().unwrap());
                offset += 8;
                val
            };

            let flags = if flags_same {
                entry.last_flags
            } else {
                if buf.len() < offset + 2 {
                    return Err(SyncError::InvalidHeaderLength(buf.len()));
                }
                u16::from_le_bytes(buf[offset..offset + 2].try_into().unwrap())
            };

            let session_id = entry.session_id;
            let path_id = entry.path_id;

            entry.last_multipath_seq = multipath_seq;
            entry.last_subpath_seq = subpath_seq;
            entry.last_timestamp_ms = timestamp_unix_ms;
            entry.last_flags = flags;
            entry.packets_since_refresh += 1;

            self.compressed_headers_count += 1;

            Ok(IsspSessionHeader::new(
                session_id,
                multipath_seq,
                subpath_seq,
                timestamp_unix_ms,
                flags,
                path_id,
            ))
        }
    }

    pub fn telemetry(&self) -> IsspHeaderCompressionTelemetry {
        let bytes_saved = self
            .uncompressed_bytes
            .saturating_sub(self.compressed_bytes);
        let ratio = if self.uncompressed_bytes > 0 {
            (bytes_saved as f64 / self.uncompressed_bytes as f64) * 100.0
        } else {
            0.0
        };
        IsspHeaderCompressionTelemetry {
            total_packets: self.total_packets,
            full_headers_count: self.full_headers_count,
            compressed_headers_count: self.compressed_headers_count,
            uncompressed_bytes: self.uncompressed_bytes,
            compressed_bytes: self.compressed_bytes,
            bytes_saved,
            compression_ratio_percent: ratio,
            decompression_resyncs: self.decompression_resyncs,
        }
    }
}

/// Encapsulated wire packet for multi-tunnel subpaths.
#[derive(Debug, Clone, PartialEq)]
pub struct IsspSubpathPacket {
    pub path_id: u32,
    pub is_encrypted: bool,
    pub is_compressed: bool,
    pub is_full_header: bool,
    pub nonce_seq: u64,
    pub auth_tag: Option<[u8; 16]>,
    pub header_wire: Vec<u8>,
    pub payload: Vec<u8>,
}

impl IsspSubpathPacket {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut flags: u16 = 0;
        if self.is_encrypted {
            flags |= ISSP_PKT_FLAG_ENCRYPTED;
        }
        if self.is_compressed {
            flags |= ISSP_PKT_FLAG_COMPRESSED;
        }
        if self.is_full_header {
            flags |= ISSP_PKT_FLAG_FULL_HEADER;
        }

        let base_len = 4
            + 2
            + 4
            + 8
            + if self.is_encrypted { 16 } else { 0 }
            + 2
            + self.header_wire.len()
            + self.payload.len();
        let mut buf = Vec::with_capacity(base_len);
        buf.extend_from_slice(&ISSP_SUBPATH_PACKET_MAGIC.to_be_bytes());
        buf.extend_from_slice(&flags.to_le_bytes());
        buf.extend_from_slice(&self.path_id.to_le_bytes());
        buf.extend_from_slice(&self.nonce_seq.to_le_bytes());
        if self.is_encrypted {
            let tag = self.auth_tag.unwrap_or([0u8; 16]);
            buf.extend_from_slice(&tag);
        }
        let h_len = self.header_wire.len() as u16;
        buf.extend_from_slice(&h_len.to_le_bytes());
        buf.extend_from_slice(&self.header_wire);
        buf.extend_from_slice(&self.payload);
        buf
    }

    pub fn from_bytes(raw: &[u8]) -> Result<Self, SyncError> {
        if raw.len() < 20 {
            return Err(SyncError::InvalidSubpathPacketLength(raw.len()));
        }
        let magic = u32::from_be_bytes(raw[0..4].try_into().unwrap());
        if magic != ISSP_SUBPATH_PACKET_MAGIC {
            return Err(SyncError::BadSubpathPacketMagic);
        }
        let flags = u16::from_le_bytes(raw[4..6].try_into().unwrap());
        let is_encrypted = (flags & ISSP_PKT_FLAG_ENCRYPTED) != 0;
        let is_compressed = (flags & ISSP_PKT_FLAG_COMPRESSED) != 0;
        let is_full_header = (flags & ISSP_PKT_FLAG_FULL_HEADER) != 0;

        let path_id = u32::from_le_bytes(raw[6..10].try_into().unwrap());
        let nonce_seq = u64::from_le_bytes(raw[10..18].try_into().unwrap());

        let mut offset = 18;
        let auth_tag = if is_encrypted {
            if raw.len() < offset + 16 + 2 {
                return Err(SyncError::InvalidSubpathPacketLength(raw.len()));
            }
            let mut tag = [0u8; 16];
            tag.copy_from_slice(&raw[offset..offset + 16]);
            offset += 16;
            Some(tag)
        } else {
            None
        };

        if raw.len() < offset + 2 {
            return Err(SyncError::InvalidSubpathPacketLength(raw.len()));
        }
        let h_len = u16::from_le_bytes(raw[offset..offset + 2].try_into().unwrap()) as usize;
        offset += 2;

        if raw.len() < offset + h_len {
            return Err(SyncError::InvalidSubpathPacketLength(raw.len()));
        }
        let header_wire = raw[offset..offset + h_len].to_vec();
        offset += h_len;

        let payload = raw[offset..].to_vec();

        Ok(Self {
            path_id,
            is_encrypted,
            is_compressed,
            is_full_header,
            nonce_seq,
            auth_tag,
            header_wire,
            payload,
        })
    }
}

/// Telemetry counters exported by the session synchronization subsystem.
#[derive(Debug, Clone, Copy)]
pub struct SyncTelemetry {
    pub node_id: u32,
    pub session_count: u64,
    pub migration_count: u64,
    pub gossip_rx_count: u64,
    pub gossip_rejected_count: u64,
    pub gossip_auth_failed_count: u64,
    pub gossip_replay_failed_count: u64,
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Congestion Control Tests ─────────────────────────────────────────────

    #[test]
    fn test_ledbat_no_queuing_weight_is_one() {
        let mut s = IsspLedbatState::default();
        // Feed same RTT twice → queuing delay = 0
        s.update(10_000);
        s.update(10_000);
        assert_eq!(s.queuing_delay_us, 0);
        assert!(!s.is_congested());
        let wf = s.weight_factor();
        assert!(
            (wf - 1.0).abs() < 1e-6,
            "weight_factor should be 1.0, got {wf}"
        );
    }

    #[test]
    fn test_ledbat_congested_weight_decreases() {
        let mut s = IsspLedbatState::default();
        // Set low base delay then high current delay → congestion
        s.update(10_000); // base = 5000 µs
        s.update(80_000); // current = 40000 µs → queuing = 35000 µs > target(25000)
        assert!(s.is_congested(), "should be congested");
        let wf = s.weight_factor();
        assert!(
            wf < 1.0,
            "weight_factor should decrease under congestion, got {wf}"
        );
        assert!(wf > 0.0, "weight_factor must stay positive, got {wf}");
    }

    #[test]
    fn test_bbr_bandwidth_estimate_grows() {
        let mut b = IsspBbrState::default();
        // Feed several samples with 1 Mib delivered over 10ms RTT
        for _ in 0..8 {
            b.update(10_000, 125_000); // 125 KiB / 10ms ≈ 100 Mbps
        }
        assert!(
            b.estimated_bandwidth_bps > 0,
            "BBR should produce a BW estimate"
        );
        // 125_000 * 8_000_000 / 10_000 = 100_000_000 bps
        assert_eq!(b.estimated_bandwidth_bps, 100_000_000);
        assert_eq!(b.pacing_gain_q8, 256); // settled to 1.0×
    }

    #[test]
    fn test_bbr_rt_prop_min_filter() {
        let mut b = IsspBbrState::default();
        b.update(50_000, 1000);
        b.update(30_000, 1000); // new minimum
        b.update(40_000, 1000);
        assert_eq!(
            b.rt_prop_us, 30_000,
            "RTprop should be minimum observed RTT"
        );
    }

    #[test]
    fn test_congestion_state_phase_transitions() {
        let mut cs = IsspCongestionState::default();
        assert_eq!(cs.phase, IsspCongestionPhase::SlowStart);

        // Deliver bytes → transitions to CongestionAvoidance once BBR has estimate
        for _ in 0..8 {
            cs.update(10_000, 0, 125_000);
        }
        assert_eq!(cs.phase, IsspCongestionPhase::CongestionAvoidance);

        // Loss signal → Recovery
        cs.update(10_000, 1000, 0);
        assert_eq!(cs.phase, IsspCongestionPhase::Recovery);
        assert_eq!(cs.congestion_events, 1);

        // No further loss → back to CongestionAvoidance
        cs.update(10_000, 0, 1000);
        assert_eq!(cs.phase, IsspCongestionPhase::CongestionAvoidance);
    }

    #[test]
    fn test_congestion_weight_factor_recovery_reduces_weight() {
        let mut cs = IsspCongestionState::default();
        // Establish baseline
        for _ in 0..8 {
            cs.update(10_000, 0, 125_000);
        }
        let normal_wf = cs.congestion_weight_factor();

        // Inject loss to enter Recovery
        cs.update(10_000, 500, 0);
        let recovery_wf = cs.congestion_weight_factor();
        assert!(
            recovery_wf < normal_wf,
            "Recovery weight_factor ({recovery_wf}) should be less than normal ({normal_wf})"
        );
    }

    #[test]
    fn test_effective_weight_reduced_by_congestion() {
        let mut route = IsspMultipathRoute::new(1, 2, "eth0", 1, 100);

        // Establish CongestionAvoidance baseline (phase_factor = 1.0, LEDBAT neutral)
        for _ in 0..8 {
            route.congestion.update(10_000, 0, 125_000);
        }
        assert_eq!(
            route.congestion.phase,
            IsspCongestionPhase::CongestionAvoidance
        );
        let baseline = route.effective_weight();
        // Should be 100 × 1.0 (phase) × ~1.0 (LEDBAT no queuing) × 1.0 (BBR settled)
        assert_eq!(
            baseline, 100,
            "CongestionAvoidance with no queuing → full weight"
        );

        // Simulate loss → Recovery phase (phase_factor = 0.4)
        route.congestion.update(10_000, 1000, 0);
        assert_eq!(route.congestion.phase, IsspCongestionPhase::Recovery);
        let recovery_weight = route.effective_weight();
        assert!(
            recovery_weight < baseline,
            "effective_weight ({recovery_weight}) should drop under congestion vs baseline ({baseline})"
        );
        assert!(recovery_weight >= 1, "effective_weight must be at least 1");
    }

    #[test]
    fn test_bandwidth_estimate_accessors() {
        let mut route = IsspMultipathRoute::new(1, 2, "eth0", 1, 100);
        // Feed BBR data
        for _ in 0..8 {
            route.congestion.update(10_000, 0, 125_000);
        }
        let est = route.bandwidth_estimate();
        assert_eq!(est.available_bps, 100_000_000);
        assert_eq!(est.phase, IsspCongestionPhase::CongestionAvoidance);
        assert!(
            (est.weight_factor - 1.0).abs() < 0.1,
            "weight_factor should be near 1.0"
        );
    }

    #[test]
    fn test_router_update_congestion_feedback_and_bandwidth_estimates() {
        let mut router =
            IsspDynamicMultipathRouter::new(1, IsspRoutingPolicy::BandwidthAggregation);
        router.add_route(IsspMultipathRoute::new(1, 2, "eth0", 1, 100));
        router.add_route(IsspMultipathRoute::new(2, 2, "wlan0", 2, 50));

        // Feed good conditions on path 1
        for _ in 0..8 {
            let f = router
                .update_congestion_feedback(1, 10_000, 0, 125_000)
                .unwrap();
            assert!(f > 0.0 && f <= 1.0);
        }
        // Feed loss on path 2
        router
            .update_congestion_feedback(2, 50_000, 500, 0)
            .unwrap();

        let estimates = router.bandwidth_estimates();
        assert_eq!(estimates.len(), 2);

        let est1 = router.path_bandwidth_estimate(1).unwrap();
        assert_eq!(est1.available_bps, 100_000_000);
        assert_eq!(est1.phase, IsspCongestionPhase::CongestionAvoidance);

        let est2 = router.path_bandwidth_estimate(2).unwrap();
        assert_eq!(est2.phase, IsspCongestionPhase::Recovery);

        // path 1 effective_weight should be much higher than path 2 under congestion
        let r1 = router.get_route(1).unwrap();
        let r2 = router.get_route(2).unwrap();
        assert!(
            r1.effective_weight() > r2.effective_weight(),
            "path 1 ({}w) should outweigh path 2 ({}w) under congestion",
            r1.effective_weight(),
            r2.effective_weight()
        );
    }

    #[test]
    fn test_router_unknown_path_congestion_feedback_errors() {
        let mut router = IsspDynamicMultipathRouter::new(1, IsspRoutingPolicy::ActiveStandby);
        let result = router.update_congestion_feedback(99, 10_000, 0, 1000);
        assert_eq!(result, Err(SyncError::PathNotFound(99)));
    }

    fn make_id(flow: u64) -> SessionId {
        SessionId::new(flow, 1, 0xDEAD)
    }

    fn make_snap(id: SessionId, epoch: u64, unix: u64) -> SessionSnapshot {
        let mut s = SessionSnapshot::new(id, 1, unix);
        s.migration_epoch = epoch;
        s.tx_seq = 42;
        s.rx_seq_high = 40;
        s
    }

    // ---- SessionId round-trip ----
    #[test]
    fn test_session_id_roundtrip() {
        let id = SessionId::new(0xCAFEBABEDEAD_u64, 7, 0xABCD);
        assert_eq!(SessionId::from_bytes(&id.to_bytes()), id);
    }

    // ---- Snapshot wire round-trip ----
    #[test]
    fn test_snapshot_wire_roundtrip() {
        let id = make_id(1);
        let snap = make_snap(id, 3, 1_700_000_000);
        let wire = snap.to_wire();
        let decoded = SessionSnapshot::from_wire(&wire);
        assert_eq!(decoded.id, snap.id);
        assert_eq!(decoded.migration_epoch, snap.migration_epoch);
        assert_eq!(decoded.tx_seq, snap.tx_seq);
        assert_eq!(decoded.rx_seq_high, snap.rx_seq_high);
        assert_eq!(decoded.crypto_epoch, snap.crypto_epoch);
        assert_eq!(decoded.captured_unix_secs, snap.captured_unix_secs);
    }

    // ---- GossipFrame CRC integrity ----
    #[test]
    fn test_gossip_frame_crc_ok() {
        let id = make_id(2);
        let snap = make_snap(id, 1, 1_700_000_001);
        let frame = GossipFrame {
            sender_node_id: 42,
            snapshot: snap,
        };
        let encoded = frame.encode();
        let decoded = GossipFrame::decode(&encoded);
        assert!(decoded.is_some());
        let d = decoded.unwrap();
        assert_eq!(d.sender_node_id, 42);
        assert_eq!(d.snapshot.migration_epoch, 1);
    }

    #[test]
    fn test_gossip_frame_crc_corruption() {
        let id = make_id(3);
        let snap = make_snap(id, 1, 1_700_000_002);
        let frame = GossipFrame {
            sender_node_id: 1,
            snapshot: snap,
        };
        let mut encoded = frame.encode();
        encoded[20] ^= 0xFF; // corrupt snapshot byte
        assert!(GossipFrame::decode(&encoded).is_none());
    }

    #[test]
    fn test_gossip_frame_bad_magic() {
        let id = make_id(4);
        let snap = make_snap(id, 1, 1_700_000_003);
        let frame = GossipFrame {
            sender_node_id: 1,
            snapshot: snap,
        };
        let mut encoded = frame.encode();
        encoded[0] = 0x00; // corrupt magic
        assert!(GossipFrame::decode(&encoded).is_none());
    }

    // ---- Registry: upsert & gossip accept/reject ----
    #[test]
    fn test_registry_upsert_primary() {
        let reg = SessionRegistry::new(1);
        let id = make_id(10);
        let snap = make_snap(id, 0, 1_700_000_100);
        reg.upsert_primary(snap).unwrap();
        assert_eq!(reg.session_count(), 1);
    }

    #[test]
    fn test_gossip_insert_new_session() {
        let reg = SessionRegistry::new(1);
        let id = make_id(20);
        let snap = make_snap(id, 1, 1_700_000_200);
        let frame = GossipFrame {
            sender_node_id: 2,
            snapshot: snap,
        };
        let result = reg.apply_gossip(&frame);
        assert_eq!(result, GossipResult::Inserted);
        assert_eq!(reg.session_count(), 1);
    }

    #[test]
    fn test_gossip_update_fresher_epoch() {
        let reg = SessionRegistry::new(1);
        let id = make_id(30);
        let snap_v1 = make_snap(id, 1, 1_700_000_300);
        let frame_v1 = GossipFrame {
            sender_node_id: 2,
            snapshot: snap_v1,
        };
        reg.apply_gossip(&frame_v1);

        let snap_v2 = make_snap(id, 2, 1_700_000_301);
        let frame_v2 = GossipFrame {
            sender_node_id: 2,
            snapshot: snap_v2,
        };
        let result = reg.apply_gossip(&frame_v2);
        assert_eq!(result, GossipResult::Updated);
    }

    #[test]
    fn test_gossip_reject_stale_epoch() {
        let reg = SessionRegistry::new(1);
        let id = make_id(40);
        let snap_v2 = make_snap(id, 5, 1_700_000_400);
        let frame_v2 = GossipFrame {
            sender_node_id: 2,
            snapshot: snap_v2,
        };
        reg.apply_gossip(&frame_v2);

        // Send older epoch — must be rejected.
        let snap_old = make_snap(id, 3, 1_700_000_399);
        let frame_old = GossipFrame {
            sender_node_id: 2,
            snapshot: snap_old,
        };
        let result = reg.apply_gossip(&frame_old);
        assert!(matches!(
            result,
            GossipResult::Rejected(RejectReason::StaleEpoch { .. })
        ));
    }

    #[test]
    fn test_gossip_ignore_self() {
        let reg = SessionRegistry::new(7);
        let id = make_id(50);
        let snap = make_snap(id, 1, 1_700_000_500);
        let frame = GossipFrame {
            sender_node_id: 7,
            snapshot: snap,
        }; // same node id
        assert_eq!(reg.apply_gossip(&frame), GossipResult::Ignored);
        assert_eq!(reg.session_count(), 0);
    }

    // ---- Transparent migration ----
    #[test]
    fn test_migration_success() {
        let reg = SessionRegistry::new(1);
        let id = make_id(60);
        // Insert as shadow via gossip from node 2.
        let snap = make_snap(id, 2, 1_700_000_600);
        let frame = GossipFrame {
            sender_node_id: 2,
            snapshot: snap,
        };
        reg.apply_gossip(&frame);

        let migrated = reg.migrate_session(id, 1_700_000_601).unwrap();
        assert_eq!(migrated.migration_epoch, 3); // bumped by 1
        assert!(
            reg.build_gossip_frame(&id)
                .unwrap()
                .snapshot
                .migration_epoch
                == 3
        );
    }

    #[test]
    fn test_migration_already_primary() {
        let reg = SessionRegistry::new(1);
        let id = make_id(70);
        let snap = make_snap(id, 0, 1_700_000_700);
        reg.upsert_primary(snap).unwrap();
        let err = reg.migrate_session(id, 1_700_000_701).unwrap_err();
        assert_eq!(err, SyncError::AlreadyPrimary);
    }

    #[test]
    fn test_migration_stale_snapshot() {
        let reg = SessionRegistry::new(1);
        let id = make_id(80);
        // Insert as shadow with captured_unix_secs = 1000 (ancient).
        let snap = make_snap(id, 1, 1000);
        let frame = GossipFrame {
            sender_node_id: 2,
            snapshot: snap,
        };
        reg.apply_gossip(&frame);

        // Attempt migration with now = 1_700_000_000 → age >> 5s.
        let err = reg.migrate_session(id, 1_700_000_000).unwrap_err();
        assert!(matches!(err, SyncError::SnapshotStale { .. }));
    }

    #[test]
    fn test_migration_not_found() {
        let reg = SessionRegistry::new(1);
        let id = make_id(99);
        let err = reg.migrate_session(id, 1_700_000_000).unwrap_err();
        assert_eq!(err, SyncError::SessionNotFound);
    }

    // ---- Remove session ----
    #[test]
    fn test_remove_session() {
        let reg = SessionRegistry::new(1);
        let id = make_id(100);
        let snap = make_snap(id, 0, 1_700_001_000);
        reg.upsert_primary(snap).unwrap();
        assert!(reg.remove_session(&id));
        assert_eq!(reg.session_count(), 0);
        assert!(!reg.remove_session(&id)); // double-remove
    }

    // ---- Telemetry ----
    #[test]
    fn test_telemetry_counters() {
        let reg = SessionRegistry::new(5);
        let id = make_id(200);
        let snap = make_snap(id, 1, 1_700_002_000);
        // Apply valid gossip → gossip_rx +1
        let frame = GossipFrame {
            sender_node_id: 2,
            snapshot: snap,
        };
        reg.apply_gossip(&frame);
        // Apply stale gossip → gossip_rx +1, rejected +1
        let snap_old = make_snap(id, 0, 1_700_001_999);
        let frame_old = GossipFrame {
            sender_node_id: 2,
            snapshot: snap_old,
        };
        reg.apply_gossip(&frame_old);
        // Migrate → migration_count +1
        reg.migrate_session(id, 1_700_002_001).unwrap();

        let tel = reg.telemetry_snapshot();
        assert_eq!(tel.node_id, 5);
        assert_eq!(tel.gossip_rx_count, 2);
        assert_eq!(tel.gossip_rejected_count, 1);
        assert_eq!(tel.migration_count, 1);
        assert_eq!(tel.session_count, 1);
        assert_eq!(tel.gossip_auth_failed_count, 0);
        assert_eq!(tel.gossip_replay_failed_count, 0);
    }

    // ---- ISSP Hardening: Cluster PSK, ChaCha20-Poly1305 & Anti-Replay ----

    #[test]
    fn test_cluster_psk_derivation() {
        let psk1 = ClusterPsk::from_passphrase(b"masque-cluster-secret-prod-eu");
        let psk2 = ClusterPsk::from_passphrase(b"masque-cluster-secret-prod-eu");
        let psk3 = ClusterPsk::from_passphrase(b"masque-cluster-secret-staging");

        assert_eq!(psk1, psk2);
        assert_ne!(psk1, psk3);
        assert_ne!(psk1.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn test_secure_gossip_roundtrip() {
        let psk = ClusterPsk::from_passphrase(b"secure-token-alpha");
        let id = make_id(300);
        let snap = make_snap(id, 4, 1_700_003_000);
        let frame = SecureGossipFrame {
            sender_node_id: 11,
            nonce_seq: 101,
            snapshot: snap,
        };

        let encoded = frame.encode(&psk);
        assert_eq!(encoded.len(), SECURE_GOSSIP_FRAME_SIZE);

        let decoded = SecureGossipFrame::decode(&encoded, &psk).expect("decode failed");
        assert_eq!(decoded.sender_node_id, 11);
        assert_eq!(decoded.nonce_seq, 101);
        assert_eq!(decoded.snapshot.id, id);
        assert_eq!(decoded.snapshot.migration_epoch, 4);
        assert_eq!(decoded.snapshot.tx_seq, 42);
    }

    #[test]
    fn test_secure_gossip_wrong_key() {
        let psk_alice = ClusterPsk::from_passphrase(b"cluster-alice");
        let psk_eve = ClusterPsk::from_passphrase(b"cluster-eve-attacker");

        let id = make_id(301);
        let snap = make_snap(id, 1, 1_700_003_001);
        let frame = SecureGossipFrame {
            sender_node_id: 1,
            nonce_seq: 1,
            snapshot: snap,
        };

        let encoded = frame.encode(&psk_alice);
        let err = SecureGossipFrame::decode(&encoded, &psk_eve).unwrap_err();
        assert_eq!(err, SecurityError::AuthenticationFailed);
    }

    #[test]
    fn test_secure_gossip_tamper_header() {
        let psk = ClusterPsk::from_passphrase(b"cluster-key");
        let id = make_id(302);
        let snap = make_snap(id, 1, 1_700_003_002);
        let frame = SecureGossipFrame {
            sender_node_id: 2,
            nonce_seq: 5,
            snapshot: snap,
        };

        let mut encoded = frame.encode(&psk);
        // Tamper with sender_node_id in AAD (offset 8)
        encoded[8] ^= 0x01;
        let err = SecureGossipFrame::decode(&encoded, &psk).unwrap_err();
        assert_eq!(err, SecurityError::AuthenticationFailed);
    }

    #[test]
    fn test_secure_gossip_tamper_ciphertext() {
        let psk = ClusterPsk::from_passphrase(b"cluster-key");
        let id = make_id(303);
        let snap = make_snap(id, 1, 1_700_003_003);
        let frame = SecureGossipFrame {
            sender_node_id: 2,
            nonce_seq: 6,
            snapshot: snap,
        };

        let mut encoded = frame.encode(&psk);
        // Tamper with ciphertext byte (offset 45)
        encoded[45] ^= 0xFF;
        let err = SecureGossipFrame::decode(&encoded, &psk).unwrap_err();
        assert_eq!(err, SecurityError::AuthenticationFailed);
    }

    #[test]
    fn test_secure_gossip_bad_magic_and_version() {
        let psk = ClusterPsk::from_passphrase(b"cluster-key");
        let id = make_id(304);
        let snap = make_snap(id, 1, 1_700_003_004);
        let frame = SecureGossipFrame {
            sender_node_id: 2,
            nonce_seq: 7,
            snapshot: snap,
        };

        let mut encoded = frame.encode(&psk);
        encoded[0] = 0x00; // corrupt magic
        assert_eq!(
            SecureGossipFrame::decode(&encoded, &psk).unwrap_err(),
            SecurityError::BadMagic
        );

        let mut encoded2 = frame.encode(&psk);
        encoded2[4] = 99; // invalid version
        assert_eq!(
            SecureGossipFrame::decode(&encoded2, &psk).unwrap_err(),
            SecurityError::UnsupportedVersion(99)
        );
    }

    #[test]
    fn test_secure_gossip_anti_replay() {
        let psk = ClusterPsk::from_passphrase(b"cluster-replay-test");
        let reg = SessionRegistry::with_psk(1, psk, SecurityPolicy::StrictPsk);
        let id = make_id(305);
        let snap1 = make_snap(id, 1, 1_700_003_005);

        let frame1 = SecureGossipFrame {
            sender_node_id: 2,
            nonce_seq: 10,
            snapshot: snap1,
        };
        let raw1 = frame1.encode(&psk);

        // First apply -> success (Inserted)
        let res = reg.apply_secure_gossip(&raw1).unwrap();
        assert_eq!(res, GossipResult::Inserted);

        // Replay same seq 10 -> rejected
        let err = reg.apply_secure_gossip(&raw1).unwrap_err();
        assert!(matches!(
            err,
            SecurityError::ReplayDetected {
                last_seq: 10,
                received_seq: 10
            }
        ));

        // Older seq 9 -> rejected
        let snap_old = make_snap(id, 2, 1_700_003_006);
        let frame_old = SecureGossipFrame {
            sender_node_id: 2,
            nonce_seq: 9,
            snapshot: snap_old,
        };
        let raw_old = frame_old.encode(&psk);
        let err_old = reg.apply_secure_gossip(&raw_old).unwrap_err();
        assert!(matches!(
            err_old,
            SecurityError::ReplayDetected {
                last_seq: 10,
                received_seq: 9
            }
        ));

        // Fresh seq 11 -> accepted (Updated)
        let snap_fresh = make_snap(id, 2, 1_700_003_007);
        let frame_fresh = SecureGossipFrame {
            sender_node_id: 2,
            nonce_seq: 11,
            snapshot: snap_fresh,
        };
        let raw_fresh = frame_fresh.encode(&psk);
        let res_fresh = reg.apply_secure_gossip(&raw_fresh).unwrap();
        assert_eq!(res_fresh, GossipResult::Updated);

        // Telemetry check
        let tel = reg.telemetry_snapshot();
        assert_eq!(tel.gossip_replay_failed_count, 2);
    }

    #[test]
    fn test_registry_strict_policy_rejects_plaintext() {
        let psk = ClusterPsk::from_passphrase(b"strict-cluster");
        let reg = SessionRegistry::with_psk(1, psk, SecurityPolicy::StrictPsk);
        let id = make_id(306);
        let snap = make_snap(id, 1, 1_700_003_008);

        let plaintext_frame = GossipFrame {
            sender_node_id: 2,
            snapshot: snap,
        };
        let raw_plain = plaintext_frame.encode();

        let err = reg.apply_raw_gossip(&raw_plain).unwrap_err();
        assert_eq!(
            err,
            RawGossipError::Security(SecurityError::PolicyViolation)
        );
    }

    #[test]
    fn test_registry_permissive_policy_accepts_both() {
        let psk = ClusterPsk::from_passphrase(b"permissive-cluster");
        let reg = SessionRegistry::with_psk(1, psk, SecurityPolicy::Permissive);

        // 1) Apply plaintext v1 frame
        let id1 = make_id(307);
        let snap1 = make_snap(id1, 1, 1_700_003_009);
        let plain_frame = GossipFrame {
            sender_node_id: 2,
            snapshot: snap1,
        };
        let raw_plain = plain_frame.encode();
        let res_plain = reg.apply_raw_gossip(&raw_plain).unwrap();
        assert_eq!(res_plain, GossipResult::Inserted);

        // 2) Apply encrypted v2 frame
        let id2 = make_id(308);
        let snap2 = make_snap(id2, 1, 1_700_003_010);
        let sec_frame = SecureGossipFrame {
            sender_node_id: 3,
            nonce_seq: 1,
            snapshot: snap2,
        };
        let raw_sec = sec_frame.encode(&psk);
        let res_sec = reg.apply_raw_gossip(&raw_sec).unwrap();
        assert_eq!(res_sec, GossipResult::Inserted);

        assert_eq!(reg.session_count(), 2);
    }

    #[test]
    fn test_registry_build_secure_gossip_frame() {
        let psk = ClusterPsk::from_passphrase(b"cluster-builder");
        let reg = SessionRegistry::with_psk(42, psk, SecurityPolicy::StrictPsk);
        let id = make_id(309);
        let snap = make_snap(id, 0, 1_700_003_011);
        reg.upsert_primary(snap).unwrap();

        let secure_bytes = reg
            .build_secure_gossip_frame(&id)
            .expect("frame build failed");
        assert_eq!(secure_bytes.len(), SECURE_GOSSIP_FRAME_SIZE);

        let decoded = SecureGossipFrame::decode(&secure_bytes, &psk).unwrap();
        assert_eq!(decoded.sender_node_id, 42);
        assert_eq!(decoded.snapshot.id, id);
    }

    #[test]
    fn test_telemetry_crypto_and_replay_counters() {
        let psk = ClusterPsk::from_passphrase(b"telem-psk");
        let reg = SessionRegistry::with_psk(1, psk, SecurityPolicy::StrictPsk);

        // Corrupted secure frame -> auth failed counter +1
        let mut corrupted = [0u8; SECURE_GOSSIP_FRAME_SIZE];
        corrupted[0..4].copy_from_slice(&ISSP_MAGIC.to_be_bytes());
        corrupted[4..8].copy_from_slice(&ISSP_VERSION_V2_ENCRYPTED.to_le_bytes());
        let _ = reg.apply_secure_gossip(&corrupted);

        let tel = reg.telemetry_snapshot();
        assert_eq!(tel.gossip_auth_failed_count, 1);
        assert_eq!(tel.gossip_replay_failed_count, 0);
    }

    // ---- ISSP Capsule Transport & on_session_tick Tests ----

    #[test]
    fn test_issp_capsule_wire_roundtrip_v1_plaintext() {
        let id = make_id(400);
        let snap = make_snap(id, 2, 1_700_004_000);
        let frame = GossipFrame {
            sender_node_id: 8,
            snapshot: snap,
        };

        let cap = IsspCapsule::from_gossip_frame(&frame);
        assert_eq!(cap.version, ISSP_VERSION_V1);
        assert_eq!(cap.origin_node_id, 8);
        assert_eq!(cap.payload.len(), GOSSIP_FRAME_SIZE);

        let wire = cap.to_bytes();
        assert_eq!(wire.len(), ISSP_CAPSULE_HEADER_SIZE + GOSSIP_FRAME_SIZE);

        let decoded = IsspCapsule::from_bytes(&wire).expect("decode capsule");
        assert_eq!(decoded.version, ISSP_VERSION_V1);
        assert_eq!(decoded.origin_node_id, 8);
        assert_eq!(decoded.payload, cap.payload);

        // Verify payload can be unpacked back to GossipFrame
        let gf = GossipFrame::decode(decoded.payload.as_slice().try_into().unwrap())
            .expect("decode gossip frame");
        assert_eq!(gf.sender_node_id, 8);
        assert_eq!(gf.snapshot.id, id);
    }

    #[test]
    fn test_issp_capsule_wire_roundtrip_v2_encrypted() {
        let psk = ClusterPsk::from_passphrase(b"capsule-psk");
        let id = make_id(401);
        let snap = make_snap(id, 3, 1_700_004_001);
        let frame = SecureGossipFrame {
            sender_node_id: 15,
            nonce_seq: 77,
            snapshot: snap,
        };
        let encoded_sec = frame.encode(&psk);

        let cap = IsspCapsule::from_secure_frame(15, &encoded_sec);
        assert_eq!(cap.version, ISSP_VERSION_V2_ENCRYPTED);
        assert_eq!(cap.origin_node_id, 15);
        assert_eq!(cap.payload.len(), SECURE_GOSSIP_FRAME_SIZE);

        let wire = cap.to_bytes();
        assert_eq!(
            wire.len(),
            ISSP_CAPSULE_HEADER_SIZE + SECURE_GOSSIP_FRAME_SIZE
        );

        let decoded = IsspCapsule::from_bytes(&wire).expect("decode capsule");
        assert_eq!(decoded.version, ISSP_VERSION_V2_ENCRYPTED);
        assert_eq!(decoded.origin_node_id, 15);

        let sec_decoded =
            SecureGossipFrame::decode(decoded.payload.as_slice().try_into().unwrap(), &psk)
                .expect("decode secure frame");
        assert_eq!(sec_decoded.sender_node_id, 15);
        assert_eq!(sec_decoded.nonce_seq, 77);
        assert_eq!(sec_decoded.snapshot.id, id);
    }

    #[test]
    fn test_issp_capsule_corrupt_magic_and_length() {
        let mut wire = vec![0u8; ISSP_CAPSULE_HEADER_SIZE + 10];
        wire[0..4].copy_from_slice(&0xDEADBEEF_u32.to_be_bytes()); // wrong magic
        assert_eq!(
            IsspCapsule::from_bytes(&wire).unwrap_err(),
            SyncError::BadCapsuleMagic
        );

        let short_wire = vec![0u8; 8];
        assert_eq!(
            IsspCapsule::from_bytes(&short_wire).unwrap_err(),
            SyncError::InvalidCapsuleLength(8)
        );
    }

    #[test]
    fn test_on_session_tick_periodic_snapshot_primary() {
        let reg = SessionRegistry::new(1);
        let id = make_id(402);
        let snap = make_snap(id, 0, 100);
        reg.upsert_primary(snap).unwrap();

        let config = SessionTickConfig {
            snapshot_interval_secs: 2,
            primary_silence_threshold_secs: 3,
            auto_migrate_on_silence: true,
            stale_eviction_secs: 10,
        };

        // Tick at t = 101: elapsed 1s < snapshot_interval (2s) -> no frame generated
        let outcome1 = reg.on_session_tick(101, &config).unwrap();
        assert_eq!(outcome1.outbound_plaintext_frames.len(), 0);
        assert_eq!(outcome1.outbound_capsules.len(), 0);

        // Tick at t = 102: elapsed 2s >= snapshot_interval (2s) -> snapshot frame generated
        let outcome2 = reg.on_session_tick(102, &config).unwrap();
        assert_eq!(outcome2.outbound_plaintext_frames.len(), 1);
        assert_eq!(outcome2.outbound_capsules.len(), 1);
        assert_eq!(
            outcome2.outbound_plaintext_frames[0]
                .snapshot
                .captured_unix_secs,
            102
        );
        assert_eq!(outcome2.auto_migrated_sessions.len(), 0);
    }

    #[test]
    fn test_on_session_tick_auto_migrate_on_silence() {
        // Node 2 has a shadow replica of a session from primary node 1
        let reg = SessionRegistry::new(2);
        let id = make_id(403);
        let snap = make_snap(id, 1, 100); // last captured at t = 100 by primary
        let frame = GossipFrame {
            sender_node_id: 1,
            snapshot: snap,
        };
        reg.apply_gossip(&frame);

        let config = SessionTickConfig {
            snapshot_interval_secs: 1,
            primary_silence_threshold_secs: 2,
            auto_migrate_on_silence: true,
            stale_eviction_secs: 10,
        };

        // At t = 101: silence = 1s < 2s -> no migration
        let outcome1 = reg.on_session_tick(101, &config).unwrap();
        assert_eq!(outcome1.auto_migrated_sessions.len(), 0);

        // At t = 102: silence = 2s >= threshold (2s) -> primary is silent!
        // Node 2 must auto-migrate session, bump epoch to 2, and emit immediate announcement!
        let outcome2 = reg.on_session_tick(102, &config).unwrap();
        assert_eq!(outcome2.auto_migrated_sessions.len(), 1);
        assert_eq!(outcome2.auto_migrated_sessions[0].migration_epoch, 2);
        assert_eq!(outcome2.auto_migrated_sessions[0].captured_unix_secs, 102);

        // Verify cutover broadcast was generated
        assert_eq!(outcome2.outbound_plaintext_frames.len(), 1);
        assert_eq!(
            outcome2.outbound_plaintext_frames[0]
                .snapshot
                .migration_epoch,
            2
        );
        assert_eq!(outcome2.outbound_capsules.len(), 1);

        // Verify node 2 is now primary
        assert_eq!(reg.telemetry_snapshot().migration_count, 1);

        // Next tick at t = 103: node 2 is now primary, so it emits periodic snapshots
        let outcome3 = reg.on_session_tick(103, &config).unwrap();
        assert_eq!(outcome3.auto_migrated_sessions.len(), 0);
        assert_eq!(outcome3.outbound_plaintext_frames.len(), 1);
    }

    #[test]
    fn test_on_session_tick_disabled_auto_migrate() {
        let reg = SessionRegistry::new(2);
        let id = make_id(404);
        let snap = make_snap(id, 1, 100);
        let frame = GossipFrame {
            sender_node_id: 1,
            snapshot: snap,
        };
        reg.apply_gossip(&frame);

        let config = SessionTickConfig {
            snapshot_interval_secs: 1,
            primary_silence_threshold_secs: 2,
            auto_migrate_on_silence: false, // disabled
            stale_eviction_secs: 10,
        };

        // Silence = 3s but auto_migrate is false -> no migration
        let outcome = reg.on_session_tick(103, &config).unwrap();
        assert_eq!(outcome.auto_migrated_sessions.len(), 0);
        assert_eq!(outcome.outbound_plaintext_frames.len(), 0);
    }

    #[test]
    fn test_on_session_tick_stale_eviction() {
        let reg = SessionRegistry::new(2);
        let id = make_id(405);
        let snap = make_snap(id, 1, 100);
        let frame = GossipFrame {
            sender_node_id: 1,
            snapshot: snap,
        };
        reg.apply_gossip(&frame);

        let config = SessionTickConfig {
            snapshot_interval_secs: 1,
            primary_silence_threshold_secs: 2,
            auto_migrate_on_silence: false,
            stale_eviction_secs: 10,
        };

        // At t = 111: age = 11s > stale_eviction_secs (10s) -> evicted
        let outcome = reg.on_session_tick(111, &config).unwrap();
        assert_eq!(outcome.evicted_sessions.len(), 1);
        assert_eq!(outcome.evicted_sessions[0], id);
        assert_eq!(reg.session_count(), 0);
    }

    #[test]
    fn test_session_tick_capsule_ingest_pipeline() {
        let psk = ClusterPsk::from_passphrase(b"tick-capsule-pipeline-secret");
        let node_a = SessionRegistry::with_psk(1, psk, SecurityPolicy::StrictPsk);
        let node_b = SessionRegistry::with_psk(2, psk, SecurityPolicy::StrictPsk);

        let id = make_id(406);
        let snap = make_snap(id, 0, 1_000);
        node_a.upsert_primary(snap).unwrap();

        // Node A produces capsule
        let capsule = node_a.build_issp_capsule(&id).expect("build capsule");
        let wire_bytes = capsule.to_bytes();

        // Wire transmission into Node B
        let decoded_cap = IsspCapsule::from_bytes(&wire_bytes).expect("decode wire");
        let res = node_b
            .ingest_issp_capsule(&decoded_cap)
            .expect("ingest capsule");
        assert_eq!(res, GossipResult::Inserted);

        // Node B now has the session in shadow state
        assert_eq!(node_b.session_count(), 1);

        // Node A becomes silent, Node B ticks at t = 1_003 (silence = 3s)
        let config = SessionTickConfig {
            snapshot_interval_secs: 1,
            primary_silence_threshold_secs: 2,
            auto_migrate_on_silence: true,
            stale_eviction_secs: 10,
        };

        let outcome = node_b.on_session_tick(1_003, &config).unwrap();
        assert_eq!(outcome.auto_migrated_sessions.len(), 1);
        assert_eq!(outcome.auto_migrated_sessions[0].migration_epoch, 1);
        assert_eq!(outcome.outbound_secure_frames.len(), 1);
        assert_eq!(outcome.outbound_capsules.len(), 1);
    }

    #[test]
    fn test_session_id_formatting_and_parsing() {
        let id = SessionId::new(0x0123456789abcdef, 1, 42);
        let s = id.to_canonical_string();
        assert_eq!(s, "0123456789abcdef:0001:002a");
        assert_eq!(format!("{id}"), "0123456789abcdef:0001:002a");

        let parsed = SessionId::parse_str(&s).expect("parse canonical");
        assert_eq!(parsed, id);

        let parsed_plain_hash =
            SessionId::parse_str("0x0123456789abcdef").expect("parse plain hex");
        assert_eq!(parsed_plain_hash.flow_hash, 0x0123456789abcdef);
    }

    #[test]
    fn test_registry_state_dump_and_session_lookup() {
        let reg = SessionRegistry::new(7);
        let id1 = SessionId::new(0x1000, 1, 10);
        let id2 = SessionId::new(0x2000, 2, 20);

        let snap1 = make_snap(id1, 0, 1_000);
        let snap2 = make_snap(id2, 1, 1_000);

        reg.upsert_primary(snap1).unwrap();
        // Insert shadow session via gossip frame
        let frame2 = GossipFrame {
            sender_node_id: 2,
            snapshot: snap2,
        };
        reg.apply_gossip(&frame2);

        assert_eq!(reg.session_count(), 2);
        let list = reg.list_sessions();
        assert_eq!(list.len(), 2);
        assert!(list[0].is_primary);
        assert!(!list[1].is_primary);

        // find_session
        let found = reg.find_session("1000").expect("find by hash");
        assert_eq!(found.snapshot.id, id1);
        let found_canon = reg
            .find_session(&id2.to_canonical_string())
            .expect("find by canonical");
        assert_eq!(found_canon.snapshot.id, id2);

        // Export and import state dump
        let dump_bytes = reg.export_state_dump();
        assert!(dump_bytes.len() >= ISSP_DUMP_HEADER_SIZE + 2 * 97);

        let imported = SessionRegistry::import_state_dump(&dump_bytes).expect("import state dump");
        assert_eq!(imported.node_id, 7);
        assert_eq!(imported.session_count(), 2);

        let rec1 = imported.get_session(&id1).expect("rec1");
        assert!(rec1.is_primary);
        assert_eq!(rec1.snapshot.tx_seq, snap1.tx_seq);

        let rec2 = imported.get_session(&id2).expect("rec2");
        assert!(!rec2.is_primary);
        assert_eq!(rec2.snapshot.migration_epoch, snap2.migration_epoch);
    }

    #[test]
    fn test_issp_heartbeat_probe_encoding_decoding_and_crc() {
        let probe = IsspHeartbeatProbe::new(101, 2, 42, 1_700_000_123_456, false);
        let wire = probe.encode();
        assert_eq!(wire.len(), ISSP_HEARTBEAT_SIZE);

        let decoded = IsspHeartbeatProbe::decode(&wire).expect("valid decode");
        assert_eq!(decoded.sender_node_id, 101);
        assert_eq!(decoded.path_id, 2);
        assert_eq!(decoded.probe_seq, 42);
        assert_eq!(decoded.timestamp_unix_ms, 1_700_000_123_456);
        assert!(!decoded.is_response);

        // Corrupt one byte -> decode must reject
        let mut corrupted = wire;
        corrupted[10] ^= 0xFF;
        assert!(IsspHeartbeatProbe::decode(&corrupted).is_none());

        // Pong response probe
        let pong = IsspHeartbeatProbe::new(102, 2, 42, 1_700_000_123_456, true);
        let wire_pong = pong.encode();
        let dec_pong = IsspHeartbeatProbe::decode(&wire_pong).expect("valid pong");
        assert!(dec_pong.is_response);
    }

    #[test]
    fn test_dynamic_multipath_router_registration_and_steering() {
        let mut router = IsspDynamicMultipathRouter::new(1, IsspRoutingPolicy::ActiveStandby);

        let route1 =
            IsspMultipathRoute::new(1, 2, "eth0-wan", 1, 100).with_state(IsspPathState::Active);
        let route2 =
            IsspMultipathRoute::new(2, 2, "wwan0-5g", 2, 50).with_state(IsspPathState::Standby);

        router.add_route(route1);
        router.add_route(route2);
        assert_eq!(router.list_routes().len(), 2);

        let s1 = SessionId::new(0x1111, 1, 1);
        let s2 = SessionId::new(0x2222, 1, 2);

        let p1 = router.resolve_path_for_session(&s1, 1_000).unwrap();
        let p2 = router.resolve_path_for_session(&s2, 1_000).unwrap();

        assert_eq!(p1, 1); // Primary active path
        assert_eq!(p2, 1);
    }

    #[test]
    fn test_dynamic_multipath_heartbeat_timeout_and_automatic_failover() {
        let mut router = IsspDynamicMultipathRouter::new(1, IsspRoutingPolicy::ActiveStandby);

        let mut r1 = IsspMultipathRoute::new(1, 10, "eth0-fiber", 1, 100)
            .with_state(IsspPathState::Active)
            .with_heartbeat_config(500, 1500, 3);
        r1.metrics.last_heartbeat_recv_unix_ms = 1_000;

        let mut r2 = IsspMultipathRoute::new(2, 10, "wwan0-5g", 2, 80)
            .with_state(IsspPathState::Standby)
            .with_heartbeat_config(500, 1500, 3);
        r2.metrics.last_heartbeat_recv_unix_ms = 1_000;

        router.add_route(r1);
        router.add_route(r2);

        let s1 = SessionId::new(0x100, 1, 1);
        let s2 = SessionId::new(0x200, 1, 2);
        router.bind_session(s1, 1).unwrap();
        router.bind_session(s2, 1).unwrap();

        assert_eq!(router.get_session_path(&s1), Some(1));
        assert_eq!(router.get_session_path(&s2), Some(1));

        // Send pings at t = 1_500
        let p1_ping = router.create_heartbeat_ping(1, 1_500).unwrap();
        let p2_ping = router.create_heartbeat_ping(2, 1_500).unwrap();
        assert_eq!(p1_ping.path_id, 1);
        assert_eq!(p2_ping.path_id, 2);

        // Path 2 responds with pong at t = 1_520 (RTT = 20ms)
        let pong2 = IsspHeartbeatProbe::new(10, 2, p2_ping.probe_seq, 1_500, true);
        router.process_heartbeat_probe(&pong2, 1_520).unwrap();
        // EWMA: (7 * 10_000 + 20_000) / 8 = 11_250 us
        assert_eq!(router.get_route(2).unwrap().metrics.smoothed_rtt_us, 11_250);

        // Path 1 receives NO replies!
        // At t = 2_600: silence on Path 1 = 1600ms >= heartbeat_timeout_ms (1500ms)
        let failovers = router.evaluate_heartbeats_and_failover(2_600);
        assert_eq!(failovers.len(), 1);

        let ev = &failovers[0];
        assert_eq!(ev.failed_path_id, 1);
        assert_eq!(ev.target_path_id, 2);
        assert_eq!(ev.reason, IsspFailoverReason::HeartbeatTimeout);
        assert_eq!(ev.sessions_rerouted, 2);
        assert!(ev.cutover_latency_us < 50_000.0); // Sub-50ms cutover

        // Verify Path 1 is marked Failed, Path 2 is promoted to Active
        assert_eq!(router.get_route(1).unwrap().state, IsspPathState::Failed);
        assert_eq!(router.get_route(2).unwrap().state, IsspPathState::Active);

        // Verify sessions are automatically remapped to Path 2!
        assert_eq!(router.get_session_path(&s1), Some(2));
        assert_eq!(router.get_session_path(&s2), Some(2));
        assert_eq!(router.resolve_path_for_session(&s1, 2_600).unwrap(), 2);

        // Recovery: Path 1 receives pong probe -> restored to Standby
        let recover_pong = IsspHeartbeatProbe::new(10, 1, 99, 2_650, true);
        router
            .process_heartbeat_probe(&recover_pong, 2_670)
            .unwrap();
        assert_eq!(router.get_route(1).unwrap().state, IsspPathState::Standby);

        // Telemetry check
        let telem = router.telemetry();
        assert_eq!(telem.total_paths, 2);
        assert_eq!(telem.active_paths, 1);
        assert_eq!(telem.standby_paths, 1);
        assert_eq!(telem.failed_paths, 0);
        assert_eq!(telem.total_failovers, 1);
    }

    #[test]
    fn test_registry_tick_multipath_heartbeat_failover_integration() {
        let reg = SessionRegistry::new(99);

        let mut r_wan = IsspMultipathRoute::new(10, 200, "eth0-wan", 1, 100)
            .with_state(IsspPathState::Active)
            .with_heartbeat_config(1_000, 2_000, 2);
        r_wan.metrics.last_heartbeat_recv_unix_ms = 1_000_000;

        let r_sat = IsspMultipathRoute::new(20, 200, "leo-sat", 2, 40)
            .with_state(IsspPathState::Standby)
            .with_heartbeat_config(1_000, 2_000, 2);

        reg.add_multipath_route(r_wan).unwrap();
        reg.add_multipath_route(r_sat).unwrap();

        let sid = SessionId::new(0x9999, 99, 1);
        let snap = make_snap(sid, 0, 1_000);
        reg.upsert_primary(snap).unwrap();

        // Bind session to path 10
        assert_eq!(reg.resolve_session_path(&sid, 1_000_000).unwrap(), 10);

        // Simulate tick at t = 1_003_000 ms (unix secs = 1003)
        // Elapsed silence on path 10 = 3000ms >= 2000ms timeout
        let config = SessionTickConfig::default();
        let outcome = reg.on_session_tick(1_003, &config).unwrap();

        assert_eq!(outcome.multipath_failover_events.len(), 1);
        let ev = &outcome.multipath_failover_events[0];
        assert_eq!(ev.failed_path_id, 10);
        assert_eq!(ev.target_path_id, 20);

        // Session is now dynamically served by path 20
        assert_eq!(reg.resolve_session_path(&sid, 1_003_000).unwrap(), 20);
    }

    #[test]
    fn test_resequencing_buffer_in_order_and_out_of_order_drain() {
        let mut reseq = IsspResequencingBuffer::new(1, 64, 200);
        let s_id = SessionId::new(0x1234, 1, 1);

        let p1 = IsspScheduledPacket {
            multipath_seq: 1,
            path_id: 10,
            session_id: s_id,
            payload: b"pkt1".to_vec(),
            scheduled_timestamp_unix_ms: 1000,
            estimated_arrival_unix_ms: 1010,
        };
        let p2 = IsspScheduledPacket {
            multipath_seq: 2,
            path_id: 10,
            session_id: s_id,
            payload: b"pkt2".to_vec(),
            scheduled_timestamp_unix_ms: 1002,
            estimated_arrival_unix_ms: 1012,
        };
        let p3 = IsspScheduledPacket {
            multipath_seq: 3,
            path_id: 20,
            session_id: s_id,
            payload: b"pkt3".to_vec(),
            scheduled_timestamp_unix_ms: 1004,
            estimated_arrival_unix_ms: 1060,
        };
        let p4 = IsspScheduledPacket {
            multipath_seq: 4,
            path_id: 10,
            session_id: s_id,
            payload: b"pkt4".to_vec(),
            scheduled_timestamp_unix_ms: 1006,
            estimated_arrival_unix_ms: 1016,
        };

        // Ingest p1 at t = 1010
        let (del1, st1) = reseq.ingest(p1, 1010);
        assert_eq!(del1.len(), 1);
        assert_eq!(del1[0].packet.multipath_seq, 1);
        assert!(!del1[0].was_reordered);
        assert_eq!(st1, IsspResequenceStatus::InOrderDelivered);

        // Ingest p2 at t = 1012
        let (del2, st2) = reseq.ingest(p2, 1012);
        assert_eq!(del2.len(), 1);
        assert_eq!(del2[0].packet.multipath_seq, 2);
        assert!(!del2[0].was_reordered);
        assert_eq!(st2, IsspResequenceStatus::InOrderDelivered);

        // Ingest p4 at t = 1016 (Out of order: p3 has not arrived yet!)
        let (del4, st4) = reseq.ingest(p4, 1016);
        assert_eq!(del4.len(), 0);
        assert_eq!(
            st4,
            IsspResequenceStatus::Buffered {
                buffered_seq: 4,
                expected_seq: 3,
                buffer_depth: 1,
            }
        );

        // Now p3 arrives at t = 1060 (arriving on slower path 20)
        let (del3, st3) = reseq.ingest(p3, 1060);
        // It must deliver both p3 and p4 in strictly contiguous order!
        assert_eq!(del3.len(), 2);
        assert_eq!(del3[0].packet.multipath_seq, 3);
        assert!(!del3[0].was_reordered);
        assert_eq!(del3[1].packet.multipath_seq, 4);
        assert!(del3[1].was_reordered);
        assert_eq!(del3[1].reorder_delay_ms, 1060 - 1016); // 44ms in buffer
        assert_eq!(
            st3,
            IsspResequenceStatus::ResequencedDelivered { delivered_count: 2 }
        );

        let telem = reseq.telemetry();
        assert_eq!(telem.total_received, 4);
        assert_eq!(telem.in_order_count, 3); // 1, 2, 3
        assert_eq!(telem.reordered_count, 1); // 4 was buffered and resequenced
        assert_eq!(telem.buffer_depth, 0);
        assert_eq!(telem.max_reorder_delay_ms, 44);
    }

    #[test]
    fn test_resequencing_buffer_duplicate_and_gap_timeout() {
        let mut reseq = IsspResequencingBuffer::new(10, 32, 100);
        let s_id = SessionId::new(0x4444, 2, 2);

        let make_pkt = |seq: u64| IsspScheduledPacket {
            multipath_seq: seq,
            path_id: 1,
            session_id: s_id,
            payload: format!("data-{}", seq).into_bytes(),
            scheduled_timestamp_unix_ms: 1000,
            estimated_arrival_unix_ms: 1010,
        };

        // Ingest duplicate / stale seq 9
        let (del_stale, st_stale) = reseq.ingest(make_pkt(9), 1010);
        assert!(del_stale.is_empty());
        assert_eq!(
            st_stale,
            IsspResequenceStatus::DuplicateOrStale {
                seq: 9,
                expected_seq: 10
            }
        );

        // Ingest seq 10 (in-order)
        let (del10, _) = reseq.ingest(make_pkt(10), 1010);
        assert_eq!(del10.len(), 1);

        // Ingest seq 12 and 13 (seq 11 is lost!)
        let (del12, st12) = reseq.ingest(make_pkt(12), 1015);
        assert!(del12.is_empty());
        assert!(matches!(st12, IsspResequenceStatus::Buffered { .. }));

        let (del13, _) = reseq.ingest(make_pkt(13), 1020);
        assert!(del13.is_empty());

        // Ingest duplicate seq 12
        let (del12_dup, st12_dup) = reseq.ingest(make_pkt(12), 1025);
        assert!(del12_dup.is_empty());
        assert!(matches!(
            st12_dup,
            IsspResequenceStatus::DuplicateOrStale { .. }
        ));

        // Check timeout at t = 1050 (elapsed 35ms < 100ms) -> no timeout yet
        let (tout_early, st_early) = reseq.check_gap_timeout(1050);
        assert!(tout_early.is_empty());
        assert!(st_early.is_none());

        // Check timeout at t = 1120 (elapsed 105ms >= 100ms) -> gap 11 expired!
        let (tout_drain, st_drain) = reseq.check_gap_timeout(1120);
        assert_eq!(tout_drain.len(), 2); // delivers 12 and 13
        assert_eq!(tout_drain[0].packet.multipath_seq, 12);
        assert_eq!(tout_drain[1].packet.multipath_seq, 13);
        assert_eq!(
            st_drain,
            Some(IsspResequenceStatus::GapExpired {
                skipped_seq: 11,
                new_expected_seq: 14,
                flushed_count: 2,
            })
        );
        assert_eq!(reseq.expected_seq, 14);
    }

    #[test]
    fn test_dynamic_multipath_bandwidth_aggregation_scheduling() {
        let mut router =
            IsspDynamicMultipathRouter::new(1, IsspRoutingPolicy::BandwidthAggregation);

        // Path 1: 1Gbps Fiber (Weight 100, RTT 10ms)
        let mut r1 =
            IsspMultipathRoute::new(1, 10, "eth0-fiber", 1, 100).with_state(IsspPathState::Active);
        r1.metrics.smoothed_rtt_us = 10_000;

        // Path 2: 500Mbps 5G (Weight 50, RTT 40ms)
        let mut r2 =
            IsspMultipathRoute::new(2, 10, "wwan0-5g", 2, 50).with_state(IsspPathState::Active);
        r2.metrics.smoothed_rtt_us = 40_000;

        router.add_route(r1);
        router.add_route(r2);

        let s_id = SessionId::new(0x7777, 1, 1);
        let mut count_p1 = 0;
        let mut count_p2 = 0;

        for i in 1..=30 {
            let pkt = router
                .schedule_packet(&s_id, vec![0u8; 128], 1_000 + i)
                .unwrap();
            assert_eq!(pkt.multipath_seq, i);
            if pkt.path_id == 1 {
                count_p1 += 1;
            } else if pkt.path_id == 2 {
                count_p2 += 1;
            }
        }

        // With weights 100 vs 50, Path 1 should schedule approximately double Path 2
        assert_eq!(count_p1 + count_p2, 30);
        assert!((18..=22).contains(&count_p1), "count_p1 was {}", count_p1);
        assert!((8..=12).contains(&count_p2), "count_p2 was {}", count_p2);

        let r1_m = router.get_route(1).unwrap();
        let r2_m = router.get_route(2).unwrap();
        assert_eq!(r1_m.metrics.total_frames_sent, count_p1);
        assert_eq!(r2_m.metrics.total_frames_sent, count_p2);
    }

    #[test]
    fn test_end_to_end_bandwidth_aggregation_and_resequencing_under_skew() {
        let reg = SessionRegistry::new(1);
        {
            let mut router = reg.multipath_router.lock().unwrap();
            router.policy = IsspRoutingPolicy::BandwidthAggregation;

            // Fast path (RTT 10ms, weight 100)
            let mut r_fast = IsspMultipathRoute::new(1, 10, "fiber-fast", 1, 100)
                .with_state(IsspPathState::Active);
            r_fast.metrics.smoothed_rtt_us = 10_000; // 5ms one-way

            // Slow path (RTT 80ms, weight 50)
            let mut r_slow = IsspMultipathRoute::new(2, 10, "wwan-slow", 2, 50)
                .with_state(IsspPathState::Active);
            r_slow.metrics.smoothed_rtt_us = 80_000; // 40ms one-way

            router.add_route(r_fast);
            router.add_route(r_slow);
        }

        let s_id = SessionId::new(0x8888, 1, 1);
        let t_start = 10_000;

        // Schedule 15 packets
        let mut inflight = Vec::new();
        for i in 0..15 {
            let pkt = reg
                .schedule_multipath_packet(
                    &s_id,
                    format!("msg-{}", i + 1).into_bytes(),
                    t_start + i * 2,
                )
                .unwrap();
            let arrival_time = pkt.estimated_arrival_unix_ms;
            inflight.push((pkt, arrival_time));
        }

        // Sort by simulated physical arrival time (simulating faster path arriving earlier)
        inflight.sort_by_key(|(_, arr)| *arr);

        // Verify that packets are out-of-order in transit due to latency skew
        let arrival_seqs: Vec<u64> = inflight.iter().map(|(p, _)| p.multipath_seq).collect();
        let is_strictly_ordered = arrival_seqs.windows(2).all(|w| w[0] < w[1]);
        assert!(
            !is_strictly_ordered,
            "Latency skew must cause out-of-order packet arrivals: {:?}",
            arrival_seqs
        );

        // Ingest into resequencing buffer in arrival order
        let mut final_delivered = Vec::new();
        for (pkt, arrival_time) in inflight {
            let (delivered, _) = reg.ingest_multipath_packet(pkt, arrival_time).unwrap();
            final_delivered.extend(delivered);
        }

        // All 15 packets must be delivered in strictly contiguous in-order sequence 1..=15
        assert_eq!(final_delivered.len(), 15);
        for (idx, d) in final_delivered.iter().enumerate() {
            assert_eq!(d.packet.multipath_seq, (idx + 1) as u64);
        }

        // Telemetry check
        let telem = reg.resequencing_telemetry(Some(&s_id)).unwrap().unwrap();
        assert_eq!(telem.total_received, 15);
        assert!(telem.reordered_count > 0);
        assert!(telem.reorder_rate_percent > 0.0);
        assert_eq!(telem.duplicate_count, 0);
        assert_eq!(telem.gaps_expired_count, 0);
    }

    #[test]
    fn test_route_flap_damping_suppression_and_decay() {
        let mut router = IsspDynamicMultipathRouter::new(1, IsspRoutingPolicy::ActiveStandby);
        // Half-life 10s (10_000ms), suppress at 1800, reuse at 750
        router.flap_damping_config = IsspFlapDampingConfig {
            enabled: true,
            flap_penalty: 1000.0,
            suppress_threshold: 1800.0,
            reuse_threshold: 750.0,
            half_life_ms: 10_000,
            max_suppress_penalty: 5000.0,
        };

        let mut r1 = IsspMultipathRoute::new(1, 2, "eth0-wan", 1, 100)
            .with_state(IsspPathState::Active)
            .with_heartbeat_config(500, 1500, 3);
        r1.metrics.last_heartbeat_recv_unix_ms = 1_000;

        let mut r2 = IsspMultipathRoute::new(2, 2, "wwan0-5g", 2, 50)
            .with_state(IsspPathState::Standby)
            .with_heartbeat_config(500, 5000, 3);
        r2.metrics.last_heartbeat_recv_unix_ms = 2_500;

        router.add_route(r1);
        router.add_route(r2);

        // Flap 1 on Path 1 at t = 2_600ms (timeout)
        let f1 = router.evaluate_heartbeats_and_failover(2_600);
        assert_eq!(f1.len(), 1);
        assert_eq!(router.get_route(1).unwrap().state, IsspPathState::Failed);
        assert_eq!(router.get_route(1).unwrap().flap_state.flap_count, 1);
        assert_eq!(router.get_route(1).unwrap().flap_state.penalty, 1000.0);
        assert!(!router.get_route(1).unwrap().flap_state.is_suppressed);

        // Pong arrives at t = 2_700ms -> recovers to Standby (not suppressed)
        let pong = IsspHeartbeatProbe::new(2, 1, 1, 2_650, true);
        router.process_heartbeat_probe(&pong, 2_700).unwrap();
        assert_eq!(router.get_route(1).unwrap().state, IsspPathState::Standby);

        // Flap 2 on Path 1 at t = 4_500ms (only 1.8s later)
        // Set consecutive missed heartbeats
        router
            .get_route_mut(1)
            .unwrap()
            .metrics
            .consecutive_missed_heartbeats = 3;
        let f2 = router.evaluate_heartbeats_and_failover(4_500);
        assert_eq!(f2.len(), 1);

        let r1_route = router.get_route(1).unwrap();
        assert_eq!(r1_route.state, IsspPathState::Failed);
        assert_eq!(r1_route.flap_state.flap_count, 2);
        // Penalty should be > 1800 (1000 decayed slightly + 1000) >= suppress_threshold 2000
        assert!(r1_route.flap_state.penalty >= 1800.0);
        assert!(r1_route.flap_state.is_suppressed);

        // Now, another pong arrives at t = 4_600ms while still suppressed!
        let pong_damped = IsspHeartbeatProbe::new(2, 1, 2, 4_550, true);
        router.process_heartbeat_probe(&pong_damped, 4_600).unwrap();
        // Crucial test: Route remains Failed because flap damping is suppressing it!
        assert_eq!(router.get_route(1).unwrap().state, IsspPathState::Failed);
        assert!(router.get_route(1).unwrap().flap_state.is_suppressed);

        // Telemetry check
        let telem = router.telemetry();
        assert_eq!(telem.failed_paths, 1);
        assert_eq!(telem.suppressed_paths, 1);
        assert_eq!(telem.total_flaps, 2);

        // Advance time by 20 seconds (2 half-lives: penalty / 4)
        // t = 24_600ms
        let pong_after_decay = IsspHeartbeatProbe::new(2, 1, 3, 24_550, true);
        router
            .process_heartbeat_probe(&pong_after_decay, 24_600)
            .unwrap();

        // Penalty has decayed below reuse_threshold (750), suppression is cleared and route recovers!
        let r1_recovered = router.get_route(1).unwrap();
        assert!(!r1_recovered.flap_state.is_suppressed);
        assert!(r1_recovered.flap_state.penalty < 750.0);
        assert_eq!(r1_recovered.state, IsspPathState::Standby);
    }

    #[test]
    fn test_progressive_probation_ramping_and_graduation() {
        let mut router =
            IsspDynamicMultipathRouter::new(1, IsspRoutingPolicy::BandwidthAggregation);
        // Enable progressive probation: 4_000ms duration, 4 probes, initial ratio 20%
        router.probation_config = IsspProbationConfig {
            enabled: true,
            probation_duration_ms: 4_000,
            min_successful_probes: 4,
            initial_weight_ratio: 0.20,
            max_loss_ppm_tolerance: 10_000,
        };

        let mut r1 =
            IsspMultipathRoute::new(1, 2, "eth0-primary", 1, 100).with_state(IsspPathState::Failed);
        r1.metrics.last_heartbeat_recv_unix_ms = 1_000;

        let r2 =
            IsspMultipathRoute::new(2, 2, "wwan0-backup", 2, 50).with_state(IsspPathState::Active);

        router.add_route(r1);
        router.add_route(r2);

        // Initial state of r1 is Failed -> effective_weight = 0
        assert_eq!(router.get_route(1).unwrap().effective_weight(), 0);

        // Recovery pong #1 arrives at t = 10_000ms -> enters Probation!
        let p1 = IsspHeartbeatProbe::new(2, 1, 1, 9_950, true);
        router.process_heartbeat_probe(&p1, 10_000).unwrap();

        let r1 = router.get_route(1).unwrap();
        assert_eq!(r1.state, IsspPathState::Probation);
        assert!(r1.state.is_usable());
        // At 20% initial ratio of weight 100 -> effective weight is 20!
        assert_eq!(r1.effective_weight(), 20);
        assert_eq!(r1.probation_state.successful_probes, 1);

        // Pong #2 at t = 11_000ms (+1s, 2 probes) -> ramp increases
        let p2 = IsspHeartbeatProbe::new(2, 1, 2, 10_950, true);
        router.process_heartbeat_probe(&p2, 11_000).unwrap();
        let r1 = router.get_route(1).unwrap();
        assert_eq!(r1.state, IsspPathState::Probation);
        assert!(r1.effective_weight() > 20);
        let weight_probe_2 = r1.effective_weight();

        // Pong #3 at t = 12_500ms (+2.5s, 3 probes) -> ramp increases further
        let p3 = IsspHeartbeatProbe::new(2, 1, 3, 12_450, true);
        router.process_heartbeat_probe(&p3, 12_500).unwrap();
        let r1 = router.get_route(1).unwrap();
        assert_eq!(r1.state, IsspPathState::Probation);
        assert!(r1.effective_weight() > weight_probe_2);

        // Pong #4 at t = 14_100ms (+4.1s >= 4000ms duration, 4 probes >= 4 required)
        let p4 = IsspHeartbeatProbe::new(2, 1, 4, 14_050, true);
        router.process_heartbeat_probe(&p4, 14_100).unwrap();

        // Path 1 graduates from probation back to Active (priority 1) with 100% nominal weight!
        let r1 = router.get_route(1).unwrap();
        assert_eq!(r1.state, IsspPathState::Active);
        assert_eq!(r1.effective_weight(), 100);
        assert!(r1.probation_state.is_graduated);

        // Verify graduation event is logged in reintegration history
        assert_eq!(router.reintegration_history().len(), 1);
        let ev = &router.reintegration_history()[0];
        assert_eq!(ev.path_id, 1);
        assert_eq!(ev.probation_duration_ms, 4_000);
        assert_eq!(ev.successful_probes, 4);
        assert_eq!(ev.restored_state, IsspPathState::Active);
        assert_eq!(router.total_reintegrations, 1);
    }

    #[test]
    fn test_progressive_probation_aborted_on_flapping() {
        let mut router = IsspDynamicMultipathRouter::new(1, IsspRoutingPolicy::ActiveStandby);
        router.probation_config = IsspProbationConfig {
            enabled: true,
            probation_duration_ms: 5_000,
            min_successful_probes: 5,
            initial_weight_ratio: 0.25,
            max_loss_ppm_tolerance: 10_000,
        };

        let mut r1 = IsspMultipathRoute::new(1, 2, "eth0-primary", 1, 100)
            .with_state(IsspPathState::Failed)
            .with_heartbeat_config(500, 1500, 3);
        r1.metrics.last_heartbeat_recv_unix_ms = 1_000;

        let mut r2 = IsspMultipathRoute::new(2, 2, "wwan0-backup", 2, 50)
            .with_state(IsspPathState::Active)
            .with_heartbeat_config(500, 5000, 3);
        r2.metrics.last_heartbeat_recv_unix_ms = 10_000;

        router.add_route(r1);
        router.add_route(r2);

        // Path 1 receives recovery pong -> enters probation
        let p1 = IsspHeartbeatProbe::new(2, 1, 1, 9_950, true);
        router.process_heartbeat_probe(&p1, 10_000).unwrap();
        assert_eq!(router.get_route(1).unwrap().state, IsspPathState::Probation);
        assert_eq!(router.get_route(1).unwrap().effective_weight(), 25);

        // While in probation, path 1 misses heartbeats and times out at t = 11_600ms
        let failovers = router.evaluate_heartbeats_and_failover(11_600);
        assert_eq!(failovers.len(), 1);

        let r1_aborted = router.get_route(1).unwrap();
        assert_eq!(r1_aborted.state, IsspPathState::Failed);
        assert!(!r1_aborted.probation_state.in_probation);
        assert_eq!(r1_aborted.probation_state.successful_probes, 0);
        assert_eq!(r1_aborted.effective_weight(), 0);
        assert!(r1_aborted.flap_state.flap_count >= 1);
    }

    #[test]
    fn test_session_header_uncompressed_roundtrip() {
        let s_id = SessionId::new(0x0123_4567_89ab_cdef, 1, 42);
        let hdr = IsspSessionHeader::new(s_id, 101, 15, 1_700_000_000_123, 0x0003, 2);
        let wire = hdr.encode_uncompressed();
        assert_eq!(wire.len(), ISSP_SESSION_HEADER_UNCOMPRESSED_SIZE);

        let decoded = IsspSessionHeader::decode_uncompressed(&wire).unwrap();
        assert_eq!(decoded, hdr);
    }

    #[test]
    fn test_adaptive_header_compression_ratio() {
        let mut comp = IsspAdaptiveHeaderCompressor::new(32);
        let mut decomp = IsspAdaptiveHeaderCompressor::new(32);

        let s_id = SessionId::new(0xfeeb_daed_caf0_1234, 2, 99);
        let base_ts = 1_000_000u64;

        // Packet 1: Full Header
        let h1 = IsspSessionHeader::new(s_id, 1, 1, base_ts, 0x10, 1);
        let (is_full1, w1) = comp.compress_header(&h1, 0);
        assert!(is_full1);
        assert_eq!(w1.len(), 47);

        let d1 = decomp.decompress_header(&w1).unwrap();
        assert_eq!(d1, h1);

        // Packets 2..30: Compressed Headers (nominal consecutive sequence, flags same, delta ts <= 255)
        for i in 2..=30 {
            let h = IsspSessionHeader::new(s_id, i, i, base_ts + (i - 1) * 20, 0x10, 1);
            let (is_full, w) = comp.compress_header(&h, 0);
            assert!(!is_full);
            // In nominal sequential mode: control byte (1) + context id (1) + ts delta (1) = 3 bytes
            assert_eq!(
                w.len(),
                3,
                "packet {} compressed header size should be 3",
                i
            );

            let d = decomp.decompress_header(&w).unwrap();
            assert_eq!(d, h);
        }

        let tele = comp.telemetry();
        assert_eq!(tele.total_packets, 30);
        assert_eq!(tele.full_headers_count, 1);
        assert_eq!(tele.compressed_headers_count, 29);
        assert!(tele.compression_ratio_percent > 85.0);
        assert_eq!(tele.decompression_resyncs, 0);
    }

    #[test]
    fn test_subpath_crypto_tunnel_modes() {
        let key = IsspSubpathKey::from_passphrase("cluster-subpath-test-secret");
        let aad = b"test-aad-metadata";
        let plaintext = b"Hello ISSP encrypted multi-tunnel packet!";

        // Mode Plaintext
        let mut tunnel_plain =
            IsspSubpathCryptoTunnel::new(1, OpportunisticSecurityLevel::Plaintext, None);
        let (enc, seq, ct, tag) = tunnel_plain.encrypt_payload(aad, plaintext).unwrap();
        assert!(!enc);
        assert_eq!(tag, None);
        let dec = tunnel_plain
            .decrypt_payload(enc, seq, aad, &ct, tag.as_ref())
            .unwrap();
        assert_eq!(dec, plaintext);

        // Mode Required without key -> fails
        let mut tunnel_req_nokey =
            IsspSubpathCryptoTunnel::new(2, OpportunisticSecurityLevel::Required, None);
        assert_eq!(
            tunnel_req_nokey
                .encrypt_payload(aad, plaintext)
                .unwrap_err(),
            SyncError::EncryptionRequired
        );

        // Mode Required with key -> succeeds AEAD
        let mut tunnel_req_key = IsspSubpathCryptoTunnel::new(
            3,
            OpportunisticSecurityLevel::Required,
            Some(key.clone()),
        );
        let (enc2, seq2, ct2, tag2) = tunnel_req_key.encrypt_payload(aad, plaintext).unwrap();
        assert!(enc2);
        assert!(tag2.is_some());
        assert_ne!(&ct2[..], plaintext);

        // Receiver tunnel
        let mut tunnel_rx = IsspSubpathCryptoTunnel::new(
            3,
            OpportunisticSecurityLevel::Required,
            Some(key.clone()),
        );
        let dec2 = tunnel_rx
            .decrypt_payload(enc2, seq2, aad, &ct2, tag2.as_ref())
            .unwrap();
        assert_eq!(dec2, plaintext);

        // Tampering payload -> authentication failed
        let mut tampered = ct2.clone();
        tampered[0] ^= 0xff;
        assert_eq!(
            tunnel_rx
                .decrypt_payload(enc2, seq2 + 1, aad, &tampered, tag2.as_ref())
                .unwrap_err(),
            SyncError::AuthenticationFailed
        );
    }

    #[test]
    fn test_subpath_crypto_anti_replay() {
        let key = IsspSubpathKey::from_passphrase("anti-replay-secret-test");
        let aad = b"aad";
        let mut tx = IsspSubpathCryptoTunnel::new(
            1,
            OpportunisticSecurityLevel::Required,
            Some(key.clone()),
        );
        let mut rx =
            IsspSubpathCryptoTunnel::new(1, OpportunisticSecurityLevel::Required, Some(key));

        let (enc, seq, ct, tag) = tx.encrypt_payload(aad, b"msg1").unwrap();
        let _ = rx
            .decrypt_payload(enc, seq, aad, &ct, tag.as_ref())
            .unwrap();

        // Replay of same seq -> rejected by anti-replay
        let err = rx
            .decrypt_payload(enc, seq, aad, &ct, tag.as_ref())
            .unwrap_err();
        assert_eq!(err, SyncError::ReplayPacketDropped);
    }

    #[test]
    fn test_router_subpath_packet_roundtrip_with_compression_and_crypto() {
        let mut sender = IsspDynamicMultipathRouter::new(1, IsspRoutingPolicy::ActiveStandby);
        let mut receiver = IsspDynamicMultipathRouter::new(2, IsspRoutingPolicy::ActiveStandby);

        let sub_key = IsspSubpathKey::from_passphrase("multi-tunnel-mesh-psk");

        let r1 = IsspMultipathRoute::new(1, 2, "eth0-secure", 1, 100)
            .with_security_level(OpportunisticSecurityLevel::Opportunistic);
        sender.add_route(r1.clone());
        receiver.add_route(r1);

        sender.configure_subpath_security(
            1,
            OpportunisticSecurityLevel::Opportunistic,
            Some(sub_key.clone()),
        );
        receiver.configure_subpath_security(
            1,
            OpportunisticSecurityLevel::Opportunistic,
            Some(sub_key),
        );

        let s_id = SessionId::new(0xabcd_ef01_2345_6789, 1, 100);
        sender.bind_session(s_id, 1).unwrap();
        receiver.bind_session(s_id, 1).unwrap();

        // Send 10 packets
        for i in 1..=10 {
            let payload = format!("Datagram payload stream chunk #{i}").into_bytes();
            let wire = sender
                .encapsulate_subpath_packet(1, &s_id, 0x01, &payload, 10_000 + i * 50)
                .unwrap();

            let (hdr, recv_payload) = receiver.decapsulate_subpath_packet(1, &wire).unwrap();
            assert_eq!(hdr.session_id, s_id);
            assert_eq!(hdr.multipath_seq, i);
            assert_eq!(hdr.subpath_seq, i);
            assert_eq!(recv_payload, payload);
        }

        let s_tele = sender.header_compression_telemetry();
        assert_eq!(s_tele.total_packets, 10);
        assert_eq!(s_tele.full_headers_count, 1);
        assert_eq!(s_tele.compressed_headers_count, 9);
        assert!(s_tele.compression_ratio_percent > 70.0);

        let c_tele = sender.subpath_crypto_telemetry(1).unwrap();
        assert_eq!(c_tele.packets_encrypted, 10);
        assert_eq!(c_tele.auth_failures, 0);
    }

    #[test]
    fn test_session_registry_congestion_feedback_and_bandwidth_estimates() {
        let reg = SessionRegistry::new(1);
        reg.set_multipath_routing_policy(IsspRoutingPolicy::BandwidthAggregation)
            .unwrap();
        reg.add_multipath_route(IsspMultipathRoute::new(1, 2, "eth0-fiber", 1, 100))
            .unwrap();
        reg.add_multipath_route(IsspMultipathRoute::new(2, 2, "wwan0-5g", 2, 50))
            .unwrap();

        // Feed nominal feedback on path 1
        for _ in 0..8 {
            let factor = reg
                .update_congestion_feedback(1, 10_000, 0, 125_000)
                .expect("valid congestion feedback update");
            assert!(factor > 0.0 && factor <= 1.0);
        }

        // Feed loss and congestion on path 2
        reg.update_congestion_feedback(2, 60_000, 1500, 10_000)
            .expect("valid congestion feedback on path 2");

        let estimates = reg
            .bandwidth_estimates()
            .expect("fetch bandwidth estimates");
        assert_eq!(estimates.len(), 2);

        let est1 = reg.path_bandwidth_estimate(1).expect("path 1 estimate");
        assert_eq!(est1.available_bps, 100_000_000);
        assert_eq!(est1.phase, IsspCongestionPhase::CongestionAvoidance);

        let est2 = reg.path_bandwidth_estimate(2).expect("path 2 estimate");
        assert_eq!(est2.phase, IsspCongestionPhase::Recovery);

        // Unknown path should return error
        let err = reg.path_bandwidth_estimate(99);
        assert!(err.is_err());
    }
}

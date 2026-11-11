//! Deterministic Cryptographic primitives for IFA standard library.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Compute standard NIST SHA-256 hash digest.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();

    // Append single '1' bit (0x80)
    msg.push(0x80);

    // Append zeros until length % 64 == 56
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }

    // Append 64-bit big-endian message bit-length
    msg.extend_from_slice(&bit_len.to_be_bytes());

    // Process each 512-bit (64-byte) chunk
    for chunk in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut h_val = h[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h_val
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h_val = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(h_val);
    }

    let mut digest = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        digest[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

/// Compute SHA-256 hash and return as lowercase hexadecimal string.
pub fn sha256_hex(data: &[u8]) -> String {
    let digest = sha256(data);
    to_hex(&digest)
}

/// Compute standard SHA-1 hash digest (FIPS 180-1 / RFC 3174).
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();

    // Append single '1' bit (0x80)
    msg.push(0x80);

    // Append zeros until length % 64 == 56
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }

    // Append 64-bit big-endian bit length
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];

        for (i, &w_val) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5a827999),
                20..=39 => (b ^ c ^ d, 0x6ed9eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
                _ => (b ^ c ^ d, 0xca62c1d6),
            };

            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w_val);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut digest = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        digest[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

/// Compute SHA-1 hash and return as lowercase hexadecimal string.
pub fn sha1_hex(data: &[u8]) -> String {
    let digest = sha1(data);
    to_hex(&digest)
}

const BASE64_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode bytes to Base64 string according to RFC 4648.
pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    let (chunks, remainder) = data.as_chunks::<3>();

    for chunk in chunks {
        let b0 = chunk[0];
        let b1 = chunk[1];
        let b2 = chunk[2];

        out.push(BASE64_CHARS[(b0 >> 2) as usize] as char);
        out.push(BASE64_CHARS[(((b0 & 3) << 4) | (b1 >> 4)) as usize] as char);
        out.push(BASE64_CHARS[(((b1 & 15) << 2) | (b2 >> 6)) as usize] as char);
        out.push(BASE64_CHARS[(b2 & 63) as usize] as char);
    }

    match remainder.len() {
        1 => {
            let b0 = remainder[0];
            out.push(BASE64_CHARS[(b0 >> 2) as usize] as char);
            out.push(BASE64_CHARS[((b0 & 3) << 4) as usize] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let b0 = remainder[0];
            let b1 = remainder[1];
            out.push(BASE64_CHARS[(b0 >> 2) as usize] as char);
            out.push(BASE64_CHARS[(((b0 & 3) << 4) | (b1 >> 4)) as usize] as char);
            out.push(BASE64_CHARS[((b1 & 15) << 2) as usize] as char);
            out.push('=');
        }
        _ => {}
    }

    out
}

/// Decode Base64 string according to RFC 4648.
pub fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    let clean: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if !clean.len().is_multiple_of(4) {
        return Err("Invalid Base64 length".to_string());
    }

    let decode_char = |b: u8| -> Result<u8, String> {
        match b {
            b'A'..=b'Z' => Ok(b - b'A'),
            b'a'..=b'z' => Ok(b - b'a' + 26),
            b'0'..=b'9' => Ok(b - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(format!("Invalid Base64 character: {}", b as char)),
        }
    };

    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    for chunk in clean.as_chunks::<4>().0 {
        if chunk[0] == b'=' || chunk[1] == b'=' {
            return Err("Invalid padding position".to_string());
        }

        let c0 = decode_char(chunk[0])?;
        let c1 = decode_char(chunk[1])?;

        if chunk[2] == b'=' {
            if chunk[3] != b'=' {
                return Err("Invalid trailing padding".to_string());
            }
            out.push((c0 << 2) | (c1 >> 4));
            break;
        }

        let c2 = decode_char(chunk[2])?;
        out.push((c0 << 2) | (c1 >> 4));

        if chunk[3] == b'=' {
            out.push(((c1 & 15) << 4) | (c2 >> 2));
            break;
        }

        let c3 = decode_char(chunk[3])?;
        out.push(((c1 & 15) << 4) | (c2 >> 2));
        out.push(((c2 & 3) << 6) | c3);
    }

    Ok(out)
}

/// Compare two byte slices in constant time to prevent side-channel timing attacks.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Encode bytes to URL-safe Base64 without padding according to RFC 4648 / RFC 7515 (JWS).
pub fn base64url_encode(data: &[u8]) -> String {
    let b64 = base64_encode(data);
    b64.replace('+', "-")
        .replace('/', "_")
        .trim_end_matches('=')
        .to_string()
}

/// Decode URL-safe Base64 string (with or without padding) according to RFC 4648 / RFC 7515 (JWS).
pub fn base64url_decode(input: &str) -> Result<Vec<u8>, String> {
    let mut s = input.trim().replace('-', "+").replace('_', "/");
    match s.len() % 4 {
        2 => s.push_str("=="),
        3 => s.push('='),
        0 => {}
        _ => return Err("Invalid base64url length".to_string()),
    }
    base64_decode(&s)
}

/// Compute Sec-WebSocket-Accept key from client Sec-WebSocket-Key per RFC 6455 section 1.3.
pub fn websocket_accept_key(client_key: &str) -> String {
    const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let concatenated = format!("{}{}", client_key.trim(), WS_GUID);
    let digest = sha1(concatenated.as_bytes());
    base64_encode(&digest)
}

/// Compute BLAKE3 cryptographic hash digest.
pub fn blake3(data: &[u8]) -> [u8; 32] {
    let hash = ::blake3::hash(data);
    *hash.as_bytes()
}

/// Compute BLAKE3 hash and return as lowercase hexadecimal string.
pub fn blake3_hex(data: &[u8]) -> String {
    let digest = blake3(data);
    to_hex(&digest)
}

/// Compute HMAC-SHA-256 message authentication code (RFC 2104).
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let digest = sha256(key);
        k[..32].copy_from_slice(&digest);
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut i_pad = [0u8; 64];
    let mut o_pad = [0u8; 64];
    for i in 0..64 {
        i_pad[i] = k[i] ^ 0x36;
        o_pad[i] = k[i] ^ 0x5c;
    }

    let mut inner = Vec::with_capacity(64 + message.len());
    inner.extend_from_slice(&i_pad);
    inner.extend_from_slice(message);
    let inner_hash = sha256(&inner);

    let mut outer = Vec::with_capacity(64 + 32);
    outer.extend_from_slice(&o_pad);
    outer.extend_from_slice(&inner_hash);
    sha256(&outer)
}

/// Compute HMAC-SHA-256 and return as lowercase hex string.
pub fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> String {
    let digest = hmac_sha256(key, message);
    to_hex(&digest)
}

/// Compute HMAC-SHA-1 message authentication code (RFC 2104).
pub fn hmac_sha1(key: &[u8], message: &[u8]) -> [u8; 20] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let digest = sha1(key);
        k[..20].copy_from_slice(&digest);
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut i_pad = [0u8; 64];
    let mut o_pad = [0u8; 64];
    for i in 0..64 {
        i_pad[i] = k[i] ^ 0x36;
        o_pad[i] = k[i] ^ 0x5c;
    }

    let mut inner = Vec::with_capacity(64 + message.len());
    inner.extend_from_slice(&i_pad);
    inner.extend_from_slice(message);
    let inner_hash = sha1(&inner);

    let mut outer = Vec::with_capacity(64 + 20);
    outer.extend_from_slice(&o_pad);
    outer.extend_from_slice(&inner_hash);
    sha1(&outer)
}

/// Compute HMAC-SHA-1 and return as lowercase hex string.
pub fn hmac_sha1_hex(key: &[u8], message: &[u8]) -> String {
    let digest = hmac_sha1(key, message);
    to_hex(&digest)
}

/// Generate HMAC-Based One-Time Password (HOTP) per RFC 4226.
pub fn hotp(key: &[u8], counter: u64, digits: u32) -> String {
    let counter_bytes = counter.to_be_bytes();
    let hash = hmac_sha1(key, &counter_bytes);
    let offset = (hash[19] & 0x0f) as usize;
    let binary = ((u32::from(hash[offset] & 0x7f)) << 24)
        | ((u32::from(hash[offset + 1])) << 16)
        | ((u32::from(hash[offset + 2])) << 8)
        | (u32::from(hash[offset + 3]));

    let modulo = 10u32.pow(digits.min(10));
    let token = binary % modulo;
    format!("{:0width$}", token, width = digits as usize)
}

/// Generate Time-Based One-Time Password (TOTP) per RFC 6238.
pub fn totp(key: &[u8], time_seconds: u64, step_seconds: u64, digits: u32) -> String {
    let step = if step_seconds == 0 { 30 } else { step_seconds };
    let counter = time_seconds / step;
    hotp(key, counter, digits)
}

/// Verify a TOTP token against a timestamp with an allowed window of time steps.
pub fn totp_verify(
    key: &[u8],
    code: &str,
    time_seconds: u64,
    step_seconds: u64,
    window_steps: i64,
) -> bool {
    let step = if step_seconds == 0 { 30 } else { step_seconds };
    let current_counter = (time_seconds / step) as i64;
    let clean_code = code.trim();
    let digits = clean_code.len() as u32;
    if digits == 0 {
        return false;
    }

    let win = window_steps.abs();
    for offset in -win..=win {
        let counter = current_counter + offset;
        if counter >= 0 {
            let expected = hotp(key, counter as u64, digits);
            if expected == clean_code {
                return true;
            }
        }
    }
    false
}

/// Compute PBKDF2-HMAC-SHA256 key derivation (RFC 2898 / RFC 8018).
pub fn pbkdf2_hmac_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    key_len: usize,
) -> Vec<u8> {
    let mut derived = Vec::with_capacity(key_len);
    let mut block_index: u32 = 1;

    while derived.len() < key_len {
        // U_1 = PRF(password, salt || INT_32_BE(block_index))
        let mut msg = Vec::with_capacity(salt.len() + 4);
        msg.extend_from_slice(salt);
        msg.extend_from_slice(&block_index.to_be_bytes());

        let mut u = hmac_sha256(password, &msg);
        let mut t = u;

        for _ in 1..iterations {
            u = hmac_sha256(password, &u);
            for i in 0..32 {
                t[i] ^= u[i];
            }
        }

        let needed = key_len - derived.len();
        if needed < 32 {
            derived.extend_from_slice(&t[..needed]);
        } else {
            derived.extend_from_slice(&t);
        }

        block_index += 1;
    }

    derived
}

/// Compute PBKDF2-HMAC-SHA256 and return lowercase hex string.
pub fn pbkdf2_hmac_sha256_hex(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    key_len: usize,
) -> String {
    let derived = pbkdf2_hmac_sha256(password, salt, iterations, key_len);
    to_hex(&derived)
}

/// JWT claims representing standard RFC 7519 registered claims and arbitrary custom fields.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct JwtClaims {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(flatten)]
    pub custom: BTreeMap<String, serde_json::Value>,
}

impl JwtClaims {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_sub(mut self, sub: impl Into<String>) -> Self {
        self.sub = Some(sub.into());
        self
    }

    pub fn with_exp(mut self, exp: u64) -> Self {
        self.exp = Some(exp);
        self
    }

    pub fn with_nbf(mut self, nbf: u64) -> Self {
        self.nbf = Some(nbf);
        self
    }

    pub fn with_iat(mut self, iat: u64) -> Self {
        self.iat = Some(iat);
        self
    }

    pub fn with_iss(mut self, iss: impl Into<String>) -> Self {
        self.iss = Some(iss.into());
        self
    }

    pub fn with_aud(mut self, aud: impl Into<String>) -> Self {
        self.aud = Some(aud.into());
        self
    }

    pub fn with_jti(mut self, jti: impl Into<String>) -> Self {
        self.jti = Some(jti.into());
        self
    }

    pub fn with_custom(mut self, key: impl Into<String>, val: serde_json::Value) -> Self {
        self.custom.insert(key.into(), val);
        self
    }

    pub fn get_custom(&self, key: &str) -> Option<&serde_json::Value> {
        self.custom.get(key)
    }
}

/// JWT verification and generation errors (RFC 7519).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwtError {
    InvalidFormat,
    InvalidHeader,
    UnsupportedAlgorithm(String),
    InvalidSignature,
    Expired { expired_at: u64, current_time: u64 },
    NotYetValid { not_before: u64, current_time: u64 },
    SerializationError(String),
}

impl std::fmt::Display for JwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFormat => {
                write!(f, "Invalid JWT format (expected 3 parts separated by dots)")
            }
            Self::InvalidHeader => write!(f, "Invalid JWT header"),
            Self::UnsupportedAlgorithm(alg) => write!(f, "Unsupported JWT algorithm: {}", alg),
            Self::InvalidSignature => write!(f, "Invalid JWT HMAC signature"),
            Self::Expired {
                expired_at,
                current_time,
            } => {
                write!(
                    f,
                    "JWT expired at {} (current time: {})",
                    expired_at, current_time
                )
            }
            Self::NotYetValid {
                not_before,
                current_time,
            } => {
                write!(
                    f,
                    "JWT not valid before {} (current time: {})",
                    not_before, current_time
                )
            }
            Self::SerializationError(msg) => write!(f, "JWT JSON serialization error: {}", msg),
        }
    }
}

impl std::error::Error for JwtError {}

/// JSON Web Token (JWT) HS256 engine according to RFC 7519 and RFC 7515.
pub struct Jwt;

impl Jwt {
    /// Sign claims using HS256 (HMAC-SHA256) and secret key.
    pub fn sign_hs256(secret: &[u8], claims: &JwtClaims) -> Result<String, JwtError> {
        let header_json = r#"{"alg":"HS256","typ":"JWT"}"#;
        let header_b64 = base64url_encode(header_json.as_bytes());

        let claims_json = serde_json::to_string(claims)
            .map_err(|e| JwtError::SerializationError(e.to_string()))?;
        let claims_b64 = base64url_encode(claims_json.as_bytes());

        let signing_input = format!("{}.{}", header_b64, claims_b64);
        let sig = hmac_sha256(secret, signing_input.as_bytes());
        let sig_b64 = base64url_encode(&sig);

        Ok(format!("{}.{}", signing_input, sig_b64))
    }

    /// Verify HS256 token against secret key, checking expiration and validity time windows.
    /// `leeway_secs` allows slight clock drift (e.g. 5 to 60 seconds, or 0).
    pub fn verify_hs256(
        secret: &[u8],
        token: &str,
        current_time_secs: u64,
        leeway_secs: u64,
    ) -> Result<JwtClaims, JwtError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(JwtError::InvalidFormat);
        }

        let header_b64 = parts[0];
        let claims_b64 = parts[1];
        let sig_b64 = parts[2];

        // 1. Verify header
        let header_bytes = base64url_decode(header_b64).map_err(|_| JwtError::InvalidHeader)?;
        let header_json: serde_json::Value =
            serde_json::from_slice(&header_bytes).map_err(|_| JwtError::InvalidHeader)?;
        let alg = header_json
            .get("alg")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if alg != "HS256" {
            return Err(JwtError::UnsupportedAlgorithm(alg.to_string()));
        }

        // 2. Verify signature in constant time
        let signing_input = format!("{}.{}", header_b64, claims_b64);
        let expected_sig = hmac_sha256(secret, signing_input.as_bytes());
        let expected_sig_b64 = base64url_encode(&expected_sig);

        if !constant_time_eq(sig_b64.as_bytes(), expected_sig_b64.as_bytes()) {
            return Err(JwtError::InvalidSignature);
        }

        // 3. Decode claims
        let claims_bytes = base64url_decode(claims_b64).map_err(|_| JwtError::InvalidFormat)?;
        let claims: JwtClaims = serde_json::from_slice(&claims_bytes)
            .map_err(|e| JwtError::SerializationError(e.to_string()))?;

        // 4. Validate exp (Expiration Time)
        if let Some(exp) = claims.exp {
            if current_time_secs > exp.saturating_add(leeway_secs) {
                return Err(JwtError::Expired {
                    expired_at: exp,
                    current_time: current_time_secs,
                });
            }
        }

        // 5. Validate nbf (Not Before)
        if let Some(nbf) = claims.nbf {
            if current_time_secs.saturating_add(leeway_secs) < nbf {
                return Err(JwtError::NotYetValid {
                    not_before: nbf,
                    current_time: current_time_secs,
                });
            }
        }

        Ok(claims)
    }
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha1_rfc3174_vectors() {
        assert_eq!(sha1_hex(b""), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(sha1_hex(b"abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            sha1_hex(b"The quick brown fox jumps over the lazy dog"),
            "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
        );
    }

    #[test]
    fn test_base64_rfc4648_roundtrip() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");

        assert_eq!(base64_decode("").unwrap(), b"");
        assert_eq!(base64_decode("Zg==").unwrap(), b"f");
        assert_eq!(base64_decode("Zm8=").unwrap(), b"fo");
        assert_eq!(base64_decode("Zm9v").unwrap(), b"foo");
        assert_eq!(base64_decode("Zm9vYg==").unwrap(), b"foob");
        assert_eq!(base64_decode("Zm9vYmE=").unwrap(), b"fooba");
        assert_eq!(base64_decode("Zm9vYmFy").unwrap(), b"foobar");
    }

    #[test]
    fn test_rfc6455_websocket_accept_key() {
        // Official RFC 6455 section 1.3 test vector
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let accept = websocket_accept_key(key);
        assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn test_hmac_sha1_and_sha256_rfc2202_rfc4231() {
        // RFC 2202 test case 1: Key = 20 bytes of 0x0b, Data = "Hi There"
        let key_20 = [0x0bu8; 20];
        assert_eq!(
            hmac_sha1_hex(&key_20, b"Hi There"),
            "b617318655057264e28bc0b6fb378c8ef146be00"
        );

        // RFC 4231 test case 1: Key = 20 bytes of 0x0b, Data = "Hi There"
        assert_eq!(
            hmac_sha256_hex(&key_20, b"Hi There"),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn test_rfc4226_hotp_and_rfc6238_totp_vectors() {
        // RFC 4226 Appendix D official test secret
        let secret = b"12345678901234567890";
        assert_eq!(hotp(secret, 0, 6), "755224");
        assert_eq!(hotp(secret, 1, 6), "287082");
        assert_eq!(hotp(secret, 2, 6), "359152");
        assert_eq!(hotp(secret, 3, 6), "969429");
        assert_eq!(hotp(secret, 4, 6), "338314");
        assert_eq!(hotp(secret, 5, 6), "254676");
        assert_eq!(hotp(secret, 6, 6), "287922");
        assert_eq!(hotp(secret, 7, 6), "162583");
        assert_eq!(hotp(secret, 8, 6), "399871");
        assert_eq!(hotp(secret, 9, 6), "520489");

        // TOTP verification at T=59 (counter 1)
        assert_eq!(totp(secret, 59, 30, 6), "287082");
        assert!(totp_verify(secret, "287082", 59, 30, 1));
        assert!(totp_verify(secret, "287082", 60, 30, 1)); // counter 2, window +/- 1 matches counter 1
        assert!(!totp_verify(secret, "000000", 59, 30, 1));
    }

    #[test]
    fn test_rfc6070_pbkdf2_hmac_sha256() {
        let password = b"password";
        let salt = b"salt";

        // c = 1, dkLen = 32
        assert_eq!(
            pbkdf2_hmac_sha256_hex(password, salt, 1, 32),
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );

        // c = 2, dkLen = 32
        assert_eq!(
            pbkdf2_hmac_sha256_hex(password, salt, 2, 32),
            "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"
        );
    }

    #[test]
    fn test_base64url_and_constant_time_eq() {
        assert!(constant_time_eq(b"hello world", b"hello world"));
        assert!(!constant_time_eq(b"hello world", b"hello word!"));
        assert!(!constant_time_eq(b"short", b"longer string"));

        let payload = b"{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        let enc = base64url_encode(payload);
        assert_eq!(enc, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
        let dec = base64url_decode(&enc).unwrap();
        assert_eq!(dec, payload);

        // Test with bytes that produce + and / in standard base64
        let binary_data = vec![251, 255, 254, 253]; // produces standard + and /
        let url_enc = base64url_encode(&binary_data);
        assert!(!url_enc.contains('+'));
        assert!(!url_enc.contains('/'));
        assert!(!url_enc.contains('='));
        let dec_binary = base64url_decode(&url_enc).unwrap();
        assert_eq!(dec_binary, binary_data);
    }

    #[test]
    fn test_jwt_sign_and_verify() {
        let secret = b"super-secret-key-for-ifa-jwt-auth";
        let claims = JwtClaims::new()
            .with_sub("user_123")
            .with_iss("ifa-auth-service")
            .with_iat(1000)
            .with_nbf(1000)
            .with_exp(2000)
            .with_custom("role", serde_json::json!("admin"))
            .with_custom("email", serde_json::json!("alice@ifa.dev"));

        // Sign token
        let token = Jwt::sign_hs256(secret, &claims).expect("Signing must succeed");
        assert_eq!(token.split('.').count(), 3);

        // Verify valid token at t = 1500
        let verified =
            Jwt::verify_hs256(secret, &token, 1500, 0).expect("Verification must succeed");
        assert_eq!(verified.sub.as_deref(), Some("user_123"));
        assert_eq!(verified.iss.as_deref(), Some("ifa-auth-service"));
        assert_eq!(
            verified.get_custom("role"),
            Some(&serde_json::json!("admin"))
        );
        assert_eq!(
            verified.get_custom("email"),
            Some(&serde_json::json!("alice@ifa.dev"))
        );

        // Verification fails with invalid secret
        let wrong_secret = b"wrong-secret-key";
        let err_sig = Jwt::verify_hs256(wrong_secret, &token, 1500, 0).unwrap_err();
        assert_eq!(err_sig, JwtError::InvalidSignature);

        // Verification fails when expired (t = 2500)
        let err_exp = Jwt::verify_hs256(secret, &token, 2500, 0).unwrap_err();
        assert_eq!(
            err_exp,
            JwtError::Expired {
                expired_at: 2000,
                current_time: 2500
            }
        );

        // Verification succeeds with leeway (exp 2000, t = 2050, leeway = 60)
        let verified_leeway = Jwt::verify_hs256(secret, &token, 2050, 60);
        assert!(verified_leeway.is_ok());

        // Verification fails before not_before (t = 500)
        let err_nbf = Jwt::verify_hs256(secret, &token, 500, 0).unwrap_err();
        assert_eq!(
            err_nbf,
            JwtError::NotYetValid {
                not_before: 1000,
                current_time: 500
            }
        );

        // Invalid format
        assert_eq!(
            Jwt::verify_hs256(secret, "invalid.token", 1500, 0).unwrap_err(),
            JwtError::InvalidFormat
        );
    }
}

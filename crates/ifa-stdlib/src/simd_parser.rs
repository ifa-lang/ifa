//! SIMD-Accelerated Vectorized HTTP Parser and HTTP/2 Framing (`std/net/simd_parser`).
//!
//! Provides high-throughput delimiter search, zero-allocation HTTP/1.1 parsing,
//! and binary HTTP/2 frame header encoding and decoding.

use std::fmt;

/// HTTP/2 Frame Type (RFC 7540 Section 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Http2FrameType {
    Data = 0x0,
    Headers = 0x1,
    Priority = 0x2,
    RstStream = 0x3,
    Settings = 0x4,
    PushPromise = 0x5,
    Ping = 0x6,
    GoAway = 0x7,
    WindowUpdate = 0x8,
    Continuation = 0x9,
    Unknown(u8),
}

impl From<u8> for Http2FrameType {
    fn from(val: u8) -> Self {
        match val {
            0x0 => Http2FrameType::Data,
            0x1 => Http2FrameType::Headers,
            0x2 => Http2FrameType::Priority,
            0x3 => Http2FrameType::RstStream,
            0x4 => Http2FrameType::Settings,
            0x5 => Http2FrameType::PushPromise,
            0x6 => Http2FrameType::Ping,
            0x7 => Http2FrameType::GoAway,
            0x8 => Http2FrameType::WindowUpdate,
            0x9 => Http2FrameType::Continuation,
            other => Http2FrameType::Unknown(other),
        }
    }
}

impl From<Http2FrameType> for u8 {
    fn from(val: Http2FrameType) -> Self {
        match val {
            Http2FrameType::Data => 0x0,
            Http2FrameType::Headers => 0x1,
            Http2FrameType::Priority => 0x2,
            Http2FrameType::RstStream => 0x3,
            Http2FrameType::Settings => 0x4,
            Http2FrameType::PushPromise => 0x5,
            Http2FrameType::Ping => 0x6,
            Http2FrameType::GoAway => 0x7,
            Http2FrameType::WindowUpdate => 0x8,
            Http2FrameType::Continuation => 0x9,
            Http2FrameType::Unknown(u) => u,
        }
    }
}

/// Fixed 9-byte HTTP/2 Frame Header (RFC 7540 Section 4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Http2FrameHeader {
    pub length: u32, // 24-bit integer
    pub frame_type: Http2FrameType,
    pub flags: u8,
    pub stream_id: u32, // 31-bit integer
}

impl Http2FrameHeader {
    pub const HEADER_SIZE: usize = 9;

    pub fn new(length: u32, frame_type: Http2FrameType, flags: u8, stream_id: u32) -> Self {
        Self {
            length: length & 0x00FF_FFFF,
            frame_type,
            flags,
            stream_id: stream_id & 0x7FFF_FFFF,
        }
    }

    /// Decode from a 9-byte slice.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::HEADER_SIZE {
            return None;
        }

        let length = ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | (bytes[2] as u32);
        let frame_type = Http2FrameType::from(bytes[3]);
        let flags = bytes[4];
        let stream_id = ((bytes[5] as u32 & 0x7F) << 24)
            | ((bytes[6] as u32) << 16)
            | ((bytes[7] as u32) << 8)
            | (bytes[8] as u32);

        Some(Self {
            length,
            frame_type,
            flags,
            stream_id,
        })
    }

    /// Encode into a 9-byte array.
    pub fn encode(&self) -> [u8; 9] {
        let mut buf = [0u8; 9];
        buf[0] = ((self.length >> 16) & 0xFF) as u8;
        buf[1] = ((self.length >> 8) & 0xFF) as u8;
        buf[2] = (self.length & 0xFF) as u8;
        buf[3] = self.frame_type.into();
        buf[4] = self.flags;
        buf[5] = ((self.stream_id >> 24) & 0x7F) as u8;
        buf[6] = ((self.stream_id >> 16) & 0xFF) as u8;
        buf[7] = ((self.stream_id >> 8) & 0xFF) as u8;
        buf[8] = (self.stream_id & 0xFF) as u8;
        buf
    }
}

/// Zero-copy parsed HTTP/1.1 Request view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FastHttpRequest<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub version: &'a str,
    pub headers: Vec<(&'a str, &'a str)>,
    pub body_offset: usize,
}

/// Zero-copy parsed HTTP/1.1 Response view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FastHttpResponse<'a> {
    pub version: &'a str,
    pub status: u16,
    pub reason: &'a str,
    pub headers: Vec<(&'a str, &'a str)>,
    pub body_offset: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub enum FastHttpError {
    Incomplete,
    InvalidRequestLine,
    InvalidHeader,
}

impl fmt::Display for FastHttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FastHttpError::Incomplete => write!(f, "Incomplete HTTP message"),
            FastHttpError::InvalidRequestLine => write!(f, "Invalid HTTP request line"),
            FastHttpError::InvalidHeader => write!(f, "Invalid HTTP header syntax"),
        }
    }
}

impl std::error::Error for FastHttpError {}

/// High-throughput vectorized search for a target byte in slice.
#[inline]
pub fn find_byte_vectorized(haystack: &[u8], needle: u8) -> Option<usize> {
    // 64-bit SWAR (SIMD Within A Register) fast-path
    let mut offset = 0;
    let len = haystack.len();
    let needle_repeat = (needle as u64) * 0x0101_0101_0101_0101u64;

    while offset + 8 <= len {
        let chunk = u64::from_ne_bytes(haystack[offset..offset + 8].try_into().unwrap());
        let xor = chunk ^ needle_repeat;
        // Check if any byte is zero: (v - 0x01010101) & ~v & 0x80808080 != 0
        let has_zero =
            (xor.wrapping_sub(0x0101_0101_0101_0101u64)) & !xor & 0x8080_8080_8080_8080u64;
        if has_zero != 0 {
            // Find specific matching byte within chunk
            for i in 0..8 {
                if haystack[offset + i] == needle {
                    return Some(offset + i);
                }
            }
        }
        offset += 8;
    }

    // Scalar fallback for remaining bytes
    for (i, &b) in haystack[offset..].iter().enumerate() {
        if b == needle {
            return Some(offset + i);
        }
    }

    None
}

/// Find CRLF `\r\n` sequence offset.
#[inline]
pub fn find_crlf_vectorized(haystack: &[u8]) -> Option<usize> {
    let mut offset = 0;
    while offset < haystack.len() {
        if let Some(pos) = find_byte_vectorized(&haystack[offset..], b'\r') {
            let abs_pos = offset + pos;
            if abs_pos + 1 < haystack.len() && haystack[abs_pos + 1] == b'\n' {
                return Some(abs_pos);
            }
            offset = abs_pos + 1;
        } else {
            break;
        }
    }
    None
}

/// Parse HTTP/1.1 Request with zero allocation on tokens.
pub fn parse_http_request_fast(raw: &[u8]) -> Result<FastHttpRequest<'_>, FastHttpError> {
    // 1. Parse Request Line
    let crlf = find_crlf_vectorized(raw).ok_or(FastHttpError::Incomplete)?;
    let req_line_bytes = &raw[..crlf];
    let req_line =
        std::str::from_utf8(req_line_bytes).map_err(|_| FastHttpError::InvalidRequestLine)?;

    let mut parts = req_line.splitn(3, ' ');
    let method = parts.next().ok_or(FastHttpError::InvalidRequestLine)?;
    let path = parts.next().ok_or(FastHttpError::InvalidRequestLine)?;
    let version = parts.next().unwrap_or("HTTP/1.1");

    let mut current_offset = crlf + 2;

    // 2. Parse Headers
    let mut headers = Vec::new();
    while current_offset < raw.len() {
        let line_rest = &raw[current_offset..];
        let crlf = find_crlf_vectorized(line_rest).ok_or(FastHttpError::Incomplete)?;

        if crlf == 0 {
            // Empty line marks end of headers
            current_offset += 2;
            break;
        }

        let header_line =
            std::str::from_utf8(&line_rest[..crlf]).map_err(|_| FastHttpError::InvalidHeader)?;
        if let Some((name, val)) = header_line.split_once(':') {
            headers.push((name.trim(), val.trim()));
        } else {
            return Err(FastHttpError::InvalidHeader);
        }

        current_offset += crlf + 2;
    }

    Ok(FastHttpRequest {
        method,
        path,
        version,
        headers,
        body_offset: current_offset,
    })
}

/// Parse HTTP/1.1 Response with zero allocation on tokens.
pub fn parse_http_response_fast(raw: &[u8]) -> Result<FastHttpResponse<'_>, FastHttpError> {
    // 1. Status Line: HTTP/1.1 200 OK
    let crlf = find_crlf_vectorized(raw).ok_or(FastHttpError::Incomplete)?;
    let status_line_bytes = &raw[..crlf];
    let status_line =
        std::str::from_utf8(status_line_bytes).map_err(|_| FastHttpError::InvalidRequestLine)?;

    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().ok_or(FastHttpError::InvalidRequestLine)?;
    let status_str = parts.next().ok_or(FastHttpError::InvalidRequestLine)?;
    let reason = parts.next().unwrap_or("");
    let status = status_str
        .parse::<u16>()
        .map_err(|_| FastHttpError::InvalidRequestLine)?;

    let mut current_offset = crlf + 2;

    // 2. Headers
    let mut headers = Vec::new();
    while current_offset < raw.len() {
        let line_rest = &raw[current_offset..];
        let crlf = find_crlf_vectorized(line_rest).ok_or(FastHttpError::Incomplete)?;

        if crlf == 0 {
            current_offset += 2;
            break;
        }

        let header_line =
            std::str::from_utf8(&line_rest[..crlf]).map_err(|_| FastHttpError::InvalidHeader)?;
        if let Some((name, val)) = header_line.split_once(':') {
            headers.push((name.trim(), val.trim()));
        } else {
            return Err(FastHttpError::InvalidHeader);
        }

        current_offset += crlf + 2;
    }

    Ok(FastHttpResponse {
        version,
        status,
        reason,
        headers,
        body_offset: current_offset,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vectorized_delimiter_finding() {
        let data = b"Header-Name: Header-Value\r\nSecond-Header: Value\r\n\r\n";
        assert_eq!(find_byte_vectorized(data, b':'), Some(11));
        assert_eq!(find_crlf_vectorized(data), Some(25));
    }

    #[test]
    fn test_fast_http_request_parsing() {
        let raw = b"GET /api/v1/metrics?format=json HTTP/1.1\r\nHost: api.ifa.org\r\nAuthorization: Bearer token123\r\nAccept: application/json\r\n\r\n{\"key\":\"val\"}";
        let req = parse_http_request_fast(raw).expect("Failed to parse fast HTTP request");

        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/api/v1/metrics?format=json");
        assert_eq!(req.version, "HTTP/1.1");
        assert_eq!(req.headers.len(), 3);
        assert_eq!(req.headers[0], ("Host", "api.ifa.org"));
        assert_eq!(req.headers[1], ("Authorization", "Bearer token123"));
        assert_eq!(&raw[req.body_offset..], b"{\"key\":\"val\"}");
    }

    #[test]
    fn test_fast_http_response_parsing() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nHello";
        let resp = parse_http_response_fast(raw).expect("Failed to parse fast HTTP response");

        assert_eq!(resp.version, "HTTP/1.1");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.reason, "OK");
        assert_eq!(resp.headers.len(), 2);
        assert_eq!(&raw[resp.body_offset..], b"Hello");
    }

    #[test]
    fn test_http2_frame_header_roundtrip() {
        let header = Http2FrameHeader::new(1024, Http2FrameType::Headers, 0x05, 42);
        let encoded = header.encode();
        assert_eq!(encoded.len(), 9);

        let decoded =
            Http2FrameHeader::decode(&encoded).expect("Failed to decode HTTP/2 frame header");
        assert_eq!(decoded, header);
        assert_eq!(decoded.length, 1024);
        assert_eq!(decoded.frame_type, Http2FrameType::Headers);
        assert_eq!(decoded.flags, 0x05);
        assert_eq!(decoded.stream_id, 42);
    }
}

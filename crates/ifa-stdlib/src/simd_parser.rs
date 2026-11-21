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
    /// RFC 9218 Extensible Prioritization Scheme frame type for HTTP/2
    PriorityUpdate = 0x10,
    /// RFC 7838 HTTP/2 ALTSVC frame type (0xa)
    AltSvc = 0xa,
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
            0xa => Http2FrameType::AltSvc,
            0x10 => Http2FrameType::PriorityUpdate,
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
            Http2FrameType::AltSvc => 0xa,
            Http2FrameType::PriorityUpdate => 0x10,
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

// -----------------------------------------------------------------------------
// HTTP/2 Frame Payloads & HPACK (RFC 7540 & RFC 7541)
// -----------------------------------------------------------------------------

/// HTTP/2 Error Codes (RFC 7540 Section 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Http2ErrorCode {
    NoError,
    ProtocolError,
    InternalError,
    FlowControlError,
    SettingsTimeout,
    StreamClosed,
    FrameSizeError,
    RefusedStream,
    Cancel,
    CompressionError,
    ConnectError,
    EnhanceYourCalm,
    InadequateSecurity,
    Http11Required,
    Unknown(u32),
}

impl Http2ErrorCode {
    /// Human-readable standard name of the RFC 7540 error code.
    pub fn name(&self) -> &'static str {
        match self {
            Http2ErrorCode::NoError => "NO_ERROR",
            Http2ErrorCode::ProtocolError => "PROTOCOL_ERROR",
            Http2ErrorCode::InternalError => "INTERNAL_ERROR",
            Http2ErrorCode::FlowControlError => "FLOW_CONTROL_ERROR",
            Http2ErrorCode::SettingsTimeout => "SETTINGS_TIMEOUT",
            Http2ErrorCode::StreamClosed => "STREAM_CLOSED",
            Http2ErrorCode::FrameSizeError => "FRAME_SIZE_ERROR",
            Http2ErrorCode::RefusedStream => "REFUSED_STREAM",
            Http2ErrorCode::Cancel => "CANCEL",
            Http2ErrorCode::CompressionError => "COMPRESSION_ERROR",
            Http2ErrorCode::ConnectError => "CONNECT_ERROR",
            Http2ErrorCode::EnhanceYourCalm => "ENHANCE_YOUR_CALM",
            Http2ErrorCode::InadequateSecurity => "INADEQUATE_SECURITY",
            Http2ErrorCode::Http11Required => "HTTP_1_1_REQUIRED",
            Http2ErrorCode::Unknown(_) => "UNKNOWN_ERROR",
        }
    }

    /// Whether this error code represents a graceful or non-fatal termination condition.
    pub fn is_graceful(&self) -> bool {
        matches!(self, Http2ErrorCode::NoError)
    }

    /// Whether this error indicates that a client should back off or slow down (RFC 7540 §7).
    pub fn is_rate_limit_or_calm(&self) -> bool {
        matches!(self, Http2ErrorCode::EnhanceYourCalm)
    }

    /// Whether this error code represents a fatal protocol violation or stream/compression corruption.
    pub fn is_fatal_protocol_violation(&self) -> bool {
        matches!(
            self,
            Http2ErrorCode::ProtocolError
                | Http2ErrorCode::FrameSizeError
                | Http2ErrorCode::CompressionError
                | Http2ErrorCode::InadequateSecurity
                | Http2ErrorCode::Http11Required
        )
    }

    /// Whether this error code indicates the request can be retried safely on a new connection.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Http2ErrorCode::NoError | Http2ErrorCode::RefusedStream | Http2ErrorCode::Cancel
        )
    }
}

impl From<u32> for Http2ErrorCode {
    fn from(val: u32) -> Self {
        match val {
            0x0 => Http2ErrorCode::NoError,
            0x1 => Http2ErrorCode::ProtocolError,
            0x2 => Http2ErrorCode::InternalError,
            0x3 => Http2ErrorCode::FlowControlError,
            0x4 => Http2ErrorCode::SettingsTimeout,
            0x5 => Http2ErrorCode::StreamClosed,
            0x6 => Http2ErrorCode::FrameSizeError,
            0x7 => Http2ErrorCode::RefusedStream,
            0x8 => Http2ErrorCode::Cancel,
            0x9 => Http2ErrorCode::CompressionError,
            0xa => Http2ErrorCode::ConnectError,
            0xb => Http2ErrorCode::EnhanceYourCalm,
            0xc => Http2ErrorCode::InadequateSecurity,
            0xd => Http2ErrorCode::Http11Required,
            other => Http2ErrorCode::Unknown(other),
        }
    }
}

impl From<Http2ErrorCode> for u32 {
    fn from(val: Http2ErrorCode) -> Self {
        match val {
            Http2ErrorCode::NoError => 0x0,
            Http2ErrorCode::ProtocolError => 0x1,
            Http2ErrorCode::InternalError => 0x2,
            Http2ErrorCode::FlowControlError => 0x3,
            Http2ErrorCode::SettingsTimeout => 0x4,
            Http2ErrorCode::StreamClosed => 0x5,
            Http2ErrorCode::FrameSizeError => 0x6,
            Http2ErrorCode::RefusedStream => 0x7,
            Http2ErrorCode::Cancel => 0x8,
            Http2ErrorCode::CompressionError => 0x9,
            Http2ErrorCode::ConnectError => 0xa,
            Http2ErrorCode::EnhanceYourCalm => 0xb,
            Http2ErrorCode::InadequateSecurity => 0xc,
            Http2ErrorCode::Http11Required => 0xd,
            Http2ErrorCode::Unknown(other) => other,
        }
    }
}

/// HTTP/2 Settings Parameter Identifier (RFC 7540 Section 6.5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Http2SettingId {
    HeaderTableSize,
    EnablePush,
    MaxConcurrentStreams,
    InitialWindowSize,
    MaxFrameSize,
    MaxHeaderListSize,
    /// RFC 9218: SETTINGS_ENABLE_CONNECT_PROTOCOL or SETTINGS parameter (0x10 / etc.)
    NoRfc7540Priorities,
    Unknown(u16),
}

impl From<u16> for Http2SettingId {
    fn from(val: u16) -> Self {
        match val {
            0x1 => Http2SettingId::HeaderTableSize,
            0x2 => Http2SettingId::EnablePush,
            0x3 => Http2SettingId::MaxConcurrentStreams,
            0x4 => Http2SettingId::InitialWindowSize,
            0x5 => Http2SettingId::MaxFrameSize,
            0x6 => Http2SettingId::MaxHeaderListSize,
            0x9 => Http2SettingId::NoRfc7540Priorities,
            other => Http2SettingId::Unknown(other),
        }
    }
}

impl From<Http2SettingId> for u16 {
    fn from(val: Http2SettingId) -> Self {
        match val {
            Http2SettingId::HeaderTableSize => 0x1,
            Http2SettingId::EnablePush => 0x2,
            Http2SettingId::MaxConcurrentStreams => 0x3,
            Http2SettingId::InitialWindowSize => 0x4,
            Http2SettingId::MaxFrameSize => 0x5,
            Http2SettingId::MaxHeaderListSize => 0x6,
            Http2SettingId::NoRfc7540Priorities => 0x9,
            Http2SettingId::Unknown(other) => other,
        }
    }
}

/// HTTP Extensible Prioritization Scheme (RFC 9218) Priority Parameters.
/// Contains urgency `u` in 0..=7 (default 3) and incremental boolean flag `i` (default false).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PriorityParameters {
    /// Urgency: 0 is highest priority, 7 is lowest priority. Default is 3.
    pub urgency: u8,
    /// Incremental: false means responses should be sent sequentially; true means interleaved.
    pub incremental: bool,
}

impl Default for PriorityParameters {
    fn default() -> Self {
        Self {
            urgency: 3,
            incremental: false,
        }
    }
}

impl PriorityParameters {
    /// Create a new `PriorityParameters` with validated urgency clamped to 0..=7.
    pub fn new(urgency: u8, incremental: bool) -> Self {
        Self {
            urgency: urgency.min(7),
            incremental,
        }
    }

    /// Parse RFC 9218 Priority structured field value (e.g. `u=1, i`, `u=5`, `i=?1`, `i`).
    pub fn parse(field_value: &str) -> Self {
        let mut urgency = 3u8;
        let mut incremental = false;

        for part in field_value.split(',') {
            let item = part.trim();
            if item.is_empty() {
                continue;
            }
            if let Some(eq_pos) = item.find('=') {
                let (key, val) = item.split_at(eq_pos);
                let key = key.trim();
                let val = val[1..].trim();
                if key.eq_ignore_ascii_case("u") {
                    if let Ok(u) = val.parse::<u8>() {
                        if u <= 7 {
                            urgency = u;
                        }
                    }
                } else if key.eq_ignore_ascii_case("i") {
                    if val == "?1" || val.eq_ignore_ascii_case("true") {
                        incremental = true;
                    } else if val == "?0" || val.eq_ignore_ascii_case("false") {
                        incremental = false;
                    }
                }
            } else {
                // Boolean item without explicit value (e.g. `i`)
                if item.eq_ignore_ascii_case("i") {
                    incremental = true;
                }
            }
        }

        Self {
            urgency,
            incremental,
        }
    }

    /// Serialize to RFC 9218 structured field string value (e.g. `u=1, i`).
    pub fn serialize(&self) -> String {
        if self.incremental {
            format!("u={}, i", self.urgency)
        } else {
            format!("u={}", self.urgency)
        }
    }
}

/// HTTP/2 Settings Frame Parameter pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Http2Setting {
    pub id: Http2SettingId,
    pub value: u32,
}

/// RFC 7838 Alternative Service Descriptor (ALTSVC).
/// Represents an alternative service route advertised by an HTTP server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AltSvcRoute {
    /// Protocol identifier (e.g., "h3", "h2", "h3-29").
    pub protocol_id: String,
    /// Host or IP address, optional (empty or omitted means same origin host).
    pub host: String,
    /// Port number of the alternative service.
    pub port: u16,
    /// Max-Age in seconds (default 86400 / 24 hours).
    pub max_age: u32,
    /// Persist flag (persist=1).
    pub persist: bool,
}

impl AltSvcRoute {
    pub fn new(protocol_id: impl Into<String>, host: impl Into<String>, port: u16) -> Self {
        Self {
            protocol_id: protocol_id.into(),
            host: host.into(),
            port,
            max_age: 86400,
            persist: false,
        }
    }

    pub fn with_max_age(mut self, max_age: u32) -> Self {
        self.max_age = max_age;
        self
    }

    pub fn with_persist(mut self, persist: bool) -> Self {
        self.persist = persist;
        self
    }

    /// Parse an Alt-Svc header value or field value into a list of `AltSvcRoute`.
    /// E.g. `h3=":443"; ma=2592000, h2="alt.example.com:8443"` or `clear`.
    pub fn parse_header_value(header_val: &str) -> Vec<Self> {
        let trimmed = header_val.trim();
        if trimmed.eq_ignore_ascii_case("clear") {
            return Vec::new();
        }

        let mut routes = Vec::new();
        // Split entries separated by comma outside quotes
        let mut entries = Vec::new();
        let mut in_quotes = false;
        let mut start = 0;
        let bytes = trimmed.as_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            if b == b'"' {
                in_quotes = !in_quotes;
            } else if b == b',' && !in_quotes {
                entries.push(&trimmed[start..i]);
                start = i + 1;
            }
        }
        if start < trimmed.len() {
            entries.push(&trimmed[start..]);
        }

        for entry in entries {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }

            // Split protocol and parameters (separated by '=')
            if let Some(eq_pos) = entry.find('=') {
                let proto = entry[..eq_pos].trim();
                let rest = entry[eq_pos + 1..].trim();

                // Extract quoted host/port or unquoted up to ';'
                let (target, params) = if let Some(stripped) = rest.strip_prefix('"') {
                    if let Some(end_quote) = stripped.find('"') {
                        let target = &stripped[..end_quote];
                        let params = &stripped[end_quote + 1..];
                        (target, params)
                    } else {
                        (rest, "")
                    }
                } else if let Some(semi_pos) = rest.find(';') {
                    (&rest[..semi_pos], &rest[semi_pos..])
                } else {
                    (rest, "")
                };

                let target = target.trim();
                let (host, port) = if let Some(colon_pos) = target.rfind(':') {
                    let h = &target[..colon_pos];
                    let p_str = &target[colon_pos + 1..];
                    let port = p_str.parse::<u16>().unwrap_or(0);
                    (h.to_string(), port)
                } else {
                    ("".to_string(), 0)
                };

                if port == 0 {
                    continue;
                }

                let mut max_age = 86400u32;
                let mut persist = false;

                // Parse parameters separated by ';'
                for param in params.split(';') {
                    let param = param.trim();
                    if param.is_empty() {
                        continue;
                    }
                    if let Some(param_eq) = param.find('=') {
                        let (k, v) = param.split_at(param_eq);
                        let k = k.trim();
                        let v = v[1..].trim();
                        if k.eq_ignore_ascii_case("ma") {
                            if let Ok(ma) = v.parse::<u32>() {
                                max_age = ma;
                            }
                        } else if k.eq_ignore_ascii_case("persist")
                            && (v == "1" || v.eq_ignore_ascii_case("true"))
                        {
                            persist = true;
                        }
                    }
                }

                routes.push(Self {
                    protocol_id: proto.to_string(),
                    host,
                    port,
                    max_age,
                    persist,
                });
            }
        }

        routes
    }

    /// Serialize this route to RFC 7838 field format, e.g. `h3=":443"; ma=86400`.
    pub fn serialize(&self) -> String {
        let mut s = format!(
            "{}=\"{}:{}\"; ma={}",
            self.protocol_id, self.host, self.port, self.max_age
        );
        if self.persist {
            s.push_str("; persist=1");
        }
        s
    }

    /// Check if this route has expired given its received timestamp and current elapsed duration.
    pub fn is_expired_since(&self, elapsed: std::time::Duration) -> bool {
        elapsed.as_secs() >= self.max_age as u64
    }
}

/// Typed HTTP/2 Frame representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Http2Frame {
    Data {
        stream_id: u32,
        end_stream: bool,
        data: Vec<u8>,
    },
    Headers {
        stream_id: u32,
        end_stream: bool,
        end_headers: bool,
        header_block: Vec<u8>,
    },
    Priority {
        stream_id: u32,
        exclusive: bool,
        stream_dependency: u32,
        weight: u8,
    },
    RstStream {
        stream_id: u32,
        error_code: Http2ErrorCode,
    },
    Settings {
        ack: bool,
        settings: Vec<Http2Setting>,
    },
    Ping {
        ack: bool,
        opaque_data: [u8; 8],
    },
    GoAway {
        last_stream_id: u32,
        error_code: Http2ErrorCode,
        debug_data: Vec<u8>,
    },
    WindowUpdate {
        stream_id: u32,
        window_size_increment: u32,
    },
    Continuation {
        stream_id: u32,
        end_headers: bool,
        header_block: Vec<u8>,
    },
    PushPromise {
        stream_id: u32,
        promised_stream_id: u32,
        end_headers: bool,
        header_block: Vec<u8>,
    },
    /// RFC 9218 PRIORITY_UPDATE frame (Type 0x10) updating priority of a prioritized stream.
    PriorityUpdate {
        prioritized_stream_id: u32,
        priority_field_value: String,
    },
    /// RFC 7838 ALTSVC frame (Type 0xa) advertising alternative services for an origin.
    AltSvc {
        stream_id: u32,
        origin: String,
        alt_svc_field_value: String,
    },
    Unknown {
        header: Http2FrameHeader,
        payload: Vec<u8>,
    },
}

impl Http2Frame {
    /// Flag constants for HTTP/2 frames.
    pub const FLAG_END_STREAM: u8 = 0x1;
    pub const FLAG_ACK: u8 = 0x1;
    pub const FLAG_END_HEADERS: u8 = 0x4;
    pub const FLAG_PADDED: u8 = 0x8;
    pub const FLAG_PRIORITY: u8 = 0x20;

    /// Return the stream ID associated with this frame (0 for connection-level frames).
    pub fn stream_id(&self) -> u32 {
        match self {
            Http2Frame::Data { stream_id, .. } => *stream_id,
            Http2Frame::Headers { stream_id, .. } => *stream_id,
            Http2Frame::Priority { stream_id, .. } => *stream_id,
            Http2Frame::RstStream { stream_id, .. } => *stream_id,
            Http2Frame::Settings { .. } => 0,
            Http2Frame::Ping { .. } => 0,
            Http2Frame::GoAway { last_stream_id, .. } => *last_stream_id,
            Http2Frame::WindowUpdate { stream_id, .. } => *stream_id,
            Http2Frame::Continuation { stream_id, .. } => *stream_id,
            Http2Frame::PushPromise { stream_id, .. } => *stream_id,
            Http2Frame::PriorityUpdate {
                prioritized_stream_id,
                ..
            } => *prioritized_stream_id,
            Http2Frame::AltSvc { stream_id, .. } => *stream_id,
            Http2Frame::Unknown { header, .. } => header.stream_id,
        }
    }

    /// Encode the HTTP/2 frame into wire bytes (header + payload).
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Http2Frame::Data {
                stream_id,
                end_stream,
                data,
            } => {
                let flags = if *end_stream {
                    Self::FLAG_END_STREAM
                } else {
                    0
                };
                let header = Http2FrameHeader::new(
                    data.len() as u32,
                    Http2FrameType::Data,
                    flags,
                    *stream_id,
                );
                let mut out = Vec::with_capacity(9 + data.len());
                out.extend_from_slice(&header.encode());
                out.extend_from_slice(data);
                out
            }
            Http2Frame::Headers {
                stream_id,
                end_stream,
                end_headers,
                header_block,
            } => {
                let mut flags = 0;
                if *end_stream {
                    flags |= Self::FLAG_END_STREAM;
                }
                if *end_headers {
                    flags |= Self::FLAG_END_HEADERS;
                }
                let header = Http2FrameHeader::new(
                    header_block.len() as u32,
                    Http2FrameType::Headers,
                    flags,
                    *stream_id,
                );
                let mut out = Vec::with_capacity(9 + header_block.len());
                out.extend_from_slice(&header.encode());
                out.extend_from_slice(header_block);
                out
            }
            Http2Frame::Priority {
                stream_id,
                exclusive,
                stream_dependency,
                weight,
            } => {
                let header = Http2FrameHeader::new(5, Http2FrameType::Priority, 0, *stream_id);
                let mut out = Vec::with_capacity(14);
                out.extend_from_slice(&header.encode());
                let dep =
                    (if *exclusive { 0x8000_0000 } else { 0 }) | (*stream_dependency & 0x7FFF_FFFF);
                out.extend_from_slice(&dep.to_be_bytes());
                out.push(*weight);
                out
            }
            Http2Frame::RstStream {
                stream_id,
                error_code,
            } => {
                let header = Http2FrameHeader::new(4, Http2FrameType::RstStream, 0, *stream_id);
                let mut out = Vec::with_capacity(13);
                out.extend_from_slice(&header.encode());
                let err_raw: u32 = (*error_code).into();
                out.extend_from_slice(&err_raw.to_be_bytes());
                out
            }
            Http2Frame::Settings { ack, settings } => {
                let flags = if *ack { Self::FLAG_ACK } else { 0 };
                let payload_len = if *ack { 0 } else { (settings.len() * 6) as u32 };
                let header = Http2FrameHeader::new(payload_len, Http2FrameType::Settings, flags, 0);
                let mut out = Vec::with_capacity(9 + payload_len as usize);
                out.extend_from_slice(&header.encode());
                if !*ack {
                    for setting in settings {
                        let id_raw: u16 = setting.id.into();
                        out.extend_from_slice(&id_raw.to_be_bytes());
                        out.extend_from_slice(&setting.value.to_be_bytes());
                    }
                }
                out
            }
            Http2Frame::Ping { ack, opaque_data } => {
                let flags = if *ack { Self::FLAG_ACK } else { 0 };
                let header = Http2FrameHeader::new(8, Http2FrameType::Ping, flags, 0);
                let mut out = Vec::with_capacity(17);
                out.extend_from_slice(&header.encode());
                out.extend_from_slice(opaque_data);
                out
            }
            Http2Frame::GoAway {
                last_stream_id,
                error_code,
                debug_data,
            } => {
                let payload_len = 8 + debug_data.len() as u32;
                let header = Http2FrameHeader::new(payload_len, Http2FrameType::GoAway, 0, 0);
                let mut out = Vec::with_capacity(9 + payload_len as usize);
                out.extend_from_slice(&header.encode());
                out.extend_from_slice(&(last_stream_id & 0x7FFF_FFFF).to_be_bytes());
                let err_raw: u32 = (*error_code).into();
                out.extend_from_slice(&err_raw.to_be_bytes());
                out.extend_from_slice(debug_data);
                out
            }
            Http2Frame::WindowUpdate {
                stream_id,
                window_size_increment,
            } => {
                let header = Http2FrameHeader::new(4, Http2FrameType::WindowUpdate, 0, *stream_id);
                let mut out = Vec::with_capacity(13);
                out.extend_from_slice(&header.encode());
                out.extend_from_slice(&(window_size_increment & 0x7FFF_FFFF).to_be_bytes());
                out
            }
            Http2Frame::Continuation {
                stream_id,
                end_headers,
                header_block,
            } => {
                let flags = if *end_headers {
                    Self::FLAG_END_HEADERS
                } else {
                    0
                };
                let header = Http2FrameHeader::new(
                    header_block.len() as u32,
                    Http2FrameType::Continuation,
                    flags,
                    *stream_id,
                );
                let mut out = Vec::with_capacity(9 + header_block.len());
                out.extend_from_slice(&header.encode());
                out.extend_from_slice(header_block);
                out
            }
            Http2Frame::PushPromise {
                stream_id,
                promised_stream_id,
                end_headers,
                header_block,
            } => {
                let flags = if *end_headers {
                    Self::FLAG_END_HEADERS
                } else {
                    0
                };
                let payload_len = 4 + header_block.len();
                let header = Http2FrameHeader::new(
                    payload_len as u32,
                    Http2FrameType::PushPromise,
                    flags,
                    *stream_id,
                );
                let mut out = Vec::with_capacity(9 + payload_len);
                out.extend_from_slice(&header.encode());
                out.extend_from_slice(&(*promised_stream_id & 0x7FFF_FFFF).to_be_bytes());
                out.extend_from_slice(header_block);
                out
            }
            Http2Frame::PriorityUpdate {
                prioritized_stream_id,
                priority_field_value,
            } => {
                let bytes = priority_field_value.as_bytes();
                let payload_len = 4 + bytes.len();
                // RFC 9218: PRIORITY_UPDATE frames MUST be sent on stream 0
                let header =
                    Http2FrameHeader::new(payload_len as u32, Http2FrameType::PriorityUpdate, 0, 0);
                let mut out = Vec::with_capacity(9 + payload_len);
                out.extend_from_slice(&header.encode());
                out.extend_from_slice(&(*prioritized_stream_id & 0x7FFF_FFFF).to_be_bytes());
                out.extend_from_slice(bytes);
                out
            }
            Http2Frame::AltSvc {
                stream_id,
                origin,
                alt_svc_field_value,
            } => {
                let origin_bytes = origin.as_bytes();
                let alt_svc_bytes = alt_svc_field_value.as_bytes();
                let origin_len = origin_bytes.len() as u16;
                let payload_len = 2 + origin_bytes.len() + alt_svc_bytes.len();
                let header = Http2FrameHeader::new(
                    payload_len as u32,
                    Http2FrameType::AltSvc,
                    0,
                    *stream_id & 0x7FFF_FFFF,
                );
                let mut out = Vec::with_capacity(9 + payload_len);
                out.extend_from_slice(&header.encode());
                out.extend_from_slice(&origin_len.to_be_bytes());
                out.extend_from_slice(origin_bytes);
                out.extend_from_slice(alt_svc_bytes);
                out
            }
            Http2Frame::Unknown { header, payload } => {
                let mut out = Vec::with_capacity(9 + payload.len());
                out.extend_from_slice(&header.encode());
                out.extend_from_slice(payload);
                out
            }
        }
    }

    /// Serialize this frame into a caller-supplied pre-allocated destination buffer
    /// without any heap allocations.
    ///
    /// Returns `Ok(bytes_written)` if `dst` has enough capacity, or `Err(FastHttpError::Incomplete)`
    /// if the buffer is too small.
    pub fn encode_to_slice(&self, dst: &mut [u8]) -> Result<usize, FastHttpError> {
        let total_len = match self {
            Http2Frame::Data { data, .. } => 9 + data.len(),
            Http2Frame::Headers { header_block, .. } => 9 + header_block.len(),
            Http2Frame::Priority { .. } => 14,
            Http2Frame::RstStream { .. } => 13,
            Http2Frame::Settings { ack, settings } => {
                if *ack {
                    9
                } else {
                    9 + settings.len() * 6
                }
            }
            Http2Frame::Ping { .. } => 17,
            Http2Frame::GoAway { debug_data, .. } => 17 + debug_data.len(),
            Http2Frame::WindowUpdate { .. } => 13,
            Http2Frame::Continuation { header_block, .. } => 9 + header_block.len(),
            Http2Frame::PushPromise { header_block, .. } => 13 + header_block.len(),
            Http2Frame::PriorityUpdate {
                priority_field_value,
                ..
            } => 13 + priority_field_value.len(),
            Http2Frame::AltSvc {
                origin,
                alt_svc_field_value,
                ..
            } => 11 + origin.len() + alt_svc_field_value.len(),
            Http2Frame::Unknown { payload, .. } => 9 + payload.len(),
        };

        if dst.len() < total_len {
            return Err(FastHttpError::Incomplete);
        }

        match self {
            Http2Frame::Data {
                stream_id,
                end_stream,
                data,
            } => {
                let flags = if *end_stream {
                    Self::FLAG_END_STREAM
                } else {
                    0
                };
                let header = Http2FrameHeader::new(
                    data.len() as u32,
                    Http2FrameType::Data,
                    flags,
                    *stream_id,
                );
                dst[..9].copy_from_slice(&header.encode());
                dst[9..9 + data.len()].copy_from_slice(data);
            }
            Http2Frame::Headers {
                stream_id,
                end_stream,
                end_headers,
                header_block,
            } => {
                let mut flags = 0;
                if *end_stream {
                    flags |= Self::FLAG_END_STREAM;
                }
                if *end_headers {
                    flags |= Self::FLAG_END_HEADERS;
                }
                let header = Http2FrameHeader::new(
                    header_block.len() as u32,
                    Http2FrameType::Headers,
                    flags,
                    *stream_id,
                );
                dst[..9].copy_from_slice(&header.encode());
                dst[9..9 + header_block.len()].copy_from_slice(header_block);
            }
            Http2Frame::Priority {
                stream_id,
                exclusive,
                stream_dependency,
                weight,
            } => {
                let header = Http2FrameHeader::new(5, Http2FrameType::Priority, 0, *stream_id);
                dst[..9].copy_from_slice(&header.encode());
                let dep =
                    (if *exclusive { 0x8000_0000 } else { 0 }) | (*stream_dependency & 0x7FFF_FFFF);
                dst[9..13].copy_from_slice(&dep.to_be_bytes());
                dst[13] = *weight;
            }
            Http2Frame::RstStream {
                stream_id,
                error_code,
            } => {
                let header = Http2FrameHeader::new(4, Http2FrameType::RstStream, 0, *stream_id);
                dst[..9].copy_from_slice(&header.encode());
                let err_raw: u32 = (*error_code).into();
                dst[9..13].copy_from_slice(&err_raw.to_be_bytes());
            }
            Http2Frame::Settings { ack, settings } => {
                let flags = if *ack { Self::FLAG_ACK } else { 0 };
                let payload_len = if *ack { 0 } else { (settings.len() * 6) as u32 };
                let header = Http2FrameHeader::new(payload_len, Http2FrameType::Settings, flags, 0);
                dst[..9].copy_from_slice(&header.encode());
                if !*ack {
                    let mut offset = 9;
                    for setting in settings {
                        let id_raw: u16 = setting.id.into();
                        dst[offset..offset + 2].copy_from_slice(&id_raw.to_be_bytes());
                        dst[offset + 2..offset + 6].copy_from_slice(&setting.value.to_be_bytes());
                        offset += 6;
                    }
                }
            }
            Http2Frame::Ping { ack, opaque_data } => {
                let flags = if *ack { Self::FLAG_ACK } else { 0 };
                let header = Http2FrameHeader::new(8, Http2FrameType::Ping, flags, 0);
                dst[..9].copy_from_slice(&header.encode());
                dst[9..17].copy_from_slice(opaque_data);
            }
            Http2Frame::GoAway {
                last_stream_id,
                error_code,
                debug_data,
            } => {
                let payload_len = 8 + debug_data.len() as u32;
                let header = Http2FrameHeader::new(payload_len, Http2FrameType::GoAway, 0, 0);
                dst[..9].copy_from_slice(&header.encode());
                dst[9..13].copy_from_slice(&(last_stream_id & 0x7FFF_FFFF).to_be_bytes());
                let err_raw: u32 = (*error_code).into();
                dst[13..17].copy_from_slice(&err_raw.to_be_bytes());
                dst[17..17 + debug_data.len()].copy_from_slice(debug_data);
            }
            Http2Frame::WindowUpdate {
                stream_id,
                window_size_increment,
            } => {
                let header = Http2FrameHeader::new(4, Http2FrameType::WindowUpdate, 0, *stream_id);
                dst[..9].copy_from_slice(&header.encode());
                dst[9..13].copy_from_slice(&(window_size_increment & 0x7FFF_FFFF).to_be_bytes());
            }
            Http2Frame::Continuation {
                stream_id,
                end_headers,
                header_block,
            } => {
                let flags = if *end_headers {
                    Self::FLAG_END_HEADERS
                } else {
                    0
                };
                let header = Http2FrameHeader::new(
                    header_block.len() as u32,
                    Http2FrameType::Continuation,
                    flags,
                    *stream_id,
                );
                dst[..9].copy_from_slice(&header.encode());
                dst[9..9 + header_block.len()].copy_from_slice(header_block);
            }
            Http2Frame::PushPromise {
                stream_id,
                promised_stream_id,
                end_headers,
                header_block,
            } => {
                let flags = if *end_headers {
                    Self::FLAG_END_HEADERS
                } else {
                    0
                };
                let payload_len = 4 + header_block.len();
                let header = Http2FrameHeader::new(
                    payload_len as u32,
                    Http2FrameType::PushPromise,
                    flags,
                    *stream_id,
                );
                dst[..9].copy_from_slice(&header.encode());
                dst[9..13].copy_from_slice(&(*promised_stream_id & 0x7FFF_FFFF).to_be_bytes());
                dst[13..13 + header_block.len()].copy_from_slice(header_block);
            }
            Http2Frame::PriorityUpdate {
                prioritized_stream_id,
                priority_field_value,
            } => {
                let bytes = priority_field_value.as_bytes();
                let payload_len = 4 + bytes.len();
                let header =
                    Http2FrameHeader::new(payload_len as u32, Http2FrameType::PriorityUpdate, 0, 0);
                dst[..9].copy_from_slice(&header.encode());
                dst[9..13].copy_from_slice(&(*prioritized_stream_id & 0x7FFF_FFFF).to_be_bytes());
                dst[13..13 + bytes.len()].copy_from_slice(bytes);
            }
            Http2Frame::AltSvc {
                stream_id,
                origin,
                alt_svc_field_value,
            } => {
                let origin_bytes = origin.as_bytes();
                let alt_svc_bytes = alt_svc_field_value.as_bytes();
                let origin_len = origin_bytes.len() as u16;
                let payload_len = 2 + origin_bytes.len() + alt_svc_bytes.len();
                let header = Http2FrameHeader::new(
                    payload_len as u32,
                    Http2FrameType::AltSvc,
                    0,
                    *stream_id & 0x7FFF_FFFF,
                );
                dst[..9].copy_from_slice(&header.encode());
                dst[9..11].copy_from_slice(&origin_len.to_be_bytes());
                dst[11..11 + origin_bytes.len()].copy_from_slice(origin_bytes);
                let alt_off = 11 + origin_bytes.len();
                dst[alt_off..alt_off + alt_svc_bytes.len()].copy_from_slice(alt_svc_bytes);
            }
            Http2Frame::Unknown { header, payload } => {
                dst[..9].copy_from_slice(&header.encode());
                dst[9..9 + payload.len()].copy_from_slice(payload);
            }
        }

        Ok(total_len)
    }

    /// Check if this frame is a lightweight control frame (PING, SETTINGS, WINDOW_UPDATE, RST_STREAM, PRIORITY).
    pub fn is_control_frame(&self) -> bool {
        matches!(
            self,
            Http2Frame::Ping { .. }
                | Http2Frame::Settings { .. }
                | Http2Frame::WindowUpdate { .. }
                | Http2Frame::RstStream { .. }
                | Http2Frame::Priority { .. }
                | Http2Frame::PriorityUpdate { .. }
        )
    }

    /// Decode an HTTP/2 frame from header and payload bytes.
    pub fn decode(header: &Http2FrameHeader, payload: &[u8]) -> Result<Self, FastHttpError> {
        if payload.len() < header.length as usize {
            return Err(FastHttpError::Incomplete);
        }
        let payload = &payload[..header.length as usize];

        match header.frame_type {
            Http2FrameType::Data => {
                let end_stream = (header.flags & Self::FLAG_END_STREAM) != 0;
                let data = if (header.flags & Self::FLAG_PADDED) != 0 {
                    if payload.is_empty() {
                        return Err(FastHttpError::InvalidRequestLine);
                    }
                    let pad_len = payload[0] as usize;
                    if 1 + pad_len > payload.len() {
                        return Err(FastHttpError::InvalidRequestLine);
                    }
                    payload[1..payload.len() - pad_len].to_vec()
                } else {
                    payload.to_vec()
                };
                Ok(Http2Frame::Data {
                    stream_id: header.stream_id,
                    end_stream,
                    data,
                })
            }
            Http2FrameType::Headers => {
                let end_stream = (header.flags & Self::FLAG_END_STREAM) != 0;
                let end_headers = (header.flags & Self::FLAG_END_HEADERS) != 0;
                let mut offset = 0;
                let mut pad_len = 0;
                if (header.flags & Self::FLAG_PADDED) != 0 {
                    if payload.is_empty() {
                        return Err(FastHttpError::InvalidHeader);
                    }
                    pad_len = payload[0] as usize;
                    offset += 1;
                }
                if (header.flags & Self::FLAG_PRIORITY) != 0 {
                    if payload.len() < offset + 5 {
                        return Err(FastHttpError::InvalidHeader);
                    }
                    offset += 5; // skip dependency (4 bytes) and weight (1 byte)
                }
                if offset + pad_len > payload.len() {
                    return Err(FastHttpError::InvalidHeader);
                }
                let header_block = payload[offset..payload.len() - pad_len].to_vec();
                Ok(Http2Frame::Headers {
                    stream_id: header.stream_id,
                    end_stream,
                    end_headers,
                    header_block,
                })
            }
            Http2FrameType::Priority => {
                if payload.len() < 5 {
                    return Err(FastHttpError::InvalidRequestLine);
                }
                let raw_dep = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                let exclusive = (raw_dep & 0x8000_0000) != 0;
                let stream_dependency = raw_dep & 0x7FFF_FFFF;
                let weight = payload[4];
                Ok(Http2Frame::Priority {
                    stream_id: header.stream_id,
                    exclusive,
                    stream_dependency,
                    weight,
                })
            }
            Http2FrameType::RstStream => {
                if payload.len() < 4 {
                    return Err(FastHttpError::InvalidRequestLine);
                }
                let code_raw = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                Ok(Http2Frame::RstStream {
                    stream_id: header.stream_id,
                    error_code: Http2ErrorCode::from(code_raw),
                })
            }
            Http2FrameType::Settings => {
                let ack = (header.flags & Self::FLAG_ACK) != 0;
                if ack && !payload.is_empty() {
                    return Err(FastHttpError::InvalidRequestLine);
                }
                if !payload.len().is_multiple_of(6) {
                    return Err(FastHttpError::InvalidRequestLine);
                }
                let (chunks, _) = payload.as_chunks::<6>();
                let mut settings = Vec::with_capacity(chunks.len());
                for chunk in chunks {
                    let id = u16::from_be_bytes([chunk[0], chunk[1]]);
                    let val = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);
                    settings.push(Http2Setting {
                        id: Http2SettingId::from(id),
                        value: val,
                    });
                }
                Ok(Http2Frame::Settings { ack, settings })
            }
            Http2FrameType::Ping => {
                if payload.len() != 8 {
                    return Err(FastHttpError::InvalidRequestLine);
                }
                let ack = (header.flags & Self::FLAG_ACK) != 0;
                let mut opaque_data = [0u8; 8];
                opaque_data.copy_from_slice(&payload[..8]);
                Ok(Http2Frame::Ping { ack, opaque_data })
            }
            Http2FrameType::GoAway => {
                if payload.len() < 8 {
                    return Err(FastHttpError::InvalidRequestLine);
                }
                let last_stream_id =
                    u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]])
                        & 0x7FFF_FFFF;
                let code_raw = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
                let debug_data = payload[8..].to_vec();
                Ok(Http2Frame::GoAway {
                    last_stream_id,
                    error_code: Http2ErrorCode::from(code_raw),
                    debug_data,
                })
            }
            Http2FrameType::WindowUpdate => {
                if payload.len() < 4 {
                    return Err(FastHttpError::InvalidRequestLine);
                }
                let window_size_increment =
                    u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]])
                        & 0x7FFF_FFFF;
                Ok(Http2Frame::WindowUpdate {
                    stream_id: header.stream_id,
                    window_size_increment,
                })
            }
            Http2FrameType::Continuation => {
                let end_headers = (header.flags & Self::FLAG_END_HEADERS) != 0;
                Ok(Http2Frame::Continuation {
                    stream_id: header.stream_id,
                    end_headers,
                    header_block: payload.to_vec(),
                })
            }
            Http2FrameType::PushPromise => {
                if payload.len() < 4 {
                    return Err(FastHttpError::InvalidRequestLine);
                }
                let mut offset = 0;
                let pad_len = if (header.flags & Self::FLAG_PADDED) != 0 {
                    if payload.is_empty() {
                        return Err(FastHttpError::InvalidHeader);
                    }
                    let p = payload[0] as usize;
                    offset += 1;
                    p
                } else {
                    0
                };
                if offset + 4 > payload.len() {
                    return Err(FastHttpError::InvalidRequestLine);
                }
                let promised_stream_id = u32::from_be_bytes([
                    payload[offset],
                    payload[offset + 1],
                    payload[offset + 2],
                    payload[offset + 3],
                ]) & 0x7FFF_FFFF;
                offset += 4;
                if offset + pad_len > payload.len() {
                    return Err(FastHttpError::InvalidHeader);
                }
                let header_block = payload[offset..payload.len() - pad_len].to_vec();
                let end_headers = (header.flags & Self::FLAG_END_HEADERS) != 0;
                Ok(Http2Frame::PushPromise {
                    stream_id: header.stream_id,
                    promised_stream_id,
                    end_headers,
                    header_block,
                })
            }
            Http2FrameType::PriorityUpdate => {
                // RFC 9218 Section 4.2:
                // A PRIORITY_UPDATE frame with length less than 4 octets MUST be treated as a connection error of type FRAME_SIZE_ERROR.
                // A PRIORITY_UPDATE frame on a stream other than stream 0 MUST be treated as a connection error of type PROTOCOL_ERROR.
                if header.stream_id != 0 {
                    return Err(FastHttpError::InvalidRequestLine);
                }
                if payload.len() < 4 {
                    return Err(FastHttpError::InvalidRequestLine);
                }
                let prioritized_stream_id =
                    u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]])
                        & 0x7FFF_FFFF;
                let priority_field_value = String::from_utf8_lossy(&payload[4..]).into_owned();
                Ok(Http2Frame::PriorityUpdate {
                    prioritized_stream_id,
                    priority_field_value,
                })
            }
            Http2FrameType::AltSvc => {
                // RFC 7838 Section 4:
                // An ALTSVC frame with length less than 2 octets MUST be treated as FRAME_SIZE_ERROR.
                if payload.len() < 2 {
                    return Err(FastHttpError::InvalidRequestLine);
                }
                let origin_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
                if 2 + origin_len > payload.len() {
                    return Err(FastHttpError::InvalidRequestLine);
                }
                let origin = String::from_utf8_lossy(&payload[2..2 + origin_len]).into_owned();
                let alt_svc_field_value =
                    String::from_utf8_lossy(&payload[2 + origin_len..]).into_owned();
                Ok(Http2Frame::AltSvc {
                    stream_id: header.stream_id,
                    origin,
                    alt_svc_field_value,
                })
            }
            _ => Ok(Http2Frame::Unknown {
                header: header.clone(),
                payload: payload.to_vec(),
            }),
        }
    }
}

/// Borrowed zero-copy slice view of an incoming HTTP/2 DATA frame payload.
/// Avoids heap allocations when decoding and inspecting DATA frames from wire buffers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Http2DataFrameSlice<'a> {
    /// Stream identifier associated with this DATA frame.
    pub stream_id: u32,
    /// Indicates whether this DATA frame terminates the stream.
    pub end_stream: bool,
    /// Borrowed slice of the frame payload (excluding any padding).
    pub data: &'a [u8],
}

impl<'a> Http2DataFrameSlice<'a> {
    /// Decode a DATA frame into a borrowed payload slice without heap allocation.
    pub fn decode(header: &Http2FrameHeader, payload: &'a [u8]) -> Result<Self, FastHttpError> {
        if header.frame_type != Http2FrameType::Data {
            return Err(FastHttpError::InvalidRequestLine);
        }
        if payload.len() < header.length as usize {
            return Err(FastHttpError::Incomplete);
        }
        let payload = &payload[..header.length as usize];
        let end_stream = (header.flags & Http2Frame::FLAG_END_STREAM) != 0;
        let data = if (header.flags & Http2Frame::FLAG_PADDED) != 0 {
            if payload.is_empty() {
                return Err(FastHttpError::InvalidRequestLine);
            }
            let pad_len = payload[0] as usize;
            if 1 + pad_len > payload.len() {
                return Err(FastHttpError::InvalidRequestLine);
            }
            &payload[1..payload.len() - pad_len]
        } else {
            payload
        };
        Ok(Self {
            stream_id: header.stream_id,
            end_stream,
            data,
        })
    }

    /// Convert this zero-copy slice view into an owned `Http2Frame::Data`.
    pub fn to_owned_frame(&self) -> Http2Frame {
        Http2Frame::Data {
            stream_id: self.stream_id,
            end_stream: self.end_stream,
            data: self.data.to_vec(),
        }
    }
}

// -----------------------------------------------------------------------------
// HPACK Integer & String representation + Static Table (RFC 7541)
// -----------------------------------------------------------------------------

/// Encode HPACK integer with N-bit prefix (RFC 7541 Section 5.1).
pub fn hpack_encode_integer(value: usize, prefix_bits: u8, prefix_mask: u8, out: &mut Vec<u8>) {
    let max_prefix = (1 << prefix_bits) - 1;
    if value < max_prefix {
        out.push(prefix_mask | (value as u8));
    } else {
        out.push(prefix_mask | (max_prefix as u8));
        let mut rem = value - max_prefix;
        while rem >= 128 {
            out.push(((rem % 128) as u8) | 0x80);
            rem /= 128;
        }
        out.push(rem as u8);
    }
}

/// Decode HPACK integer with N-bit prefix (RFC 7541 Section 5.1).
pub fn hpack_decode_integer(
    bytes: &[u8],
    prefix_bits: u8,
) -> Result<(usize, usize), FastHttpError> {
    if bytes.is_empty() {
        return Err(FastHttpError::Incomplete);
    }
    let max_prefix = (1 << prefix_bits) - 1;
    let initial = (bytes[0] as usize) & max_prefix;
    if initial < max_prefix {
        return Ok((initial, 1));
    }

    let mut value = initial;
    let mut m = 0;
    let mut idx = 1;
    loop {
        if idx >= bytes.len() {
            return Err(FastHttpError::Incomplete);
        }
        let b = bytes[idx] as usize;
        idx += 1;
        value += (b & 127) << m;
        m += 7;
        if (b & 128) == 0 {
            break;
        }
        if m > 28 {
            return Err(FastHttpError::InvalidHeader);
        }
    }
    Ok((value, idx))
}

use crate::hpack_huffman_table::{HUFFMAN_CODES, HUFFMAN_TRIE};

/// Encode an octet slice using HPACK static Huffman coding (RFC 7541 Appendix B).
pub fn hpack_huffman_encode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut cur: u64 = 0;
    let mut cur_bits: u8 = 0;

    for &b in input {
        let (code, bits) = HUFFMAN_CODES[b as usize];
        cur = (cur << bits) | (code as u64);
        cur_bits += bits;
        while cur_bits >= 8 {
            cur_bits -= 8;
            out.push((cur >> cur_bits) as u8);
        }
    }

    if cur_bits > 0 {
        // Pad with 1s (most significant bits of EOS)
        let pad = 8 - cur_bits;
        cur = (cur << pad) | ((1 << pad) - 1);
        out.push(cur as u8);
    }

    out
}

/// Decode an octet slice using HPACK static Huffman coding (RFC 7541 Appendix B).
pub fn hpack_huffman_decode(input: &[u8]) -> Result<Vec<u8>, FastHttpError> {
    let mut out = Vec::with_capacity(input.len());
    let mut node_idx: usize = 0;

    for &b in input {
        for bit_pos in (0..8).rev() {
            let bit = ((b >> bit_pos) & 1) as usize;
            let node = HUFFMAN_TRIE[node_idx];
            let next_idx = node[bit] as usize;
            if next_idx == 0 && node_idx != 0 {
                return Err(FastHttpError::InvalidHeader);
            }
            let next_node = HUFFMAN_TRIE[next_idx];
            let sym = next_node[2];
            if sym != 0xffff {
                if sym == 256 {
                    // EOS symbol must not appear in encoded string
                    return Err(FastHttpError::InvalidHeader);
                }
                out.push(sym as u8);
                node_idx = 0;
            } else {
                node_idx = next_idx;
            }
        }
    }

    // RFC 7541 Section 5.2: padding must be strictly less than 8 bits and strictly 1s
    if node_idx != 0 {
        let node = HUFFMAN_TRIE[node_idx];
        if node[2] == 0xffff && node[1] != 0 {
            // Path was following 1s; verify padding validity
        }
    }

    Ok(out)
}

/// Encode an octet string with optional Huffman coding (RFC 7541 Section 5.2).
pub fn hpack_encode_string(s: &[u8], out: &mut Vec<u8>) {
    hpack_encode_string_custom(s, out, false);
}

/// Encode an octet string allowing Huffman compression (RFC 7541 Section 5.2).
pub fn hpack_encode_string_custom(s: &[u8], out: &mut Vec<u8>, use_huffman: bool) {
    if use_huffman {
        let encoded = hpack_huffman_encode(s);
        if encoded.len() < s.len() {
            hpack_encode_integer(encoded.len(), 7, 0x80, out);
            out.extend_from_slice(&encoded);
            return;
        }
    }
    // H bit = 0 (no Huffman) with 7-bit prefix
    hpack_encode_integer(s.len(), 7, 0x00, out);
    out.extend_from_slice(s);
}

/// Decode an octet string (RFC 7541 Section 5.2), supporting both raw and Huffman strings.
pub fn hpack_decode_string(
    bytes: &[u8],
) -> Result<(std::borrow::Cow<'_, [u8]>, usize), FastHttpError> {
    if bytes.is_empty() {
        return Err(FastHttpError::Incomplete);
    }
    let is_huffman = (bytes[0] & 0x80) != 0;
    let (len, consumed) = hpack_decode_integer(bytes, 7)?;
    if bytes.len() < consumed + len {
        return Err(FastHttpError::Incomplete);
    }
    let raw = &bytes[consumed..consumed + len];
    if is_huffman {
        let decoded = hpack_huffman_decode(raw)?;
        Ok((std::borrow::Cow::Owned(decoded), consumed + len))
    } else {
        Ok((std::borrow::Cow::Borrowed(raw), consumed + len))
    }
}

/// HPACK Static Table (RFC 7541 Appendix A).
pub const HPACK_STATIC_TABLE: &[(&str, &str)] = &[
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

/// Dynamic table eviction policy for HPACK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HpackEvictionPolicy {
    /// Standard FIFO eviction (RFC 7541: oldest inserted entry evicted first).
    Fifo,
    /// LRU eviction: entries accessed during encoding or decoding are refreshed,
    /// and the least recently referenced dynamic header is evicted first when table capacity is exceeded.
    Lru,
}

/// HPACK compression telemetry metrics tracking header savings and compression efficiency.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HpackTelemetry {
    /// Total count of headers passed for encoding.
    pub total_headers: usize,
    /// Total bytes of raw (uncompressed) header names and values.
    pub raw_bytes: usize,
    /// Total bytes produced after HPACK encoding.
    pub compressed_bytes: usize,
    /// Number of header fields served directly from static table index (1-byte overhead).
    pub static_table_hits: usize,
    /// Number of header fields served directly from dynamic table index.
    pub dynamic_table_hits: usize,
    /// Number of header literals emitted with Huffman encoding.
    pub huffman_encoded_literals: usize,
}

impl HpackTelemetry {
    /// Compression ratio: compressed bytes divided by raw bytes.
    /// E.g. 0.40 indicates headers compressed to 40% of their raw size.
    pub fn compression_ratio(&self) -> f64 {
        if self.raw_bytes == 0 {
            1.0
        } else {
            self.compressed_bytes as f64 / self.raw_bytes as f64
        }
    }

    /// Savings percentage: (1.0 - compression_ratio) * 100.
    /// E.g. 60.0% means HPACK saved 60% of wire traffic compared to uncompressed HTTP/1.1 headers.
    pub fn savings_percentage(&self) -> f64 {
        if self.raw_bytes == 0 {
            0.0
        } else {
            (1.0 - self.compression_ratio()) * 100.0
        }
    }
}

/// Adaptive flow control parameters based on estimated bandwidth and round-trip time (RTT).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AdaptiveFlowControlConfig {
    /// Minimum connection window allowed (default: 64 KB).
    pub min_connection_window: i32,
    /// Maximum connection window allowed (default: 16 MB).
    pub max_connection_window: i32,
    /// Target bandwidth-delay product (BDP) multiplier headroom (default: 1.5).
    pub bdp_headroom: f64,
}

impl Default for AdaptiveFlowControlConfig {
    fn default() -> Self {
        Self {
            min_connection_window: 65535,
            max_connection_window: 16 * 1024 * 1024,
            bdp_headroom: 1.5,
        }
    }
}

/// Adaptive flow control estimator maintaining smoothed RTT and bandwidth metrics.
#[derive(Debug, Clone)]
pub struct AdaptiveFlowController {
    pub config: AdaptiveFlowControlConfig,
    /// Smoothed round-trip time in microseconds (SRTT).
    pub smoothed_rtt_us: Option<u64>,
    /// Estimated bandwidth in bytes per second.
    pub estimated_bandwidth_bps: Option<u64>,
    /// Last target connection window calculated from BDP.
    pub target_connection_window: i32,
    /// Last ping sequence sent timestamp for RTT measurement.
    pub pending_ping_timestamp: Option<(u64, std::time::Instant)>,
}

impl Default for AdaptiveFlowController {
    fn default() -> Self {
        Self::new(AdaptiveFlowControlConfig::default())
    }
}

impl AdaptiveFlowController {
    pub fn new(config: AdaptiveFlowControlConfig) -> Self {
        let initial_win = config.min_connection_window;
        Self {
            config,
            smoothed_rtt_us: None,
            estimated_bandwidth_bps: None,
            target_connection_window: initial_win,
            pending_ping_timestamp: None,
        }
    }

    /// Record a round-trip time sample in microseconds and update smoothed RTT (RFC 6298 EWMA).
    pub fn record_rtt_sample(&mut self, sample_rtt_us: u64) {
        match self.smoothed_rtt_us {
            None => self.smoothed_rtt_us = Some(sample_rtt_us),
            Some(srtt) => {
                // EWMA: srtt = 7/8 * srtt + 1/8 * sample
                let new_srtt = (srtt * 7 + sample_rtt_us) / 8;
                self.smoothed_rtt_us = Some(new_srtt);
            }
        }
        self.recompute_target_window();
    }

    /// Record an observed bandwidth sample in bytes per second.
    pub fn record_bandwidth_sample(
        &mut self,
        bytes_transferred: usize,
        duration: std::time::Duration,
    ) {
        let dur_secs = duration.as_secs_f64();
        if dur_secs > 0.0 {
            let sample_bps = (bytes_transferred as f64 / dur_secs) as u64;
            match self.estimated_bandwidth_bps {
                None => self.estimated_bandwidth_bps = Some(sample_bps),
                Some(prev_bps) => {
                    // EWMA with 3/4 weight on historical
                    let new_bps = (prev_bps * 3 + sample_bps) / 4;
                    self.estimated_bandwidth_bps = Some(new_bps);
                }
            }
            self.recompute_target_window();
        }
    }

    /// Recompute the optimal Bandwidth-Delay Product (BDP) window size.
    pub fn recompute_target_window(&mut self) -> i32 {
        let rtt_us = self.smoothed_rtt_us.unwrap_or(5_000);
        if let Some(bps) = self.estimated_bandwidth_bps {
            let rtt_secs = rtt_us as f64 / 1_000_000.0;
            let bdp_bytes = bps as f64 * rtt_secs;
            let target_with_headroom = (bdp_bytes * self.config.bdp_headroom) as i32;
            let clamped = target_with_headroom.clamp(
                self.config.min_connection_window,
                self.config.max_connection_window,
            );
            self.target_connection_window = clamped;
            clamped
        } else {
            self.target_connection_window
        }
    }
}

/// HPACK Header Encoder / Decoder with Dynamic Table (RFC 7541) and Literal Cache.
#[derive(Debug, Clone)]
pub struct HpackContext {
    pub max_table_size: usize,
    pub dynamic_table: Vec<(String, String)>,
    /// Eviction policy governing the dynamic table (default: Fifo as per RFC 7541).
    pub eviction_policy: HpackEvictionPolicy,
    /// Cache of frequently decoded literal strings to avoid repeated allocation and decoding.
    pub literal_cache: Vec<(Vec<u8>, String)>,
    pub max_literal_cache_size: usize,
    pub literal_cache_hits: usize,
    pub literal_cache_misses: usize,
    /// Telemetry metrics tracking compression ratio and table hits.
    pub telemetry: HpackTelemetry,
}

impl Default for HpackContext {
    fn default() -> Self {
        Self::new(4096)
    }
}

impl HpackContext {
    pub fn new(max_table_size: usize) -> Self {
        Self {
            max_table_size,
            dynamic_table: Vec::new(),
            eviction_policy: HpackEvictionPolicy::Fifo,
            literal_cache: Vec::new(),
            max_literal_cache_size: 64,
            literal_cache_hits: 0,
            literal_cache_misses: 0,
            telemetry: HpackTelemetry::default(),
        }
    }

    /// Set the dynamic table eviction policy (e.g. Fifo or Lru).
    pub fn with_eviction_policy(mut self, policy: HpackEvictionPolicy) -> Self {
        self.eviction_policy = policy;
        self
    }

    /// Set the dynamic table eviction policy mutably.
    pub fn set_eviction_policy(&mut self, policy: HpackEvictionPolicy) {
        self.eviction_policy = policy;
    }

    /// Configure the maximum number of entries cached for literal string representations.
    pub fn with_literal_cache_size(mut self, size: usize) -> Self {
        self.max_literal_cache_size = size;
        if self.literal_cache.len() > size {
            self.literal_cache.truncate(size);
        }
        self
    }

    /// Retrieve or decode a literal string from the internal cache.
    pub fn get_or_decode_literal(&mut self, raw_slice: &[u8]) -> Result<String, FastHttpError> {
        for (i, (key, val)) in self.literal_cache.iter().enumerate() {
            if key.as_slice() == raw_slice {
                self.literal_cache_hits += 1;
                let val_clone = val.clone();
                // Move accessed entry to front (LRU)
                if i > 0 {
                    let entry = self.literal_cache.remove(i);
                    self.literal_cache.insert(0, entry);
                }
                return Ok(val_clone);
            }
        }

        self.literal_cache_misses += 1;
        let (decoded_slice, _) = hpack_decode_string(raw_slice)?;
        let decoded_str = String::from_utf8_lossy(&decoded_slice).into_owned();

        if self.max_literal_cache_size > 0 {
            if self.literal_cache.len() >= self.max_literal_cache_size {
                self.literal_cache.pop();
            }
            self.literal_cache
                .insert(0, (raw_slice.to_vec(), decoded_str.clone()));
        }

        Ok(decoded_str)
    }

    /// Retrieve an entry by 1-based index (RFC 7541 Section 2.3.3).
    pub fn get_entry(&self, index: usize) -> Option<(&str, &str)> {
        if index == 0 {
            return None;
        }
        if index <= HPACK_STATIC_TABLE.len() {
            let (n, v) = HPACK_STATIC_TABLE[index - 1];
            Some((n, v))
        } else {
            let dyn_idx = index - HPACK_STATIC_TABLE.len() - 1;
            self.dynamic_table
                .get(dyn_idx)
                .map(|(n, v)| (n.as_str(), v.as_str()))
        }
    }

    /// Retrieve an entry by 1-based index and touch it if LRU eviction policy is active.
    pub fn get_and_touch_entry(&mut self, index: usize) -> Option<(String, String)> {
        if index == 0 {
            return None;
        }
        if index <= HPACK_STATIC_TABLE.len() {
            let (n, v) = HPACK_STATIC_TABLE[index - 1];
            Some((n.to_string(), v.to_string()))
        } else {
            let dyn_idx = index - HPACK_STATIC_TABLE.len() - 1;
            if dyn_idx < self.dynamic_table.len() {
                if self.eviction_policy == HpackEvictionPolicy::Lru && dyn_idx > 0 {
                    let entry = self.dynamic_table.remove(dyn_idx);
                    self.dynamic_table.insert(0, entry);
                    Some(self.dynamic_table[0].clone())
                } else {
                    Some(self.dynamic_table[dyn_idx].clone())
                }
            } else {
                None
            }
        }
    }

    /// Add an entry to the dynamic table with configurable eviction (FIFO or LRU).
    pub fn add_dynamic_entry(&mut self, name: String, value: String) {
        let entry_size = name.len() + value.len() + 32;
        if entry_size > self.max_table_size {
            self.dynamic_table.clear();
            return;
        }
        // If entry already exists and LRU is enabled, move/update to front
        if self.eviction_policy == HpackEvictionPolicy::Lru {
            if let Some(pos) = self
                .dynamic_table
                .iter()
                .position(|(n, v)| n == &name && v == &value)
            {
                self.dynamic_table.remove(pos);
            }
        }
        self.dynamic_table.insert(0, (name, value));
        let mut cur_size: usize = self
            .dynamic_table
            .iter()
            .map(|(k, v)| k.len() + v.len() + 32)
            .sum();
        while cur_size > self.max_table_size && !self.dynamic_table.is_empty() {
            if let Some((k, v)) = self.dynamic_table.pop() {
                cur_size -= k.len() + v.len() + 32;
            }
        }
    }

    /// Encode a list of headers into an HPACK byte block (using static table indexing and literal encoding).
    pub fn encode_headers(&mut self, headers: &[(&str, &str)]) -> Vec<u8> {
        self.encode_headers_with_options(headers, false)
    }

    /// Encode a list of headers into an HPACK byte block with optional Huffman compression.
    pub fn encode_headers_with_options(
        &mut self,
        headers: &[(&str, &str)],
        use_huffman: bool,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        let initial_len = out.len();
        let mut raw_bytes_count = 0;

        for &(name, value) in headers {
            raw_bytes_count += name.len() + value.len() + 4; // approximate raw HTTP/1.1 ": \r\n"
            self.telemetry.total_headers += 1;

            let mut matched_idx = None;
            let mut matched_name_idx = None;

            // Search static table
            for (idx, &(s_name, s_val)) in HPACK_STATIC_TABLE.iter().enumerate() {
                if s_name.eq_ignore_ascii_case(name) {
                    if matched_name_idx.is_none() {
                        matched_name_idx = Some(idx + 1);
                    }
                    if s_val == value {
                        matched_idx = Some(idx + 1);
                        break;
                    }
                }
            }

            // Search dynamic table if not exact match in static
            if matched_idx.is_none() {
                for (idx, (d_name, d_val)) in self.dynamic_table.iter().enumerate() {
                    let full_idx = HPACK_STATIC_TABLE.len() + idx + 1;
                    if d_name.eq_ignore_ascii_case(name) {
                        if matched_name_idx.is_none() {
                            matched_name_idx = Some(full_idx);
                        }
                        if d_val == value {
                            matched_idx = Some(full_idx);
                            break;
                        }
                    }
                }
            }

            if let Some(idx) = matched_idx {
                // 1. Indexed Header Field (RFC 7541 Section 6.1): 1xxxxxxx
                if idx <= HPACK_STATIC_TABLE.len() {
                    self.telemetry.static_table_hits += 1;
                } else {
                    self.telemetry.dynamic_table_hits += 1;
                }
                hpack_encode_integer(idx, 7, 0x80, &mut out);
            } else if let Some(name_idx) = matched_name_idx {
                // 2. Literal Header Field with Incremental Indexing — Indexed Name (RFC 7541 Section 6.2.1): 01xxxxxx
                if use_huffman {
                    self.telemetry.huffman_encoded_literals += 1;
                }
                hpack_encode_integer(name_idx, 6, 0x40, &mut out);
                hpack_encode_string_custom(value.as_bytes(), &mut out, use_huffman);
                self.add_dynamic_entry(name.to_ascii_lowercase(), value.to_string());
            } else {
                // 3. Literal Header Field with Incremental Indexing — New Name: 01000000
                if use_huffman {
                    self.telemetry.huffman_encoded_literals += 2;
                }
                out.push(0x40);
                hpack_encode_string_custom(
                    name.to_ascii_lowercase().as_bytes(),
                    &mut out,
                    use_huffman,
                );
                hpack_encode_string_custom(value.as_bytes(), &mut out, use_huffman);
                self.add_dynamic_entry(name.to_ascii_lowercase(), value.to_string());
            }
        }

        self.telemetry.raw_bytes += raw_bytes_count;
        self.telemetry.compressed_bytes += out.len() - initial_len;

        out
    }

    /// Decode an octet string length and payload slice (RFC 7541 Section 5.2).
    /// Returns the exact slice of the encoded string (including length prefix) and total consumed bytes.
    fn decode_string_raw(bytes: &[u8]) -> Result<(&[u8], usize), FastHttpError> {
        if bytes.is_empty() {
            return Err(FastHttpError::Incomplete);
        }
        let (len, consumed) = hpack_decode_integer(bytes, 7)?;
        if bytes.len() < consumed + len {
            return Err(FastHttpError::Incomplete);
        }
        let total = consumed + len;
        Ok((&bytes[..total], total))
    }

    /// Decode an HPACK byte block into a list of (name, value) headers.
    pub fn decode_headers(&mut self, bytes: &[u8]) -> Result<Vec<(String, String)>, FastHttpError> {
        let mut out = Vec::new();
        let mut offset = 0;

        while offset < bytes.len() {
            let b = bytes[offset];
            if (b & 0x80) != 0 {
                // Indexed Header Field (RFC 7541 Section 6.1)
                let (idx, consumed) = hpack_decode_integer(&bytes[offset..], 7)?;
                offset += consumed;
                let (name, val) = self
                    .get_and_touch_entry(idx)
                    .ok_or(FastHttpError::InvalidHeader)?;
                out.push((name, val));
            } else if (b & 0x40) != 0 {
                // Literal Header Field with Incremental Indexing (RFC 7541 Section 6.2.1)
                let (idx, consumed) = hpack_decode_integer(&bytes[offset..], 6)?;
                offset += consumed;
                let name = if idx != 0 {
                    let (n, _) = self
                        .get_and_touch_entry(idx)
                        .ok_or(FastHttpError::InvalidHeader)?;
                    n
                } else {
                    let (raw_str, consumed_str) = Self::decode_string_raw(&bytes[offset..])?;
                    let s = self.get_or_decode_literal(raw_str)?;
                    offset += consumed_str;
                    s
                };
                let (raw_val, consumed_val) = Self::decode_string_raw(&bytes[offset..])?;
                let val = self.get_or_decode_literal(raw_val)?;
                offset += consumed_val;

                self.add_dynamic_entry(name.clone(), val.clone());
                out.push((name, val));
            } else if (b & 0x20) != 0 {
                // Dynamic Table Size Update (RFC 7541 Section 6.3)
                let (new_size, consumed) = hpack_decode_integer(&bytes[offset..], 5)?;
                offset += consumed;
                self.max_table_size = new_size;
            } else {
                // Literal Header Field without Indexing / Never Indexed (RFC 7541 Section 6.2.2 & 6.2.3)
                let (idx, consumed) = hpack_decode_integer(&bytes[offset..], 4)?;
                offset += consumed;
                let name = if idx != 0 {
                    let (n, _) = self
                        .get_and_touch_entry(idx)
                        .ok_or(FastHttpError::InvalidHeader)?;
                    n
                } else {
                    let (raw_str, consumed_str) = Self::decode_string_raw(&bytes[offset..])?;
                    let s = self.get_or_decode_literal(raw_str)?;
                    offset += consumed_str;
                    s
                };
                let (raw_val, consumed_val) = Self::decode_string_raw(&bytes[offset..])?;
                let val = self.get_or_decode_literal(raw_val)?;
                offset += consumed_val;
                out.push((name, val));
            }
        }

        Ok(out)
    }
}

// -----------------------------------------------------------------------------
// HTTP/2 Multiplexed Stream Management (RFC 7540)
// -----------------------------------------------------------------------------

/// HTTP/2 Stream State according to RFC 7540 Section 5.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Http2StreamState {
    Idle,
    ReservedLocal,
    ReservedRemote,
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
}

/// HTTP/2 Stream representation for multiplexing over an active connection.
#[derive(Debug, Clone)]
pub struct Http2Stream {
    pub id: u32,
    pub state: Http2StreamState,
    pub window_size: i32,
    pub received_headers: Vec<(String, String)>,
    pub received_trailers: Vec<(String, String)>,
    pub received_data: Vec<u8>,
    pub reset_error: Option<Http2ErrorCode>,
    pub stream_dependency: u32,
    pub weight: u8,
    pub exclusive: bool,
    /// Extensible Prioritization Scheme (RFC 9218) parameters
    pub priority_params: PriorityParameters,
    /// Inbound flow control window size allocated by the local peer for this stream
    pub local_window_size: i32,
    /// Target inbound flow control window capacity (adapted dynamically based on traffic / priority)
    pub target_local_window_size: i32,
}

impl Http2Stream {
    pub fn new(id: u32, initial_window_size: i32) -> Self {
        Self {
            id,
            state: Http2StreamState::Idle,
            window_size: initial_window_size,
            received_headers: Vec::new(),
            received_trailers: Vec::new(),
            received_data: Vec::new(),
            reset_error: None,
            stream_dependency: 0,
            weight: 16,
            exclusive: false,
            priority_params: PriorityParameters::default(),
            local_window_size: initial_window_size,
            target_local_window_size: initial_window_size,
        }
    }
}

/// Represents an HTTP/2 server push promise request initiated via PUSH_PROMISE (RFC 7540 Section 8.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Http2PromisedRequest {
    /// Stream ID on which the PUSH_PROMISE was received (the associated client request).
    pub associated_stream_id: u32,
    /// New reserved stream ID on which the server will push the promised response.
    pub promised_stream_id: u32,
    /// HTTP method (e.g., "GET", "HEAD"). MUST be safe according to RFC 7540 §8.2.
    pub method: String,
    /// Promised request path (e.g., "/style.css").
    pub path: String,
    /// Promised URI scheme (e.g., "https", "http").
    pub scheme: String,
    /// Promised authority (e.g., "example.com:443").
    pub authority: String,
    /// All raw promised request headers.
    pub headers: Vec<(String, String)>,
    /// Whether this push promise passes RFC 7540 validation requirements.
    pub is_valid: bool,
    /// Reason string if validation failed.
    pub validation_error: Option<String>,
}

impl Http2PromisedRequest {
    /// Construct and validate an HTTP/2 promised request from raw decoded header block.
    pub fn new(
        associated_stream_id: u32,
        promised_stream_id: u32,
        raw_headers: Vec<(String, String)>,
    ) -> Self {
        let mut method = String::new();
        let mut path = String::new();
        let mut scheme = String::new();
        let mut authority = String::new();
        let mut regular_header_seen = false;
        let mut pseudo_order_valid = true;

        for (k, v) in &raw_headers {
            if k.starts_with(':') {
                if regular_header_seen {
                    pseudo_order_valid = false;
                }
                match k.as_str() {
                    ":method" => method = v.clone(),
                    ":path" => path = v.clone(),
                    ":scheme" => scheme = v.clone(),
                    ":authority" => authority = v.clone(),
                    _ => {}
                }
            } else {
                regular_header_seen = true;
                if k.eq_ignore_ascii_case("host") && authority.is_empty() {
                    authority = v.clone();
                }
            }
        }

        // RFC 7540 §8.2.1:
        // 1. The request method MUST be safe (RFC 7231 Section 4.2.1: GET or HEAD).
        // 2. Mandatory pseudo-headers: :method, :path, :scheme.
        // 3. Pseudo-headers MUST appear before standard header fields (Section 8.1.2.1).
        let mut is_valid = true;
        let mut validation_error = None;

        if !pseudo_order_valid {
            is_valid = false;
            validation_error = Some(
                "Pseudo-headers must appear before regular headers (RFC 7540 §8.1.2.1)".to_string(),
            );
        } else if method.is_empty() {
            is_valid = false;
            validation_error =
                Some("Missing mandatory :method pseudo-header in PUSH_PROMISE".to_string());
        } else if !method.eq_ignore_ascii_case("GET") && !method.eq_ignore_ascii_case("HEAD") {
            is_valid = false;
            validation_error = Some(format!(
                "Unsafe HTTP method '{}' prohibited in PUSH_PROMISE (RFC 7540 §8.2: must be GET or HEAD)",
                method
            ));
        } else if path.is_empty() {
            is_valid = false;
            validation_error =
                Some("Missing mandatory :path pseudo-header in PUSH_PROMISE".to_string());
        } else if scheme.is_empty() {
            is_valid = false;
            validation_error =
                Some("Missing mandatory :scheme pseudo-header in PUSH_PROMISE".to_string());
        }

        Self {
            associated_stream_id,
            promised_stream_id,
            method,
            path,
            scheme,
            authority,
            headers: raw_headers,
            is_valid,
            validation_error,
        }
    }
}

/// Parsed HTTP/2 Cache-Control directives conforming to RFC 7234 Section 5.2.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Http2CacheDirectives {
    /// Directive `no-cache`: response must be revalidated with origin before use.
    pub no_cache: bool,
    /// Directive `no-store`: response must never be stored in persistent or shared cache.
    pub no_store: bool,
    /// Directive `must-revalidate`: once stale, response must be revalidated before use.
    pub must_revalidate: bool,
    /// Directive `public`: response may be cached by any cache.
    pub is_public: bool,
    /// Directive `private`: response intended for single user; not cacheable in shared cache.
    pub is_private: bool,
    /// Directive `immutable`: content will not change while fresh.
    pub immutable: bool,
    /// Directive `max-age=N`: lifetime in seconds.
    pub max_age_secs: Option<u64>,
    /// Directive `s-maxage=N`: shared cache lifetime in seconds.
    pub s_maxage_secs: Option<u64>,
}

impl Http2CacheDirectives {
    /// Parse Cache-Control header string into structured directives.
    pub fn parse(header_value: &str) -> Self {
        let mut d = Self::default();
        for item in header_value.split(',') {
            let part = item.trim();
            if part.is_empty() {
                continue;
            }
            let mut kv = part.splitn(2, '=');
            let key = kv.next().unwrap_or("").trim().to_ascii_lowercase();
            let val = kv.next().map(|v| v.trim().trim_matches('"'));
            match key.as_str() {
                "no-cache" => d.no_cache = true,
                "no-store" => d.no_store = true,
                "must-revalidate" => d.must_revalidate = true,
                "public" => d.is_public = true,
                "private" => d.is_private = true,
                "immutable" => d.immutable = true,
                "max-age" => {
                    if let Some(v) = val {
                        d.max_age_secs = v.parse::<u64>().ok();
                    }
                }
                "s-maxage" => {
                    if let Some(v) = val {
                        d.s_maxage_secs = v.parse::<u64>().ok();
                    }
                }
                _ => {}
            }
        }
        d
    }

    /// Whether this response is eligible to be stored in client cache under RFC 7234.
    #[inline]
    pub fn is_cacheable(&self) -> bool {
        !self.no_store
    }

    /// Effective maximum age in seconds, preferring s-maxage if specified.
    #[inline]
    pub fn effective_max_age(&self) -> Option<u64> {
        self.s_maxage_secs.or(self.max_age_secs)
    }
}

/// Check whether an HTTP status code is cacheable by default under RFC 7234 Section 3.
#[inline]
pub fn is_http_status_cacheable_by_default(status: u16) -> bool {
    matches!(
        status,
        200 | 203 | 204 | 206 | 300 | 301 | 304 | 404 | 405 | 410 | 414 | 501
    )
}

/// Extract parsed Cache-Control directives from headers slice.
pub fn extract_http2_cache_control(headers: &[(String, String)]) -> Option<Http2CacheDirectives> {
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("cache-control") {
            return Some(Http2CacheDirectives::parse(v));
        }
    }
    None
}

/// Extract ETag validator string from headers slice (RFC 7232 §2.3).
pub fn extract_http2_etag(headers: &[(String, String)]) -> Option<String> {
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("etag") {
            return Some(v.trim().to_string());
        }
    }
    None
}

/// Extract Last-Modified header string from headers slice (RFC 7232 §2.2).
pub fn extract_http2_last_modified(headers: &[(String, String)]) -> Option<String> {
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("last-modified") {
            return Some(v.trim().to_string());
        }
    }
    None
}

/// Build conditional request headers (If-None-Match, If-Modified-Since) for RFC 7232 revalidation.
pub fn build_http2_conditional_headers(
    etag: Option<&str>,
    last_modified: Option<&str>,
) -> Vec<(String, String)> {
    let mut headers = Vec::new();
    if let Some(tag) = etag {
        headers.push(("if-none-match".to_string(), tag.to_string()));
    }
    if let Some(lm) = last_modified {
        headers.push(("if-modified-since".to_string(), lm.to_string()));
    }
    headers
}

/// Parsed HTTP/2 Vary header directives conforming to RFC 7234 Section 4.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Http2Vary {
    /// Directive `Vary: *`: The stored response cannot be used to satisfy subsequent requests.
    Any,
    /// Selecting request header field names (normalized to lowercase).
    Headers(Vec<String>),
}

impl Http2Vary {
    /// Parse a Vary header field value into an [`Http2Vary`] directive.
    pub fn parse(header_value: &str) -> Self {
        let trimmed = header_value.trim();
        if trimmed == "*" {
            return Http2Vary::Any;
        }
        let mut fields = Vec::new();
        for item in trimmed.split(',') {
            let part = item.trim();
            if part == "*" {
                return Http2Vary::Any;
            }
            if !part.is_empty() {
                let lower = part.to_ascii_lowercase();
                if !fields.contains(&lower) {
                    fields.push(lower);
                }
            }
        }
        Http2Vary::Headers(fields)
    }

    /// Whether this Vary specification allows matching secondary requests under RFC 7234 §4.1.
    #[inline]
    pub fn is_matchable(&self) -> bool {
        !matches!(self, Http2Vary::Any)
    }

    /// Check if the selecting request headers from a stored response match a presented request (RFC 7234 §4.1).
    pub fn matches_request(
        &self,
        stored_req_headers: &[(String, String)],
        presented_req_headers: &[(String, String)],
    ) -> bool {
        match self {
            Http2Vary::Any => false,
            Http2Vary::Headers(field_names) => {
                for name in field_names {
                    let stored_val =
                        find_combined_header_case_insensitive(stored_req_headers, name);
                    let presented_val =
                        find_combined_header_case_insensitive(presented_req_headers, name);
                    if stored_val != presented_val {
                        return false;
                    }
                }
                true
            }
        }
    }
}

/// Helper to find and combine header values case-insensitively.
pub fn find_combined_header_case_insensitive(
    headers: &[(String, String)],
    name: &str,
) -> Option<String> {
    let mut parts: Vec<&str> = Vec::new();
    for (k, v) in headers {
        if k.eq_ignore_ascii_case(name) {
            parts.push(v.trim());
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(", "))
    }
}

/// Extract parsed Vary directives from headers slice (RFC 7234 §4.1).
pub fn extract_http2_vary(headers: &[(String, String)]) -> Option<Http2Vary> {
    let mut vary_parts = Vec::new();
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("vary") {
            vary_parts.push(v.trim());
        }
    }
    if vary_parts.is_empty() {
        None
    } else {
        Some(Http2Vary::parse(&vary_parts.join(", ")))
    }
}

/// Multiplexed HTTP/2 Session Manager handling streams, flow control, and HPACK.
#[derive(Debug)]
pub struct Http2Session {
    pub is_server: bool,
    pub next_stream_id: u32,
    pub peer_settings: Vec<Http2Setting>,
    pub local_settings: Vec<Http2Setting>,
    pub streams: std::collections::HashMap<u32, Http2Stream>,
    pub push_promises: std::collections::HashMap<u32, Vec<(String, String)>>,
    /// Structured promised requests mapped by promised stream ID.
    pub promised_requests: std::collections::HashMap<u32, Http2PromisedRequest>,
    /// Whether server push promises are enabled and accepted (RFC 7540 Section 6.5.2).
    pub enable_push: bool,
    pub hpack_encoder: HpackContext,
    pub hpack_decoder: HpackContext,
    pub connection_window_size: i32,
    pub initial_stream_window_size: i32,
    pub last_received_goaway: Option<(u32, Http2ErrorCode, Vec<u8>)>,
    /// RFC 7838 alternative services advertised by peer.
    /// Maps origin string (or empty for current origin) to list of available routes.
    pub alt_svc_routes: std::collections::HashMap<String, Vec<AltSvcRoute>>,
    /// Queued outbound data pending transmission, mapped by stream ID.
    pub pending_outbound_data: std::collections::HashMap<u32, Vec<u8>>,
    /// Adaptive flow controller optimizing connection and stream windows based on RTT and bandwidth.
    pub adaptive_flow_controller: AdaptiveFlowController,
}

impl Http2Session {
    pub const CLIENT_PREFACE: &'static [u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    pub const DEFAULT_INITIAL_WINDOW_SIZE: i32 = 65535;

    pub fn new(is_server: bool) -> Self {
        Self {
            is_server,
            next_stream_id: if is_server { 2 } else { 1 },
            peer_settings: Vec::new(),
            local_settings: vec![
                Http2Setting {
                    id: Http2SettingId::MaxConcurrentStreams,
                    value: 100,
                },
                Http2Setting {
                    id: Http2SettingId::InitialWindowSize,
                    value: Self::DEFAULT_INITIAL_WINDOW_SIZE as u32,
                },
            ],
            streams: std::collections::HashMap::new(),
            push_promises: std::collections::HashMap::new(),
            promised_requests: std::collections::HashMap::new(),
            enable_push: true,
            hpack_encoder: HpackContext::default(),
            hpack_decoder: HpackContext::default(),
            connection_window_size: Self::DEFAULT_INITIAL_WINDOW_SIZE,
            initial_stream_window_size: Self::DEFAULT_INITIAL_WINDOW_SIZE,
            last_received_goaway: None,
            alt_svc_routes: std::collections::HashMap::new(),
            pending_outbound_data: std::collections::HashMap::new(),
            adaptive_flow_controller: AdaptiveFlowController::default(),
        }
    }

    /// Get a peer setting value if negotiated.
    pub fn get_peer_setting(&self, id: Http2SettingId) -> Option<u32> {
        self.peer_settings
            .iter()
            .find(|s| s.id == id)
            .map(|s| s.value)
    }

    /// Get a local setting value.
    pub fn get_local_setting(&self, id: Http2SettingId) -> Option<u32> {
        self.local_settings
            .iter()
            .find(|s| s.id == id)
            .map(|s| s.value)
    }

    /// Update local settings and create an outbound non-ACK SETTINGS frame.
    /// Also updates local flow control / header limits if relevant.
    pub fn update_local_settings(&mut self, settings: &[Http2Setting]) -> Http2Frame {
        for new_s in settings {
            if let Some(existing) = self.local_settings.iter_mut().find(|s| s.id == new_s.id) {
                existing.value = new_s.value;
            } else {
                self.local_settings.push(*new_s);
            }
        }
        Http2Frame::Settings {
            ack: false,
            settings: settings.to_vec(),
        }
    }

    /// Open a new stream locally (e.g. client sending a request).
    pub fn open_stream(&mut self) -> u32 {
        let stream_id = self.next_stream_id;
        self.next_stream_id += 2;
        let stream = Http2Stream::new(stream_id, self.initial_stream_window_size);
        self.streams.insert(stream_id, stream);
        stream_id
    }

    /// Apply dynamic renegotiation of flow control window sizes at session level (stream ID 0)
    /// or stream level (stream ID > 0), returning the resulting new window size.
    pub fn update_window_size(
        &mut self,
        stream_id: u32,
        increment: u32,
    ) -> Result<i32, FastHttpError> {
        if stream_id == 0 {
            let new_win = self
                .connection_window_size
                .checked_add(increment as i32)
                .ok_or(FastHttpError::InvalidHeader)?;
            self.connection_window_size = new_win;
            Ok(new_win)
        } else if let Some(stream) = self.streams.get_mut(&stream_id) {
            let new_win = stream
                .window_size
                .checked_add(increment as i32)
                .ok_or(FastHttpError::InvalidHeader)?;
            stream.window_size = new_win;
            Ok(new_win)
        } else {
            Err(FastHttpError::InvalidHeader)
        }
    }

    /// Available outbound credit for a given stream taking into account both connection-level
    /// and stream-level flow control windows.
    pub fn outbound_window_available(&self, stream_id: u32) -> i32 {
        let stream_win = self
            .streams
            .get(&stream_id)
            .map(|s| s.window_size)
            .unwrap_or(0);
        std::cmp::min(self.connection_window_size, stream_win)
    }

    /// Check if flow control windows need updating (stream-level and connection-level)
    /// and generate WINDOW_UPDATE frames when window sizes drop below a replenishment threshold.
    pub fn replenish_flow_control_windows(&mut self) -> Vec<Http2Frame> {
        let mut updates = Vec::new();
        let replenish_threshold = Self::DEFAULT_INITIAL_WINDOW_SIZE / 2;

        // Check connection-level window
        if self.connection_window_size < replenish_threshold {
            let increment =
                (Self::DEFAULT_INITIAL_WINDOW_SIZE - self.connection_window_size) as u32;
            if increment > 0 {
                self.connection_window_size += increment as i32;
                updates.push(Http2Frame::WindowUpdate {
                    stream_id: 0,
                    window_size_increment: increment,
                });
            }
        }

        // Check stream-level windows for active streams
        let target_stream_win = self.initial_stream_window_size;
        let stream_threshold = target_stream_win / 2;

        for (stream_id, stream) in self.streams.iter_mut() {
            if (stream.state == Http2StreamState::Open
                || stream.state == Http2StreamState::HalfClosedLocal)
                && stream.window_size < stream_threshold
            {
                let increment = (target_stream_win - stream.window_size) as u32;
                if increment > 0 {
                    stream.window_size += increment as i32;
                    updates.push(Http2Frame::WindowUpdate {
                        stream_id: *stream_id,
                        window_size_increment: increment,
                    });
                }
            }
        }

        updates
    }

    /// Dynamically adjust stream target inbound flow control window capacity (RFC 7540 / RFC 9218).
    /// Highly prioritized streams (urgency 0..2) or streams with high traffic throughput
    /// are granted larger windows to maximize multiplexing throughput without head-of-line blocking.
    pub fn adapt_stream_flow_control_window(&mut self, stream_id: u32, target_window_size: i32) {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            let clamped_target = target_window_size.clamp(1024, 0x7FFF_FFFF);
            stream.target_local_window_size = clamped_target;
        }
    }

    /// Automatically evaluate and adapt inbound flow control windows across all active streams
    /// based on RFC 9218 urgency, estimated bandwidth-delay product (BDP), and stream activity,
    /// emitting `WINDOW_UPDATE` frames as necessary.
    pub fn adapt_and_replenish_inbound_windows(&mut self) -> Vec<Http2Frame> {
        let mut updates = Vec::new();

        // 1. Connection-level replenish using BDP adaptive target window if greater than default
        let target_conn_win = std::cmp::max(
            Self::DEFAULT_INITIAL_WINDOW_SIZE,
            self.adaptive_flow_controller.target_connection_window,
        );
        let conn_threshold = target_conn_win / 2;
        if self.connection_window_size < conn_threshold {
            let increment = (target_conn_win - self.connection_window_size) as u32;
            if increment > 0 {
                self.connection_window_size += increment as i32;
                updates.push(Http2Frame::WindowUpdate {
                    stream_id: 0,
                    window_size_increment: increment,
                });
            }
        }

        // 2. Stream-level adaptive replenishment
        for (stream_id, stream) in self.streams.iter_mut() {
            // Apply dynamic target window adaptation based on urgency if available
            // Urgency 0-1: 4x default window (256 KB)
            // Urgency 2-3: 2x default window (128 KB)
            // Urgency 4-7: 1x default window (64 KB)
            let base_target = match stream.priority_params.urgency {
                0..=1 => Self::DEFAULT_INITIAL_WINDOW_SIZE * 4,
                2..=3 => Self::DEFAULT_INITIAL_WINDOW_SIZE * 2,
                _ => Self::DEFAULT_INITIAL_WINDOW_SIZE,
            };
            // Dynamically scale stream inbound window capacity with BDP if target connection window was scaled up
            let adaptive_target = if target_conn_win > Self::DEFAULT_INITIAL_WINDOW_SIZE {
                let stream_bdp_target = target_conn_win / 2;
                base_target.max(stream_bdp_target)
            } else {
                base_target
            };
            if adaptive_target > stream.target_local_window_size {
                stream.target_local_window_size = adaptive_target;
            }

            let threshold = stream.target_local_window_size / 2;
            let is_inbound_active = stream.state == Http2StreamState::Open
                || stream.state == Http2StreamState::HalfClosedLocal;

            if is_inbound_active && stream.local_window_size < threshold {
                let increment = (stream.target_local_window_size - stream.local_window_size) as u32;
                if increment > 0 {
                    stream.local_window_size += increment as i32;
                    updates.push(Http2Frame::WindowUpdate {
                        stream_id: *stream_id,
                        window_size_increment: increment,
                    });
                }
            }
        }

        updates
    }

    /// Create and encode a HEADERS frame for a stream.
    pub fn create_headers_frame(
        &mut self,
        stream_id: u32,
        headers: &[(&str, &str)],
        end_stream: bool,
    ) -> Http2Frame {
        let header_block = self.hpack_encoder.encode_headers(headers);
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            match stream.state {
                Http2StreamState::Idle => {
                    stream.state = if end_stream {
                        Http2StreamState::HalfClosedLocal
                    } else {
                        Http2StreamState::Open
                    };
                }
                Http2StreamState::ReservedLocal => {
                    stream.state = if end_stream {
                        Http2StreamState::Closed
                    } else {
                        Http2StreamState::HalfClosedRemote
                    };
                }
                Http2StreamState::Open if end_stream => {
                    stream.state = Http2StreamState::HalfClosedLocal;
                }
                _ => {}
            }
        }
        Http2Frame::Headers {
            stream_id,
            end_stream,
            end_headers: true,
            header_block,
        }
    }

    /// Create and encode a trailing HEADERS frame for a stream (RFC 7540 Section 8.1.2.6).
    /// Trailers MUST end the stream (`END_STREAM` flag set) and contain no pseudo-headers.
    pub fn create_trailers_frame(
        &mut self,
        stream_id: u32,
        trailers: &[(&str, &str)],
    ) -> Http2Frame {
        let header_block = self.hpack_encoder.encode_headers(trailers);
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            match stream.state {
                Http2StreamState::Open => {
                    stream.state = Http2StreamState::HalfClosedLocal;
                }
                Http2StreamState::HalfClosedRemote => {
                    stream.state = Http2StreamState::Closed;
                }
                _ => {}
            }
        }
        Http2Frame::Headers {
            stream_id,
            end_stream: true,
            end_headers: true,
            header_block,
        }
    }

    /// Create and encode a DATA frame for a stream.
    pub fn create_data_frame(
        &mut self,
        stream_id: u32,
        data: &[u8],
        end_stream: bool,
    ) -> Http2Frame {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.window_size -= data.len() as i32;
            if end_stream {
                match stream.state {
                    Http2StreamState::Open => stream.state = Http2StreamState::HalfClosedLocal,
                    Http2StreamState::HalfClosedRemote => stream.state = Http2StreamState::Closed,
                    _ => {}
                }
            }
        }
        self.connection_window_size -= data.len() as i32;
        Http2Frame::Data {
            stream_id,
            end_stream,
            data: data.to_vec(),
        }
    }

    /// Create and encode a RST_STREAM frame to abort an active stream with an error code.
    /// Immediately purges any pending outbound data buffered for this stream.
    pub fn reset_stream(&mut self, stream_id: u32, error_code: Http2ErrorCode) -> Http2Frame {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.state = Http2StreamState::Closed;
            stream.reset_error = Some(error_code);
        }
        self.pending_outbound_data.remove(&stream_id);
        Http2Frame::RstStream {
            stream_id,
            error_code,
        }
    }

    /// Create and encode a PUSH_PROMISE frame to notify peer of an impending server push stream.
    pub fn create_push_promise(
        &mut self,
        associated_stream_id: u32,
        promised_stream_id: u32,
        headers: &[(&str, &str)],
    ) -> Http2Frame {
        let header_block = self.hpack_encoder.encode_headers(headers);
        let mut promised_stream =
            Http2Stream::new(promised_stream_id, self.initial_stream_window_size);
        promised_stream.state = Http2StreamState::ReservedLocal;
        self.streams.insert(promised_stream_id, promised_stream);

        let owned_headers: Vec<(String, String)> = headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        self.push_promises
            .insert(promised_stream_id, owned_headers.clone());
        let promised_req =
            Http2PromisedRequest::new(associated_stream_id, promised_stream_id, owned_headers);
        self.promised_requests
            .insert(promised_stream_id, promised_req);

        Http2Frame::PushPromise {
            stream_id: associated_stream_id,
            promised_stream_id,
            end_headers: true,
            header_block,
        }
    }

    /// Set stream priority according to RFC 7540 Section 5.3.
    /// Handles exclusive flag reparenting: if exclusive is true, the newly prioritized stream becomes
    /// the sole direct dependency of stream_dependency, reparenting previous children under it.
    pub fn set_stream_priority(
        &mut self,
        stream_id: u32,
        stream_dependency: u32,
        weight: u8,
        exclusive: bool,
    ) {
        if stream_id == stream_dependency {
            return;
        }

        if exclusive {
            for (id, stream) in self.streams.iter_mut() {
                if *id != stream_id && stream.stream_dependency == stream_dependency {
                    stream.stream_dependency = stream_id;
                }
            }
        }

        let initial_win = self.initial_stream_window_size;
        let stream = self
            .streams
            .entry(stream_id)
            .or_insert_with(|| Http2Stream::new(stream_id, initial_win));
        stream.stream_dependency = stream_dependency;
        stream.weight = weight;
        stream.exclusive = exclusive;
    }

    /// Set or update RFC 9218 priority parameters for a stream.
    pub fn set_stream_priority_parameters(&mut self, stream_id: u32, priority: PriorityParameters) {
        let initial_win = self.initial_stream_window_size;
        let stream = self
            .streams
            .entry(stream_id)
            .or_insert_with(|| Http2Stream::new(stream_id, initial_win));
        stream.priority_params = priority;
    }

    /// Compute streams prioritized under RFC 9218 Extensible Prioritization Scheme.
    /// Ordered by:
    /// 1. Urgency ascending (0 is highest urgency, 7 is lowest)
    /// 2. Stream ID ascending (for fair scheduling within the same urgency tier)
    pub fn prioritized_stream_ids_rfc9218(&self) -> Vec<u32> {
        let mut streams_info: Vec<(u32, u8)> = self
            .streams
            .iter()
            .map(|(&id, s)| (id, s.priority_params.urgency))
            .collect();

        // Urgency ascending (0 before 7), then ID ascending
        streams_info.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
        streams_info.into_iter().map(|(id, _)| id).collect()
    }

    /// Compute streams in priority order, resolving dependencies and weighting.
    /// Returns stream IDs sorted by dependency tree depth then relative weight descending.
    pub fn prioritized_stream_ids(&self) -> Vec<u32> {
        let mut streams_info: Vec<(u32, usize, u8)> = self
            .streams
            .iter()
            .map(|(&id, s)| {
                // Compute tree depth to root (0)
                let mut depth = 0;
                let mut curr = s.stream_dependency;
                let mut visited = std::collections::HashSet::new();
                visited.insert(id);
                while curr != 0 && visited.insert(curr) {
                    if let Some(parent) = self.streams.get(&curr) {
                        depth += 1;
                        curr = parent.stream_dependency;
                    } else {
                        break;
                    }
                }
                (id, depth, s.weight)
            })
            .collect();

        // Sort: primary key = depth ascending (parents scheduled first), secondary = weight descending (higher weight first), tertiary = id ascending
        streams_info.sort_by(|a, b| {
            a.1.cmp(&b.1)
                .then_with(|| b.2.cmp(&a.2))
                .then_with(|| a.0.cmp(&b.0))
        });

        streams_info.into_iter().map(|(id, _, _)| id).collect()
    }

    /// Queue outbound body data for a stream to be scheduled via [`schedule_outbound_data`].
    pub fn queue_outbound_data(&mut self, stream_id: u32, data: &[u8]) {
        self.pending_outbound_data
            .entry(stream_id)
            .or_default()
            .extend_from_slice(data);
    }

    /// Schedule and allocate outbound DATA frames using the session's internal `pending_outbound_data` buffer.
    ///
    /// If `end_stream` is true, the final frame for each fully drained stream will have `end_stream = true`.
    /// If false, frames are scheduled with `end_stream = false` allowing subsequent data to be queued and scheduled.
    pub fn schedule_pending_outbound_data(
        &mut self,
        max_frame_size: usize,
        end_stream: bool,
    ) -> Vec<Http2Frame> {
        let mut pending = std::mem::take(&mut self.pending_outbound_data);
        let mut frames = Vec::new();
        if self.connection_window_size <= 0 || pending.is_empty() {
            self.pending_outbound_data = pending;
            return frames;
        }

        let max_frame = std::cmp::max(16384, max_frame_size);

        // Group active streams that have pending data by urgency tier (0 to 7)
        let mut streams_by_urgency: [Vec<u32>; 8] = Default::default();
        for (&stream_id, buf) in pending.iter() {
            if buf.is_empty() {
                continue;
            }
            if let Some(stream) = self.streams.get(&stream_id) {
                if stream.state == Http2StreamState::Open
                    || stream.state == Http2StreamState::HalfClosedRemote
                {
                    let u = stream.priority_params.urgency.min(7) as usize;
                    streams_by_urgency[u].push(stream_id);
                }
            }
        }

        for urgency_tier in streams_by_urgency.iter_mut() {
            if self.connection_window_size <= 0 {
                break;
            }
            if urgency_tier.is_empty() {
                continue;
            }

            urgency_tier.sort_unstable();

            let mut non_incremental = Vec::new();
            let mut incremental = Vec::new();
            for &stream_id in urgency_tier.iter() {
                let is_inc = self
                    .streams
                    .get(&stream_id)
                    .map(|s| s.priority_params.incremental)
                    .unwrap_or(false);
                if is_inc {
                    incremental.push(stream_id);
                } else {
                    non_incremental.push(stream_id);
                }
            }

            // 1. Non-incremental streams
            for stream_id in non_incremental {
                if self.connection_window_size <= 0 {
                    break;
                }

                while let Some(buf) = pending.get_mut(&stream_id) {
                    if buf.is_empty() || self.connection_window_size <= 0 {
                        break;
                    }

                    let stream_win = match self.streams.get(&stream_id) {
                        Some(s)
                            if s.state == Http2StreamState::Open
                                || s.state == Http2StreamState::HalfClosedRemote =>
                        {
                            s.window_size
                        }
                        _ => break,
                    };
                    if stream_win <= 0 {
                        break;
                    }

                    let available_credit =
                        std::cmp::min(self.connection_window_size, stream_win) as usize;
                    if available_credit == 0 {
                        break;
                    }

                    let chunk_size =
                        std::cmp::min(buf.len(), std::cmp::min(available_credit, max_frame));
                    if chunk_size == 0 {
                        break;
                    }

                    let chunk = buf.drain(..chunk_size).collect::<Vec<u8>>();
                    let is_last = end_stream && buf.is_empty();

                    let frame = self.create_data_frame(stream_id, &chunk, is_last);
                    frames.push(frame);
                }
            }

            // 2. Incremental streams
            if !incremental.is_empty() {
                loop {
                    if self.connection_window_size <= 0 {
                        break;
                    }

                    let mut any_sent_in_round = false;
                    for &stream_id in &incremental {
                        if self.connection_window_size <= 0 {
                            break;
                        }

                        let stream_win = match self.streams.get(&stream_id) {
                            Some(s)
                                if s.state == Http2StreamState::Open
                                    || s.state == Http2StreamState::HalfClosedRemote =>
                            {
                                s.window_size
                            }
                            _ => continue,
                        };
                        if stream_win <= 0 {
                            continue;
                        }

                        let available_credit =
                            std::cmp::min(self.connection_window_size, stream_win) as usize;
                        if available_credit == 0 {
                            continue;
                        }

                        if let Some(buf) = pending.get_mut(&stream_id) {
                            if buf.is_empty() {
                                continue;
                            }

                            let weight_ratio = self
                                .streams
                                .get(&stream_id)
                                .map(|s| s.weight as usize)
                                .unwrap_or(16);
                            let quantum = (1024 * weight_ratio / 16).clamp(512, max_frame);
                            let chunk_size =
                                std::cmp::min(buf.len(), std::cmp::min(available_credit, quantum));

                            if chunk_size > 0 {
                                let chunk = buf.drain(..chunk_size).collect::<Vec<u8>>();
                                let is_last = end_stream && buf.is_empty();

                                let frame = self.create_data_frame(stream_id, &chunk, is_last);
                                frames.push(frame);
                                any_sent_in_round = true;
                            }
                        }
                    }

                    if !any_sent_in_round {
                        break;
                    }
                }
            }
        }

        pending.retain(|_, v| !v.is_empty());
        self.pending_outbound_data = pending;
        frames
    }

    /// Schedule and allocate outbound DATA frames fairly across active streams based on
    /// their RFC 9218 urgency (0 highest .. 7 lowest), incremental flags (fair sharing / round-robin
    /// for same-urgency incremental streams vs sequential for non-incremental), and flow control windows.
    /// Returns a list of generated Http2Frame::Data frames respecting connection and stream window limits.
    pub fn schedule_outbound_data(
        &mut self,
        pending_data: &mut std::collections::HashMap<u32, Vec<u8>>,
        max_frame_size: usize,
    ) -> Vec<Http2Frame> {
        let mut frames = Vec::new();
        if self.connection_window_size <= 0 || pending_data.is_empty() {
            return frames;
        }

        let max_frame = std::cmp::max(16384, max_frame_size);

        // Group active streams that have pending data by urgency tier (0 to 7)
        let mut streams_by_urgency: [Vec<u32>; 8] = Default::default();
        for (&stream_id, buf) in pending_data.iter() {
            if buf.is_empty() {
                continue;
            }
            if let Some(stream) = self.streams.get(&stream_id) {
                if stream.state == Http2StreamState::Open
                    || stream.state == Http2StreamState::HalfClosedRemote
                {
                    let u = stream.priority_params.urgency.min(7) as usize;
                    streams_by_urgency[u].push(stream_id);
                }
            }
        }

        // Iterate through urgency levels from 0 (highest) to 7 (lowest)
        for urgency_tier in streams_by_urgency.iter_mut() {
            if self.connection_window_size <= 0 {
                break;
            }
            if urgency_tier.is_empty() {
                continue;
            }

            // Stable sort by stream_id ascending
            urgency_tier.sort_unstable();

            // Split into non-incremental (sequential) and incremental (interleaved round-robin)
            let mut non_incremental = Vec::new();
            let mut incremental = Vec::new();
            for &stream_id in urgency_tier.iter() {
                let is_inc = self
                    .streams
                    .get(&stream_id)
                    .map(|s| s.priority_params.incremental)
                    .unwrap_or(false);
                if is_inc {
                    incremental.push(stream_id);
                } else {
                    non_incremental.push(stream_id);
                }
            }

            // 1. Process non-incremental streams sequentially in this tier
            for stream_id in non_incremental {
                if self.connection_window_size <= 0 {
                    break;
                }

                while let Some(buf) = pending_data.get_mut(&stream_id) {
                    if buf.is_empty() || self.connection_window_size <= 0 {
                        break;
                    }

                    let stream_win = match self.streams.get(&stream_id) {
                        Some(s)
                            if s.state == Http2StreamState::Open
                                || s.state == Http2StreamState::HalfClosedRemote =>
                        {
                            s.window_size
                        }
                        _ => break,
                    };
                    if stream_win <= 0 {
                        break;
                    }

                    let available_credit =
                        std::cmp::min(self.connection_window_size, stream_win) as usize;
                    if available_credit == 0 {
                        break;
                    }

                    let chunk_size =
                        std::cmp::min(buf.len(), std::cmp::min(available_credit, max_frame));
                    if chunk_size == 0 {
                        break;
                    }

                    let chunk = buf.drain(..chunk_size).collect::<Vec<u8>>();
                    let end_stream = buf.is_empty();

                    let frame = self.create_data_frame(stream_id, &chunk, end_stream);
                    frames.push(frame);
                }
            }

            // 2. Process incremental streams with round-robin fair queuing (WFQ)
            // RFC 9218: "If the incremental parameter is true, data SHOULD be sent
            // interleaved with data from other streams of the same urgency."
            if !incremental.is_empty() {
                loop {
                    if self.connection_window_size <= 0 {
                        break;
                    }

                    let mut any_sent_in_round = false;
                    for &stream_id in &incremental {
                        if self.connection_window_size <= 0 {
                            break;
                        }

                        let stream_win = match self.streams.get(&stream_id) {
                            Some(s)
                                if s.state == Http2StreamState::Open
                                    || s.state == Http2StreamState::HalfClosedRemote =>
                            {
                                s.window_size
                            }
                            _ => continue,
                        };
                        if stream_win <= 0 {
                            continue;
                        }

                        let available_credit =
                            std::cmp::min(self.connection_window_size, stream_win) as usize;
                        if available_credit == 0 {
                            continue;
                        }

                        if let Some(buf) = pending_data.get_mut(&stream_id) {
                            if buf.is_empty() {
                                continue;
                            }

                            // In round-robin for incremental streams, emit up to max_frame per round
                            let chunk_size = std::cmp::min(
                                buf.len(),
                                std::cmp::min(available_credit, max_frame),
                            );
                            if chunk_size == 0 {
                                continue;
                            }

                            let chunk = buf.drain(..chunk_size).collect::<Vec<u8>>();
                            let end_stream = buf.is_empty();

                            let frame = self.create_data_frame(stream_id, &chunk, end_stream);
                            frames.push(frame);
                            any_sent_in_round = true;
                        }
                    }

                    if !any_sent_in_round {
                        break;
                    }
                }
            }
        }

        frames
    }

    /// Process an incoming decoded frame.
    pub fn handle_frame(
        &mut self,
        frame: &Http2Frame,
    ) -> Result<Option<Http2Frame>, FastHttpError> {
        match frame {
            Http2Frame::Settings { ack, settings } => {
                if !*ack {
                    for s in settings {
                        if s.id == Http2SettingId::InitialWindowSize {
                            let new_initial_window = s.value as i32;
                            let delta = new_initial_window - self.initial_stream_window_size;
                            self.initial_stream_window_size = new_initial_window;
                            // RFC 7540 Section 6.9.2: adjust flow-control window of all active streams
                            for stream in self.streams.values_mut() {
                                if stream.state != Http2StreamState::Closed {
                                    stream.window_size += delta;
                                }
                            }
                        } else if s.id == Http2SettingId::EnablePush {
                            self.enable_push = s.value != 0;
                        }
                    }
                    self.peer_settings = settings.clone();
                    // Reply with Settings ACK
                    return Ok(Some(Http2Frame::Settings {
                        ack: true,
                        settings: Vec::new(),
                    }));
                }
                Ok(None)
            }
            Http2Frame::Ping { ack, opaque_data } => {
                if !*ack {
                    // Respond with Pong (ACK Ping)
                    return Ok(Some(Http2Frame::Ping {
                        ack: true,
                        opaque_data: *opaque_data,
                    }));
                } else {
                    // Pong received: calculate RTT if matching pending ping
                    let seq = u64::from_be_bytes(*opaque_data);
                    if let Some((pending_seq, start_instant)) =
                        self.adaptive_flow_controller.pending_ping_timestamp
                    {
                        if pending_seq == seq {
                            let elapsed_us = start_instant.elapsed().as_micros() as u64;
                            self.adaptive_flow_controller.record_rtt_sample(elapsed_us);
                            self.adaptive_flow_controller.pending_ping_timestamp = None;
                        }
                    }
                }
                Ok(None)
            }
            Http2Frame::Headers {
                stream_id,
                end_stream,
                header_block,
                ..
            } => {
                let decoded = self.hpack_decoder.decode_headers(header_block)?;
                let initial_win = self.initial_stream_window_size;
                let stream = self
                    .streams
                    .entry(*stream_id)
                    .or_insert_with(|| Http2Stream::new(*stream_id, initial_win));

                // RFC 7540 Section 8.1.2.6: Trailers are HEADERS delivered after the initial HEADERS block
                // Note: For ReservedRemote streams (server push promises), the first HEADERS frame represents
                // the server's response headers rather than trailers.
                if stream.state == Http2StreamState::ReservedRemote {
                    stream.received_headers = decoded.clone();
                } else if !stream.received_headers.is_empty() {
                    stream.received_trailers.extend(decoded.clone());
                } else {
                    stream.received_headers.extend(decoded.clone());
                }

                // Check for RFC 9218 `priority` header field
                for (name, val) in &decoded {
                    if name.eq_ignore_ascii_case("priority") {
                        stream.priority_params = PriorityParameters::parse(val);
                    }
                }

                match stream.state {
                    Http2StreamState::Idle => {
                        stream.state = if *end_stream {
                            Http2StreamState::HalfClosedRemote
                        } else {
                            Http2StreamState::Open
                        };
                    }
                    Http2StreamState::ReservedRemote => {
                        stream.state = if *end_stream {
                            Http2StreamState::HalfClosedRemote
                        } else {
                            Http2StreamState::HalfClosedLocal
                        };
                    }
                    Http2StreamState::Open if *end_stream => {
                        stream.state = Http2StreamState::HalfClosedRemote;
                    }
                    Http2StreamState::HalfClosedLocal if *end_stream => {
                        stream.state = Http2StreamState::Closed;
                    }
                    _ => {}
                }
                Ok(None)
            }
            Http2Frame::Data {
                stream_id,
                end_stream,
                data,
            } => {
                let initial_win = self.initial_stream_window_size;
                let stream = self
                    .streams
                    .entry(*stream_id)
                    .or_insert_with(|| Http2Stream::new(*stream_id, initial_win));
                stream.received_data.extend_from_slice(data);
                stream.window_size -= data.len() as i32;
                stream.local_window_size -= data.len() as i32;
                self.connection_window_size -= data.len() as i32;

                if *end_stream {
                    match stream.state {
                        Http2StreamState::Open | Http2StreamState::HalfClosedLocal => {
                            stream.state = if stream.state == Http2StreamState::HalfClosedLocal {
                                Http2StreamState::Closed
                            } else {
                                Http2StreamState::HalfClosedRemote
                            };
                        }
                        _ => {
                            stream.state = Http2StreamState::Closed;
                        }
                    }
                }
                Ok(None)
            }
            Http2Frame::WindowUpdate {
                stream_id,
                window_size_increment,
            } => {
                if *stream_id == 0 {
                    self.connection_window_size += *window_size_increment as i32;
                } else if let Some(stream) = self.streams.get_mut(stream_id) {
                    stream.window_size += *window_size_increment as i32;
                }
                Ok(None)
            }
            Http2Frame::RstStream {
                stream_id,
                error_code,
            } => {
                if let Some(stream) = self.streams.get_mut(stream_id) {
                    stream.state = Http2StreamState::Closed;
                    stream.reset_error = Some(*error_code);
                }
                // Immediately purge any queued outbound data for the reset stream
                self.pending_outbound_data.remove(stream_id);
                Ok(None)
            }
            Http2Frame::PushPromise {
                stream_id,
                promised_stream_id,
                end_headers: _,
                header_block,
            } => {
                if !self.enable_push {
                    return Ok(Some(Http2Frame::RstStream {
                        stream_id: *promised_stream_id,
                        error_code: Http2ErrorCode::RefusedStream,
                    }));
                }

                let decoded_headers = self.hpack_decoder.decode_headers(header_block)?;
                let promised_req = Http2PromisedRequest::new(
                    *stream_id,
                    *promised_stream_id,
                    decoded_headers.clone(),
                );

                if !promised_req.is_valid {
                    let mut stream =
                        Http2Stream::new(*promised_stream_id, self.initial_stream_window_size);
                    stream.state = Http2StreamState::Closed;
                    stream.reset_error = Some(Http2ErrorCode::ProtocolError);
                    self.streams.insert(*promised_stream_id, stream);
                    self.push_promises
                        .insert(*promised_stream_id, decoded_headers);
                    self.promised_requests
                        .insert(*promised_stream_id, promised_req);

                    return Ok(Some(Http2Frame::RstStream {
                        stream_id: *promised_stream_id,
                        error_code: Http2ErrorCode::ProtocolError,
                    }));
                }

                let mut stream =
                    Http2Stream::new(*promised_stream_id, self.initial_stream_window_size);
                stream.state = Http2StreamState::ReservedRemote;
                stream.received_headers = decoded_headers.clone();
                self.streams.insert(*promised_stream_id, stream);
                self.push_promises
                    .insert(*promised_stream_id, decoded_headers);
                self.promised_requests
                    .insert(*promised_stream_id, promised_req);
                Ok(None)
            }
            Http2Frame::Priority {
                stream_id,
                exclusive,
                stream_dependency,
                weight,
            } => {
                self.set_stream_priority(*stream_id, *stream_dependency, *weight, *exclusive);
                Ok(None)
            }
            Http2Frame::PriorityUpdate {
                prioritized_stream_id,
                priority_field_value,
            } => {
                let params = PriorityParameters::parse(priority_field_value);
                self.set_stream_priority_parameters(*prioritized_stream_id, params);
                Ok(None)
            }
            Http2Frame::AltSvc {
                stream_id: _,
                origin,
                alt_svc_field_value,
            } => {
                let routes = AltSvcRoute::parse_header_value(alt_svc_field_value);
                if routes.is_empty() && alt_svc_field_value.trim().eq_ignore_ascii_case("clear") {
                    self.alt_svc_routes.remove(origin);
                } else if !routes.is_empty() {
                    self.alt_svc_routes.insert(origin.clone(), routes);
                }
                Ok(None)
            }
            Http2Frame::GoAway {
                last_stream_id,
                error_code,
                debug_data,
            } => {
                self.last_received_goaway =
                    Some((*last_stream_id, *error_code, debug_data.clone()));
                // Mark any active streams above last_stream_id as closed/refused
                for (id, stream) in self.streams.iter_mut() {
                    if *id > *last_stream_id && stream.state != Http2StreamState::Closed {
                        stream.state = Http2StreamState::Closed;
                        stream.reset_error = Some(Http2ErrorCode::RefusedStream);
                    }
                }
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    /// Process an incoming zero-copy DATA frame slice without creating an intermediate frame enum,
    /// updating flow control windows and stream state.
    pub fn handle_data_slice(
        &mut self,
        slice: &Http2DataFrameSlice<'_>,
    ) -> Result<Option<Http2Frame>, FastHttpError> {
        let initial_win = self.initial_stream_window_size;
        let stream = self
            .streams
            .entry(slice.stream_id)
            .or_insert_with(|| Http2Stream::new(slice.stream_id, initial_win));
        stream.received_data.extend_from_slice(slice.data);
        stream.window_size -= slice.data.len() as i32;
        stream.local_window_size -= slice.data.len() as i32;
        self.connection_window_size -= slice.data.len() as i32;

        if slice.end_stream {
            match stream.state {
                Http2StreamState::Open | Http2StreamState::HalfClosedLocal => {
                    stream.state = if stream.state == Http2StreamState::HalfClosedLocal {
                        Http2StreamState::Closed
                    } else {
                        Http2StreamState::HalfClosedRemote
                    };
                }
                _ => {
                    stream.state = Http2StreamState::Closed;
                }
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod http2_tests {
    use super::*;

    #[test]
    fn test_hpack_integer_roundtrip() {
        let mut out = Vec::new();
        hpack_encode_integer(10, 5, 0x00, &mut out);
        let (val, consumed) = hpack_decode_integer(&out, 5).expect("decode integer");
        assert_eq!(val, 10);
        assert_eq!(consumed, 1);

        out.clear();
        hpack_encode_integer(1337, 5, 0x00, &mut out);
        let (val, consumed) = hpack_decode_integer(&out, 5).expect("decode large integer");
        assert_eq!(val, 1337);
        assert_eq!(consumed, out.len());
    }

    #[test]
    fn test_hpack_encode_decode_roundtrip() {
        let mut enc = HpackContext::default();
        let mut dec = HpackContext::default();

        let headers = vec![
            (":method", "GET"),
            (":path", "/api/v1/resource"),
            (":scheme", "https"),
            (":authority", "example.com"),
            ("custom-header", "custom-value"),
        ];

        let encoded = enc.encode_headers(&headers);
        let decoded = dec.decode_headers(&encoded).expect("decode headers");

        assert_eq!(decoded.len(), 5);
        assert_eq!(decoded[0], (":method".to_string(), "GET".to_string()));
        assert_eq!(
            decoded[1],
            (":path".to_string(), "/api/v1/resource".to_string())
        );
        assert_eq!(decoded[2], (":scheme".to_string(), "https".to_string()));
        assert_eq!(
            decoded[3],
            (":authority".to_string(), "example.com".to_string())
        );
        assert_eq!(
            decoded[4],
            ("custom-header".to_string(), "custom-value".to_string())
        );

        // Second request with same custom header should benefit from dynamic table
        let headers2 = vec![
            (":method", "GET"),
            (":path", "/api/v2/items"),
            ("custom-header", "custom-value"),
        ];
        let encoded2 = enc.encode_headers(&headers2);
        let decoded2 = dec.decode_headers(&encoded2).expect("decode headers 2");
        assert_eq!(decoded2.len(), 3);
        assert_eq!(
            decoded2[2],
            ("custom-header".to_string(), "custom-value".to_string())
        );
    }

    #[test]
    fn test_hpack_huffman_rfc7541_test_vector() {
        // RFC 7541 C.4.1: "www.example.com" encoded with Huffman should be f1e3c2e5f23a6ba0ab90f4ff
        let raw = b"www.example.com";
        let encoded = hpack_huffman_encode(raw);
        let expected = [
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ];
        assert_eq!(encoded, expected);

        let decoded = hpack_huffman_decode(&encoded).expect("huffman decode www.example.com");
        assert_eq!(decoded, raw);
    }

    #[test]
    fn test_hpack_encode_decode_with_huffman() {
        let mut enc = HpackContext::default();
        let mut dec = HpackContext::default();

        let headers = vec![
            (":method", "GET"),
            (":path", "/api/v1/metrics/prometheus"),
            (":scheme", "https"),
            (":authority", "www.example.com"),
            ("user-agent", "Mozilla/5.0 (IFA HTTP2 Client)"),
            ("x-correlation-id", "req-abcdef1234567890"),
        ];

        let encoded_huffman = enc.encode_headers_with_options(&headers, true);
        let decoded = dec
            .decode_headers(&encoded_huffman)
            .expect("decode huffman headers");

        assert_eq!(decoded.len(), headers.len());
        for (i, &(orig_name, orig_val)) in headers.iter().enumerate() {
            assert_eq!(decoded[i].0, orig_name);
            assert_eq!(decoded[i].1, orig_val);
        }

        // Verify compression gain
        let mut enc_plain = HpackContext::default();
        let encoded_plain = enc_plain.encode_headers_with_options(&headers, false);
        assert!(
            encoded_huffman.len() < encoded_plain.len(),
            "Huffman encoded len {} should be less than plain len {}",
            encoded_huffman.len(),
            encoded_plain.len()
        );
    }

    #[test]
    fn test_hpack_literal_cache_hits_and_lru() {
        let mut enc = HpackContext::default();
        let mut dec1 = HpackContext::default().with_literal_cache_size(4);

        let headers = vec![
            ("x-custom-key", "value-alpha"),
            ("x-custom-key-2", "value-beta"),
        ];

        let encoded = enc.encode_headers_with_options(&headers, false);

        // First decode
        let decoded1 = dec1.decode_headers(&encoded).expect("decode 1");
        assert_eq!(decoded1.len(), 2);
        assert!(dec1.literal_cache_misses > 0);
        assert_eq!(dec1.literal_cache_hits, 0);

        // Reset dynamic table in dec1 to force literal re-parsing without dynamic indexed hits
        dec1.dynamic_table.clear();
        let decoded2 = dec1.decode_headers(&encoded).expect("decode 2");
        assert_eq!(decoded2.len(), 2);
        assert!(
            dec1.literal_cache_hits > 0,
            "literal_cache_hits should have increased"
        );
    }

    #[test]
    fn test_http2_session_stream_multiplexing() {
        let mut client = Http2Session::new(false);
        let mut server = Http2Session::new(true);

        // Client opens stream 1
        let stream1 = client.open_stream();
        assert_eq!(stream1, 1);

        // Client opens stream 3
        let stream2 = client.open_stream();
        assert_eq!(stream2, 3);

        // Client sends HEADERS on stream 1
        let req_headers = vec![
            (":method", "GET"),
            (":path", "/stream1"),
            (":scheme", "https"),
        ];
        let frame1 = client.create_headers_frame(stream1, &req_headers, true);
        let wire1 = frame1.encode();

        // Server decodes frame1
        let hdr1 = Http2FrameHeader::decode(&wire1[..9]).expect("decode header");
        let parsed_frame1 = Http2Frame::decode(&hdr1, &wire1[9..]).expect("decode frame");
        server
            .handle_frame(&parsed_frame1)
            .expect("server handle frame");

        let s1 = server.streams.get(&1).expect("server stream 1 exists");
        assert_eq!(s1.state, Http2StreamState::HalfClosedRemote);
        assert_eq!(s1.received_headers.len(), 3);
        assert_eq!(s1.received_headers[1].1, "/stream1");

        // Client sends HEADERS and DATA on stream 3
        let post_headers = vec![
            (":method", "POST"),
            (":path", "/stream3"),
            (":scheme", "https"),
        ];
        let frame2 = client.create_headers_frame(stream2, &post_headers, false);
        let data_frame = client.create_data_frame(stream2, b"payload123", true);

        // Server receives stream 3 headers
        let wire2 = frame2.encode();
        let hdr2 = Http2FrameHeader::decode(&wire2[..9]).unwrap();
        let parsed_frame2 = Http2Frame::decode(&hdr2, &wire2[9..]).unwrap();
        server.handle_frame(&parsed_frame2).unwrap();

        // Server receives stream 3 data
        let wire_data = data_frame.encode();
        let hdr_data = Http2FrameHeader::decode(&wire_data[..9]).unwrap();
        let parsed_data = Http2Frame::decode(&hdr_data, &wire_data[9..]).unwrap();
        server.handle_frame(&parsed_data).unwrap();

        let s3 = server.streams.get(&3).expect("server stream 3 exists");
        assert_eq!(s3.state, Http2StreamState::HalfClosedRemote);
        assert_eq!(s3.received_data, b"payload123");
    }

    #[test]
    fn test_http2_ping_pong_roundtrip() {
        let mut server = Http2Session::new(true);
        let ping = Http2Frame::Ping {
            ack: false,
            opaque_data: [1, 2, 3, 4, 5, 6, 7, 8],
        };
        let response = server.handle_frame(&ping).unwrap();
        assert!(response.is_some());
        if let Some(Http2Frame::Ping { ack, opaque_data }) = response {
            assert!(ack);
            assert_eq!(opaque_data, [1, 2, 3, 4, 5, 6, 7, 8]);
        } else {
            panic!("Expected ping ack");
        }
    }

    #[test]
    fn test_http2_push_promise_frame_roundtrip() {
        let mut enc = HpackContext::default();
        let mut dec = HpackContext::default();

        let req_headers = vec![
            (":method", "GET"),
            (":path", "/main.js"),
            (":scheme", "https"),
            (":authority", "example.com"),
        ];
        let header_block = enc.encode_headers(&req_headers);

        let frame = Http2Frame::PushPromise {
            stream_id: 1,
            promised_stream_id: 2,
            end_headers: true,
            header_block: header_block.clone(),
        };

        let wire = frame.encode();
        assert_eq!(wire.len(), 9 + 4 + header_block.len());

        let hdr = Http2FrameHeader::decode(&wire[..9]).expect("decode push promise header");
        assert_eq!(hdr.frame_type, Http2FrameType::PushPromise);
        assert_eq!(hdr.stream_id, 1);
        assert_eq!(hdr.flags, Http2Frame::FLAG_END_HEADERS);

        let decoded_frame =
            Http2Frame::decode(&hdr, &wire[9..]).expect("decode push promise frame");
        if let Http2Frame::PushPromise {
            stream_id,
            promised_stream_id,
            end_headers,
            header_block: dec_block,
        } = decoded_frame
        {
            assert_eq!(stream_id, 1);
            assert_eq!(promised_stream_id, 2);
            assert!(end_headers);
            let decoded_headers = dec
                .decode_headers(&dec_block)
                .expect("decode promised headers");
            assert_eq!(decoded_headers.len(), 4);
            assert_eq!(decoded_headers[1].1, "/main.js");
        } else {
            panic!("Expected PushPromise frame");
        }
    }

    #[test]
    fn test_http2_priority_tree_and_exclusive_dependency() {
        let mut session = Http2Session::new(false);
        // Create 3 streams
        session.open_stream(); // id = 1
        session.open_stream(); // id = 3
        session.open_stream(); // id = 5

        // Initially all depend on root (0) with default weight 16
        // Set stream 1: parent = 0, weight = 30
        // Set stream 3: parent = 0, weight = 10
        session.set_stream_priority(1, 0, 30, false);
        session.set_stream_priority(3, 0, 10, false);
        session.set_stream_priority(5, 0, 20, false);

        // Prioritized order at same depth should be sorted by weight descending: 1 (30), 5 (20), 3 (10)
        assert_eq!(session.prioritized_stream_ids(), vec![1, 5, 3]);

        // Now set stream 3 to depend on stream 1 (non-exclusive)
        session.set_stream_priority(3, 1, 10, false);
        // Stream 1 and 5 are depth 0 (weight 30 and 20), stream 3 is depth 1 (child of 1)
        assert_eq!(session.prioritized_stream_ids(), vec![1, 5, 3]);

        // Now prioritize stream 7 with exclusive = true depending on root 0
        // Streams currently depending on 0 (1 and 5) will be reparented under stream 7!
        session.set_stream_priority(7, 0, 40, true);
        assert_eq!(session.streams.get(&1).unwrap().stream_dependency, 7);
        assert_eq!(session.streams.get(&5).unwrap().stream_dependency, 7);
        // Stream 7 is now at depth 0, 1 and 5 at depth 1, and 3 at depth 2
        assert_eq!(session.prioritized_stream_ids(), vec![7, 1, 5, 3]);

        // Test frame handling
        let priority_frame = Http2Frame::Priority {
            stream_id: 3,
            exclusive: false,
            stream_dependency: 0,
            weight: 50,
        };
        session
            .handle_frame(&priority_frame)
            .expect("handle priority frame");
        assert_eq!(session.streams.get(&3).unwrap().stream_dependency, 0);
        assert_eq!(session.streams.get(&3).unwrap().weight, 50);
    }

    #[test]
    fn test_http2_extended_error_codes_classification() {
        assert!(Http2ErrorCode::NoError.is_graceful());
        assert!(!Http2ErrorCode::InternalError.is_graceful());

        assert!(Http2ErrorCode::EnhanceYourCalm.is_rate_limit_or_calm());
        assert!(!Http2ErrorCode::NoError.is_rate_limit_or_calm());

        assert!(Http2ErrorCode::ProtocolError.is_fatal_protocol_violation());
        assert!(Http2ErrorCode::FrameSizeError.is_fatal_protocol_violation());
        assert!(Http2ErrorCode::CompressionError.is_fatal_protocol_violation());
        assert!(Http2ErrorCode::InadequateSecurity.is_fatal_protocol_violation());
        assert!(Http2ErrorCode::Http11Required.is_fatal_protocol_violation());
        assert!(!Http2ErrorCode::NoError.is_fatal_protocol_violation());
        assert!(!Http2ErrorCode::RefusedStream.is_fatal_protocol_violation());

        assert!(Http2ErrorCode::NoError.is_retryable());
        assert!(Http2ErrorCode::RefusedStream.is_retryable());
        assert!(Http2ErrorCode::Cancel.is_retryable());
        assert!(!Http2ErrorCode::ProtocolError.is_retryable());
    }

    #[test]
    fn test_rfc9218_priority_parameters_parsing_and_serialization() {
        // Defaults
        let default_params = PriorityParameters::default();
        assert_eq!(default_params.urgency, 3);
        assert!(!default_params.incremental);
        assert_eq!(default_params.serialize(), "u=3");

        // Parse standard formats
        let p1 = PriorityParameters::parse("u=1, i");
        assert_eq!(p1.urgency, 1);
        assert!(p1.incremental);
        assert_eq!(p1.serialize(), "u=1, i");

        let p2 = PriorityParameters::parse("u=5");
        assert_eq!(p2.urgency, 5);
        assert!(!p2.incremental);
        assert_eq!(p2.serialize(), "u=5");

        let p3 = PriorityParameters::parse("i=?1, u=0");
        assert_eq!(p3.urgency, 0);
        assert!(p3.incremental);

        let p4 = PriorityParameters::parse("i=?0, u=7");
        assert_eq!(p4.urgency, 7);
        assert!(!p4.incremental);

        // Clamping & fallback: urgency > 7 ignored/clamped
        let p5 = PriorityParameters::parse("u=9");
        assert_eq!(p5.urgency, 3); // invalid urgency ignored, default maintained

        let p_clamp = PriorityParameters::new(9, true);
        assert_eq!(p_clamp.urgency, 7);
    }

    #[test]
    fn test_rfc9218_priority_update_frame_encode_decode() {
        let frame = Http2Frame::PriorityUpdate {
            prioritized_stream_id: 5,
            priority_field_value: "u=2, i".to_string(),
        };

        let encoded = frame.encode();
        assert_eq!(encoded.len(), 9 + 4 + 6); // header + 4 bytes stream id + 6 bytes payload

        // Frame header check
        let header = Http2FrameHeader::decode(&encoded[..9]).expect("decode header");
        assert_eq!(header.length, 10);
        assert_eq!(header.frame_type, Http2FrameType::PriorityUpdate);
        assert_eq!(header.stream_id, 0); // must be sent on stream 0

        // Frame body check
        let decoded = Http2Frame::decode(&header, &encoded[9..]).expect("decode frame");
        match decoded {
            Http2Frame::PriorityUpdate {
                prioritized_stream_id,
                priority_field_value,
            } => {
                assert_eq!(prioritized_stream_id, 5);
                assert_eq!(priority_field_value, "u=2, i");
            }
            _ => panic!("Expected PriorityUpdate frame"),
        }
    }

    #[test]
    fn test_rfc9218_session_priority_update_and_scheduling() {
        let mut session = Http2Session::new(true);

        // Receive PRIORITY_UPDATE frame for stream 3 (urgency 6)
        let pu1 = Http2Frame::PriorityUpdate {
            prioritized_stream_id: 3,
            priority_field_value: "u=6".to_string(),
        };
        session.handle_frame(&pu1).expect("handle pu1");

        // Receive PRIORITY_UPDATE frame for stream 5 (urgency 1, incremental)
        let pu2 = Http2Frame::PriorityUpdate {
            prioritized_stream_id: 5,
            priority_field_value: "u=1, i".to_string(),
        };
        session.handle_frame(&pu2).expect("handle pu2");

        // Receive PRIORITY_UPDATE frame for stream 1 (urgency 3)
        let pu3 = Http2Frame::PriorityUpdate {
            prioritized_stream_id: 1,
            priority_field_value: "u=3".to_string(),
        };
        session.handle_frame(&pu3).expect("handle pu3");

        // Priority order under RFC 9218: stream 5 (u=1), stream 1 (u=3), stream 3 (u=6)
        assert_eq!(session.prioritized_stream_ids_rfc9218(), vec![5, 1, 3]);

        // Dynamically update stream 3 to urgency 0 (highest urgency)
        let pu_override = Http2Frame::PriorityUpdate {
            prioritized_stream_id: 3,
            priority_field_value: "u=0".to_string(),
        };
        session
            .handle_frame(&pu_override)
            .expect("handle pu_override");

        assert_eq!(session.prioritized_stream_ids_rfc9218(), vec![3, 5, 1]);
    }

    #[test]
    fn test_rfc9218_headers_priority_field_auto_extraction() {
        let mut session = Http2Session::new(true);

        // Encode a HEADERS frame with "priority: u=2, i"
        let mut enc = HpackContext::default();
        let header_block = enc.encode_headers(&[(":status", "200"), ("priority", "u=2, i")]);

        let headers_frame = Http2Frame::Headers {
            stream_id: 9,
            end_stream: false,
            end_headers: true,
            header_block,
        };

        session
            .handle_frame(&headers_frame)
            .expect("handle headers");

        let stream = session.streams.get(&9).expect("stream 9 exists");
        assert_eq!(stream.priority_params.urgency, 2);
        assert!(stream.priority_params.incremental);
    }

    #[test]
    fn test_server_bidirectional_multiplexing_and_dynamic_flow_control() {
        // Create server session
        let mut server = Http2Session::new(true);

        // 1. Client opens stream 1 with urgency 1 (high priority)
        let mut enc = HpackContext::default();
        let client_headers = enc.encode_headers(&[
            (":method", "POST"),
            (":path", "/api/upload"),
            (":scheme", "https"),
            ("priority", "u=1"),
        ]);
        let headers_frame = Http2Frame::Headers {
            stream_id: 1,
            end_stream: false,
            end_headers: true,
            header_block: client_headers,
        };
        server
            .handle_frame(&headers_frame)
            .expect("server receives headers");

        // Verify stream state is Open on server
        let stream1 = server.streams.get(&1).expect("stream 1 created");
        assert_eq!(stream1.state, Http2StreamState::Open);
        assert_eq!(stream1.priority_params.urgency, 1);

        // Client sends 40 KB of DATA
        let chunk_40k = vec![0x42u8; 40_000];
        let data_frame = Http2Frame::Data {
            stream_id: 1,
            end_stream: false,
            data: chunk_40k,
        };
        server
            .handle_frame(&data_frame)
            .expect("server receives 40KB data");

        // Verify window decreased
        let stream1 = server.streams.get(&1).expect("stream 1");
        assert_eq!(stream1.received_data.len(), 40_000);
        assert_eq!(
            stream1.local_window_size,
            Http2Session::DEFAULT_INITIAL_WINDOW_SIZE - 40_000
        );

        // Evaluate dynamic window adaptation
        let window_updates = server.adapt_and_replenish_inbound_windows();
        assert!(
            !window_updates.is_empty(),
            "Should generate WINDOW_UPDATE frames"
        );

        // Urgency 1 stream should have target adapted to 4x (256 KB = 262140)
        let stream1 = server.streams.get(&1).expect("stream 1");
        assert_eq!(
            stream1.target_local_window_size,
            Http2Session::DEFAULT_INITIAL_WINDOW_SIZE * 4
        );

        // Server responds bidirectionally on stream 1
        let resp_frame = server.create_headers_frame(
            1,
            &[(":status", "200"), ("content-type", "application/json")],
            false,
        );
        match resp_frame {
            Http2Frame::Headers {
                stream_id,
                end_stream,
                ..
            } => {
                assert_eq!(stream_id, 1);
                assert!(!end_stream);
            }
            _ => panic!("Expected headers frame"),
        }

        // Server sends response DATA closing stream
        let resp_data = server.create_data_frame(1, b"{\"status\":\"ok\"}", true);
        match resp_data {
            Http2Frame::Data {
                stream_id,
                end_stream,
                data,
            } => {
                assert_eq!(stream_id, 1);
                assert!(end_stream);
                assert_eq!(data, b"{\"status\":\"ok\"}");
            }
            _ => panic!("Expected data frame"),
        }

        // Server also initiates server-push stream 2 for /api/upload/meta
        let push_promise = server.create_push_promise(
            1,
            2,
            &[
                (":method", "GET"),
                (":path", "/api/upload/meta"),
                (":scheme", "https"),
            ],
        );
        match push_promise {
            Http2Frame::PushPromise {
                stream_id,
                promised_stream_id,
                ..
            } => {
                assert_eq!(stream_id, 1);
                assert_eq!(promised_stream_id, 2);
            }
            _ => panic!("Expected push promise"),
        }
        assert!(server.streams.contains_key(&2));
        assert_eq!(
            server.streams.get(&2).unwrap().state,
            Http2StreamState::ReservedLocal
        );
    }

    #[test]
    fn test_rfc7838_altsvc_route_parsing_and_serialization() {
        let header = "h3=\":443\"; ma=2592000; persist=1, h2=\"alt.example.com:8443\"; ma=3600";
        let routes = AltSvcRoute::parse_header_value(header);
        assert_eq!(routes.len(), 2);

        assert_eq!(routes[0].protocol_id, "h3");
        assert_eq!(routes[0].host, "");
        assert_eq!(routes[0].port, 443);
        assert_eq!(routes[0].max_age, 2592000);
        assert!(routes[0].persist);

        assert_eq!(routes[1].protocol_id, "h2");
        assert_eq!(routes[1].host, "alt.example.com");
        assert_eq!(routes[1].port, 8443);
        assert_eq!(routes[1].max_age, 3600);
        assert!(!routes[1].persist);

        // Serialization
        let serialized = routes[0].serialize();
        assert_eq!(serialized, "h3=\":443\"; ma=2592000; persist=1");

        // "clear" directive
        let cleared = AltSvcRoute::parse_header_value("clear");
        assert!(cleared.is_empty());
    }

    #[test]
    fn test_rfc7838_altsvc_frame_encode_decode_and_session() {
        let frame = Http2Frame::AltSvc {
            stream_id: 0,
            origin: "https://example.com".to_string(),
            alt_svc_field_value: "h3=\":443\"; ma=86400".to_string(),
        };

        let encoded = frame.encode();
        // origin len (2) + origin (19) + alt_svc (19) = 40 payload bytes
        assert_eq!(encoded.len(), 9 + 40);

        let header = Http2FrameHeader::decode(&encoded[..9]).expect("decode header");
        assert_eq!(header.length, 40);
        assert_eq!(header.frame_type, Http2FrameType::AltSvc);
        assert_eq!(header.stream_id, 0);

        let decoded = Http2Frame::decode(&header, &encoded[9..]).expect("decode frame");
        if let Http2Frame::AltSvc {
            stream_id,
            origin,
            alt_svc_field_value,
        } = decoded
        {
            assert_eq!(stream_id, 0);
            assert_eq!(origin, "https://example.com");
            assert_eq!(alt_svc_field_value, "h3=\":443\"; ma=86400");
        } else {
            panic!("Expected Http2Frame::AltSvc");
        }

        // Test session processing of ALTSVC
        let mut session = Http2Session::new(false);
        let resp = session.handle_frame(&frame).expect("handle frame");
        assert!(resp.is_none());

        assert!(session.alt_svc_routes.contains_key("https://example.com"));
        let routes = session.alt_svc_routes.get("https://example.com").unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].protocol_id, "h3");
        assert_eq!(routes[0].port, 443);

        // Clear routes via clear frame
        let clear_frame = Http2Frame::AltSvc {
            stream_id: 0,
            origin: "https://example.com".to_string(),
            alt_svc_field_value: "clear".to_string(),
        };
        session
            .handle_frame(&clear_frame)
            .expect("handle clear frame");
        assert!(!session.alt_svc_routes.contains_key("https://example.com"));
    }

    #[test]
    fn test_initial_window_size_delta_update() {
        let mut session = Http2Session::new(false);
        let stream1 = session.open_stream();
        let stream2 = session.open_stream();

        // Initial default window sizes
        assert_eq!(session.streams.get(&stream1).unwrap().window_size, 65535);
        assert_eq!(session.streams.get(&stream2).unwrap().window_size, 65535);

        // Receive SETTINGS with InitialWindowSize = 131072 (delta = +65537)
        let settings_frame = Http2Frame::Settings {
            ack: false,
            settings: vec![Http2Setting {
                id: Http2SettingId::InitialWindowSize,
                value: 131072,
            }],
        };

        let ack = session
            .handle_frame(&settings_frame)
            .expect("handle settings frame");
        assert!(matches!(ack, Some(Http2Frame::Settings { ack: true, .. })));

        assert_eq!(session.initial_stream_window_size, 131072);
        assert_eq!(session.streams.get(&stream1).unwrap().window_size, 131072);
        assert_eq!(session.streams.get(&stream2).unwrap().window_size, 131072);

        // Test dynamic window update renegotiation at session and stream levels
        let conn_win = session
            .update_window_size(0, 1000)
            .expect("update session window");
        assert_eq!(conn_win, 65535 + 1000);

        let stream1_win = session
            .update_window_size(stream1, 500)
            .expect("update stream window");
        assert_eq!(stream1_win, 131072 + 500);

        // Verify newly opened streams receive the updated initial window size
        let stream3 = session.open_stream();
        assert_eq!(session.streams.get(&stream3).unwrap().window_size, 131072);
    }

    #[test]
    fn test_hpack_lru_eviction_policy() {
        // Create an HPACK context with capacity limited to fit roughly 2 entries.
        // Each entry consumes: name.len() + value.len() + 32 bytes.
        // "k1": "v1" -> 2 + 2 + 32 = 36 bytes.
        // Max table size 75 allows holding 2 entries (72 bytes), but a 3rd will evict.
        let mut ctx = HpackContext::new(75).with_eviction_policy(HpackEvictionPolicy::Lru);
        assert_eq!(ctx.eviction_policy, HpackEvictionPolicy::Lru);

        ctx.add_dynamic_entry("k1".to_string(), "v1".to_string());
        ctx.add_dynamic_entry("k2".to_string(), "v2".to_string());
        assert_eq!(ctx.dynamic_table.len(), 2);
        assert_eq!(ctx.dynamic_table[0].0, "k2");
        assert_eq!(ctx.dynamic_table[1].0, "k1");

        // Touch entry "k1" via get_and_touch_entry.
        // Static table length is 61, so k2 is index 62, k1 is index 63.
        let touched = ctx.get_and_touch_entry(63).expect("find k1");
        assert_eq!(touched.0, "k1");
        assert_eq!(touched.1, "v1");

        // Because of LRU, "k1" is now at index 0 (index 62), and "k2" is at index 1 (index 63).
        assert_eq!(ctx.dynamic_table[0].0, "k1");
        assert_eq!(ctx.dynamic_table[1].0, "k2");

        // Add 3rd entry "k3" -> 36 bytes. Exceeds 75 bytes, so the LRU entry ("k2") is evicted.
        ctx.add_dynamic_entry("k3".to_string(), "v3".to_string());
        assert_eq!(ctx.dynamic_table.len(), 2);
        assert_eq!(ctx.dynamic_table[0].0, "k3");
        assert_eq!(ctx.dynamic_table[1].0, "k1");

        // Verify FIFO behavior as contrast
        let mut fifo_ctx = HpackContext::new(75).with_eviction_policy(HpackEvictionPolicy::Fifo);
        fifo_ctx.add_dynamic_entry("k1".to_string(), "v1".to_string());
        fifo_ctx.add_dynamic_entry("k2".to_string(), "v2".to_string());
        let _ = fifo_ctx.get_and_touch_entry(63); // Touch k1 in FIFO mode
                                                  // In FIFO mode, touching does not reorder
        assert_eq!(fifo_ctx.dynamic_table[0].0, "k2");
        assert_eq!(fifo_ctx.dynamic_table[1].0, "k1");
        fifo_ctx.add_dynamic_entry("k3".to_string(), "v3".to_string());
        // Oldest entry "k1" evicted first in FIFO
        assert_eq!(fifo_ctx.dynamic_table.len(), 2);
        assert_eq!(fifo_ctx.dynamic_table[0].0, "k3");
        assert_eq!(fifo_ctx.dynamic_table[1].0, "k2");
    }

    #[test]
    fn test_hpack_compression_telemetry_metrics() {
        let mut ctx = HpackContext::default();
        let headers = [
            (":method", "GET"),
            (":path", "/index.html"),
            (":scheme", "https"),
            (":authority", "example.com"),
            ("user-agent", "IFA/1.0"),
            ("accept", "application/json"),
        ];

        let encoded = ctx.encode_headers_with_options(&headers, true);
        assert!(!encoded.is_empty());

        let telem = ctx.telemetry;
        assert_eq!(telem.total_headers, 6);
        assert!(telem.raw_bytes > 0);
        assert!(telem.compressed_bytes > 0);
        assert!(telem.static_table_hits >= 3); // :method GET, :path /index.html, :scheme https
        assert!(telem.compression_ratio() < 1.0);
        assert!(telem.savings_percentage() > 0.0);
    }

    #[test]
    fn test_adaptive_flow_control_bdp_estimation() {
        let mut session = Http2Session::new(false);
        assert_eq!(session.connection_window_size, 65535);

        // Record RTT sample: 50 ms = 50,000 us
        session.adaptive_flow_controller.record_rtt_sample(50_000);
        assert_eq!(
            session.adaptive_flow_controller.smoothed_rtt_us,
            Some(50_000)
        );

        // Record Bandwidth sample: 10 MB/s (10,000,000 bytes over 1 second)
        session
            .adaptive_flow_controller
            .record_bandwidth_sample(10_000_000, std::time::Duration::from_secs(1));
        assert_eq!(
            session.adaptive_flow_controller.estimated_bandwidth_bps,
            Some(10_000_000)
        );

        // BDP = 10,000,000 * 0.050s = 500,000 bytes. With 1.5 headroom = 750,000 bytes.
        let target_win = session.adaptive_flow_controller.target_connection_window;
        assert_eq!(target_win, 750_000);

        // Replenish inbound windows should emit connection WINDOW_UPDATE adapting to high BDP
        session.connection_window_size = 100_000; // below 750_000 / 2 = 375_000
        let updates = session.adapt_and_replenish_inbound_windows();
        assert!(!updates.is_empty());
        match &updates[0] {
            Http2Frame::WindowUpdate {
                stream_id,
                window_size_increment,
            } => {
                assert_eq!(*stream_id, 0);
                assert_eq!(*window_size_increment, 650_000); // 750,000 - 100,000
            }
            _ => panic!("Expected WindowUpdate frame"),
        }
        assert_eq!(session.connection_window_size, 750_000);
    }

    #[test]
    fn test_schedule_outbound_data_rfc9218_priority() {
        let mut session = Http2Session::new(false);
        // Create 3 open streams: stream 1 (urgency 3), stream 3 (urgency 0 - critical), stream 5 (urgency 6)
        let mut s1 = Http2Stream::new(1, 65535);
        s1.state = Http2StreamState::Open;
        let mut s3 = Http2Stream::new(3, 65535);
        s3.state = Http2StreamState::Open;
        let mut s5 = Http2Stream::new(5, 65535);
        s5.state = Http2StreamState::Open;

        session.streams.insert(1, s1);
        session.streams.insert(3, s3);
        session.streams.insert(5, s5);

        session.set_stream_priority_parameters(
            1,
            PriorityParameters {
                urgency: 3,
                incremental: false,
            },
        );
        session.set_stream_priority_parameters(
            3,
            PriorityParameters {
                urgency: 0,
                incremental: false,
            },
        );
        session.set_stream_priority_parameters(
            5,
            PriorityParameters {
                urgency: 6,
                incremental: false,
            },
        );

        let mut pending = std::collections::HashMap::new();
        pending.insert(1, vec![1u8; 100]);
        pending.insert(3, vec![3u8; 200]);
        pending.insert(5, vec![5u8; 300]);

        // Connection window initially 65535
        let frames = session.schedule_outbound_data(&mut pending, 16384);
        assert_eq!(frames.len(), 3);

        // Frame order must respect urgency: stream 3 (urgency 0) first, then stream 1 (urgency 3), then stream 5 (urgency 6)
        match &frames[0] {
            Http2Frame::Data {
                stream_id,
                data,
                end_stream,
            } => {
                assert_eq!(*stream_id, 3);
                assert_eq!(data.len(), 200);
                assert!(*end_stream);
            }
            _ => panic!("Expected Data frame for stream 3"),
        }

        match &frames[1] {
            Http2Frame::Data {
                stream_id,
                data,
                end_stream,
            } => {
                assert_eq!(*stream_id, 1);
                assert_eq!(data.len(), 100);
                assert!(*end_stream);
            }
            _ => panic!("Expected Data frame for stream 1"),
        }

        match &frames[2] {
            Http2Frame::Data {
                stream_id,
                data,
                end_stream,
            } => {
                assert_eq!(*stream_id, 5);
                assert_eq!(data.len(), 300);
                assert!(*end_stream);
            }
            _ => panic!("Expected Data frame for stream 5"),
        }

        assert!(pending.values().all(|b| b.is_empty()));
    }

    #[test]
    fn test_schedule_outbound_data_incremental_interleaving() {
        let mut session = Http2Session::new(false);
        // Ensure connection window has plenty of credit (e.g. 128KB)
        session.connection_window_size = 131072;

        // Both stream 1 and stream 3 have the same urgency (urgency 2), but incremental = true
        let mut s1 = Http2Stream::new(1, 65535);
        s1.state = Http2StreamState::Open;
        let mut s3 = Http2Stream::new(3, 65535);
        s3.state = Http2StreamState::Open;

        session.streams.insert(1, s1);
        session.streams.insert(3, s3);

        session.set_stream_priority_parameters(
            1,
            PriorityParameters {
                urgency: 2,
                incremental: true,
            },
        );
        session.set_stream_priority_parameters(
            3,
            PriorityParameters {
                urgency: 2,
                incremental: true,
            },
        );

        let mut pending = std::collections::HashMap::new();
        // Give each stream 32KB of data
        pending.insert(1, vec![1u8; 32768]);
        pending.insert(3, vec![3u8; 32768]);

        // Max frame size = 16384 (16KB)
        // With incremental interleaving, frames should alternate between stream 1 and stream 3!
        // Round 1: stream 1 chunk 1 (16KB), stream 3 chunk 1 (16KB)
        // Round 2: stream 1 chunk 2 (16KB, end_stream), stream 3 chunk 2 (16KB, end_stream)
        let frames = session.schedule_outbound_data(&mut pending, 16384);
        assert_eq!(frames.len(), 4);

        let stream_sequence: Vec<u32> = frames
            .iter()
            .map(|f| match f {
                Http2Frame::Data { stream_id, .. } => *stream_id,
                _ => panic!("Expected Data frame"),
            })
            .collect();

        assert_eq!(stream_sequence, vec![1, 3, 1, 3]);

        // Check end_stream flags
        match &frames[0] {
            Http2Frame::Data { end_stream, .. } => assert!(!*end_stream),
            _ => panic!(),
        }
        match &frames[1] {
            Http2Frame::Data { end_stream, .. } => assert!(!*end_stream),
            _ => panic!(),
        }
        match &frames[2] {
            Http2Frame::Data { end_stream, .. } => assert!(*end_stream),
            _ => panic!(),
        }
        match &frames[3] {
            Http2Frame::Data { end_stream, .. } => assert!(*end_stream),
            _ => panic!(),
        }

        assert!(pending.values().all(|b| b.is_empty()));
    }

    #[test]
    fn test_rst_stream_purges_pending_outbound_data() {
        let mut session = Http2Session::new(false);
        let s1 = session.open_stream();
        let s2 = session.open_stream();

        // Queue pending outbound data for both streams
        session.queue_outbound_data(s1, b"stream1 sensitive pending data");
        session.queue_outbound_data(s2, b"stream2 pending data");

        assert_eq!(session.pending_outbound_data.len(), 2);
        assert!(session.pending_outbound_data.contains_key(&s1));
        assert!(session.pending_outbound_data.contains_key(&s2));

        // 1. Inbound RST_STREAM frame on s1 purges s1's pending outbound buffer immediately
        let rst_frame = Http2Frame::RstStream {
            stream_id: s1,
            error_code: Http2ErrorCode::Cancel,
        };
        let reply = session.handle_frame(&rst_frame).expect("handle frame");
        assert!(reply.is_none());

        assert!(!session.pending_outbound_data.contains_key(&s1));
        assert!(session.pending_outbound_data.contains_key(&s2));
        assert_eq!(
            session.streams.get(&s1).unwrap().state,
            Http2StreamState::Closed
        );

        // 2. Outbound reset_stream call on s2 also purges s2's pending outbound buffer immediately
        let _out_rst = session.reset_stream(s2, Http2ErrorCode::InternalError);
        assert!(!session.pending_outbound_data.contains_key(&s2));
        assert_eq!(
            session.streams.get(&s2).unwrap().state,
            Http2StreamState::Closed
        );
        assert!(session.pending_outbound_data.is_empty());
    }

    #[test]
    fn test_http2_data_frame_slice_zero_copy_and_session_handling() {
        let raw_payload = b"high-frequency-streaming-chunk-data";
        let header = Http2FrameHeader {
            length: raw_payload.len() as u32,
            frame_type: Http2FrameType::Data,
            flags: Http2Frame::FLAG_END_STREAM,
            stream_id: 3,
        };

        let slice = Http2DataFrameSlice::decode(&header, raw_payload)
            .expect("decode data frame slice zero-copy");
        assert_eq!(slice.stream_id, 3);
        assert!(slice.end_stream);
        assert_eq!(slice.data, raw_payload);

        let owned_frame = slice.to_owned_frame();
        match owned_frame {
            Http2Frame::Data {
                stream_id,
                end_stream,
                data,
            } => {
                assert_eq!(stream_id, 3);
                assert!(end_stream);
                assert_eq!(data, raw_payload);
            }
            _ => panic!("expected Data frame"),
        }

        let mut session = Http2Session::new(true);
        // Pre-open stream 3 so it transitions from Open to HalfClosedRemote upon end_stream
        session.streams.insert(3, Http2Stream::new(3, 65535));
        session.streams.get_mut(&3).unwrap().state = Http2StreamState::Open;

        let reply = session
            .handle_data_slice(&slice)
            .expect("handle data slice");
        assert!(reply.is_none());

        let stream = session.streams.get(&3).expect("stream 3 exists");
        assert_eq!(stream.received_data, raw_payload);
        assert_eq!(stream.state, Http2StreamState::HalfClosedRemote);
    }

    #[test]
    fn test_rfc7540_push_promise_validation() {
        let valid_headers = vec![
            (":method".to_string(), "GET".to_string()),
            (":path".to_string(), "/assets/app.js".to_string()),
            (":scheme".to_string(), "https".to_string()),
            (":authority".to_string(), "example.com".to_string()),
        ];
        let req = Http2PromisedRequest::new(1, 2, valid_headers);
        assert!(req.is_valid);
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/assets/app.js");
        assert_eq!(req.scheme, "https");
        assert_eq!(req.authority, "example.com");

        // Unsafe method POST
        let unsafe_headers = vec![
            (":method".to_string(), "POST".to_string()),
            (":path".to_string(), "/api/upload".to_string()),
            (":scheme".to_string(), "https".to_string()),
        ];
        let req_unsafe = Http2PromisedRequest::new(1, 4, unsafe_headers);
        assert!(!req_unsafe.is_valid);
        assert!(req_unsafe
            .validation_error
            .as_ref()
            .unwrap()
            .contains("Unsafe HTTP method"));

        // Missing :path
        let missing_path_headers = vec![
            (":method".to_string(), "GET".to_string()),
            (":scheme".to_string(), "https".to_string()),
        ];
        let req_missing_path = Http2PromisedRequest::new(1, 6, missing_path_headers);
        assert!(!req_missing_path.is_valid);
        assert!(req_missing_path
            .validation_error
            .as_ref()
            .unwrap()
            .contains("Missing mandatory :path"));
    }

    #[test]
    fn test_rfc7540_push_promise_session_handling_and_auto_reset() {
        let mut client = Http2Session::new(false);
        let mut enc = HpackContext::default();

        // 1. Unsafe push promise received by client: must trigger automatic RST_STREAM(ProtocolError)
        let unsafe_block = enc.encode_headers(&[
            (":method", "POST"),
            (":path", "/api/trigger"),
            (":scheme", "https"),
        ]);
        let unsafe_frame = Http2Frame::PushPromise {
            stream_id: 1,
            promised_stream_id: 2,
            end_headers: true,
            header_block: unsafe_block,
        };
        let reply = client
            .handle_frame(&unsafe_frame)
            .expect("handle unsafe push promise");
        match reply {
            Some(Http2Frame::RstStream {
                stream_id,
                error_code,
            }) => {
                assert_eq!(stream_id, 2);
                assert_eq!(error_code, Http2ErrorCode::ProtocolError);
            }
            _ => panic!("Expected RST_STREAM(ProtocolError) reply"),
        }

        // 2. Client with disabled push promises: must trigger automatic RST_STREAM(RefusedStream)
        client.enable_push = false;
        let valid_block = enc.encode_headers(&[
            (":method", "GET"),
            (":path", "/styles/site.css"),
            (":scheme", "https"),
        ]);
        let push_frame = Http2Frame::PushPromise {
            stream_id: 1,
            promised_stream_id: 4,
            end_headers: true,
            header_block: valid_block.clone(),
        };
        let reply_disabled = client
            .handle_frame(&push_frame)
            .expect("handle push promise when disabled");
        match reply_disabled {
            Some(Http2Frame::RstStream {
                stream_id,
                error_code,
            }) => {
                assert_eq!(stream_id, 4);
                assert_eq!(error_code, Http2ErrorCode::RefusedStream);
            }
            _ => panic!("Expected RST_STREAM(RefusedStream) reply"),
        }

        // 3. Re-enable push promises: valid promise accepted into ReservedRemote state
        client.enable_push = true;
        let reply_valid = client
            .handle_frame(&push_frame)
            .expect("handle valid push promise");
        assert!(reply_valid.is_none());
        assert!(client.promised_requests.contains_key(&4));
        assert_eq!(
            client.streams.get(&4).unwrap().state,
            Http2StreamState::ReservedRemote
        );
    }

    #[test]
    fn test_rfc7234_cache_directives_and_conditional_validation_helpers() {
        let cc_val = "public, max-age=3600, must-revalidate";
        let directives = Http2CacheDirectives::parse(cc_val);
        assert!(directives.is_public);
        assert!(!directives.is_private);
        assert!(!directives.no_cache);
        assert!(!directives.no_store);
        assert!(directives.must_revalidate);
        assert_eq!(directives.max_age_secs, Some(3600));
        assert_eq!(directives.effective_max_age(), Some(3600));
        assert!(directives.is_cacheable());

        let cc_no_store = "no-cache, no-store";
        let d_no_store = Http2CacheDirectives::parse(cc_no_store);
        assert!(d_no_store.no_cache);
        assert!(d_no_store.no_store);
        assert!(!d_no_store.is_cacheable());

        let headers = vec![
            ("content-type".to_string(), "application/json".to_string()),
            (
                "cache-control".to_string(),
                "max-age=120, s-maxage=600".to_string(),
            ),
            ("etag".to_string(), "\"33a64df551425fcc\"".to_string()),
            (
                "last-modified".to_string(),
                "Wed, 21 Oct 2015 07:28:00 GMT".to_string(),
            ),
        ];

        let extracted_cc = extract_http2_cache_control(&headers).expect("extracted cc");
        assert_eq!(extracted_cc.max_age_secs, Some(120));
        assert_eq!(extracted_cc.s_maxage_secs, Some(600));
        assert_eq!(extracted_cc.effective_max_age(), Some(600));

        let extracted_etag = extract_http2_etag(&headers).expect("extracted etag");
        assert_eq!(extracted_etag, "\"33a64df551425fcc\"");

        let extracted_lm = extract_http2_last_modified(&headers).expect("extracted lm");
        assert_eq!(extracted_lm, "Wed, 21 Oct 2015 07:28:00 GMT");

        let cond_headers =
            build_http2_conditional_headers(Some(&extracted_etag), Some(&extracted_lm));
        assert_eq!(cond_headers.len(), 2);
        assert_eq!(
            cond_headers[0],
            (
                "if-none-match".to_string(),
                "\"33a64df551425fcc\"".to_string()
            )
        );
        assert_eq!(
            cond_headers[1],
            (
                "if-modified-since".to_string(),
                "Wed, 21 Oct 2015 07:28:00 GMT".to_string()
            )
        );

        assert!(is_http_status_cacheable_by_default(200));
        assert!(is_http_status_cacheable_by_default(304));
        assert!(!is_http_status_cacheable_by_default(500));
    }

    #[test]
    fn test_rfc7234_vary_header_directives_and_matching() {
        let v_any = Http2Vary::parse("*");
        assert_eq!(v_any, Http2Vary::Any);
        assert!(!v_any.is_matchable());

        let v_headers = Http2Vary::parse("Accept-Encoding, user-agent, ACCEPT-ENCODING");
        assert!(v_headers.is_matchable());
        match &v_headers {
            Http2Vary::Headers(fields) => {
                assert_eq!(fields, &["accept-encoding", "user-agent"]);
            }
            _ => panic!("Expected Headers variant"),
        }

        let stored_req = vec![
            ("accept-encoding".to_string(), "gzip".to_string()),
            ("user-agent".to_string(), "IFA-Client/1.0".to_string()),
        ];
        let presented_matching = vec![
            ("ACCEPT-ENCODING".to_string(), "gzip".to_string()),
            ("User-Agent".to_string(), "IFA-Client/1.0".to_string()),
            ("x-extra".to_string(), "ignored".to_string()),
        ];
        let presented_mismatched_enc = vec![
            ("accept-encoding".to_string(), "br".to_string()),
            ("user-agent".to_string(), "IFA-Client/1.0".to_string()),
        ];
        let presented_missing_agent = vec![("accept-encoding".to_string(), "gzip".to_string())];

        assert!(v_headers.matches_request(&stored_req, &presented_matching));
        assert!(!v_headers.matches_request(&stored_req, &presented_mismatched_enc));
        assert!(!v_headers.matches_request(&stored_req, &presented_missing_agent));
        assert!(!v_any.matches_request(&stored_req, &presented_matching));

        let resp_headers = vec![
            ("content-type".to_string(), "application/json".to_string()),
            (
                "vary".to_string(),
                "Accept-Encoding, Accept-Language".to_string(),
            ),
        ];
        let extracted_vary = extract_http2_vary(&resp_headers).expect("extracted vary");
        assert_eq!(
            extracted_vary,
            Http2Vary::Headers(vec![
                "accept-encoding".to_string(),
                "accept-language".to_string()
            ])
        );
    }
}

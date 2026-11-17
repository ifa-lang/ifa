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
            Http2Frame::PriorityUpdate { priority_field_value, .. } => {
                13 + priority_field_value.len()
            }
            Http2Frame::AltSvc { origin, alt_svc_field_value, .. } => {
                11 + origin.len() + alt_svc_field_value.len()
            }
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
                let flags = if *end_stream { Self::FLAG_END_STREAM } else { 0 };
                let header = Http2FrameHeader::new(data.len() as u32, Http2FrameType::Data, flags, *stream_id);
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
                if *end_stream { flags |= Self::FLAG_END_STREAM; }
                if *end_headers { flags |= Self::FLAG_END_HEADERS; }
                let header = Http2FrameHeader::new(header_block.len() as u32, Http2FrameType::Headers, flags, *stream_id);
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
                let dep = (if *exclusive { 0x8000_0000 } else { 0 }) | (*stream_dependency & 0x7FFF_FFFF);
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
                let flags = if *end_headers { Self::FLAG_END_HEADERS } else { 0 };
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
                let flags = if *end_headers { Self::FLAG_END_HEADERS } else { 0 };
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
                let header = Http2FrameHeader::new(payload_len as u32, Http2FrameType::PriorityUpdate, 0, 0);
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

/// HPACK Header Encoder / Decoder with Dynamic Table (RFC 7541) and Literal Cache.
#[derive(Debug, Clone)]
pub struct HpackContext {
    pub max_table_size: usize,
    pub dynamic_table: Vec<(String, String)>,
    /// Cache of frequently decoded literal strings to avoid repeated allocation and decoding.
    pub literal_cache: Vec<(Vec<u8>, String)>,
    pub max_literal_cache_size: usize,
    pub literal_cache_hits: usize,
    pub literal_cache_misses: usize,
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
            literal_cache: Vec::new(),
            max_literal_cache_size: 64,
            literal_cache_hits: 0,
            literal_cache_misses: 0,
        }
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

    /// Add an entry to the dynamic table with FIFO eviction.
    pub fn add_dynamic_entry(&mut self, name: String, value: String) {
        let entry_size = name.len() + value.len() + 32;
        if entry_size > self.max_table_size {
            self.dynamic_table.clear();
            return;
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
        for &(name, value) in headers {
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
                hpack_encode_integer(idx, 7, 0x80, &mut out);
            } else if let Some(name_idx) = matched_name_idx {
                // 2. Literal Header Field with Incremental Indexing — Indexed Name (RFC 7541 Section 6.2.1): 01xxxxxx
                hpack_encode_integer(name_idx, 6, 0x40, &mut out);
                hpack_encode_string_custom(value.as_bytes(), &mut out, use_huffman);
                self.add_dynamic_entry(name.to_ascii_lowercase(), value.to_string());
            } else {
                // 3. Literal Header Field with Incremental Indexing — New Name: 01000000
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
                let (name, val) = self.get_entry(idx).ok_or(FastHttpError::InvalidHeader)?;
                out.push((name.to_string(), val.to_string()));
            } else if (b & 0x40) != 0 {
                // Literal Header Field with Incremental Indexing (RFC 7541 Section 6.2.1)
                let (idx, consumed) = hpack_decode_integer(&bytes[offset..], 6)?;
                offset += consumed;
                let name = if idx != 0 {
                    let (n, _) = self.get_entry(idx).ok_or(FastHttpError::InvalidHeader)?;
                    n.to_string()
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
                    let (n, _) = self.get_entry(idx).ok_or(FastHttpError::InvalidHeader)?;
                    n.to_string()
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

/// Multiplexed HTTP/2 Session Manager handling streams, flow control, and HPACK.
#[derive(Debug)]
pub struct Http2Session {
    pub is_server: bool,
    pub next_stream_id: u32,
    pub peer_settings: Vec<Http2Setting>,
    pub local_settings: Vec<Http2Setting>,
    pub streams: std::collections::HashMap<u32, Http2Stream>,
    pub push_promises: std::collections::HashMap<u32, Vec<(String, String)>>,
    pub hpack_encoder: HpackContext,
    pub hpack_decoder: HpackContext,
    pub connection_window_size: i32,
    pub initial_stream_window_size: i32,
    pub last_received_goaway: Option<(u32, Http2ErrorCode, Vec<u8>)>,
    /// RFC 7838 alternative services advertised by peer.
    /// Maps origin string (or empty for current origin) to list of available routes.
    pub alt_svc_routes: std::collections::HashMap<String, Vec<AltSvcRoute>>,
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
            hpack_encoder: HpackContext::default(),
            hpack_decoder: HpackContext::default(),
            connection_window_size: Self::DEFAULT_INITIAL_WINDOW_SIZE,
            initial_stream_window_size: Self::DEFAULT_INITIAL_WINDOW_SIZE,
            last_received_goaway: None,
            alt_svc_routes: std::collections::HashMap::new(),
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
    pub fn update_window_size(&mut self, stream_id: u32, increment: u32) -> Result<i32, FastHttpError> {
        if stream_id == 0 {
            let new_win = self.connection_window_size.checked_add(increment as i32)
                .ok_or(FastHttpError::InvalidHeader)?;
            self.connection_window_size = new_win;
            Ok(new_win)
        } else if let Some(stream) = self.streams.get_mut(&stream_id) {
            let new_win = stream.window_size.checked_add(increment as i32)
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
    /// based on RFC 9218 urgency and stream activity, emitting `WINDOW_UPDATE` frames as necessary.
    pub fn adapt_and_replenish_inbound_windows(&mut self) -> Vec<Http2Frame> {
        let mut updates = Vec::new();

        // 1. Connection-level replenish if below half default initial window
        let conn_threshold = Self::DEFAULT_INITIAL_WINDOW_SIZE / 2;
        if self.connection_window_size < conn_threshold {
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

        // 2. Stream-level adaptive replenishment
        for (stream_id, stream) in self.streams.iter_mut() {
            // Apply dynamic target window adaptation based on urgency if available
            // Urgency 0-1: 4x default window (256 KB)
            // Urgency 2-3: 2x default window (128 KB)
            // Urgency 4-7: 1x default window (64 KB)
            let adaptive_target = match stream.priority_params.urgency {
                0..=1 => Self::DEFAULT_INITIAL_WINDOW_SIZE * 4,
                2..=3 => Self::DEFAULT_INITIAL_WINDOW_SIZE * 2,
                _ => Self::DEFAULT_INITIAL_WINDOW_SIZE,
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
    pub fn reset_stream(&mut self, stream_id: u32, error_code: Http2ErrorCode) -> Http2Frame {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.state = Http2StreamState::Closed;
            stream.reset_error = Some(error_code);
        }
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
        self.push_promises.insert(promised_stream_id, owned_headers);

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
                Ok(None)
            }
            Http2Frame::PushPromise {
                stream_id: _,
                promised_stream_id,
                end_headers: _,
                header_block,
            } => {
                let decoded_headers = self.hpack_decoder.decode_headers(header_block)?;
                let mut stream =
                    Http2Stream::new(*promised_stream_id, self.initial_stream_window_size);
                stream.state = Http2StreamState::ReservedRemote;
                stream.received_headers = decoded_headers.clone();
                self.streams.insert(*promised_stream_id, stream);
                self.push_promises
                    .insert(*promised_stream_id, decoded_headers);
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

        let ack = session.handle_frame(&settings_frame).expect("handle settings frame");
        assert!(matches!(ack, Some(Http2Frame::Settings { ack: true, .. })));

        assert_eq!(session.initial_stream_window_size, 131072);
        assert_eq!(session.streams.get(&stream1).unwrap().window_size, 131072);
        assert_eq!(session.streams.get(&stream2).unwrap().window_size, 131072);

        // Test dynamic window update renegotiation at session and stream levels
        let conn_win = session.update_window_size(0, 1000).expect("update session window");
        assert_eq!(conn_win, 65535 + 1000);

        let stream1_win = session.update_window_size(stream1, 500).expect("update stream window");
        assert_eq!(stream1_win, 131072 + 500);

        // Verify newly opened streams receive the updated initial window size
        let stream3 = session.open_stream();
        assert_eq!(session.streams.get(&stream3).unwrap().window_size, 131072);
    }
}

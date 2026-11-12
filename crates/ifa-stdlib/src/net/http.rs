//! Minimalist HTTP/1.1 wire parser, serializer, and chunked transfer codec over `BufferedTcpStream` (`std::net::http`).

use std::collections::HashMap;
use std::fmt;
use std::io::{self, BufRead, Read, Write};

use super::BufferedTcpStream;

/// Standard HTTP Protocol Version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpVersion {
    Http10,
    Http11,
}

impl HttpVersion {
    pub fn as_str(&self) -> &'static str {
        match self {
            HttpVersion::Http10 => "HTTP/1.0",
            HttpVersion::Http11 => "HTTP/1.1",
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HttpParseError> {
        match bytes {
            b"HTTP/1.1" => Ok(HttpVersion::Http11),
            b"HTTP/1.0" => Ok(HttpVersion::Http10),
            _ => Err(HttpParseError::InvalidVersion),
        }
    }
}

impl fmt::Display for HttpVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Standard HTTP request methods (RFC 7231).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
    Trace,
    Connect,
}

impl HttpMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Head => "HEAD",
            HttpMethod::Options => "OPTIONS",
            HttpMethod::Trace => "TRACE",
            HttpMethod::Connect => "CONNECT",
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HttpParseError> {
        match bytes {
            b"GET" => Ok(HttpMethod::Get),
            b"POST" => Ok(HttpMethod::Post),
            b"PUT" => Ok(HttpMethod::Put),
            b"DELETE" => Ok(HttpMethod::Delete),
            b"PATCH" => Ok(HttpMethod::Patch),
            b"HEAD" => Ok(HttpMethod::Head),
            b"OPTIONS" => Ok(HttpMethod::Options),
            b"TRACE" => Ok(HttpMethod::Trace),
            b"CONNECT" => Ok(HttpMethod::Connect),
            _ => Err(HttpParseError::InvalidMethod),
        }
    }
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Standard HTTP Status Codes (RFC 7231, RFC 6585, RFC 7540).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HttpStatus(pub u16);

impl HttpStatus {
    pub const CONTINUE: HttpStatus = HttpStatus(100);
    pub const SWITCHING_PROTOCOLS: HttpStatus = HttpStatus(101);

    pub const OK: HttpStatus = HttpStatus(200);
    pub const CREATED: HttpStatus = HttpStatus(201);
    pub const ACCEPTED: HttpStatus = HttpStatus(202);
    pub const NO_CONTENT: HttpStatus = HttpStatus(204);
    pub const RESET_CONTENT: HttpStatus = HttpStatus(205);
    pub const PARTIAL_CONTENT: HttpStatus = HttpStatus(206);

    pub const MOVED_PERMANENTLY: HttpStatus = HttpStatus(301);
    pub const FOUND: HttpStatus = HttpStatus(302);
    pub const SEE_OTHER: HttpStatus = HttpStatus(303);
    pub const NOT_MODIFIED: HttpStatus = HttpStatus(304);
    pub const TEMPORARY_REDIRECT: HttpStatus = HttpStatus(307);
    pub const PERMANENT_REDIRECT: HttpStatus = HttpStatus(308);

    pub const BAD_REQUEST: HttpStatus = HttpStatus(400);
    pub const UNAUTHORIZED: HttpStatus = HttpStatus(401);
    pub const FORBIDDEN: HttpStatus = HttpStatus(403);
    pub const NOT_FOUND: HttpStatus = HttpStatus(404);
    pub const METHOD_NOT_ALLOWED: HttpStatus = HttpStatus(405);
    pub const NOT_ACCEPTABLE: HttpStatus = HttpStatus(406);
    pub const REQUEST_TIMEOUT: HttpStatus = HttpStatus(408);
    pub const CONFLICT: HttpStatus = HttpStatus(409);
    pub const GONE: HttpStatus = HttpStatus(410);
    pub const LENGTH_REQUIRED: HttpStatus = HttpStatus(411);
    pub const PRECONDITION_FAILED: HttpStatus = HttpStatus(412);
    pub const PAYLOAD_TOO_LARGE: HttpStatus = HttpStatus(413);
    pub const URI_TOO_LONG: HttpStatus = HttpStatus(414);
    pub const UNSUPPORTED_MEDIA_TYPE: HttpStatus = HttpStatus(415);
    pub const RANGE_NOT_SATISFIABLE: HttpStatus = HttpStatus(416);
    pub const UNPROCESSABLE_ENTITY: HttpStatus = HttpStatus(422);
    pub const TOO_MANY_REQUESTS: HttpStatus = HttpStatus(429);

    pub const INTERNAL_SERVER_ERROR: HttpStatus = HttpStatus(500);
    pub const NOT_IMPLEMENTED: HttpStatus = HttpStatus(501);
    pub const BAD_GATEWAY: HttpStatus = HttpStatus(502);
    pub const SERVICE_UNAVAILABLE: HttpStatus = HttpStatus(503);
    pub const GATEWAY_TIMEOUT: HttpStatus = HttpStatus(504);
    pub const HTTP_VERSION_NOT_SUPPORTED: HttpStatus = HttpStatus(505);

    #[inline]
    pub fn code(&self) -> u16 {
        self.0
    }

    #[inline]
    pub fn is_informational(&self) -> bool {
        (100..200).contains(&self.0)
    }

    #[inline]
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.0)
    }

    #[inline]
    pub fn is_redirection(&self) -> bool {
        (300..400).contains(&self.0)
    }

    #[inline]
    pub fn is_client_error(&self) -> bool {
        (400..500).contains(&self.0)
    }

    #[inline]
    pub fn is_server_error(&self) -> bool {
        (500..600).contains(&self.0)
    }

    pub fn reason_phrase(&self) -> &'static str {
        match self.0 {
            100 => "Continue",
            101 => "Switching Protocols",
            200 => "OK",
            201 => "Created",
            202 => "Accepted",
            204 => "No Content",
            205 => "Reset Content",
            206 => "Partial Content",
            301 => "Moved Permanently",
            302 => "Found",
            303 => "See Other",
            304 => "Not Modified",
            307 => "Temporary Redirect",
            308 => "Permanent Redirect",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            406 => "Not Acceptable",
            408 => "Request Timeout",
            409 => "Conflict",
            410 => "Gone",
            411 => "Length Required",
            412 => "Precondition Failed",
            413 => "Payload Too Large",
            414 => "URI Too Long",
            415 => "Unsupported Media Type",
            416 => "Range Not Satisfiable",
            422 => "Unprocessable Entity",
            429 => "Too Many Requests",
            500 => "Internal Server Error",
            501 => "Not Implemented",
            502 => "Bad Gateway",
            503 => "Service Unavailable",
            504 => "Gateway Timeout",
            505 => "HTTP Version Not Supported",
            _ => "Unknown",
        }
    }
}

impl fmt::Display for HttpStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.0, self.reason_phrase())
    }
}

/// Case-insensitive HTTP Header collection with deterministic order preservation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HeaderMap {
    entries: Vec<(String, String)>,
    lookup: HashMap<String, usize>,
}

impl HeaderMap {
    pub const CONTENT_LENGTH: &'static str = "content-length";
    pub const CONTENT_TYPE: &'static str = "content-type";
    pub const TRANSFER_ENCODING: &'static str = "transfer-encoding";
    pub const CONNECTION: &'static str = "connection";
    pub const HOST: &'static str = "host";
    pub const USER_AGENT: &'static str = "user-agent";
    pub const ACCEPT: &'static str = "accept";
    pub const COOKIE: &'static str = "cookie";
    pub const SET_COOKIE: &'static str = "set-cookie";
    pub const LOCATION: &'static str = "location";
    pub const DATE: &'static str = "date";
    pub const SERVER: &'static str = "server";
    pub const ETAG: &'static str = "etag";
    pub const IF_NONE_MATCH: &'static str = "if-none-match";
    pub const AUTHORIZATION: &'static str = "authorization";

    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            lookup: HashMap::new(),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity),
            lookup: HashMap::with_capacity(capacity),
        }
    }

    /// Insert or replace header. Case-insensitive key comparison.
    pub fn insert(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let name_str = name.into();
        let key = name_str.to_ascii_lowercase();
        let val_str = value.into();

        if let Some(&idx) = self.lookup.get(&key) {
            self.entries[idx] = (name_str, val_str);
        } else {
            let idx = self.entries.len();
            self.entries.push((name_str, val_str));
            self.lookup.insert(key, idx);
        }
    }

    /// Append header without replacing previous entries with same key.
    pub fn append(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let name_str = name.into();
        let key = name_str.to_ascii_lowercase();
        let val_str = value.into();
        let idx = self.entries.len();
        self.entries.push((name_str, val_str));
        self.lookup.entry(key).or_insert(idx);
    }

    /// Get first matching header value (case-insensitive).
    pub fn get(&self, name: &str) -> Option<&str> {
        let key = name.to_ascii_lowercase();
        self.lookup
            .get(&key)
            .and_then(|&idx| self.entries.get(idx))
            .map(|(_, v)| v.as_str())
    }

    /// Get all matching header values in order of appearance (case-insensitive).
    pub fn get_all(&self, name: &str) -> Vec<&str> {
        let key = name.to_ascii_lowercase();
        self.entries
            .iter()
            .filter(|(k, _)| k.to_ascii_lowercase() == key)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    /// Check if a header exists.
    pub fn contains_key(&self, name: &str) -> bool {
        let key = name.to_ascii_lowercase();
        self.lookup.contains_key(&key)
    }

    /// Remove header by name (case-insensitive).
    pub fn remove(&mut self, name: &str) -> Option<String> {
        let key = name.to_ascii_lowercase();
        if let Some(removed_idx) = self.lookup.remove(&key) {
            let removed_val = self.entries.remove(removed_idx).1;
            self.lookup.clear();
            for (i, (k, _)) in self.entries.iter().enumerate() {
                self.lookup.entry(k.to_ascii_lowercase()).or_insert(i);
            }
            Some(removed_val)
        } else {
            None
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }
}

/// HTTP Request Header metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequestHead {
    pub method: HttpMethod,
    pub uri: String,
    pub version: HttpVersion,
    pub headers: HeaderMap,
}

impl HttpRequestHead {
    pub fn new(method: HttpMethod, uri: impl Into<String>, version: HttpVersion) -> Self {
        Self {
            method,
            uri: uri.into(),
            version,
            headers: HeaderMap::new(),
        }
    }

    /// Construct a standard HTTP/1.1 GET request head.
    pub fn get(uri: impl Into<String>) -> Self {
        Self::new(HttpMethod::Get, uri, HttpVersion::Http11)
    }

    /// Construct a standard HTTP/1.1 POST request head.
    pub fn post(uri: impl Into<String>) -> Self {
        Self::new(HttpMethod::Post, uri, HttpVersion::Http11)
    }

    /// Construct a standard HTTP/1.1 PUT request head.
    pub fn put(uri: impl Into<String>) -> Self {
        Self::new(HttpMethod::Put, uri, HttpVersion::Http11)
    }

    /// Construct a standard HTTP/1.1 DELETE request head.
    pub fn delete(uri: impl Into<String>) -> Self {
        Self::new(HttpMethod::Delete, uri, HttpVersion::Http11)
    }

    /// Add or update a header, returning self.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name, value);
        self
    }

    pub fn content_length(&self) -> Option<usize> {
        self.headers
            .get(HeaderMap::CONTENT_LENGTH)
            .and_then(|v| v.trim().parse::<usize>().ok())
    }

    pub fn is_chunked(&self) -> bool {
        self.headers
            .get(HeaderMap::TRANSFER_ENCODING)
            .map(|v| v.to_ascii_lowercase().contains("chunked"))
            .unwrap_or(false)
    }

    pub fn is_keep_alive(&self) -> bool {
        if let Some(conn) = self.headers.get(HeaderMap::CONNECTION) {
            let lower = conn.to_ascii_lowercase();
            if lower.contains("close") {
                return false;
            }
            if lower.contains("keep-alive") {
                return true;
            }
        }
        self.version == HttpVersion::Http11
    }
}

/// HTTP Response Header metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponseHead {
    pub version: HttpVersion,
    pub status: HttpStatus,
    pub headers: HeaderMap,
}

impl HttpResponseHead {
    pub fn new(status: HttpStatus, version: HttpVersion) -> Self {
        Self {
            version,
            status,
            headers: HeaderMap::new(),
        }
    }

    pub fn ok() -> Self {
        Self::new(HttpStatus::OK, HttpVersion::Http11)
    }

    /// Construct a standard 400 Bad Request response head.
    pub fn bad_request() -> Self {
        Self::new(HttpStatus::BAD_REQUEST, HttpVersion::Http11)
    }

    /// Construct a standard 404 Not Found response head.
    pub fn not_found() -> Self {
        Self::new(HttpStatus::NOT_FOUND, HttpVersion::Http11)
    }

    /// Construct a standard 500 Internal Server Error response head.
    pub fn internal_server_error() -> Self {
        Self::new(HttpStatus::INTERNAL_SERVER_ERROR, HttpVersion::Http11)
    }

    /// Add or update a header, returning self.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name, value);
        self
    }

    pub fn content_length(&self) -> Option<usize> {
        self.headers
            .get(HeaderMap::CONTENT_LENGTH)
            .and_then(|v| v.trim().parse::<usize>().ok())
    }

    pub fn is_chunked(&self) -> bool {
        self.headers
            .get(HeaderMap::TRANSFER_ENCODING)
            .map(|v| v.to_ascii_lowercase().contains("chunked"))
            .unwrap_or(false)
    }

    pub fn is_keep_alive(&self) -> bool {
        if let Some(conn) = self.headers.get(HeaderMap::CONNECTION) {
            let lower = conn.to_ascii_lowercase();
            if lower.contains("close") {
                return false;
            }
            if lower.contains("keep-alive") {
                return true;
            }
        }
        self.version == HttpVersion::Http11
    }
}

/// HTTP Parsing and Decoding Errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpParseError {
    Incomplete,
    InvalidMethod,
    InvalidUri,
    InvalidVersion,
    InvalidStatus,
    InvalidHeader,
    HeaderTooLarge,
    TooManyHeaders,
    InvalidChunkSize,
    InvalidChunkFraming,
    UnexpectedEof,
    Io(String),
}

impl fmt::Display for HttpParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpParseError::Incomplete => write!(f, "Incomplete HTTP message"),
            HttpParseError::InvalidMethod => write!(f, "Invalid HTTP method"),
            HttpParseError::InvalidUri => write!(f, "Invalid HTTP request URI"),
            HttpParseError::InvalidVersion => write!(f, "Unsupported or invalid HTTP version"),
            HttpParseError::InvalidStatus => write!(f, "Invalid HTTP status code"),
            HttpParseError::InvalidHeader => write!(f, "Malformed HTTP header"),
            HttpParseError::HeaderTooLarge => write!(f, "HTTP header exceeds allowed size"),
            HttpParseError::TooManyHeaders => write!(f, "Too many HTTP headers in request"),
            HttpParseError::InvalidChunkSize => write!(f, "Malformed chunked transfer size"),
            HttpParseError::InvalidChunkFraming => {
                write!(f, "Invalid chunk framing or missing CRLF")
            }
            HttpParseError::UnexpectedEof => write!(f, "Unexpected end of stream"),
            HttpParseError::Io(err) => write!(f, "I/O error during HTTP processing: {}", err),
        }
    }
}

impl std::error::Error for HttpParseError {}

impl From<io::Error> for HttpParseError {
    fn from(err: io::Error) -> Self {
        HttpParseError::Io(err.to_string())
    }
}

/// HTTP wire parser configuration with anti-DoS bounds.
#[derive(Debug, Clone, Copy)]
pub struct HttpParserConfig {
    pub max_request_line_len: usize,
    pub max_header_count: usize,
    pub max_header_size: usize,
    pub max_chunk_size: usize,
}

impl Default for HttpParserConfig {
    fn default() -> Self {
        Self {
            max_request_line_len: 8192,
            max_header_count: 128,
            max_header_size: 32768,
            max_chunk_size: 16 * 1024 * 1024,
        }
    }
}

/// Locate CRLF CRLF delimiter in buffer.
fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Parse HTTP/1.1 Request Head from byte slice.
/// Returns `Ok(Some((HttpRequestHead, consumed_bytes)))` if complete,
/// `Ok(None)` if more data is required, or `Err(HttpParseError)`.
pub fn parse_request_head(
    buf: &[u8],
    config: &HttpParserConfig,
) -> Result<Option<(HttpRequestHead, usize)>, HttpParseError> {
    let header_end = match find_headers_end(buf) {
        Some(pos) => pos,
        None => {
            if buf.len() > config.max_header_size {
                return Err(HttpParseError::HeaderTooLarge);
            }
            return Ok(None);
        }
    };

    if header_end > config.max_header_size {
        return Err(HttpParseError::HeaderTooLarge);
    }

    let header_bytes = &buf[..header_end];
    let header_text =
        std::str::from_utf8(header_bytes).map_err(|_| HttpParseError::InvalidHeader)?;

    let mut lines = header_text.split("\r\n");
    let req_line = lines.next().ok_or(HttpParseError::Incomplete)?;
    if req_line.len() > config.max_request_line_len {
        return Err(HttpParseError::InvalidUri);
    }

    let mut parts = req_line.split(' ');
    let method_str = parts.next().ok_or(HttpParseError::InvalidMethod)?;
    let uri_str = parts.next().ok_or(HttpParseError::InvalidUri)?;
    let version_str = parts.next().ok_or(HttpParseError::InvalidVersion)?;

    if parts.next().is_some() || uri_str.is_empty() {
        return Err(HttpParseError::InvalidUri);
    }

    let method = HttpMethod::from_bytes(method_str.as_bytes())?;
    let version = HttpVersion::from_bytes(version_str.as_bytes())?;

    let mut headers = HeaderMap::new();
    let mut count = 0;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        count += 1;
        if count > config.max_header_count {
            return Err(HttpParseError::TooManyHeaders);
        }
        if let Some((name, val)) = line.split_once(':') {
            headers.append(name.trim(), val.trim());
        } else {
            return Err(HttpParseError::InvalidHeader);
        }
    }

    let consumed = header_end + 4; // includes \r\n\r\n
    Ok(Some((
        HttpRequestHead {
            method,
            uri: uri_str.to_string(),
            version,
            headers,
        },
        consumed,
    )))
}

/// Parse HTTP/1.1 Response Head from byte slice.
/// Returns `Ok(Some((HttpResponseHead, consumed_bytes)))` if complete,
/// `Ok(None)` if more data is required, or `Err(HttpParseError)`.
pub fn parse_response_head(
    buf: &[u8],
    config: &HttpParserConfig,
) -> Result<Option<(HttpResponseHead, usize)>, HttpParseError> {
    let header_end = match find_headers_end(buf) {
        Some(pos) => pos,
        None => {
            if buf.len() > config.max_header_size {
                return Err(HttpParseError::HeaderTooLarge);
            }
            return Ok(None);
        }
    };

    if header_end > config.max_header_size {
        return Err(HttpParseError::HeaderTooLarge);
    }

    let header_bytes = &buf[..header_end];
    let header_text =
        std::str::from_utf8(header_bytes).map_err(|_| HttpParseError::InvalidHeader)?;

    let mut lines = header_text.split("\r\n");
    let status_line = lines.next().ok_or(HttpParseError::Incomplete)?;
    let mut parts = status_line.splitn(3, ' ');
    let version_str = parts.next().ok_or(HttpParseError::InvalidVersion)?;
    let status_code_str = parts.next().ok_or(HttpParseError::InvalidStatus)?;

    let version = HttpVersion::from_bytes(version_str.as_bytes())?;
    let code = status_code_str
        .parse::<u16>()
        .map_err(|_| HttpParseError::InvalidStatus)?;

    let mut headers = HeaderMap::new();
    let mut count = 0;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        count += 1;
        if count > config.max_header_count {
            return Err(HttpParseError::TooManyHeaders);
        }
        if let Some((name, val)) = line.split_once(':') {
            headers.append(name.trim(), val.trim());
        } else {
            return Err(HttpParseError::InvalidHeader);
        }
    }

    let consumed = header_end + 4; // includes \r\n\r\n
    Ok(Some((
        HttpResponseHead {
            version,
            status: HttpStatus(code),
            headers,
        },
        consumed,
    )))
}

/// A parsed chunk from an HTTP/1.1 Chunked stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Chunk {
    Data(Vec<u8>),
    End { trailers: HeaderMap },
}

/// Parse a single chunk from raw buffer.
/// Returns `Ok(Some((Chunk, consumed_bytes)))` if a chunk was successfully decoded,
/// `Ok(None)` if buffer is incomplete, or `Err(HttpParseError)`.
pub fn parse_chunk(
    buf: &[u8],
    max_chunk_size: usize,
) -> Result<Option<(Chunk, usize)>, HttpParseError> {
    let first_crlf = match buf.windows(2).position(|w| w == b"\r\n") {
        Some(pos) => pos,
        None => return Ok(None),
    };

    let size_line =
        std::str::from_utf8(&buf[..first_crlf]).map_err(|_| HttpParseError::InvalidChunkSize)?;
    // RFC 7230 §4.1.1: chunk-size [ chunk-ext ]
    let size_hex = size_line.split(';').next().unwrap_or("").trim();

    let chunk_len =
        usize::from_str_radix(size_hex, 16).map_err(|_| HttpParseError::InvalidChunkSize)?;

    if chunk_len > max_chunk_size {
        return Err(HttpParseError::InvalidChunkSize);
    }

    let chunk_data_start = first_crlf + 2;

    if chunk_len == 0 {
        // Final terminating chunk: may contain trailers ended by \r\n\r\n
        let remaining = &buf[chunk_data_start..];
        if remaining.starts_with(b"\r\n") {
            // No trailers, immediately finished: 0\r\n\r\n
            let consumed = chunk_data_start + 2;
            return Ok(Some((
                Chunk::End {
                    trailers: HeaderMap::new(),
                },
                consumed,
            )));
        }

        // Try finding \r\n\r\n for trailers
        if let Some(trailer_end) = remaining.windows(4).position(|w| w == b"\r\n\r\n") {
            let trailer_str = std::str::from_utf8(&remaining[..trailer_end])
                .map_err(|_| HttpParseError::InvalidHeader)?;
            let mut trailers = HeaderMap::new();
            for line in trailer_str.split("\r\n") {
                if let Some((k, v)) = line.split_once(':') {
                    trailers.append(k.trim(), v.trim());
                }
            }
            let consumed = chunk_data_start + trailer_end + 4;
            return Ok(Some((Chunk::End { trailers }, consumed)));
        }

        // Incomplete trailers
        return Ok(None);
    }

    let required_len = chunk_data_start + chunk_len + 2; // +2 for trailing \r\n
    if buf.len() < required_len {
        return Ok(None);
    }

    if &buf[chunk_data_start + chunk_len..required_len] != b"\r\n" {
        return Err(HttpParseError::InvalidChunkFraming);
    }

    let data = buf[chunk_data_start..chunk_data_start + chunk_len].to_vec();
    Ok(Some((Chunk::Data(data), required_len)))
}

/// Helper to decode an entire chunked body from a `BufRead` stream into a byte buffer.
pub fn decode_chunked_body<R: BufRead>(
    reader: &mut R,
    max_body_size: usize,
) -> Result<(Vec<u8>, HeaderMap), HttpParseError> {
    let mut body = Vec::new();
    let mut line_buf = String::new();

    loop {
        line_buf.clear();
        let bytes_read = reader
            .read_line(&mut line_buf)
            .map_err(|e| HttpParseError::Io(e.to_string()))?;
        if bytes_read == 0 {
            return Err(HttpParseError::UnexpectedEof);
        }

        let trimmed = line_buf.trim();
        let size_hex = trimmed.split(';').next().unwrap_or("").trim();
        let chunk_size =
            usize::from_str_radix(size_hex, 16).map_err(|_| HttpParseError::InvalidChunkSize)?;

        if chunk_size == 0 {
            // Read trailers until empty line
            let mut trailers = HeaderMap::new();
            loop {
                line_buf.clear();
                let tr_bytes = reader
                    .read_line(&mut line_buf)
                    .map_err(|e| HttpParseError::Io(e.to_string()))?;
                if tr_bytes == 0 {
                    break;
                }
                let t_line = line_buf.trim();
                if t_line.is_empty() {
                    break;
                }
                if let Some((k, v)) = t_line.split_once(':') {
                    trailers.append(k.trim(), v.trim());
                }
            }
            return Ok((body, trailers));
        }

        if body.len() + chunk_size > max_body_size {
            return Err(HttpParseError::InvalidChunkSize);
        }

        let mut chunk_buf = vec![0u8; chunk_size];
        reader
            .read_exact(&mut chunk_buf)
            .map_err(|e| HttpParseError::Io(e.to_string()))?;
        body.extend_from_slice(&chunk_buf);

        // Read and verify trailing \r\n
        let mut crlf = [0u8; 2];
        reader
            .read_exact(&mut crlf)
            .map_err(|e| HttpParseError::Io(e.to_string()))?;
        if &crlf != b"\r\n" {
            return Err(HttpParseError::InvalidChunkFraming);
        }
    }
}

/// Encode a data payload into an HTTP/1.1 chunk (`<hex-len>\r\n<data>\r\n`).
pub fn encode_chunk(data: &[u8]) -> Vec<u8> {
    let hex_len = format!("{:x}\r\n", data.len());
    let mut out = Vec::with_capacity(hex_len.len() + data.len() + 2);
    out.extend_from_slice(hex_len.as_bytes());
    out.extend_from_slice(data);
    out.extend_from_slice(b"\r\n");
    out
}

/// Write a single HTTP/1.1 chunk directly into a writer.
pub fn encode_chunk_to<W: Write>(writer: &mut W, data: &[u8]) -> io::Result<usize> {
    let header = format!("{:x}\r\n", data.len());
    writer.write_all(header.as_bytes())?;
    writer.write_all(data)?;
    writer.write_all(b"\r\n")?;
    Ok(header.len() + data.len() + 2)
}

/// Write terminating chunk (`0\r\n\r\n` or with optional trailers).
pub fn encode_chunk_end_to<W: Write>(
    writer: &mut W,
    trailers: Option<&HeaderMap>,
) -> io::Result<usize> {
    let mut written = 0;
    writer.write_all(b"0\r\n")?;
    written += 3;

    if let Some(headers) = trailers {
        for (k, v) in headers.iter() {
            let line = format!("{}: {}\r\n", k, v);
            writer.write_all(line.as_bytes())?;
            written += line.len();
        }
    }

    writer.write_all(b"\r\n")?;
    written += 2;
    Ok(written)
}

/// Format an `HttpRequestHead` into standard wire bytes.
pub fn format_request_head(head: &HttpRequestHead) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    let line = format!(
        "{} {} {}\r\n",
        head.method.as_str(),
        head.uri,
        head.version.as_str()
    );
    out.extend_from_slice(line.as_bytes());

    for (k, v) in head.headers.iter() {
        let h_line = format!("{}: {}\r\n", k, v);
        out.extend_from_slice(h_line.as_bytes());
    }

    out.extend_from_slice(b"\r\n");
    out
}

/// Format an `HttpResponseHead` into standard wire bytes.
pub fn format_response_head(head: &HttpResponseHead) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    let line = format!(
        "{} {} {}\r\n",
        head.version.as_str(),
        head.status.code(),
        head.status.reason_phrase()
    );
    out.extend_from_slice(line.as_bytes());

    for (k, v) in head.headers.iter() {
        let h_line = format!("{}: {}\r\n", k, v);
        out.extend_from_slice(h_line.as_bytes());
    }

    out.extend_from_slice(b"\r\n");
    out
}

/// Read an HTTP request (headers + body) from `BufferedTcpStream`.
pub fn read_request(
    stream: &mut BufferedTcpStream,
    max_body_size: usize,
) -> Result<Option<(HttpRequestHead, Vec<u8>)>, HttpParseError> {
    let config = HttpParserConfig::default();
    let mut header_buf = Vec::new();

    // Read header line by line
    loop {
        let line = stream
            .read_line()
            .map_err(|e| HttpParseError::Io(e.to_string()))?;
        match line {
            Some(l) if l.is_empty() => {
                header_buf.extend_from_slice(b"\r\n");
                break;
            }
            Some(l) => {
                header_buf.extend_from_slice(l.as_bytes());
                header_buf.extend_from_slice(b"\r\n");
                if header_buf.len() > config.max_header_size {
                    return Err(HttpParseError::HeaderTooLarge);
                }
            }
            None => {
                if header_buf.is_empty() {
                    return Ok(None);
                } else {
                    return Err(HttpParseError::UnexpectedEof);
                }
            }
        }
    }

    let (head, _) = parse_request_head(&header_buf, &config)?.ok_or(HttpParseError::Incomplete)?;

    let body = if head.is_chunked() {
        let (chunked_body, _) = decode_chunked_body(stream, max_body_size)?;
        chunked_body
    } else if let Some(len) = head.content_length() {
        if len > max_body_size {
            return Err(HttpParseError::Io("Payload too large".to_string()));
        }
        let mut body_buf = vec![0u8; len];
        stream
            .read_exact(&mut body_buf)
            .map_err(|e| HttpParseError::Io(e.to_string()))?;
        body_buf
    } else {
        Vec::new()
    };

    Ok(Some((head, body)))
}

/// Read an HTTP response (headers + body) from `BufferedTcpStream`.
pub fn read_response(
    stream: &mut BufferedTcpStream,
    max_body_size: usize,
) -> Result<Option<(HttpResponseHead, Vec<u8>)>, HttpParseError> {
    let config = HttpParserConfig::default();
    let mut header_buf = Vec::new();

    loop {
        let line = stream
            .read_line()
            .map_err(|e| HttpParseError::Io(e.to_string()))?;
        match line {
            Some(l) if l.is_empty() => {
                header_buf.extend_from_slice(b"\r\n");
                break;
            }
            Some(l) => {
                header_buf.extend_from_slice(l.as_bytes());
                header_buf.extend_from_slice(b"\r\n");
                if header_buf.len() > config.max_header_size {
                    return Err(HttpParseError::HeaderTooLarge);
                }
            }
            None => {
                if header_buf.is_empty() {
                    return Ok(None);
                } else {
                    return Err(HttpParseError::UnexpectedEof);
                }
            }
        }
    }

    let (head, _) = parse_response_head(&header_buf, &config)?.ok_or(HttpParseError::Incomplete)?;

    // Handle body framing
    let body = if head.status == HttpStatus::NO_CONTENT || head.status == HttpStatus::NOT_MODIFIED {
        Vec::new()
    } else if head.is_chunked() {
        let (chunked_body, _) = decode_chunked_body(stream, max_body_size)?;
        chunked_body
    } else if let Some(len) = head.content_length() {
        if len > max_body_size {
            return Err(HttpParseError::Io("Payload too large".to_string()));
        }
        let mut body_buf = vec![0u8; len];
        stream
            .read_exact(&mut body_buf)
            .map_err(|e| HttpParseError::Io(e.to_string()))?;
        body_buf
    } else if !head.is_keep_alive() {
        // Read until EOF
        let mut body_buf = Vec::new();
        stream
            .read_to_end(&mut body_buf)
            .map_err(|e| HttpParseError::Io(e.to_string()))?;
        if body_buf.len() > max_body_size {
            return Err(HttpParseError::Io("Payload too large".to_string()));
        }
        body_buf
    } else {
        Vec::new()
    };

    Ok(Some((head, body)))
}

/// Write a complete HTTP request with body and flush to `BufferedTcpStream`.
pub fn write_request_full(
    stream: &mut BufferedTcpStream,
    head: &HttpRequestHead,
    body: &[u8],
) -> io::Result<()> {
    let mut head_clone = head.clone();
    if !head_clone.headers.contains_key(HeaderMap::CONTENT_LENGTH) && !head_clone.is_chunked() {
        head_clone
            .headers
            .insert(HeaderMap::CONTENT_LENGTH, body.len().to_string());
    }

    let wire_head = format_request_head(&head_clone);
    stream.write_all(&wire_head)?;
    if !body.is_empty() {
        stream.write_all(body)?;
    }
    stream.flush()
}

/// Write a complete HTTP response with body and flush to `BufferedTcpStream`.
pub fn write_response_full(
    stream: &mut BufferedTcpStream,
    head: &HttpResponseHead,
    body: &[u8],
) -> io::Result<()> {
    let mut head_clone = head.clone();
    if !head_clone.headers.contains_key(HeaderMap::CONTENT_LENGTH) && !head_clone.is_chunked() {
        head_clone
            .headers
            .insert(HeaderMap::CONTENT_LENGTH, body.len().to_string());
    }

    let wire_head = format_response_head(&head_clone);
    stream.write_all(&wire_head)?;
    if !body.is_empty() {
        stream.write_all(body)?;
    }
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{TcpListener, TcpStream};
    use std::io::Cursor;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_http_version_and_method() {
        assert_eq!(
            HttpVersion::from_bytes(b"HTTP/1.1").unwrap(),
            HttpVersion::Http11
        );
        assert_eq!(
            HttpVersion::from_bytes(b"HTTP/1.0").unwrap(),
            HttpVersion::Http10
        );
        assert!(HttpVersion::from_bytes(b"HTTP/2.0").is_err());

        assert_eq!(HttpMethod::from_bytes(b"GET").unwrap(), HttpMethod::Get);
        assert_eq!(HttpMethod::from_bytes(b"POST").unwrap(), HttpMethod::Post);
        assert_eq!(HttpMethod::from_bytes(b"PUT").unwrap(), HttpMethod::Put);
        assert_eq!(
            HttpMethod::from_bytes(b"DELETE").unwrap(),
            HttpMethod::Delete
        );
        assert_eq!(HttpMethod::from_bytes(b"PATCH").unwrap(), HttpMethod::Patch);
        assert_eq!(HttpMethod::from_bytes(b"HEAD").unwrap(), HttpMethod::Head);
        assert_eq!(
            HttpMethod::from_bytes(b"OPTIONS").unwrap(),
            HttpMethod::Options
        );
        assert!(HttpMethod::from_bytes(b"INVALID").is_err());
    }

    #[test]
    fn test_http_status_codes_and_predicates() {
        let s200 = HttpStatus::OK;
        assert_eq!(s200.code(), 200);
        assert_eq!(s200.reason_phrase(), "OK");
        assert!(s200.is_success());
        assert!(!s200.is_client_error());

        let s404 = HttpStatus::NOT_FOUND;
        assert_eq!(s404.code(), 404);
        assert_eq!(s404.reason_phrase(), "Not Found");
        assert!(s404.is_client_error());
        assert!(!s404.is_server_error());

        let s503 = HttpStatus::SERVICE_UNAVAILABLE;
        assert!(s503.is_server_error());

        let s301 = HttpStatus::MOVED_PERMANENTLY;
        assert!(s301.is_redirection());

        let s100 = HttpStatus::CONTINUE;
        assert!(s100.is_informational());
    }

    #[test]
    fn test_header_map_operations() {
        let mut map = HeaderMap::new();
        map.insert("Content-Type", "application/json");
        map.insert("host", "example.com:8080");

        assert_eq!(map.get("content-type"), Some("application/json"));
        assert_eq!(map.get("CONTENT-TYPE"), Some("application/json"));
        assert_eq!(map.get("Host"), Some("example.com:8080"));
        assert!(map.contains_key("HOST"));
        assert!(!map.contains_key("Authorization"));

        // Overwrite
        map.insert("Host", "ifa-lang.org");
        assert_eq!(map.get("host"), Some("ifa-lang.org"));
        assert_eq!(map.len(), 2);

        // Remove
        let removed = map.remove("CONTENT-TYPE");
        assert_eq!(removed, Some("application/json".to_string()));
        assert!(!map.contains_key("Content-Type"));
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn test_parse_request_and_response_heads() {
        let config = HttpParserConfig::default();

        let req_raw = b"POST /api/v1/resource HTTP/1.1\r\nHost: localhost\r\nContent-Length: 13\r\nConnection: keep-alive\r\n\r\n";
        let (req_head, consumed) = parse_request_head(req_raw, &config).unwrap().unwrap();
        assert_eq!(consumed, req_raw.len());
        assert_eq!(req_head.method, HttpMethod::Post);
        assert_eq!(req_head.uri, "/api/v1/resource");
        assert_eq!(req_head.version, HttpVersion::Http11);
        assert_eq!(req_head.content_length(), Some(13));
        assert!(req_head.is_keep_alive());
        assert!(!req_head.is_chunked());

        let resp_raw = b"HTTP/1.1 201 Created\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n";
        let (resp_head, resp_consumed) = parse_response_head(resp_raw, &config).unwrap().unwrap();
        assert_eq!(resp_consumed, resp_raw.len());
        assert_eq!(resp_head.version, HttpVersion::Http11);
        assert_eq!(resp_head.status, HttpStatus::CREATED);
        assert!(resp_head.is_chunked());
        assert!(resp_head.is_keep_alive());
    }

    #[test]
    fn test_chunked_codec_and_trailers() {
        // Encode chunk
        let chunk1 = encode_chunk(b"Hello ");
        assert_eq!(chunk1, b"6\r\nHello \r\n");

        let chunk2 = encode_chunk(b"World!");
        assert_eq!(chunk2, b"6\r\nWorld!\r\n");

        // Parse chunk incrementally
        let (parsed1, n1) = parse_chunk(&chunk1, 1024).unwrap().unwrap();
        assert_eq!(n1, chunk1.len());
        assert_eq!(parsed1, Chunk::Data(b"Hello ".to_vec()));

        // Terminating chunk with trailers
        let mut trailers = HeaderMap::new();
        trailers.insert("X-Checksum", "a1b2c3d4");

        let mut stream_buf = Vec::new();
        stream_buf.extend_from_slice(&chunk1);
        stream_buf.extend_from_slice(&chunk2);
        encode_chunk_end_to(&mut stream_buf, Some(&trailers)).unwrap();

        let mut cursor = Cursor::new(stream_buf);
        let (body, parsed_trailers) = decode_chunked_body(&mut cursor, 4096).unwrap();
        assert_eq!(&body, b"Hello World!");
        assert_eq!(parsed_trailers.get("X-Checksum"), Some("a1b2c3d4"));
    }

    #[test]
    fn test_buffered_tcp_stream_http_integration() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.port().expect("local port");

        let handle = thread::spawn(move || {
            let mut server_raw = None;
            for _ in 0..100 {
                if let Ok(Some((stream, _))) = listener.try_accept() {
                    server_raw = Some(stream);
                    break;
                }
                thread::sleep(Duration::from_millis(5));
            }
            let server_raw = server_raw.expect("accepted server stream");
            server_raw.set_nonblocking(false).expect("blocking server");
            let mut server_buf = BufferedTcpStream::new(server_raw).expect("server buffered");

            // Read request from client
            let (req_head, req_body) = read_request(&mut server_buf, 65536)
                .expect("read_request")
                .expect("request head present");

            assert_eq!(req_head.method, HttpMethod::Post);
            assert_eq!(req_head.uri, "/echo");
            assert_eq!(&req_body, b"ping-payload");

            // Write chunked response to client
            let mut resp_head = HttpResponseHead::new(HttpStatus::OK, HttpVersion::Http11);
            resp_head.headers.insert("Transfer-Encoding", "chunked");
            resp_head.headers.insert("Content-Type", "text/plain");

            let wire_head = format_response_head(&resp_head);
            server_buf
                .write_all(&wire_head)
                .expect("write response head");
            encode_chunk_to(&mut server_buf, b"pong-").expect("chunk 1");
            encode_chunk_to(&mut server_buf, b"payload").expect("chunk 2");
            encode_chunk_end_to(&mut server_buf, None).expect("end chunk");
            server_buf.flush().expect("flush server");
        });

        // Client side
        let raw_client = TcpStream::connect(format!("127.0.0.1:{}", port)).expect("connect client");
        raw_client.set_nonblocking(false).expect("blocking client");
        let mut client_buf = BufferedTcpStream::new(raw_client).expect("client buffered");

        let mut req_head = HttpRequestHead::new(HttpMethod::Post, "/echo", HttpVersion::Http11);
        req_head.headers.insert("Host", "localhost");
        write_request_full(&mut client_buf, &req_head, b"ping-payload")
            .expect("write request full");

        let (resp_head, resp_body) = read_response(&mut client_buf, 65536)
            .expect("read response")
            .expect("response present");

        assert_eq!(resp_head.status, HttpStatus::OK);
        assert_eq!(&resp_body, b"pong-payload");

        handle.join().expect("server thread finished");
    }

    #[test]
    fn test_header_map_multi_and_builders() {
        let mut headers = HeaderMap::new();
        headers.append("Set-Cookie", "sid=123; Path=/");
        headers.append("SET-COOKIE", "theme=dark; Path=/");
        headers.append("Accept", "text/html");

        let cookies = headers.get_all("set-cookie");
        assert_eq!(cookies.len(), 2);
        assert_eq!(cookies[0], "sid=123; Path=/");
        assert_eq!(cookies[1], "theme=dark; Path=/");

        let req = HttpRequestHead::get("/api/v1/items")
            .with_header("Host", "example.com")
            .with_header("Accept", "application/json");
        assert_eq!(req.method, HttpMethod::Get);
        assert_eq!(req.uri, "/api/v1/items");
        assert_eq!(req.headers.get("host"), Some("example.com"));
        assert_eq!(req.headers.get("accept"), Some("application/json"));

        let resp_ok = HttpResponseHead::ok().with_header("Content-Type", "application/json");
        assert_eq!(resp_ok.status, HttpStatus::OK);
        assert_eq!(
            resp_ok.headers.get("content-type"),
            Some("application/json")
        );

        let resp_nf = HttpResponseHead::not_found();
        assert_eq!(resp_nf.status, HttpStatus::NOT_FOUND);

        let resp_br = HttpResponseHead::bad_request();
        assert_eq!(resp_br.status, HttpStatus::BAD_REQUEST);

        let resp_err = HttpResponseHead::internal_server_error();
        assert_eq!(resp_err.status, HttpStatus::INTERNAL_SERVER_ERROR);
    }
}

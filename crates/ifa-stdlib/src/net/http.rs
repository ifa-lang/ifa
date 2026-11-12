//! Minimalist HTTP/1.1 wire parser, serializer, and chunked transfer codec over `BufferedTcpStream` (`std::net::http`).

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io::{self, BufRead, Read, Write};
use std::time::Duration;

use super::{BufferedTcpStream, TcpStream};

pub use crate::http::{MultipartBuilder, MultipartPart};

/// Extract the boundary parameter from a `multipart/form-data` Content-Type value (RFC 2046 / RFC 7578).
pub fn extract_multipart_boundary(content_type: &str) -> Option<String> {
    for part in content_type.split(';') {
        let trimmed = part.trim();
        if let Some(rest) = trimmed.strip_prefix("boundary=") {
            let val = rest.trim().trim_matches('"');
            if !val.is_empty() {
                return Some(val.to_string());
            }
        }
    }
    None
}

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
    pub fn as_u16(&self) -> u16 {
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
    pub const CACHE_CONTROL: &'static str = "cache-control";
    pub const UPGRADE: &'static str = "upgrade";
    pub const KEEP_ALIVE: &'static str = "keep-alive";
    pub const PROXY_AUTHENTICATE: &'static str = "proxy-authenticate";
    pub const PROXY_AUTHORIZATION: &'static str = "proxy-authorization";
    pub const TE: &'static str = "te";
    pub const TRAILER: &'static str = "trailer";
    pub const PROXY_CONNECTION: &'static str = "proxy-connection";
    pub const FORWARDED: &'static str = "forwarded";
    pub const X_FORWARDED_FOR: &'static str = "x-forwarded-for";
    pub const X_FORWARDED_PROTO: &'static str = "x-forwarded-proto";
    pub const X_FORWARDED_HOST: &'static str = "x-forwarded-host";
    pub const ACCEPT_ENCODING: &'static str = "accept-encoding";
    pub const CONTENT_ENCODING: &'static str = "content-encoding";

    /// Standard hop-by-hop headers as defined in RFC 7230 §6.1 and related specs.
    pub const HOP_BY_HOP_HEADERS: &'static [&'static str] = &[
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "proxy-connection",
    ];

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

    /// Check if a header name is a standard hop-by-hop header (case-insensitive).
    pub fn is_hop_by_hop(name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        Self::HOP_BY_HOP_HEADERS.iter().any(|&h| h == lower)
    }

    /// Extract connection option tokens specified in the `Connection` header(s).
    pub fn connection_tokens(&self) -> Vec<String> {
        let mut tokens = Vec::new();
        for val in self.get_all("connection") {
            for token in val.split(',') {
                let trimmed = token.trim();
                if !trimmed.is_empty() {
                    tokens.push(trimmed.to_ascii_lowercase());
                }
            }
        }
        tokens
    }

    /// Check if this HeaderMap contains any hop-by-hop headers (standard or in Connection header).
    pub fn contains_hop_by_hop(&self) -> bool {
        let conn_tokens = self.connection_tokens();
        for (k, _) in self.entries.iter() {
            let lower = k.to_ascii_lowercase();
            if Self::is_hop_by_hop(&lower) || conn_tokens.contains(&lower) {
                return true;
            }
        }
        false
    }

    /// Strip all hop-by-hop headers as required by RFC 7230 intermediaries and gateways:
    /// removes standard hop-by-hop headers, all headers listed in the `Connection` header,
    /// and the `Connection` header itself.
    pub fn strip_hop_by_hop(&mut self) {
        let mut to_remove: HashSet<String> = self.connection_tokens().into_iter().collect();
        for &h in Self::HOP_BY_HOP_HEADERS {
            to_remove.insert(h.to_string());
        }

        self.entries
            .retain(|(k, _)| !to_remove.contains(&k.to_ascii_lowercase()));
        self.lookup.clear();
        for (i, (k, _)) in self.entries.iter().enumerate() {
            self.lookup.entry(k.to_ascii_lowercase()).or_insert(i);
        }
    }

    /// Check if a header name is valid according to RFC 7230 §3.2.6 token rules.
    pub fn is_valid_name(name: &str) -> bool {
        if name.is_empty() {
            return false;
        }
        name.bytes().all(|b| {
            matches!(
                b,
                b'a'..=b'z'
                    | b'A'..=b'Z'
                    | b'0'..=b'9'
                    | b'!'
                    | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'|'
                    | b'~'
            )
        })
    }

    /// Check if a header value is valid (prevents CRLF injection and NUL byte poisoning).
    pub fn is_valid_value(value: &str) -> bool {
        !value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
    }

    /// Attempt to insert a header, returning an error if the name or value fails RFC validation.
    pub fn try_insert(
        &mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<(), HttpParseError> {
        let name_str = name.into();
        let val_str = value.into();
        if !Self::is_valid_name(&name_str) || !Self::is_valid_value(&val_str) {
            return Err(HttpParseError::InvalidHeader);
        }
        self.insert(name_str, val_str);
        Ok(())
    }

    /// Attempt to append a header, returning an error if the name or value fails RFC validation.
    pub fn try_append(
        &mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<(), HttpParseError> {
        let name_str = name.into();
        let val_str = value.into();
        if !Self::is_valid_name(&name_str) || !Self::is_valid_value(&val_str) {
            return Err(HttpParseError::InvalidHeader);
        }
        self.append(name_str, val_str);
        Ok(())
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

    /// Construct a standard HTTP/1.1 PATCH request head.
    pub fn patch(uri: impl Into<String>) -> Self {
        Self::new(HttpMethod::Patch, uri, HttpVersion::Http11)
    }

    /// Construct a standard HTTP/1.1 HEAD request head.
    pub fn head(uri: impl Into<String>) -> Self {
        Self::new(HttpMethod::Head, uri, HttpVersion::Http11)
    }

    /// Construct a standard HTTP/1.1 OPTIONS request head.
    pub fn options(uri: impl Into<String>) -> Self {
        Self::new(HttpMethod::Options, uri, HttpVersion::Http11)
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

    /// Return the Content-Type header value if present.
    pub fn content_type(&self) -> Option<&str> {
        self.headers.get(HeaderMap::CONTENT_TYPE)
    }

    /// Check if Content-Type is application/json.
    pub fn is_json(&self) -> bool {
        self.content_type()
            .map(|ct| ct.to_ascii_lowercase().contains("application/json"))
            .unwrap_or(false)
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

    /// Extract parsed cookies from request `Cookie` header.
    pub fn cookies(&self) -> Vec<Cookie> {
        match self.headers.get("cookie") {
            Some(v) => Cookie::parse_header(v),
            None => Vec::new(),
        }
    }

    /// Check if Content-Type is multipart/form-data.
    pub fn is_multipart(&self) -> bool {
        self.headers
            .get("content-type")
            .map(|ct| ct.to_ascii_lowercase().contains("multipart/form-data"))
            .unwrap_or(false)
    }

    /// Extract multipart boundary if present in Content-Type header.
    pub fn multipart_boundary(&self) -> Option<String> {
        self.headers
            .get("content-type")
            .and_then(extract_multipart_boundary)
    }

    /// Check if Content-Type is application/x-www-form-urlencoded.
    pub fn is_form_urlencoded(&self) -> bool {
        self.headers
            .get("content-type")
            .map(|ct| {
                ct.to_ascii_lowercase()
                    .contains("application/x-www-form-urlencoded")
            })
            .unwrap_or(false)
    }

    /// Return the path portion of the URI (excluding any query string or fragment).
    pub fn path(&self) -> &str {
        let uri = self.uri.as_str();
        let end_idx = uri.find(['?', '#']).unwrap_or(uri.len());
        &uri[..end_idx]
    }

    /// Return the optional query string of the URI (excluding the leading '?').
    pub fn query_string(&self) -> Option<&str> {
        let uri = self.uri.as_str();
        if let Some(q_idx) = uri.find('?') {
            let after_q = &uri[q_idx + 1..];
            let end_idx = after_q.find('#').unwrap_or(after_q.len());
            Some(&after_q[..end_idx])
        } else {
            None
        }
    }

    /// Parse URI query parameters into a key-value map.
    pub fn query_params(&self) -> HashMap<String, String> {
        match self.query_string() {
            Some(qs) => crate::http::parse_form_urlencoded(qs),
            None => HashMap::new(),
        }
    }

    /// Extract parsed `Cache-Control` directive from request headers.
    pub fn cache_control(&self) -> Option<CacheControl> {
        self.headers.get("cache-control").map(CacheControl::parse)
    }

    /// Return the raw Authorization header value if present.
    pub fn authorization(&self) -> Option<&str> {
        self.headers.get(HeaderMap::AUTHORIZATION)
    }

    /// Extract Bearer token from Authorization header (RFC 6750).
    pub fn bearer_token(&self) -> Option<String> {
        self.authorization().and_then(parse_bearer_token)
    }

    /// Extract Basic Auth credentials (username, password) from Authorization header.
    pub fn basic_auth(&self) -> Option<(String, String)> {
        self.authorization().and_then(parse_basic_auth)
    }

    /// Set standard Bearer token in Authorization header.
    pub fn set_bearer_auth(&mut self, token: impl AsRef<str>) {
        self.headers.insert(
            HeaderMap::AUTHORIZATION,
            format!("Bearer {}", token.as_ref()),
        );
    }

    /// Set standard Basic Authentication credentials in Authorization header.
    pub fn set_basic_auth(&mut self, username: &str, password: &str) {
        self.headers.insert(
            HeaderMap::AUTHORIZATION,
            encode_basic_auth(username, password),
        );
    }

    /// Strip hop-by-hop headers from this request head.
    pub fn strip_hop_by_hop_headers(&mut self) {
        self.headers.strip_hop_by_hop();
    }

    /// Return a copy of this request head with all hop-by-hop headers stripped.
    pub fn with_hop_by_hop_stripped(mut self) -> Self {
        self.headers.strip_hop_by_hop();
        self
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

    /// Construct a standard 201 Created response head.
    pub fn created() -> Self {
        Self::new(HttpStatus::CREATED, HttpVersion::Http11)
    }

    /// Construct a standard 202 Accepted response head.
    pub fn accepted() -> Self {
        Self::new(HttpStatus::ACCEPTED, HttpVersion::Http11)
    }

    /// Construct a standard 204 No Content response head.
    pub fn no_content() -> Self {
        Self::new(HttpStatus::NO_CONTENT, HttpVersion::Http11)
    }

    /// Construct a standard 400 Bad Request response head.
    pub fn bad_request() -> Self {
        Self::new(HttpStatus::BAD_REQUEST, HttpVersion::Http11)
    }

    /// Construct a standard 401 Unauthorized response head.
    pub fn unauthorized() -> Self {
        Self::new(HttpStatus::UNAUTHORIZED, HttpVersion::Http11)
    }

    /// Construct a standard 403 Forbidden response head.
    pub fn forbidden() -> Self {
        Self::new(HttpStatus::FORBIDDEN, HttpVersion::Http11)
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

    /// Return the Content-Type header value if present.
    pub fn content_type(&self) -> Option<&str> {
        self.headers.get(HeaderMap::CONTENT_TYPE)
    }

    /// Check if Content-Type is application/json.
    pub fn is_json(&self) -> bool {
        self.content_type()
            .map(|ct| ct.to_ascii_lowercase().contains("application/json"))
            .unwrap_or(false)
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

    /// Extract parsed `Set-Cookie` directives from response headers.
    pub fn set_cookies(&self) -> Vec<SetCookie> {
        self.headers
            .get_all("set-cookie")
            .into_iter()
            .filter_map(SetCookie::parse)
            .collect()
    }

    /// Extract parsed `Cache-Control` directive from response headers.
    pub fn cache_control(&self) -> Option<CacheControl> {
        self.headers.get("cache-control").map(CacheControl::parse)
    }

    /// Return the Location header value if present (e.g. for redirects).
    pub fn location(&self) -> Option<&str> {
        self.headers.get(HeaderMap::LOCATION)
    }

    /// Check if Content-Type is multipart/form-data.
    pub fn is_multipart(&self) -> bool {
        self.headers
            .get("content-type")
            .map(|ct| ct.to_ascii_lowercase().contains("multipart/form-data"))
            .unwrap_or(false)
    }

    /// Extract multipart boundary if present in Content-Type header.
    pub fn multipart_boundary(&self) -> Option<String> {
        self.headers
            .get("content-type")
            .and_then(extract_multipart_boundary)
    }

    /// Check if Content-Type is application/x-www-form-urlencoded.
    pub fn is_form_urlencoded(&self) -> bool {
        self.headers
            .get("content-type")
            .map(|ct| {
                ct.to_ascii_lowercase()
                    .contains("application/x-www-form-urlencoded")
            })
            .unwrap_or(false)
    }

    /// Strip hop-by-hop headers from this response head.
    pub fn strip_hop_by_hop_headers(&mut self) {
        self.headers.strip_hop_by_hop();
    }

    /// Return a copy of this response head with all hop-by-hop headers stripped.
    pub fn with_hop_by_hop_stripped(mut self) -> Self {
        self.headers.strip_hop_by_hop();
        self
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

impl Chunk {
    /// Whether this is a terminating chunk (`Chunk::End`).
    pub fn is_end(&self) -> bool {
        matches!(self, Chunk::End { .. })
    }

    /// Return data bytes if this is a data chunk.
    pub fn data(&self) -> Option<&[u8]> {
        match self {
            Chunk::Data(d) => Some(d.as_slice()),
            Chunk::End { .. } => None,
        }
    }

    /// Number of bytes in this chunk payload.
    pub fn len(&self) -> usize {
        match self {
            Chunk::Data(d) => d.len(),
            Chunk::End { .. } => 0,
        }
    }

    /// Whether this chunk payload is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
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

/// Read the next individual HTTP chunk from a buffered reader.
/// Returns `Ok(Some(Chunk::Data(bytes)))` for data chunks,
/// `Ok(Some(Chunk::End { trailers }))` for the final chunk (size 0),
/// or `Ok(None)` if the reader reached EOF before any chunk header was read.
pub fn read_next_chunk<R: BufRead>(
    reader: &mut R,
    max_chunk_size: usize,
) -> Result<Option<Chunk>, HttpParseError> {
    let mut line_buf = String::new();
    let bytes_read = reader
        .read_line(&mut line_buf)
        .map_err(|e| HttpParseError::Io(e.to_string()))?;
    if bytes_read == 0 {
        return Ok(None);
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
        return Ok(Some(Chunk::End { trailers }));
    }

    if chunk_size > max_chunk_size {
        return Err(HttpParseError::InvalidChunkSize);
    }

    let mut chunk_buf = vec![0u8; chunk_size];
    reader
        .read_exact(&mut chunk_buf)
        .map_err(|e| HttpParseError::Io(e.to_string()))?;

    // Read and verify trailing \r\n
    let mut crlf = [0u8; 2];
    reader
        .read_exact(&mut crlf)
        .map_err(|e| HttpParseError::Io(e.to_string()))?;
    if &crlf != b"\r\n" {
        return Err(HttpParseError::InvalidChunkFraming);
    }

    Ok(Some(Chunk::Data(chunk_buf)))
}

/// Streaming chunk iterator wrapping a buffered reader.
pub struct ChunkStream<R: BufRead> {
    reader: R,
    max_chunk_size: usize,
    finished: bool,
    trailers: HeaderMap,
}

impl<R: BufRead> ChunkStream<R> {
    /// Create a new `ChunkStream` over a buffered reader.
    pub fn new(reader: R, max_chunk_size: usize) -> Self {
        Self {
            reader,
            max_chunk_size,
            finished: false,
            trailers: HeaderMap::new(),
        }
    }

    /// Read next chunk from the stream. Returns `None` once `Chunk::End` or EOF has been encountered.
    pub fn next_chunk(&mut self) -> Result<Option<Chunk>, HttpParseError> {
        if self.finished {
            return Ok(None);
        }
        match read_next_chunk(&mut self.reader, self.max_chunk_size)? {
            Some(Chunk::End { trailers }) => {
                self.finished = true;
                self.trailers = trailers.clone();
                Ok(Some(Chunk::End { trailers }))
            }
            Some(Chunk::Data(data)) => Ok(Some(Chunk::Data(data))),
            None => {
                self.finished = true;
                Ok(None)
            }
        }
    }

    /// Decoded trailers if the stream has finished.
    pub fn trailers(&self) -> &HeaderMap {
        &self.trailers
    }

    /// Whether the stream reached the terminating end-chunk.
    pub fn is_finished(&self) -> bool {
        self.finished
    }

    /// Reference to the underlying reader.
    pub fn get_ref(&self) -> &R {
        &self.reader
    }

    /// Mutable reference to the underlying reader.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.reader
    }

    /// Unwrap the inner reader.
    pub fn into_inner(self) -> R {
        self.reader
    }
}

/// Helper to decode an entire chunked body from a `BufRead` stream into a byte buffer.
pub fn decode_chunked_body<R: BufRead>(
    reader: &mut R,
    max_body_size: usize,
) -> Result<(Vec<u8>, HeaderMap), HttpParseError> {
    let mut body = Vec::new();
    loop {
        match read_next_chunk(reader, max_body_size)? {
            Some(Chunk::Data(data)) => {
                if body.len() + data.len() > max_body_size {
                    return Err(HttpParseError::InvalidChunkSize);
                }
                body.extend_from_slice(&data);
            }
            Some(Chunk::End { trailers }) => return Ok((body, trailers)),
            None => return Err(HttpParseError::UnexpectedEof),
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

/// Streaming chunked HTTP/1.1 body writer (`Transfer-Encoding: chunked`).
pub struct ChunkedWriter<W: Write> {
    writer: W,
    finished: bool,
}

impl<W: Write> ChunkedWriter<W> {
    /// Create a new `ChunkedWriter` wrapping an underlying byte writer.
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            finished: false,
        }
    }

    /// Write an explicit chunk of data to the stream.
    pub fn write_chunk(&mut self, chunk: &[u8]) -> io::Result<usize> {
        if self.finished {
            return Err(io::Error::other(
                "Cannot write to already finalized ChunkedWriter",
            ));
        }
        if chunk.is_empty() {
            return Ok(0);
        }
        encode_chunk_to(&mut self.writer, chunk)
    }

    /// Finalize the chunked stream with an end-chunk (`0\r\n\r\n`) and optional trailers.
    pub fn finish(&mut self, trailers: Option<&HeaderMap>) -> io::Result<usize> {
        if self.finished {
            return Ok(0);
        }
        self.finished = true;
        let bytes = encode_chunk_end_to(&mut self.writer, trailers)?;
        self.writer.flush()?;
        Ok(bytes)
    }

    /// Whether this chunked stream has been terminated with a closing chunk.
    pub fn is_finished(&self) -> bool {
        self.finished
    }

    /// Reference to the underlying writer.
    pub fn get_ref(&self) -> &W {
        &self.writer
    }

    /// Mutable reference to the underlying writer.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.writer
    }

    /// Unwrap the inner writer.
    pub fn into_inner(self) -> W {
        self.writer
    }
}

impl<W: Write> Write for ChunkedWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.write_chunk(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

/// Streaming chunked HTTP/1.1 body reader implementing `std::io::Read`.
pub struct ChunkedReader<R: BufRead> {
    reader: R,
    remaining_chunk_bytes: usize,
    first_chunk: bool,
    finished: bool,
    max_chunk_size: usize,
    trailers: HeaderMap,
}

impl<R: BufRead> ChunkedReader<R> {
    /// Create a new `ChunkedReader` over a buffered input stream.
    pub fn new(reader: R, max_chunk_size: usize) -> Self {
        Self {
            reader,
            remaining_chunk_bytes: 0,
            first_chunk: true,
            finished: false,
            max_chunk_size,
            trailers: HeaderMap::new(),
        }
    }

    /// Decoded HTTP trailers parsed at the end of the chunked payload.
    pub fn trailers(&self) -> &HeaderMap {
        &self.trailers
    }

    /// Whether the stream reached the final terminating chunk (size 0).
    pub fn is_finished(&self) -> bool {
        self.finished
    }

    /// Reference to the inner reader.
    pub fn get_ref(&self) -> &R {
        &self.reader
    }

    /// Mutable reference to the inner reader.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.reader
    }

    /// Consume the `ChunkedReader` and return the underlying reader.
    pub fn into_inner(self) -> R {
        self.reader
    }
}

impl<R: BufRead> Read for ChunkedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.finished {
            return Ok(0);
        }

        while self.remaining_chunk_bytes == 0 {
            // Consume CRLF following previous chunk
            if !self.first_chunk {
                let mut crlf = [0u8; 2];
                self.reader.read_exact(&mut crlf)?;
                if &crlf != b"\r\n" {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Missing CRLF delimiter after chunk data",
                    ));
                }
            }
            self.first_chunk = false;

            // Read chunk-size line
            let mut line = String::new();
            let bytes_read = self.reader.read_line(&mut line)?;
            if bytes_read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Unexpected EOF while reading chunk size",
                ));
            }

            let trimmed = line.trim();
            let size_str = trimmed.split(';').next().unwrap_or("").trim();
            let chunk_size = usize::from_str_radix(size_str, 16).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Invalid hex chunk size '{}': {}", size_str, e),
                )
            })?;

            if chunk_size > self.max_chunk_size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Chunk size {} exceeds configured maximum {}",
                        chunk_size, self.max_chunk_size
                    ),
                ));
            }

            if chunk_size == 0 {
                // Final terminating chunk: parse optional trailers until empty line
                loop {
                    let mut trailer_line = String::new();
                    let t_bytes = self.reader.read_line(&mut trailer_line)?;
                    if t_bytes == 0 {
                        break;
                    }
                    let t_trimmed = trailer_line.trim_end_matches(['\r', '\n']);
                    if t_trimmed.is_empty() {
                        break;
                    }
                    if let Some((k, v)) = t_trimmed.split_once(':') {
                        self.trailers.insert(k.trim(), v.trim());
                    }
                }
                self.finished = true;
                return Ok(0);
            }

            self.remaining_chunk_bytes = chunk_size;
        }

        let to_read = buf.len().min(self.remaining_chunk_bytes);
        let n = self.reader.read(&mut buf[..to_read])?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Unexpected EOF while reading chunk body data",
            ));
        }
        self.remaining_chunk_bytes -= n;
        Ok(n)
    }
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

/// Read an `HttpRequestHead` from a buffered reader up to the empty line separating headers from body.
pub fn read_request_head<R: BufRead>(
    reader: &mut R,
    config: Option<&HttpParserConfig>,
) -> Result<Option<HttpRequestHead>, HttpParseError> {
    let default_cfg = HttpParserConfig::default();
    let cfg = config.unwrap_or(&default_cfg);
    let mut header_buf = Vec::new();
    let mut line = String::new();

    loop {
        line.clear();
        let bytes_read = reader
            .read_line(&mut line)
            .map_err(|e| HttpParseError::Io(e.to_string()))?;
        if bytes_read == 0 {
            if header_buf.is_empty() {
                return Ok(None);
            } else {
                return Err(HttpParseError::UnexpectedEof);
            }
        }

        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            header_buf.extend_from_slice(b"\r\n");
            break;
        }

        header_buf.extend_from_slice(trimmed.as_bytes());
        header_buf.extend_from_slice(b"\r\n");
        if header_buf.len() > cfg.max_header_size {
            return Err(HttpParseError::HeaderTooLarge);
        }
    }

    let (head, _) = parse_request_head(&header_buf, cfg)?.ok_or(HttpParseError::Incomplete)?;
    Ok(Some(head))
}

/// Read an `HttpResponseHead` from a buffered reader up to the empty line separating headers from body.
pub fn read_response_head<R: BufRead>(
    reader: &mut R,
    config: Option<&HttpParserConfig>,
) -> Result<Option<HttpResponseHead>, HttpParseError> {
    let default_cfg = HttpParserConfig::default();
    let cfg = config.unwrap_or(&default_cfg);
    let mut header_buf = Vec::new();
    let mut line = String::new();

    loop {
        line.clear();
        let bytes_read = reader
            .read_line(&mut line)
            .map_err(|e| HttpParseError::Io(e.to_string()))?;
        if bytes_read == 0 {
            if header_buf.is_empty() {
                return Ok(None);
            } else {
                return Err(HttpParseError::UnexpectedEof);
            }
        }

        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            header_buf.extend_from_slice(b"\r\n");
            break;
        }

        header_buf.extend_from_slice(trimmed.as_bytes());
        header_buf.extend_from_slice(b"\r\n");
        if header_buf.len() > cfg.max_header_size {
            return Err(HttpParseError::HeaderTooLarge);
        }
    }

    let (head, _) = parse_response_head(&header_buf, cfg)?.ok_or(HttpParseError::Incomplete)?;
    Ok(Some(head))
}

/// Read an HTTP request (headers + body) from `BufferedTcpStream`.
pub fn read_request(
    stream: &mut BufferedTcpStream,
    max_body_size: usize,
) -> Result<Option<(HttpRequestHead, Vec<u8>)>, HttpParseError> {
    let head = match read_request_head(stream, None)? {
        Some(h) => h,
        None => return Ok(None),
    };

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
    let head = match read_response_head(stream, None)? {
        Some(h) => h,
        None => return Ok(None),
    };

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

/// Write an `HttpRequestHead` to a writer and flush.
pub fn write_request_head<W: Write>(writer: &mut W, head: &HttpRequestHead) -> io::Result<()> {
    let wire_head = format_request_head(head);
    writer.write_all(&wire_head)?;
    writer.flush()
}

/// Write an `HttpResponseHead` to a writer and flush.
pub fn write_response_head<W: Write>(writer: &mut W, head: &HttpResponseHead) -> io::Result<()> {
    let wire_head = format_response_head(head);
    writer.write_all(&wire_head)?;
    writer.flush()
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

/// A single HTTP cookie key-value pair (`Cookie` request header).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cookie {
    pub name: String,
    pub value: String,
}

impl Cookie {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }

    /// Parse multiple cookies from a `Cookie` request header value.
    pub fn parse_header(value: &str) -> Vec<Cookie> {
        let mut list = Vec::new();
        for part in value.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if let Some((k, v)) = part.split_once('=') {
                list.push(Cookie::new(k.trim(), v.trim()));
            }
        }
        list
    }

    /// Format a slice of cookies into standard `Cookie` header string value.
    pub fn format_cookies(cookies: &[Cookie]) -> String {
        cookies
            .iter()
            .map(|c| format!("{}={}", c.name, c.value))
            .collect::<Vec<_>>()
            .join("; ")
    }
}

impl fmt::Display for Cookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={}", self.name, self.value)
    }
}

/// A parsed `Set-Cookie` response header directive (RFC 6265).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetCookie {
    pub name: String,
    pub value: String,
    pub expires: Option<String>,
    pub max_age: Option<i64>,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: Option<String>,
}

impl SetCookie {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            expires: None,
            max_age: None,
            domain: None,
            path: None,
            secure: false,
            http_only: false,
            same_site: None,
        }
    }

    /// Parse a `Set-Cookie` header value.
    pub fn parse(value: &str) -> Option<Self> {
        let mut parts = value.split(';');
        let first = parts.next()?.trim();
        let (name, val) = first.split_once('=')?;

        let mut cookie = SetCookie::new(name.trim(), val.trim());
        for attr in parts {
            let attr = attr.trim();
            if attr.is_empty() {
                continue;
            }
            if let Some((k, v)) = attr.split_once('=') {
                let k_lower = k.trim().to_ascii_lowercase();
                let v = v.trim();
                match k_lower.as_str() {
                    "expires" => cookie.expires = Some(v.to_string()),
                    "max-age" => cookie.max_age = v.parse::<i64>().ok(),
                    "domain" => cookie.domain = Some(v.to_string()),
                    "path" => cookie.path = Some(v.to_string()),
                    "samesite" => cookie.same_site = Some(v.to_string()),
                    _ => {}
                }
            } else {
                let attr_lower = attr.to_ascii_lowercase();
                match attr_lower.as_str() {
                    "secure" => cookie.secure = true,
                    "httponly" => cookie.http_only = true,
                    _ => {}
                }
            }
        }
        Some(cookie)
    }

    /// Format to wire `Set-Cookie` header value string.
    pub fn to_header_value(&self) -> String {
        let mut parts = vec![format!("{}={}", self.name, self.value)];
        if let Some(ref exp) = self.expires {
            parts.push(format!("Expires={}", exp));
        }
        if let Some(max_age) = self.max_age {
            parts.push(format!("Max-Age={}", max_age));
        }
        if let Some(ref dom) = self.domain {
            parts.push(format!("Domain={}", dom));
        }
        if let Some(ref p) = self.path {
            parts.push(format!("Path={}", p));
        }
        if self.secure {
            parts.push("Secure".to_string());
        }
        if self.http_only {
            parts.push("HttpOnly".to_string());
        }
        if let Some(ref ss) = self.same_site {
            parts.push(format!("SameSite={}", ss));
        }
        parts.join("; ")
    }
}

impl fmt::Display for SetCookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_header_value())
    }
}

/// Parsed HTTP `Cache-Control` header directives (RFC 7234).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CacheControl {
    pub no_cache: bool,
    pub no_store: bool,
    pub no_transform: bool,
    pub must_revalidate: bool,
    pub public: bool,
    pub private: bool,
    pub max_age: Option<u64>,
    pub s_maxage: Option<u64>,
}

impl CacheControl {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse from `Cache-Control` header value.
    pub fn parse(value: &str) -> Self {
        let mut cc = CacheControl::default();
        for part in value.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if let Some((k, v)) = part.split_once('=') {
                let k_lower = k.trim().to_ascii_lowercase();
                let v = v.trim().trim_matches('"');
                match k_lower.as_str() {
                    "max-age" => cc.max_age = v.parse::<u64>().ok(),
                    "s-maxage" => cc.s_maxage = v.parse::<u64>().ok(),
                    _ => {}
                }
            } else {
                let part_lower = part.to_ascii_lowercase();
                match part_lower.as_str() {
                    "no-cache" => cc.no_cache = true,
                    "no-store" => cc.no_store = true,
                    "no-transform" => cc.no_transform = true,
                    "must-revalidate" => cc.must_revalidate = true,
                    "public" => cc.public = true,
                    "private" => cc.private = true,
                    _ => {}
                }
            }
        }
        cc
    }

    /// Format to wire `Cache-Control` header value string.
    pub fn to_header_value(&self) -> String {
        let mut parts = Vec::new();
        if self.public {
            parts.push("public".to_string());
        }
        if self.private {
            parts.push("private".to_string());
        }
        if self.no_cache {
            parts.push("no-cache".to_string());
        }
        if self.no_store {
            parts.push("no-store".to_string());
        }
        if self.no_transform {
            parts.push("no-transform".to_string());
        }
        if self.must_revalidate {
            parts.push("must-revalidate".to_string());
        }
        if let Some(ma) = self.max_age {
            parts.push(format!("max-age={}", ma));
        }
        if let Some(sma) = self.s_maxage {
            parts.push(format!("s-maxage={}", sma));
        }
        parts.join(", ")
    }
}

impl fmt::Display for CacheControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_header_value())
    }
}

/// Encode username and password into a standard HTTP Basic Authorization header value.
pub fn encode_basic_auth(username: &str, password: &str) -> String {
    let creds = format!("{}:{}", username, password);
    let encoded = crate::crypto::base64_encode(creds.as_bytes());
    format!("Basic {}", encoded)
}

/// Parse HTTP Basic Authentication credentials from an Authorization header value.
pub fn parse_basic_auth(header_val: &str) -> Option<(String, String)> {
    let trimmed = header_val.trim();
    if trimmed.len() < 6 {
        return None;
    }
    let (scheme, rest) = trimmed.split_at(6);
    if !scheme.eq_ignore_ascii_case("basic ") {
        return None;
    }
    let decoded_bytes = crate::crypto::base64_decode(rest.trim()).ok()?;
    let decoded_str = String::from_utf8(decoded_bytes).ok()?;
    let (user, pass) = decoded_str.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}

/// Parse Bearer token from an Authorization header value (RFC 6750).
pub fn parse_bearer_token(header_val: &str) -> Option<String> {
    let trimmed = header_val.trim();
    if trimmed.len() < 7 {
        return None;
    }
    let (scheme, rest) = trimmed.split_at(7);
    if !scheme.eq_ignore_ascii_case("bearer ") {
        return None;
    }
    let token = rest.trim();
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

/// Parsed HTTP URL (RFC 3986 basic subset).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpUrl {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path_and_query: String,
}

impl HttpUrl {
    /// Parse an HTTP URL string (e.g. "http://localhost:8080/api/v1?k=v" or "http://example.com/").
    pub fn parse(url: &str) -> Result<Self, HttpClientError> {
        let (scheme, rest) = if let Some((s, rem)) = url.split_once("://") {
            (s.to_ascii_lowercase(), rem)
        } else {
            ("http".to_string(), url)
        };

        if scheme != "http" {
            if scheme == "https" {
                return Err(HttpClientError::UnsupportedScheme(
                    "HTTPS is not supported without TLS".to_string(),
                ));
            }
            return Err(HttpClientError::UnsupportedScheme(scheme));
        }

        let (host_port, path_and_query) = match rest.find('/') {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, "/"),
        };

        if host_port.is_empty() {
            return Err(HttpClientError::InvalidUrl("Empty host in URL".to_string()));
        }

        let (host, port) = if let Some((h, p)) = host_port.split_once(':') {
            let parsed_port = p
                .parse::<u16>()
                .map_err(|_| HttpClientError::InvalidUrl(format!("Invalid port: '{}'", p)))?;
            (h.to_string(), parsed_port)
        } else {
            (host_port.to_string(), 80)
        };

        let path = if path_and_query.is_empty() {
            "/".to_string()
        } else {
            path_and_query.to_string()
        };

        Ok(Self {
            scheme,
            host,
            port,
            path_and_query: path,
        })
    }

    /// Return host:port format for TCP socket connection.
    pub fn socket_addr_str(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// Format standard Host header value (omits :80 if default HTTP port).
    pub fn host_header_value(&self) -> String {
        if self.port == 80 {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// Resolve a possibly relative redirect target against this base URL.
    pub fn join(&self, location: &str) -> Result<Self, HttpClientError> {
        if location.starts_with("http://") || location.starts_with("https://") {
            HttpUrl::parse(location)
        } else if location.starts_with('/') {
            Ok(Self {
                scheme: self.scheme.clone(),
                host: self.host.clone(),
                port: self.port,
                path_and_query: location.to_string(),
            })
        } else {
            let base_dir = match self.path_and_query.rfind('/') {
                Some(idx) => &self.path_and_query[..=idx],
                None => "/",
            };
            Ok(Self {
                scheme: self.scheme.clone(),
                host: self.host.clone(),
                port: self.port,
                path_and_query: format!("{}{}", base_dir, location),
            })
        }
    }

    /// Check if target host is loopback (localhost, 127.x.x.x, ::1).
    pub fn is_loopback(&self) -> bool {
        let host = self.host.to_ascii_lowercase();
        if host == "localhost" || host == "::1" || host == "[::1]" {
            return true;
        }
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            return ip.is_loopback();
        }
        host.starts_with("127.")
    }

    /// Check if target host is an internal/private or local network address (RFC 1918, link-local, loopback).
    pub fn is_private_or_local(&self) -> bool {
        if self.is_loopback() {
            return true;
        }
        let host = self.host.to_ascii_lowercase();
        if host.ends_with(".local")
            || host.ends_with(".localhost")
            || host.ends_with(".internal")
            || host == "local"
        {
            return true;
        }
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            match ip {
                std::net::IpAddr::V4(ipv4) => {
                    let oct = ipv4.octets();
                    oct[0] == 10
                        || (oct[0] == 172 && (16..=31).contains(&oct[1]))
                        || (oct[0] == 192 && oct[1] == 168)
                        || (oct[0] == 169 && oct[1] == 254)
                        || oct[0] == 0
                        || oct[0] == 127
                }
                std::net::IpAddr::V6(ipv6) => {
                    ipv6.is_loopback()
                        || ipv6.is_unspecified()
                        || (ipv6.segments()[0] & 0xfe00) == 0xfc00
                        || (ipv6.segments()[0] & 0xffc0) == 0xfe80
                }
            }
        } else {
            false
        }
    }

    /// Format standard origin string: scheme://host[:port].
    pub fn origin(&self) -> String {
        format!("{}://{}", self.scheme, self.host_header_value())
    }
}

impl fmt::Display for HttpUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}://{}{}",
            self.scheme,
            self.host_header_value(),
            self.path_and_query
        )
    }
}

/// Error type for synchronous HTTP client operations.
#[derive(Debug)]
pub enum HttpClientError {
    Io(io::Error),
    Parse(HttpParseError),
    InvalidUrl(String),
    UnsupportedScheme(String),
    TooManyRedirects,
    ConnectionFailed(String),
    Timeout,
    SecurityViolation(String),
}

impl fmt::Display for HttpClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpClientError::Io(err) => write!(f, "HTTP client I/O error: {}", err),
            HttpClientError::Parse(err) => write!(f, "HTTP client parse error: {}", err),
            HttpClientError::InvalidUrl(msg) => write!(f, "Invalid HTTP URL: {}", msg),
            HttpClientError::UnsupportedScheme(scheme) => {
                write!(f, "Unsupported HTTP scheme '{}'", scheme)
            }
            HttpClientError::TooManyRedirects => write!(f, "Too many HTTP redirects exceeded"),
            HttpClientError::ConnectionFailed(msg) => write!(f, "Connection failed: {}", msg),
            HttpClientError::Timeout => write!(f, "HTTP operation timed out"),
            HttpClientError::SecurityViolation(msg) => {
                write!(f, "HTTP client security violation: {}", msg)
            }
        }
    }
}

impl std::error::Error for HttpClientError {}

impl From<io::Error> for HttpClientError {
    fn from(err: io::Error) -> Self {
        HttpClientError::Io(err)
    }
}

impl From<HttpParseError> for HttpClientError {
    fn from(err: HttpParseError) -> Self {
        HttpClientError::Parse(err)
    }
}

/// High-level HTTP Request wrapper containing head and decoded body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub head: HttpRequestHead,
    pub body: Vec<u8>,
}

impl HttpRequest {
    pub fn new(head: HttpRequestHead, body: Vec<u8>) -> Self {
        Self { head, body }
    }

    /// Construct a standard GET request.
    pub fn get(uri: impl Into<String>) -> Self {
        Self::new(HttpRequestHead::get(uri), Vec::new())
    }

    /// Construct a standard POST request with body and optional content type.
    pub fn post(uri: impl Into<String>, body: Vec<u8>, content_type: Option<&str>) -> Self {
        let mut head = HttpRequestHead::post(uri);
        if let Some(ct) = content_type {
            head.headers.insert("Content-Type", ct);
        }
        Self::new(head, body)
    }

    /// Construct a standard PUT request with body and optional content type.
    pub fn put(uri: impl Into<String>, body: Vec<u8>, content_type: Option<&str>) -> Self {
        let mut head = HttpRequestHead::put(uri);
        if let Some(ct) = content_type {
            head.headers.insert("Content-Type", ct);
        }
        Self::new(head, body)
    }

    /// Construct a standard DELETE request.
    pub fn delete(uri: impl Into<String>) -> Self {
        Self::new(HttpRequestHead::delete(uri), Vec::new())
    }

    /// Construct a standard PATCH request with body and optional content type.
    pub fn patch(uri: impl Into<String>, body: Vec<u8>, content_type: Option<&str>) -> Self {
        let mut head = HttpRequestHead::patch(uri);
        if let Some(ct) = content_type {
            head.headers.insert("Content-Type", ct);
        }
        Self::new(head, body)
    }

    /// Construct a standard HEAD request.
    pub fn head(uri: impl Into<String>) -> Self {
        Self::new(HttpRequestHead::head(uri), Vec::new())
    }

    /// Construct a standard OPTIONS request.
    pub fn options(uri: impl Into<String>) -> Self {
        Self::new(HttpRequestHead::options(uri), Vec::new())
    }

    /// Construct a request with a serialized JSON payload.
    pub fn json_payload<T: serde::Serialize>(
        uri: impl Into<String>,
        method: HttpMethod,
        payload: &T,
    ) -> Result<Self, serde_json::Error> {
        let bytes = serde_json::to_vec(payload)?;
        let mut head = HttpRequestHead::new(method, uri, HttpVersion::Http11);
        head.headers.insert("Content-Type", "application/json");
        Ok(Self::new(head, bytes))
    }

    /// Add or update a header on the request head, returning self.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.head.headers.insert(name, value);
        self
    }

    pub fn method(&self) -> HttpMethod {
        self.head.method
    }

    pub fn uri(&self) -> &str {
        &self.head.uri
    }

    pub fn path(&self) -> &str {
        self.head.path()
    }

    pub fn query_string(&self) -> Option<&str> {
        self.head.query_string()
    }

    pub fn query_params(&self) -> HashMap<String, String> {
        self.head.query_params()
    }

    pub fn version(&self) -> HttpVersion {
        self.head.version
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.head.headers
    }

    pub fn headers_mut(&mut self) -> &mut HeaderMap {
        &mut self.head.headers
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.head.headers.get(name)
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn text(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.body)
    }

    pub fn text_lossy(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.body)
    }

    /// Deserialize the request body as JSON.
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_slice(&self.body)
    }

    pub fn content_length(&self) -> Option<usize> {
        self.head.content_length()
    }

    pub fn content_type(&self) -> Option<&str> {
        self.head.content_type()
    }

    pub fn is_json(&self) -> bool {
        self.head.is_json()
    }

    pub fn is_chunked(&self) -> bool {
        self.head.is_chunked()
    }

    pub fn is_keep_alive(&self) -> bool {
        self.head.is_keep_alive()
    }

    pub fn cookies(&self) -> Vec<Cookie> {
        self.head.cookies()
    }

    pub fn cache_control(&self) -> Option<CacheControl> {
        self.head.cache_control()
    }

    pub fn authorization(&self) -> Option<&str> {
        self.head.authorization()
    }

    pub fn bearer_token(&self) -> Option<String> {
        self.head.bearer_token()
    }

    pub fn basic_auth(&self) -> Option<(String, String)> {
        self.head.basic_auth()
    }

    /// Add or update Bearer authorization header, returning self.
    pub fn with_bearer_auth(mut self, token: impl AsRef<str>) -> Self {
        self.head.set_bearer_auth(token);
        self
    }

    /// Add or update Basic authorization header, returning self.
    pub fn with_basic_auth(mut self, username: &str, password: &str) -> Self {
        self.head.set_basic_auth(username, password);
        self
    }

    pub fn is_multipart(&self) -> bool {
        self.head.is_multipart()
    }

    pub fn multipart_boundary(&self) -> Option<String> {
        self.head.multipart_boundary()
    }

    pub fn multipart(&self) -> Result<Vec<MultipartPart>, String> {
        let boundary = self.multipart_boundary().ok_or_else(|| {
            "Missing or invalid multipart boundary in Content-Type header".to_string()
        })?;
        crate::http::parse_multipart(&self.body, &boundary)
    }

    pub fn is_form_urlencoded(&self) -> bool {
        self.head.is_form_urlencoded()
    }

    pub fn form_data(&self) -> Result<HashMap<String, String>, String> {
        let text = self.text().map_err(|e| e.to_string())?;
        Ok(crate::http::parse_form_urlencoded(text))
    }

    pub fn into_parts(self) -> (HttpRequestHead, Vec<u8>) {
        (self.head, self.body)
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.body
    }

    /// Strip hop-by-hop headers from this request.
    pub fn strip_hop_by_hop_headers(&mut self) {
        self.head.strip_hop_by_hop_headers();
    }

    /// Return a copy of this request with all hop-by-hop headers stripped.
    pub fn with_hop_by_hop_stripped(mut self) -> Self {
        self.head.strip_hop_by_hop_headers();
        self
    }
}

/// High-level HTTP Response wrapper containing head and decoded body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub head: HttpResponseHead,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn new(head: HttpResponseHead, body: Vec<u8>) -> Self {
        Self { head, body }
    }

    /// Construct a standard 200 OK response with body and optional content type.
    pub fn ok(body: Vec<u8>, content_type: Option<&str>) -> Self {
        let mut head = HttpResponseHead::ok();
        if let Some(ct) = content_type {
            head.headers.insert("Content-Type", ct);
        }
        Self::new(head, body)
    }

    /// Construct a plain text response with the given status code and UTF-8 body.
    pub fn plain_text(status: HttpStatus, text: impl Into<String>) -> Self {
        let mut head = HttpResponseHead::new(status, HttpVersion::Http11);
        head.headers
            .insert("Content-Type", "text/plain; charset=utf-8");
        Self::new(head, text.into().into_bytes())
    }

    /// Construct an HTTP response with serialized JSON payload.
    pub fn json_payload<T: serde::Serialize>(
        status: HttpStatus,
        payload: &T,
    ) -> Result<Self, serde_json::Error> {
        let bytes = serde_json::to_vec(payload)?;
        let mut head = HttpResponseHead::new(status, HttpVersion::Http11);
        head.headers.insert("Content-Type", "application/json");
        Ok(Self::new(head, bytes))
    }

    /// Construct an empty response with the given status code.
    pub fn empty(status: HttpStatus) -> Self {
        Self::new(
            HttpResponseHead::new(status, HttpVersion::Http11),
            Vec::new(),
        )
    }

    /// Construct a redirection response with Location header.
    pub fn redirect(status: HttpStatus, location: impl Into<String>) -> Self {
        let mut head = HttpResponseHead::new(status, HttpVersion::Http11);
        head.headers.insert("Location", location);
        Self::new(head, Vec::new())
    }

    /// Add or update a header on the response head, returning self.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.head.headers.insert(name, value);
        self
    }

    /// Check if the status code is informational (1xx).
    pub fn is_informational(&self) -> bool {
        self.head.status.is_informational()
    }

    /// Check if the status code is success (2xx).
    pub fn is_success(&self) -> bool {
        self.head.status.is_success()
    }

    /// Check if the status code is redirection (3xx).
    pub fn is_redirection(&self) -> bool {
        self.head.status.is_redirection()
    }

    /// Check if the status code is a client error (4xx).
    pub fn is_client_error(&self) -> bool {
        self.head.status.is_client_error()
    }

    /// Check if the status code is a server error (5xx).
    pub fn is_server_error(&self) -> bool {
        self.head.status.is_server_error()
    }

    /// Return the numeric HTTP status code.
    pub fn status_code(&self) -> u16 {
        self.head.status.as_u16()
    }

    /// Return the standard HTTP reason phrase.
    pub fn reason_phrase(&self) -> &'static str {
        self.head.status.reason_phrase()
    }

    pub fn status(&self) -> HttpStatus {
        self.head.status
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.head.headers
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn text(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.body)
    }

    pub fn text_lossy(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.body)
    }

    pub fn content_length(&self) -> Option<usize> {
        self.head.content_length()
    }

    pub fn content_type(&self) -> Option<&str> {
        self.head.content_type()
    }

    pub fn is_json(&self) -> bool {
        self.head.is_json()
    }

    pub fn location(&self) -> Option<&str> {
        self.head.location()
    }

    pub fn is_chunked(&self) -> bool {
        self.head.is_chunked()
    }

    pub fn is_keep_alive(&self) -> bool {
        self.head.is_keep_alive()
    }

    pub fn set_cookies(&self) -> Vec<SetCookie> {
        self.head.set_cookies()
    }

    pub fn cache_control(&self) -> Option<CacheControl> {
        self.head.cache_control()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.body
    }

    /// Deserialize the response body as JSON.
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_slice(&self.body)
    }

    /// Check if Content-Type is multipart/form-data.
    pub fn is_multipart(&self) -> bool {
        self.head.is_multipart()
    }

    /// Extract multipart boundary if present in Content-Type header.
    pub fn multipart_boundary(&self) -> Option<String> {
        self.head.multipart_boundary()
    }

    /// Parse multipart form-data body (RFC 7578 / RFC 2046) using Content-Type boundary.
    pub fn multipart(&self) -> Result<Vec<MultipartPart>, String> {
        let boundary = self.multipart_boundary().ok_or_else(|| {
            "Missing or invalid multipart boundary in Content-Type header".to_string()
        })?;
        crate::http::parse_multipart(&self.body, &boundary)
    }

    /// Check if Content-Type is application/x-www-form-urlencoded.
    pub fn is_form_urlencoded(&self) -> bool {
        self.head.is_form_urlencoded()
    }

    /// Parse application/x-www-form-urlencoded body into key-value map.
    pub fn form_data(&self) -> Result<HashMap<String, String>, String> {
        let text = self.text().map_err(|e| e.to_string())?;
        Ok(crate::http::parse_form_urlencoded(text))
    }

    pub fn version(&self) -> HttpVersion {
        self.head.version
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.head.headers.get(name)
    }

    pub fn headers_mut(&mut self) -> &mut HeaderMap {
        &mut self.head.headers
    }

    pub fn into_parts(self) -> (HttpResponseHead, Vec<u8>) {
        (self.head, self.body)
    }

    /// Strip hop-by-hop headers from this response.
    pub fn strip_hop_by_hop_headers(&mut self) {
        self.head.strip_hop_by_hop_headers();
    }

    /// Return a copy of this response with all hop-by-hop headers stripped.
    pub fn with_hop_by_hop_stripped(mut self) -> Self {
        self.head.strip_hop_by_hop_headers();
        self
    }
}

/// Read a full HTTP request with its body from a `BufferedTcpStream` into an `HttpRequest` object.
pub fn read_request_object(
    stream: &mut BufferedTcpStream,
    max_body_size: usize,
) -> Result<Option<HttpRequest>, HttpParseError> {
    match read_request(stream, max_body_size)? {
        Some((head, body)) => Ok(Some(HttpRequest::new(head, body))),
        None => Ok(None),
    }
}

/// Read a full HTTP response with its body from a `BufferedTcpStream` into an `HttpResponse` object.
pub fn read_response_object(
    stream: &mut BufferedTcpStream,
    max_body_size: usize,
) -> Result<Option<HttpResponse>, HttpParseError> {
    match read_response(stream, max_body_size)? {
        Some((head, body)) => Ok(Some(HttpResponse::new(head, body))),
        None => Ok(None),
    }
}

/// Write an `HttpRequest` object and its body to `BufferedTcpStream`.
pub fn write_http_request(stream: &mut BufferedTcpStream, request: &HttpRequest) -> io::Result<()> {
    write_request_full(stream, &request.head, &request.body)
}

/// Write an `HttpResponse` object and its body to `BufferedTcpStream`.
pub fn write_http_response(
    stream: &mut BufferedTcpStream,
    response: &HttpResponse,
) -> io::Result<()> {
    write_response_full(stream, &response.head, &response.body)
}

/// Synchronous HTTP Client built on top of `BufferedTcpStream`.
#[derive(Debug, Clone)]
pub struct HttpClient {
    pub timeout: Option<Duration>,
    pub max_body_size: usize,
    pub follow_redirects: bool,
    pub max_redirects: usize,
    pub allow_private_networks: bool,
    pub strip_hop_by_hop_headers: bool,
    pub default_headers: HeaderMap,
}

impl Default for HttpClient {
    fn default() -> Self {
        let mut default_headers = HeaderMap::new();
        default_headers.insert("User-Agent", "ifa-stdlib-http/1.0");
        default_headers.insert("Accept", "*/*");
        Self {
            timeout: Some(Duration::from_secs(30)),
            max_body_size: 16 * 1024 * 1024,
            follow_redirects: true,
            max_redirects: 5,
            allow_private_networks: true,
            strip_hop_by_hop_headers: true,
            default_headers,
        }
    }
}

impl HttpClient {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn builder() -> HttpClientBuilder {
        HttpClientBuilder::new()
    }

    /// Execute a raw request against target host:port.
    pub fn execute(
        &self,
        host_port: &str,
        mut head: HttpRequestHead,
        body: &[u8],
    ) -> Result<HttpResponse, HttpClientError> {
        let raw_stream = TcpStream::connect(host_port)
            .map_err(|e| HttpClientError::ConnectionFailed(format!("{}: {}", host_port, e)))?;

        raw_stream.set_nonblocking(false)?;
        if let Some(to) = self.timeout {
            raw_stream.set_read_timeout(Some(to))?;
            raw_stream.set_write_timeout(Some(to))?;
        }

        let mut buffered = BufferedTcpStream::new(raw_stream)?;

        // Apply default headers if absent
        for (k, v) in self.default_headers.iter() {
            if !head.headers.contains_key(k) {
                head.headers.insert(k, v);
            }
        }

        write_request_full(&mut buffered, &head, body)?;

        let (resp_head, resp_body) = read_response(&mut buffered, self.max_body_size)?
            .ok_or(HttpParseError::UnexpectedEof)?;

        Ok(HttpResponse::new(resp_head, resp_body))
    }

    /// Perform an HTTP request following redirects if enabled.
    pub fn request(
        &self,
        method: HttpMethod,
        url: &str,
        body: &[u8],
    ) -> Result<HttpResponse, HttpClientError> {
        self.request_with_headers(method, url, &HeaderMap::new(), body)
    }

    /// Perform an HTTP request with explicit custom headers, following redirects if enabled.
    pub fn request_with_headers(
        &self,
        method: HttpMethod,
        url: &str,
        extra_headers: &HeaderMap,
        body: &[u8],
    ) -> Result<HttpResponse, HttpClientError> {
        let mut current_url = HttpUrl::parse(url)?;
        let mut current_method = method;
        let mut current_body = body.to_vec();
        let mut redirects_followed = 0;

        loop {
            if !self.allow_private_networks && current_url.is_private_or_local() {
                return Err(HttpClientError::SecurityViolation(format!(
                    "Blocked request to private/local network address '{}'",
                    current_url.host
                )));
            }

            let mut head = HttpRequestHead::new(
                current_method,
                current_url.path_and_query.clone(),
                HttpVersion::Http11,
            );
            head.headers.insert("Host", current_url.host_header_value());

            for (k, v) in extra_headers.iter() {
                head.headers.insert(k, v);
            }

            if self.strip_hop_by_hop_headers {
                head.strip_hop_by_hop_headers();
            }
            head.headers.insert("Connection", "close");

            let host_port = current_url.socket_addr_str();
            let response = self.execute(&host_port, head, &current_body)?;

            if self.follow_redirects && response.status().is_redirection() {
                if redirects_followed >= self.max_redirects {
                    return Err(HttpClientError::TooManyRedirects);
                }

                if let Some(location) = response.location() {
                    current_url = current_url.join(location)?;
                    redirects_followed += 1;

                    // RFC 7231 §6.4.2 & §6.4.3: 301/302/303 often change POST/PUT to GET
                    if response.status() == HttpStatus::SEE_OTHER
                        || ((response.status() == HttpStatus::MOVED_PERMANENTLY
                            || response.status() == HttpStatus::FOUND)
                            && (current_method == HttpMethod::Post
                                || current_method == HttpMethod::Put))
                    {
                        current_method = HttpMethod::Get;
                        current_body.clear();
                    }
                    continue;
                }
            }

            return Ok(response);
        }
    }

    /// Send a GET request.
    pub fn get(&self, url: &str) -> Result<HttpResponse, HttpClientError> {
        self.request(HttpMethod::Get, url, &[])
    }

    /// Send a POST request.
    pub fn post(
        &self,
        url: &str,
        body: &[u8],
        content_type: Option<&str>,
    ) -> Result<HttpResponse, HttpClientError> {
        let mut client = self.clone();
        if let Some(ct) = content_type {
            client.default_headers.insert("Content-Type", ct);
        }
        client.request(HttpMethod::Post, url, body)
    }

    /// Send a PUT request.
    pub fn put(
        &self,
        url: &str,
        body: &[u8],
        content_type: Option<&str>,
    ) -> Result<HttpResponse, HttpClientError> {
        let mut client = self.clone();
        if let Some(ct) = content_type {
            client.default_headers.insert("Content-Type", ct);
        }
        client.request(HttpMethod::Put, url, body)
    }

    /// Send a DELETE request.
    pub fn delete(&self, url: &str) -> Result<HttpResponse, HttpClientError> {
        self.request(HttpMethod::Delete, url, &[])
    }

    /// Send a PATCH request.
    pub fn patch(
        &self,
        url: &str,
        body: &[u8],
        content_type: Option<&str>,
    ) -> Result<HttpResponse, HttpClientError> {
        let mut client = self.clone();
        if let Some(ct) = content_type {
            client.default_headers.insert("Content-Type", ct);
        }
        client.request(HttpMethod::Patch, url, body)
    }

    /// Send a HEAD request.
    pub fn head(&self, url: &str) -> Result<HttpResponse, HttpClientError> {
        self.request(HttpMethod::Head, url, &[])
    }

    /// Send an OPTIONS request.
    pub fn options(&self, url: &str) -> Result<HttpResponse, HttpClientError> {
        self.request(HttpMethod::Options, url, &[])
    }

    /// Convenience helper to send a JSON POST request.
    pub fn post_json<T: serde::Serialize>(
        &self,
        url: &str,
        payload: &T,
    ) -> Result<HttpResponse, HttpClientError> {
        let body = serde_json::to_vec(payload)
            .map_err(|e| HttpClientError::Io(io::Error::new(io::ErrorKind::InvalidData, e)))?;
        self.post(url, &body, Some("application/json"))
    }

    /// Convenience helper to send a JSON PUT request.
    pub fn put_json<T: serde::Serialize>(
        &self,
        url: &str,
        payload: &T,
    ) -> Result<HttpResponse, HttpClientError> {
        let body = serde_json::to_vec(payload)
            .map_err(|e| HttpClientError::Io(io::Error::new(io::ErrorKind::InvalidData, e)))?;
        self.put(url, &body, Some("application/json"))
    }

    /// Convenience helper to send a JSON PATCH request.
    pub fn patch_json<T: serde::Serialize>(
        &self,
        url: &str,
        payload: &T,
    ) -> Result<HttpResponse, HttpClientError> {
        let body = serde_json::to_vec(payload)
            .map_err(|e| HttpClientError::Io(io::Error::new(io::ErrorKind::InvalidData, e)))?;
        self.patch(url, &body, Some("application/json"))
    }

    /// Convenience helper to send an application/x-www-form-urlencoded POST request.
    pub fn post_form(
        &self,
        url: &str,
        fields: &[(&str, &str)],
    ) -> Result<HttpResponse, HttpClientError> {
        let form_body = crate::http::format_form_urlencoded(fields);
        self.post(
            url,
            form_body.as_bytes(),
            Some("application/x-www-form-urlencoded"),
        )
    }

    /// Convenience helper to send a multipart/form-data POST request.
    pub fn post_multipart(
        &self,
        url: &str,
        multipart: &MultipartBuilder,
    ) -> Result<HttpResponse, HttpClientError> {
        let ct = multipart.content_type();
        let body = multipart.clone().finish();
        self.post(url, &body, Some(&ct))
    }

    /// Send an `HttpRequest` object to the specified URL using this client.
    pub fn send_request(
        &self,
        url: &str,
        request: &HttpRequest,
    ) -> Result<HttpResponse, HttpClientError> {
        self.request_with_headers(request.method(), url, request.headers(), request.body())
    }

    /// Return a copy of this client configured with Bearer authentication.
    pub fn with_bearer_auth(&self, token: impl AsRef<str>) -> Self {
        let mut client = self.clone();
        client.default_headers.insert(
            HeaderMap::AUTHORIZATION,
            format!("Bearer {}", token.as_ref()),
        );
        client
    }

    /// Return a copy of this client configured with HTTP Basic authentication.
    pub fn with_basic_auth(&self, username: &str, password: &str) -> Self {
        let mut client = self.clone();
        client.default_headers.insert(
            HeaderMap::AUTHORIZATION,
            encode_basic_auth(username, password),
        );
        client
    }
}

/// Builder for configuring custom `HttpClient` instances.
#[derive(Debug, Clone, Default)]
pub struct HttpClientBuilder {
    timeout: Option<Duration>,
    max_body_size: Option<usize>,
    follow_redirects: Option<bool>,
    max_redirects: Option<usize>,
    allow_private_networks: Option<bool>,
    strip_hop_by_hop_headers: Option<bool>,
    headers: HeaderMap,
}

impl HttpClientBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn max_body_size(mut self, size: usize) -> Self {
        self.max_body_size = Some(size);
        self
    }

    pub fn follow_redirects(mut self, follow: bool) -> Self {
        self.follow_redirects = Some(follow);
        self
    }

    pub fn max_redirects(mut self, count: usize) -> Self {
        self.max_redirects = Some(count);
        self
    }

    /// Enable or disable access to private or local network addresses (anti-SSRF protection).
    pub fn allow_private_networks(mut self, allow: bool) -> Self {
        self.allow_private_networks = Some(allow);
        self
    }

    /// Enable or disable stripping hop-by-hop headers from outgoing requests.
    pub fn strip_hop_by_hop(mut self, strip: bool) -> Self {
        self.strip_hop_by_hop_headers = Some(strip);
        self
    }

    pub fn header(mut self, name: impl Into<String>, val: impl Into<String>) -> Self {
        self.headers.insert(name, val);
        self
    }

    /// Set standard HTTP Bearer token authorization header.
    pub fn bearer_auth(mut self, token: impl AsRef<str>) -> Self {
        self.headers.insert(
            HeaderMap::AUTHORIZATION,
            format!("Bearer {}", token.as_ref()),
        );
        self
    }

    /// Set standard HTTP Basic authentication credentials.
    pub fn basic_auth(mut self, username: &str, password: &str) -> Self {
        self.headers.insert(
            HeaderMap::AUTHORIZATION,
            encode_basic_auth(username, password),
        );
        self
    }

    pub fn build(self) -> HttpClient {
        let mut client = HttpClient::default();
        if let Some(to) = self.timeout {
            client.timeout = Some(to);
        }
        if let Some(sz) = self.max_body_size {
            client.max_body_size = sz;
        }
        if let Some(fr) = self.follow_redirects {
            client.follow_redirects = fr;
        }
        if let Some(mr) = self.max_redirects {
            client.max_redirects = mr;
        }
        if let Some(apn) = self.allow_private_networks {
            client.allow_private_networks = apn;
        }
        if let Some(sh) = self.strip_hop_by_hop_headers {
            client.strip_hop_by_hop_headers = sh;
        }
        for (k, v) in self.headers.iter() {
            client.default_headers.insert(k, v);
        }
        client
    }
}

/// Convenience shortcut to issue a GET request using default client settings.
pub fn get(url: &str) -> Result<HttpResponse, HttpClientError> {
    HttpClient::new().get(url)
}

/// Convenience shortcut to issue a POST request using default client settings.
pub fn post(
    url: &str,
    body: &[u8],
    content_type: Option<&str>,
) -> Result<HttpResponse, HttpClientError> {
    HttpClient::new().post(url, body, content_type)
}

/// Convenience shortcut to issue a PUT request using default client settings.
pub fn put(
    url: &str,
    body: &[u8],
    content_type: Option<&str>,
) -> Result<HttpResponse, HttpClientError> {
    HttpClient::new().put(url, body, content_type)
}

/// Convenience shortcut to issue a DELETE request using default client settings.
pub fn delete(url: &str) -> Result<HttpResponse, HttpClientError> {
    HttpClient::new().delete(url)
}

/// Convenience shortcut to issue a PATCH request using default client settings.
pub fn patch(
    url: &str,
    body: &[u8],
    content_type: Option<&str>,
) -> Result<HttpResponse, HttpClientError> {
    HttpClient::new().patch(url, body, content_type)
}

/// Convenience shortcut to issue a HEAD request using default client settings.
pub fn head(url: &str) -> Result<HttpResponse, HttpClientError> {
    HttpClient::new().head(url)
}

/// Convenience shortcut to issue an OPTIONS request using default client settings.
pub fn options(url: &str) -> Result<HttpResponse, HttpClientError> {
    HttpClient::new().options(url)
}

/// Convenience shortcut to issue a POST request with a JSON payload.
pub fn post_json<T: serde::Serialize>(
    url: &str,
    payload: &T,
) -> Result<HttpResponse, HttpClientError> {
    HttpClient::new().post_json(url, payload)
}

/// Convenience shortcut to issue a PUT request with a JSON payload.
pub fn put_json<T: serde::Serialize>(
    url: &str,
    payload: &T,
) -> Result<HttpResponse, HttpClientError> {
    HttpClient::new().put_json(url, payload)
}

/// Convenience shortcut to issue a PATCH request with a JSON payload.
pub fn patch_json<T: serde::Serialize>(
    url: &str,
    payload: &T,
) -> Result<HttpResponse, HttpClientError> {
    HttpClient::new().patch_json(url, payload)
}

/// Convenience shortcut to issue an application/x-www-form-urlencoded POST request.
pub fn post_form(url: &str, fields: &[(&str, &str)]) -> Result<HttpResponse, HttpClientError> {
    HttpClient::new().post_form(url, fields)
}

/// Convenience shortcut to issue a multipart/form-data POST request.
pub fn post_multipart(
    url: &str,
    multipart: &MultipartBuilder,
) -> Result<HttpResponse, HttpClientError> {
    HttpClient::new().post_multipart(url, multipart)
}

/// Convenience shortcut to issue a request using an `HttpRequest` object.
pub fn send_request(url: &str, request: &HttpRequest) -> Result<HttpResponse, HttpClientError> {
    HttpClient::new().send_request(url, request)
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

    #[test]
    fn test_cookie_and_set_cookie_parsing_formatting() {
        // Cookie parsing
        let cookie_header = "session_id=abc12345; dark_mode=true; lang=fr";
        let cookies = Cookie::parse_header(cookie_header);
        assert_eq!(cookies.len(), 3);
        assert_eq!(cookies[0].name, "session_id");
        assert_eq!(cookies[0].value, "abc12345");
        assert_eq!(cookies[1].name, "dark_mode");
        assert_eq!(cookies[1].value, "true");
        assert_eq!(cookies[2].name, "lang");
        assert_eq!(cookies[2].value, "fr");

        // Format
        let formatted = Cookie::format_cookies(&cookies);
        assert_eq!(formatted, "session_id=abc12345; dark_mode=true; lang=fr");

        // Set-Cookie parsing
        let sc_raw = "token=secret99; Domain=example.com; Path=/api; Max-Age=3600; Secure; HttpOnly; SameSite=Strict";
        let sc = SetCookie::parse(sc_raw).expect("parsed set-cookie");
        assert_eq!(sc.name, "token");
        assert_eq!(sc.value, "secret99");
        assert_eq!(sc.domain.as_deref(), Some("example.com"));
        assert_eq!(sc.path.as_deref(), Some("/api"));
        assert_eq!(sc.max_age, Some(3600));
        assert!(sc.secure);
        assert!(sc.http_only);
        assert_eq!(sc.same_site.as_deref(), Some("Strict"));

        let sc_wire = sc.to_header_value();
        assert!(sc_wire.contains("token=secret99"));
        assert!(sc_wire.contains("Path=/api"));
        assert!(sc_wire.contains("Max-Age=3600"));
        assert!(sc_wire.contains("Secure"));
        assert!(sc_wire.contains("HttpOnly"));
        assert!(sc_wire.contains("SameSite=Strict"));
    }

    #[test]
    fn test_cache_control_parsing_formatting() {
        let raw = "public, max-age=3600, must-revalidate, no-transform";
        let cc = CacheControl::parse(raw);
        assert!(cc.public);
        assert!(!cc.private);
        assert_eq!(cc.max_age, Some(3600));
        assert!(cc.must_revalidate);
        assert!(cc.no_transform);
        assert!(!cc.no_cache);
        assert!(!cc.no_store);

        let formatted = cc.to_header_value();
        assert!(formatted.contains("public"));
        assert!(formatted.contains("max-age=3600"));
        assert!(formatted.contains("must-revalidate"));
        assert!(formatted.contains("no-transform"));
    }

    #[test]
    fn test_http_url_parsing_and_resolution() {
        let u1 = HttpUrl::parse("http://ifa-lang.org/docs/std?v=1").unwrap();
        assert_eq!(u1.scheme, "http");
        assert_eq!(u1.host, "ifa-lang.org");
        assert_eq!(u1.port, 80);
        assert_eq!(u1.path_and_query, "/docs/std?v=1");
        assert_eq!(u1.socket_addr_str(), "ifa-lang.org:80");
        assert_eq!(u1.host_header_value(), "ifa-lang.org");

        let u2 = HttpUrl::parse("http://127.0.0.1:8080/metrics").unwrap();
        assert_eq!(u2.host, "127.0.0.1");
        assert_eq!(u2.port, 8080);
        assert_eq!(u2.host_header_value(), "127.0.0.1:8080");

        // Relative resolution
        let u3 = u1.join("/guide/install").unwrap();
        assert_eq!(u3.path_and_query, "/guide/install");

        let u4 = u1.join("submodule").unwrap();
        assert_eq!(u4.path_and_query, "/docs/submodule");

        // Reject HTTPS without TLS
        assert!(HttpUrl::parse("https://secure.example.com").is_err());
    }

    #[test]
    fn test_http_client_local_flow_and_redirect() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.port().expect("port");

        let handle = thread::spawn(move || {
            // First request: redirect to /final
            let mut s1 = None;
            for _ in 0..100 {
                if let Ok(Some((stream, _))) = listener.try_accept() {
                    s1 = Some(stream);
                    break;
                }
                thread::sleep(Duration::from_millis(5));
            }
            let s1 = s1.expect("s1 accepted");
            s1.set_nonblocking(false).expect("blocking");
            let mut b1 = BufferedTcpStream::new(s1).expect("b1");
            let (req1, _) = read_request(&mut b1, 4096).unwrap().unwrap();
            assert_eq!(req1.uri, "/initial");

            let mut resp1 = HttpResponseHead::new(HttpStatus::FOUND, HttpVersion::Http11);
            resp1.headers.insert("Location", "/final");
            resp1.headers.insert("Connection", "close");
            write_response_full(&mut b1, &resp1, b"").unwrap();

            // Second request: handled at /final
            let mut s2 = None;
            for _ in 0..100 {
                if let Ok(Some((stream, _))) = listener.try_accept() {
                    s2 = Some(stream);
                    break;
                }
                thread::sleep(Duration::from_millis(5));
            }
            let s2 = s2.expect("s2 accepted");
            s2.set_nonblocking(false).expect("blocking");
            let mut b2 = BufferedTcpStream::new(s2).expect("b2");
            let (req2, _) = read_request(&mut b2, 4096).unwrap().unwrap();
            assert_eq!(req2.uri, "/final");

            let mut resp2 = HttpResponseHead::ok();
            resp2.headers.insert("Content-Type", "text/plain");
            resp2.headers.insert("Connection", "close");
            write_response_full(&mut b2, &resp2, b"Welcome to IFA std::net::http!").unwrap();
        });

        let client = HttpClient::builder()
            .timeout(Duration::from_secs(5))
            .follow_redirects(true)
            .build();

        let target_url = format!("http://127.0.0.1:{}/initial", port);
        let resp = client.get(&target_url).expect("http get success");
        assert_eq!(resp.status(), HttpStatus::OK);
        assert_eq!(resp.text().unwrap(), "Welcome to IFA std::net::http!");

        handle.join().expect("server thread finished");
    }

    #[test]
    fn test_http_extended_heads_and_json() {
        let req_patch = HttpRequestHead::patch("/items/1");
        assert_eq!(req_patch.method, HttpMethod::Patch);
        assert_eq!(req_patch.uri, "/items/1");

        let req_head = HttpRequestHead::head("/ping");
        assert_eq!(req_head.method, HttpMethod::Head);

        let req_opt = HttpRequestHead::options("/api");
        assert_eq!(req_opt.method, HttpMethod::Options);

        let r_created = HttpResponseHead::created();
        assert_eq!(r_created.status, HttpStatus::CREATED);
        let r_accepted = HttpResponseHead::accepted();
        assert_eq!(r_accepted.status, HttpStatus::ACCEPTED);
        let r_no_content = HttpResponseHead::no_content();
        assert_eq!(r_no_content.status, HttpStatus::NO_CONTENT);
        let r_bad_req = HttpResponseHead::bad_request();
        assert_eq!(r_bad_req.status, HttpStatus::BAD_REQUEST);
        let r_unauth = HttpResponseHead::unauthorized();
        assert_eq!(r_unauth.status, HttpStatus::UNAUTHORIZED);
        let r_forbid = HttpResponseHead::forbidden();
        assert_eq!(r_forbid.status, HttpStatus::FORBIDDEN);
        let r_notfound = HttpResponseHead::not_found();
        assert_eq!(r_notfound.status, HttpStatus::NOT_FOUND);

        #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
        struct TestMessage {
            name: String,
            count: u32,
        }

        let orig = TestMessage {
            name: "IFA Stdlib".to_string(),
            count: 7,
        };
        let body = serde_json::to_vec(&orig).unwrap();
        let resp = HttpResponse {
            head: HttpResponseHead::ok(),
            body,
        };
        let parsed: TestMessage = resp.json().unwrap();
        assert_eq!(parsed, orig);
    }

    #[test]
    fn test_http_client_post_json_and_patch() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.port().expect("port");

        let handle = thread::spawn(move || {
            let mut s = None;
            for _ in 0..100 {
                if let Ok(Some((stream, _))) = listener.try_accept() {
                    s = Some(stream);
                    break;
                }
                thread::sleep(Duration::from_millis(5));
            }
            let s = s.expect("stream accepted");
            s.set_nonblocking(false).expect("blocking");
            let mut b = BufferedTcpStream::new(s).expect("buffered stream");
            let (req, body) = read_request(&mut b, 4096).unwrap().unwrap();
            assert_eq!(req.method, HttpMethod::Post);
            assert_eq!(req.uri, "/api/data");
            assert_eq!(req.headers.get("content-type"), Some("application/json"));
            assert_eq!(body, b"{\"key\":\"ifa\"}");

            // Respond with 201 Created and JSON body
            let resp_body = b"{\"status\":\"created\",\"id\":101}";
            let mut resp = HttpResponseHead::created();
            resp.headers.insert("Content-Type", "application/json");
            resp.headers.insert("Connection", "close");
            resp.headers
                .insert("Content-Length", resp_body.len().to_string());
            write_response_full(&mut b, &resp, resp_body).unwrap();
        });

        #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
        struct InputPayload {
            key: String,
        }

        #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
        struct OutputPayload {
            status: String,
            id: u64,
        }

        let target_url = format!("http://127.0.0.1:{}/api/data", port);
        let resp = HttpClient::new()
            .post_json(&target_url, &InputPayload { key: "ifa".into() })
            .expect("post_json");

        assert_eq!(resp.status(), HttpStatus::CREATED);
        let output: OutputPayload = resp.json().expect("parse response json");
        assert_eq!(output.status, "created");
        assert_eq!(output.id, 101);

        handle.join().expect("server thread finished");
    }

    #[test]
    fn test_extract_multipart_boundary_and_headers() {
        let ct1 = "multipart/form-data; boundary=xyz123";
        assert_eq!(extract_multipart_boundary(ct1), Some("xyz123".to_string()));

        let ct2 = "multipart/form-data; charset=utf-8; boundary=\"----WebKitBoundary\"";
        assert_eq!(
            extract_multipart_boundary(ct2),
            Some("----WebKitBoundary".to_string())
        );

        let ct3 = "application/json";
        assert_eq!(extract_multipart_boundary(ct3), None);

        let mut req = HttpRequestHead::post("/upload");
        req.headers.insert("Content-Type", ct2);
        assert!(req.is_multipart());
        assert!(!req.is_form_urlencoded());
        assert_eq!(
            req.multipart_boundary(),
            Some("----WebKitBoundary".to_string())
        );

        let mut resp = HttpResponseHead::ok();
        resp.headers
            .insert("Content-Type", "application/x-www-form-urlencoded");
        assert!(!resp.is_multipart());
        assert!(resp.is_form_urlencoded());
    }

    #[test]
    fn test_chunked_writer_and_reader_streaming() {
        let mut buffer = Vec::new();
        let mut writer = ChunkedWriter::new(&mut buffer);

        // Write chunks
        let w1 = writer.write_chunk(b"FirstChunk ").unwrap();
        assert!(w1 > 0);
        let w2 = writer.write(b"SecondChunk ").unwrap();
        assert_eq!(w2, 12);
        let w3 = writer.write_chunk(b"FinalData").unwrap();
        assert!(w3 > 0);

        let mut trailers = HeaderMap::new();
        trailers.insert("X-Checksum", "blake3-mock");
        writer.finish(Some(&trailers)).unwrap();
        assert!(writer.is_finished());

        // Now stream read using ChunkedReader with small chunks (7 bytes)
        let mut cursor = io::Cursor::new(buffer);
        let mut reader = ChunkedReader::new(&mut cursor, 1024);

        let mut received = Vec::new();
        let mut chunk_buf = [0u8; 7];
        loop {
            let n = reader.read(&mut chunk_buf).unwrap();
            if n == 0 {
                break;
            }
            received.extend_from_slice(&chunk_buf[..n]);
        }

        assert_eq!(received, b"FirstChunk SecondChunk FinalData");
        assert!(reader.is_finished());
        assert_eq!(reader.trailers().get("x-checksum"), Some("blake3-mock"));
    }

    #[test]
    fn test_http_client_post_form_and_multipart() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.port().expect("port");

        let handle = thread::spawn(move || {
            // First request: form-urlencoded
            let mut s1 = None;
            for _ in 0..100 {
                if let Ok(Some((stream, _))) = listener.try_accept() {
                    s1 = Some(stream);
                    break;
                }
                thread::sleep(Duration::from_millis(5));
            }
            let s1 = s1.expect("stream 1 accepted");
            s1.set_nonblocking(false).expect("blocking");
            let mut b1 = BufferedTcpStream::new(s1).expect("buffered 1");
            let (req1, body1) = read_request(&mut b1, 4096).unwrap().unwrap();
            assert_eq!(req1.method, HttpMethod::Post);
            assert_eq!(req1.uri, "/api/form");
            assert!(req1.is_form_urlencoded());

            let body_str = std::str::from_utf8(&body1).unwrap();
            let parsed_form = crate::http::parse_form_urlencoded(body_str);
            assert_eq!(parsed_form.get("user").map(|s| s.as_str()), Some("alice"));
            assert_eq!(parsed_form.get("role").map(|s| s.as_str()), Some("admin"));

            let mut resp1 = HttpResponseHead::ok();
            resp1.headers.insert("Content-Type", "text/plain");
            resp1.headers.insert("Connection", "close");
            write_response_full(&mut b1, &resp1, b"form-ok").unwrap();

            // Second request: multipart
            let mut s2 = None;
            for _ in 0..100 {
                if let Ok(Some((stream, _))) = listener.try_accept() {
                    s2 = Some(stream);
                    break;
                }
                thread::sleep(Duration::from_millis(5));
            }
            let s2 = s2.expect("stream 2 accepted");
            s2.set_nonblocking(false).expect("blocking");
            let mut b2 = BufferedTcpStream::new(s2).expect("buffered 2");
            let (req2, body2) = read_request(&mut b2, 8192).unwrap().unwrap();
            assert_eq!(req2.method, HttpMethod::Post);
            assert_eq!(req2.uri, "/api/upload");
            assert!(req2.is_multipart());

            let boundary = req2.multipart_boundary().expect("multipart boundary");
            let parts = crate::http::parse_multipart(&body2, &boundary).expect("parse multipart");
            assert_eq!(parts.len(), 2);
            assert_eq!(parts[0].name, "description");
            assert_eq!(parts[0].data, b"System binary update");
            assert_eq!(parts[1].name, "file");
            assert_eq!(parts[1].filename.as_deref(), Some("kernel.bin"));
            assert_eq!(
                parts[1].content_type.as_deref(),
                Some("application/octet-stream")
            );
            assert_eq!(parts[1].data, b"\x7fELF_DATA");

            // Respond with a multipart response
            let resp_form =
                MultipartBuilder::new("respBoundary99").add_field("status", "processed");
            let mut resp2 = HttpResponseHead::ok();
            resp2
                .headers
                .insert("Content-Type", resp_form.content_type());
            resp2.headers.insert("Connection", "close");
            let resp2_body = resp_form.finish();
            write_response_full(&mut b2, &resp2, &resp2_body).unwrap();
        });

        let client = HttpClient::new();

        // 1. Post form urlencoded
        let form_url = format!("http://127.0.0.1:{}/api/form", port);
        let resp_form = client
            .post_form(&form_url, &[("user", "alice"), ("role", "admin")])
            .expect("post form");
        assert_eq!(resp_form.status(), HttpStatus::OK);
        assert_eq!(resp_form.text().unwrap(), "form-ok");

        // 2. Post multipart
        let upload_url = format!("http://127.0.0.1:{}/api/upload", port);
        let multi = MultipartBuilder::new("ifaBoundaryTest123")
            .add_field("description", "System binary update")
            .add_file(
                "file",
                "kernel.bin",
                "application/octet-stream",
                b"\x7fELF_DATA",
            );
        let resp_multi = client
            .post_multipart(&upload_url, &multi)
            .expect("post multipart");
        assert_eq!(resp_multi.status(), HttpStatus::OK);
        assert!(resp_multi.is_multipart());
        let resp_parts = resp_multi.multipart().expect("parse response multipart");
        assert_eq!(resp_parts.len(), 1);
        assert_eq!(resp_parts[0].name, "status");
        assert_eq!(resp_parts[0].data, b"processed");

        handle.join().expect("server thread finished");
    }

    #[test]
    fn test_http_head_and_response_metadata_helpers() {
        let mut req = HttpRequestHead::post("/api/v1/resource");
        req.headers
            .insert("Content-Type", "application/json; charset=utf-8");
        req.headers.insert("Content-Length", "42");
        assert_eq!(req.content_type(), Some("application/json; charset=utf-8"));
        assert!(req.is_json());
        assert_eq!(req.content_length(), Some(42));
        assert!(req.is_keep_alive());

        let mut resp_head = HttpResponseHead::ok();
        resp_head.headers.insert("Content-Type", "application/json");
        resp_head.headers.insert("Location", "/dashboard");
        resp_head.headers.insert("Transfer-Encoding", "chunked");
        assert_eq!(resp_head.content_type(), Some("application/json"));
        assert!(resp_head.is_json());
        assert_eq!(resp_head.location(), Some("/dashboard"));
        assert!(resp_head.is_chunked());

        let resp = HttpResponse::new(resp_head, b"{\"status\":\"ready\"}".to_vec());
        assert_eq!(resp.content_type(), Some("application/json"));
        assert!(resp.is_json());
        assert_eq!(resp.location(), Some("/dashboard"));
        assert!(resp.is_chunked());
        assert_eq!(resp.content_length(), None);

        #[derive(serde::Deserialize, PartialEq, Eq, Debug)]
        struct StatusPayload {
            status: String,
        }
        let parsed: StatusPayload = resp.json().unwrap();
        assert_eq!(parsed.status, "ready");
    }

    #[test]
    fn test_convenience_shortcuts_form_multipart_and_json() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.local_addr().unwrap().port();

        let handle = thread::spawn(move || {
            let mut stream = None;
            for _ in 0..100 {
                if let Ok(Some((s, _))) = listener.try_accept() {
                    stream = Some(s);
                    break;
                }
                thread::sleep(Duration::from_millis(5));
            }
            let stream = stream.expect("accept put json");
            stream.set_nonblocking(false).expect("blocking");
            let mut b = BufferedTcpStream::new(stream).unwrap();
            let (req, body) = read_request(&mut b, 1024 * 1024).unwrap().unwrap();
            assert_eq!(req.method, HttpMethod::Put);
            assert_eq!(req.content_type(), Some("application/json"));
            assert!(req.is_json());
            let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(val["key"], "val1");

            let mut resp = HttpResponseHead::ok();
            resp.headers.insert("Content-Type", "application/json");
            resp.headers.insert("Connection", "close");
            let resp_body = b"{\"updated\":true}";
            write_response_full(&mut b, &resp, resp_body).unwrap();
        });

        let url = format!("http://127.0.0.1:{}/items/42", port);
        #[derive(serde::Serialize)]
        struct ReqPayload<'a> {
            key: &'a str,
        }
        let resp = put_json(&url, &ReqPayload { key: "val1" }).expect("put_json succeeds");
        assert_eq!(resp.status(), HttpStatus::OK);
        assert!(resp.is_json());
        let body: serde_json::Value = resp.json().expect("parse response json");
        assert_eq!(body["updated"], true);

        handle.join().expect("server thread finished");
    }

    #[test]
    fn test_chunk_stream_and_head_io() {
        // 1. Chunk methods
        let data_chunk = Chunk::Data(b"hello world".to_vec());
        assert!(!data_chunk.is_end());
        assert_eq!(data_chunk.data(), Some(b"hello world".as_slice()));
        assert_eq!(data_chunk.len(), 11);
        assert!(!data_chunk.is_empty());

        let mut trailers = HeaderMap::new();
        trailers.insert("X-Digest", "sha256-abc");
        let end_chunk = Chunk::End {
            trailers: trailers.clone(),
        };
        assert!(end_chunk.is_end());
        assert_eq!(end_chunk.data(), None);
        assert_eq!(end_chunk.len(), 0);
        assert!(end_chunk.is_empty());

        // 2. ChunkStream iterating through chunks
        let wire = b"5\r\nfirst\r\n6\r\nsecond\r\n0\r\nX-Digest: sha256-abc\r\n\r\n";
        let mut cursor = io::Cursor::new(wire.as_slice());
        let mut stream = ChunkStream::new(&mut cursor, 1024);

        let c1 = stream.next_chunk().unwrap().expect("first chunk");
        assert_eq!(c1, Chunk::Data(b"first".to_vec()));
        assert!(!stream.is_finished());

        let c2 = stream.next_chunk().unwrap().expect("second chunk");
        assert_eq!(c2, Chunk::Data(b"second".to_vec()));
        assert!(!stream.is_finished());

        let c3 = stream.next_chunk().unwrap().expect("end chunk");
        assert!(c3.is_end());
        assert!(stream.is_finished());
        assert_eq!(stream.trailers().get("x-digest"), Some("sha256-abc"));

        // Subsequent calls return None
        assert!(stream.next_chunk().unwrap().is_none());

        // 3. read_request_head and read_response_head
        let req_bytes = b"POST /api/upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nchunk\r\n0\r\n\r\n";
        let mut req_cursor = io::Cursor::new(req_bytes.as_slice());
        let req_head = read_request_head(&mut req_cursor, None)
            .unwrap()
            .expect("read req head");
        assert_eq!(req_head.method, HttpMethod::Post);
        assert_eq!(req_head.uri, "/api/upload");
        assert!(req_head.is_chunked());

        // Immediately read remaining chunks via ChunkStream
        let mut chunk_reader = ChunkStream::new(&mut req_cursor, 1024);
        let chk = chunk_reader.next_chunk().unwrap().expect("chunk");
        assert_eq!(chk, Chunk::Data(b"chunk".to_vec()));
        let end_chk = chunk_reader.next_chunk().unwrap().expect("end");
        assert!(end_chk.is_end());

        // 4. write_request_head & write_response_head
        let mut out_req = Vec::new();
        let head = HttpRequestHead::new(HttpMethod::Get, "/status", HttpVersion::Http11);
        write_request_head(&mut out_req, &head).expect("write req head");
        assert!(out_req.starts_with(b"GET /status HTTP/1.1\r\n"));

        let mut out_resp = Vec::new();
        let resp_head = HttpResponseHead::ok();
        write_response_head(&mut out_resp, &resp_head).expect("write resp head");
        assert!(out_resp.starts_with(b"HTTP/1.1 200 OK\r\n"));
    }

    #[test]
    fn test_http_request_and_response_objects() {
        // 1. HttpRequest construction, URI inspection and query params
        let req = HttpRequest::get("/search?q=rust+ifa&page=2#results");
        assert_eq!(req.method(), HttpMethod::Get);
        assert_eq!(req.uri(), "/search?q=rust+ifa&page=2#results");
        assert_eq!(req.path(), "/search");
        assert_eq!(req.query_string(), Some("q=rust+ifa&page=2"));
        let params = req.query_params();
        assert_eq!(params.get("q").map(String::as_str), Some("rust ifa"));
        assert_eq!(params.get("page").map(String::as_str), Some("2"));

        // JSON payload request
        let mut post_req = HttpRequest::post(
            "/api/echo",
            b"{\"key\":\"value\"}".to_vec(),
            Some("application/json"),
        );
        assert_eq!(post_req.method(), HttpMethod::Post);
        assert!(post_req.is_json());
        assert_eq!(post_req.header("Content-Type"), Some("application/json"));
        assert_eq!(post_req.text().unwrap(), "{\"key\":\"value\"}");
        #[derive(serde::Deserialize)]
        struct EchoPayload {
            key: String,
        }
        let parsed: EchoPayload = post_req.json().unwrap();
        assert_eq!(parsed.key, "value");

        post_req.headers_mut().insert("X-Custom", "ifa-test");
        assert_eq!(post_req.header("x-custom"), Some("ifa-test"));

        let (head, body) = post_req.into_parts();
        assert_eq!(head.method, HttpMethod::Post);
        assert_eq!(body, b"{\"key\":\"value\"}");

        // 2. High-level socket exchange using read_request_object / write_http_response
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.local_addr().unwrap().port();

        let handle = thread::spawn(move || {
            let mut stream = None;
            for _ in 0..100 {
                if let Ok(Some((s, _))) = listener.try_accept() {
                    stream = Some(s);
                    break;
                }
                thread::sleep(Duration::from_millis(5));
            }
            let stream = stream.expect("accept stream");
            stream.set_nonblocking(false).expect("blocking");
            let mut buf_stream = BufferedTcpStream::new(stream).unwrap();

            // Read request object
            let server_req = read_request_object(&mut buf_stream, 64 * 1024)
                .unwrap()
                .expect("receive request");
            assert_eq!(server_req.method(), HttpMethod::Post);
            assert_eq!(server_req.path(), "/api/upload");
            assert_eq!(
                server_req.query_params().get("token").map(String::as_str),
                Some("xyz123")
            );
            assert_eq!(server_req.body(), b"payload-bytes");

            // Reply with write_http_response
            let mut resp_head = HttpResponseHead::ok();
            resp_head.headers.insert("Content-Type", "text/plain");
            resp_head.headers.insert("X-Server", "ifa-http");
            let resp = HttpResponse::new(resp_head, b"ACK".to_vec());
            write_http_response(&mut buf_stream, &resp).expect("write http response");
        });

        // Client writes request object and reads response object
        let client_raw = TcpStream::connect(format!("127.0.0.1:{}", port)).expect("connect client");
        client_raw.set_nonblocking(false).expect("blocking");
        let mut client_buf = BufferedTcpStream::new(client_raw).unwrap();

        let mut client_req = HttpRequest::post(
            "/api/upload?token=xyz123",
            b"payload-bytes".to_vec(),
            Some("application/octet-stream"),
        );
        client_req.headers_mut().insert("Connection", "close");
        write_http_request(&mut client_buf, &client_req).expect("write client req");

        let client_resp = read_response_object(&mut client_buf, 64 * 1024)
            .unwrap()
            .expect("read response");
        assert_eq!(client_resp.status(), HttpStatus::OK);
        assert_eq!(client_resp.version(), HttpVersion::Http11);
        assert_eq!(client_resp.header("X-Server"), Some("ifa-http"));
        assert_eq!(client_resp.text().unwrap(), "ACK");

        let (resp_head, resp_body) = client_resp.into_parts();
        assert_eq!(resp_head.status, HttpStatus::OK);
        assert_eq!(resp_body, b"ACK");

        handle.join().expect("server thread finished");
    }

    #[test]
    fn test_http_request_and_response_builder_and_shortcuts() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq, Debug)]
        struct TestMsg {
            message: String,
            code: u32,
        }

        // Test HttpRequest builders
        let req_patch = HttpRequest::patch("/items/42", b"update".to_vec(), Some("text/plain"))
            .with_header("X-Custom", "val1");
        assert_eq!(req_patch.method(), HttpMethod::Patch);
        assert_eq!(req_patch.path(), "/items/42");
        assert_eq!(req_patch.header("Content-Type"), Some("text/plain"));
        assert_eq!(req_patch.header("X-Custom"), Some("val1"));
        assert_eq!(req_patch.body(), b"update");

        let req_head = HttpRequest::head("/ping");
        assert_eq!(req_head.method(), HttpMethod::Head);
        assert!(req_head.body().is_empty());

        let req_opt = HttpRequest::options("/cors");
        assert_eq!(req_opt.method(), HttpMethod::Options);

        let test_payload = TestMsg {
            message: "hello".to_string(),
            code: 200,
        };
        let req_json = HttpRequest::json_payload("/api", HttpMethod::Post, &test_payload).unwrap();
        assert_eq!(req_json.header("Content-Type"), Some("application/json"));
        let parsed_payload: TestMsg = req_json.json().unwrap();
        assert_eq!(parsed_payload, test_payload);

        // Test HttpResponse builders and status predicates
        let resp_ok = HttpResponse::ok(b"done".to_vec(), Some("application/octet-stream"))
            .with_header("X-Trace", "123");
        assert!(resp_ok.is_success());
        assert!(!resp_ok.is_client_error());
        assert_eq!(resp_ok.status_code(), 200);
        assert_eq!(resp_ok.reason_phrase(), "OK");
        assert_eq!(resp_ok.header("X-Trace"), Some("123"));

        let resp_text = HttpResponse::plain_text(HttpStatus::BAD_REQUEST, "invalid input");
        assert!(resp_text.is_client_error());
        assert_eq!(resp_text.status_code(), 400);
        assert_eq!(resp_text.text().unwrap(), "invalid input");
        assert_eq!(
            resp_text.header("Content-Type"),
            Some("text/plain; charset=utf-8")
        );

        let resp_json = HttpResponse::json_payload(HttpStatus::CREATED, &test_payload).unwrap();
        assert!(resp_json.is_success());
        assert_eq!(resp_json.status_code(), 201);
        let resp_msg: TestMsg = resp_json.json().unwrap();
        assert_eq!(resp_msg, test_payload);

        let resp_redir = HttpResponse::redirect(HttpStatus::FOUND, "/new-url");
        assert!(resp_redir.is_redirection());
        assert_eq!(resp_redir.location(), Some("/new-url"));

        let resp_empty = HttpResponse::empty(HttpStatus::NO_CONTENT);
        assert!(resp_empty.is_success());
        assert!(resp_empty.body().is_empty());

        let resp_500 = HttpResponse::empty(HttpStatus::INTERNAL_SERVER_ERROR);
        assert!(resp_500.is_server_error());

        let resp_100 = HttpResponse::empty(HttpStatus::CONTINUE);
        assert!(resp_100.is_informational());

        // Test send_request convenience function over local listener
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.port().expect("port");

        let handle = thread::spawn(move || {
            let mut stream = None;
            for _ in 0..100 {
                if let Ok(Some((s, _))) = listener.try_accept() {
                    stream = Some(s);
                    break;
                }
                thread::sleep(Duration::from_millis(5));
            }
            let stream = stream.expect("accept");
            stream.set_nonblocking(false).expect("blocking");
            let mut buf_stream = BufferedTcpStream::new(stream).unwrap();

            let (req_head, body) = read_request(&mut buf_stream, 4096).unwrap().unwrap();
            assert_eq!(req_head.method, HttpMethod::Patch);
            assert_eq!(req_head.uri, "/items/10");
            assert_eq!(body, b"new-patch");

            let mut resp_head = HttpResponseHead::ok();
            resp_head.headers.insert("Content-Type", "text/plain");
            resp_head.headers.insert("Connection", "close");
            write_response_full(&mut buf_stream, &resp_head, b"patched-ok").unwrap();
        });

        let client_req = HttpRequest::patch("/items/10", b"new-patch".to_vec(), Some("text/plain"));
        let url = format!("http://127.0.0.1:{}/items/10", port);
        let resp = send_request(&url, &client_req).expect("send request");
        assert_eq!(resp.status(), HttpStatus::OK);
        assert_eq!(resp.text().unwrap(), "patched-ok");

        handle.join().expect("server thread finished");
    }

    #[test]
    fn test_http_authentication_and_cache_control_helpers() {
        // 1. Basic Auth encoding and decoding
        let encoded = encode_basic_auth("aladdin", "open sesame");
        assert_eq!(encoded, "Basic YWxhZGRpbjpvcGVuIHNlc2FtZQ==");
        let (user, pass) = parse_basic_auth(&encoded).expect("parse basic auth");
        assert_eq!(user, "aladdin");
        assert_eq!(pass, "open sesame");

        assert!(parse_basic_auth("Bearer token123").is_none());
        assert!(parse_basic_auth("invalid").is_none());

        // 2. Bearer Token parsing
        let token_hdr = "Bearer secret-jwt-token-xyz_456";
        assert_eq!(
            parse_bearer_token(token_hdr),
            Some("secret-jwt-token-xyz_456".to_string())
        );
        assert_eq!(
            parse_bearer_token("bearer lowercase-token"),
            Some("lowercase-token".to_string())
        );
        assert!(parse_bearer_token("Basic 1234").is_none());
        assert!(parse_bearer_token("Bearer ").is_none());

        // 3. HttpRequest builders with auth and Cache-Control
        let req_bearer = HttpRequest::get("/protected")
            .with_bearer_auth("token-abc")
            .with_header("Cache-Control", "no-cache, max-age=3600");
        assert_eq!(req_bearer.authorization(), Some("Bearer token-abc"));
        assert_eq!(req_bearer.bearer_token(), Some("token-abc".to_string()));
        assert!(req_bearer.basic_auth().is_none());

        let cc = req_bearer.cache_control().expect("cache control present");
        assert!(cc.no_cache);
        assert_eq!(cc.max_age, Some(3600));

        let req_basic =
            HttpRequest::post("/login", b"".to_vec(), None).with_basic_auth("admin", "p@ssw0rd");
        assert_eq!(
            req_basic.basic_auth(),
            Some(("admin".to_string(), "p@ssw0rd".to_string()))
        );

        // 4. Client server exchange verifying auth headers
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.port().expect("port");

        let handle = thread::spawn(move || {
            // First request: Bearer auth
            let mut s1 = None;
            for _ in 0..100 {
                if let Ok(Some((s, _))) = listener.try_accept() {
                    s1 = Some(s);
                    break;
                }
                thread::sleep(Duration::from_millis(5));
            }
            let s1 = s1.expect("accept s1");
            s1.set_nonblocking(false).expect("blocking");
            let mut buf1 = BufferedTcpStream::new(s1).unwrap();
            let req1 = read_request_object(&mut buf1, 1024).unwrap().unwrap();
            assert_eq!(req1.bearer_token().as_deref(), Some("client-secret-token"));

            let mut resp1_head = HttpResponseHead::ok();
            resp1_head.headers.insert("Connection", "close");
            write_http_response(
                &mut buf1,
                &HttpResponse::new(resp1_head, b"auth-ok".to_vec()),
            )
            .unwrap();

            // Second request: Basic auth
            let mut s2 = None;
            for _ in 0..100 {
                if let Ok(Some((s, _))) = listener.try_accept() {
                    s2 = Some(s);
                    break;
                }
                thread::sleep(Duration::from_millis(5));
            }
            let s2 = s2.expect("accept s2");
            s2.set_nonblocking(false).expect("blocking");
            let mut buf2 = BufferedTcpStream::new(s2).unwrap();
            let req2 = read_request_object(&mut buf2, 1024).unwrap().unwrap();
            assert_eq!(
                req2.basic_auth(),
                Some(("alice".to_string(), "secret-key".to_string()))
            );

            let mut resp2_head = HttpResponseHead::ok();
            resp2_head.headers.insert("Connection", "close");
            write_http_response(
                &mut buf2,
                &HttpResponse::new(resp2_head, b"basic-ok".to_vec()),
            )
            .unwrap();
        });

        // Client 1: Bearer auth via client builder
        let client_bearer = HttpClient::builder()
            .bearer_auth("client-secret-token")
            .build();
        let resp_b = client_bearer
            .get(&format!("http://127.0.0.1:{}/protected", port))
            .expect("get with bearer");
        assert_eq!(resp_b.status(), HttpStatus::OK);
        assert_eq!(resp_b.text().unwrap(), "auth-ok");

        // Client 2: Basic auth via with_basic_auth
        let client_basic = HttpClient::new().with_basic_auth("alice", "secret-key");
        let resp_basic = client_basic
            .get(&format!("http://127.0.0.1:{}/secure", port))
            .expect("get with basic");
        assert_eq!(resp_basic.status(), HttpStatus::OK);
        assert_eq!(resp_basic.text().unwrap(), "basic-ok");

        handle.join().expect("server thread finished");
    }

    #[test]
    fn test_http_security_validation_and_hop_by_hop_filtering() {
        // 1. Hop-by-hop detection
        assert!(HeaderMap::is_hop_by_hop("connection"));
        assert!(HeaderMap::is_hop_by_hop("keep-alive"));
        assert!(HeaderMap::is_hop_by_hop("upgrade"));
        assert!(HeaderMap::is_hop_by_hop("proxy-authenticate"));
        assert!(HeaderMap::is_hop_by_hop("proxy-authorization"));
        assert!(HeaderMap::is_hop_by_hop("te"));
        assert!(HeaderMap::is_hop_by_hop("trailer"));
        assert!(HeaderMap::is_hop_by_hop("transfer-encoding"));
        assert!(!HeaderMap::is_hop_by_hop("content-type"));
        assert!(!HeaderMap::is_hop_by_hop("authorization"));

        // 2. Hop-by-hop stripping including Connection tokens
        let mut headers = HeaderMap::new();
        headers.insert("Content-Type", "application/json");
        headers.insert("Connection", "keep-alive, X-Hop-Header");
        headers.insert("Keep-Alive", "timeout=5, max=100");
        headers.insert("Upgrade", "websocket");
        headers.insert("X-Hop-Header", "temp-val");
        headers.insert("X-Permanent", "stays");

        assert!(headers.contains_hop_by_hop());
        headers.strip_hop_by_hop();

        assert!(!headers.contains_hop_by_hop());
        assert_eq!(headers.get("content-type"), Some("application/json"));
        assert_eq!(headers.get("x-permanent"), Some("stays"));
        assert!(headers.get("connection").is_none());
        assert!(headers.get("keep-alive").is_none());
        assert!(headers.get("upgrade").is_none());
        assert!(headers.get("x-hop-header").is_none());

        // 3. RFC Header name & value validation (anti-CRLF injection)
        assert!(HeaderMap::is_valid_name("X-Custom-Token_1"));
        assert!(!HeaderMap::is_valid_name("Invalid Header"));
        assert!(!HeaderMap::is_valid_name("Invalid:Header"));
        assert!(!HeaderMap::is_valid_name(""));

        assert!(HeaderMap::is_valid_value("Valid value 123 !@#"));
        assert!(!HeaderMap::is_valid_value("Injected\r\nHeader: bad"));
        assert!(!HeaderMap::is_valid_value("Injected\nHeader: bad"));

        let mut safe_map = HeaderMap::new();
        assert!(safe_map.try_insert("X-Valid", "good").is_ok());
        assert!(safe_map.try_insert("X Injected", "value").is_err());
        assert!(safe_map.try_insert("X-Valid", "bad\r\nvalue").is_err());

        // 4. Request and Response head stripping helpers
        let mut req_head = HttpRequestHead::get("/api/test");
        req_head.headers.insert("Connection", "close");
        req_head.headers.insert("Upgrade", "websocket");
        req_head.headers.insert("X-Api-Key", "secret");

        let stripped_req_head = req_head.with_hop_by_hop_stripped();
        assert!(stripped_req_head.headers.get("connection").is_none());
        assert!(stripped_req_head.headers.get("upgrade").is_none());
        assert_eq!(stripped_req_head.headers.get("x-api-key"), Some("secret"));

        let mut resp_head = HttpResponseHead::ok();
        resp_head.headers.insert("Transfer-Encoding", "chunked");
        resp_head.headers.insert("X-Data", "123");
        let stripped_resp = resp_head.with_hop_by_hop_stripped();
        assert!(stripped_resp.headers.get("transfer-encoding").is_none());
        assert_eq!(stripped_resp.headers.get("x-data"), Some("123"));

        // 5. HttpUrl security inspection (anti-SSRF)
        let local_url = HttpUrl::parse("http://localhost:8080/status").unwrap();
        assert!(local_url.is_loopback());
        assert!(local_url.is_private_or_local());
        assert_eq!(local_url.origin(), "http://localhost:8080");

        let ip_url = HttpUrl::parse("http://192.168.1.100/admin").unwrap();
        assert!(!ip_url.is_loopback());
        assert!(ip_url.is_private_or_local());

        let public_url = HttpUrl::parse("http://example.com/api").unwrap();
        assert!(!public_url.is_loopback());
        assert!(!public_url.is_private_or_local());
        assert_eq!(public_url.origin(), "http://example.com");

        // 6. HttpClient anti-SSRF enforcement
        let client_restricted = HttpClient::builder().allow_private_networks(false).build();
        let err = client_restricted
            .get("http://127.0.0.1:9999/private")
            .unwrap_err();
        match err {
            HttpClientError::SecurityViolation(msg) => {
                assert!(msg.contains("private/local network"));
            }
            other => panic!("Expected SecurityViolation, got: {:?}", other),
        }
    }
}

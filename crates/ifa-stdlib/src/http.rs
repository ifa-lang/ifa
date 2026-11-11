use crate::json::{self, JsonValue};
use std::collections::{BTreeMap, HashMap};

/// Standard HTTP Methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
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
        }
    }
}

impl std::str::FromStr for HttpMethod {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_uppercase().as_str() {
            "GET" => Ok(HttpMethod::Get),
            "POST" => Ok(HttpMethod::Post),
            "PUT" => Ok(HttpMethod::Put),
            "DELETE" => Ok(HttpMethod::Delete),
            "PATCH" => Ok(HttpMethod::Patch),
            "HEAD" => Ok(HttpMethod::Head),
            "OPTIONS" => Ok(HttpMethod::Options),
            _ => Err(()),
        }
    }
}

/// Standard HTTP Status Codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpStatus(pub u16);

impl HttpStatus {
    pub const OK: HttpStatus = HttpStatus(200);
    pub const CREATED: HttpStatus = HttpStatus(201);
    pub const NO_CONTENT: HttpStatus = HttpStatus(204);
    pub const NOT_MODIFIED: HttpStatus = HttpStatus(304);
    pub const BAD_REQUEST: HttpStatus = HttpStatus(400);
    pub const UNAUTHORIZED: HttpStatus = HttpStatus(401);
    pub const FORBIDDEN: HttpStatus = HttpStatus(403);
    pub const NOT_FOUND: HttpStatus = HttpStatus(404);
    pub const INTERNAL_SERVER_ERROR: HttpStatus = HttpStatus(500);

    pub fn reason_phrase(&self) -> &'static str {
        match self.0 {
            200 => "OK",
            201 => "Created",
            204 => "No Content",
            304 => "Not Modified",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            500 => "Internal Server Error",
            _ => "Unknown",
        }
    }
}

/// Case-insensitive HTTP headers map.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HttpHeaders {
    headers: HashMap<String, String>,
}

impl HttpHeaders {
    pub fn new() -> Self {
        Self {
            headers: HashMap::new(),
        }
    }

    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let k = key.into();
        self.headers.insert(k.to_ascii_lowercase(), value.into());
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.headers
            .get(&key.to_ascii_lowercase())
            .map(|s| s.as_str())
    }

    pub fn has(&self, key: &str) -> bool {
        self.headers.contains_key(&key.to_ascii_lowercase())
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &String)> {
        self.headers.iter()
    }
}

/// Incoming or outgoing HTTP Request message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub path: String,
    pub headers: HttpHeaders,
    pub body: Vec<u8>,
    pub path_params: BTreeMap<String, String>,
}

impl HttpRequest {
    pub fn new(method: HttpMethod, path: impl Into<String>) -> Self {
        Self {
            method,
            path: path.into(),
            headers: HttpHeaders::new(),
            body: Vec::new(),
            path_params: BTreeMap::new(),
        }
    }

    /// Retrieve dynamic path parameter matched by router (e.g. :id or *wildcard).
    pub fn param(&self, name: &str) -> Option<&str> {
        self.path_params.get(name).map(|s| s.as_str())
    }

    /// Set a path parameter manually.
    pub fn with_param(mut self, name: impl Into<String>, val: impl Into<String>) -> Self {
        self.path_params.insert(name.into(), val.into());
        self
    }

    pub fn header(mut self, key: &str, val: &str) -> Self {
        self.headers.set(key, val);
        self
    }

    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.headers.set("Content-Length", body.len().to_string());
        self.body = body;
        self
    }

    pub fn json(mut self, val: &JsonValue) -> Self {
        let s = json::encode(val);
        self.headers.set("Content-Type", "application/json");
        self.headers.set("Content-Length", s.len().to_string());
        self.body = s.into_bytes();
        self
    }
}

/// HTTP Response message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: HttpStatus,
    pub headers: HttpHeaders,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn new(status: HttpStatus) -> Self {
        Self {
            status,
            headers: HttpHeaders::new(),
            body: Vec::new(),
        }
    }

    pub fn ok() -> Self {
        Self::new(HttpStatus::OK)
    }

    pub fn created() -> Self {
        Self::new(HttpStatus::CREATED)
    }

    pub fn no_content() -> Self {
        Self::new(HttpStatus::NO_CONTENT)
    }

    pub fn not_modified(etag_str: Option<&str>) -> Self {
        let mut resp = Self::new(HttpStatus::NOT_MODIFIED);
        if let Some(etag) = etag_str {
            resp.headers.set("ETag", etag);
        }
        resp
    }

    pub fn unauthorized(realm: &str) -> Self {
        let challenge = format!("Basic realm=\"{}\"", realm);
        Self::new(HttpStatus::UNAUTHORIZED)
            .header("WWW-Authenticate", &challenge)
            .text("401 Unauthorized\n")
    }

    pub fn bad_request() -> Self {
        Self::new(HttpStatus::BAD_REQUEST)
    }

    pub fn not_found() -> Self {
        Self::new(HttpStatus::NOT_FOUND)
    }

    pub fn server_error() -> Self {
        Self::new(HttpStatus::INTERNAL_SERVER_ERROR)
    }

    pub fn etag(mut self, etag_str: &str) -> Self {
        self.headers.set("ETag", etag_str);
        self
    }

    pub fn header(mut self, key: &str, val: &str) -> Self {
        self.headers.set(key, val);
        self
    }

    pub fn text(mut self, body: impl Into<String>) -> Self {
        let s = body.into();
        self.headers
            .set("Content-Type", "text/plain; charset=utf-8");
        self.headers.set("Content-Length", s.len().to_string());
        self.body = s.into_bytes();
        self
    }

    pub fn json(mut self, val: &JsonValue) -> Self {
        let s = json::encode(val);
        self.headers.set("Content-Type", "application/json");
        self.headers.set("Content-Length", s.len().to_string());
        self.body = s.into_bytes();
        self
    }

    /// Serialize HTTP Response into HTTP/1.1 wire protocol format.
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let mut wire = Vec::new();
        let status_line = format!(
            "HTTP/1.1 {} {}\r\n",
            self.status.0,
            self.status.reason_phrase()
        );
        wire.extend_from_slice(status_line.as_bytes());

        for (k, v) in self.headers.iter() {
            wire.extend_from_slice(format!("{}: {}\r\n", k, v).as_bytes());
        }

        wire.extend_from_slice(b"\r\n");
        wire.extend_from_slice(&self.body);
        wire
    }

    /// Access body as UTF-8 string slice.
    pub fn body_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.body)
    }

    /// Add a Set-Cookie header (RFC 6265).
    #[allow(clippy::too_many_arguments)]
    pub fn set_cookie(
        mut self,
        name: &str,
        value: &str,
        path: Option<&str>,
        max_age_secs: Option<u64>,
        secure: bool,
        http_only: bool,
        same_site: Option<&str>,
    ) -> Self {
        let cookie_str = format_set_cookie(
            name,
            value,
            path,
            max_age_secs,
            secure,
            http_only,
            same_site,
        );
        self.headers.set("Set-Cookie", cookie_str);
        self
    }

    /// Create an HTTP Response initialized for Server-Sent Events (SSE).
    pub fn sse() -> Self {
        Self::new(HttpStatus::OK)
            .header("Content-Type", "text/event-stream")
            .header("Cache-Control", "no-cache")
            .header("Connection", "keep-alive")
    }

    /// Append a Server-Sent Event (SSE) to response body.
    pub fn sse_event(mut self, event: &SseEvent) -> Self {
        let wire = event.to_wire_bytes();
        self.body.extend_from_slice(&wire);
        self.headers
            .set("Content-Length", self.body.len().to_string());
        self
    }

    /// Append multiple Server-Sent Events (SSE) to response body.
    pub fn sse_events(mut self, events: &[SseEvent]) -> Self {
        for ev in events {
            let wire = ev.to_wire_bytes();
            self.body.extend_from_slice(&wire);
        }
        self.headers
            .set("Content-Length", self.body.len().to_string());
        self
    }

    /// Create an HTTP 101 Switching Protocols response for RFC 6455 WebSocket upgrade.
    pub fn websocket_upgrade(accept_key: &str) -> Self {
        Self::new(HttpStatus(101))
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .header("Sec-WebSocket-Accept", accept_key)
    }

    /// Check if this response is an RFC 6455 WebSocket switching protocols upgrade response.
    pub fn is_websocket_upgrade(&self) -> bool {
        self.status.0 == 101
            && self
                .headers
                .get("upgrade")
                .map(|u| u.eq_ignore_ascii_case("websocket"))
                .unwrap_or(false)
            && self
                .headers
                .get("connection")
                .map(|c| {
                    c.split(',')
                        .any(|part| part.trim().eq_ignore_ascii_case("upgrade"))
                })
                .unwrap_or(false)
            && self.headers.has("sec-websocket-accept")
    }

    /// Retrieve the Sec-WebSocket-Accept header value if present.
    pub fn websocket_accept_key(&self) -> Option<&str> {
        self.headers.get("sec-websocket-accept")
    }

    /// Verify whether this response's Sec-WebSocket-Accept header matches client key per RFC 6455.
    pub fn verify_websocket_accept(&self, client_key: &str) -> bool {
        if !self.is_websocket_upgrade() {
            return false;
        }
        let expected = crate::crypto::websocket_accept_key(client_key);
        self.websocket_accept_key() == Some(expected.as_str())
    }

    /// Parse HTTP Response from raw wire bytes.
    pub fn parse_from_wire(raw: &[u8]) -> Result<(Self, usize), String> {
        let header_end = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or("Incomplete HTTP headers")?;

        let header_str =
            std::str::from_utf8(&raw[..header_end]).map_err(|e| format!("UTF-8 error: {}", e))?;
        let mut lines = header_str.split("\r\n");

        let status_line = lines.next().ok_or("Missing status line")?;
        let mut status_parts = status_line.splitn(3, ' ');
        let _proto = status_parts.next().ok_or("Missing HTTP protocol")?;
        let code_str = status_parts.next().ok_or("Missing status code")?;
        let code = code_str.parse::<u16>().map_err(|_| "Invalid status code")?;

        let mut headers = HttpHeaders::new();
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                headers.set(k.trim(), v.trim());
            }
        }

        let body_start = header_end + 4;
        let content_length = headers
            .get("content-length")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(raw.len().saturating_sub(body_start));

        let total_size = body_start + content_length;
        if raw.len() < total_size {
            return Err("Incomplete HTTP body".to_string());
        }

        let body = raw[body_start..total_size].to_vec();
        Ok((
            Self {
                status: HttpStatus(code),
                headers,
                body,
            },
            total_size,
        ))
    }
}

impl HttpRequest {
    /// Serialize HTTP Request to wire protocol format.
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let mut wire = Vec::new();
        let req_line = format!("{} {} HTTP/1.1\r\n", self.method.as_str(), self.path);
        wire.extend_from_slice(req_line.as_bytes());

        for (k, v) in self.headers.iter() {
            wire.extend_from_slice(format!("{}: {}\r\n", k, v).as_bytes());
        }

        wire.extend_from_slice(b"\r\n");
        wire.extend_from_slice(&self.body);
        wire
    }

    /// Access body as UTF-8 string slice.
    pub fn body_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.body)
    }

    /// Parse HTTP Request from raw wire bytes.
    pub fn parse_from_wire(raw: &[u8]) -> Result<(Self, usize), String> {
        let header_end = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or("Incomplete HTTP headers")?;

        let header_str =
            std::str::from_utf8(&raw[..header_end]).map_err(|e| format!("UTF-8 error: {}", e))?;
        let mut lines = header_str.split("\r\n");

        let req_line = lines.next().ok_or("Missing request line")?;
        let mut req_parts = req_line.splitn(3, ' ');
        let method_str = req_parts.next().ok_or("Missing HTTP method")?;
        let path = req_parts.next().ok_or("Missing request path")?;
        let method = method_str
            .parse::<HttpMethod>()
            .map_err(|_| "Unknown HTTP method")?;

        let mut headers = HttpHeaders::new();
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                headers.set(k.trim(), v.trim());
            }
        }

        let body_start = header_end + 4;
        let content_length = headers
            .get("content-length")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0);

        let total_size = body_start + content_length;
        if raw.len() < total_size {
            return Err("Incomplete HTTP body".to_string());
        }

        let body = raw[body_start..total_size].to_vec();
        Ok((
            Self {
                method,
                path: path.to_string(),
                headers,
                body,
                path_params: BTreeMap::new(),
            },
            total_size,
        ))
    }

    /// Parse Cookies from request header (RFC 6265).
    pub fn cookies(&self) -> HashMap<String, String> {
        if let Some(cookie_hdr) = self.headers.get("cookie") {
            parse_cookies(cookie_hdr)
        } else {
            HashMap::new()
        }
    }

    /// Retrieve a specific cookie by name.
    pub fn cookie(&self, name: &str) -> Option<String> {
        self.cookies().get(name).cloned()
    }

    /// Parse form-urlencoded body into key-value map.
    pub fn form_urlencoded(&self) -> Result<HashMap<String, String>, String> {
        let s = self.body_str().map_err(|e| format!("UTF-8 error: {}", e))?;
        Ok(parse_form_urlencoded(s))
    }

    /// Set form-urlencoded body and appropriate Content-Type header.
    pub fn form_urlencoded_body(mut self, pairs: &[(&str, &str)]) -> Self {
        let encoded = format_form_urlencoded(pairs);
        self.headers
            .set("Content-Type", "application/x-www-form-urlencoded");
        self.headers
            .set("Content-Length", encoded.len().to_string());
        self.body = encoded.into_bytes();
        self
    }

    /// Parse multipart form-data body (RFC 7578 / RFC 2046).
    pub fn multipart(&self, boundary: &str) -> Result<Vec<MultipartPart>, String> {
        parse_multipart(&self.body, boundary)
    }

    /// Check if the request accepts a specific MIME type.
    pub fn accepts(&self, mime: &str) -> bool {
        if let Some(accept_hdr) = self.headers.get("accept") {
            let items = parse_accept_header(accept_hdr);
            if items.is_empty() {
                return true;
            }
            let target = mime.to_ascii_lowercase();
            let target_type = target.split('/').next().unwrap_or("");

            for item in &items {
                if item.quality <= 0.0 {
                    if item.media_type == "*/*"
                        || item.media_type == target
                        || item.media_type == format!("{}/*", target_type)
                    {
                        return false;
                    }
                } else if item.media_type == "*/*"
                    || item.media_type == target
                    || item.media_type == format!("{}/*", target_type)
                {
                    return true;
                }
            }
            false
        } else {
            true
        }
    }

    /// Negotiate Content-Type from available choices based on Accept header.
    pub fn negotiate_content_type(&self, available: &[&str]) -> Option<String> {
        if let Some(accept_hdr) = self.headers.get("accept") {
            negotiate_content_type(accept_hdr, available)
        } else if !available.is_empty() {
            Some(available[0].to_string())
        } else {
            None
        }
    }

    /// Content-Type header of the request, if present.
    pub fn content_type(&self) -> Option<&str> {
        self.headers.get("content-type")
    }

    /// Check if Content-Type is JSON.
    pub fn is_json(&self) -> bool {
        self.content_type()
            .map(|c| c.to_ascii_lowercase().contains("application/json"))
            .unwrap_or(false)
    }

    /// Check if Accept header indicates Server-Sent Events.
    pub fn is_sse(&self) -> bool {
        self.headers
            .get("accept")
            .map(|a| a.to_ascii_lowercase().contains("text/event-stream"))
            .unwrap_or(false)
    }

    /// Check if Content-Type is application/x-www-form-urlencoded.
    pub fn is_form_urlencoded(&self) -> bool {
        self.content_type()
            .map(|c| {
                c.to_ascii_lowercase()
                    .contains("application/x-www-form-urlencoded")
            })
            .unwrap_or(false)
    }

    /// Check if Content-Type is multipart/form-data.
    pub fn is_multipart(&self) -> bool {
        self.content_type()
            .map(|c| c.to_ascii_lowercase().contains("multipart/form-data"))
            .unwrap_or(false)
    }

    /// Returns the Authorization header value if present.
    pub fn authorization(&self) -> Option<&str> {
        self.headers.get("authorization")
    }

    /// Parse HTTP Basic Authentication credentials (RFC 7617).
    /// Returns Some((username, password)) if format is "Basic <base64>" and valid.
    pub fn basic_auth(&self) -> Option<(String, String)> {
        self.authorization().and_then(parse_basic_auth)
    }

    /// Parse HTTP Bearer token from Authorization header (RFC 6750).
    /// Returns Some(token) if format is "Bearer <token>".
    pub fn bearer_token(&self) -> Option<String> {
        self.authorization().and_then(parse_bearer_token)
    }

    /// Check if this is a CORS preflight OPTIONS request.
    pub fn is_cors_preflight(&self) -> bool {
        self.method == HttpMethod::Options
            && self.headers.get("origin").is_some()
            && self.headers.get("access-control-request-method").is_some()
    }

    /// Evaluate If-None-Match header against the given ETag (RFC 7232).
    /// Returns true if client version is fresh and server should reply 304 Not Modified.
    pub fn if_none_match(&self, current_etag: &str) -> bool {
        self.headers
            .get("if-none-match")
            .map(|val| matches_if_none_match(current_etag, val))
            .unwrap_or(false)
    }

    /// Evaluate If-Match header against the given ETag (RFC 7232).
    /// Returns true if operation is permitted (matches or header absent).
    pub fn if_match(&self, current_etag: &str) -> bool {
        self.headers
            .get("if-match")
            .map(|val| matches_if_match(current_etag, val))
            .unwrap_or(true)
    }

    /// Check whether request is an RFC 6455 WebSocket handshake upgrade request.
    pub fn is_websocket_upgrade(&self) -> bool {
        let has_upgrade = self
            .headers
            .get("upgrade")
            .map(|v| v.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false);

        let has_connection = self
            .headers
            .get("connection")
            .map(|v| {
                v.split(',')
                    .any(|part| part.trim().eq_ignore_ascii_case("upgrade"))
            })
            .unwrap_or(false);

        let has_valid_version = self
            .headers
            .get("sec-websocket-version")
            .map(|v| v.trim() == "13")
            .unwrap_or(false);

        let has_key = self
            .headers
            .get("sec-websocket-key")
            .map(|k| !k.trim().is_empty())
            .unwrap_or(false);

        self.method == HttpMethod::Get
            && has_upgrade
            && has_connection
            && has_valid_version
            && has_key
    }

    /// Retrieve client Sec-WebSocket-Key header if present.
    pub fn websocket_key(&self) -> Option<&str> {
        self.headers.get("sec-websocket-key").map(|k| k.trim())
    }

    /// Retrieve client-requested Sec-WebSocket-Protocol header if present.
    pub fn websocket_protocol(&self) -> Option<&str> {
        self.headers.get("sec-websocket-protocol").map(|p| p.trim())
    }

    /// Create an RFC 6455 101 Switching Protocols response accepting this WebSocket handshake request.
    pub fn websocket_upgrade_response(
        &self,
        selected_protocol: Option<&str>,
    ) -> Option<HttpResponse> {
        if !self.is_websocket_upgrade() {
            return None;
        }
        let key = self.websocket_key()?;
        let accept = crate::crypto::websocket_accept_key(key);
        let mut resp = HttpResponse::websocket_upgrade(&accept);
        if let Some(proto) = selected_protocol {
            resp = resp.header("Sec-WebSocket-Protocol", proto);
        }
        Some(resp)
    }

    /// Construct a client RFC 6455 WebSocket handshake upgrade request.
    pub fn websocket_handshake(
        path: impl Into<String>,
        host: impl AsRef<str>,
        client_key: &str,
    ) -> Self {
        Self::new(HttpMethod::Get, path)
            .header("Host", host.as_ref())
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .header("Sec-WebSocket-Key", client_key)
            .header("Sec-WebSocket-Version", "13")
    }
}

// -------------------------------------------------------------
// COLORLESS NON-BLOCKING ASYNC HTTP SERVER & CLIENT (ZERO-GC)
// -------------------------------------------------------------

use ifa_runtime::reactor::{AsyncTcpListener, AsyncTcpStream};
use ifa_runtime::GLOBAL_SCHEDULER;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub type HttpHandler = Arc<dyn Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static>;

/// Route segment kind for dynamic URI routing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteSegment {
    /// Static exact path segment (e.g. "api", "v1", "users").
    Exact(String),
    /// Dynamic named path parameter (e.g. ":id", ":username") storing parameter key.
    Param(String),
    /// Catch-all wildcard matching remainder of URI (e.g. "*filepath", "*").
    Wildcard(String),
}

/// Registered route with HTTP method, URI pattern, parsed segments and execution handler.
#[derive(Clone)]
pub struct HttpRoute {
    pub method: HttpMethod,
    pub pattern: String,
    pub segments: Vec<RouteSegment>,
    pub handler: HttpHandler,
}

/// High-performance URI router supporting dynamic path parameters (:param) and wildcards (*wildcard).
#[derive(Clone, Default)]
pub struct HttpRouter {
    pub routes: Vec<HttpRoute>,
}

impl HttpRouter {
    pub fn new() -> Self {
        Self { routes: Vec::new() }
    }

    /// Parse a URI pattern into an ordered list of route segments.
    pub fn parse_pattern(pattern: &str) -> Vec<RouteSegment> {
        let clean = pattern.split_once('?').map(|(p, _)| p).unwrap_or(pattern);
        clean
            .split('/')
            .filter(|s| !s.is_empty())
            .map(|seg| {
                if let Some(param) = seg.strip_prefix(':') {
                    RouteSegment::Param(param.to_string())
                } else if let Some(wildcard) = seg.strip_prefix('*') {
                    let name = if wildcard.is_empty() {
                        "wildcard"
                    } else {
                        wildcard
                    };
                    RouteSegment::Wildcard(name.to_string())
                } else {
                    RouteSegment::Exact(seg.to_string())
                }
            })
            .collect()
    }

    /// Register a route handler with an HTTP method and URI pattern.
    pub fn add(
        &mut self,
        method: HttpMethod,
        pattern: impl Into<String>,
        handler: impl Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static,
    ) -> &mut Self {
        let pat_str = pattern.into();
        let segments = Self::parse_pattern(&pat_str);
        self.routes.push(HttpRoute {
            method,
            pattern: pat_str,
            segments,
            handler: Arc::new(handler),
        });
        self
    }

    /// Register a GET route handler.
    pub fn get(
        &mut self,
        pattern: impl Into<String>,
        handler: impl Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static,
    ) -> &mut Self {
        self.add(HttpMethod::Get, pattern, handler)
    }

    /// Register a POST route handler.
    pub fn post(
        &mut self,
        pattern: impl Into<String>,
        handler: impl Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static,
    ) -> &mut Self {
        self.add(HttpMethod::Post, pattern, handler)
    }

    /// Register a PUT route handler.
    pub fn put(
        &mut self,
        pattern: impl Into<String>,
        handler: impl Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static,
    ) -> &mut Self {
        self.add(HttpMethod::Put, pattern, handler)
    }

    /// Register a DELETE route handler.
    pub fn delete(
        &mut self,
        pattern: impl Into<String>,
        handler: impl Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static,
    ) -> &mut Self {
        self.add(HttpMethod::Delete, pattern, handler)
    }

    /// Register a PATCH route handler.
    pub fn patch(
        &mut self,
        pattern: impl Into<String>,
        handler: impl Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static,
    ) -> &mut Self {
        self.add(HttpMethod::Patch, pattern, handler)
    }

    /// Register a HEAD route handler.
    pub fn head(
        &mut self,
        pattern: impl Into<String>,
        handler: impl Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static,
    ) -> &mut Self {
        self.add(HttpMethod::Head, pattern, handler)
    }

    /// Register an OPTIONS route handler.
    pub fn options(
        &mut self,
        pattern: impl Into<String>,
        handler: impl Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static,
    ) -> &mut Self {
        self.add(HttpMethod::Options, pattern, handler)
    }

    /// Match an incoming request against registered routes and extract dynamic path parameters.
    pub fn match_route<'a>(
        &'a self,
        method: &HttpMethod,
        path: &str,
    ) -> Option<(&'a HttpRoute, BTreeMap<String, String>)> {
        let clean_path = path.split_once('?').map(|(p, _)| p).unwrap_or(path);
        let path_segs: Vec<&str> = clean_path.split('/').filter(|s| !s.is_empty()).collect();

        for route in &self.routes {
            if route.method != *method {
                continue;
            }

            let mut params = BTreeMap::new();
            let mut matches = true;
            let mut req_idx = 0;

            for seg in &route.segments {
                match seg {
                    RouteSegment::Exact(expected) => {
                        if req_idx >= path_segs.len() || path_segs[req_idx] != expected {
                            matches = false;
                            break;
                        }
                        req_idx += 1;
                    }
                    RouteSegment::Param(param_name) => {
                        if req_idx >= path_segs.len() {
                            matches = false;
                            break;
                        }
                        params.insert(param_name.clone(), path_segs[req_idx].to_string());
                        req_idx += 1;
                    }
                    RouteSegment::Wildcard(wildcard_name) => {
                        let remaining = path_segs[req_idx..].join("/");
                        params.insert(wildcard_name.clone(), remaining);
                        req_idx = path_segs.len();
                        break;
                    }
                }
            }

            if matches && req_idx == path_segs.len() {
                return Some((route, params));
            }
        }
        None
    }
}

/// High-performance, non-blocking HTTP server driven by IFA colorless fibers.
pub struct HttpServer {
    port: u16,
    router: Arc<HttpRouter>,
    is_running: Arc<AtomicBool>,
}

impl HttpServer {
    /// Create a new HTTP Server on the specified port.
    pub fn new(port: u16) -> Self {
        Self {
            port,
            router: Arc::new(HttpRouter::new()),
            is_running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Register a route handler for an HTTP method and path pattern.
    pub fn route(
        &mut self,
        method: HttpMethod,
        path: impl Into<String>,
        handler: impl Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static,
    ) -> &mut Self {
        let router = Arc::get_mut(&mut self.router).expect("Cannot register route while listening");
        router.add(method, path, handler);
        self
    }

    /// Register a GET route handler.
    pub fn get(
        &mut self,
        path: impl Into<String>,
        handler: impl Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static,
    ) -> &mut Self {
        self.route(HttpMethod::Get, path, handler)
    }

    /// Register a POST route handler.
    pub fn post(
        &mut self,
        path: impl Into<String>,
        handler: impl Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static,
    ) -> &mut Self {
        self.route(HttpMethod::Post, path, handler)
    }

    /// Register a PUT route handler.
    pub fn put(
        &mut self,
        path: impl Into<String>,
        handler: impl Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static,
    ) -> &mut Self {
        self.route(HttpMethod::Put, path, handler)
    }

    /// Register a DELETE route handler.
    pub fn delete(
        &mut self,
        path: impl Into<String>,
        handler: impl Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static,
    ) -> &mut Self {
        self.route(HttpMethod::Delete, path, handler)
    }

    /// Register a PATCH route handler.
    pub fn patch(
        &mut self,
        path: impl Into<String>,
        handler: impl Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static,
    ) -> &mut Self {
        self.route(HttpMethod::Patch, path, handler)
    }

    /// Register a HEAD route handler.
    pub fn head(
        &mut self,
        path: impl Into<String>,
        handler: impl Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static,
    ) -> &mut Self {
        self.route(HttpMethod::Head, path, handler)
    }

    /// Register an OPTIONS route handler.
    pub fn options(
        &mut self,
        path: impl Into<String>,
        handler: impl Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static,
    ) -> &mut Self {
        self.route(HttpMethod::Options, path, handler)
    }

    /// Start listening in a background colorless fiber and return bound address.
    pub fn listen_background(&self) -> io::Result<std::net::SocketAddr> {
        let listener = AsyncTcpListener::bind(format!("127.0.0.1:{}", self.port))?;
        let addr = listener.local_addr()?;
        self.is_running.store(true, Ordering::SeqCst);

        let running = Arc::clone(&self.is_running);
        let router = Arc::clone(&self.router);

        GLOBAL_SCHEDULER.spawn(move || {
            while running.load(Ordering::Relaxed) {
                if let Ok(Some((mut stream, _))) = listener.try_accept() {
                    let router_worker = Arc::clone(&router);
                    GLOBAL_SCHEDULER.spawn(move || {
                        let mut buf = vec![0u8; 16384];
                        let mut total_read = 0;
                        let mut spins = 0;
                        let mut last_activity = Instant::now();

                        loop {
                            match stream.try_read(&mut buf[total_read..]) {
                                Ok(Some(0)) => break,
                                Ok(Some(n)) => {
                                    total_read += n;
                                    spins = 0;
                                    last_activity = Instant::now();

                                    while total_read > 0 {
                                        match HttpRequest::parse_from_wire(&buf[..total_read]) {
                                            Ok((mut req, consumed)) => {
                                                let keep_alive =
                                                    http_should_keep_alive(200, &req.headers);
                                                let mut res = if let Some((route, params)) =
                                                    router_worker
                                                        .match_route(&req.method, &req.path)
                                                {
                                                    req.path_params = params;
                                                    (route.handler)(&req)
                                                } else {
                                                    HttpResponse::not_found()
                                                        .text("Route not found")
                                                };

                                                if keep_alive {
                                                    res.headers.set("Connection", "keep-alive");
                                                } else {
                                                    res.headers.set("Connection", "close");
                                                }

                                                let wire = res.to_wire_bytes();
                                                if stream.write_all(&wire).is_err() {
                                                    return;
                                                }

                                                buf.copy_within(consumed..total_read, 0);
                                                total_read -= consumed;

                                                if !keep_alive {
                                                    return;
                                                }
                                            }
                                            Err(_) => {
                                                // Incomplete request body or headers, await more bytes
                                                break;
                                            }
                                        }
                                    }
                                }
                                Ok(None) | Err(_) => {
                                    spins += 1;
                                    if spins < 32 {
                                        std::hint::spin_loop();
                                    } else {
                                        if last_activity.elapsed() > Duration::from_secs(30) {
                                            break;
                                        }
                                        GLOBAL_SCHEDULER.yield_now();
                                        std::thread::sleep(Duration::from_millis(1));
                                    }
                                }
                            }
                        }
                    });
                } else {
                    GLOBAL_SCHEDULER.yield_now();
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
            }
        });

        Ok(addr)
    }

    /// Stop the server listener.
    pub fn stop(&self) {
        self.is_running.store(false, Ordering::SeqCst);
    }
}

/// Read an HTTP response from an async TCP stream over colorless fibers.
pub fn read_http_response(stream: &mut AsyncTcpStream) -> io::Result<HttpResponse> {
    let mut buf = vec![0u8; 16384];
    let mut total_read = 0;
    let mut spins = 0;
    let start = Instant::now();

    loop {
        match stream.try_read(&mut buf[total_read..]) {
            Ok(Some(0)) => {
                // Connection closed by peer
                if total_read > 0 {
                    if let Ok((resp, _)) = HttpResponse::parse_from_wire(&buf[..total_read]) {
                        return Ok(resp);
                    }
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Connection closed by server",
                ));
            }
            Ok(Some(n)) => {
                total_read += n;
                if let Ok((resp, _)) = HttpResponse::parse_from_wire(&buf[..total_read]) {
                    return Ok(resp);
                }
                if total_read == buf.len() {
                    buf.resize(buf.len() * 2, 0);
                }
                spins = 0;
            }
            Ok(None) | Err(_) => {
                spins += 1;
                if spins < 32 {
                    std::hint::spin_loop();
                } else {
                    if start.elapsed() > Duration::from_secs(15) {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "HTTP response timed out waiting for data",
                        ));
                    }
                    GLOBAL_SCHEDULER.yield_now();
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        }
    }
}

/// Determine whether an HTTP request or response permits socket reuse under RFC 7230 Keep-Alive rules.
pub fn http_should_keep_alive(status_code: u16, headers: &HttpHeaders) -> bool {
    if let Some(conn) = headers.get("connection") {
        let val = conn.to_ascii_lowercase();
        if val.contains("close") {
            return false;
        }
        if val.contains("keep-alive") {
            return true;
        }
    }
    // 204 No Content or 304 Not Modified have no message body
    if status_code == 204 || status_code == 304 {
        return true;
    }
    // Must have deterministic framing (Content-Length or chunked Transfer-Encoding)
    if headers.has("content-length") {
        return true;
    }
    if let Some(te) = headers.get("transfer-encoding") {
        if te.to_ascii_lowercase().contains("chunked") {
            return true;
        }
    }
    false
}

/// Asynchronous non-blocking HTTP client running over colorless fibers.
pub struct HttpClient;

impl HttpClient {
    pub fn new() -> Self {
        Self
    }

    /// Send an HTTP request to host and port over an async TCP stream.
    pub fn send(&self, req: &HttpRequest, host: &str, port: u16) -> io::Result<HttpResponse> {
        let mut stream = AsyncTcpStream::connect(format!("{}:{}", host, port))?;
        let wire = req.to_wire_bytes();
        stream.write_all(&wire)?;
        read_http_response(&mut stream)
    }

    /// Execute a non-blocking GET request.
    pub fn get(&self, host: &str, port: u16, path: &str) -> io::Result<HttpResponse> {
        let req = HttpRequest::new(HttpMethod::Get, path)
            .header("Host", host)
            .header("User-Agent", "IFA-HttpClient/0.1.0")
            .header("Connection", "close");
        self.send(&req, host, port)
    }

    /// Execute a non-blocking POST request with JSON payload.
    pub fn post_json(
        &self,
        host: &str,
        port: u16,
        path: &str,
        payload: &JsonValue,
    ) -> io::Result<HttpResponse> {
        let req = HttpRequest::new(HttpMethod::Post, path)
            .header("Host", host)
            .header("User-Agent", "IFA-HttpClient/0.1.0")
            .header("Connection", "close")
            .json(payload);
        self.send(&req, host, port)
    }
}

impl Default for HttpClient {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------
// RFC 3986 URL ENCODING, FORM URLENCODED, COOKIES & MULTIPART
// -------------------------------------------------------------

/// Percent-encode a string according to RFC 3986 (unreserved: [A-Za-z0-9-_.~]).
pub fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char);
            }
            _ => {
                out.push('%');
                out.push_str(&format!("{:02X}", b));
            }
        }
    }
    out
}

/// Percent-decode an RFC 3986 string. Converts '+' to space ' ' for form compatibility.
pub fn url_decode(s: &str) -> Result<String, String> {
    let mut bytes = Vec::with_capacity(s.len());
    let raw = s.as_bytes();
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'%' {
            if i + 2 >= raw.len() {
                return Err("Incomplete percent-encoded sequence".to_string());
            }
            let hex_str = std::str::from_utf8(&raw[i + 1..=i + 2])
                .map_err(|_| "Invalid UTF-8 in percent escape".to_string())?;
            let val = u8::from_str_radix(hex_str, 16)
                .map_err(|_| format!("Invalid hex sequence: %{}", hex_str))?;
            bytes.push(val);
            i += 3;
        } else if raw[i] == b'+' {
            bytes.push(b' ');
            i += 1;
        } else {
            bytes.push(raw[i]);
            i += 1;
        }
    }
    String::from_utf8(bytes).map_err(|e| format!("Invalid UTF-8 after decoding: {}", e))
}

/// Parse `application/x-www-form-urlencoded` query or body into key-value map.
pub fn parse_form_urlencoded(s: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if s.is_empty() {
        return map;
    }
    for pair in s.split('&') {
        if pair.is_empty() {
            continue;
        }
        if let Some((k, v)) = pair.split_once('=') {
            let key = url_decode(k).unwrap_or_else(|_| k.to_string());
            let val = url_decode(v).unwrap_or_else(|_| v.to_string());
            map.insert(key, val);
        } else {
            let key = url_decode(pair).unwrap_or_else(|_| pair.to_string());
            map.insert(key, String::new());
        }
    }
    map
}

/// Format key-value pairs into `application/x-www-form-urlencoded` string.
pub fn format_form_urlencoded(pairs: &[(&str, &str)]) -> String {
    let mut out = String::new();
    for (idx, (k, v)) in pairs.iter().enumerate() {
        if idx > 0 {
            out.push('&');
        }
        out.push_str(&url_encode(k));
        out.push('=');
        out.push_str(&url_encode(v));
    }
    out
}

/// Parse HTTP `Cookie` header into key-value map (RFC 6265).
pub fn parse_cookies(header: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for part in header.split(';') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some((k, v)) = trimmed.split_once('=') {
            map.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    map
}

/// Format `Set-Cookie` header value (RFC 6265).
pub fn format_set_cookie(
    name: &str,
    value: &str,
    path: Option<&str>,
    max_age_secs: Option<u64>,
    secure: bool,
    http_only: bool,
    same_site: Option<&str>,
) -> String {
    let mut out = format!("{}={}", name, value);
    if let Some(p) = path {
        out.push_str(&format!("; Path={}", p));
    }
    if let Some(secs) = max_age_secs {
        out.push_str(&format!("; Max-Age={}", secs));
    }
    if let Some(ss) = same_site {
        out.push_str(&format!("; SameSite={}", ss));
    }
    if secure {
        out.push_str("; Secure");
    }
    if http_only {
        out.push_str("; HttpOnly");
    }
    out
}

/// Multipart part representation (RFC 7578 / RFC 2046).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultipartPart {
    pub name: String,
    pub filename: Option<String>,
    pub content_type: Option<String>,
    pub data: Vec<u8>,
}

/// Fluent builder for constructing `multipart/form-data` payloads.
#[derive(Debug, Clone)]
pub struct MultipartBuilder {
    boundary: String,
    body: Vec<u8>,
}

impl MultipartBuilder {
    pub fn new(boundary: impl Into<String>) -> Self {
        Self {
            boundary: boundary.into(),
            body: Vec::new(),
        }
    }

    pub fn boundary(&self) -> &str {
        &self.boundary
    }

    pub fn content_type(&self) -> String {
        format!("multipart/form-data; boundary={}", self.boundary)
    }

    pub fn add_field(mut self, name: &str, value: &str) -> Self {
        let header = format!(
            "--{}\r\nContent-Disposition: form-data; name=\"{}\"\r\n\r\n",
            self.boundary, name
        );
        self.body.extend_from_slice(header.as_bytes());
        self.body.extend_from_slice(value.as_bytes());
        self.body.extend_from_slice(b"\r\n");
        self
    }

    pub fn add_file(mut self, name: &str, filename: &str, content_type: &str, data: &[u8]) -> Self {
        let header = format!(
            "--{}\r\nContent-Disposition: form-data; name=\"{}\"; filename=\"{}\"\r\nContent-Type: {}\r\n\r\n",
            self.boundary, name, filename, content_type
        );
        self.body.extend_from_slice(header.as_bytes());
        self.body.extend_from_slice(data);
        self.body.extend_from_slice(b"\r\n");
        self
    }

    pub fn finish(mut self) -> Vec<u8> {
        let footer = format!("--{}--\r\n", self.boundary);
        self.body.extend_from_slice(footer.as_bytes());
        self.body
    }
}

/// Parse multipart payload into individual `MultipartPart` items.
pub fn parse_multipart(body: &[u8], boundary: &str) -> Result<Vec<MultipartPart>, String> {
    let delim = format!("--{}", boundary);
    let delim_bytes = delim.as_bytes();
    let mut parts = Vec::new();

    let mut start_idx = 0;
    while let Some(pos) = body[start_idx..]
        .windows(delim_bytes.len())
        .position(|w| w == delim_bytes)
    {
        let part_start = start_idx + pos + delim_bytes.len();
        if part_start + 2 <= body.len() && &body[part_start..part_start + 2] == b"--" {
            // End boundary
            break;
        }
        // Skip \r\n after boundary
        let search_start =
            if part_start + 2 <= body.len() && &body[part_start..part_start + 2] == b"\r\n" {
                part_start + 2
            } else {
                part_start
            };

        // Next boundary or end
        let part_end = if let Some(next_pos) = body[search_start..]
            .windows(delim_bytes.len())
            .position(|w| w == delim_bytes)
        {
            let end = search_start + next_pos;
            if end >= 2 && &body[end - 2..end] == b"\r\n" {
                end - 2
            } else {
                end
            }
        } else {
            body.len()
        };

        let raw_part = &body[search_start..part_end];
        if let Some(header_sep) = raw_part.windows(4).position(|w| w == b"\r\n\r\n") {
            let header_str = std::str::from_utf8(&raw_part[..header_sep])
                .map_err(|e| format!("Header UTF-8 error: {}", e))?;
            let part_data = &raw_part[header_sep + 4..];

            let mut name = String::new();
            let mut filename = None;
            let mut content_type = None;

            for line in header_str.split("\r\n") {
                if let Some((k, v)) = line.split_once(':') {
                    let k_lower = k.trim().to_ascii_lowercase();
                    let v_trim = v.trim();
                    if k_lower == "content-disposition" {
                        for disp_part in v_trim.split(';') {
                            let dp = disp_part.trim();
                            if let Some(unquoted) = dp
                                .strip_prefix("name=\"")
                                .and_then(|s| s.strip_suffix('\"'))
                            {
                                name = unquoted.to_string();
                            } else if let Some(unquoted) = dp
                                .strip_prefix("filename=\"")
                                .and_then(|s| s.strip_suffix('\"'))
                            {
                                filename = Some(unquoted.to_string());
                            }
                        }
                    } else if k_lower == "content-type" {
                        content_type = Some(v_trim.to_string());
                    }
                }
            }

            if !name.is_empty() {
                parts.push(MultipartPart {
                    name,
                    filename,
                    content_type,
                    data: part_data.to_vec(),
                });
            }
        }

        start_idx = part_end;
    }

    Ok(parts)
}

// -------------------------------------------------------------
// SERVER-SENT EVENTS (SSE) & CONTENT NEGOTIATION
// -------------------------------------------------------------

/// Server-Sent Event (SSE) structure according to W3C / WHATWG EventSource specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    pub id: Option<String>,
    pub event: Option<String>,
    pub data: String,
    pub retry: Option<u64>,
    pub comment: Option<String>,
}

impl SseEvent {
    /// Create a new SSE event with data.
    pub fn new(data: impl Into<String>) -> Self {
        Self {
            id: None,
            event: None,
            data: data.into(),
            retry: None,
            comment: None,
        }
    }

    /// Set event type name.
    pub fn with_event(mut self, event: impl Into<String>) -> Self {
        self.event = Some(event.into());
        self
    }

    /// Set event identifier.
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Set reconnection retry time in milliseconds.
    pub fn with_retry(mut self, retry_ms: u64) -> Self {
        self.retry = Some(retry_ms);
        self
    }

    /// Set optional comment / ping line.
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    /// Serialize event into W3C EventSource wire format terminated by double newline "\n\n".
    pub fn to_wire_string(&self) -> String {
        let mut out = String::new();
        if let Some(ref comment) = self.comment {
            out.push_str(": ");
            out.push_str(comment);
            out.push('\n');
        }
        if let Some(ref id) = self.id {
            out.push_str("id: ");
            out.push_str(id);
            out.push('\n');
        }
        if let Some(ref event) = self.event {
            out.push_str("event: ");
            out.push_str(event);
            out.push('\n');
        }
        if let Some(retry) = self.retry {
            out.push_str("retry: ");
            out.push_str(&retry.to_string());
            out.push('\n');
        }

        if self.data.is_empty() {
            out.push_str("data:\n");
        } else {
            for line in self.data.split('\n') {
                let clean_line = line.strip_suffix('\r').unwrap_or(line);
                out.push_str("data: ");
                out.push_str(clean_line);
                out.push('\n');
            }
        }

        out.push('\n');
        out
    }

    /// Serialize event into wire bytes.
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        self.to_wire_string().into_bytes()
    }
}

/// Parse a stream of Server-Sent Events from wire text.
pub fn parse_sse_events(input: &str) -> Vec<SseEvent> {
    let mut events = Vec::new();
    let mut current_id = None;
    let mut current_event = None;
    let mut current_data_lines = Vec::new();
    let mut current_retry = None;
    let mut current_comment = None;
    let mut has_fields = false;

    for line in input.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);

        if line.is_empty() {
            if has_fields {
                events.push(SseEvent {
                    id: current_id.take(),
                    event: current_event.take(),
                    data: current_data_lines.join("\n"),
                    retry: current_retry.take(),
                    comment: current_comment.take(),
                });
                current_data_lines.clear();
                has_fields = false;
            }
            continue;
        }

        if let Some(comment) = line.strip_prefix(':') {
            has_fields = true;
            let c = comment.strip_prefix(' ').unwrap_or(comment);
            current_comment = Some(c.to_string());
        } else if let Some(data) = line.strip_prefix("data:") {
            has_fields = true;
            let val = data.strip_prefix(' ').unwrap_or(data);
            current_data_lines.push(val.to_string());
        } else if let Some(event) = line.strip_prefix("event:") {
            has_fields = true;
            let val = event.strip_prefix(' ').unwrap_or(event);
            current_event = Some(val.to_string());
        } else if let Some(id) = line.strip_prefix("id:") {
            has_fields = true;
            let val = id.strip_prefix(' ').unwrap_or(id);
            current_id = Some(val.to_string());
        } else if let Some(retry) = line.strip_prefix("retry:") {
            has_fields = true;
            let val = retry.trim();
            if let Ok(ms) = val.parse::<u64>() {
                current_retry = Some(ms);
            }
        }
    }

    if has_fields {
        events.push(SseEvent {
            id: current_id,
            event: current_event,
            data: current_data_lines.join("\n"),
            retry: current_retry,
            comment: current_comment,
        });
    }

    events
}

/// Representation of an item in the HTTP `Accept` header with quality score and specificity.
#[derive(Debug, Clone, PartialEq)]
pub struct AcceptItem {
    pub media_type: String,
    pub quality: f32,
    pub specificity: u8,
}

/// Parse HTTP `Accept` header into sorted list of `AcceptItem`s (highest precedence first).
pub fn parse_accept_header(header: &str) -> Vec<AcceptItem> {
    let mut items = Vec::new();

    for part in header.split(',') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }

        let mut subparts = trimmed.split(';');
        let media_type = subparts.next().unwrap_or("").trim().to_ascii_lowercase();
        if media_type.is_empty() {
            continue;
        }

        let mut quality = 1.0f32;
        for param in subparts {
            let p = param.trim();
            if let Some(q_val) = p.strip_prefix("q=") {
                if let Ok(q) = q_val.trim().parse::<f32>() {
                    quality = q.clamp(0.0, 1.0);
                }
            }
        }

        let specificity = if media_type == "*/*" {
            1
        } else if media_type.ends_with("/*") {
            2
        } else {
            3
        };

        items.push(AcceptItem {
            media_type,
            quality,
            specificity,
        });
    }

    items.sort_by(|a, b| {
        b.quality
            .partial_cmp(&a.quality)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.specificity.cmp(&a.specificity))
    });

    items
}

/// Negotiate the most suitable Content-Type from a client's Accept header and available MIME types.
pub fn negotiate_content_type(accept_header: &str, available: &[&str]) -> Option<String> {
    if available.is_empty() {
        return None;
    }

    let accept_items = parse_accept_header(accept_header);
    if accept_items.is_empty() {
        return Some(available[0].to_string());
    }

    for item in &accept_items {
        if item.quality <= 0.0 {
            continue;
        }

        if item.media_type == "*/*" {
            return Some(available[0].to_string());
        }

        if let Some(prefix) = item.media_type.strip_suffix("/*") {
            let type_prefix = format!("{}/", prefix);
            for avail in available {
                if avail.to_ascii_lowercase().starts_with(&type_prefix) {
                    return Some((*avail).to_string());
                }
            }
        } else {
            for avail in available {
                if avail.eq_ignore_ascii_case(&item.media_type) {
                    return Some((*avail).to_string());
                }
            }
        }
    }

    None
}

// ============================================================================
// HTTP Authentication Helpers (RFC 7617, RFC 6750)
// ============================================================================

/// Encode Basic Authentication header value from username and password.
/// Format: "Basic <base64(username:password)>"
pub fn encode_basic_auth(username: &str, password: &str) -> String {
    let creds = format!("{}:{}", username, password);
    let encoded = crate::crypto::base64_encode(creds.as_bytes());
    format!("Basic {}", encoded)
}

/// Parse Basic Authentication header value.
/// Accepts "Basic <base64>" (case-insensitive scheme) and returns Some((user, password)).
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

/// Parse Bearer token from Authorization header value (RFC 6750).
/// Accepts "Bearer <token>" (case-insensitive scheme) and returns Some(token).
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

// ============================================================================
// HTTP CORS (Cross-Origin Resource Sharing) Configuration & Preflight
// ============================================================================

/// Cross-Origin Resource Sharing (CORS) policy configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorsConfig {
    pub allow_origin: String,
    pub allow_methods: String,
    pub allow_headers: String,
    pub max_age_secs: Option<u32>,
    pub allow_credentials: bool,
    pub expose_headers: Option<String>,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allow_origin: "*".to_string(),
            allow_methods: "GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD".to_string(),
            allow_headers: "Content-Type, Authorization, X-Requested-With, Accept".to_string(),
            max_age_secs: Some(86400),
            allow_credentials: false,
            expose_headers: None,
        }
    }
}

impl CorsConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn allow_origin(mut self, origin: impl Into<String>) -> Self {
        self.allow_origin = origin.into();
        self
    }

    pub fn allow_methods(mut self, methods: impl Into<String>) -> Self {
        self.allow_methods = methods.into();
        self
    }

    pub fn allow_headers(mut self, headers: impl Into<String>) -> Self {
        self.allow_headers = headers.into();
        self
    }

    pub fn max_age(mut self, secs: u32) -> Self {
        self.max_age_secs = Some(secs);
        self
    }

    pub fn credentials(mut self, allow: bool) -> Self {
        self.allow_credentials = allow;
        self
    }

    pub fn expose_headers(mut self, headers: impl Into<String>) -> Self {
        self.expose_headers = Some(headers.into());
        self
    }

    /// Apply standard CORS response headers to an HttpResponse.
    pub fn apply(&self, mut resp: HttpResponse) -> HttpResponse {
        resp = resp.header("Access-Control-Allow-Origin", &self.allow_origin);
        if self.allow_credentials {
            resp = resp.header("Access-Control-Allow-Credentials", "true");
        }
        if let Some(expose) = &self.expose_headers {
            resp = resp.header("Access-Control-Expose-Headers", expose);
        }
        resp
    }

    /// Create a 204 No Content preflight response with full Access-Control headers.
    pub fn preflight_response(&self) -> HttpResponse {
        let mut resp = HttpResponse::no_content()
            .header("Access-Control-Allow-Origin", &self.allow_origin)
            .header("Access-Control-Allow-Methods", &self.allow_methods)
            .header("Access-Control-Allow-Headers", &self.allow_headers);
        if let Some(max_age) = self.max_age_secs {
            resp = resp.header("Access-Control-Max-Age", &max_age.to_string());
        }
        if self.allow_credentials {
            resp = resp.header("Access-Control-Allow-Credentials", "true");
        }
        resp
    }
}

// ============================================================================
// HTTP ETag & Conditional Requests (RFC 7232)
// ============================================================================

/// Compute an HTTP ETag string from arbitrary byte content.
/// Strong ETag: "\"<16-char-sha256-hex>\""
/// Weak ETag: "W/\"<16-char-sha256-hex>\""
pub fn compute_etag(content: &[u8], weak: bool) -> String {
    let full_hex = crate::crypto::sha256_hex(content);
    let tag = &full_hex[..16];
    if weak {
        format!("W/\"{}\"", tag)
    } else {
        format!("\"{}\"", tag)
    }
}

/// Matches an entity tag against an If-None-Match header value (RFC 7232 section 3.2).
/// Supports wildcard '*', weak comparisons, and comma-separated lists.
pub fn matches_if_none_match(etag: &str, header_val: &str) -> bool {
    let target = etag.trim();
    let target_clean = target
        .strip_prefix("W/")
        .unwrap_or(target)
        .trim_matches('"');

    for part in header_val.split(',') {
        let p = part.trim();
        if p == "*" {
            return true;
        }
        let p_clean = p.strip_prefix("W/").unwrap_or(p).trim_matches('"');
        if p_clean == target_clean {
            return true;
        }
    }
    false
}

/// Matches an entity tag against an If-Match header value (RFC 7232 section 3.1).
/// Requires strong comparison (neither candidate nor header item can be weak).
pub fn matches_if_match(etag: &str, header_val: &str) -> bool {
    let target = etag.trim();
    if target.starts_with("W/") {
        return false;
    }
    let target_clean = target.trim_matches('"');

    for part in header_val.split(',') {
        let p = part.trim();
        if p == "*" {
            return true;
        }
        if p.starts_with("W/") {
            continue; // Weak ETags not permitted in strong comparison
        }
        let p_clean = p.trim_matches('"');
        if p_clean == target_clean {
            return true;
        }
    }
    false
}

/// Hop-by-hop headers that MUST be removed by an HTTP proxy according to RFC 7230 §6.1.
pub const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

/// Checks if a header name is an RFC 7230 hop-by-hop header.
pub fn is_hop_by_hop_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    HOP_BY_HOP_HEADERS.iter().any(|&h| h == lower)
}

/// Upstream backend target in an HTTP reverse proxy / gateway cluster.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamBackend {
    pub host: String,
    pub port: u16,
    pub weight: u32,
    pub healthy: bool,
    pub active_conns: usize,
}

impl UpstreamBackend {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            weight: 1,
            healthy: true,
            active_conns: 0,
        }
    }

    pub fn with_weight(mut self, weight: u32) -> Self {
        self.weight = weight.max(1);
        self
    }
}

/// Load balancing strategy across upstream backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadBalancingStrategy {
    RoundRobin,
    Random,
    LeastConnections,
}

/// Reverse proxy load balancer managing upstream backends with health tracking.
#[derive(Debug, Clone)]
pub struct HttpLoadBalancer {
    backends: Vec<UpstreamBackend>,
    strategy: LoadBalancingStrategy,
    rr_index: usize,
}

impl HttpLoadBalancer {
    pub fn new(backends: Vec<UpstreamBackend>, strategy: LoadBalancingStrategy) -> Self {
        Self {
            backends,
            strategy,
            rr_index: 0,
        }
    }

    pub fn backends(&self) -> &[UpstreamBackend] {
        &self.backends
    }

    pub fn healthy_count(&self) -> usize {
        self.backends.iter().filter(|b| b.healthy).count()
    }

    pub fn mark_healthy(&mut self, host: &str, port: u16, healthy: bool) {
        for b in &mut self.backends {
            if b.host == host && b.port == port {
                b.healthy = healthy;
            }
        }
    }

    pub fn next_backend(&mut self) -> Option<&UpstreamBackend> {
        if self.backends.is_empty() {
            return None;
        }

        match self.strategy {
            LoadBalancingStrategy::RoundRobin => {
                let total = self.backends.len();
                for _ in 0..total {
                    let idx = self.rr_index % total;
                    self.rr_index = (self.rr_index + 1) % total;
                    if self.backends[idx].healthy {
                        return Some(&self.backends[idx]);
                    }
                }
                Some(&self.backends[0])
            }
            LoadBalancingStrategy::LeastConnections => self
                .backends
                .iter()
                .filter(|b| b.healthy)
                .min_by_key(|b| b.active_conns)
                .or_else(|| self.backends.first()),
            LoadBalancingStrategy::Random => {
                let healthy: Vec<&UpstreamBackend> =
                    self.backends.iter().filter(|b| b.healthy).collect();
                if let Some(b) = healthy.first() {
                    Some(*b)
                } else {
                    self.backends.first()
                }
            }
        }
    }
}

/// HTTP Reverse Proxy Gateway configuration and request/response processor.
#[derive(Debug, Clone)]
pub struct HttpProxyGateway {
    pub via_name: String,
    pub strip_prefix: Option<String>,
    pub preserve_host: bool,
}

impl Default for HttpProxyGateway {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpProxyGateway {
    pub fn new() -> Self {
        Self {
            via_name: "1.1 ifa-gateway".to_string(),
            strip_prefix: None,
            preserve_host: false,
        }
    }

    pub fn strip_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.strip_prefix = Some(prefix.into());
        self
    }

    pub fn preserve_host(mut self, preserve: bool) -> Self {
        self.preserve_host = preserve;
        self
    }

    pub fn rewrite_path<'a>(&'a self, incoming_path: &'a str) -> &'a str {
        if let Some(prefix) = &self.strip_prefix {
            if incoming_path.starts_with(prefix) {
                let remainder = &incoming_path[prefix.len()..];
                if remainder.is_empty() {
                    return "/";
                }
                if !remainder.starts_with('/') {
                    return remainder;
                }
                return remainder;
            }
        }
        incoming_path
    }

    pub fn prepare_upstream_request(
        &self,
        req: &HttpRequest,
        client_ip: &str,
        client_proto: &str,
        upstream_host: &str,
        upstream_port: u16,
    ) -> HttpRequest {
        let rewritten_path = self.rewrite_path(&req.path);
        let mut upstream_req = HttpRequest::new(req.method, rewritten_path);

        // Copy non-hop-by-hop headers
        for (k, v) in req.headers.iter() {
            if !is_hop_by_hop_header(k) && k != "host" {
                upstream_req.headers.set(k.as_str(), v.as_str());
            }
        }

        // Host header
        let host_val = if self.preserve_host {
            req.headers
                .get("host")
                .map(str::to_string)
                .unwrap_or_else(|| {
                    if upstream_port == 80 || upstream_port == 443 {
                        upstream_host.to_string()
                    } else {
                        format!("{}:{}", upstream_host, upstream_port)
                    }
                })
        } else if upstream_port == 80 || upstream_port == 443 {
            upstream_host.to_string()
        } else {
            format!("{}:{}", upstream_host, upstream_port)
        };
        upstream_req.headers.set("Host", host_val);

        // X-Forwarded-For: append if already present
        let x_forwarded_for = match req.headers.get("x-forwarded-for") {
            Some(existing) => format!("{}, {}", existing, client_ip),
            None => client_ip.to_string(),
        };
        upstream_req.headers.set("X-Forwarded-For", x_forwarded_for);

        // X-Forwarded-Proto
        upstream_req.headers.set("X-Forwarded-Proto", client_proto);

        // X-Forwarded-Host
        if let Some(orig_host) = req.headers.get("host") {
            upstream_req.headers.set("X-Forwarded-Host", orig_host);
        }

        // X-Forwarded-Prefix
        if let Some(prefix) = &self.strip_prefix {
            upstream_req
                .headers
                .set("X-Forwarded-Prefix", prefix.as_str());
        }

        // Via header
        let via_val = match req.headers.get("via") {
            Some(existing) => format!("{}, {}", existing, self.via_name),
            None => self.via_name.clone(),
        };
        upstream_req.headers.set("Via", via_val);

        // Body & Content-Length
        if !req.body.is_empty() {
            upstream_req = upstream_req.body(req.body.clone());
        }

        upstream_req
    }

    pub fn prepare_client_response(&self, upstream_resp: HttpResponse) -> HttpResponse {
        let mut client_resp = HttpResponse::new(upstream_resp.status);

        // Filter hop-by-hop headers
        for (k, v) in upstream_resp.headers.iter() {
            if !is_hop_by_hop_header(k) {
                client_resp.headers.set(k.as_str(), v.as_str());
            }
        }

        // Append Via header
        let via_val = match upstream_resp.headers.get("via") {
            Some(existing) => format!("{}, {}", existing, self.via_name),
            None => self.via_name.clone(),
        };
        client_resp.headers.set("Via", via_val);

        client_resp.body = upstream_resp.body;
        client_resp
    }
}

// -------------------------------------------------------------
// HTTP CONNECTION POOLING (KEEP-ALIVE & SOCKET REUSE)
// -------------------------------------------------------------

/// Configuration options for the HTTP Keep-Alive connection pool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpConnectionPoolConfig {
    /// Maximum idle connections preserved per host:port endpoint.
    pub max_idle_per_host: usize,
    /// Maximum total connections (active + idle) across all hosts.
    pub max_total_conns: usize,
    /// Idle connection lifetime in milliseconds before automatic expiration.
    pub idle_timeout_ms: u64,
}

impl Default for HttpConnectionPoolConfig {
    fn default() -> Self {
        Self {
            max_idle_per_host: 8,
            max_total_conns: 64,
            idle_timeout_ms: 15_000,
        }
    }
}

impl HttpConnectionPoolConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn max_idle_per_host(mut self, max: usize) -> Self {
        self.max_idle_per_host = max.max(1);
        self
    }

    pub fn max_total_conns(mut self, max: usize) -> Self {
        self.max_total_conns = max.max(1);
        self
    }

    pub fn idle_timeout_ms(mut self, ms: u64) -> Self {
        self.idle_timeout_ms = ms;
        self
    }
}

/// A pooled socket wrapper tracking connection lifecycle and utilization.
pub struct PooledConnection {
    pub stream: AsyncTcpStream,
    pub host: String,
    pub port: u16,
    pub created_at: Instant,
    pub last_used_at: Instant,
    pub use_count: usize,
}

impl PooledConnection {
    pub fn new(stream: AsyncTcpStream, host: impl Into<String>, port: u16) -> Self {
        let now = Instant::now();
        Self {
            stream,
            host: host.into(),
            port,
            created_at: now,
            last_used_at: now,
            use_count: 0,
        }
    }

    /// Check if idle duration exceeds given timeout.
    pub fn is_idle_expired(&self, timeout: Duration) -> bool {
        self.last_used_at.elapsed() >= timeout
    }

    /// Check if underlying TCP socket is open and healthy.
    pub fn is_healthy(&mut self) -> bool {
        let mut buf = [0u8; 1];
        match self.stream.try_read(&mut buf) {
            Ok(Some(0)) => false, // EOF / closed by remote peer
            Ok(Some(_)) => false, // Unexpected unconsumed byte
            Ok(None) => true,     // Open and waiting (WouldBlock)
            Err(_) => false,      // Socket error
        }
    }
}

/// HTTP Keep-Alive connection pool managing reusable TCP connections per host.
pub struct HttpConnectionPool {
    config: HttpConnectionPoolConfig,
    idle_conns: BTreeMap<(String, u16), Vec<PooledConnection>>,
    active_counts: BTreeMap<(String, u16), usize>,
    total_acquired: usize,
    total_reused: usize,
}

impl Default for HttpConnectionPool {
    fn default() -> Self {
        Self::new(HttpConnectionPoolConfig::default())
    }
}

impl HttpConnectionPool {
    pub fn new(config: HttpConnectionPoolConfig) -> Self {
        Self {
            config,
            idle_conns: BTreeMap::new(),
            active_counts: BTreeMap::new(),
            total_acquired: 0,
            total_reused: 0,
        }
    }

    pub fn config(&self) -> &HttpConnectionPoolConfig {
        &self.config
    }

    pub fn idle_count(&self, host: &str, port: u16) -> usize {
        self.idle_conns
            .get(&(host.to_string(), port))
            .map(|v| v.len())
            .unwrap_or(0)
    }

    pub fn active_count(&self, host: &str, port: u16) -> usize {
        self.active_counts
            .get(&(host.to_string(), port))
            .copied()
            .unwrap_or(0)
    }

    pub fn total_idle(&self) -> usize {
        self.idle_conns.values().map(|v| v.len()).sum()
    }

    pub fn total_active(&self) -> usize {
        self.active_counts.values().sum()
    }

    pub fn total_acquired(&self) -> usize {
        self.total_acquired
    }

    pub fn total_reused(&self) -> usize {
        self.total_reused
    }

    /// Prune expired and closed idle connections. Returns number of purged sockets.
    pub fn prune_idle(&mut self) -> usize {
        let timeout = Duration::from_millis(self.config.idle_timeout_ms);
        let mut purged = 0;
        for list in self.idle_conns.values_mut() {
            let before = list.len();
            list.retain_mut(|conn| !conn.is_idle_expired(timeout) && conn.is_healthy());
            purged += before - list.len();
        }
        purged
    }

    /// Clear and close all idle sockets in the pool.
    pub fn clear(&mut self) {
        self.idle_conns.clear();
        self.active_counts.clear();
    }

    /// Acquire a reusable connection from the pool, or establish a new TCP stream.
    pub fn acquire(&mut self, host: &str, port: u16) -> io::Result<PooledConnection> {
        let timeout = Duration::from_millis(self.config.idle_timeout_ms);
        let key = (host.to_string(), port);

        // Check idle pool for a live, unexpired socket
        if let Some(list) = self.idle_conns.get_mut(&key) {
            while let Some(mut conn) = list.pop() {
                if !conn.is_idle_expired(timeout) && conn.is_healthy() {
                    conn.use_count += 1;
                    conn.last_used_at = Instant::now();
                    self.total_reused += 1;
                    self.total_acquired += 1;
                    *self.active_counts.entry(key).or_insert(0) += 1;
                    return Ok(conn);
                }
            }
        }

        // Establish new connection
        let stream = AsyncTcpStream::connect(format!("{}:{}", host, port))?;
        let mut conn = PooledConnection::new(stream, host, port);
        conn.use_count = 1;
        self.total_acquired += 1;
        *self.active_counts.entry(key).or_insert(0) += 1;
        Ok(conn)
    }

    /// Release an acquired connection back to the pool, or drop it if Keep-Alive is disabled or expired.
    pub fn release(&mut self, mut conn: PooledConnection, can_reuse: bool) {
        let key = (conn.host.clone(), conn.port);
        if let Some(count) = self.active_counts.get_mut(&key) {
            if *count > 0 {
                *count -= 1;
            }
        }

        let timeout = Duration::from_millis(self.config.idle_timeout_ms);
        let total_idle = self.total_idle();
        if can_reuse && !conn.is_idle_expired(timeout) && total_idle < self.config.max_total_conns {
            let host_idle = self.idle_conns.entry(key).or_default();
            if host_idle.len() < self.config.max_idle_per_host {
                conn.last_used_at = Instant::now();
                host_idle.push(conn);
            }
        }
        // Connection dropped and closed automatically
    }

    /// Send an HTTP request reusing pooled connections and handling transparent Keep-Alive retry.
    pub fn send_request(
        &mut self,
        req: &HttpRequest,
        host: &str,
        port: u16,
    ) -> io::Result<HttpResponse> {
        let mut req_wire = req.clone();
        if !req_wire.headers.has("connection") {
            req_wire.headers.set("Connection", "keep-alive");
        }
        if !req_wire.headers.has("host") {
            if port == 80 || port == 443 {
                req_wire.headers.set("Host", host);
            } else {
                req_wire.headers.set("Host", format!("{}:{}", host, port));
            }
        }

        let wire = req_wire.to_wire_bytes();
        let mut conn = self.acquire(host, port)?;

        let write_res = conn.stream.write_all(&wire);
        let was_reused = conn.use_count > 1;

        let (conn, resp_res) = if write_res.is_err() && was_reused {
            self.release(conn, false);
            let mut fresh_conn = self.acquire(host, port)?;
            let fresh_write = fresh_conn.stream.write_all(&wire);
            if let Err(e) = fresh_write {
                self.release(fresh_conn, false);
                return Err(e);
            }
            let resp = read_http_response(&mut fresh_conn.stream);
            (fresh_conn, resp)
        } else if let Err(e) = write_res {
            self.release(conn, false);
            return Err(e);
        } else {
            let resp = read_http_response(&mut conn.stream);
            if resp.is_err() && was_reused {
                self.release(conn, false);
                let mut fresh_conn = self.acquire(host, port)?;
                let fresh_write = fresh_conn.stream.write_all(&wire);
                if let Err(e) = fresh_write {
                    self.release(fresh_conn, false);
                    return Err(e);
                }
                let fresh_resp = read_http_response(&mut fresh_conn.stream);
                (fresh_conn, fresh_resp)
            } else {
                (conn, resp)
            }
        };

        match resp_res {
            Ok(resp) => {
                let can_reuse = http_should_keep_alive(resp.status.0, &resp.headers);
                self.release(conn, can_reuse);
                Ok(resp)
            }
            Err(e) => {
                self.release(conn, false);
                Err(e)
            }
        }
    }
}

impl HttpClient {
    /// Send request utilizing an external connection pool.
    pub fn send_pooled(
        &self,
        pool: &mut HttpConnectionPool,
        req: &HttpRequest,
        host: &str,
        port: u16,
    ) -> io::Result<HttpResponse> {
        pool.send_request(req, host, port)
    }
}

impl HttpProxyGateway {
    /// Forward an incoming request to an upstream backend reusing a connection pool.
    pub fn forward_pooled(
        &self,
        pool: &mut HttpConnectionPool,
        req: &HttpRequest,
        client_ip: &str,
        client_proto: &str,
        backend: &UpstreamBackend,
    ) -> io::Result<HttpResponse> {
        let upstream_req = self.prepare_upstream_request(
            req,
            client_ip,
            client_proto,
            &backend.host,
            backend.port,
        );
        let upstream_resp = pool.send_request(&upstream_req, &backend.host, backend.port)?;
        Ok(self.prepare_client_response(upstream_resp))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_encode_decode_roundtrip() {
        let input = "Hello World! & IFA = 100%?";
        let encoded = url_encode(input);
        assert_eq!(encoded, "Hello%20World%21%20%26%20IFA%20%3D%20100%25%3F");
        let decoded = url_decode(&encoded).expect("decode");
        assert_eq!(decoded, input);

        // Form '+' decoding
        let with_plus = "IFA+Systems+Programming";
        assert_eq!(url_decode(with_plus).unwrap(), "IFA Systems Programming");
    }

    #[test]
    fn test_form_urlencoded() {
        let params = [
            ("user", "Dieudonné Assogba"),
            ("email", "jprud67@gmail.com"),
            ("status", "active & verified"),
        ];
        let encoded = format_form_urlencoded(&params);
        let parsed = parse_form_urlencoded(&encoded);

        assert_eq!(
            parsed.get("user").map(|s| s.as_str()),
            Some("Dieudonné Assogba")
        );
        assert_eq!(
            parsed.get("email").map(|s| s.as_str()),
            Some("jprud67@gmail.com")
        );
        assert_eq!(
            parsed.get("status").map(|s| s.as_str()),
            Some("active & verified")
        );

        // HttpRequest integration
        let req = HttpRequest::new(HttpMethod::Post, "/api/v1/login").form_urlencoded_body(&params);
        assert_eq!(
            req.headers.get("content-type"),
            Some("application/x-www-form-urlencoded")
        );
        let parsed_req_form = req.form_urlencoded().expect("parse req form");
        assert_eq!(
            parsed_req_form.get("user").map(|s| s.as_str()),
            Some("Dieudonné Assogba")
        );
    }

    #[test]
    fn test_http_cookies() {
        let cookie_header = "sessionId=ifa_sec_token_9876; user_role=admin; theme=dark";
        let cookies = parse_cookies(cookie_header);
        assert_eq!(
            cookies.get("sessionId").map(|s| s.as_str()),
            Some("ifa_sec_token_9876")
        );
        assert_eq!(cookies.get("user_role").map(|s| s.as_str()), Some("admin"));
        assert_eq!(cookies.get("theme").map(|s| s.as_str()), Some("dark"));
        assert_eq!(cookies.get("missing"), None);

        let formatted = format_set_cookie(
            "sessionId",
            "ifa_sec_token_9876",
            Some("/api"),
            Some(7200),
            true,
            true,
            Some("Strict"),
        );
        assert_eq!(
            formatted,
            "sessionId=ifa_sec_token_9876; Path=/api; Max-Age=7200; SameSite=Strict; Secure; HttpOnly"
        );

        let resp = HttpResponse::ok().set_cookie(
            "sessionId",
            "ifa_sec_token_9876",
            Some("/api"),
            Some(7200),
            true,
            true,
            Some("Strict"),
        );
        assert_eq!(resp.headers.get("set-cookie"), Some(formatted.as_str()));
    }

    #[test]
    fn test_multipart_form_data() {
        let builder = MultipartBuilder::new("ifaBoundary4242")
            .add_field("username", "prudence")
            .add_field("description", "IFA Systems Programming")
            .add_file(
                "document",
                "report.txt",
                "text/plain",
                b"Deterministic compilation fixed point OK",
            );

        assert_eq!(
            builder.content_type(),
            "multipart/form-data; boundary=ifaBoundary4242"
        );

        let wire_body = builder.finish();
        let parts = parse_multipart(&wire_body, "ifaBoundary4242").expect("parse multipart");
        assert_eq!(parts.len(), 3);

        assert_eq!(parts[0].name, "username");
        assert_eq!(parts[0].filename, None);
        assert_eq!(parts[0].content_type, None);
        assert_eq!(parts[0].data, b"prudence");

        assert_eq!(parts[1].name, "description");
        assert_eq!(parts[1].data, b"IFA Systems Programming");

        assert_eq!(parts[2].name, "document");
        assert_eq!(parts[2].filename.as_deref(), Some("report.txt"));
        assert_eq!(parts[2].content_type.as_deref(), Some("text/plain"));
        assert_eq!(parts[2].data, b"Deterministic compilation fixed point OK");
    }

    #[test]
    fn test_sse_event_formatting_and_parsing() {
        let ev1 = SseEvent::new("Hello IFA Fiber Stream")
            .with_event("greeting")
            .with_id("msg-001")
            .with_retry(5000)
            .with_comment("heartbeat ping");

        let wire1 = ev1.to_wire_string();
        assert!(wire1.starts_with(": heartbeat ping\n"));
        assert!(wire1.contains("id: msg-001\n"));
        assert!(wire1.contains("event: greeting\n"));
        assert!(wire1.contains("retry: 5000\n"));
        assert!(wire1.contains("data: Hello IFA Fiber Stream\n"));
        assert!(wire1.ends_with("\n\n"));

        let ev2 = SseEvent::new("line1\nline2\nline3").with_event("multiline");
        let wire2 = ev2.to_wire_string();
        assert!(wire2.contains("data: line1\ndata: line2\ndata: line3\n\n"));

        // Parse stream containing multiple events
        let full_stream = format!("{}{}", wire1, wire2);
        let parsed = parse_sse_events(&full_stream);
        assert_eq!(parsed.len(), 2);

        assert_eq!(parsed[0].id.as_deref(), Some("msg-001"));
        assert_eq!(parsed[0].event.as_deref(), Some("greeting"));
        assert_eq!(parsed[0].retry, Some(5000));
        assert_eq!(parsed[0].comment.as_deref(), Some("heartbeat ping"));
        assert_eq!(parsed[0].data, "Hello IFA Fiber Stream");

        assert_eq!(parsed[1].id, None);
        assert_eq!(parsed[1].event.as_deref(), Some("multiline"));
        assert_eq!(parsed[1].data, "line1\nline2\nline3");

        // Test HttpResponse SSE builder
        let resp = HttpResponse::sse().sse_event(&ev1).sse_event(&ev2);
        assert_eq!(resp.headers.get("content-type"), Some("text/event-stream"));
        assert_eq!(resp.headers.get("cache-control"), Some("no-cache"));
        assert_eq!(resp.headers.get("connection"), Some("keep-alive"));
        assert_eq!(resp.body, full_stream.as_bytes());
    }

    #[test]
    fn test_content_negotiation() {
        let available = ["application/json", "text/html", "text/plain"];

        // Client accepts JSON
        let chosen = negotiate_content_type("application/json", &available);
        assert_eq!(chosen.as_deref(), Some("application/json"));

        // Client prefers HTML over JSON
        let chosen2 = negotiate_content_type("application/json;q=0.8, text/html;q=1.0", &available);
        assert_eq!(chosen2.as_deref(), Some("text/html"));

        // Client prefers wildcard text/*
        let chosen3 = negotiate_content_type("text/*;q=0.9, image/webp", &available);
        assert_eq!(chosen3.as_deref(), Some("text/html"));

        // Client accepts anything */*
        let chosen4 = negotiate_content_type("*/*;q=0.1", &available);
        assert_eq!(chosen4.as_deref(), Some("application/json"));

        // Client accepts only unsupported type
        let chosen5 = negotiate_content_type("image/png, audio/mpeg", &available);
        assert_eq!(chosen5, None);

        // Test HttpRequest methods
        let req = HttpRequest::new(HttpMethod::Get, "/api/resource")
            .header("Accept", "text/html, application/json;q=0.9, */*;q=0.8")
            .header("Content-Type", "application/json; charset=utf-8");

        assert!(req.accepts("text/html"));
        assert!(req.accepts("application/json"));
        assert!(req.accepts("application/xml")); // Matches */*;q=0.8
        assert!(req.is_json());
        assert!(!req.is_sse());
        assert_eq!(
            req.negotiate_content_type(&available).as_deref(),
            Some("text/html")
        );

        let sse_req =
            HttpRequest::new(HttpMethod::Get, "/events").header("Accept", "text/event-stream");
        assert!(sse_req.is_sse());
        assert!(sse_req.accepts("text/event-stream"));
    }

    #[test]
    fn test_http_auth_cors_and_etag() {
        // 1. Basic Auth encoding and decoding
        let basic_header = encode_basic_auth("aladdin", "open sesame");
        assert_eq!(basic_header, "Basic YWxhZGRpbjpvcGVuIHNlc2FtZQ==");
        let parsed_creds = parse_basic_auth(&basic_header);
        assert_eq!(
            parsed_creds,
            Some(("aladdin".to_string(), "open sesame".to_string()))
        );

        // Case-insensitive scheme and whitespace tolerance
        let mixed_case = "   bAsIc   YWxhZGRpbjpvcGVuIHNlc2FtZQ==  ";
        assert_eq!(
            parse_basic_auth(mixed_case),
            Some(("aladdin".to_string(), "open sesame".to_string()))
        );
        assert_eq!(parse_basic_auth("Bearer some-token"), None);
        assert_eq!(parse_basic_auth("Basic !!!invalid-b64"), None);

        // 2. Bearer Token
        let bearer_hdr = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M";
        assert_eq!(
            parse_bearer_token(bearer_hdr),
            Some("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M".to_string())
        );
        assert_eq!(
            parse_bearer_token("bearer  my_api_key_12345 "),
            Some("my_api_key_12345".to_string())
        );
        assert_eq!(
            parse_bearer_token("Basic YWxhZGRpbjpvcGVuIHNlc2FtZQ=="),
            None
        );

        // 3. HttpRequest auth helpers
        let req_with_auth =
            HttpRequest::new(HttpMethod::Get, "/api/secure").header("Authorization", &basic_header);
        assert_eq!(
            req_with_auth.basic_auth(),
            Some(("aladdin".to_string(), "open sesame".to_string()))
        );
        assert_eq!(req_with_auth.bearer_token(), None);

        let req_with_bearer = HttpRequest::new(HttpMethod::Get, "/api/token-gated")
            .header("Authorization", "Bearer tok_live_abcdef123456");
        assert_eq!(
            req_with_bearer.bearer_token(),
            Some("tok_live_abcdef123456".to_string())
        );

        // 4. HttpResponse unauthorized
        let unauth = HttpResponse::unauthorized("IFA Secure API");
        assert_eq!(unauth.status, HttpStatus::UNAUTHORIZED);
        assert_eq!(
            unauth.headers.get("www-authenticate"),
            Some("Basic realm=\"IFA Secure API\"")
        );

        // 5. CORS Config & Preflight
        let cors = CorsConfig::new()
            .allow_origin("https://ifa-lang.org")
            .allow_methods("GET, POST, OPTIONS")
            .allow_headers("Content-Type, Authorization, X-Request-ID")
            .max_age(3600)
            .credentials(true)
            .expose_headers("X-RateLimit-Remaining");

        let preflight_resp = cors.preflight_response();
        assert_eq!(preflight_resp.status, HttpStatus::NO_CONTENT);
        assert_eq!(
            preflight_resp.headers.get("access-control-allow-origin"),
            Some("https://ifa-lang.org")
        );
        assert_eq!(
            preflight_resp.headers.get("access-control-allow-methods"),
            Some("GET, POST, OPTIONS")
        );
        assert_eq!(
            preflight_resp.headers.get("access-control-allow-headers"),
            Some("Content-Type, Authorization, X-Request-ID")
        );
        assert_eq!(
            preflight_resp.headers.get("access-control-max-age"),
            Some("3600")
        );
        assert_eq!(
            preflight_resp
                .headers
                .get("access-control-allow-credentials"),
            Some("true")
        );

        let standard_resp = HttpResponse::ok().text("cors payload");
        let applied_resp = cors.apply(standard_resp);
        assert_eq!(
            applied_resp.headers.get("access-control-allow-origin"),
            Some("https://ifa-lang.org")
        );
        assert_eq!(
            applied_resp.headers.get("access-control-expose-headers"),
            Some("X-RateLimit-Remaining")
        );

        // HttpRequest CORS preflight check
        let preflight_req = HttpRequest::new(HttpMethod::Options, "/api/data")
            .header("Origin", "https://ifa-lang.org")
            .header("Access-Control-Request-Method", "POST");
        assert!(preflight_req.is_cors_preflight());

        let non_preflight =
            HttpRequest::new(HttpMethod::Get, "/api/data").header("Origin", "https://ifa-lang.org");
        assert!(!non_preflight.is_cors_preflight());

        // 6. ETag & Conditional Requests (RFC 7232)
        let body = b"System deterministic bytecode artifact";
        let strong_etag = compute_etag(body, false);
        let weak_etag = compute_etag(body, true);

        assert!(strong_etag.starts_with('"') && strong_etag.ends_with('"'));
        assert!(weak_etag.starts_with("W/\"") && weak_etag.ends_with('"'));

        // If-None-Match matching
        assert!(matches_if_none_match(&strong_etag, &strong_etag));
        assert!(matches_if_none_match(&strong_etag, &weak_etag)); // Weak match allowed for If-None-Match
        assert!(matches_if_none_match(&weak_etag, &strong_etag));
        assert!(matches_if_none_match(&strong_etag, "*"));
        assert!(matches_if_none_match(
            &strong_etag,
            &format!("\"other-tag\", {}", strong_etag)
        ));
        assert!(!matches_if_none_match(&strong_etag, "\"mismatched-tag\""));

        // If-Match matching (strong comparison)
        assert!(matches_if_match(&strong_etag, &strong_etag));
        assert!(!matches_if_match(&weak_etag, &strong_etag)); // Weak candidate disallowed
        assert!(!matches_if_match(&strong_etag, &weak_etag)); // Weak header item disallowed
        assert!(matches_if_match(&strong_etag, "*"));
        assert!(matches_if_match(
            &strong_etag,
            &format!("\"tag1\", {}", strong_etag)
        ));
        assert!(!matches_if_match(&strong_etag, "\"tag1\", \"tag2\""));

        // HttpRequest conditional request helpers
        let cond_req =
            HttpRequest::new(HttpMethod::Get, "/resource").header("If-None-Match", &strong_etag);
        assert!(cond_req.if_none_match(&strong_etag));
        assert!(!cond_req.if_none_match("\"outdated-tag\""));

        let not_mod = HttpResponse::not_modified(Some(&strong_etag));
        assert_eq!(not_mod.status, HttpStatus::NOT_MODIFIED);
        assert_eq!(not_mod.headers.get("etag"), Some(strong_etag.as_str()));
    }

    #[test]
    fn test_dynamic_uri_router_and_path_params() {
        let mut router = HttpRouter::new();
        router.get("/api/v1/health", |_| HttpResponse::ok().text("healthy"));
        router.get("/api/v1/users/:user_id/posts/:post_id", |req| {
            let u = req.param("user_id").unwrap_or("missing");
            let p = req.param("post_id").unwrap_or("missing");
            HttpResponse::ok().text(format!("User {} Post {}", u, p))
        });
        router.post("/orders/:order_id/items", |req| {
            let o = req.param("order_id").unwrap_or("missing");
            HttpResponse::created().text(format!("Item added to order {}", o))
        });
        router.get("/assets/*filepath", |req| {
            let f = req.param("filepath").unwrap_or("missing");
            HttpResponse::ok().text(format!("Asset {}", f))
        });

        // 1. Match static
        let (r1, p1) = router
            .match_route(&HttpMethod::Get, "/api/v1/health")
            .expect("Match static");
        assert_eq!(r1.pattern, "/api/v1/health");
        assert!(p1.is_empty());

        // 2. Match dynamic parameters with query string ignored
        let (r2, p2) = router
            .match_route(
                &HttpMethod::Get,
                "/api/v1/users/usr-42/posts/pst-999?expand=all",
            )
            .expect("Match dynamic");
        assert_eq!(r2.pattern, "/api/v1/users/:user_id/posts/:post_id");
        assert_eq!(p2.get("user_id").map(|s| s.as_str()), Some("usr-42"));
        assert_eq!(p2.get("post_id").map(|s| s.as_str()), Some("pst-999"));

        // 3. Match POST with dynamic param
        let (r3, p3) = router
            .match_route(&HttpMethod::Post, "/orders/ORD-777/items")
            .expect("Match POST dynamic");
        assert_eq!(r3.pattern, "/orders/:order_id/items");
        assert_eq!(p3.get("order_id").map(|s| s.as_str()), Some("ORD-777"));

        // 4. Match wildcard
        let (r4, p4) = router
            .match_route(&HttpMethod::Get, "/assets/images/icons/logo.png")
            .expect("Match wildcard");
        assert_eq!(r4.pattern, "/assets/*filepath");
        assert_eq!(
            p4.get("filepath").map(|s| s.as_str()),
            Some("images/icons/logo.png")
        );

        // 5. Mismatched methods or paths
        assert!(router
            .match_route(&HttpMethod::Put, "/api/v1/health")
            .is_none());
        assert!(router
            .match_route(&HttpMethod::Get, "/api/v1/users/42")
            .is_none());
        assert!(router
            .match_route(&HttpMethod::Get, "/orders/ORD-777/items")
            .is_none());

        // 6. Test integrated HttpServer with dynamic parameters
        let mut server = HttpServer::new(0);
        server.get("/api/v1/agents/:agent_id", |req| {
            let id = req.param("agent_id").unwrap_or("anon");
            HttpResponse::ok().text(format!("Agent: {}", id))
        });

        let bound_addr = server.listen_background().expect("Server listen failed");
        let client = HttpClient::new();

        let resp = client
            .get("127.0.0.1", bound_addr.port(), "/api/v1/agents/AGT-4048")
            .expect("Client GET failed");
        assert_eq!(resp.status, HttpStatus::OK);
        assert_eq!(resp.body_str().unwrap(), "Agent: AGT-4048");

        server.stop();
    }

    #[test]
    fn test_rfc6455_websocket_handshake() {
        let client_key = "dGhlIHNhbXBsZSBub25jZQ==";
        let expected_accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

        // 1. Client handshake request construction
        let req = HttpRequest::websocket_handshake("/chat/v1", "localhost:8080", client_key)
            .header("Sec-WebSocket-Protocol", "chat.ifa, binary.ifa");

        assert!(req.is_websocket_upgrade());
        assert_eq!(req.websocket_key(), Some(client_key));
        assert_eq!(req.websocket_protocol(), Some("chat.ifa, binary.ifa"));

        // 2. Server upgrade response generation
        let resp = req
            .websocket_upgrade_response(Some("chat.ifa"))
            .expect("Upgrade response should be generated");

        assert_eq!(resp.status.0, 101);
        assert_eq!(resp.headers.get("upgrade"), Some("websocket"));
        assert_eq!(resp.headers.get("connection"), Some("Upgrade"));
        assert_eq!(
            resp.headers.get("sec-websocket-accept"),
            Some(expected_accept)
        );
        assert_eq!(resp.headers.get("sec-websocket-protocol"), Some("chat.ifa"));

        // 3. Client validation
        assert!(resp.is_websocket_upgrade());
        assert!(resp.verify_websocket_accept(client_key));
        assert!(!resp.verify_websocket_accept("invalid_other_key=="));

        // 4. Negative tests
        let bad_method = HttpRequest::new(HttpMethod::Post, "/ws")
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .header("Sec-WebSocket-Key", client_key)
            .header("Sec-WebSocket-Version", "13");
        assert!(!bad_method.is_websocket_upgrade());

        let bad_ver = HttpRequest::new(HttpMethod::Get, "/ws")
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .header("Sec-WebSocket-Key", client_key)
            .header("Sec-WebSocket-Version", "8");
        assert!(!bad_ver.is_websocket_upgrade());

        let missing_key = HttpRequest::new(HttpMethod::Get, "/ws")
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .header("Sec-WebSocket-Version", "13");
        assert!(!missing_key.is_websocket_upgrade());
        assert!(missing_key.websocket_upgrade_response(None).is_none());
    }

    #[test]
    fn test_http_reverse_proxy_gateway_and_load_balancer() {
        // 1. Hop-by-hop headers
        assert!(is_hop_by_hop_header("Connection"));
        assert!(is_hop_by_hop_header("keep-alive"));
        assert!(is_hop_by_hop_header("Upgrade"));
        assert!(is_hop_by_hop_header("Transfer-Encoding"));
        assert!(is_hop_by_hop_header("Proxy-Authorization"));
        assert!(!is_hop_by_hop_header("Content-Type"));
        assert!(!is_hop_by_hop_header("Authorization"));
        assert!(!is_hop_by_hop_header("X-Custom-Header"));

        // 2. Load Balancer Round Robin & Health Tracking
        let backends = vec![
            UpstreamBackend::new("10.0.0.1", 8080),
            UpstreamBackend::new("10.0.0.2", 8080),
            UpstreamBackend::new("10.0.0.3", 8080),
        ];
        let mut lb = HttpLoadBalancer::new(backends, LoadBalancingStrategy::RoundRobin);
        assert_eq!(lb.healthy_count(), 3);

        let b1 = lb.next_backend().unwrap();
        assert_eq!(b1.host, "10.0.0.1");
        let b2 = lb.next_backend().unwrap();
        assert_eq!(b2.host, "10.0.0.2");
        let b3 = lb.next_backend().unwrap();
        assert_eq!(b3.host, "10.0.0.3");
        let b4 = lb.next_backend().unwrap();
        assert_eq!(b4.host, "10.0.0.1");

        // Mark 10.0.0.2 as unhealthy
        lb.mark_healthy("10.0.0.2", 8080, false);
        assert_eq!(lb.healthy_count(), 2);

        // Next should cycle 10.0.0.3 -> 10.0.0.1 (skipping 10.0.0.2)
        let b5 = lb.next_backend().unwrap();
        assert_eq!(b5.host, "10.0.0.3");
        let b6 = lb.next_backend().unwrap();
        assert_eq!(b6.host, "10.0.0.1");
        let b7 = lb.next_backend().unwrap();
        assert_eq!(b7.host, "10.0.0.3");

        // 3. Reverse Proxy Gateway Request Preparation
        let gateway = HttpProxyGateway::new()
            .strip_prefix("/api/v1")
            .preserve_host(false);

        let incoming_req = HttpRequest::new(HttpMethod::Post, "/api/v1/orders/create")
            .header("Host", "api.example.com")
            .header("User-Agent", "IFA-Client/1.0")
            .header("Connection", "keep-alive")
            .header("Upgrade", "websocket")
            .header("Authorization", "Bearer sec_tok_42")
            .body(b"{\"order_id\":\"ORD-101\"}".to_vec());

        let upstream_req = gateway.prepare_upstream_request(
            &incoming_req,
            "192.168.1.100",
            "https",
            "backend.internal",
            8080,
        );

        // Verify path rewritten
        assert_eq!(upstream_req.path, "/orders/create");
        // Verify host updated to upstream
        assert_eq!(
            upstream_req.headers.get("host"),
            Some("backend.internal:8080")
        );
        // Verify hop-by-hop headers stripped
        assert!(!upstream_req.headers.has("connection"));
        assert!(!upstream_req.headers.has("upgrade"));
        // Verify standard headers preserved
        assert_eq!(
            upstream_req.headers.get("authorization"),
            Some("Bearer sec_tok_42")
        );
        assert_eq!(
            upstream_req.headers.get("user-agent"),
            Some("IFA-Client/1.0")
        );
        // Verify gateway forwarding headers
        assert_eq!(
            upstream_req.headers.get("x-forwarded-for"),
            Some("192.168.1.100")
        );
        assert_eq!(upstream_req.headers.get("x-forwarded-proto"), Some("https"));
        assert_eq!(
            upstream_req.headers.get("x-forwarded-host"),
            Some("api.example.com")
        );
        assert_eq!(
            upstream_req.headers.get("x-forwarded-prefix"),
            Some("/api/v1")
        );
        assert_eq!(upstream_req.headers.get("via"), Some("1.1 ifa-gateway"));
        assert_eq!(upstream_req.body, b"{\"order_id\":\"ORD-101\"}");

        // 4. Reverse Proxy Gateway Response Sanitization
        let upstream_resp = HttpResponse::ok()
            .text("{\"status\":\"created\"}")
            .header("Content-Type", "application/json")
            .header("Connection", "close")
            .header("Keep-Alive", "timeout=5")
            .header("X-Server-Id", "node-3");

        let client_resp = gateway.prepare_client_response(upstream_resp);
        assert_eq!(client_resp.status, HttpStatus::OK);
        assert_eq!(
            client_resp.headers.get("content-type"),
            Some("application/json")
        );
        assert_eq!(client_resp.headers.get("x-server-id"), Some("node-3"));
        assert!(!client_resp.headers.has("connection"));
        assert!(!client_resp.headers.has("keep-alive"));
        assert_eq!(client_resp.headers.get("via"), Some("1.1 ifa-gateway"));
        assert_eq!(client_resp.body_str().unwrap(), "{\"status\":\"created\"}");
    }

    #[test]
    fn test_http_connection_pool_keep_alive_and_socket_reuse() {
        // 1. Config validation
        let config = HttpConnectionPoolConfig::new()
            .max_idle_per_host(4)
            .max_total_conns(16)
            .idle_timeout_ms(5000);
        assert_eq!(config.max_idle_per_host, 4);
        assert_eq!(config.max_total_conns, 16);
        assert_eq!(config.idle_timeout_ms, 5000);

        // 2. Start HTTP server supporting Keep-Alive
        let mut server = HttpServer::new(0);
        server.get("/api/ping", |_req| {
            HttpResponse::ok()
                .text("pong")
                .header("Content-Type", "text/plain")
        });
        server.get("/api/data", |_req| {
            HttpResponse::ok()
                .text("{\"ok\":true}")
                .header("Content-Type", "application/json")
        });

        let bound_addr = server.listen_background().expect("Server listen failed");
        let port = bound_addr.port();

        // 3. Connection pool execution
        let mut pool = HttpConnectionPool::new(config);
        assert_eq!(pool.total_idle(), 0);
        assert_eq!(pool.total_active(), 0);
        assert_eq!(pool.total_acquired(), 0);
        assert_eq!(pool.total_reused(), 0);

        let req1 = HttpRequest::new(HttpMethod::Get, "/api/ping");
        let resp1 = pool
            .send_request(&req1, "127.0.0.1", port)
            .expect("First pooled request failed");
        assert_eq!(resp1.status, HttpStatus::OK);
        assert_eq!(resp1.body_str().unwrap(), "pong");
        assert_eq!(pool.total_acquired(), 1);
        assert_eq!(pool.total_reused(), 0);
        assert_eq!(pool.total_idle(), 1);
        assert_eq!(pool.idle_count("127.0.0.1", port), 1);
        assert_eq!(pool.total_active(), 0);

        // 4. Second request on same host:port should reuse the idle socket
        let req2 = HttpRequest::new(HttpMethod::Get, "/api/data");
        let resp2 = pool
            .send_request(&req2, "127.0.0.1", port)
            .expect("Second pooled request failed");
        assert_eq!(resp2.status, HttpStatus::OK);
        assert_eq!(resp2.body_str().unwrap(), "{\"ok\":true}");
        assert_eq!(pool.total_acquired(), 2);
        assert_eq!(pool.total_reused(), 1);
        assert_eq!(pool.total_idle(), 1);

        // 5. Third request via HttpClient::send_pooled
        let client = HttpClient::new();
        let resp3 = client
            .send_pooled(&mut pool, &req1, "127.0.0.1", port)
            .expect("Third pooled request failed");
        assert_eq!(resp3.status, HttpStatus::OK);
        assert_eq!(resp3.body_str().unwrap(), "pong");
        assert_eq!(pool.total_acquired(), 3);
        assert_eq!(pool.total_reused(), 2);

        // 6. Test prune_idle & clear
        let pruned = pool.prune_idle();
        assert_eq!(pruned, 0); // Not expired yet
        assert_eq!(pool.total_idle(), 1);

        pool.clear();
        assert_eq!(pool.total_idle(), 0);
        assert_eq!(pool.total_active(), 0);

        server.stop();
    }
}

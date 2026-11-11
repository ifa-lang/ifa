use crate::json::{self, JsonValue};
use std::collections::HashMap;

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
}

impl HttpRequest {
    pub fn new(method: HttpMethod, path: impl Into<String>) -> Self {
        Self {
            method,
            path: path.into(),
            headers: HttpHeaders::new(),
            body: Vec::new(),
        }
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
}

// -------------------------------------------------------------
// COLORLESS NON-BLOCKING ASYNC HTTP SERVER & CLIENT (ZERO-GC)
// -------------------------------------------------------------

use ifa_runtime::reactor::{AsyncTcpListener, AsyncTcpStream};
use ifa_runtime::GLOBAL_SCHEDULER;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub type HttpHandler = Arc<dyn Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static>;

/// High-performance, non-blocking HTTP server driven by IFA colorless fibers.
pub struct HttpServer {
    port: u16,
    routes: Arc<Vec<(HttpMethod, String, HttpHandler)>>,
    is_running: Arc<AtomicBool>,
}

impl HttpServer {
    /// Create a new HTTP Server on the specified port.
    pub fn new(port: u16) -> Self {
        Self {
            port,
            routes: Arc::new(Vec::new()),
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
        let routes = Arc::get_mut(&mut self.routes).expect("Cannot register route while listening");
        routes.push((method, path.into(), Arc::new(handler)));
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

    /// Start listening in a background colorless fiber and return bound address.
    pub fn listen_background(&self) -> io::Result<std::net::SocketAddr> {
        let listener = AsyncTcpListener::bind(format!("127.0.0.1:{}", self.port))?;
        let addr = listener.local_addr()?;
        self.is_running.store(true, Ordering::SeqCst);

        let running = Arc::clone(&self.is_running);
        let routes = Arc::clone(&self.routes);

        GLOBAL_SCHEDULER.spawn(move || {
            while running.load(Ordering::Relaxed) {
                if let Ok(Some((mut stream, _))) = listener.try_accept() {
                    let routes_worker = Arc::clone(&routes);
                    GLOBAL_SCHEDULER.spawn(move || {
                        let mut buf = vec![0u8; 8192];
                        if let Ok(n) = stream.read(&mut buf) {
                            if n > 0 {
                                let res = match HttpRequest::parse_from_wire(&buf[..n]) {
                                    Ok((req, _)) => {
                                        let mut matched = None;
                                        for (m, p, h) in routes_worker.iter() {
                                            if *m == req.method && p == &req.path {
                                                matched = Some(h(&req));
                                                break;
                                            }
                                        }
                                        matched.unwrap_or_else(|| {
                                            HttpResponse::not_found().text("Route not found")
                                        })
                                    }
                                    Err(err) => HttpResponse::bad_request()
                                        .text(format!("Invalid HTTP request: {}", err)),
                                };

                                let wire = res.to_wire_bytes();
                                let _ = stream.write_all(&wire);
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

        let mut buf = vec![0u8; 16384];
        let mut total_read = 0;
        let mut spins = 0;

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
                }
                Ok(None) | Err(_) => {
                    spins += 1;
                    if spins < 32 {
                        std::hint::spin_loop();
                    } else {
                        GLOBAL_SCHEDULER.yield_now();
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                }
            }
        }
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
}

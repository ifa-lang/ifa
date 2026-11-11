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

    pub fn bad_request() -> Self {
        Self::new(HttpStatus::BAD_REQUEST)
    }

    pub fn not_found() -> Self {
        Self::new(HttpStatus::NOT_FOUND)
    }

    pub fn server_error() -> Self {
        Self::new(HttpStatus::INTERNAL_SERVER_ERROR)
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
}

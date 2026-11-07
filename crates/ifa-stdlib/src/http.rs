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

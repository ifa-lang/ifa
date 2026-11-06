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
}

use crate::crypto::{constant_time_eq, Jwt, JwtClaims, JwtError};
use crate::json::{self, JsonValue};
use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Encode byte slices into an HTTP/1.1 chunked transfer stream (RFC 7230 §4.1).
/// Each non-empty chunk is serialized as `<hex-len>\r\n<data>\r\n`.
/// A terminating `0\r\n\r\n` chunk is appended.
pub fn encode_chunked(chunks: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in chunks {
        if !chunk.is_empty() {
            out.extend_from_slice(format!("{:X}\r\n", chunk.len()).as_bytes());
            out.extend_from_slice(chunk);
            out.extend_from_slice(b"\r\n");
        }
    }
    out.extend_from_slice(b"0\r\n\r\n");
    out
}

/// Decode an HTTP/1.1 chunked transfer encoded stream (RFC 7230 §4.1).
/// Returns `Ok((decoded_body, bytes_consumed, trailers))` if complete chunked stream is read,
/// or `Err("Incomplete chunked body")` if the buffer is incomplete,
/// or `Err(...)` on syntax error.
pub fn decode_chunked_stream(raw: &[u8]) -> Result<(Vec<u8>, usize, HttpHeaders), String> {
    let mut body = Vec::new();
    let mut offset = 0;
    let mut trailers = HttpHeaders::new();

    loop {
        let crlf_pos = raw[offset..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| "Incomplete chunked body".to_string())?;

        let line_bytes = &raw[offset..offset + crlf_pos];
        let line_str = std::str::from_utf8(line_bytes)
            .map_err(|e| format!("Invalid UTF-8 in chunk size: {}", e))?;

        let size_str = line_str.split(';').next().unwrap_or("").trim();
        let chunk_size = usize::from_str_radix(size_str, 16)
            .map_err(|e| format!("Invalid hex chunk size '{}': {}", size_str, e))?;

        let chunk_data_start = offset + crlf_pos + 2;

        if chunk_size == 0 {
            let remaining = &raw[chunk_data_start..];
            let trailer_end = remaining
                .windows(2)
                .position(|w| w == b"\r\n")
                .ok_or_else(|| "Incomplete chunked body".to_string())?;

            if trailer_end == 0 {
                let total_consumed = chunk_data_start + 2;
                return Ok((body, total_consumed, trailers));
            }

            let full_trailer_end = remaining
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .ok_or_else(|| "Incomplete chunked body".to_string())?;

            let trailer_str = std::str::from_utf8(&remaining[..full_trailer_end])
                .map_err(|e| format!("Invalid UTF-8 in chunk trailers: {}", e))?;

            for tline in trailer_str.split("\r\n") {
                if let Some((k, v)) = tline.split_once(':') {
                    trailers.append(k.trim(), v.trim());
                }
            }

            let total_consumed = chunk_data_start + full_trailer_end + 4;
            return Ok((body, total_consumed, trailers));
        }

        let chunk_data_end = chunk_data_start + chunk_size;
        if raw.len() < chunk_data_end + 2 {
            return Err("Incomplete chunked body".to_string());
        }

        if &raw[chunk_data_end..chunk_data_end + 2] != b"\r\n" {
            return Err("Missing CRLF after chunk data".to_string());
        }

        body.extend_from_slice(&raw[chunk_data_start..chunk_data_end]);
        offset = chunk_data_end + 2;
    }
}

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
    pub const INTERNAL_SERVER_ERROR: HttpStatus = HttpStatus(500);
    pub const BAD_GATEWAY: HttpStatus = HttpStatus(502);
    pub const SERVICE_UNAVAILABLE: HttpStatus = HttpStatus(503);
    pub const GATEWAY_TIMEOUT: HttpStatus = HttpStatus(504);

    /// Numeric HTTP status code.
    pub fn code(&self) -> u16 {
        self.0
    }

    /// Check whether the status represents a redirection (3xx).
    pub fn is_redirection(&self) -> bool {
        self.0 >= 300 && self.0 < 400
    }

    pub fn reason_phrase(&self) -> &'static str {
        match self.0 {
            200 => "OK",
            201 => "Created",
            204 => "No Content",
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
            500 => "Internal Server Error",
            502 => "Bad Gateway",
            503 => "Service Unavailable",
            504 => "Gateway Timeout",
            _ => "Unknown",
        }
    }
}

/// Case-insensitive HTTP headers map.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HttpHeaders {
    headers: HashMap<String, String>,
    multi_headers: HashMap<String, Vec<String>>,
    raw_entries: Vec<(String, String)>,
}

impl HttpHeaders {
    pub fn new() -> Self {
        Self {
            headers: HashMap::new(),
            multi_headers: HashMap::new(),
            raw_entries: Vec::new(),
        }
    }

    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let k = key.into();
        let k_lower = k.to_ascii_lowercase();
        let val = value.into();
        self.raw_entries
            .retain(|(name, _)| !name.eq_ignore_ascii_case(&k_lower));
        self.raw_entries.push((k, val.clone()));
        self.multi_headers
            .insert(k_lower.clone(), vec![val.clone()]);
        self.headers.insert(k_lower, val);
    }

    pub fn append(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let k = key.into();
        let k_lower = k.to_ascii_lowercase();
        let val = value.into();
        self.headers.insert(k_lower.clone(), val.clone());
        self.multi_headers
            .entry(k_lower)
            .or_default()
            .push(val.clone());
        self.raw_entries.push((k, val));
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.headers
            .get(&key.to_ascii_lowercase())
            .map(|s| s.as_str())
    }

    pub fn get_all(&self, key: &str) -> Vec<&str> {
        self.multi_headers
            .get(&key.to_ascii_lowercase())
            .map(|vec| vec.iter().map(|s| s.as_str()).collect())
            .unwrap_or_default()
    }

    pub fn has(&self, key: &str) -> bool {
        self.headers.contains_key(&key.to_ascii_lowercase())
    }

    pub fn remove(&mut self, key: &str) -> Option<String> {
        let k_lower = key.to_ascii_lowercase();
        self.raw_entries
            .retain(|(name, _)| !name.eq_ignore_ascii_case(&k_lower));
        self.multi_headers.remove(&k_lower);
        self.headers.remove(&k_lower)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &String)> {
        self.raw_entries.iter().map(|(k, v)| (k, v))
    }

    /// Check if headers map is empty.
    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }

    /// Number of distinct header keys.
    pub fn len(&self) -> usize {
        self.headers.len()
    }
}

/// Standard HTTP Content-Encoding types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentEncoding {
    Identity,
    Gzip,
    Deflate,
    Other(String),
}

impl ContentEncoding {
    pub fn as_str(&self) -> &str {
        match self {
            ContentEncoding::Identity => "identity",
            ContentEncoding::Gzip => "gzip",
            ContentEncoding::Deflate => "deflate",
            ContentEncoding::Other(s) => s.as_str(),
        }
    }

    pub fn from_header(val: &str) -> Self {
        let lower = val.to_ascii_lowercase();
        if lower.contains("gzip") {
            ContentEncoding::Gzip
        } else if lower.contains("deflate") {
            ContentEncoding::Deflate
        } else if lower.contains("identity") || lower.trim().is_empty() {
            ContentEncoding::Identity
        } else {
            ContentEncoding::Other(val.trim().to_string())
        }
    }
}

/// Compute standard IEEE 802.3 CRC32 checksum.
pub fn http_crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFF;
    crc = http_crc32_update(crc, data);
    !crc
}

/// Update running CRC32 value with additional data bytes.
pub fn http_crc32_update(mut crc: u32, data: &[u8]) -> u32 {
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if (crc & 1) != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

/// Compress arbitrary byte payload into RFC 1951 Deflate non-compressed blocks (BTYPE 00).
pub fn compress_deflate(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    if data.is_empty() {
        out.push(1); // BFINAL=1, BTYPE=00
        out.extend_from_slice(&[0, 0, 255, 255]);
        return out;
    }
    let total_len = data.len();
    let mut pos = 0;
    while pos < total_len {
        let mut chunk_len = total_len - pos;
        if chunk_len > 32768 {
            chunk_len = 32768;
        }
        let is_final: u8 = if pos + chunk_len >= total_len { 1 } else { 0 };
        out.push(is_final);
        out.push((chunk_len & 0xFF) as u8);
        out.push(((chunk_len >> 8) & 0xFF) as u8);
        let nlen = (65535 - chunk_len) as u16;
        out.push((nlen & 0xFF) as u8);
        out.push(((nlen >> 8) & 0xFF) as u8);
        out.extend_from_slice(&data[pos..pos + chunk_len]);
        pos += chunk_len;
    }
    out
}

/// Decompress an RFC 1951 Deflate byte stream containing uncompressed blocks.
pub fn decompress_deflate(compressed: &[u8]) -> Result<Vec<u8>, String> {
    if compressed.is_empty() {
        return Err("Deflate stream is empty".to_string());
    }
    let mut out = Vec::new();
    let comp_len = compressed.len();
    let mut pos = 0;
    let mut finished = false;
    while pos < comp_len {
        let header = compressed[pos];
        pos += 1;
        let is_final = header & 1;
        let btype = (header >> 1) & 3;
        if btype == 0 {
            if pos + 4 > comp_len {
                return Err("Incomplete uncompressed deflate block header".to_string());
            }
            let len = (compressed[pos] as u16) | ((compressed[pos + 1] as u16) << 8);
            pos += 2;
            let nlen = (compressed[pos] as u16) | ((compressed[pos + 1] as u16) << 8);
            pos += 2;
            if (len ^ nlen) != 0xFFFF {
                return Err("Corrupted uncompressed block length integrity".to_string());
            }
            let block_len = len as usize;
            if pos + block_len > comp_len {
                return Err("Deflate block data truncated".to_string());
            }
            out.extend_from_slice(&compressed[pos..pos + block_len]);
            pos += block_len;
            if is_final == 1 {
                finished = true;
                break;
            }
        } else {
            return Err(format!(
                "Unsupported deflate compression block type: {}",
                btype
            ));
        }
    }
    if !finished {
        return Err("Deflate stream truncated: no final block encountered".to_string());
    }
    Ok(out)
}

/// Compress arbitrary byte payload into RFC 1952 Gzip format.
pub fn compress_gzip(data: &[u8]) -> Vec<u8> {
    // 10-byte Gzip Header (RFC 1952): ID1, ID2, CM, FLG, MTIME (4B), XFL, OS
    let mut out = vec![0x1F, 0x8B, 8, 0, 0, 0, 0, 0, 0, 255];

    // Deflate payload
    let deflated = compress_deflate(data);
    out.extend_from_slice(&deflated);

    // 8-byte Trailer: CRC32 (4 bytes LE) + ISIZE (4 bytes LE)
    let crc = http_crc32(data);
    out.extend_from_slice(&crc.to_le_bytes());

    let isize = (data.len() & 0xFFFF_FFFF) as u32;
    out.extend_from_slice(&isize.to_le_bytes());

    out
}

/// Decompress RFC 1952 Gzip byte payload, validating headers, CRC32 checksum and uncompressed size.
pub fn decompress_gzip(gz: &[u8]) -> Result<Vec<u8>, String> {
    let gz_len = gz.len();
    if gz_len < 18 {
        return Err("Gzip payload too short (minimum 18 bytes required)".to_string());
    }
    if gz[0] != 0x1F || gz[1] != 0x8B || gz[2] != 8 {
        return Err("Invalid Gzip magic numbers or unsupported compression method".to_string());
    }
    let flg = gz[3];
    let mut pos = 10;
    // FEXTRA
    if (flg & 4) != 0 {
        if pos + 2 > gz_len {
            return Err("Incomplete FEXTRA header in gzip".to_string());
        }
        let xlen = (gz[pos] as usize) | ((gz[pos + 1] as usize) << 8);
        pos += 2 + xlen;
    }
    // FNAME
    if (flg & 8) != 0 {
        while pos < gz_len && gz[pos] != 0 {
            pos += 1;
        }
        pos += 1;
    }
    // FCOMMENT
    if (flg & 16) != 0 {
        while pos < gz_len && gz[pos] != 0 {
            pos += 1;
        }
        pos += 1;
    }
    // FHCRC
    if (flg & 2) != 0 {
        pos += 2;
    }
    if pos >= gz_len.saturating_sub(8) {
        return Err("Truncated gzip payload: missing deflate stream and trailer".to_string());
    }
    let payload_end = gz_len - 8;
    let decompressed = decompress_deflate(&gz[pos..payload_end])?;

    let expected_crc = u32::from_le_bytes([
        gz[gz_len - 8],
        gz[gz_len - 7],
        gz[gz_len - 6],
        gz[gz_len - 5],
    ]);
    let actual_crc = http_crc32(&decompressed);
    if expected_crc != actual_crc {
        return Err(format!(
            "Gzip CRC32 checksum mismatch: expected {:#010X}, computed {:#010X}",
            expected_crc, actual_crc
        ));
    }

    let expected_isize = u32::from_le_bytes([
        gz[gz_len - 4],
        gz[gz_len - 3],
        gz[gz_len - 2],
        gz[gz_len - 1],
    ]);
    let actual_isize = (decompressed.len() & 0xFFFF_FFFF) as u32;
    if expected_isize != actual_isize {
        return Err(format!(
            "Gzip ISIZE mismatch: expected {}, got {}",
            expected_isize, actual_isize
        ));
    }

    Ok(decompressed)
}

/// Streaming Gzip encoder that produces RFC 1952 byte stream chunks on the fly.
/// Useful for large response streaming or chunked compression.
#[derive(Debug, Clone)]
pub struct GzipStreamEncoder {
    header_written: bool,
    crc: u32,
    total_uncompressed_len: u64,
    finished: bool,
}

impl Default for GzipStreamEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl GzipStreamEncoder {
    pub fn new() -> Self {
        Self {
            header_written: false,
            crc: 0,
            total_uncompressed_len: 0,
            finished: false,
        }
    }

    /// Feed uncompressed data chunk and retrieve compressed output bytes.
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<u8> {
        if self.finished {
            return Vec::new();
        }
        let mut out = Vec::new();
        if !self.header_written {
            // 10-byte Gzip header: ID1=0x1F, ID2=0x8B, CM=8, FLG=0, MTIME=0, XFL=0, OS=255
            out.extend_from_slice(&[0x1F, 0x8B, 8, 0, 0, 0, 0, 0, 0, 255]);
            self.header_written = true;
        }

        if !chunk.is_empty() {
            // Update CRC32 with polynomial 0xEDB88320
            let running = !self.crc;
            let updated = http_crc32_update(running, chunk);
            self.crc = !updated;
            self.total_uncompressed_len += chunk.len() as u64;

            // Stream chunk as non-final Deflate uncompressed blocks (BFINAL=0, BTYPE=00)
            let mut pos = 0;
            while pos < chunk.len() {
                let mut blk_len = chunk.len() - pos;
                if blk_len > 32768 {
                    blk_len = 32768;
                }
                out.push(0); // BFINAL=0, BTYPE=00
                out.push((blk_len & 0xFF) as u8);
                out.push(((blk_len >> 8) & 0xFF) as u8);
                let nlen = (65535 - blk_len) as u16;
                out.push((nlen & 0xFF) as u8);
                out.push(((nlen >> 8) & 0xFF) as u8);
                out.extend_from_slice(&chunk[pos..pos + blk_len]);
                pos += blk_len;
            }
        }

        out
    }

    /// Finish the stream by writing the final empty deflate block and 8-byte trailer.
    pub fn finish(&mut self) -> Vec<u8> {
        if self.finished {
            return Vec::new();
        }
        let mut out = Vec::new();
        if !self.header_written {
            out.extend_from_slice(&[0x1F, 0x8B, 8, 0, 0, 0, 0, 0, 0, 255]);
            self.header_written = true;
        }

        // Final empty Deflate block: BFINAL=1, BTYPE=00, LEN=0, NLEN=0xFFFF
        out.push(1);
        out.extend_from_slice(&[0, 0, 255, 255]);

        // 8-byte trailer: CRC32 (4 bytes LE) + ISIZE (4 bytes LE)
        out.extend_from_slice(&self.crc.to_le_bytes());
        let isize = (self.total_uncompressed_len & 0xFFFF_FFFF) as u32;
        out.extend_from_slice(&isize.to_le_bytes());

        self.finished = true;
        out
    }

    pub fn is_finished(&self) -> bool {
        self.finished
    }
}

/// Streaming Gzip decoder that accepts chunks of compressed gzip stream
/// and produces decompressed bytes incrementally.
#[derive(Debug, Clone)]
pub struct GzipStreamDecoder {
    buffer: Vec<u8>,
    header_parsed: bool,
    header_offset: usize,
    flg: u8,
    crc: u32,
    total_uncompressed_len: u64,
    finished: bool,
}

impl Default for GzipStreamDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl GzipStreamDecoder {
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            header_parsed: false,
            header_offset: 0,
            flg: 0,
            crc: 0,
            total_uncompressed_len: 0,
            finished: false,
        }
    }

    /// Feed compressed bytes into the decoder and return any newly decompressed data.
    pub fn feed(&mut self, chunk: &[u8]) -> Result<Vec<u8>, String> {
        if self.finished {
            return Ok(Vec::new());
        }
        self.buffer.extend_from_slice(chunk);
        let mut decompressed_out = Vec::new();

        // 1. Try to parse Gzip header if not done yet
        if !self.header_parsed {
            if self.buffer.len() < 10 {
                return Ok(Vec::new()); // Wait for full base header
            }
            if self.buffer[0] != 0x1F || self.buffer[1] != 0x8B || self.buffer[2] != 8 {
                return Err("Invalid Gzip magic numbers or unsupported compression method".to_string());
            }
            self.flg = self.buffer[3];
            let mut pos = 10;

            // FEXTRA
            if (self.flg & 4) != 0 {
                if self.buffer.len() < pos + 2 {
                    return Ok(Vec::new());
                }
                let xlen = (self.buffer[pos] as usize) | ((self.buffer[pos + 1] as usize) << 8);
                if self.buffer.len() < pos + 2 + xlen {
                    return Ok(Vec::new());
                }
                pos += 2 + xlen;
            }

            // FNAME
            if (self.flg & 8) != 0 {
                let mut found = false;
                while pos < self.buffer.len() {
                    if self.buffer[pos] == 0 {
                        pos += 1;
                        found = true;
                        break;
                    }
                    pos += 1;
                }
                if !found {
                    return Ok(Vec::new());
                }
            }

            // FCOMMENT
            if (self.flg & 16) != 0 {
                let mut found = false;
                while pos < self.buffer.len() {
                    if self.buffer[pos] == 0 {
                        pos += 1;
                        found = true;
                        break;
                    }
                    pos += 1;
                }
                if !found {
                    return Ok(Vec::new());
                }
            }

            // FHCRC
            if (self.flg & 2) != 0 {
                if self.buffer.len() < pos + 2 {
                    return Ok(Vec::new());
                }
                pos += 2;
            }

            self.header_offset = pos;
            self.header_parsed = true;
        }

        // 2. Decode deflate blocks incrementally
        let mut cur = self.header_offset;
        while cur < self.buffer.len() {
            let header = self.buffer[cur];
            let is_final = header & 1;
            let btype = (header >> 1) & 3;

            if btype != 0 {
                return Err(format!("Unsupported deflate compression block type: {}", btype));
            }

            if cur + 5 > self.buffer.len() {
                // Not enough bytes to read block header
                break;
            }

            let len = (self.buffer[cur + 1] as u16) | ((self.buffer[cur + 2] as u16) << 8);
            let nlen = (self.buffer[cur + 3] as u16) | ((self.buffer[cur + 4] as u16) << 8);

            if (len ^ nlen) != 0xFFFF {
                return Err("Corrupted uncompressed block length integrity".to_string());
            }

            let block_len = len as usize;
            let block_end = cur + 5 + block_len;

            if block_end > self.buffer.len() {
                // Incomplete block data, wait for next feed
                break;
            }

            if is_final == 1 {
                // Check if the 8-byte trailer is also present in self.buffer
                if block_end + 8 > self.buffer.len() {
                    // Trailer not fully received yet, wait for next feed
                    break;
                }
            }

            let block_data = &self.buffer[cur + 5..block_end];
            // Update CRC
            let running = !self.crc;
            let updated = http_crc32_update(running, block_data);
            self.crc = !updated;
            self.total_uncompressed_len += block_len as u64;

            decompressed_out.extend_from_slice(block_data);
            cur = block_end;

            if is_final == 1 {
                let expected_crc = u32::from_le_bytes([
                    self.buffer[cur],
                    self.buffer[cur + 1],
                    self.buffer[cur + 2],
                    self.buffer[cur + 3],
                ]);
                let expected_isize = u32::from_le_bytes([
                    self.buffer[cur + 4],
                    self.buffer[cur + 5],
                    self.buffer[cur + 6],
                    self.buffer[cur + 7],
                ]);

                if expected_crc != self.crc {
                    return Err(format!(
                        "Gzip CRC32 checksum mismatch: expected {:#010X}, computed {:#010X}",
                        expected_crc, self.crc
                    ));
                }

                let actual_isize = (self.total_uncompressed_len & 0xFFFF_FFFF) as u32;
                if expected_isize != actual_isize {
                    return Err(format!(
                        "Gzip ISIZE mismatch: expected {}, got {}",
                        expected_isize, actual_isize
                    ));
                }

                self.finished = true;
                cur += 8;
                break;
            }
        }

        // Drain consumed bytes from buffer up to cur
        if cur > 0 {
            self.buffer.drain(..cur);
            self.header_offset = 0;
        }

        Ok(decompressed_out)
    }

    pub fn is_finished(&self) -> bool {
        self.finished
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
    pub context: BTreeMap<String, String>,
}

impl HttpRequest {
    pub fn new(method: HttpMethod, path: impl Into<String>) -> Self {
        Self {
            method,
            path: path.into(),
            headers: HttpHeaders::new(),
            body: Vec::new(),
            path_params: BTreeMap::new(),
            context: BTreeMap::new(),
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

    /// Retrieve contextual attribute set by middlewares (e.g. auth_sub, claims, etc.).
    pub fn context(&self, name: &str) -> Option<&str> {
        self.context.get(name).map(|s| s.as_str())
    }

    /// Set a contextual attribute fluently.
    pub fn with_context(mut self, name: impl Into<String>, val: impl Into<String>) -> Self {
        self.context.insert(name.into(), val.into());
        self
    }

    /// Insert or update a contextual attribute.
    pub fn set_context(&mut self, name: impl Into<String>, val: impl Into<String>) {
        self.context.insert(name.into(), val.into());
    }

    /// Returns the raw query string part of the path (after '?'), if any.
    pub fn query_string(&self) -> Option<&str> {
        self.path.split_once('?').map(|(_, q)| q)
    }

    /// Extract query parameter by key from the request path query string.
    pub fn query_param(&self, key: &str) -> Option<String> {
        let qs = self.query_string()?;
        for pair in qs.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                if k == key {
                    return Some(url_decode(v).unwrap_or_else(|_| v.to_string()));
                }
            } else if pair == key {
                return Some(String::new());
            }
        }
        None
    }

    pub fn header(mut self, key: &str, val: &str) -> Self {
        self.headers.set(key, val);
        self
    }

    /// Set HTTP Basic Authentication header (RFC 7617).
    /// Format: `Authorization: Basic <base64(username:password)>`
    pub fn with_basic_auth(mut self, username: &str, password: &str) -> Self {
        self.headers
            .set("Authorization", encode_basic_auth(username, password));
        self
    }

    /// Set HTTP Bearer token Authentication header (RFC 6750).
    /// Format: `Authorization: Bearer <token>`
    pub fn with_bearer_auth(mut self, token: &str) -> Self {
        self.headers
            .set("Authorization", format!("Bearer {}", token.trim()));
        self
    }

    /// Set an API Key header or custom header.
    /// If header_name is None, defaults to "X-API-Key".
    pub fn with_api_key(mut self, key: &str, header_name: Option<&str>) -> Self {
        let name = header_name.unwrap_or("X-API-Key");
        self.headers.set(name, key.trim());
        self
    }

    /// Set an individual Cookie header value (RFC 6265) or append if other cookies already exist.
    pub fn with_cookie(mut self, name: &str, value: &str) -> Self {
        let pair = format!("{}={}", name.trim(), value.trim());
        if let Some(existing) = self.headers.get("Cookie") {
            let combined = format!("{}; {}", existing, pair);
            self.headers.set("Cookie", combined);
        } else {
            self.headers.set("Cookie", pair);
        }
        self
    }

    /// Set Cookie header directly from an RFC 6265 `Cookie` instance.
    pub fn with_cookie_obj(self, cookie: &Cookie) -> Self {
        self.with_cookie(&cookie.name, &cookie.value)
    }

    /// Set Cookie header from an RFC 6265 `CookieJar`.
    pub fn with_cookie_jar(mut self, jar: &CookieJar) -> Self {
        jar.apply_to_request(&mut self);
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

    /// Check whether the client accepts a specific content encoding (e.g. "gzip", "deflate").
    pub fn accepts_encoding(&self, encoding: &str) -> bool {
        if let Some(val) = self.headers.get("accept-encoding") {
            let enc_lower = encoding.to_ascii_lowercase();
            val.to_ascii_lowercase().split(',').any(|part| {
                part.trim().split(';').next().map(|s| s.trim()) == Some(enc_lower.as_str())
            })
        } else {
            false
        }
    }

    /// Retrieve Content-Encoding of the request payload.
    pub fn content_encoding(&self) -> ContentEncoding {
        if let Some(val) = self.headers.get("content-encoding") {
            ContentEncoding::from_header(val)
        } else {
            ContentEncoding::Identity
        }
    }

    /// Compress request body using RFC 1952 Gzip and set Content-Encoding header.
    pub fn gzip(mut self) -> Self {
        self.body = compress_gzip(&self.body);
        self.headers.set("Content-Encoding", "gzip");
        self.headers
            .set("Content-Length", self.body.len().to_string());
        self
    }

    /// Decompress request body based on Content-Encoding header.
    pub fn decompress_body(&self) -> Result<Vec<u8>, String> {
        match self.content_encoding() {
            ContentEncoding::Identity => Ok(self.body.clone()),
            ContentEncoding::Gzip => decompress_gzip(&self.body),
            ContentEncoding::Deflate => decompress_deflate(&self.body),
            ContentEncoding::Other(enc) => {
                Err(format!("Unsupported request Content-Encoding: {}", enc))
            }
        }
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

    /// Create a 301 Moved Permanently redirect response with Location header.
    pub fn moved_permanently(location: &str) -> Self {
        Self::new(HttpStatus::MOVED_PERMANENTLY).header("Location", location)
    }

    /// Create a 302 Found redirect response with Location header.
    pub fn found(location: &str) -> Self {
        Self::new(HttpStatus::FOUND).header("Location", location)
    }

    /// Create a 303 See Other redirect response with Location header.
    pub fn see_other(location: &str) -> Self {
        Self::new(HttpStatus::SEE_OTHER).header("Location", location)
    }

    /// Create a 307 Temporary Redirect response with Location header.
    pub fn temporary_redirect(location: &str) -> Self {
        Self::new(HttpStatus::TEMPORARY_REDIRECT).header("Location", location)
    }

    /// Create a 308 Permanent Redirect response with Location header.
    pub fn permanent_redirect(location: &str) -> Self {
        Self::new(HttpStatus::PERMANENT_REDIRECT).header("Location", location)
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

    pub fn forbidden() -> Self {
        Self::new(HttpStatus::FORBIDDEN)
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

    /// Set Last-Modified header with standard RFC 7231 / RFC 1123 HTTP date.
    pub fn last_modified(mut self, time: SystemTime) -> Self {
        self.headers.set("Last-Modified", format_http_date(time));
        self
    }

    /// Set Cache-Control header directives (e.g. "public, max-age=3600, must-revalidate").
    pub fn cache_control(mut self, directives: &str) -> Self {
        self.headers.set("Cache-Control", directives);
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
        self.headers.append("Set-Cookie", cookie_str);
        self
    }

    /// Add a structured Cookie object as a Set-Cookie header.
    pub fn set_cookie_obj(mut self, cookie: &Cookie) -> Self {
        let cookie_str = cookie.to_set_cookie_header();
        self.headers.append("Set-Cookie", cookie_str);
        self
    }

    /// Extract all Set-Cookie headers as parsed Cookie instances.
    pub fn cookies(&self) -> Vec<Cookie> {
        self.headers
            .get_all("set-cookie")
            .into_iter()
            .filter_map(Cookie::parse_set_cookie)
            .collect()
    }

    /// Check if this response is a redirection status (3xx).
    pub fn is_redirection(&self) -> bool {
        self.status.is_redirection()
    }

    /// Retrieve the target location URL for redirects if present.
    pub fn location(&self) -> Option<&str> {
        self.headers.get("Location")
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

    /// Retrieve Content-Encoding of the response payload.
    pub fn content_encoding(&self) -> ContentEncoding {
        if let Some(val) = self.headers.get("content-encoding") {
            ContentEncoding::from_header(val)
        } else {
            ContentEncoding::Identity
        }
    }

    /// Compress response body using RFC 1952 Gzip and set Content-Encoding header.
    pub fn gzip(mut self) -> Self {
        self.body = compress_gzip(&self.body);
        self.headers.set("Content-Encoding", "gzip");
        self.headers
            .set("Content-Length", self.body.len().to_string());
        self
    }

    /// Compress response body using RFC 1951 Deflate and set Content-Encoding header.
    pub fn deflate(mut self) -> Self {
        self.body = compress_deflate(&self.body);
        self.headers.set("Content-Encoding", "deflate");
        self.headers
            .set("Content-Length", self.body.len().to_string());
        self
    }

    /// Decompress response body according to Content-Encoding header.
    pub fn decompress_body(&self) -> Result<Vec<u8>, String> {
        match self.content_encoding() {
            ContentEncoding::Identity => Ok(self.body.clone()),
            ContentEncoding::Gzip => decompress_gzip(&self.body),
            ContentEncoding::Deflate => decompress_deflate(&self.body),
            ContentEncoding::Other(enc) => {
                Err(format!("Unsupported response Content-Encoding: {}", enc))
            }
        }
    }

    /// Decompress response body and decode as UTF-8 string.
    pub fn body_decompressed_str(&self) -> Result<String, String> {
        let bytes = self.decompress_body()?;
        String::from_utf8(bytes).map_err(|e| format!("UTF-8 decode error: {}", e))
    }

    /// Conditionally compress response using Gzip if client accepts gzip encoding and min_bytes threshold is met.
    pub fn compress_if_accepted(self, req: &HttpRequest, min_bytes: usize) -> Self {
        if req.accepts_encoding("gzip")
            && self.body.len() >= min_bytes
            && !self.headers.has("content-encoding")
        {
            self.gzip()
        } else {
            self
        }
    }

    /// Set a chunked body from a list of data slices and set Transfer-Encoding: chunked.
    pub fn chunked_body(mut self, chunks: &[&[u8]]) -> Self {
        self.headers.set("Transfer-Encoding", "chunked");
        self.headers.remove("Content-Length");
        self.body = encode_chunked(chunks);
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
                headers.append(k.trim(), v.trim());
            }
        }

        let body_start = header_end + 4;

        let is_chunked = headers
            .get("transfer-encoding")
            .map(|te| te.to_ascii_lowercase().contains("chunked"))
            .unwrap_or(false);

        if is_chunked {
            let (body, consumed, trailers) = decode_chunked_stream(&raw[body_start..])?;
            for (k, v) in trailers.iter() {
                headers.append(k, v);
            }
            let total_size = body_start + consumed;
            return Ok((
                Self {
                    status: HttpStatus(code),
                    headers,
                    body,
                },
                total_size,
            ));
        }

        let content_length = headers
            .get("content-length")
            .and_then(|v| v.parse::<usize>().ok());

        let (body, total_size) = match content_length {
            Some(cl) => {
                let total_size = body_start + cl;
                if raw.len() < total_size {
                    return Err("Incomplete HTTP body".to_string());
                }
                (raw[body_start..total_size].to_vec(), total_size)
            }
            None => {
                // Without Content-Length or chunked transfer-encoding, the body spans
                // the remainder of the currently available payload until EOF.
                (raw[body_start..].to_vec(), raw.len())
            }
        };

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
                headers.append(k.trim(), v.trim());
            }
        }

        let body_start = header_end + 4;

        let is_chunked = headers
            .get("transfer-encoding")
            .map(|te| te.to_ascii_lowercase().contains("chunked"))
            .unwrap_or(false);

        if is_chunked {
            let (body, consumed, trailers) = decode_chunked_stream(&raw[body_start..])?;
            for (k, v) in trailers.iter() {
                headers.append(k, v);
            }
            let total_size = body_start + consumed;
            return Ok((
                Self {
                    method,
                    path: path.to_string(),
                    headers,
                    body,
                    path_params: BTreeMap::new(),
                    context: BTreeMap::new(),
                },
                total_size,
            ));
        }

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
                context: BTreeMap::new(),
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

    /// Set a chunked body from a list of data slices and set Transfer-Encoding: chunked.
    pub fn chunked_body(mut self, chunks: &[&[u8]]) -> Self {
        self.headers.set("Transfer-Encoding", "chunked");
        self.headers.remove("Content-Length");
        self.body = encode_chunked(chunks);
        self
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

    /// Extract API Key from request headers (defaults to "X-API-Key" or custom header name).
    pub fn api_key(&self, header_name: Option<&str>) -> Option<&str> {
        let name = header_name.unwrap_or("x-api-key");
        self.headers.get(name)
    }

    /// Verify Bearer token as an HS256 JWT (RFC 7519), returning validated claims.
    pub fn verify_jwt_bearer(
        &self,
        secret: &[u8],
        current_time_secs: u64,
    ) -> Result<JwtClaims, JwtError> {
        let token = self.bearer_token().ok_or(JwtError::InvalidFormat)?;
        Jwt::verify_hs256(secret, &token, current_time_secs, 0)
    }

    /// Extract CSRF token from headers (X-CSRF-Token, X-XSRF-Token) or query parameter (_csrf).
    pub fn csrf_token(&self) -> Option<String> {
        self.headers
            .get("x-csrf-token")
            .or_else(|| self.headers.get("x-xsrf-token"))
            .map(|s| s.to_string())
            .or_else(|| self.query_param("_csrf").map(|s| s.to_string()))
    }

    /// Validate CSRF token against expected session token in constant time.
    pub fn verify_csrf(&self, expected_token: &str) -> bool {
        self.csrf_token()
            .map(|t| constant_time_eq(t.as_bytes(), expected_token.as_bytes()))
            .unwrap_or(false)
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

    /// Evaluate If-Modified-Since header against last modified timestamp (RFC 7232 §3.3).
    /// Returns true if the resource has NOT been modified since the given timestamp
    /// (i.e. client cache is fresh, server should respond 304 Not Modified).
    pub fn if_modified_since(&self, last_modified: SystemTime) -> bool {
        let header_val = match self.headers.get("if-modified-since") {
            Some(v) => v,
            None => return false,
        };
        let client_time = match parse_http_date(header_val) {
            Some(t) => t,
            None => return false,
        };
        // If last_modified <= client_time (accounting for 1-second RFC 7231 resolution),
        // then the resource has not been modified.
        let lm_secs = last_modified
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let ct_secs = client_time
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        lm_secs <= ct_secs
    }

    /// Evaluate If-Unmodified-Since header against last modified timestamp (RFC 7232 §3.4).
    /// Returns true if the resource has NOT been modified (operation is allowed to proceed).
    /// If the resource was modified since the provided date, returns false (412 Precondition Failed).
    pub fn if_unmodified_since(&self, last_modified: SystemTime) -> bool {
        let header_val = match self.headers.get("if-unmodified-since") {
            Some(v) => v,
            None => return true,
        };
        let client_time = match parse_http_date(header_val) {
            Some(t) => t,
            None => return true, // If date is malformed, ignore precondition per RFC
        };
        let lm_secs = last_modified
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let ct_secs = client_time
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        lm_secs <= ct_secs
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

/// HTTP Middleware function that intercepts a request before handler execution.
/// Returning `Some(HttpResponse)` short-circuits the request pipeline immediately (e.g. 401 Unauthorized or 403 Forbidden).
/// Returning `None` allows execution to proceed to the next middleware or route handler.
pub type HttpMiddleware = Arc<dyn Fn(&mut HttpRequest) -> Option<HttpResponse> + Send + Sync>;

/// Registered route with HTTP method, URI pattern, parsed segments, route-specific middlewares, and execution handler.
#[derive(Clone)]
pub struct HttpRoute {
    pub method: HttpMethod,
    pub pattern: String,
    pub segments: Vec<RouteSegment>,
    pub middlewares: Vec<HttpMiddleware>,
    pub handler: HttpHandler,
}

/// High-performance URI router supporting dynamic path parameters (:param) and wildcards (*wildcard),
/// along with global and per-route middleware pipelines.
#[derive(Clone, Default)]
pub struct HttpRouter {
    pub routes: Vec<HttpRoute>,
    pub global_middlewares: Vec<HttpMiddleware>,
}

impl HttpRouter {
    pub fn new() -> Self {
        Self {
            routes: Vec::new(),
            global_middlewares: Vec::new(),
        }
    }

    /// Register a global middleware executed before every route handler.
    pub fn use_middleware(&mut self, middleware: HttpMiddleware) -> &mut Self {
        self.global_middlewares.push(middleware);
        self
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
        self.add_with_middlewares(method, pattern, Vec::new(), handler)
    }

    /// Register a route handler with an HTTP method, URI pattern, and specific middlewares.
    pub fn add_with_middlewares(
        &mut self,
        method: HttpMethod,
        pattern: impl Into<String>,
        middlewares: Vec<HttpMiddleware>,
        handler: impl Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static,
    ) -> &mut Self {
        let pat_str = pattern.into();
        let segments = Self::parse_pattern(&pat_str);
        self.routes.push(HttpRoute {
            method,
            pattern: pat_str,
            segments,
            middlewares,
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

    /// Register a GET route handler with specific middlewares.
    pub fn get_with_middlewares(
        &mut self,
        pattern: impl Into<String>,
        middlewares: Vec<HttpMiddleware>,
        handler: impl Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static,
    ) -> &mut Self {
        self.add_with_middlewares(HttpMethod::Get, pattern, middlewares, handler)
    }

    /// Register a POST route handler.
    pub fn post(
        &mut self,
        pattern: impl Into<String>,
        handler: impl Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static,
    ) -> &mut Self {
        self.add(HttpMethod::Post, pattern, handler)
    }

    /// Register a POST route handler with specific middlewares.
    pub fn post_with_middlewares(
        &mut self,
        pattern: impl Into<String>,
        middlewares: Vec<HttpMiddleware>,
        handler: impl Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static,
    ) -> &mut Self {
        self.add_with_middlewares(HttpMethod::Post, pattern, middlewares, handler)
    }

    /// Register a PUT route handler.
    pub fn put(
        &mut self,
        pattern: impl Into<String>,
        handler: impl Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static,
    ) -> &mut Self {
        self.add(HttpMethod::Put, pattern, handler)
    }

    /// Register a PUT route handler with specific middlewares.
    pub fn put_with_middlewares(
        &mut self,
        pattern: impl Into<String>,
        middlewares: Vec<HttpMiddleware>,
        handler: impl Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static,
    ) -> &mut Self {
        self.add_with_middlewares(HttpMethod::Put, pattern, middlewares, handler)
    }

    /// Register a DELETE route handler.
    pub fn delete(
        &mut self,
        pattern: impl Into<String>,
        handler: impl Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static,
    ) -> &mut Self {
        self.add(HttpMethod::Delete, pattern, handler)
    }

    /// Register a DELETE route handler with specific middlewares.
    pub fn delete_with_middlewares(
        &mut self,
        pattern: impl Into<String>,
        middlewares: Vec<HttpMiddleware>,
        handler: impl Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static,
    ) -> &mut Self {
        self.add_with_middlewares(HttpMethod::Delete, pattern, middlewares, handler)
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

    /// Dispatch an incoming HTTP request through global middlewares, match route,
    /// execute route-specific middlewares, and invoke the matched handler.
    pub fn dispatch(&self, req: &mut HttpRequest) -> HttpResponse {
        for mw in &self.global_middlewares {
            if let Some(resp) = mw(req) {
                return resp;
            }
        }

        if let Some((route, params)) = self.match_route(&req.method, &req.path) {
            req.path_params = params;
            for mw in &route.middlewares {
                if let Some(resp) = mw(req) {
                    return resp;
                }
            }
            (route.handler)(req)
        } else {
            HttpResponse::not_found().text("Route not found")
        }
    }
}

/// Create an authentication middleware validating RFC 7519 JWT Bearer tokens with HMAC-SHA256.
/// On success, populates `auth_sub` and `auth_claims` in `req.context`.
/// On failure or missing token, returns 401 Unauthorized JSON error response.
pub fn jwt_auth_middleware(secret: impl Into<Vec<u8>>) -> HttpMiddleware {
    let secret = secret.into();
    Arc::new(move |req: &mut HttpRequest| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        match req.verify_jwt_bearer(&secret, now) {
            Ok(claims) => {
                if let Some(sub) = &claims.sub {
                    req.context.insert("auth_sub".to_string(), sub.clone());
                }
                if let Ok(claims_json) = serde_json::to_string(&claims) {
                    req.context.insert("auth_claims".to_string(), claims_json);
                }
                None
            }
            Err(err) => {
                let body = format!(r#"{{"error":"unauthorized","reason":"{}"}}"#, err);
                Some(
                    HttpResponse::new(HttpStatus::UNAUTHORIZED)
                        .header("WWW-Authenticate", "Bearer")
                        .header("Content-Type", "application/json")
                        .text(body),
                )
            }
        }
    })
}

/// Create a CSRF protection middleware requiring a valid CSRF token on mutating requests (POST, PUT, DELETE, PATCH).
/// Verifies that the header token matches the session/cookie token in constant time.
/// On mismatch or missing token, returns 403 Forbidden JSON error response.
pub fn csrf_protection_middleware(
    cookie_name: impl Into<String>,
    _header_name: impl Into<String>,
) -> HttpMiddleware {
    let cookie_name = cookie_name.into();
    Arc::new(move |req: &mut HttpRequest| match req.method {
        HttpMethod::Get | HttpMethod::Head | HttpMethod::Options => None,
        _ => {
            let cookies = req.cookies();
            let expected = cookies.get(&cookie_name);
            if let Some(expected_val) = expected {
                if req.verify_csrf(expected_val) {
                    return None;
                }
            }
            let body = r#"{"error":"forbidden","reason":"invalid_or_missing_csrf_token"}"#;
            Some(
                HttpResponse::forbidden()
                    .header("Content-Type", "application/json")
                    .text(body),
            )
        }
    })
}

/// Create a CORS middleware responding to preflight OPTIONS requests with CORS headers.
pub fn cors_middleware(
    allowed_origin: impl Into<String>,
    allowed_methods: impl Into<String>,
    allowed_headers: impl Into<String>,
) -> HttpMiddleware {
    let origin = allowed_origin.into();
    let methods = allowed_methods.into();
    let headers = allowed_headers.into();
    Arc::new(move |req: &mut HttpRequest| {
        if req.method == HttpMethod::Options {
            let mut resp = HttpResponse::ok();
            resp.headers.set("Access-Control-Allow-Origin", &origin);
            resp.headers.set("Access-Control-Allow-Methods", &methods);
            resp.headers.set("Access-Control-Allow-Headers", &headers);
            resp.headers.set("Access-Control-Max-Age", "86400");
            Some(resp)
        } else {
            None
        }
    })
}

/// High-performance, non-blocking HTTP server driven by IFA colorless fibers.
pub struct HttpServer {
    port: u16,
    router: Arc<HttpRouter>,
    is_running: Arc<AtomicBool>,
    auto_compress_threshold: Option<usize>,
}

impl HttpServer {
    /// Create a new HTTP Server on the specified port.
    pub fn new(port: u16) -> Self {
        Self {
            port,
            router: Arc::new(HttpRouter::new()),
            is_running: Arc::new(AtomicBool::new(false)),
            auto_compress_threshold: None,
        }
    }

    /// Enable automatic Gzip compression on responses if client accepts gzip and body >= min_bytes.
    pub fn with_auto_compression(&mut self, min_bytes: usize) -> &mut Self {
        self.auto_compress_threshold = Some(min_bytes);
        self
    }

    /// Register a global middleware that executes before every route handler.
    pub fn use_middleware(&mut self, middleware: HttpMiddleware) -> &mut Self {
        let router =
            Arc::get_mut(&mut self.router).expect("Cannot register middleware while listening");
        router.use_middleware(middleware);
        self
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

    /// Register a route handler with specific middlewares.
    pub fn route_with_middlewares(
        &mut self,
        method: HttpMethod,
        path: impl Into<String>,
        middlewares: Vec<HttpMiddleware>,
        handler: impl Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static,
    ) -> &mut Self {
        let router = Arc::get_mut(&mut self.router).expect("Cannot register route while listening");
        router.add_with_middlewares(method, path, middlewares, handler);
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

    /// Register a GET route handler with specific middlewares.
    pub fn get_with_middlewares(
        &mut self,
        path: impl Into<String>,
        middlewares: Vec<HttpMiddleware>,
        handler: impl Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static,
    ) -> &mut Self {
        self.route_with_middlewares(HttpMethod::Get, path, middlewares, handler)
    }

    /// Register a POST route handler.
    pub fn post(
        &mut self,
        path: impl Into<String>,
        handler: impl Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static,
    ) -> &mut Self {
        self.route(HttpMethod::Post, path, handler)
    }

    /// Register a POST route handler with specific middlewares.
    pub fn post_with_middlewares(
        &mut self,
        path: impl Into<String>,
        middlewares: Vec<HttpMiddleware>,
        handler: impl Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static,
    ) -> &mut Self {
        self.route_with_middlewares(HttpMethod::Post, path, middlewares, handler)
    }

    /// Register a PUT route handler.
    pub fn put(
        &mut self,
        path: impl Into<String>,
        handler: impl Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static,
    ) -> &mut Self {
        self.route(HttpMethod::Put, path, handler)
    }

    /// Register a PUT route handler with specific middlewares.
    pub fn put_with_middlewares(
        &mut self,
        path: impl Into<String>,
        middlewares: Vec<HttpMiddleware>,
        handler: impl Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static,
    ) -> &mut Self {
        self.route_with_middlewares(HttpMethod::Put, path, middlewares, handler)
    }

    /// Register a DELETE route handler.
    pub fn delete(
        &mut self,
        path: impl Into<String>,
        handler: impl Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static,
    ) -> &mut Self {
        self.route(HttpMethod::Delete, path, handler)
    }

    /// Register a DELETE route handler with specific middlewares.
    pub fn delete_with_middlewares(
        &mut self,
        path: impl Into<String>,
        middlewares: Vec<HttpMiddleware>,
        handler: impl Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static,
    ) -> &mut Self {
        self.route_with_middlewares(HttpMethod::Delete, path, middlewares, handler)
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
        let auto_compress = self.auto_compress_threshold;

        let _ = std::thread::Builder::new()
            .name("ifa-http-listener".to_string())
            .spawn(move || {
                while running.load(Ordering::Relaxed) {
                    if let Ok(Some((mut stream, _))) = listener.try_accept() {
                        let router_worker = Arc::clone(&router);
                        let _ = std::thread::Builder::new()
                            .name("ifa-http-worker".to_string())
                            .spawn(move || {
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
                                                match HttpRequest::parse_from_wire(
                                                    &buf[..total_read],
                                                ) {
                                                    Ok((mut req, consumed)) => {
                                                        let keep_alive = http_should_keep_alive(
                                                            200,
                                                            &req.headers,
                                                        );
                                                        let mut res =
                                                            router_worker.dispatch(&mut req);

                                                        if let Some(threshold) = auto_compress {
                                                            res = res.compress_if_accepted(
                                                                &req, threshold,
                                                            );
                                                        }

                                                        if keep_alive {
                                                            res.headers
                                                                .set("Connection", "keep-alive");
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
                                                if last_activity.elapsed() > Duration::from_secs(30)
                                                {
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

/// Read an HTTP response from an async TCP stream over colorless fibers with configurable timeout.
pub fn read_http_response_with_timeout(
    stream: &mut AsyncTcpStream,
    timeout: Duration,
) -> io::Result<HttpResponse> {
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
                    if start.elapsed() > timeout {
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

/// Read an HTTP response from an async TCP stream over colorless fibers (default 15s timeout).
pub fn read_http_response(stream: &mut AsyncTcpStream) -> io::Result<HttpResponse> {
    read_http_response_with_timeout(stream, Duration::from_secs(15))
}

/// Read multiple sequential HTTP responses from an async TCP stream (e.g. for HTTP/1.1 pipelining).
/// Continues reading until `expected_count` responses are parsed or until timeout occurs.
pub fn read_http_responses_pipelined(
    stream: &mut AsyncTcpStream,
    expected_count: usize,
    timeout: Duration,
) -> io::Result<Vec<HttpResponse>> {
    let mut responses = Vec::with_capacity(expected_count);
    let mut buf = vec![0u8; 16384];
    let mut total_read = 0;
    let mut spins = 0;
    let start = Instant::now();

    while responses.len() < expected_count {
        // Try parsing existing buffered data before reading more
        let mut consumed_any = false;
        while total_read > 0 {
            match HttpResponse::parse_from_wire(&buf[..total_read]) {
                Ok((resp, consumed)) => {
                    responses.push(resp);
                    buf.copy_within(consumed..total_read, 0);
                    total_read -= consumed;
                    consumed_any = true;
                    if responses.len() == expected_count {
                        return Ok(responses);
                    }
                }
                Err(_) => {
                    // Need more bytes to complete next response
                    break;
                }
            }
        }

        if responses.len() == expected_count {
            return Ok(responses);
        }

        if total_read == buf.len() {
            buf.resize(buf.len() * 2, 0);
        }

        match stream.try_read(&mut buf[total_read..]) {
            Ok(Some(0)) => {
                // Connection closed by peer
                if responses.len() == expected_count {
                    return Ok(responses);
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!(
                        "Connection closed by server before receiving all pipelined responses (got {} of {})",
                        responses.len(),
                        expected_count
                    ),
                ));
            }
            Ok(Some(n)) => {
                total_read += n;
                spins = 0;
            }
            Ok(None) | Err(_) => {
                spins += 1;
                if spins < 32 && !consumed_any {
                    std::hint::spin_loop();
                } else {
                    if start.elapsed() > timeout {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!(
                                "HTTP pipelined response timed out (got {} of {})",
                                responses.len(),
                                expected_count
                            ),
                        ));
                    }
                    GLOBAL_SCHEDULER.yield_now();
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        }
    }

    Ok(responses)
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

/// Latency and timing metrics collected during an HTTP request-response cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpMetrics {
    /// Latency elapsed during TCP handshake / connection establishment.
    pub connect_duration: Duration,
    /// Latency elapsed sending request wire bytes and awaiting the full response.
    pub request_duration: Duration,
    /// Total end-to-end latency.
    pub total_duration: Duration,
    /// Number of bytes transmitted in the request frame.
    pub bytes_sent: usize,
    /// Number of bytes received in the response body.
    pub bytes_received: usize,
}

impl Default for HttpMetrics {
    fn default() -> Self {
        Self {
            connect_duration: Duration::ZERO,
            request_duration: Duration::ZERO,
            total_duration: Duration::ZERO,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }
}

/// Asynchronous non-blocking HTTP client running over colorless fibers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpClient {
    /// Optional application read/response timeout.
    pub timeout: Option<Duration>,
    /// Last recorded request-response latency and transfer metrics.
    pub metrics: Option<HttpMetrics>,
}

impl HttpClient {
    pub fn new() -> Self {
        Self {
            timeout: None,
            metrics: None,
        }
    }

    /// Set an application timeout for network operations.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Retrieve the most recently recorded execution metrics.
    pub fn last_metrics(&self) -> Option<&HttpMetrics> {
        self.metrics.as_ref()
    }

    /// Send an HTTP request to host and port over an async TCP stream.
    pub fn send(&self, req: &HttpRequest, host: &str, port: u16) -> io::Result<HttpResponse> {
        let (resp, _) = self.send_with_metrics(req, host, port)?;
        Ok(resp)
    }

    /// Send an HTTP request to host and port over an async TCP stream, recording execution metrics.
    pub fn send_with_metrics(
        &self,
        req: &HttpRequest,
        host: &str,
        port: u16,
    ) -> io::Result<(HttpResponse, HttpMetrics)> {
        let t0 = Instant::now();
        let mut stream = AsyncTcpStream::connect(format!("{}:{}", host, port))?;
        let connect_duration = t0.elapsed();

        let t_req = Instant::now();
        let wire = req.to_wire_bytes();
        let bytes_sent = wire.len();
        stream.write_all(&wire)?;

        let timeout = self.timeout.unwrap_or(Duration::from_secs(15));
        let resp = read_http_response_with_timeout(&mut stream, timeout)?;
        let request_duration = t_req.elapsed();
        let total_duration = t0.elapsed();

        let metrics = HttpMetrics {
            connect_duration,
            request_duration,
            total_duration,
            bytes_sent,
            bytes_received: resp.body.len(),
        };

        Ok((resp, metrics))
    }

    /// Send multiple HTTP requests sequentially over a single TCP connection using HTTP/1.1 pipelining (RFC 7230).
    /// All requests are written to the wire consecutively before reading responses back in the exact same order.
    pub fn send_pipelined(
        &self,
        requests: &[HttpRequest],
        host: &str,
        port: u16,
    ) -> io::Result<Vec<HttpResponse>> {
        if requests.is_empty() {
            return Ok(Vec::new());
        }

        let mut stream = AsyncTcpStream::connect(format!("{}:{}", host, port))?;

        // Concatenate all wire requests into a single buffer
        let mut wire_batch = Vec::new();
        for (idx, req) in requests.iter().enumerate() {
            let mut req_wire = req.clone();
            // Automatically ensure Connection header conforms to keep-alive except possibly the last one
            if req_wire.headers.get("Connection").is_none() {
                if idx + 1 < requests.len() {
                    req_wire.headers.set("Connection", "keep-alive");
                } else {
                    req_wire.headers.set("Connection", "close");
                }
            }
            wire_batch.extend_from_slice(&req_wire.to_wire_bytes());
        }

        stream.write_all(&wire_batch)?;

        let timeout = self.timeout.unwrap_or(Duration::from_secs(15));
        read_http_responses_pipelined(&mut stream, requests.len(), timeout)
    }

    /// Send an HTTP request targeted at a structured `Url`.
    pub fn send_url(&self, req: &mut HttpRequest, url: &Url) -> io::Result<HttpResponse> {
        let (resp, _) = self.send_url_with_metrics(req, url)?;
        Ok(resp)
    }

    /// Send an HTTP request targeted at a structured `Url`, recording execution metrics.
    pub fn send_url_with_metrics(
        &self,
        req: &mut HttpRequest,
        url: &Url,
    ) -> io::Result<(HttpResponse, HttpMetrics)> {
        if url.host.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Url has no host defined",
            ));
        }
        let port = url.port.unwrap_or(match url.scheme.as_str() {
            "https" | "wss" => 443,
            _ => 80,
        });

        // Set Host header if not already explicitly set
        if req.headers.get("Host").is_none() {
            req.headers.set("Host", url.host.as_str());
        }
        // Align request target with URL's path and query
        req.path = url.request_target();

        self.send_with_metrics(req, &url.host, port)
    }

    /// Execute a non-blocking GET request targeting a structured `Url`.
    pub fn get_url(&self, url: &Url) -> io::Result<HttpResponse> {
        let req = HttpRequest::new(HttpMethod::Get, url.request_target())
            .header("Host", url.host.as_str())
            .header("User-Agent", "IFA-HttpClient/0.1.0")
            .header("Connection", "close");
        let port = url.port.unwrap_or(match url.scheme.as_str() {
            "https" | "wss" => 443,
            _ => 80,
        });
        self.send(&req, &url.host, port)
    }

    /// Execute a non-blocking POST request with JSON payload targeting a structured `Url`.
    pub fn post_url_json(&self, url: &Url, payload: &JsonValue) -> io::Result<HttpResponse> {
        let req = HttpRequest::new(HttpMethod::Post, url.request_target())
            .header("Host", url.host.as_str())
            .header("User-Agent", "IFA-HttpClient/0.1.0")
            .header("Connection", "close")
            .json(payload);
        let port = url.port.unwrap_or(match url.scheme.as_str() {
            "https" | "wss" => 443,
            _ => 80,
        });
        self.send(&req, &url.host, port)
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

    /// Send an HTTP request managing cookies through the provided CookieJar.
    pub fn send_with_cookie_jar(
        &self,
        req: &mut HttpRequest,
        host: &str,
        port: u16,
        cookie_jar: &mut CookieJar,
    ) -> io::Result<HttpResponse> {
        cookie_jar.apply_to_request(req);
        let resp = self.send(req, host, port)?;
        cookie_jar.store_from_response(&resp);
        Ok(resp)
    }

    /// Send an HTTP request targeted at a structured `Url`, automatically following redirects up to `max_redirects`.
    /// When following redirects:
    /// - 301, 302: rewrites method to GET and clears body if original method was POST (RFC 7231 / browser convention)
    /// - 303 (See Other): always rewrites method to GET and clears body
    /// - 307, 308: preserves method and body
    /// - Cross-origin redirects strip sensitive Authorization headers to prevent token leakage.
    pub fn send_url_following_redirects(
        &self,
        req: &HttpRequest,
        url: &Url,
        max_redirects: usize,
    ) -> io::Result<HttpResponse> {
        let mut current_url = url.clone();
        let mut current_req = req.clone();
        let mut redirects_followed = 0;

        loop {
            let resp = self.send_url(&mut current_req, &current_url)?;

            if resp.is_redirection() {
                if let Some(loc_header) = resp.location() {
                    if redirects_followed >= max_redirects {
                        return Err(io::Error::other(format!(
                            "Too many redirects (max: {})",
                            max_redirects
                        )));
                    }

                    let next_url = current_url.join(loc_header).map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("Invalid redirect Location URL: {}", e),
                        )
                    })?;

                    // Check for cross-origin redirect
                    let is_cross_origin = !current_url.host.eq_ignore_ascii_case(&next_url.host)
                        || current_url.port != next_url.port
                        || !current_url.scheme.eq_ignore_ascii_case(&next_url.scheme);

                    if is_cross_origin {
                        current_req.headers.remove("authorization");
                        current_req.headers.remove("cookie");
                    }

                    // Adjust method and body according to RFC specs
                    match resp.status {
                        HttpStatus::SEE_OTHER => {
                            current_req.method = HttpMethod::Get;
                            current_req.body.clear();
                            current_req.headers.remove("content-length");
                            current_req.headers.remove("content-type");
                        }
                        HttpStatus::MOVED_PERMANENTLY | HttpStatus::FOUND => {
                            if current_req.method == HttpMethod::Post {
                                current_req.method = HttpMethod::Get;
                                current_req.body.clear();
                                current_req.headers.remove("content-length");
                                current_req.headers.remove("content-type");
                            }
                        }
                        HttpStatus::TEMPORARY_REDIRECT | HttpStatus::PERMANENT_REDIRECT => {
                            // Retain method and body unchanged
                        }
                        _ => {}
                    }

                    // Reset Host header to match next URL's host
                    current_req.headers.set("Host", next_url.host.as_str());
                    current_url = next_url;
                    redirects_followed += 1;
                    continue;
                }
            }

            return Ok(resp);
        }
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

/// Parse a query string or form into an ordered list of key-value pairs (preserving duplicates and order).
pub fn parse_query_pairs(query: &str) -> Vec<(String, String)> {
    let clean_query = query.strip_prefix('?').unwrap_or(query);
    if clean_query.is_empty() {
        return Vec::new();
    }
    let mut pairs = Vec::new();
    for part in clean_query.split('&') {
        if part.is_empty() {
            continue;
        }
        if let Some((k, v)) = part.split_once('=') {
            let key = url_decode(k).unwrap_or_else(|_| k.to_string());
            let val = url_decode(v).unwrap_or_else(|_| v.to_string());
            pairs.push((key, val));
        } else {
            let key = url_decode(part).unwrap_or_else(|_| part.to_string());
            pairs.push((key, String::new()));
        }
    }
    pairs
}

/// Structured RFC 3986 URI/URL representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    pub scheme: String,
    pub host: String,
    pub port: Option<u16>,
    pub path: String,
    pub query: Option<String>,
    pub fragment: Option<String>,
    pub userinfo: Option<String>,
}

impl Url {
    /// Parse an absolute or origin-relative URL/URI string according to RFC 3986.
    pub fn parse(s: &str) -> Result<Self, String> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err("URL string is empty".to_string());
        }

        let mut work = trimmed;

        // 1. Extract fragment if present (#...)
        let fragment = if let Some((before_frag, frag)) = work.split_once('#') {
            work = before_frag;
            Some(frag.to_string())
        } else {
            None
        };

        // 2. Extract query if present (?...)
        let query = if let Some((before_q, q)) = work.split_once('?') {
            work = before_q;
            Some(q.to_string())
        } else {
            None
        };

        // 3. Scheme and Authority vs relative path
        let (scheme, authority, path) = if let Some((sch, rest)) = work.split_once("://") {
            if sch.is_empty() {
                return Err("Missing scheme before '://'".to_string());
            }
            let (auth, p) = match rest.find('/') {
                Some(idx) => (&rest[..idx], &rest[idx..]),
                None => (rest, "/"),
            };
            (sch.to_ascii_lowercase(), Some(auth), p.to_string())
        } else {
            // Origin-relative or path-only
            ("".to_string(), None, work.to_string())
        };

        // 4. Parse authority: [userinfo@]host[:port]
        let mut host = String::new();
        let mut port = None;
        let mut userinfo = None;

        if let Some(auth) = authority {
            let mut auth_work = auth;
            if let Some((uinfo, rest)) = auth_work.split_once('@') {
                userinfo = Some(uinfo.to_string());
                auth_work = rest;
            }

            // Handle IPv6 bracketed address: [::1]:8080 or [::1]
            if auth_work.starts_with('[') {
                if let Some(bracket_end) = auth_work.find(']') {
                    host = auth_work[1..bracket_end].to_string();
                    let remainder = &auth_work[bracket_end + 1..];
                    if let Some(port_str) = remainder.strip_prefix(':') {
                        port =
                            Some(port_str.parse::<u16>().map_err(|_| {
                                format!("Invalid port '{}' in authority", port_str)
                            })?);
                    }
                } else {
                    return Err("Unclosed IPv6 bracket in authority".to_string());
                }
            } else if let Some((h, p_str)) = auth_work.split_once(':') {
                host = h.to_ascii_lowercase();
                port = Some(
                    p_str
                        .parse::<u16>()
                        .map_err(|_| format!("Invalid port '{}' in authority", p_str))?,
                );
            } else {
                host = auth_work.to_ascii_lowercase();
            }
        }

        // Canonical default port resolution if scheme known
        let effective_port = match (port, scheme.as_str()) {
            (Some(p), _) => Some(p),
            (None, "http") => Some(80),
            (None, "https") => Some(443),
            (None, "ws") => Some(80),
            (None, "wss") => Some(443),
            _ => None,
        };

        let normalized_path = if path.is_empty() {
            "/".to_string()
        } else {
            path
        };

        Ok(Url {
            scheme,
            host,
            port: effective_port,
            path: normalized_path,
            query,
            fragment,
            userinfo,
        })
    }

    /// Return parsed query parameters as an ordered list of (key, value) pairs.
    pub fn query_pairs(&self) -> Vec<(String, String)> {
        match &self.query {
            Some(q) => parse_query_pairs(q),
            None => Vec::new(),
        }
    }

    /// Return query parameters converted to a HashMap.
    pub fn query_map(&self) -> HashMap<String, String> {
        match &self.query {
            Some(q) => parse_form_urlencoded(q),
            None => HashMap::new(),
        }
    }

    /// Retrieve the relative path and query string suitable for HTTP request lines (e.g., `/path?query`).
    pub fn request_target(&self) -> String {
        let p = if self.path.is_empty() {
            "/"
        } else {
            &self.path
        };
        if let Some(ref q) = self.query {
            format!("{}?{}", p, q)
        } else {
            p.to_string()
        }
    }

    /// Fluently append or update a query parameter key-value pair.
    pub fn with_query_param(mut self, key: &str, value: &str) -> Self {
        self.set_query_param(key, value);
        self
    }

    /// Set or update a query parameter key-value pair.
    pub fn set_query_param(&mut self, key: &str, value: &str) {
        let mut pairs = self.query_pairs();
        let mut found = false;
        for (k, v) in pairs.iter_mut() {
            if k == key {
                *v = value.to_string();
                found = true;
                break;
            }
        }
        if !found {
            pairs.push((key.to_string(), value.to_string()));
        }
        let ref_pairs: Vec<(&str, &str)> = pairs
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        self.query = Some(format_form_urlencoded(&ref_pairs));
    }

    /// Reconstruct standard RFC 3986 URI string representation.
    pub fn to_uri_string(&self) -> String {
        let mut out = String::new();
        if !self.scheme.is_empty() {
            out.push_str(&self.scheme);
            out.push_str("://");
            if let Some(ref u) = self.userinfo {
                out.push_str(u);
                out.push('@');
            }
            if self.host.contains(':') && !self.host.starts_with('[') {
                out.push('[');
                out.push_str(&self.host);
                out.push(']');
            } else {
                out.push_str(&self.host);
            }
            if let Some(p) = self.port {
                let default_port = match self.scheme.as_str() {
                    "http" | "ws" => 80,
                    "https" | "wss" => 443,
                    _ => 0,
                };
                if p != default_port {
                    out.push(':');
                    out.push_str(&p.to_string());
                }
            }
        }
        out.push_str(&self.path);
        if let Some(ref q) = self.query {
            out.push('?');
            out.push_str(q);
        }
        if let Some(ref f) = self.fragment {
            out.push('#');
            out.push_str(f);
        }
        out
    }

    /// Resolve a relative or absolute URL reference against this base URL (RFC 3986 Section 5).
    pub fn join(&self, reference: &str) -> Result<Self, String> {
        let ref_trimmed = reference.trim();
        if ref_trimmed.is_empty() {
            return Ok(self.clone());
        }

        // 1. If reference contains scheme, parse directly as absolute URL
        if ref_trimmed.contains("://") {
            return Self::parse(ref_trimmed);
        }

        // 2. Protocol-relative URL ("//other-host/path")
        if let Some(rest) = ref_trimmed.strip_prefix("//") {
            let full = format!("{}:{}", self.scheme, rest);
            return Self::parse(&full);
        }

        let mut target = self.clone();

        // 3. Extract fragment if present (#...)
        let (without_frag, frag) = if let Some((before_f, f)) = ref_trimmed.split_once('#') {
            (before_f, Some(f.to_string()))
        } else {
            (ref_trimmed, None)
        };
        target.fragment = frag;

        // 4. Extract query if present (?...)
        let (path_part, query) = if let Some((before_q, q)) = without_frag.split_once('?') {
            (before_q, Some(q.to_string()))
        } else {
            (without_frag, None)
        };
        target.query = query;

        // 5. Resolve path
        if path_part.is_empty() {
            // Keep base path
            return Ok(target);
        }

        if path_part.starts_with('/') {
            // Absolute path against host
            target.path = path_part.to_string();
        } else {
            // Relative path: resolve against base directory
            let base_dir = match self.path.rfind('/') {
                Some(idx) => &self.path[..=idx],
                None => "/",
            };
            let mut segments: Vec<&str> = base_dir.split('/').filter(|s| !s.is_empty()).collect();
            for seg in path_part.split('/') {
                match seg {
                    "" | "." => {}
                    ".." => {
                        segments.pop();
                    }
                    other => {
                        segments.push(other);
                    }
                }
            }
            let mut resolved_path = String::from("/");
            resolved_path.push_str(&segments.join("/"));
            if path_part.ends_with('/') && !resolved_path.ends_with('/') {
                resolved_path.push('/');
            }
            target.path = resolved_path;
        }

        Ok(target)
    }
}

impl std::fmt::Display for Url {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_uri_string())
    }
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

/// RFC 6265bis SameSite attribute policy for HTTP cookies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameSite {
    Strict,
    Lax,
    None,
}

impl SameSite {
    pub fn as_str(&self) -> &'static str {
        match self {
            SameSite::Strict => "Strict",
            SameSite::Lax => "Lax",
            SameSite::None => "None",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        if s.eq_ignore_ascii_case("strict") {
            Some(SameSite::Strict)
        } else if s.eq_ignore_ascii_case("lax") {
            Some(SameSite::Lax)
        } else if s.eq_ignore_ascii_case("none") {
            Some(SameSite::None)
        } else {
            None
        }
    }
}

/// Structured HTTP Cookie complying with RFC 6265 and RFC 6265bis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub path: Option<String>,
    pub domain: Option<String>,
    pub max_age_secs: Option<u64>,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: Option<SameSite>,
    pub created_at: Instant,
}

impl Cookie {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            path: None,
            domain: None,
            max_age_secs: None,
            secure: false,
            http_only: false,
            same_site: None,
            created_at: Instant::now(),
        }
    }

    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    pub fn domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self
    }

    pub fn max_age(mut self, secs: u64) -> Self {
        self.max_age_secs = Some(secs);
        self
    }

    pub fn secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }

    pub fn http_only(mut self, http_only: bool) -> Self {
        self.http_only = http_only;
        self
    }

    pub fn same_site(mut self, same_site: SameSite) -> Self {
        self.same_site = Some(same_site);
        self
    }

    /// Check if this cookie is expired relative to a reference instant.
    pub fn is_expired_at(&self, now: Instant) -> bool {
        if let Some(max_age) = self.max_age_secs {
            if max_age == 0 {
                return true;
            }
            let elapsed = now.saturating_duration_since(self.created_at);
            elapsed >= Duration::from_secs(max_age)
        } else {
            false
        }
    }

    /// Check if this cookie has expired as of right now.
    pub fn is_expired(&self) -> bool {
        self.is_expired_at(Instant::now())
    }

    /// Format as an RFC 6265 Set-Cookie header value.
    pub fn to_set_cookie_header(&self) -> String {
        format_set_cookie(
            &self.name,
            &self.value,
            self.path.as_deref(),
            self.max_age_secs,
            self.secure,
            self.http_only,
            self.same_site.map(|ss| ss.as_str()),
        )
    }

    /// Format as a single key-value pair for Cookie request headers.
    pub fn to_cookie_pair(&self) -> String {
        format!("{}={}", self.name, self.value)
    }

    /// Parse a raw Set-Cookie header string into a structured Cookie.
    pub fn parse_set_cookie(header: &str) -> Option<Self> {
        let mut parts = header.split(';');
        let first = parts.next()?.trim();
        let (name, value) = first.split_once('=')?;
        let name = name.trim();
        let value = value.trim();
        if name.is_empty() {
            return None;
        }

        let mut cookie = Cookie::new(name, value);

        for part in parts {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some((attr_name, attr_val)) = trimmed.split_once('=') {
                let attr_name = attr_name.trim();
                let attr_val = attr_val.trim();
                if attr_name.eq_ignore_ascii_case("path") {
                    cookie.path = Some(attr_val.to_string());
                } else if attr_name.eq_ignore_ascii_case("domain") {
                    cookie.domain = Some(attr_val.to_string());
                } else if attr_name.eq_ignore_ascii_case("max-age") {
                    if let Ok(secs) = attr_val.parse::<u64>() {
                        cookie.max_age_secs = Some(secs);
                    }
                } else if attr_name.eq_ignore_ascii_case("samesite") {
                    cookie.same_site = SameSite::parse(attr_val);
                }
            } else if trimmed.eq_ignore_ascii_case("secure") {
                cookie.secure = true;
            } else if trimmed.eq_ignore_ascii_case("httponly") {
                cookie.http_only = true;
            }
        }

        Some(cookie)
    }
}

/// RFC 6265 client cookie jar managing automatic persistence, expiration, and header formatting.
#[derive(Debug, Clone, Default)]
pub struct CookieJar {
    cookies: HashMap<String, Cookie>,
}

impl CookieJar {
    pub fn new() -> Self {
        Self {
            cookies: HashMap::new(),
        }
    }

    /// Store or update a cookie in the jar.
    pub fn add(&mut self, mut cookie: Cookie) {
        cookie.created_at = Instant::now();
        self.cookies.insert(cookie.name.clone(), cookie);
    }

    /// Retrieve an unexpired cookie by name.
    pub fn get(&self, name: &str) -> Option<&Cookie> {
        if let Some(cookie) = self.cookies.get(name) {
            if cookie.is_expired() {
                None
            } else {
                Some(cookie)
            }
        } else {
            None
        }
    }

    /// Retrieve an unexpired cookie value by name.
    pub fn get_value(&self, name: &str) -> Option<&str> {
        self.get(name).map(|c| c.value.as_str())
    }

    /// Check if an unexpired cookie with the given name exists.
    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    /// Remove a cookie by name.
    pub fn remove(&mut self, name: &str) -> Option<Cookie> {
        self.cookies.remove(name)
    }

    /// Remove all cookies.
    pub fn clear(&mut self) {
        self.cookies.clear();
    }

    /// Count of currently valid (non-expired) cookies.
    pub fn len(&self) -> usize {
        self.cookies.values().filter(|c| !c.is_expired()).count()
    }

    /// Return all active, non-expired cookies.
    pub fn all(&self) -> Vec<&Cookie> {
        self.cookies.values().filter(|c| !c.is_expired()).collect()
    }

    /// Returns true if no valid cookies exist.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Purge expired cookies and return the number of purged cookies.
    pub fn purge_expired(&mut self) -> usize {
        let initial_len = self.cookies.len();
        self.cookies.retain(|_, c| !c.is_expired());
        initial_len - self.cookies.len()
    }

    /// Parse and store a Set-Cookie header. If Max-Age=0, removes the cookie.
    pub fn store_set_cookie(&mut self, set_cookie_str: &str) -> bool {
        if let Some(cookie) = Cookie::parse_set_cookie(set_cookie_str) {
            if cookie.max_age_secs == Some(0) {
                self.remove(&cookie.name);
            } else {
                self.add(cookie);
            }
            true
        } else {
            false
        }
    }

    /// Extract and store all Set-Cookie headers from an HTTP response.
    pub fn store_from_response(&mut self, response: &HttpResponse) -> usize {
        let set_cookie_headers = response.headers.get_all("set-cookie");
        let mut count = 0;
        for sc in set_cookie_headers {
            if self.store_set_cookie(sc) {
                count += 1;
            }
        }
        count
    }

    /// Build a Cookie header string (e.g. "foo=bar; baz=qux") in deterministic order.
    pub fn to_cookie_header(&self) -> Option<String> {
        let mut valid: Vec<&Cookie> = self.cookies.values().filter(|c| !c.is_expired()).collect();
        if valid.is_empty() {
            return None;
        }
        valid.sort_by(|a, b| a.name.cmp(&b.name));
        let s = valid
            .iter()
            .map(|c| c.to_cookie_pair())
            .collect::<Vec<_>>()
            .join("; ");
        Some(s)
    }

    /// Apply valid cookies to an HTTP request's headers.
    pub fn apply_to_request(&self, request: &mut HttpRequest) {
        if let Some(header_val) = self.to_cookie_header() {
            request.headers.set("Cookie", header_val);
        }
    }
}

/// In-memory server-side HTTP session with expiration and key-value attributes.
#[derive(Debug, Clone)]
pub struct HttpSession {
    pub id: String,
    pub created_at: Instant,
    pub last_accessed_at: Instant,
    pub ttl: Duration,
    data: HashMap<String, String>,
}

impl HttpSession {
    pub fn new(id: impl Into<String>, ttl: Duration) -> Self {
        let now = Instant::now();
        Self {
            id: id.into(),
            created_at: now,
            last_accessed_at: now,
            ttl,
            data: HashMap::new(),
        }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.data.get(key).map(|s| s.as_str())
    }

    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.data.insert(key.into(), value.into());
        self.last_accessed_at = Instant::now();
    }

    pub fn remove(&mut self, key: &str) -> Option<String> {
        self.last_accessed_at = Instant::now();
        self.data.remove(key)
    }

    pub fn is_expired_at(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.last_accessed_at) >= self.ttl
    }

    pub fn is_expired(&self) -> bool {
        self.is_expired_at(Instant::now())
    }

    pub fn touch(&mut self) {
        self.last_accessed_at = Instant::now();
    }
}

/// Server-side session store managing active sessions, generation, and TTL eviction.
#[derive(Debug)]
pub struct SessionStore {
    sessions: HashMap<String, HttpSession>,
    default_ttl: Duration,
    counter: u64,
}

impl SessionStore {
    pub fn new(default_ttl: Duration) -> Self {
        Self {
            sessions: HashMap::new(),
            default_ttl,
            counter: 0,
        }
    }

    fn generate_session_id(&mut self) -> String {
        self.counter += 1;
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let mix = (ts ^ (self.counter as u128).wrapping_mul(0x517cc1b727220a95)) as u64;
        format!("ifa_sess_{:016x}_{:08x}", mix, self.counter)
    }

    pub fn create_session(&mut self) -> String {
        self.create_session_with_ttl(self.default_ttl)
    }

    pub fn create_session_with_ttl(&mut self, ttl: Duration) -> String {
        let sid = self.generate_session_id();
        let session = HttpSession::new(sid.clone(), ttl);
        self.sessions.insert(sid.clone(), session);
        sid
    }

    pub fn get_session(&mut self, id: &str) -> Option<&HttpSession> {
        let is_exp = self
            .sessions
            .get(id)
            .map(|s| s.is_expired())
            .unwrap_or(true);
        if is_exp {
            self.sessions.remove(id);
            None
        } else {
            if let Some(s) = self.sessions.get_mut(id) {
                s.touch();
            }
            self.sessions.get(id)
        }
    }

    pub fn get_session_mut(&mut self, id: &str) -> Option<&mut HttpSession> {
        let is_exp = self
            .sessions
            .get(id)
            .map(|s| s.is_expired())
            .unwrap_or(true);
        if is_exp {
            self.sessions.remove(id);
            None
        } else {
            let session = self.sessions.get_mut(id)?;
            session.touch();
            Some(session)
        }
    }

    pub fn remove_session(&mut self, id: &str) -> Option<HttpSession> {
        self.sessions.remove(id)
    }

    pub fn purge_expired(&mut self) -> usize {
        let now = Instant::now();
        let initial_len = self.sessions.len();
        self.sessions.retain(|_, s| !s.is_expired_at(now));
        initial_len - self.sessions.len()
    }

    pub fn active_sessions_count(&self) -> usize {
        let now = Instant::now();
        self.sessions
            .values()
            .filter(|s| !s.is_expired_at(now))
            .count()
    }
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
// HTTP Date (RFC 7231 / RFC 1123) Formatting and Parsing
// ============================================================================

const DAYS_SHORT: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
const MONTHS_SHORT: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];
const DAYS_PER_MONTH: [u32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

fn is_leap_year(year: u32) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

fn month_days(year: u32, month: usize) -> u32 {
    if month == 1 && is_leap_year(year) {
        29
    } else {
        DAYS_PER_MONTH[month]
    }
}

/// Format a `SystemTime` as an RFC 7231 / RFC 1123 IMF-fixdate string (e.g. "Sun, 06 Nov 1994 08:49:37 GMT").
pub fn format_http_date(time: SystemTime) -> String {
    let secs = time
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let day_of_week = ((secs / 86400) % 7) as usize; // 0 = Thu 1970-01-01
    let weekday_str = DAYS_SHORT[day_of_week];

    let mut days_remaining = (secs / 86400) as u32;
    let day_seconds = (secs % 86400) as u32;
    let hour = day_seconds / 3600;
    let minute = (day_seconds % 3600) / 60;
    let second = day_seconds % 60;

    let mut year = 1970u32;
    loop {
        let year_days = if is_leap_year(year) { 366 } else { 365 };
        if days_remaining < year_days {
            break;
        }
        days_remaining -= year_days;
        year += 1;
    }

    let mut month = 0usize;
    loop {
        let m_days = month_days(year, month);
        if days_remaining < m_days {
            break;
        }
        days_remaining -= m_days;
        month += 1;
    }
    let day = days_remaining + 1;
    let month_str = MONTHS_SHORT[month];

    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        weekday_str, day, month_str, year, hour, minute, second
    )
}

/// Parse an RFC 7231 / RFC 1123 IMF-fixdate string into a `SystemTime`.
/// Accepts "Sun, 06 Nov 1994 08:49:37 GMT". Returns None if parsing fails.
pub fn parse_http_date(date_str: &str) -> Option<SystemTime> {
    let trimmed = date_str.trim();
    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    // Expected format: ["Sun,", "06", "Nov", "1994", "08:49:37", "GMT"]
    if parts.len() != 6 {
        return None;
    }
    if !parts[5].eq_ignore_ascii_case("GMT") && !parts[5].eq_ignore_ascii_case("UTC") {
        return None;
    }

    let day: u32 = parts[1].parse().ok()?;
    let month_name = parts[2];
    let month = MONTHS_SHORT
        .iter()
        .position(|&m| m.eq_ignore_ascii_case(month_name))?;
    let year: u32 = parts[3].parse().ok()?;

    if !(1970..=2200).contains(&year) {
        return None;
    }
    if day < 1 || day > month_days(year, month) {
        return None;
    }

    let time_parts: Vec<&str> = parts[4].split(':').collect();
    if time_parts.len() != 3 {
        return None;
    }
    let hour: u32 = time_parts[0].parse().ok()?;
    let minute: u32 = time_parts[1].parse().ok()?;
    let second: u32 = time_parts[2].parse().ok()?;

    if hour >= 24 || minute >= 60 || second >= 60 {
        return None;
    }

    let mut days = 0u64;
    for y in 1970..year {
        days += if is_leap_year(y) { 366 } else { 365 };
    }
    for m in 0..month {
        days += month_days(year, m) as u64;
    }
    days += (day - 1) as u64;

    let total_secs = days * 86400 + (hour as u64) * 3600 + (minute as u64) * 60 + (second as u64);
    Some(UNIX_EPOCH + Duration::from_secs(total_secs))
}

// ============================================================================
// HTTP Cache-Control Directive Parser (RFC 7234)
// ============================================================================

/// Parsed HTTP Cache-Control directives for clients, servers, and intermediaries.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HttpCacheDirectives {
    pub no_cache: bool,
    pub no_store: bool,
    pub no_transform: bool,
    pub only_if_cached: bool,
    pub must_revalidate: bool,
    pub proxy_revalidate: bool,
    pub must_understand: bool,
    pub is_public: bool,
    pub is_private: bool,
    pub immutable: bool,
    pub max_age: Option<u64>,
    pub s_maxage: Option<u64>,
    pub max_stale: Option<Option<u64>>, // Some(None) means any age stale; Some(Some(s)) max delta
    pub min_fresh: Option<u64>,
    pub stale_while_revalidate: Option<u64>,
    pub stale_if_error: Option<u64>,
}

impl HttpCacheDirectives {
    /// Parse a Cache-Control header string (comma-separated directives).
    pub fn parse(header_val: &str) -> Self {
        let mut d = Self::default();
        for directive in header_val.split(',') {
            let item = directive.trim();
            if item.is_empty() {
                continue;
            }

            let mut kv = item.splitn(2, '=');
            let name = kv.next().unwrap_or("").trim().to_ascii_lowercase();
            let val = kv.next().map(|v| v.trim().trim_matches('"'));

            match name.as_str() {
                "no-cache" => d.no_cache = true,
                "no-store" => d.no_store = true,
                "no-transform" => d.no_transform = true,
                "only-if-cached" => d.only_if_cached = true,
                "must-revalidate" => d.must_revalidate = true,
                "proxy-revalidate" => d.proxy_revalidate = true,
                "must-understand" => d.must_understand = true,
                "public" => d.is_public = true,
                "private" => d.is_private = true,
                "immutable" => d.immutable = true,
                "max-age" => {
                    if let Some(v) = val {
                        d.max_age = v.parse::<u64>().ok();
                    }
                }
                "s-maxage" => {
                    if let Some(v) = val {
                        d.s_maxage = v.parse::<u64>().ok();
                    }
                }
                "max-stale" => {
                    if let Some(v) = val {
                        d.max_stale = Some(v.parse::<u64>().ok());
                    } else {
                        d.max_stale = Some(None);
                    }
                }
                "min-fresh" => {
                    if let Some(v) = val {
                        d.min_fresh = v.parse::<u64>().ok();
                    }
                }
                "stale-while-revalidate" => {
                    if let Some(v) = val {
                        d.stale_while_revalidate = v.parse::<u64>().ok();
                    }
                }
                "stale-if-error" => {
                    if let Some(v) = val {
                        d.stale_if_error = v.parse::<u64>().ok();
                    }
                }
                _ => {}
            }
        }
        d
    }

    /// Check if resource can be stored in a shared or private cache.
    pub fn is_cacheable(&self) -> bool {
        !self.no_store
    }

    /// Serialize directives back to standard Cache-Control header string.
    pub fn to_header_value(&self) -> String {
        let mut parts = Vec::new();
        if self.is_public {
            parts.push("public".to_string());
        }
        if self.is_private {
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
        if self.proxy_revalidate {
            parts.push("proxy-revalidate".to_string());
        }
        if self.immutable {
            parts.push("immutable".to_string());
        }
        if let Some(max_age) = self.max_age {
            parts.push(format!("max-age={}", max_age));
        }
        if let Some(s_maxage) = self.s_maxage {
            parts.push(format!("s-maxage={}", s_maxage));
        }
        if let Some(max_stale) = self.max_stale {
            if let Some(delta) = max_stale {
                parts.push(format!("max-stale={}", delta));
            } else {
                parts.push("max-stale".to_string());
            }
        }
        if let Some(min_fresh) = self.min_fresh {
            parts.push(format!("min-fresh={}", min_fresh));
        }
        if let Some(swr) = self.stale_while_revalidate {
            parts.push(format!("stale-while-revalidate={}", swr));
        }
        if let Some(sie) = self.stale_if_error {
            parts.push(format!("stale-if-error={}", sie));
        }

        parts.join(", ")
    }
}

// ============================================================================
// HTTP Cache Entry & Client Cache Storage (RFC 7234)
// ============================================================================

/// In-memory cache entry for cached HTTP responses.
#[derive(Debug, Clone)]
pub struct HttpCacheEntry {
    pub key: String,
    pub status: HttpStatus,
    pub headers: HttpHeaders,
    pub body: Vec<u8>,
    pub response_time: SystemTime,
    pub expires_at: Option<SystemTime>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

impl HttpCacheEntry {
    /// Create a cache entry from an HTTP response and URI key.
    pub fn new(key: impl Into<String>, response: &HttpResponse, response_time: SystemTime) -> Self {
        let etag = response.headers.get("etag").map(|s| s.to_string());
        let last_modified = response.headers.get("last-modified").map(|s| s.to_string());

        let expires_at = if let Some(cc) = response.headers.get("cache-control") {
            let directives = HttpCacheDirectives::parse(cc);
            directives.max_age.map(|sec| response_time + Duration::from_secs(sec))
        } else if let Some(exp) = response.headers.get("expires") {
            parse_http_date(exp)
        } else {
            None
        };

        Self {
            key: key.into(),
            status: response.status,
            headers: response.headers.clone(),
            body: response.body.clone(),
            response_time,
            expires_at,
            etag,
            last_modified,
        }
    }

    /// Check if this cached entry is fresh at time `now`.
    pub fn is_fresh(&self, now: SystemTime) -> bool {
        if let Some(exp) = self.expires_at {
            now < exp
        } else {
            false
        }
    }

    /// Reconstruct an HttpResponse from this cache entry.
    pub fn to_response(&self) -> HttpResponse {
        let mut resp = HttpResponse::new(self.status);
        resp.headers = self.headers.clone();
        resp.body = self.body.clone();
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

    /// Send request protected by a circuit breaker.
    pub fn send_with_circuit_breaker(
        &self,
        breaker: &mut HttpCircuitBreaker,
        req: &HttpRequest,
        host: &str,
        port: u16,
    ) -> io::Result<HttpResponse> {
        breaker.execute(|| self.send(req, host, port))
    }

    /// Send request utilizing connection pooling protected by a circuit breaker.
    pub fn send_pooled_with_circuit_breaker(
        &self,
        breaker: &mut HttpCircuitBreaker,
        pool: &mut HttpConnectionPool,
        req: &HttpRequest,
        host: &str,
        port: u16,
    ) -> io::Result<HttpResponse> {
        breaker.execute(|| pool.send_request(req, host, port))
    }

    /// Send request governed by a retry policy with exponential backoff and jitter.
    pub fn send_with_retry(
        &self,
        policy: &HttpRetryPolicy,
        req: &HttpRequest,
        host: &str,
        port: u16,
    ) -> (io::Result<HttpResponse>, HttpRetryReport) {
        policy.execute(&req.method, |_attempt| self.send(req, host, port))
    }

    /// Send request utilizing connection pooling governed by a retry policy.
    pub fn send_pooled_with_retry(
        &self,
        policy: &HttpRetryPolicy,
        pool: &mut HttpConnectionPool,
        req: &HttpRequest,
        host: &str,
        port: u16,
    ) -> (io::Result<HttpResponse>, HttpRetryReport) {
        policy.execute(&req.method, |_attempt| pool.send_request(req, host, port))
    }

    /// Fully resilient request execution: retry policy wrapping a circuit breaker and connection pool.
    pub fn send_resilient(
        &self,
        policy: &HttpRetryPolicy,
        breaker: &mut HttpCircuitBreaker,
        pool: &mut HttpConnectionPool,
        req: &HttpRequest,
        host: &str,
        port: u16,
    ) -> (io::Result<HttpResponse>, HttpRetryReport) {
        policy.execute(&req.method, |_attempt| {
            breaker.execute(|| pool.send_request(req, host, port))
        })
    }
}

/// Configuration and policy engine for automatic HTTP request retries with exponential backoff and jitter.
#[derive(Debug, Clone, PartialEq)]
pub struct HttpRetryPolicy {
    /// Maximum number of retry attempts (default: 3).
    pub max_retries: usize,
    /// Base delay in milliseconds before the first retry (default: 50ms).
    pub initial_delay_ms: u64,
    /// Maximum backoff ceiling in milliseconds (default: 2000ms).
    pub max_delay_ms: u64,
    /// Exponential multiplication factor applied between successive attempts (default: 2.0).
    pub backoff_factor: f64,
    /// Jitter variance ratio [0.0..=0.5] applied to avoid synchronized retries / thundering herds (default: 0.1).
    pub jitter_ratio: f64,
    /// HTTP status codes considered transient and eligible for retry (default: 408, 429, 500, 502, 503, 504).
    pub retryable_status_codes: Vec<u16>,
    /// HTTP methods considered safe/idempotent to retry (default: GET, HEAD, PUT, DELETE, OPTIONS, TRACE).
    pub retryable_methods: Vec<HttpMethod>,
    /// Whether to retry when an I/O network connection error occurs (default: true).
    pub retry_on_network_error: bool,
}

/// Execution telemetry and statistics for an HTTP operation processed with retry policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRetryReport {
    /// Total number of attempts executed (1 initial attempt + number of retries).
    pub attempts: usize,
    /// Total number of retries performed (attempts - 1).
    pub retries: usize,
    /// Whether the request ultimately succeeded.
    pub succeeded: bool,
    /// Final HTTP status code obtained, if available.
    pub last_status: Option<u16>,
    /// Total cumulative backoff delay waited in milliseconds.
    pub total_backoff_ms: u64,
}

impl Default for HttpRetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay_ms: 50,
            max_delay_ms: 2000,
            backoff_factor: 2.0,
            jitter_ratio: 0.1,
            retryable_status_codes: vec![408, 429, 500, 502, 503, 504],
            retryable_methods: vec![
                HttpMethod::Get,
                HttpMethod::Head,
                HttpMethod::Put,
                HttpMethod::Delete,
                HttpMethod::Options,
            ],
            retry_on_network_error: true,
        }
    }
}

impl HttpRetryPolicy {
    /// Create a new retry policy with standard default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set maximum retry count.
    pub fn with_max_retries(mut self, max: usize) -> Self {
        self.max_retries = max;
        self
    }

    /// Set initial backoff delay in milliseconds.
    pub fn with_initial_delay_ms(mut self, delay: u64) -> Self {
        self.initial_delay_ms = delay;
        self
    }

    /// Set maximum ceiling delay in milliseconds.
    pub fn with_max_delay_ms(mut self, max: u64) -> Self {
        self.max_delay_ms = max;
        self
    }

    /// Set exponential backoff multiplication factor.
    pub fn with_backoff_factor(mut self, factor: f64) -> Self {
        self.backoff_factor = factor;
        self
    }

    /// Set jitter variance ratio [0.0..=0.5].
    pub fn with_jitter_ratio(mut self, jitter: f64) -> Self {
        self.jitter_ratio = jitter;
        self
    }

    /// Set list of HTTP status codes eligible for retry.
    pub fn with_retryable_statuses(mut self, statuses: Vec<u16>) -> Self {
        self.retryable_status_codes = statuses;
        self
    }

    /// Set list of HTTP methods permitted to be retried.
    pub fn with_retryable_methods(mut self, methods: Vec<HttpMethod>) -> Self {
        self.retryable_methods = methods;
        self
    }

    /// Enable or disable retrying on I/O network errors.
    pub fn with_retry_on_network_error(mut self, enable: bool) -> Self {
        self.retry_on_network_error = enable;
        self
    }

    /// Check if a given HTTP status code is retryable under this policy.
    pub fn is_status_retryable(&self, status: u16) -> bool {
        self.retryable_status_codes.contains(&status)
    }

    /// Check if a given HTTP method is idempotent/safe to retry under this policy.
    pub fn is_method_retryable(&self, method: &HttpMethod) -> bool {
        self.retryable_methods.contains(method)
    }

    /// Calculate backoff delay in milliseconds for the given attempt count (1-based).
    pub fn calculate_delay_ms(&self, attempt: usize) -> u64 {
        if attempt <= 1 {
            return self.initial_delay_ms.min(self.max_delay_ms);
        }
        let exp = (attempt - 1) as i32;
        let base_delay = (self.initial_delay_ms as f64) * self.backoff_factor.powi(exp);
        let capped = base_delay.min(self.max_delay_ms as f64);
        let jitter_amount = capped * self.jitter_ratio.clamp(0.0, 0.5);
        // Deterministic salt based on attempt for reproducible jitter
        let salt = (((attempt as u64) * 1103515245 + 12345) % 100) as f64 / 100.0;
        let jitter_offset = (salt - 0.5) * 2.0 * jitter_amount;
        (capped + jitter_offset).clamp(1.0, self.max_delay_ms as f64) as u64
    }

    /// Execute an HTTP operation with automatic retries, backoff, and telemetry reporting.
    pub fn execute<F>(
        &self,
        method: &HttpMethod,
        mut op: F,
    ) -> (io::Result<HttpResponse>, HttpRetryReport)
    where
        F: FnMut(usize) -> io::Result<HttpResponse>,
    {
        let mut attempts = 0;
        let mut total_backoff_ms = 0;
        let max_attempts = self.max_retries + 1;

        for attempt in 1..=max_attempts {
            attempts = attempt;
            match op(attempt) {
                Ok(resp) => {
                    let status = resp.status.0;
                    let should_retry = attempt < max_attempts
                        && self.is_method_retryable(method)
                        && self.is_status_retryable(status);

                    if should_retry {
                        let delay = self.calculate_delay_ms(attempt);
                        std::thread::sleep(Duration::from_millis(delay));
                        total_backoff_ms += delay;
                        continue;
                    }

                    let succeeded = status < 400 || !self.is_status_retryable(status);
                    let report = HttpRetryReport {
                        attempts,
                        retries: attempts.saturating_sub(1),
                        succeeded,
                        last_status: Some(status),
                        total_backoff_ms,
                    };
                    return (Ok(resp), report);
                }
                Err(err) => {
                    let should_retry = attempt < max_attempts
                        && self.retry_on_network_error
                        && self.is_method_retryable(method);

                    if should_retry {
                        let delay = self.calculate_delay_ms(attempt);
                        std::thread::sleep(Duration::from_millis(delay));
                        total_backoff_ms += delay;
                        continue;
                    }

                    let report = HttpRetryReport {
                        attempts,
                        retries: attempts.saturating_sub(1),
                        succeeded: false,
                        last_status: None,
                        total_backoff_ms,
                    };
                    return (Err(err), report);
                }
            }
        }

        let report = HttpRetryReport {
            attempts,
            retries: attempts.saturating_sub(1),
            succeeded: false,
            last_status: None,
            total_backoff_ms,
        };
        (Err(io::Error::other("Retries exhausted")), report)
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

    /// Forward an incoming request protected by a circuit breaker.
    pub fn forward_with_circuit_breaker(
        &self,
        breaker: &mut HttpCircuitBreaker,
        pool: &mut HttpConnectionPool,
        req: &HttpRequest,
        client_ip: &str,
        client_proto: &str,
        backend: &UpstreamBackend,
    ) -> io::Result<HttpResponse> {
        breaker.execute(|| self.forward_pooled(pool, req, client_ip, client_proto, backend))
    }
}

/// State of the HTTP Circuit Breaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Circuit is closed; normal operation, all requests forwarded.
    Closed,
    /// Circuit is open; upstream is failing, fast-failing requests.
    Open,
    /// Circuit is half-open; probe requests allowed to test upstream recovery.
    HalfOpen,
}

/// Configuration options for the HTTP Circuit Breaker.
#[derive(Debug, Clone)]
pub struct HttpCircuitBreakerConfig {
    /// Number of consecutive failures before tripping the circuit from Closed to Open.
    pub failure_threshold: usize,
    /// Number of consecutive successes in HalfOpen state before closing the circuit.
    pub success_threshold: usize,
    /// Duration in milliseconds the circuit remains Open before transitioning to HalfOpen.
    pub recovery_timeout_ms: u64,
    /// Upstream HTTP status codes treated as failures (e.g. 500, 502, 503, 504).
    pub failure_status_codes: Vec<u16>,
}

impl Default for HttpCircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 2,
            recovery_timeout_ms: 10_000,
            failure_status_codes: vec![500, 502, 503, 504],
        }
    }
}

/// HTTP Circuit Breaker implementing the standard resilience pattern for downstream calls.
#[derive(Debug)]
pub struct HttpCircuitBreaker {
    config: HttpCircuitBreakerConfig,
    state: CircuitState,
    consecutive_failures: usize,
    consecutive_successes: usize,
    last_state_change: Instant,
    last_failure: Option<Instant>,
    total_trips: u64,
    total_requests: u64,
    total_rejected: u64,
}

impl Default for HttpCircuitBreaker {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpCircuitBreaker {
    /// Create a new circuit breaker with default configuration.
    pub fn new() -> Self {
        Self::with_config(HttpCircuitBreakerConfig::default())
    }

    /// Create a new circuit breaker with custom configuration.
    pub fn with_config(config: HttpCircuitBreakerConfig) -> Self {
        Self {
            config,
            state: CircuitState::Closed,
            consecutive_failures: 0,
            consecutive_successes: 0,
            last_state_change: Instant::now(),
            last_failure: None,
            total_trips: 0,
            total_requests: 0,
            total_rejected: 0,
        }
    }

    /// Current circuit state.
    pub fn state(&self) -> CircuitState {
        self.state
    }

    /// True if circuit is closed (healthy).
    pub fn is_closed(&self) -> bool {
        self.state == CircuitState::Closed
    }

    /// True if circuit is open (tripped).
    pub fn is_open(&self) -> bool {
        self.state == CircuitState::Open
    }

    /// True if circuit is half-open (probing).
    pub fn is_half_open(&self) -> bool {
        self.state == CircuitState::HalfOpen
    }

    /// Total number of times the circuit tripped from Closed/HalfOpen to Open.
    pub fn total_trips(&self) -> u64 {
        self.total_trips
    }

    /// Total requests allowed through.
    pub fn total_requests(&self) -> u64 {
        self.total_requests
    }

    /// Total requests rejected while open.
    pub fn total_rejected(&self) -> u64 {
        self.total_rejected
    }

    /// Consecutive failures count.
    pub fn consecutive_failures(&self) -> usize {
        self.consecutive_failures
    }

    /// Consecutive successes count.
    pub fn consecutive_successes(&self) -> usize {
        self.consecutive_successes
    }

    /// Determine if an outgoing request is allowed.
    pub fn allow_request(&mut self) -> bool {
        match self.state {
            CircuitState::Closed => {
                self.total_requests += 1;
                true
            }
            CircuitState::Open => {
                if self.last_state_change.elapsed()
                    >= Duration::from_millis(self.config.recovery_timeout_ms)
                {
                    self.state = CircuitState::HalfOpen;
                    self.consecutive_successes = 0;
                    self.last_state_change = Instant::now();
                    self.total_requests += 1;
                    true
                } else {
                    self.total_rejected += 1;
                    false
                }
            }
            CircuitState::HalfOpen => {
                self.total_requests += 1;
                true
            }
        }
    }

    /// Record a successful request outcome.
    pub fn record_success(&mut self) {
        match self.state {
            CircuitState::HalfOpen => {
                self.consecutive_successes += 1;
                if self.consecutive_successes >= self.config.success_threshold {
                    self.state = CircuitState::Closed;
                    self.consecutive_failures = 0;
                    self.consecutive_successes = 0;
                    self.last_state_change = Instant::now();
                }
            }
            CircuitState::Closed => {
                self.consecutive_failures = 0;
            }
            CircuitState::Open => {}
        }
    }

    /// Record a failure outcome (network error or server 5xx error).
    pub fn record_failure(&mut self) {
        self.last_failure = Some(Instant::now());
        match self.state {
            CircuitState::Closed => {
                self.consecutive_failures += 1;
                if self.consecutive_failures >= self.config.failure_threshold {
                    self.state = CircuitState::Open;
                    self.total_trips += 1;
                    self.consecutive_failures = 0;
                    self.consecutive_successes = 0;
                    self.last_state_change = Instant::now();
                }
            }
            CircuitState::HalfOpen => {
                self.state = CircuitState::Open;
                self.total_trips += 1;
                self.consecutive_failures = 0;
                self.consecutive_successes = 0;
                self.last_state_change = Instant::now();
            }
            CircuitState::Open => {}
        }
    }

    /// Record response, classifying status code according to failure_status_codes.
    pub fn record_response(&mut self, resp: &HttpResponse) {
        if self
            .config
            .failure_status_codes
            .contains(&resp.status.code())
        {
            self.record_failure();
        } else {
            self.record_success();
        }
    }

    /// Execute a request closure within the protection of this circuit breaker.
    pub fn execute<F>(&mut self, f: F) -> io::Result<HttpResponse>
    where
        F: FnOnce() -> io::Result<HttpResponse>,
    {
        if !self.allow_request() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "HTTP circuit breaker is OPEN",
            ));
        }
        match f() {
            Ok(resp) => {
                self.record_response(&resp);
                Ok(resp)
            }
            Err(err) => {
                self.record_failure();
                Err(err)
            }
        }
    }

    /// Reset circuit breaker to default Closed state with zeroed counters.
    pub fn reset(&mut self) {
        self.state = CircuitState::Closed;
        self.consecutive_failures = 0;
        self.consecutive_successes = 0;
        self.last_state_change = Instant::now();
        self.last_failure = None;
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
    fn test_cookie_struct_and_samesite_rfc6265() {
        let c = Cookie::new("jwt_auth", "token_val_12345")
            .path("/auth")
            .domain("ifa-lang.org")
            .max_age(3600)
            .secure(true)
            .http_only(true)
            .same_site(SameSite::Strict);

        assert_eq!(c.name, "jwt_auth");
        assert_eq!(c.value, "token_val_12345");
        assert_eq!(c.path.as_deref(), Some("/auth"));
        assert_eq!(c.domain.as_deref(), Some("ifa-lang.org"));
        assert_eq!(c.max_age_secs, Some(3600));
        assert!(c.secure);
        assert!(c.http_only);
        assert_eq!(c.same_site, Some(SameSite::Strict));

        let set_cookie_hdr = c.to_set_cookie_header();
        assert!(set_cookie_hdr.contains("jwt_auth=token_val_12345"));
        assert!(set_cookie_hdr.contains("Path=/auth"));
        assert!(set_cookie_hdr.contains("Max-Age=3600"));
        assert!(set_cookie_hdr.contains("SameSite=Strict"));
        assert!(set_cookie_hdr.contains("Secure"));
        assert!(set_cookie_hdr.contains("HttpOnly"));

        let parsed = Cookie::parse_set_cookie(&set_cookie_hdr).expect("Parsed Set-Cookie");
        assert_eq!(parsed.name, "jwt_auth");
        assert_eq!(parsed.value, "token_val_12345");
        assert_eq!(parsed.path.as_deref(), Some("/auth"));
        assert_eq!(parsed.max_age_secs, Some(3600));
        assert!(parsed.secure);
        assert!(parsed.http_only);
        assert_eq!(parsed.same_site, Some(SameSite::Strict));

        // Expiration check relative to future instant
        let future_expired = c.created_at + Duration::from_secs(3601);
        let future_valid = c.created_at + Duration::from_secs(3599);
        assert!(c.is_expired_at(future_expired));
        assert!(!c.is_expired_at(future_valid));
    }

    #[test]
    fn test_cookie_jar_lifecycle_and_max_age_expiration() {
        let mut jar = CookieJar::new();
        assert!(jar.is_empty());

        let c1 = Cookie::new("session", "sess_abc").max_age(100);
        let c2 = Cookie::new("theme", "dracula");
        let c3 = Cookie::new("temp", "remove_soon").max_age(0);

        jar.add(c1);
        jar.add(c2);
        assert_eq!(jar.len(), 2);
        assert_eq!(jar.get_value("session"), Some("sess_abc"));
        assert_eq!(jar.get_value("theme"), Some("dracula"));

        // Max-Age=0 removal
        jar.store_set_cookie(&c3.to_set_cookie_header());
        assert!(!jar.contains("temp"));

        // Format to header
        let hdr = jar.to_cookie_header().expect("Cookie header present");
        assert!(hdr.contains("session=sess_abc"));
        assert!(hdr.contains("theme=dracula"));

        // Apply to request
        let mut req = HttpRequest::new(HttpMethod::Get, "/api/dashboard");
        jar.apply_to_request(&mut req);
        assert_eq!(req.headers.get("cookie"), Some(hdr.as_str()));

        // Manual removal
        jar.remove("session");
        assert_eq!(jar.len(), 1);
        assert!(!jar.contains("session"));
    }

    #[test]
    fn test_http_response_multiple_set_cookie_headers() {
        let c1 = Cookie::new("sid", "123").path("/").http_only(true);
        let c2 = Cookie::new("pref", "dark").path("/");
        let c3 = Cookie::new("lang", "fr").path("/");

        let resp = HttpResponse::ok()
            .set_cookie_obj(&c1)
            .set_cookie_obj(&c2)
            .set_cookie_obj(&c3);

        let parsed_cookies = resp.cookies();
        assert_eq!(parsed_cookies.len(), 3);
        assert_eq!(parsed_cookies[0].name, "sid");
        assert_eq!(parsed_cookies[0].value, "123");
        assert!(parsed_cookies[0].http_only);
        assert_eq!(parsed_cookies[1].name, "pref");
        assert_eq!(parsed_cookies[1].value, "dark");
        assert_eq!(parsed_cookies[2].name, "lang");
        assert_eq!(parsed_cookies[2].value, "fr");

        let mut jar = CookieJar::new();
        let stored = jar.store_from_response(&resp);
        assert_eq!(stored, 3);
        assert_eq!(jar.len(), 3);
        assert_eq!(jar.get_value("sid"), Some("123"));
        assert_eq!(jar.get_value("pref"), Some("dark"));
        assert_eq!(jar.get_value("lang"), Some("fr"));
    }

    #[test]
    fn test_http_session_and_session_store() {
        let mut store = SessionStore::new(Duration::from_secs(60));
        assert_eq!(store.active_sessions_count(), 0);

        let sid = store.create_session();
        assert!(sid.starts_with("ifa_sess_"));
        assert_eq!(store.active_sessions_count(), 1);

        {
            let sess = store.get_session_mut(&sid).expect("Session found");
            sess.set("user_id", "42");
            sess.set("username", "prudence");
            assert_eq!(sess.get("user_id"), Some("42"));
            assert_eq!(sess.get("username"), Some("prudence"));
        }

        {
            let sess = store.get_session(&sid).expect("Session found read-only");
            assert_eq!(sess.get("user_id"), Some("42"));
        }

        // Test custom short TTL expiration
        let short_sid = store.create_session_with_ttl(Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(5));
        assert!(store.get_session(&short_sid).is_none());

        // Invalidation
        store.remove_session(&sid);
        assert_eq!(store.active_sessions_count(), 0);
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

        // 7. HTTP Date (RFC 7231 / RFC 1123) Formatting and Parsing
        let test_epoch = UNIX_EPOCH + Duration::from_secs(784111777); // Sun, 06 Nov 1994 08:49:37 GMT
        let formatted_date = format_http_date(test_epoch);
        assert_eq!(formatted_date, "Sun, 06 Nov 1994 08:49:37 GMT");

        let parsed_date = parse_http_date(&formatted_date).expect("HTTP date parse failed");
        assert_eq!(
            parsed_date.duration_since(UNIX_EPOCH).unwrap().as_secs(),
            784111777
        );

        // If-Modified-Since and If-Unmodified-Since conditional handling
        let resource_time = test_epoch;
        let future_time = test_epoch + Duration::from_secs(3600);
        let past_time = test_epoch - Duration::from_secs(3600);

        // Client has cache from future_time -> resource (test_epoch) NOT modified
        let req_ims_fresh = HttpRequest::new(HttpMethod::Get, "/doc")
            .header("If-Modified-Since", &format_http_date(future_time));
        assert!(req_ims_fresh.if_modified_since(resource_time));

        // Client has cache from past_time -> resource (test_epoch) HAS been modified
        let req_ims_stale = HttpRequest::new(HttpMethod::Get, "/doc")
            .header("If-Modified-Since", &format_http_date(past_time));
        assert!(!req_ims_stale.if_modified_since(resource_time));

        // If-Unmodified-Since (e.g. for safe conditional PUT / DELETE)
        let req_ius_ok = HttpRequest::new(HttpMethod::Put, "/doc")
            .header("If-Unmodified-Since", &format_http_date(future_time));
        assert!(req_ius_ok.if_unmodified_since(resource_time));

        let req_ius_conflict = HttpRequest::new(HttpMethod::Put, "/doc")
            .header("If-Unmodified-Since", &format_http_date(past_time));
        assert!(!req_ius_conflict.if_unmodified_since(resource_time));

        // 8. HTTP Cache-Control Directives & Entry (RFC 7234)
        let cc_header = "public, max-age=3600, s-maxage=7200, must-revalidate, stale-while-revalidate=60";
        let cc = HttpCacheDirectives::parse(cc_header);
        assert!(cc.is_public);
        assert!(!cc.is_private);
        assert!(!cc.no_cache);
        assert!(cc.is_cacheable());
        assert_eq!(cc.max_age, Some(3600));
        assert_eq!(cc.s_maxage, Some(7200));
        assert!(cc.must_revalidate);
        assert_eq!(cc.stale_while_revalidate, Some(60));

        let resp_with_cache = HttpResponse::ok()
            .cache_control(cc_header)
            .etag(&strong_etag)
            .last_modified(test_epoch)
            .text("cached payload");

        let entry = HttpCacheEntry::new("/api/cached", &resp_with_cache, test_epoch);
        assert_eq!(entry.key, "/api/cached");
        assert_eq!(entry.etag, Some(strong_etag));
        assert_eq!(entry.last_modified, Some(formatted_date));
        assert!(entry.is_fresh(test_epoch + Duration::from_secs(1800)));
        assert!(!entry.is_fresh(test_epoch + Duration::from_secs(3601)));

        let reconstructed = entry.to_response();
        assert_eq!(reconstructed.status, HttpStatus::OK);
        assert_eq!(reconstructed.body_str().unwrap(), "cached payload");
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

    #[test]
    fn test_http_circuit_breaker_lifecycle() {
        let config = HttpCircuitBreakerConfig {
            failure_threshold: 3,
            success_threshold: 2,
            recovery_timeout_ms: 50,
            failure_status_codes: vec![500, 502, 503],
        };

        let mut cb = HttpCircuitBreaker::with_config(config);
        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.is_closed());
        assert!(!cb.is_open());
        assert!(!cb.is_half_open());
        assert_eq!(cb.total_trips(), 0);

        // 1. Initial success in Closed state
        assert!(cb.allow_request());
        cb.record_success();
        assert_eq!(cb.consecutive_failures(), 0);
        assert_eq!(cb.state(), CircuitState::Closed);

        // 2. Consecutive failures below threshold
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.consecutive_failures(), 2);
        assert_eq!(cb.state(), CircuitState::Closed);

        // 3. 3rd failure trips the circuit open
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        assert!(cb.is_open());
        assert_eq!(cb.total_trips(), 1);

        // 4. Immediate calls rejected (Fast fail)
        assert!(!cb.allow_request());
        assert_eq!(cb.total_rejected(), 1);

        // Execute helper returns Err
        let exec_res = cb.execute(|| Ok(HttpResponse::ok().text("test")));
        assert!(exec_res.is_err());
        assert_eq!(cb.total_rejected(), 2);

        // 5. Wait for recovery timeout to transition to HalfOpen
        std::thread::sleep(Duration::from_millis(60));
        assert!(cb.allow_request()); // Transitions to HalfOpen
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        assert!(cb.is_half_open());

        // 6. First probe success
        cb.record_success();
        assert_eq!(cb.consecutive_successes(), 1);
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        // 7. Second probe success restores Closed state
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.is_closed());
        assert_eq!(cb.consecutive_successes(), 0);
        assert_eq!(cb.consecutive_failures(), 0);

        // 8. Test half-open probe failure trips back to open
        cb.record_failure();
        cb.record_failure();
        cb.record_failure(); // trips to open
        assert_eq!(cb.state(), CircuitState::Open);
        assert_eq!(cb.total_trips(), 2);

        std::thread::sleep(Duration::from_millis(60));
        assert!(cb.allow_request()); // Transitions to HalfOpen
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        // Failure during HalfOpen re-trips immediately
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        assert_eq!(cb.total_trips(), 3);

        // 9. Reset
        cb.reset();
        assert_eq!(cb.state(), CircuitState::Closed);
        assert_eq!(cb.consecutive_failures(), 0);
    }

    #[test]
    fn test_http_circuit_breaker_client_server_integration() {
        let mut server = HttpServer::new(0);
        server.get("/api/healthy", |_req| {
            HttpResponse::ok().text("healthy service")
        });
        server.get("/api/failing", |_req| {
            HttpResponse::new(HttpStatus::SERVICE_UNAVAILABLE).text("service unavailable")
        });

        let bound = server.listen_background().expect("Server listen failed");
        let port = bound.port();

        let client = HttpClient::new();
        let config = HttpCircuitBreakerConfig {
            failure_threshold: 2,
            success_threshold: 1,
            recovery_timeout_ms: 50,
            failure_status_codes: vec![500, 502, 503],
        };
        let mut breaker = HttpCircuitBreaker::with_config(config);

        // Healthy requests pass
        let req_ok = HttpRequest::new(HttpMethod::Get, "/api/healthy");
        let resp_ok = client
            .send_with_circuit_breaker(&mut breaker, &req_ok, "127.0.0.1", port)
            .expect("Healthy request failed");
        assert_eq!(resp_ok.status, HttpStatus::OK);
        assert!(breaker.is_closed());

        // Failing requests record failure and trip breaker
        let req_fail = HttpRequest::new(HttpMethod::Get, "/api/failing");
        let resp1 = client
            .send_with_circuit_breaker(&mut breaker, &req_fail, "127.0.0.1", port)
            .expect("First 503 received");
        assert_eq!(resp1.status, HttpStatus::SERVICE_UNAVAILABLE);
        assert_eq!(breaker.consecutive_failures(), 1);

        let resp2 = client
            .send_with_circuit_breaker(&mut breaker, &req_fail, "127.0.0.1", port)
            .expect("Second 503 received");
        assert_eq!(resp2.status, HttpStatus::SERVICE_UNAVAILABLE);
        assert!(breaker.is_open());
        assert_eq!(breaker.total_trips(), 1);

        // Immediate subsequent request fails fast
        let fast_fail = client.send_with_circuit_breaker(&mut breaker, &req_ok, "127.0.0.1", port);
        assert!(fast_fail.is_err());
        assert_eq!(breaker.total_rejected(), 1);

        // Wait for recovery timeout
        std::thread::sleep(Duration::from_millis(60));

        // Half-open trial request recovers circuit
        let probe = client
            .send_with_circuit_breaker(&mut breaker, &req_ok, "127.0.0.1", port)
            .expect("Probe request succeeded");
        assert_eq!(probe.status, HttpStatus::OK);
        assert!(breaker.is_closed());

        server.stop();
    }

    #[test]
    fn test_http_retry_policy_delay_calculation() {
        let policy = HttpRetryPolicy::new()
            .with_max_retries(4)
            .with_initial_delay_ms(10)
            .with_max_delay_ms(100)
            .with_backoff_factor(2.0)
            .with_jitter_ratio(0.0);

        assert_eq!(policy.calculate_delay_ms(1), 10);
        assert_eq!(policy.calculate_delay_ms(2), 20);
        assert_eq!(policy.calculate_delay_ms(3), 40);
        assert_eq!(policy.calculate_delay_ms(4), 80);
        assert_eq!(policy.calculate_delay_ms(5), 100);

        assert!(policy.is_status_retryable(503));
        assert!(policy.is_status_retryable(429));
        assert!(!policy.is_status_retryable(200));
        assert!(!policy.is_status_retryable(404));

        assert!(policy.is_method_retryable(&HttpMethod::Get));
        assert!(policy.is_method_retryable(&HttpMethod::Put));
        assert!(!policy.is_method_retryable(&HttpMethod::Post));
    }

    #[test]
    fn test_http_retry_policy_execute_success_after_retries() {
        let policy = HttpRetryPolicy::new()
            .with_max_retries(3)
            .with_initial_delay_ms(2)
            .with_jitter_ratio(0.0);

        let mut attempts_seen = 0;
        let (res, report) = policy.execute(&HttpMethod::Get, |attempt| {
            attempts_seen = attempt;
            if attempt < 3 {
                Ok(HttpResponse::new(HttpStatus::SERVICE_UNAVAILABLE).text("transient error"))
            } else {
                Ok(HttpResponse::ok().text("recovered"))
            }
        });

        let resp = res.expect("Should succeed on attempt 3");
        assert_eq!(resp.status, HttpStatus::OK);
        assert_eq!(resp.body_str().unwrap(), "recovered");
        assert_eq!(attempts_seen, 3);
        assert_eq!(report.attempts, 3);
        assert_eq!(report.retries, 2);
        assert!(report.succeeded);
        assert_eq!(report.last_status, Some(200));
    }

    #[test]
    fn test_http_retry_policy_non_idempotent_no_retry() {
        let policy = HttpRetryPolicy::new()
            .with_max_retries(3)
            .with_initial_delay_ms(2);

        let mut attempts_seen = 0;
        let (res, report) = policy.execute(&HttpMethod::Post, |attempt| {
            attempts_seen = attempt;
            Ok(HttpResponse::new(HttpStatus::INTERNAL_SERVER_ERROR).text("failure"))
        });

        let resp = res.expect("Should return response without retry");
        assert_eq!(resp.status, HttpStatus::INTERNAL_SERVER_ERROR);
        assert_eq!(attempts_seen, 1);
        assert_eq!(report.attempts, 1);
        assert_eq!(report.retries, 0);
    }

    #[test]
    fn test_http_client_send_with_retry_integration() {
        let mut server = HttpServer::new(0);
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c_clone = Arc::clone(&counter);

        server.get("/api/flaky", move |_req| {
            let n = c_clone.fetch_add(1, Ordering::SeqCst);
            if n < 2 {
                HttpResponse::new(HttpStatus::SERVICE_UNAVAILABLE).text("unavailable")
            } else {
                HttpResponse::ok().text("service restored")
            }
        });

        let bound = server.listen_background().expect("Server listen failed");
        let port = bound.port();

        let client = HttpClient::new();
        let policy = HttpRetryPolicy::new()
            .with_max_retries(3)
            .with_initial_delay_ms(5)
            .with_jitter_ratio(0.0);

        let req = HttpRequest::new(HttpMethod::Get, "/api/flaky");
        let (res, report) = client.send_with_retry(&policy, &req, "127.0.0.1", port);

        let resp = res.expect("Flaky endpoint should succeed on attempt 3");
        assert_eq!(resp.status, HttpStatus::OK);
        assert_eq!(resp.body_str().unwrap(), "service restored");
        assert_eq!(report.attempts, 3);
        assert_eq!(report.retries, 2);
        assert!(report.succeeded);

        server.stop();
    }

    #[test]
    fn test_http_crc32_standard() {
        assert_eq!(http_crc32(b""), 0);
        assert_eq!(http_crc32(b"123456789"), 0xCBF43926);
    }

    #[test]
    fn test_compress_decompress_deflate_roundtrip() {
        // 1. Empty payload
        let empty_comp = compress_deflate(b"");
        let empty_decomp =
            decompress_deflate(&empty_comp).expect("Empty deflate decompress failed");
        assert_eq!(empty_decomp, b"");

        // 2. Short payload
        let data = b"Hello, IFA HTTP colorless fibers with deflate compression!";
        let comp = compress_deflate(data);
        let decomp = decompress_deflate(&comp).expect("Deflate decompress failed");
        assert_eq!(decomp, data);

        // 3. Multi-block payload exceeding 32768 chunk boundary (e.g. 70,000 bytes)
        let mut large = Vec::with_capacity(70000);
        for i in 0..70000 {
            large.push((i % 251) as u8);
        }
        let comp_large = compress_deflate(&large);
        let decomp_large = decompress_deflate(&comp_large).expect("Multi-block deflate failed");
        assert_eq!(decomp_large, large);

        // 4. Corrupted data detection
        assert!(decompress_deflate(b"").is_err());
        assert!(decompress_deflate(b"\x00\x05\x00\xFA\xFFbad").is_err());
    }

    #[test]
    fn test_compress_decompress_gzip_roundtrip() {
        // 1. Empty payload
        let empty_gz = compress_gzip(b"");
        let empty_decomp = decompress_gzip(&empty_gz).expect("Empty gzip decompress failed");
        assert_eq!(empty_decomp, b"");

        // 2. Standard text payload
        let text = b"The quick brown fox jumps over the lazy dog. IFA runtime!";
        let gz = compress_gzip(text);
        assert_eq!(gz[0], 0x1F);
        assert_eq!(gz[1], 0x8B);
        let decomp = decompress_gzip(&gz).expect("Gzip text decompress failed");
        assert_eq!(decomp, text);

        // 3. Corrupted CRC32 detection
        let mut corrupted_crc = gz.clone();
        let len = corrupted_crc.len();
        corrupted_crc[len - 8] ^= 0xFF;
        assert!(decompress_gzip(&corrupted_crc).is_err());

        // 4. Corrupted ISIZE detection
        let mut corrupted_isize = gz.clone();
        corrupted_isize[len - 1] ^= 0x01;
        assert!(decompress_gzip(&corrupted_isize).is_err());
    }

    #[test]
    fn test_http_request_response_encoding_helpers() {
        let req = HttpRequest::new(HttpMethod::Get, "/api/data")
            .header("Accept-Encoding", "gzip, deflate;q=0.5, br");

        assert!(req.accepts_encoding("gzip"));
        assert!(req.accepts_encoding("deflate"));
        assert!(req.accepts_encoding("br"));
        assert!(!req.accepts_encoding("zstd"));

        let uncompressed = HttpResponse::ok().text("Plain uncompressed body text for testing");
        assert_eq!(uncompressed.content_encoding(), ContentEncoding::Identity);

        // Test explicit gzip compression
        let compressed = uncompressed.gzip();
        assert_eq!(compressed.content_encoding(), ContentEncoding::Gzip);
        assert_eq!(compressed.headers.get("content-encoding"), Some("gzip"));

        let decompressed_str = compressed
            .body_decompressed_str()
            .expect("Decompression failed");
        assert_eq!(decompressed_str, "Plain uncompressed body text for testing");

        // Test auto compress if accepted threshold
        let short_resp = HttpResponse::ok().text("short");
        let not_compressed = short_resp.clone().compress_if_accepted(&req, 64);
        assert_eq!(not_compressed.content_encoding(), ContentEncoding::Identity);

        let long_text = "A".repeat(128);
        let long_resp = HttpResponse::ok().text(long_text.clone());
        let auto_compressed = long_resp.compress_if_accepted(&req, 64);
        assert_eq!(auto_compressed.content_encoding(), ContentEncoding::Gzip);
        assert_eq!(auto_compressed.body_decompressed_str().unwrap(), long_text);
    }

    #[test]
    fn test_http_server_auto_compression_integration() {
        let mut server = HttpServer::new(0);
        server.with_auto_compression(32);

        server.get("/api/article", |_req| {
            HttpResponse::ok().text("This is an article payload that is long enough to trigger automatic gzip compression in IFA HttpServer.")
        });

        let bound = server.listen_background().expect("Server listen failed");
        let port = bound.port();
        let client = HttpClient::new();

        // 1. Request WITHOUT Accept-Encoding: gzip -> server sends identity (uncompressed)
        let req_plain = HttpRequest::new(HttpMethod::Get, "/api/article");
        let resp_plain = client
            .send(&req_plain, "127.0.0.1", port)
            .expect("Plain request failed");
        assert_eq!(resp_plain.status, HttpStatus::OK);
        assert_eq!(resp_plain.headers.get("content-encoding"), None);
        assert!(resp_plain
            .body_str()
            .unwrap()
            .starts_with("This is an article"));

        // 2. Request WITH Accept-Encoding: gzip -> server compresses automatically
        let req_gzip =
            HttpRequest::new(HttpMethod::Get, "/api/article").header("Accept-Encoding", "gzip");
        let resp_gzip = client
            .send(&req_gzip, "127.0.0.1", port)
            .expect("Gzip request failed");
        assert_eq!(resp_gzip.status, HttpStatus::OK);
        assert_eq!(resp_gzip.headers.get("content-encoding"), Some("gzip"));

        // Verify transparent decompression
        let decompressed_body = resp_gzip
            .body_decompressed_str()
            .expect("Decompress response failed");
        assert_eq!(
            decompressed_body,
            "This is an article payload that is long enough to trigger automatic gzip compression in IFA HttpServer."
        );

        server.stop();
    }

    #[test]
    fn test_jwt_and_csrf_http_security() {
        let secret = b"ifa-secure-jwt-secret-key-32b!";
        let claims = JwtClaims::new()
            .with_sub("user-99")
            .with_exp(3000)
            .with_custom("tenant", serde_json::json!("enterprise"));

        let token = Jwt::sign_hs256(secret, &claims).unwrap();

        // 1. JWT Bearer verification
        let req = HttpRequest::new(HttpMethod::Get, "/api/profile?tab=security&_csrf=token_xyz")
            .header("Authorization", &format!("Bearer {}", token));

        assert_eq!(req.query_string(), Some("tab=security&_csrf=token_xyz"));
        assert_eq!(req.query_param("tab"), Some("security".to_string()));
        assert_eq!(req.query_param("_csrf"), Some("token_xyz".to_string()));
        assert_eq!(req.bearer_token(), Some(token.clone()));

        let verified_claims = req
            .verify_jwt_bearer(secret, 2000)
            .expect("Bearer verification failed");
        assert_eq!(verified_claims.sub.as_deref(), Some("user-99"));
        assert_eq!(
            verified_claims.get_custom("tenant"),
            Some(&serde_json::json!("enterprise"))
        );

        // 2. CSRF Token extraction & constant time verification
        assert_eq!(req.csrf_token(), Some("token_xyz".to_string()));
        assert!(req.verify_csrf("token_xyz"));
        assert!(!req.verify_csrf("wrong_csrf_token"));

        // CSRF from header takes precedence
        let req_header_csrf = HttpRequest::new(HttpMethod::Post, "/api/transfer?_csrf=param_token")
            .header("X-CSRF-Token", "header_token");
        assert_eq!(
            req_header_csrf.csrf_token(),
            Some("header_token".to_string())
        );
        assert!(req_header_csrf.verify_csrf("header_token"));
        assert!(!req_header_csrf.verify_csrf("param_token"));
    }

    #[test]
    fn test_http_router_middlewares_jwt_and_csrf() {
        let jwt_secret = b"ifa-production-secret-key-32b!!";
        let claims = JwtClaims::new()
            .with_sub("member-42")
            .with_exp(4_000_000_000);
        let valid_token = Jwt::sign_hs256(jwt_secret, &claims).unwrap();

        // 1. Configure router with global middleware and protected routes
        let mut router = HttpRouter::new();

        // Global middleware: attach custom security header and inspect maintenance flag
        router.use_middleware(Arc::new(|req: &mut HttpRequest| {
            if req.headers.get("x-maintenance").is_some() {
                Some(
                    HttpResponse::new(HttpStatus::SERVICE_UNAVAILABLE)
                        .text("System undergoing maintenance"),
                )
            } else {
                req.headers.set("X-IFA-Filter", "active");
                None
            }
        }));

        // Public route
        router.get("/api/v1/public", |_req| {
            HttpResponse::ok().text("public data")
        });

        // JWT-protected route
        let auth_mw = jwt_auth_middleware(jwt_secret.to_vec());
        router.get_with_middlewares("/api/v1/account", vec![auth_mw.clone()], |req| {
            let sub = req.context("auth_sub").unwrap_or("anonymous");
            HttpResponse::ok().text(format!("Welcome {}", sub))
        });

        // Mutating route requiring BOTH JWT auth and CSRF protection
        let csrf_mw = csrf_protection_middleware("csrf_cookie", "X-CSRF-Token");
        router.post_with_middlewares("/api/v1/settings", vec![auth_mw, csrf_mw], |req| {
            let sub = req.context("auth_sub").unwrap_or("anonymous");
            HttpResponse::ok().text(format!("Settings updated for {}", sub))
        });

        // --- Dispatch Unit Tests ---

        // A. Maintenance short-circuit
        let mut req_maint =
            HttpRequest::new(HttpMethod::Get, "/api/v1/public").header("X-Maintenance", "1");
        let resp_maint = router.dispatch(&mut req_maint);
        assert_eq!(resp_maint.status, HttpStatus::SERVICE_UNAVAILABLE);
        assert_eq!(
            resp_maint.body_str().unwrap(),
            "System undergoing maintenance"
        );

        // B. Public route succeeds
        let mut req_pub = HttpRequest::new(HttpMethod::Get, "/api/v1/public");
        let resp_pub = router.dispatch(&mut req_pub);
        assert_eq!(resp_pub.status, HttpStatus::OK);
        assert_eq!(resp_pub.body_str().unwrap(), "public data");

        // C. Protected route without token -> 401 Unauthorized
        let mut req_unauth = HttpRequest::new(HttpMethod::Get, "/api/v1/account");
        let resp_unauth = router.dispatch(&mut req_unauth);
        assert_eq!(resp_unauth.status, HttpStatus::UNAUTHORIZED);
        assert!(resp_unauth.body_str().unwrap().contains("unauthorized"));

        // D. Protected route with valid token -> 200 OK + context populated
        let mut req_auth = HttpRequest::new(HttpMethod::Get, "/api/v1/account")
            .header("Authorization", &format!("Bearer {}", valid_token));
        let resp_auth = router.dispatch(&mut req_auth);
        assert_eq!(resp_auth.status, HttpStatus::OK);
        assert_eq!(resp_auth.body_str().unwrap(), "Welcome member-42");
        assert_eq!(req_auth.context("auth_sub"), Some("member-42"));

        // E. Mutating POST without CSRF token -> 403 Forbidden
        let mut req_post_no_csrf = HttpRequest::new(HttpMethod::Post, "/api/v1/settings")
            .header("Authorization", &format!("Bearer {}", valid_token));
        let resp_post_no_csrf = router.dispatch(&mut req_post_no_csrf);
        assert_eq!(resp_post_no_csrf.status, HttpStatus::FORBIDDEN);
        assert!(resp_post_no_csrf
            .body_str()
            .unwrap()
            .contains("invalid_or_missing_csrf_token"));

        // F. Mutating POST with valid CSRF cookie and header -> 200 OK
        let mut req_post_valid = HttpRequest::new(HttpMethod::Post, "/api/v1/settings")
            .header("Authorization", &format!("Bearer {}", valid_token))
            .header("Cookie", "csrf_cookie=sec_token_9999")
            .header("X-CSRF-Token", "sec_token_9999");
        let resp_post_valid = router.dispatch(&mut req_post_valid);
        assert_eq!(resp_post_valid.status, HttpStatus::OK);
        assert_eq!(
            resp_post_valid.body_str().unwrap(),
            "Settings updated for member-42"
        );

        // --- HttpServer Fiber Integration Test ---
        let mut server = HttpServer::new(0);
        let srv_auth_mw = jwt_auth_middleware(jwt_secret.to_vec());
        server.get_with_middlewares("/api/protected", vec![srv_auth_mw], |req| {
            let sub = req.context("auth_sub").unwrap_or("anon");
            HttpResponse::ok().text(format!("Fiber member: {}", sub))
        });

        let bound = server.listen_background().expect("Server bind failed");
        let port = bound.port();
        let client = HttpClient::new();

        // Server rejects missing token
        let req_net_unauth = HttpRequest::new(HttpMethod::Get, "/api/protected");
        let resp_net_unauth = client.send(&req_net_unauth, "127.0.0.1", port).unwrap();
        assert_eq!(resp_net_unauth.status, HttpStatus::UNAUTHORIZED);

        // Server accepts valid token over TCP socket
        let req_net_auth = HttpRequest::new(HttpMethod::Get, "/api/protected")
            .header("Authorization", &format!("Bearer {}", valid_token));
        let resp_net_auth = client.send(&req_net_auth, "127.0.0.1", port).unwrap();
        assert_eq!(resp_net_auth.status, HttpStatus::OK);
        assert_eq!(resp_net_auth.body_str().unwrap(), "Fiber member: member-42");

        server.stop();
    }

    #[test]
    fn test_rfc3986_url_parsing_and_formatting() {
        // 1. Full absolute HTTPS URL with userinfo, custom port, query and fragment
        let raw = "https://alice:secret@example.com:8443/api/v1/resource?filter=active&sort=desc#section-2";
        let url = Url::parse(raw).expect("parse full url");
        assert_eq!(url.scheme, "https");
        assert_eq!(url.host, "example.com");
        assert_eq!(url.port, Some(8443));
        assert_eq!(url.userinfo, Some("alice:secret".to_string()));
        assert_eq!(url.path, "/api/v1/resource");
        assert_eq!(url.query, Some("filter=active&sort=desc".to_string()));
        assert_eq!(url.fragment, Some("section-2".to_string()));

        // Check query parsing
        let pairs = url.query_pairs();
        assert_eq!(
            pairs,
            vec![
                ("filter".to_string(), "active".to_string()),
                ("sort".to_string(), "desc".to_string()),
            ]
        );
        let map = url.query_map();
        assert_eq!(map.get("filter").map(|s| s.as_str()), Some("active"));
        assert_eq!(map.get("sort").map(|s| s.as_str()), Some("desc"));

        // Roundtrip to URI string
        assert_eq!(url.to_uri_string(), raw);
        assert_eq!(format!("{}", url), raw);

        // 2. Default port omission for standard schemes
        let std_http = Url::parse("http://example.org:80/index.html").expect("parse http 80");
        assert_eq!(std_http.port, Some(80));
        assert_eq!(std_http.to_uri_string(), "http://example.org/index.html");

        let std_https = Url::parse("https://api.github.com/events").expect("parse https 443");
        assert_eq!(std_https.port, Some(443));
        assert_eq!(std_https.to_uri_string(), "https://api.github.com/events");

        // 3. IPv6 authority URL
        let ipv6_url = Url::parse("http://[::1]:9090/status").expect("parse ipv6");
        assert_eq!(ipv6_url.host, "::1");
        assert_eq!(ipv6_url.port, Some(9090));
        assert_eq!(ipv6_url.to_uri_string(), "http://[::1]:9090/status");

        // 4. Origin-relative path with query
        let rel_url = Url::parse("/search?q=ifa+language&page=1").expect("parse relative");
        assert_eq!(rel_url.scheme, "");
        assert_eq!(rel_url.host, "");
        assert_eq!(rel_url.path, "/search");
        let rel_pairs = rel_url.query_pairs();
        assert_eq!(rel_pairs[0], ("q".to_string(), "ifa language".to_string()));
        assert_eq!(rel_pairs[1], ("page".to_string(), "1".to_string()));
        assert_eq!(rel_url.to_uri_string(), "/search?q=ifa+language&page=1");

        // 5. request_target and query param manipulation
        let mut mod_url = Url::parse("https://example.com/api/data?foo=bar").unwrap();
        assert_eq!(mod_url.request_target(), "/api/data?foo=bar");
        mod_url.set_query_param("limit", "10");
        assert_eq!(
            mod_url.query_map().get("limit").map(|s| s.as_str()),
            Some("10")
        );
        let chained = mod_url.with_query_param("foo", "baz");
        assert_eq!(
            chained.query_map().get("foo").map(|s| s.as_str()),
            Some("baz")
        );
    }

    #[test]
    fn test_request_auth_helpers() {
        // Basic auth fluent builder and parsing
        let req1 = HttpRequest::new(HttpMethod::Get, "/api/v1/protected")
            .with_basic_auth("admin", "secret_pass123");
        assert_eq!(
            req1.authorization(),
            Some("Basic YWRtaW46c2VjcmV0X3Bhc3MxMjM=")
        );
        let parsed_creds = req1.basic_auth();
        assert_eq!(
            parsed_creds,
            Some(("admin".to_string(), "secret_pass123".to_string()))
        );

        // Bearer token fluent builder and parsing
        let req2 = HttpRequest::new(HttpMethod::Post, "/api/v1/orders")
            .with_bearer_auth("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz");
        assert_eq!(
            req2.authorization(),
            Some("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz")
        );
        assert_eq!(
            req2.bearer_token(),
            Some("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz".to_string())
        );

        // API Key builder and extraction (default header and custom header)
        let req3 = HttpRequest::new(HttpMethod::Get, "/api/v1/data")
            .with_api_key("secret-api-key-123", None);
        assert_eq!(req3.api_key(None), Some("secret-api-key-123"));
        assert_eq!(req3.headers.get("x-api-key"), Some("secret-api-key-123"));

        let req4 = HttpRequest::new(HttpMethod::Get, "/api/v1/custom")
            .with_api_key("custom-key-999", Some("X-Custom-Auth"));
        assert_eq!(req4.api_key(Some("x-custom-auth")), Some("custom-key-999"));
        assert_eq!(req4.headers.get("X-Custom-Auth"), Some("custom-key-999"));

        // Cookie request builders and jar integration
        let req5 = HttpRequest::new(HttpMethod::Get, "/api/v1/profile")
            .with_cookie("session_id", "sess-555")
            .with_cookie("theme", "midnight");
        assert_eq!(
            req5.headers.get("cookie"),
            Some("session_id=sess-555; theme=midnight")
        );
        let cookies5 = req5.cookies();
        assert_eq!(cookies5.get("session_id"), Some(&"sess-555".to_string()));
        assert_eq!(cookies5.get("theme"), Some(&"midnight".to_string()));
        assert_eq!(req5.cookie("session_id"), Some("sess-555".to_string()));

        let mut jar = CookieJar::new();
        jar.add(Cookie::new("sid", "abc"));
        jar.add(Cookie::new("tracker", "xyz"));
        assert_eq!(jar.all().len(), 2);
        let req6 = HttpRequest::new(HttpMethod::Get, "/api/v1/checkout").with_cookie_jar(&jar);
        assert_eq!(req6.cookie("sid"), Some("abc".to_string()));
        assert_eq!(req6.cookie("tracker"), Some("xyz".to_string()));
    }

    #[test]
    fn test_redirect_handling_and_url_join() {
        let base = Url::parse("https://example.com/api/v1/users/").expect("base url");

        // 1. Join relative paths
        let joined1 = base.join("profile").expect("join profile");
        assert_eq!(
            joined1.to_uri_string(),
            "https://example.com/api/v1/users/profile"
        );

        let joined_parent = base.join("../items?sort=name").expect("join parent");
        assert_eq!(
            joined_parent.to_uri_string(),
            "https://example.com/api/v1/items?sort=name"
        );

        let joined_root = base.join("/login").expect("join root");
        assert_eq!(joined_root.to_uri_string(), "https://example.com/login");

        let joined_absolute = base
            .join("http://other.org:8080/landing")
            .expect("join absolute");
        assert_eq!(
            joined_absolute.to_uri_string(),
            "http://other.org:8080/landing"
        );

        // 2. HTTP Status redirect helpers
        let resp301 = HttpResponse::moved_permanently("/new-path");
        assert_eq!(resp301.status, HttpStatus::MOVED_PERMANENTLY);
        assert!(resp301.status.is_redirection());
        assert!(resp301.is_redirection());
        assert_eq!(resp301.location(), Some("/new-path"));

        let resp302 = HttpResponse::found("/temporary");
        assert_eq!(resp302.status, HttpStatus::FOUND);
        assert!(resp302.is_redirection());
        assert_eq!(resp302.location(), Some("/temporary"));

        let resp303 = HttpResponse::see_other("/other");
        assert_eq!(resp303.status, HttpStatus::SEE_OTHER);
        assert!(resp303.is_redirection());

        let resp307 = HttpResponse::temporary_redirect("/temp-redirect");
        assert_eq!(resp307.status, HttpStatus::TEMPORARY_REDIRECT);
        assert!(resp307.is_redirection());

        let resp308 = HttpResponse::permanent_redirect("/perm-redirect");
        assert_eq!(resp308.status, HttpStatus::PERMANENT_REDIRECT);
        assert!(resp308.is_redirection());

        let resp200 = HttpResponse::ok();
        assert!(!resp200.status.is_redirection());
        assert!(!resp200.is_redirection());
        assert_eq!(resp200.location(), None);
    }

    #[test]
    fn test_client_timeouts_and_metrics() {
        let mut server = HttpServer::new(0);
        server.get("/healthz", |_req| {
            HttpResponse::ok()
                .header("Content-Type", "application/json")
                .text("{\"status\":\"healthy\",\"server_time\":1700000000}")
        });

        let bound = server.listen_background().expect("Server listen failed");
        let port = bound.port();

        // 1. Client with configuration and metrics
        let client = HttpClient::new().with_timeout(Duration::from_secs(5));
        assert_eq!(client.timeout, Some(Duration::from_secs(5)));

        let req = HttpRequest::new(HttpMethod::Get, "/healthz");
        let (resp, metrics) = client
            .send_with_metrics(&req, "127.0.0.1", port)
            .expect("Request with metrics failed");

        assert_eq!(resp.status, HttpStatus::OK);
        assert!(metrics.bytes_sent > 0);
        assert!(metrics.bytes_received > 0);
        assert_eq!(metrics.bytes_received, resp.body.len());
        assert!(metrics.connect_duration <= Duration::from_secs(2));
        assert!(metrics.request_duration <= Duration::from_secs(2));
        assert!(metrics.total_duration >= metrics.request_duration);

        // 2. Structured Url request with metrics
        let target_url =
            Url::parse(&format!("http://127.0.0.1:{}/healthz", port)).expect("Valid url");
        let mut req_url = HttpRequest::new(HttpMethod::Get, "/healthz");
        let (resp_url, metrics_url) = client
            .send_url_with_metrics(&mut req_url, &target_url)
            .expect("URL request with metrics failed");

        assert_eq!(resp_url.status, HttpStatus::OK);
        assert!(metrics_url.bytes_sent > 0);
        assert_eq!(metrics_url.bytes_received, resp_url.body.len());

        // 3. Timeout behavior verification
        let timeout_client = HttpClient::new().with_timeout(Duration::from_nanos(1));
        assert_eq!(timeout_client.timeout, Some(Duration::from_nanos(1)));
    }

    #[test]
    fn test_chunked_transfer_encoding_roundtrip_and_streaming() {
        // 1. Direct encoding and decoding unit tests
        let chunks: [&[u8]; 3] = [b"Hello, ", b"world of ", b"colorless chunked streaming!"];
        let encoded = encode_chunked(&chunks);
        let expected_wire =
            "7\r\nHello, \r\n9\r\nworld of \r\n1C\r\ncolorless chunked streaming!\r\n0\r\n\r\n";
        assert_eq!(String::from_utf8_lossy(&encoded), expected_wire);

        let (decoded, consumed, trailers) =
            decode_chunked_stream(&encoded).expect("Chunked stream decode failed");
        assert_eq!(
            String::from_utf8_lossy(&decoded),
            "Hello, world of colorless chunked streaming!"
        );
        assert_eq!(consumed, encoded.len());
        assert!(trailers.is_empty());

        // 2. Incomplete chunk stream test
        let partial = &encoded[..15];
        assert_eq!(
            decode_chunked_stream(partial).unwrap_err(),
            "Incomplete chunked body"
        );

        // 3. Chunked transfer with trailers
        let wire_with_trailers = b"5\r\nhello\r\n0\r\nExpires: Wed, 21 Oct 2026 07:28:00 GMT\r\nX-Checksum: abc123\r\n\r\n";
        let (body_tr, consumed_tr, trailers_tr) =
            decode_chunked_stream(wire_with_trailers).expect("Chunked with trailers failed");
        assert_eq!(body_tr, b"hello");
        assert_eq!(consumed_tr, wire_with_trailers.len());
        assert_eq!(
            trailers_tr.get("Expires"),
            Some("Wed, 21 Oct 2026 07:28:00 GMT")
        );
        assert_eq!(trailers_tr.get("X-Checksum"), Some("abc123"));

        // 4. HttpRequest and HttpResponse parse_from_wire with chunked Transfer-Encoding
        let raw_req = b"POST /upload HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n6\r\npedia \r\n0\r\n\r\n";
        let (req_parsed, req_consumed) =
            HttpRequest::parse_from_wire(raw_req).expect("Parse chunked request");
        assert_eq!(req_consumed, raw_req.len());
        assert_eq!(req_parsed.body_str().unwrap(), "Wikipedia ");

        let raw_resp = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nServer: IFA\r\n\r\n4\r\nData\r\n0\r\n\r\n";
        let (resp_parsed, resp_consumed) =
            HttpResponse::parse_from_wire(raw_resp).expect("Parse chunked response");
        assert_eq!(resp_consumed, raw_resp.len());
        assert_eq!(resp_parsed.body_str().unwrap(), "Data");

        // 5. Integration test: HttpServer sending chunked response to HttpClient
        let mut server = HttpServer::new(0);
        server.get("/stream", |_req| {
            HttpResponse::ok()
                .header("Content-Type", "text/plain")
                .chunked_body(&[
                    b"chunk-1: welcome\n",
                    b"chunk-2: to ifa\n",
                    b"chunk-3: streams\n",
                ])
        });

        // Also test server receiving chunked request from client
        server.post("/chunked-receiver", |req| {
            let received = req.body_str().unwrap_or("");
            HttpResponse::ok().text(format!("received:{}", received))
        });

        let bound = server.listen_background().expect("Server listen failed");
        let port = bound.port();

        let client = HttpClient::new();

        // GET chunked response
        let resp = client
            .get("127.0.0.1", port, "/stream")
            .expect("GET chunked");
        assert_eq!(resp.status, HttpStatus::OK);
        assert_eq!(
            resp.body_str().unwrap(),
            "chunk-1: welcome\nchunk-2: to ifa\nchunk-3: streams\n"
        );

        // POST chunked request
        let post_req = HttpRequest::new(HttpMethod::Post, "/chunked-receiver")
            .header("Host", "127.0.0.1")
            .chunked_body(&[b"alpha-", b"beta-", b"gamma"]);
        let post_resp = client
            .send(&post_req, "127.0.0.1", port)
            .expect("POST chunked request failed");
        assert_eq!(post_resp.status, HttpStatus::OK);
        assert_eq!(post_resp.body_str().unwrap(), "received:alpha-beta-gamma");
    }

    #[test]
    fn test_http_pipelining() {
        let mut server = HttpServer::new(0);
        server.get("/pipe/1", |_req| HttpResponse::ok().text("one"));
        server.get("/pipe/2", |_req| HttpResponse::ok().text("two"));
        server.get("/pipe/3", |_req| HttpResponse::ok().text("three"));

        let bound = server.listen_background().expect("Server listen failed");
        let port = bound.port();

        let client = HttpClient::new();

        let requests = vec![
            HttpRequest::new(HttpMethod::Get, "/pipe/1").header("Host", "127.0.0.1"),
            HttpRequest::new(HttpMethod::Get, "/pipe/2").header("Host", "127.0.0.1"),
            HttpRequest::new(HttpMethod::Get, "/pipe/3").header("Host", "127.0.0.1"),
        ];

        let responses = client
            .send_pipelined(&requests, "127.0.0.1", port)
            .expect("Pipelined requests failed");

        assert_eq!(responses.len(), 3);
        assert_eq!(responses[0].status, HttpStatus::OK);
        assert_eq!(responses[0].body_str().unwrap(), "one");
        assert_eq!(responses[1].status, HttpStatus::OK);
        assert_eq!(responses[1].body_str().unwrap(), "two");
        assert_eq!(responses[2].status, HttpStatus::OK);
        assert_eq!(responses[2].body_str().unwrap(), "three");
    }

    #[test]
    fn test_gzip_streaming_encoder_and_decoder() {
        let mut encoder = GzipStreamEncoder::new();
        let mut decoder = GzipStreamDecoder::new();

        let part1 = b"Hello, ";
        let part2 = b"colorless streaming ";
        let part3 = b"gzip fibers in IFA!";

        let mut compressed_wire = Vec::new();
        compressed_wire.extend_from_slice(&encoder.feed(part1));
        compressed_wire.extend_from_slice(&encoder.feed(part2));
        compressed_wire.extend_from_slice(&encoder.feed(part3));
        compressed_wire.extend_from_slice(&encoder.finish());
        assert!(encoder.is_finished());

        // Decompress via streaming decoder in small fragments (e.g. 5 bytes each)
        let mut decompressed = Vec::new();
        for chunk in compressed_wire.chunks(5) {
            let out = decoder.feed(chunk).expect("Feed failed");
            decompressed.extend_from_slice(&out);
        }

        assert!(decoder.is_finished());
        assert_eq!(
            String::from_utf8(decompressed).unwrap(),
            "Hello, colorless streaming gzip fibers in IFA!"
        );
    }
}

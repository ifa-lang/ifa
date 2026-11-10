//! Non-blocking networking, TCP stream management, and multi-connection server (`std::net`).

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{
    SocketAddr, TcpListener as StdTcpListener, TcpStream as StdTcpStream, ToSocketAddrs,
};
use std::time::Duration;

/// Managed non-blocking TCP Stream.
pub struct TcpStream {
    inner: StdTcpStream,
    is_open: bool,
}

impl TcpStream {
    /// Connect to a remote host and set the socket to non-blocking mode.
    pub fn connect<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        let stream = StdTcpStream::connect(addr)?;
        stream.set_nonblocking(true)?;
        stream.set_read_timeout(Some(Duration::from_millis(500)))?;
        stream.set_write_timeout(Some(Duration::from_millis(500)))?;
        Ok(Self {
            inner: stream,
            is_open: true,
        })
    }

    /// Wrap an existing standard stream.
    pub fn from_std(stream: StdTcpStream) -> io::Result<Self> {
        stream.set_nonblocking(true)?;
        Ok(Self {
            inner: stream,
            is_open: true,
        })
    }

    /// Read up to `buf.len()` bytes non-blockingly. Returns number of bytes read (0 if would block or EOF).
    pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.is_open {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "Stream is closed",
            ));
        }
        match self.inner.read(buf) {
            Ok(n) => Ok(n),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Ok(0),
            Err(e) => Err(e),
        }
    }

    /// Read all currently available data as a byte vector.
    pub fn read_available(&mut self, max_bytes: usize) -> io::Result<Vec<u8>> {
        let mut buffer = vec![0u8; max_bytes.min(65536)];
        let n = self.read(&mut buffer)?;
        buffer.truncate(n);
        Ok(buffer)
    }

    /// Write all bytes to the stream.
    pub fn write_all(&mut self, data: &[u8]) -> io::Result<usize> {
        if !self.is_open {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "Stream is closed",
            ));
        }
        self.inner.write_all(data)?;
        let _ = self.inner.flush();
        Ok(data.len())
    }

    /// Check if stream is currently marked open.
    pub fn is_open(&self) -> bool {
        self.is_open
    }

    /// Close the stream.
    pub fn close(&mut self) {
        if self.is_open {
            self.is_open = false;
            let _ = self.inner.shutdown(std::net::Shutdown::Both);
        }
    }

    /// Peer socket address.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.peer_addr()
    }

    /// Local socket address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

/// Managed non-blocking TCP Listener.
pub struct TcpListener {
    inner: StdTcpListener,
    is_open: bool,
}

impl TcpListener {
    /// Bind to a local address and set non-blocking mode.
    pub fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        let listener = StdTcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            inner: listener,
            is_open: true,
        })
    }

    /// Non-blocking attempt to accept an incoming connection.
    pub fn try_accept(&self) -> io::Result<Option<(TcpStream, SocketAddr)>> {
        if !self.is_open {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "Listener is closed",
            ));
        }
        match self.inner.accept() {
            Ok((stream, addr)) => {
                let managed = TcpStream::from_std(stream)?;
                Ok(Some((managed, addr)))
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Local socket address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// Bound port number.
    pub fn port(&self) -> io::Result<u16> {
        self.inner.local_addr().map(|a| a.port())
    }

    /// Close the listener.
    pub fn close(&mut self) {
        self.is_open = false;
    }
}

/// Active connection state in a multi-connection server.
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub id: usize,
    pub addr: SocketAddr,
    pub bytes_sent: usize,
    pub bytes_received: usize,
}

/// Multi-connection TCP Server orchestrating non-blocking client connections.
pub struct TcpServer {
    listener: TcpListener,
    clients: HashMap<usize, TcpStream>,
    client_info: HashMap<usize, ConnectionInfo>,
    next_client_id: usize,
    max_clients: usize,
    is_running: bool,
}

impl TcpServer {
    /// Bind server to local address with a maximum concurrent client capacity.
    pub fn bind<A: ToSocketAddrs>(addr: A, max_clients: usize) -> io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        Ok(Self {
            listener,
            clients: HashMap::new(),
            client_info: HashMap::new(),
            next_client_id: 1,
            max_clients,
            is_running: true,
        })
    }

    /// Local bound address of the server.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Bound port of the server.
    pub fn port(&self) -> io::Result<u16> {
        self.listener.port()
    }

    /// Number of currently active client connections.
    pub fn client_count(&self) -> usize {
        self.clients.len()
    }

    /// Poll for pending incoming connections and accept them without blocking.
    /// Returns number of newly accepted clients.
    pub fn accept_pending(&mut self) -> io::Result<usize> {
        if !self.is_running {
            return Ok(0);
        }
        let mut accepted = 0;
        while self.clients.len() < self.max_clients {
            match self.listener.try_accept()? {
                Some((stream, addr)) => {
                    let id = self.next_client_id;
                    self.next_client_id += 1;
                    self.client_info.insert(
                        id,
                        ConnectionInfo {
                            id,
                            addr,
                            bytes_sent: 0,
                            bytes_received: 0,
                        },
                    );
                    self.clients.insert(id, stream);
                    accepted += 1;
                }
                None => break,
            }
        }
        Ok(accepted)
    }

    /// Broadcast a message to all connected clients. Returns the number of successfully delivered messages.
    pub fn broadcast(&mut self, data: &[u8]) -> usize {
        let mut delivered = 0;
        let mut dead_clients = Vec::new();

        for (&id, stream) in self.clients.iter_mut() {
            match stream.write_all(data) {
                Ok(n) => {
                    if let Some(info) = self.client_info.get_mut(&id) {
                        info.bytes_sent += n;
                    }
                    delivered += 1;
                }
                Err(_) => {
                    dead_clients.push(id);
                }
            }
        }

        for id in dead_clients {
            self.disconnect(id);
        }

        delivered
    }

    /// Poll all active connections for incoming data without blocking.
    /// Returns vector of `(client_id, data_bytes)`.
    pub fn poll_readable(&mut self) -> Vec<(usize, Vec<u8>)> {
        let mut received = Vec::new();
        let mut dead_clients = Vec::new();

        for (&id, stream) in self.clients.iter_mut() {
            let mut buf = [0u8; 4096];
            match stream.read(&mut buf) {
                Ok(0) => {
                    // Would block or zero bytes available
                }
                Ok(n) => {
                    if let Some(info) = self.client_info.get_mut(&id) {
                        info.bytes_received += n;
                    }
                    received.push((id, buf[..n].to_vec()));
                }
                Err(_) => {
                    dead_clients.push(id);
                }
            }
        }

        for id in dead_clients {
            self.disconnect(id);
        }

        received
    }

    /// Send data directly to a specific connected client.
    pub fn send_to(&mut self, client_id: usize, data: &[u8]) -> io::Result<usize> {
        let stream = self
            .clients
            .get_mut(&client_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Client ID not connected"))?;
        let n = stream.write_all(data)?;
        if let Some(info) = self.client_info.get_mut(&client_id) {
            info.bytes_sent += n;
        }
        Ok(n)
    }

    /// Disconnect and remove a client by ID.
    pub fn disconnect(&mut self, client_id: usize) -> bool {
        if let Some(mut stream) = self.clients.remove(&client_id) {
            stream.close();
            self.client_info.remove(&client_id);
            true
        } else {
            false
        }
    }

    /// Get connection info for a client.
    pub fn get_info(&self, client_id: usize) -> Option<&ConnectionInfo> {
        self.client_info.get(&client_id)
    }

    /// Stop server, closing all client connections and listener.
    pub fn stop(&mut self) {
        self.is_running = false;
        for (_, mut stream) in self.clients.drain() {
            stream.close();
        }
        self.client_info.clear();
        self.listener.close();
    }
}

/// WebSocket Opcode enumeration per RFC 6455.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsOpcode {
    Continuation = 0x0,
    Text = 0x1,
    Binary = 0x2,
    Close = 0x8,
    Ping = 0x9,
    Pong = 0xA,
}

impl WsOpcode {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x0 => Some(Self::Continuation),
            0x1 => Some(Self::Text),
            0x2 => Some(Self::Binary),
            0x8 => Some(Self::Close),
            0x9 => Some(Self::Ping),
            0xA => Some(Self::Pong),
            _ => None,
        }
    }
}

/// A parsed or serialized WebSocket frame (RFC 6455).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsFrame {
    pub fin: bool,
    pub opcode: WsOpcode,
    pub is_masked: bool,
    pub mask_key: Option<[u8; 4]>,
    pub payload: Vec<u8>,
}

impl WsFrame {
    pub fn text(payload: &str, is_masked: bool, mask_key: Option<[u8; 4]>) -> Self {
        Self {
            fin: true,
            opcode: WsOpcode::Text,
            is_masked,
            mask_key,
            payload: payload.as_bytes().to_vec(),
        }
    }

    pub fn binary(payload: Vec<u8>, is_masked: bool, mask_key: Option<[u8; 4]>) -> Self {
        Self {
            fin: true,
            opcode: WsOpcode::Binary,
            is_masked,
            mask_key,
            payload,
        }
    }

    pub fn ping(payload: Vec<u8>, is_masked: bool, mask_key: Option<[u8; 4]>) -> Self {
        Self {
            fin: true,
            opcode: WsOpcode::Ping,
            is_masked,
            mask_key,
            payload,
        }
    }

    pub fn pong(payload: Vec<u8>, is_masked: bool, mask_key: Option<[u8; 4]>) -> Self {
        Self {
            fin: true,
            opcode: WsOpcode::Pong,
            is_masked,
            mask_key,
            payload,
        }
    }

    pub fn close(code: u16, reason: &str, is_masked: bool, mask_key: Option<[u8; 4]>) -> Self {
        let mut payload = code.to_be_bytes().to_vec();
        payload.extend_from_slice(reason.as_bytes());
        Self {
            fin: true,
            opcode: WsOpcode::Close,
            is_masked,
            mask_key,
            payload,
        }
    }

    /// Encode frame to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut wire = Vec::new();
        let b0 = (if self.fin { 0x80 } else { 0 }) | (self.opcode as u8 & 0x0F);
        wire.push(b0);

        let len = self.payload.len();
        let mask_bit = if self.is_masked { 0x80 } else { 0 };

        if len < 126 {
            wire.push(mask_bit | (len as u8));
        } else if len <= 65535 {
            wire.push(mask_bit | 126);
            wire.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            wire.push(mask_bit | 127);
            wire.extend_from_slice(&(len as u64).to_be_bytes());
        }

        if self.is_masked {
            let key = self.mask_key.unwrap_or([0x37, 0xfa, 0x21, 0x3d]);
            wire.extend_from_slice(&key);
            for (i, byte) in self.payload.iter().enumerate() {
                wire.push(byte ^ key[i % 4]);
            }
        } else {
            wire.extend_from_slice(&self.payload);
        }

        wire
    }

    /// Decode one frame from raw slice, returning (frame, bytes_consumed) if available.
    pub fn decode(raw: &[u8]) -> Option<(Self, usize)> {
        if raw.len() < 2 {
            return None;
        }

        let b0 = raw[0];
        let b1 = raw[1];

        let fin = (b0 & 0x80) != 0;
        let opcode = WsOpcode::from_u8(b0 & 0x0F)?;
        let is_masked = (b1 & 0x80) != 0;
        let raw_len = (b1 & 0x7F) as usize;

        let mut cursor = 2;
        let payload_len = if raw_len == 126 {
            if raw.len() < cursor + 2 {
                return None;
            }
            let len = u16::from_be_bytes([raw[cursor], raw[cursor + 1]]) as usize;
            cursor += 2;
            len
        } else if raw_len == 127 {
            if raw.len() < cursor + 8 {
                return None;
            }
            let len = u64::from_be_bytes(raw[cursor..cursor + 8].try_into().ok()?) as usize;
            cursor += 8;
            len
        } else {
            raw_len
        };

        let mask_key = if is_masked {
            if raw.len() < cursor + 4 {
                return None;
            }
            let key: [u8; 4] = raw[cursor..cursor + 4].try_into().ok()?;
            cursor += 4;
            Some(key)
        } else {
            None
        };

        if raw.len() < cursor + payload_len {
            return None;
        }

        let raw_payload = &raw[cursor..cursor + payload_len];
        let payload = if let Some(key) = mask_key {
            raw_payload
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ key[i % 4])
                .collect()
        } else {
            raw_payload.to_vec()
        };

        let total_consumed = cursor + payload_len;
        Some((
            Self {
                fin,
                opcode,
                is_masked,
                mask_key,
                payload,
            },
            total_consumed,
        ))
    }
}

/// Active WebSocket session on top of a non-blocking TCP Stream.
pub struct WsSession {
    pub id: usize,
    pub stream: TcpStream,
    pub is_upgraded: bool,
    buffer: Vec<u8>,
}

impl WsSession {
    pub fn new(id: usize, stream: TcpStream) -> Self {
        Self {
            id,
            stream,
            is_upgraded: false,
            buffer: Vec::new(),
        }
    }

    /// Try to read HTTP upgrade request and complete WebSocket handshake.
    pub fn try_handshake(&mut self) -> io::Result<bool> {
        if self.is_upgraded {
            return Ok(true);
        }

        let mut chunk = [0u8; 1024];
        match self.stream.read(&mut chunk) {
            Ok(n) if n > 0 => {
                self.buffer.extend_from_slice(&chunk[..n]);
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }

        let text = String::from_utf8_lossy(&self.buffer);
        if let Some(header_end) = text.find("\r\n\r\n") {
            let header_part = &text[..header_end];
            let mut key: Option<String> = None;
            for line in header_part.lines() {
                if line.to_ascii_lowercase().starts_with("sec-websocket-key:") {
                    // find original line slice to preserve case-sensitive key
                    let orig_idx = line.find(':').unwrap() + 1;
                    key = Some(line[orig_idx..].trim().to_string());
                }
            }

            if let Some(k) = key {
                let accept = crate::crypto::websocket_accept_key(&k);
                let response = format!(
                    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
                    accept
                );
                self.stream.write_all(response.as_bytes())?;
                self.is_upgraded = true;
                // keep any trailing frame bytes
                self.buffer = self.buffer[header_end + 4..].to_vec();
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Send a text message to this session (unmasked from server per RFC 6455).
    pub fn send_text(&mut self, text: &str) -> io::Result<()> {
        let frame = WsFrame::text(text, false, None);
        self.stream.write_all(&frame.encode())?;
        Ok(())
    }

    /// Poll incoming WebSocket text messages, responding automatically to ping and handling close frames.
    pub fn poll_text_messages(&mut self) -> io::Result<Vec<String>> {
        if !self.is_upgraded {
            return Ok(Vec::new());
        }

        let mut chunk = [0u8; 2048];
        match self.stream.read(&mut chunk) {
            Ok(n) if n > 0 => {
                self.buffer.extend_from_slice(&chunk[..n]);
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }

        let mut messages = Vec::new();
        while let Some((frame, consumed)) = WsFrame::decode(&self.buffer) {
            self.buffer.drain(..consumed);
            match frame.opcode {
                WsOpcode::Text => {
                    if let Ok(msg) = String::from_utf8(frame.payload) {
                        messages.push(msg);
                    }
                }
                WsOpcode::Ping => {
                    let pong = WsFrame::pong(frame.payload, false, None);
                    let _ = self.stream.write_all(&pong.encode());
                }
                WsOpcode::Close => {
                    self.stream.close();
                    break;
                }
                _ => {}
            }
        }

        Ok(messages)
    }

    /// Close session.
    pub fn close(&mut self) {
        let frame = WsFrame::close(1000, "Normal Closure", false, None);
        let _ = self.stream.write_all(&frame.encode());
        self.stream.close();
    }
}

/// Multi-client WebSocket Server (RFC 6455) multiplexed on non-blocking TCP sockets.
pub struct WsServer {
    tcp_server: TcpServer,
    sessions: HashMap<usize, WsSession>,
}

impl WsServer {
    /// Bind server to local address.
    pub fn bind<A: ToSocketAddrs>(addr: A, max_clients: usize) -> io::Result<Self> {
        let tcp_server = TcpServer::bind(addr, max_clients)?;
        Ok(Self {
            tcp_server,
            sessions: HashMap::new(),
        })
    }

    /// Bound port of the server.
    pub fn port(&self) -> io::Result<u16> {
        self.tcp_server.port()
    }

    /// Number of active WebSocket sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Accept pending incoming connections and advance handshakes.
    pub fn accept_and_upgrade(&mut self) -> io::Result<usize> {
        let _ = self.tcp_server.accept_pending()?;
        // Transfer raw clients to sessions
        let mut new_streams = Vec::new();
        for (id, stream) in self.tcp_server.clients.drain() {
            new_streams.push((id, stream));
        }
        for (id, stream) in new_streams {
            self.sessions.insert(id, WsSession::new(id, stream));
        }

        let mut upgraded_count = 0;
        let mut dead_sessions = Vec::new();
        for (id, session) in self.sessions.iter_mut() {
            match session.try_handshake() {
                Ok(true) => upgraded_count += 1,
                Ok(false) => {}
                Err(_) => dead_sessions.push(*id),
            }
        }

        for id in dead_sessions {
            self.sessions.remove(&id);
        }

        Ok(upgraded_count)
    }

    /// Broadcast text message to all upgraded sessions.
    pub fn broadcast_text(&mut self, text: &str) -> usize {
        let mut delivered = 0;
        let mut dead = Vec::new();
        for (id, session) in self.sessions.iter_mut() {
            if session.is_upgraded {
                if session.send_text(text).is_ok() {
                    delivered += 1;
                } else {
                    dead.push(*id);
                }
            }
        }
        for id in dead {
            self.sessions.remove(&id);
        }
        delivered
    }

    /// Send text to a specific session id.
    pub fn send_to(&mut self, session_id: usize, text: &str) -> io::Result<()> {
        if let Some(session) = self.sessions.get_mut(&session_id) {
            session.send_text(text)
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "WebSocket session not found",
            ))
        }
    }

    /// Poll incoming text messages across all active sessions. Returns (session_id, message).
    pub fn poll_all_messages(&mut self) -> Vec<(usize, String)> {
        let mut all_msgs = Vec::new();
        let mut dead = Vec::new();
        for (id, session) in self.sessions.iter_mut() {
            match session.poll_text_messages() {
                Ok(msgs) => {
                    for m in msgs {
                        all_msgs.push((*id, m));
                    }
                }
                Err(_) => dead.push(*id),
            }
        }
        for id in dead {
            self.sessions.remove(&id);
        }
        all_msgs
    }

    /// Disconnect a session.
    pub fn disconnect(&mut self, session_id: usize) {
        if let Some(mut session) = self.sessions.remove(&session_id) {
            session.close();
        }
    }

    /// Stop server and close all sessions.
    pub fn stop(&mut self) {
        for (_, mut session) in self.sessions.drain() {
            session.close();
        }
        self.tcp_server.stop();
    }
}

/// WebSocket Client (RFC 6455) with client-side masking.
pub struct WsClient {
    stream: TcpStream,
    buffer: Vec<u8>,
    is_upgraded: bool,
    expected_accept: String,
}

impl WsClient {
    /// Initiate a non-blocking connection to a WebSocket server and send HTTP upgrade request.
    pub fn connect(host: &str, port: u16, path: &str) -> io::Result<Self> {
        let mut stream = TcpStream::connect(format!("{}:{}", host, port))?;
        let client_key = "dGhlIHNhbXBsZSBub25jZQ==";
        let expected_accept = crate::crypto::websocket_accept_key(client_key);

        let handshake_req = format!(
            "GET {} HTTP/1.1\r\nHost: {}:{}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\n\r\n",
            path, host, port, client_key
        );

        stream.write_all(handshake_req.as_bytes())?;

        Ok(Self {
            stream,
            buffer: Vec::new(),
            is_upgraded: false,
            expected_accept,
        })
    }

    /// Check if the handshake is complete.
    pub fn is_upgraded(&self) -> bool {
        self.is_upgraded
    }

    /// Poll incoming server response for the 101 Switching Protocols handshake.
    pub fn poll_handshake(&mut self) -> io::Result<bool> {
        if self.is_upgraded {
            return Ok(true);
        }

        let mut chunk = [0u8; 1024];
        match self.stream.read(&mut chunk) {
            Ok(n) if n > 0 => {
                self.buffer.extend_from_slice(&chunk[..n]);
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }

        let resp = String::from_utf8_lossy(&self.buffer);
        if resp.contains("101 Switching Protocols") && resp.contains(&self.expected_accept) {
            if let Some(idx) = resp.find("\r\n\r\n") {
                self.buffer = self.buffer[idx + 4..].to_vec();
                self.is_upgraded = true;
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Send text message (masked per RFC 6455 requirement for clients).
    pub fn send_text(&mut self, text: &str) -> io::Result<()> {
        let frame = WsFrame::text(text, true, Some([0x12, 0x34, 0x56, 0x78]));
        self.stream.write_all(&frame.encode())?;
        Ok(())
    }

    /// Poll incoming text message from server.
    pub fn poll_text_message(&mut self) -> io::Result<Option<String>> {
        let mut chunk = [0u8; 1024];
        if let Ok(n) = self.stream.read(&mut chunk) {
            if n > 0 {
                self.buffer.extend_from_slice(&chunk[..n]);
            }
        }

        if let Some((frame, consumed)) = WsFrame::decode(&self.buffer) {
            self.buffer.drain(..consumed);
            if frame.opcode == WsOpcode::Text {
                return Ok(String::from_utf8(frame.payload).ok());
            }
        }

        Ok(None)
    }

    /// Close client connection.
    pub fn close(&mut self) {
        let frame = WsFrame::close(1000, "Normal Closure", true, Some([0xAA, 0xBB, 0xCC, 0xDD]));
        let _ = self.stream.write_all(&frame.encode());
        self.stream.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonblocking_tcp_server_and_multiple_clients() {
        let mut server = TcpServer::bind("127.0.0.1:0", 10).expect("bind server");
        let port = server.port().expect("port");
        assert_eq!(server.client_count(), 0);

        // Connect client 1
        let mut c1 = TcpStream::connect(format!("127.0.0.1:{}", port)).expect("connect c1");
        // Connect client 2
        let mut c2 = TcpStream::connect(format!("127.0.0.1:{}", port)).expect("connect c2");

        // Accept pending connections
        let accepted = server.accept_pending().expect("accept pending");
        assert_eq!(accepted, 2);
        assert_eq!(server.client_count(), 2);

        // Server broadcasts message to all clients
        let delivered = server.broadcast(b"IFA_SERVER_BROADCAST_OK");
        assert_eq!(delivered, 2);

        // Give sockets a tiny slice for wire propagation
        std::thread::sleep(Duration::from_millis(50));

        // Clients read broadcast message
        let mut b1 = [0u8; 64];
        let n1 = c1.read(&mut b1).expect("c1 read");
        assert_eq!(&b1[..n1], b"IFA_SERVER_BROADCAST_OK");

        let mut b2 = [0u8; 64];
        let n2 = c2.read(&mut b2).expect("c2 read");
        assert_eq!(&b2[..n2], b"IFA_SERVER_BROADCAST_OK");

        // Clients reply
        c1.write_all(b"MSG_FROM_C1").expect("c1 write");
        c2.write_all(b"MSG_FROM_C2").expect("c2 write");

        std::thread::sleep(Duration::from_millis(50));

        let msgs = server.poll_readable();
        assert_eq!(msgs.len(), 2);
        let payloads: Vec<String> = msgs
            .into_iter()
            .map(|(_, bytes)| String::from_utf8_lossy(&bytes).into_owned())
            .collect();
        assert!(payloads.contains(&"MSG_FROM_C1".to_string()));
        assert!(payloads.contains(&"MSG_FROM_C2".to_string()));

        // Disconnect one client
        assert!(server.disconnect(1));
        assert_eq!(server.client_count(), 1);

        server.stop();
        c1.close();
        c2.close();
    }

    #[test]
    fn test_websocket_framing_encode_decode() {
        let frame = WsFrame::text("Hello IFA WebSocket RFC 6455", false, None);
        let wire = frame.encode();
        let (decoded, consumed) = WsFrame::decode(&wire).expect("decode unmasked");
        assert_eq!(consumed, wire.len());
        assert_eq!(decoded.opcode, WsOpcode::Text);
        assert!(!decoded.is_masked);
        assert_eq!(
            String::from_utf8(decoded.payload).unwrap(),
            "Hello IFA WebSocket RFC 6455"
        );

        // Masked frame
        let masked_frame =
            WsFrame::text("Masked Payload Test", true, Some([0xde, 0xad, 0xbe, 0xef]));
        let masked_wire = masked_frame.encode();
        let (decoded_masked, consumed_m) = WsFrame::decode(&masked_wire).expect("decode masked");
        assert_eq!(consumed_m, masked_wire.len());
        assert_eq!(decoded_masked.opcode, WsOpcode::Text);
        assert!(decoded_masked.is_masked);
        assert_eq!(
            String::from_utf8(decoded_masked.payload).unwrap(),
            "Masked Payload Test"
        );
    }

    #[test]
    fn test_websocket_server_and_client_roundtrip() {
        let mut server = WsServer::bind("127.0.0.1:0", 5).expect("bind ws server");
        let port = server.port().expect("port");

        // Connect client 1 and client 2 non-blockingly
        let mut client1 = WsClient::connect("127.0.0.1", port, "/chat").expect("connect client 1");
        let mut client2 = WsClient::connect("127.0.0.1", port, "/chat").expect("connect client 2");

        std::thread::sleep(Duration::from_millis(50));

        // Accept and upgrade handshake on server
        let upgraded = server.accept_and_upgrade().expect("accept and upgrade");
        assert_eq!(upgraded, 2);
        assert_eq!(server.session_count(), 2);

        // Advance client handshake polling
        std::thread::sleep(Duration::from_millis(50));
        assert!(client1.poll_handshake().expect("c1 handshake"));
        assert!(client2.poll_handshake().expect("c2 handshake"));
        assert!(client1.is_upgraded());
        assert!(client2.is_upgraded());

        // Server broadcasts to both clients
        let delivered = server.broadcast_text("BROADCAST_TO_ALL_WS_CLIENTS");
        assert_eq!(delivered, 2);

        std::thread::sleep(Duration::from_millis(50));

        let msg1 = client1.poll_text_message().expect("c1 poll");
        assert_eq!(msg1.as_deref(), Some("BROADCAST_TO_ALL_WS_CLIENTS"));

        let msg2 = client2.poll_text_message().expect("c2 poll");
        assert_eq!(msg2.as_deref(), Some("BROADCAST_TO_ALL_WS_CLIENTS"));

        // Clients send masked text messages to server
        client1.send_text("CLIENT_1_HELLO").expect("c1 send");
        client2.send_text("CLIENT_2_HELLO").expect("c2 send");

        std::thread::sleep(Duration::from_millis(50));

        let received = server.poll_all_messages();
        assert_eq!(received.len(), 2);
        let payloads: Vec<String> = received.into_iter().map(|(_, m)| m).collect();
        assert!(payloads.contains(&"CLIENT_1_HELLO".to_string()));
        assert!(payloads.contains(&"CLIENT_2_HELLO".to_string()));

        client1.close();
        client2.close();
        server.stop();
    }
}

//! Non-blocking networking, TCP stream management, and multi-connection server (`std::net`).

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{
    SocketAddr, TcpListener as StdTcpListener, TcpStream as StdTcpStream, ToSocketAddrs,
};
use std::time::Duration;

use ifa_runtime::fiber::GLOBAL_SCHEDULER;
use ifa_runtime::reactor::AsyncTcpStream;

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

    pub fn continuation(
        payload: Vec<u8>,
        fin: bool,
        is_masked: bool,
        mask_key: Option<[u8; 4]>,
    ) -> Self {
        Self {
            fin,
            opcode: WsOpcode::Continuation,
            is_masked,
            mask_key,
            payload,
        }
    }

    /// Extract close status code from payload if this is a Close frame.
    pub fn close_code(&self) -> Option<u16> {
        if self.opcode == WsOpcode::Close && self.payload.len() >= 2 {
            Some(u16::from_be_bytes([self.payload[0], self.payload[1]]))
        } else {
            None
        }
    }

    /// Extract close reason string from payload if this is a Close frame.
    pub fn close_reason(&self) -> Option<&str> {
        if self.opcode == WsOpcode::Close && self.payload.len() > 2 {
            std::str::from_utf8(&self.payload[2..]).ok()
        } else {
            None
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

/// High-level WebSocket message demultiplexed and reassembled from RFC 6455 data/control frames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsMessage {
    /// Complete UTF-8 text message.
    Text(String),
    /// Complete arbitrary binary payload message.
    Binary(Vec<u8>),
    /// Ping control frame containing heartbeat payload.
    Ping(Vec<u8>),
    /// Pong control frame answering a ping or unsolicited.
    Pong(Vec<u8>),
    /// Close control frame with optional status code and reason string.
    Close(Option<u16>, String),
}

impl WsMessage {
    pub fn text(s: impl Into<String>) -> Self {
        Self::Text(s.into())
    }

    pub fn binary(data: impl Into<Vec<u8>>) -> Self {
        Self::Binary(data.into())
    }

    pub fn ping(payload: impl Into<Vec<u8>>) -> Self {
        Self::Ping(payload.into())
    }

    pub fn pong(payload: impl Into<Vec<u8>>) -> Self {
        Self::Pong(payload.into())
    }

    pub fn close(code: Option<u16>, reason: impl Into<String>) -> Self {
        Self::Close(code, reason.into())
    }

    pub fn to_frame(&self, is_masked: bool, mask_key: Option<[u8; 4]>) -> WsFrame {
        match self {
            Self::Text(t) => WsFrame::text(t, is_masked, mask_key),
            Self::Binary(b) => WsFrame::binary(b.clone(), is_masked, mask_key),
            Self::Ping(p) => WsFrame::ping(p.clone(), is_masked, mask_key),
            Self::Pong(p) => WsFrame::pong(p.clone(), is_masked, mask_key),
            Self::Close(code, reason) => {
                WsFrame::close(code.unwrap_or(1000), reason, is_masked, mask_key)
            }
        }
    }
}

/// Streaming RFC 6455 frame demultiplexer and fragmented message reassembler.
#[derive(Debug, Default, Clone)]
pub struct WsDemux {
    pub buffer: Vec<u8>,
    fragment_opcode: Option<WsOpcode>,
    fragment_payload: Vec<u8>,
}

impl WsDemux {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append incoming TCP wire bytes to demux buffer.
    pub fn push_bytes(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// Current unconsumed wire bytes in buffer.
    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }

    /// Drain and decode next complete raw frame from buffer, if available.
    pub fn poll_frame(&mut self) -> Option<WsFrame> {
        if let Some((frame, consumed)) = WsFrame::decode(&self.buffer) {
            self.buffer.drain(..consumed);
            Some(frame)
        } else {
            None
        }
    }

    /// Decode all currently complete raw frames from buffer.
    pub fn poll_all_frames(&mut self) -> Vec<WsFrame> {
        let mut frames = Vec::new();
        while let Some(frame) = self.poll_frame() {
            frames.push(frame);
        }
        frames
    }

    /// Demultiplex and reassemble the next complete `WsMessage`.
    /// Control frames (Ping, Pong, Close) are emitted immediately even if interleaved
    /// between fragmented data frames per RFC 6455 §5.4.
    pub fn poll_message(&mut self) -> io::Result<Option<WsMessage>> {
        while let Some(frame) = self.poll_frame() {
            match frame.opcode {
                WsOpcode::Ping => {
                    return Ok(Some(WsMessage::Ping(frame.payload)));
                }
                WsOpcode::Pong => {
                    return Ok(Some(WsMessage::Pong(frame.payload)));
                }
                WsOpcode::Close => {
                    let code = frame.close_code();
                    let reason = frame.close_reason().unwrap_or("").to_string();
                    return Ok(Some(WsMessage::Close(code, reason)));
                }
                WsOpcode::Text | WsOpcode::Binary => {
                    if frame.fin {
                        if frame.opcode == WsOpcode::Text {
                            let text = String::from_utf8(frame.payload).map_err(|e| {
                                io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    format!("Invalid UTF-8 in WebSocket text frame: {}", e),
                                )
                            })?;
                            return Ok(Some(WsMessage::Text(text)));
                        } else {
                            return Ok(Some(WsMessage::Binary(frame.payload)));
                        }
                    } else {
                        // First fragment of a fragmented message
                        self.fragment_opcode = Some(frame.opcode);
                        self.fragment_payload = frame.payload;
                    }
                }
                WsOpcode::Continuation => {
                    if let Some(initial_op) = self.fragment_opcode {
                        self.fragment_payload.extend_from_slice(&frame.payload);
                        if frame.fin {
                            self.fragment_opcode = None;
                            let full_payload = std::mem::take(&mut self.fragment_payload);
                            if initial_op == WsOpcode::Text {
                                let text = String::from_utf8(full_payload).map_err(|e| {
                                    io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        format!(
                                            "Invalid UTF-8 in fragmented WebSocket text message: {}",
                                            e
                                        ),
                                    )
                                })?;
                                return Ok(Some(WsMessage::Text(text)));
                            } else {
                                return Ok(Some(WsMessage::Binary(full_payload)));
                            }
                        }
                    } else {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Received unexpected WebSocket continuation frame without initial fragment",
                        ));
                    }
                }
            }
        }
        Ok(None)
    }
}

/// Active WebSocket session on top of a non-blocking TCP Stream.
pub struct WsSession {
    pub id: usize,
    pub stream: TcpStream,
    pub is_upgraded: bool,
    demux: WsDemux,
}

impl WsSession {
    pub fn new(id: usize, stream: TcpStream) -> Self {
        Self {
            id,
            stream,
            is_upgraded: false,
            demux: WsDemux::new(),
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
                self.demux.push_bytes(&chunk[..n]);
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }

        let text = String::from_utf8_lossy(&self.demux.buffer);
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
                // keep any trailing frame bytes in demux buffer
                self.demux.buffer.drain(..header_end + 4);
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

    /// Send binary data to this session (unmasked from server per RFC 6455).
    pub fn send_binary(&mut self, data: &[u8]) -> io::Result<()> {
        let frame = WsFrame::binary(data.to_vec(), false, None);
        self.stream.write_all(&frame.encode())?;
        Ok(())
    }

    /// Send a Ping frame to this session.
    pub fn send_ping(&mut self, payload: &[u8]) -> io::Result<()> {
        let frame = WsFrame::ping(payload.to_vec(), false, None);
        self.stream.write_all(&frame.encode())?;
        Ok(())
    }

    /// Send a Pong frame to this session.
    pub fn send_pong(&mut self, payload: &[u8]) -> io::Result<()> {
        let frame = WsFrame::pong(payload.to_vec(), false, None);
        self.stream.write_all(&frame.encode())?;
        Ok(())
    }

    /// Send a Close frame to this session.
    pub fn send_close(&mut self, code: u16, reason: &str) -> io::Result<()> {
        let frame = WsFrame::close(code, reason, false, None);
        let _ = self.stream.write_all(&frame.encode());
        self.stream.close();
        Ok(())
    }

    /// Send a fragmented text message.
    pub fn send_fragmented_text(&mut self, chunks: &[&str]) -> io::Result<()> {
        if chunks.is_empty() {
            return self.send_text("");
        }
        for (i, chunk) in chunks.iter().enumerate() {
            let is_first = i == 0;
            let is_last = i == chunks.len() - 1;
            let opcode = if is_first {
                WsOpcode::Text
            } else {
                WsOpcode::Continuation
            };
            let frame = WsFrame {
                fin: is_last,
                opcode,
                is_masked: false,
                mask_key: None,
                payload: chunk.as_bytes().to_vec(),
            };
            self.stream.write_all(&frame.encode())?;
        }
        Ok(())
    }

    /// Send a fragmented binary message.
    pub fn send_fragmented_binary(&mut self, chunks: &[&[u8]]) -> io::Result<()> {
        if chunks.is_empty() {
            return self.send_binary(&[]);
        }
        for (i, chunk) in chunks.iter().enumerate() {
            let is_first = i == 0;
            let is_last = i == chunks.len() - 1;
            let opcode = if is_first {
                WsOpcode::Binary
            } else {
                WsOpcode::Continuation
            };
            let frame = WsFrame {
                fin: is_last,
                opcode,
                is_masked: false,
                mask_key: None,
                payload: chunk.to_vec(),
            };
            self.stream.write_all(&frame.encode())?;
        }
        Ok(())
    }

    /// Poll incoming WebSocket messages (Text, Binary, Ping, Pong, Close) with automatic ping/pong handling.
    pub fn poll_messages(&mut self) -> io::Result<Vec<WsMessage>> {
        if !self.is_upgraded {
            return Ok(Vec::new());
        }

        let mut chunk = [0u8; 4096];
        match self.stream.read(&mut chunk) {
            Ok(n) if n > 0 => {
                self.demux.push_bytes(&chunk[..n]);
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }

        let mut messages = Vec::new();
        while let Some(msg) = self.demux.poll_message()? {
            match &msg {
                WsMessage::Ping(payload) => {
                    let pong = WsFrame::pong(payload.clone(), false, None);
                    let _ = self.stream.write_all(&pong.encode());
                }
                WsMessage::Close(code, reason) => {
                    let reply = WsFrame::close(code.unwrap_or(1000), reason, false, None);
                    let _ = self.stream.write_all(&reply.encode());
                    self.stream.close();
                    messages.push(msg);
                    break;
                }
                _ => messages.push(msg),
            }
        }

        Ok(messages)
    }

    /// Poll incoming WebSocket text messages, responding automatically to ping and handling close frames.
    pub fn poll_text_messages(&mut self) -> io::Result<Vec<String>> {
        let msgs = self.poll_messages()?;
        let mut text_msgs = Vec::new();
        for m in msgs {
            if let WsMessage::Text(t) = m {
                text_msgs.push(t);
            }
        }
        Ok(text_msgs)
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

    /// Broadcast binary data to all upgraded sessions.
    pub fn broadcast_binary(&mut self, data: &[u8]) -> usize {
        let mut delivered = 0;
        let mut dead = Vec::new();
        for (id, session) in self.sessions.iter_mut() {
            if session.is_upgraded {
                if session.send_binary(data).is_ok() {
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

    /// Send binary data to a specific session id.
    pub fn send_binary_to(&mut self, session_id: usize, data: &[u8]) -> io::Result<()> {
        if let Some(session) = self.sessions.get_mut(&session_id) {
            session.send_binary(data)
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

    /// Poll all incoming events (Text, Binary, Close) across all active sessions.
    pub fn poll_all_events(&mut self) -> Vec<(usize, WsMessage)> {
        let mut all_events = Vec::new();
        let mut dead = Vec::new();
        for (id, session) in self.sessions.iter_mut() {
            match session.poll_messages() {
                Ok(msgs) => {
                    for m in msgs {
                        all_events.push((*id, m));
                    }
                }
                Err(_) => dead.push(*id),
            }
        }
        for id in dead {
            self.sessions.remove(&id);
        }
        all_events
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

    /// Send binary data (masked per RFC 6455 requirement for clients).
    pub fn send_binary(&mut self, data: &[u8]) -> io::Result<()> {
        let frame = WsFrame::binary(data.to_vec(), true, Some([0x12, 0x34, 0x56, 0x78]));
        self.stream.write_all(&frame.encode())?;
        Ok(())
    }

    /// Send Ping control frame (masked per RFC 6455 requirement for clients).
    pub fn send_ping(&mut self, payload: &[u8]) -> io::Result<()> {
        let frame = WsFrame::ping(payload.to_vec(), true, Some([0x12, 0x34, 0x56, 0x78]));
        self.stream.write_all(&frame.encode())?;
        Ok(())
    }

    /// Send Pong control frame (masked per RFC 6455 requirement for clients).
    pub fn send_pong(&mut self, payload: &[u8]) -> io::Result<()> {
        let frame = WsFrame::pong(payload.to_vec(), true, Some([0x12, 0x34, 0x56, 0x78]));
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

    /// Poll incoming WebSocket message (Text, Binary, Ping, Pong, Close) from server.
    pub fn poll_ws_message(&mut self) -> io::Result<Option<WsMessage>> {
        let mut chunk = [0u8; 2048];
        if let Ok(n) = self.stream.read(&mut chunk) {
            if n > 0 {
                self.buffer.extend_from_slice(&chunk[..n]);
            }
        }

        if let Some((frame, consumed)) = WsFrame::decode(&self.buffer) {
            self.buffer.drain(..consumed);
            match frame.opcode {
                WsOpcode::Text => {
                    let text = String::from_utf8(frame.payload).map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("Invalid UTF-8 in WebSocket text frame: {}", e),
                        )
                    })?;
                    return Ok(Some(WsMessage::Text(text)));
                }
                WsOpcode::Binary => return Ok(Some(WsMessage::Binary(frame.payload))),
                WsOpcode::Ping => return Ok(Some(WsMessage::Ping(frame.payload))),
                WsOpcode::Pong => return Ok(Some(WsMessage::Pong(frame.payload))),
                WsOpcode::Close => {
                    let code = frame.close_code();
                    let reason = frame.close_reason().unwrap_or("").to_string();
                    return Ok(Some(WsMessage::Close(code, reason)));
                }
                _ => {}
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

/// Asynchronous WebSocket connection running over an `AsyncTcpStream` in colorless fibers.
pub struct AsyncWsConnection {
    pub stream: AsyncTcpStream,
    demux: WsDemux,
    is_client: bool,
    is_closed: bool,
}

impl AsyncWsConnection {
    /// Create a new async WebSocket connection wrapping an async TCP stream.
    pub fn new(stream: AsyncTcpStream, is_client: bool) -> Self {
        Self {
            stream,
            demux: WsDemux::new(),
            is_client,
            is_closed: false,
        }
    }

    /// Whether this connection has been closed.
    pub fn is_closed(&self) -> bool {
        self.is_closed
    }

    /// Send a complete RFC 6455 WebSocket frame over the async TCP stream.
    pub fn send_frame(&mut self, frame: &WsFrame) -> io::Result<()> {
        if self.is_closed {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "WebSocket connection is closed",
            ));
        }
        let wire = frame.encode();
        self.stream.write_all(&wire)
    }

    /// Send a UTF-8 text message.
    pub fn send_text(&mut self, text: &str) -> io::Result<()> {
        let frame = if self.is_client {
            WsFrame::text(text, true, Some([0x12, 0x34, 0x56, 0x78]))
        } else {
            WsFrame::text(text, false, None)
        };
        self.send_frame(&frame)
    }

    /// Send arbitrary binary payload.
    pub fn send_binary(&mut self, data: &[u8]) -> io::Result<()> {
        let frame = if self.is_client {
            WsFrame::binary(data.to_vec(), true, Some([0x12, 0x34, 0x56, 0x78]))
        } else {
            WsFrame::binary(data.to_vec(), false, None)
        };
        self.send_frame(&frame)
    }

    /// Send a Ping control frame.
    pub fn send_ping(&mut self, payload: &[u8]) -> io::Result<()> {
        let frame = if self.is_client {
            WsFrame::ping(payload.to_vec(), true, Some([0x12, 0x34, 0x56, 0x78]))
        } else {
            WsFrame::ping(payload.to_vec(), false, None)
        };
        self.send_frame(&frame)
    }

    /// Send a Pong control frame.
    pub fn send_pong(&mut self, payload: &[u8]) -> io::Result<()> {
        let frame = if self.is_client {
            WsFrame::pong(payload.to_vec(), true, Some([0x12, 0x34, 0x56, 0x78]))
        } else {
            WsFrame::pong(payload.to_vec(), false, None)
        };
        self.send_frame(&frame)
    }

    /// Send a Close control frame and mark connection closed.
    pub fn send_close(&mut self, code: u16, reason: &str) -> io::Result<()> {
        let frame = if self.is_client {
            WsFrame::close(code, reason, true, Some([0x12, 0x34, 0x56, 0x78]))
        } else {
            WsFrame::close(code, reason, false, None)
        };
        let res = self.send_frame(&frame);
        self.is_closed = true;
        res
    }

    /// Send a high-level `WsMessage`.
    pub fn send_message(&mut self, msg: &WsMessage) -> io::Result<()> {
        let mask = if self.is_client {
            Some([0x12, 0x34, 0x56, 0x78])
        } else {
            None
        };
        let frame = msg.to_frame(self.is_client, mask);
        self.send_frame(&frame)
    }

    /// Send a fragmented text message across multiple continuation frames.
    pub fn send_fragmented_text(&mut self, chunks: &[&str]) -> io::Result<()> {
        if chunks.is_empty() {
            return self.send_text("");
        }
        for (i, chunk) in chunks.iter().enumerate() {
            let is_first = i == 0;
            let is_last = i == chunks.len() - 1;
            let opcode = if is_first {
                WsOpcode::Text
            } else {
                WsOpcode::Continuation
            };
            let mask_key = if self.is_client {
                Some([0x12, 0x34, 0x56, 0x78])
            } else {
                None
            };
            let frame = WsFrame {
                fin: is_last,
                opcode,
                is_masked: self.is_client,
                mask_key,
                payload: chunk.as_bytes().to_vec(),
            };
            self.send_frame(&frame)?;
        }
        Ok(())
    }

    /// Send a fragmented binary message across multiple continuation frames.
    pub fn send_fragmented_binary(&mut self, chunks: &[&[u8]]) -> io::Result<()> {
        if chunks.is_empty() {
            return self.send_binary(&[]);
        }
        for (i, chunk) in chunks.iter().enumerate() {
            let is_first = i == 0;
            let is_last = i == chunks.len() - 1;
            let opcode = if is_first {
                WsOpcode::Binary
            } else {
                WsOpcode::Continuation
            };
            let mask_key = if self.is_client {
                Some([0x12, 0x34, 0x56, 0x78])
            } else {
                None
            };
            let frame = WsFrame {
                fin: is_last,
                opcode,
                is_masked: self.is_client,
                mask_key,
                payload: chunk.to_vec(),
            };
            self.send_frame(&frame)?;
        }
        Ok(())
    }

    /// Non-blocking check for incoming messages from the async TCP stream.
    /// Handles Ping frames automatically by replying with a Pong.
    pub fn try_recv_message(&mut self) -> io::Result<Option<WsMessage>> {
        let mut buf = [0u8; 4096];
        let mut eof = false;
        match self.stream.try_read(&mut buf) {
            Ok(Some(n)) if n > 0 => {
                self.demux.push_bytes(&buf[..n]);
            }
            Ok(Some(0)) => {
                eof = true;
            }
            Ok(Some(_)) | Ok(None) => {}
            Err(e) => return Err(e),
        }

        while let Some(msg) = self.demux.poll_message()? {
            match &msg {
                WsMessage::Ping(payload) => {
                    let _ = self.send_pong(payload);
                }
                WsMessage::Close(code, reason) => {
                    if !self.is_closed {
                        let _ = self.send_close(code.unwrap_or(1000), reason);
                    }
                    return Ok(Some(msg));
                }
                _ => return Ok(Some(msg)),
            }
        }

        if eof {
            self.is_closed = true;
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "WebSocket connection closed by peer",
            ));
        }

        Ok(None)
    }

    /// Receive the next `WsMessage` asynchronously, yielding the colorless fiber cooperatively.
    pub fn recv_message(&mut self) -> io::Result<WsMessage> {
        let mut spins = 0;
        loop {
            if let Some(msg) = self.try_recv_message()? {
                return Ok(msg);
            }
            if self.is_closed {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "WebSocket connection closed",
                ));
            }
            spins += 1;
            if spins < 16 {
                std::hint::spin_loop();
            } else {
                GLOBAL_SCHEDULER.yield_now();
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }
}

/// Token Bucket Rate Limiter for network request throttling and DoS mitigation.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    capacity: u64,
    tokens: u64,
    refill_rate_per_sec: u64,
    last_refill_timestamp: u64,
}

impl TokenBucket {
    /// Create a new TokenBucket with maximum burst capacity and refill rate in tokens per second.
    pub fn new(capacity: u64, refill_rate_per_sec: u64, now_sec: u64) -> Self {
        Self {
            capacity,
            tokens: capacity,
            refill_rate_per_sec,
            last_refill_timestamp: now_sec,
        }
    }

    /// Refill tokens based on elapsed seconds since last refill.
    pub fn refill(&mut self, now_sec: u64) {
        if now_sec > self.last_refill_timestamp {
            let elapsed = now_sec - self.last_refill_timestamp;
            let added = elapsed.saturating_mul(self.refill_rate_per_sec);
            self.tokens = (self.tokens + added).min(self.capacity);
            self.last_refill_timestamp = now_sec;
        }
    }

    /// Try to consume `count` tokens. Returns true if permitted, false if rate limited.
    pub fn try_consume(&mut self, count: u64, now_sec: u64) -> bool {
        self.refill(now_sec);
        if self.tokens >= count {
            self.tokens -= count;
            true
        } else {
            false
        }
    }

    /// Get current remaining available tokens.
    pub fn remaining(&self) -> u64 {
        self.tokens
    }

    /// Compute seconds until at least full capacity is reached or reset.
    pub fn seconds_until_reset(&self) -> u64 {
        if self.tokens >= self.capacity || self.refill_rate_per_sec == 0 {
            0
        } else {
            let needed = self.capacity - self.tokens;
            needed.div_ceil(self.refill_rate_per_sec)
        }
    }
}

/// MIME content type resolver for HTTP static file serving.
pub fn lookup_mime_type(extension: &str) -> &'static str {
    match extension.to_ascii_lowercase().as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "application/javascript",
        "json" => "application/json",
        "xml" => "application/xml",
        "txt" => "text/plain; charset=utf-8",
        "csv" => "text/csv; charset=utf-8",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "webp" => "image/webp",
        "wasm" => "application/wasm",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "tar" => "application/x-tar",
        "gz" => "application/gzip",
        _ => "application/octet-stream",
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

    #[test]
    fn test_websocket_binary_and_control_frames() {
        // Binary unmasked
        let bin_payload = vec![0x00, 0xFF, 0x42, 0x13, 0x37];
        let bin_frame = WsFrame::binary(bin_payload.clone(), false, None);
        let wire = bin_frame.encode();
        let (dec, consumed) = WsFrame::decode(&wire).expect("decode binary");
        assert_eq!(consumed, wire.len());
        assert_eq!(dec.opcode, WsOpcode::Binary);
        assert_eq!(dec.payload, bin_payload);

        // Binary masked
        let mask = [0x11, 0x22, 0x33, 0x44];
        let masked_bin = WsFrame::binary(bin_payload.clone(), true, Some(mask));
        let masked_wire = masked_bin.encode();
        let (dec_m, consumed_m) = WsFrame::decode(&masked_wire).expect("decode masked binary");
        assert_eq!(consumed_m, masked_wire.len());
        assert_eq!(dec_m.opcode, WsOpcode::Binary);
        assert!(dec_m.is_masked);
        assert_eq!(dec_m.payload, bin_payload);

        // Ping / Pong
        let ping = WsFrame::ping(b"heartbeat-seq-1".to_vec(), false, None);
        let ping_wire = ping.encode();
        let (dec_ping, _) = WsFrame::decode(&ping_wire).expect("decode ping");
        assert_eq!(dec_ping.opcode, WsOpcode::Ping);
        assert_eq!(dec_ping.payload, b"heartbeat-seq-1");

        let pong = WsFrame::pong(b"heartbeat-seq-1".to_vec(), false, None);
        let pong_wire = pong.encode();
        let (dec_pong, _) = WsFrame::decode(&pong_wire).expect("decode pong");
        assert_eq!(dec_pong.opcode, WsOpcode::Pong);
        assert_eq!(dec_pong.payload, b"heartbeat-seq-1");

        // Close frame code and reason extraction
        let close = WsFrame::close(1001, "Going Away", false, None);
        let close_wire = close.encode();
        let (dec_close, _) = WsFrame::decode(&close_wire).expect("decode close");
        assert_eq!(dec_close.opcode, WsOpcode::Close);
        assert_eq!(dec_close.close_code(), Some(1001));
        assert_eq!(dec_close.close_reason(), Some("Going Away"));
    }

    #[test]
    fn test_websocket_extended_payload_lengths() {
        // Medium payload: 126..=65535 bytes (16-bit extended length)
        let medium_payload = vec![0xAA; 1000];
        let medium_frame = WsFrame::binary(medium_payload.clone(), false, None);
        let wire = medium_frame.encode();
        assert_eq!(wire[1] & 0x7F, 126);
        let (dec, consumed) = WsFrame::decode(&wire).expect("decode medium");
        assert_eq!(consumed, wire.len());
        assert_eq!(dec.payload.len(), 1000);
        assert_eq!(dec.payload, medium_payload);

        // Masked medium payload
        let masked_medium =
            WsFrame::binary(medium_payload.clone(), true, Some([0x12, 0x34, 0x56, 0x78]));
        let masked_wire = masked_medium.encode();
        let (dec_m, consumed_m) = WsFrame::decode(&masked_wire).expect("decode masked medium");
        assert_eq!(consumed_m, masked_wire.len());
        assert_eq!(dec_m.payload, medium_payload);

        // Large payload: 70000 bytes (>65535 bytes, 64-bit extended length)
        let large_payload = vec![0x55; 70000];
        let large_frame = WsFrame::binary(large_payload.clone(), false, None);
        let large_wire = large_frame.encode();
        assert_eq!(large_wire[1] & 0x7F, 127);
        let (dec_l, consumed_l) = WsFrame::decode(&large_wire).expect("decode large");
        assert_eq!(consumed_l, large_wire.len());
        assert_eq!(dec_l.payload.len(), 70000);
        assert_eq!(dec_l.payload, large_payload);
    }

    #[test]
    fn test_websocket_demux_and_fragmentation_reassembly() {
        let mut demux = WsDemux::new();

        // 1. Unfragmented text message
        let f1 = WsFrame::text("Hello IFA Demux", false, None);
        demux.push_bytes(&f1.encode());
        let msg1 = demux.poll_message().expect("poll").expect("some msg");
        assert_eq!(msg1, WsMessage::Text("Hello IFA Demux".to_string()));

        // 2. Fragmented text message: 3 chunks (Text -> Continuation -> Continuation)
        let frag1 = WsFrame {
            fin: false,
            opcode: WsOpcode::Text,
            is_masked: false,
            mask_key: None,
            payload: b"Part 1 - ".to_vec(),
        };
        let frag2 = WsFrame {
            fin: false,
            opcode: WsOpcode::Continuation,
            is_masked: false,
            mask_key: None,
            payload: b"Part 2 - ".to_vec(),
        };
        let frag3 = WsFrame {
            fin: true,
            opcode: WsOpcode::Continuation,
            is_masked: false,
            mask_key: None,
            payload: b"Part 3 Complete".to_vec(),
        };

        // Push fragments in byte streams
        demux.push_bytes(&frag1.encode());
        assert_eq!(demux.poll_message().expect("poll"), None); // incomplete

        demux.push_bytes(&frag2.encode());
        assert_eq!(demux.poll_message().expect("poll"), None); // incomplete

        demux.push_bytes(&frag3.encode());
        let reassembled = demux.poll_message().expect("poll").expect("reassembled");
        assert_eq!(
            reassembled,
            WsMessage::Text("Part 1 - Part 2 - Part 3 Complete".to_string())
        );

        // 3. Fragmented binary message
        let b1 = WsFrame {
            fin: false,
            opcode: WsOpcode::Binary,
            is_masked: false,
            mask_key: None,
            payload: vec![1, 2, 3],
        };
        let b2 = WsFrame {
            fin: true,
            opcode: WsOpcode::Continuation,
            is_masked: false,
            mask_key: None,
            payload: vec![4, 5, 6],
        };
        demux.push_bytes(&b1.encode());
        demux.push_bytes(&b2.encode());
        let reassembled_bin = demux
            .poll_message()
            .expect("poll bin")
            .expect("reassembled bin");
        assert_eq!(reassembled_bin, WsMessage::Binary(vec![1, 2, 3, 4, 5, 6]));
    }

    #[test]
    fn test_websocket_interleaved_control_frames() {
        let mut demux = WsDemux::new();

        // Start a fragmented message
        let frag1 = WsFrame {
            fin: false,
            opcode: WsOpcode::Text,
            is_masked: false,
            mask_key: None,
            payload: b"Segment A - ".to_vec(),
        };
        demux.push_bytes(&frag1.encode());

        // Interleave a Ping control frame
        let ping = WsFrame::ping(b"interleaved-heartbeat".to_vec(), false, None);
        demux.push_bytes(&ping.encode());

        // Ping must be demultiplexed immediately!
        let msg_ping = demux.poll_message().expect("poll ping").expect("got ping");
        assert_eq!(msg_ping, WsMessage::Ping(b"interleaved-heartbeat".to_vec()));

        // Now push final continuation fragment
        let frag2 = WsFrame {
            fin: true,
            opcode: WsOpcode::Continuation,
            is_masked: false,
            mask_key: None,
            payload: b"Segment B".to_vec(),
        };
        demux.push_bytes(&frag2.encode());

        // Fragment reassembly continues seamlessly
        let msg_text = demux.poll_message().expect("poll text").expect("got text");
        assert_eq!(
            msg_text,
            WsMessage::Text("Segment A - Segment B".to_string())
        );
    }

    #[test]
    fn test_async_ws_connection_colorless_fibers() {
        use ifa_runtime::reactor::AsyncTcpListener;

        let listener = AsyncTcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");

        // Spawn client fiber
        GLOBAL_SCHEDULER.spawn(move || {
            let stream = AsyncTcpStream::connect(addr).expect("connect async client");
            let mut client = AsyncWsConnection::new(stream, true);

            // Client sends text message
            client
                .send_text("FIBER_WS_CLIENT_PING")
                .expect("client send");

            // Client receives server reply
            let reply = client.recv_message().expect("client recv");
            assert_eq!(reply, WsMessage::Text("FIBER_WS_SERVER_PONG".to_string()));

            // Client sends fragmented binary
            client
                .send_fragmented_binary(&[&[0x01, 0x02], &[0x03, 0x04, 0x05]])
                .expect("client send frag bin");

            // Client sends close
            client
                .send_close(1000, "Clean shutdown")
                .expect("client close");
            std::thread::sleep(Duration::from_millis(50));
        });

        // Server accepts connection
        let mut server_conn = loop {
            if let Ok(Some((stream, _))) = listener.try_accept() {
                break AsyncWsConnection::new(stream, false);
            }
            GLOBAL_SCHEDULER.yield_now();
            std::thread::sleep(Duration::from_millis(5));
        };

        // Server receives client text message
        let msg1 = server_conn.recv_message().expect("server recv text");
        assert_eq!(msg1, WsMessage::Text("FIBER_WS_CLIENT_PING".to_string()));

        // Server replies
        server_conn
            .send_text("FIBER_WS_SERVER_PONG")
            .expect("server send");

        // Server receives reassembled binary message
        let bin_msg = server_conn.recv_message().expect("server recv bin");
        assert_eq!(
            bin_msg,
            WsMessage::Binary(vec![0x01, 0x02, 0x03, 0x04, 0x05])
        );

        // Server receives close
        let close_msg = server_conn.recv_message().expect("server recv close");
        match close_msg {
            WsMessage::Close(code, reason) => {
                assert_eq!(code, Some(1000));
                assert_eq!(reason, "Clean shutdown");
            }
            other => panic!("Expected close message, got {:?}", other),
        }
    }

    #[test]
    fn test_token_bucket_rate_limiting() {
        let mut tb = TokenBucket::new(10, 2, 1000);
        assert_eq!(tb.remaining(), 10);

        // Consume 6 tokens
        assert!(tb.try_consume(6, 1000));
        assert_eq!(tb.remaining(), 4);

        // Consume 4 tokens
        assert!(tb.try_consume(4, 1000));
        assert_eq!(tb.remaining(), 0);

        // Consume 1 token fails (throttled)
        assert!(!tb.try_consume(1, 1000));

        // Advance 3 seconds -> refills 6 tokens
        assert!(tb.try_consume(5, 1003));
        assert_eq!(tb.remaining(), 1);

        // Reset seconds calculation
        assert_eq!(tb.seconds_until_reset(), 5);
    }

    #[test]
    fn test_mime_type_lookup() {
        assert_eq!(lookup_mime_type("html"), "text/html; charset=utf-8");
        assert_eq!(lookup_mime_type("json"), "application/json");
        assert_eq!(lookup_mime_type("css"), "text/css; charset=utf-8");
        assert_eq!(lookup_mime_type("wasm"), "application/wasm");
        assert_eq!(lookup_mime_type("png"), "image/png");
        assert_eq!(lookup_mime_type("unknown_ext"), "application/octet-stream");
    }
}

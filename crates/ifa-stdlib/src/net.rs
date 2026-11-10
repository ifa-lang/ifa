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
}

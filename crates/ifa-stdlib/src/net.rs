//! Non-blocking networking, TCP stream management, and multi-connection server (`std::net`).

use std::collections::{HashMap, HashSet};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener as StdTcpListener,
    TcpStream as StdTcpStream, ToSocketAddrs, UdpSocket as StdUdpSocket,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::io::AsRawFd;

use ifa_runtime::fiber::GLOBAL_SCHEDULER;
pub use ifa_runtime::reactor::{
    AsyncTcpListener, AsyncTcpReadHalf, AsyncTcpStream, AsyncTcpWriteHalf, AsyncTimer,
    AsyncUdpSocket,
};

pub mod http;

#[cfg(unix)]
fn sock_set_recv_buffer<T: AsRawFd>(socket: &T, size: usize) -> io::Result<()> {
    let fd = socket.as_raw_fd();
    let val = size as libc::c_int;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of_val(&val) as libc::socklen_t,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn sock_get_recv_buffer<T: AsRawFd>(socket: &T) -> io::Result<usize> {
    let fd = socket.as_raw_fd();
    let mut val: libc::c_int = 0;
    let mut len = std::mem::size_of_val(&val) as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &mut val as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if ret == 0 {
        Ok(val as usize)
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn sock_set_send_buffer<T: AsRawFd>(socket: &T, size: usize) -> io::Result<()> {
    let fd = socket.as_raw_fd();
    let val = size as libc::c_int;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of_val(&val) as libc::socklen_t,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn sock_get_send_buffer<T: AsRawFd>(socket: &T) -> io::Result<usize> {
    let fd = socket.as_raw_fd();
    let mut val: libc::c_int = 0;
    let mut len = std::mem::size_of_val(&val) as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &mut val as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if ret == 0 {
        Ok(val as usize)
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
fn sock_set_recv_buffer<T>(_socket: &T, _size: usize) -> io::Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn sock_get_recv_buffer<T>(_socket: &T) -> io::Result<usize> {
    Ok(65536)
}

#[cfg(not(unix))]
fn sock_set_send_buffer<T>(_socket: &T, _size: usize) -> io::Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn sock_get_send_buffer<T>(_socket: &T) -> io::Result<usize> {
    Ok(65536)
}

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

    /// Sets the value of the `TCP_NODELAY` option on this socket.
    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.inner.set_nodelay(nodelay)
    }

    /// Gets the value of the `TCP_NODELAY` option on this socket.
    pub fn nodelay(&self) -> io::Result<bool> {
        self.inner.nodelay()
    }

    /// Sets the value for the `IP_TTL` option on this socket.
    pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        self.inner.set_ttl(ttl)
    }

    /// Gets the value of the `IP_TTL` option for this socket.
    pub fn ttl(&self) -> io::Result<u32> {
        self.inner.ttl()
    }

    /// Creates a new independently owned handle to the underlying socket.
    pub fn try_clone(&self) -> io::Result<Self> {
        let cloned = self.inner.try_clone()?;
        Ok(Self {
            inner: cloned,
            is_open: self.is_open,
        })
    }

    /// Write bytes to the stream non-blockingly. Returns number of bytes written.
    pub fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if !self.is_open {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "Stream is closed",
            ));
        }
        self.inner.write(buf)
    }

    /// Flush the underlying stream.
    pub fn flush(&mut self) -> io::Result<()> {
        if !self.is_open {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "Stream is closed",
            ));
        }
        self.inner.flush()
    }

    /// Peek at incoming data without consuming it from the stream buffer.
    pub fn peek(&self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.is_open {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "Stream is closed",
            ));
        }
        match self.inner.peek(buf) {
            Ok(n) => Ok(n),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Ok(0),
            Err(e) => Err(e),
        }
    }

    /// Sets the read timeout to the timeout specified.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.set_read_timeout(timeout)
    }

    /// Returns the read timeout of this socket.
    pub fn read_timeout(&self) -> io::Result<Option<Duration>> {
        self.inner.read_timeout()
    }

    /// Sets the write timeout to the timeout specified.
    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.set_write_timeout(timeout)
    }

    /// Returns the write timeout of this socket.
    pub fn write_timeout(&self) -> io::Result<Option<Duration>> {
        self.inner.write_timeout()
    }

    /// Shuts down the read, write, or both halves of this connection.
    pub fn shutdown(&self, how: std::net::Shutdown) -> io::Result<()> {
        self.inner.shutdown(how)
    }

    /// Moves this stream into or out of nonblocking mode.
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.inner.set_nonblocking(nonblocking)
    }

    /// Get and clear the last socket error if any.
    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        self.inner.take_error()
    }

    /// Set kernel socket receive buffer size (SO_RCVBUF).
    pub fn set_recv_buffer_size(&self, size: usize) -> io::Result<()> {
        sock_set_recv_buffer(&self.inner, size)
    }

    /// Retrieve kernel socket receive buffer size (SO_RCVBUF).
    pub fn recv_buffer_size(&self) -> io::Result<usize> {
        sock_get_recv_buffer(&self.inner)
    }

    /// Set kernel socket send buffer size (SO_SNDBUF).
    pub fn set_send_buffer_size(&self, size: usize) -> io::Result<()> {
        sock_set_send_buffer(&self.inner, size)
    }

    /// Retrieve kernel socket send buffer size (SO_SNDBUF).
    pub fn send_buffer_size(&self) -> io::Result<usize> {
        sock_get_send_buffer(&self.inner)
    }

    /// Apply standard configuration options to this stream.
    pub fn apply_config(&self, config: &SocketConfig) -> io::Result<()> {
        config.apply_tcp(self)
    }
}

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        TcpStream::read(self, buf)
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        TcpStream::write(self, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        TcpStream::flush(self)
    }
}

impl Read for &TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.is_open {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "Stream is closed",
            ));
        }
        match (&self.inner).read(buf) {
            Ok(n) => Ok(n),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Ok(0),
            Err(e) => Err(e),
        }
    }
}

impl Write for &TcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if !self.is_open {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "Stream is closed",
            ));
        }
        (&self.inner).write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.is_open {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "Stream is closed",
            ));
        }
        (&self.inner).flush()
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

    /// Sets the value for the `IP_TTL` option on this socket.
    pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        self.inner.set_ttl(ttl)
    }

    /// Gets the value of the `IP_TTL` option for this socket.
    pub fn ttl(&self) -> io::Result<u32> {
        self.inner.ttl()
    }

    /// Creates a new independently owned handle to the underlying listener.
    pub fn try_clone(&self) -> io::Result<Self> {
        let cloned = self.inner.try_clone()?;
        Ok(Self {
            inner: cloned,
            is_open: self.is_open,
        })
    }

    /// Close the listener.
    pub fn close(&mut self) {
        self.is_open = false;
    }

    /// Moves this listener, if possible, into or out of nonblocking mode.
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.inner.set_nonblocking(nonblocking)
    }

    /// Get and clear the last socket error if any.
    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        self.inner.take_error()
    }
}

/// Managed non-blocking UDP Socket (`std::net::UdpSocket`).
pub struct UdpSocket {
    inner: StdUdpSocket,
    is_open: bool,
}

impl UdpSocket {
    /// Bind to a local address and configure socket in non-blocking mode.
    pub fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        let socket = StdUdpSocket::bind(addr)?;
        socket.set_nonblocking(true)?;
        Ok(Self {
            inner: socket,
            is_open: true,
        })
    }

    /// Wrap an existing standard UDP socket.
    pub fn from_std(socket: StdUdpSocket) -> io::Result<Self> {
        socket.set_nonblocking(true)?;
        Ok(Self {
            inner: socket,
            is_open: true,
        })
    }

    /// Sends data on the socket to the given address.
    pub fn send_to<A: ToSocketAddrs>(&self, buf: &[u8], target: A) -> io::Result<usize> {
        if !self.is_open {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "UDP socket is closed",
            ));
        }
        self.inner.send_to(buf, target)
    }

    /// Receives a single datagram message on the socket.
    /// In non-blocking mode, if no data is available, returns Ok((0, dummy_addr)).
    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        if !self.is_open {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "UDP socket is closed",
            ));
        }
        match self.inner.recv_from(buf) {
            Ok(res) => Ok(res),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                let dummy: SocketAddr = "0.0.0.0:0".parse().unwrap();
                Ok((0, dummy))
            }
            Err(e) => Err(e),
        }
    }

    /// Non-blocking poll for incoming datagram. Returns `Ok(Some((bytes_read, sender_addr)))`
    /// or `Ok(None)` if no datagram is pending.
    pub fn poll_recv_from(&self, buf: &mut [u8]) -> io::Result<Option<(usize, SocketAddr)>> {
        if !self.is_open {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "UDP socket is closed",
            ));
        }
        match self.inner.recv_from(buf) {
            Ok((n, addr)) => Ok(Some((n, addr))),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Connects this UDP socket to a remote address, allowing the `send` and `recv` shortcuts.
    pub fn connect<A: ToSocketAddrs>(&self, addr: A) -> io::Result<()> {
        if !self.is_open {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "UDP socket is closed",
            ));
        }
        self.inner.connect(addr)
    }

    /// Sends data on the socket to the connected peer.
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        if !self.is_open {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "UDP socket is closed",
            ));
        }
        self.inner.send(buf)
    }

    /// Receives a single datagram message from the connected peer.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.is_open {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "UDP socket is closed",
            ));
        }
        match self.inner.recv(buf) {
            Ok(n) => Ok(n),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Ok(0),
            Err(e) => Err(e),
        }
    }

    /// Returns the socket address of the local half of this UDP socket.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// Returns the bound port number.
    pub fn port(&self) -> io::Result<u16> {
        self.inner.local_addr().map(|a| a.port())
    }

    /// Returns the socket address of the remote peer this socket was connected to.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.peer_addr()
    }

    /// Sets the value of the `SO_BROADCAST` option for this socket.
    pub fn set_broadcast(&self, on: bool) -> io::Result<()> {
        self.inner.set_broadcast(on)
    }

    /// Gets the value of the `SO_BROADCAST` option for this socket.
    pub fn broadcast(&self) -> io::Result<bool> {
        self.inner.broadcast()
    }

    /// Sets the value of the `IP_MULTICAST_LOOP` option for this socket.
    pub fn set_multicast_loop_v4(&self, on: bool) -> io::Result<()> {
        self.inner.set_multicast_loop_v4(on)
    }

    /// Gets the value of the `IP_MULTICAST_LOOP` option for this socket.
    pub fn multicast_loop_v4(&self) -> io::Result<bool> {
        self.inner.multicast_loop_v4()
    }

    /// Sets the value for the `IP_TTL` option on this socket.
    pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        self.inner.set_ttl(ttl)
    }

    /// Gets the value of the `IP_TTL` option for this socket.
    pub fn ttl(&self) -> io::Result<u32> {
        self.inner.ttl()
    }

    /// Moves this UDP socket into or out of nonblocking mode.
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.inner.set_nonblocking(nonblocking)
    }

    /// Creates a new independently owned handle to the underlying socket.
    pub fn try_clone(&self) -> io::Result<Self> {
        let cloned = self.inner.try_clone()?;
        Ok(Self {
            inner: cloned,
            is_open: self.is_open,
        })
    }

    /// Receives data on the socket from the remote address without removing it from the input queue.
    pub fn peek_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        if !self.is_open {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "UDP socket is closed",
            ));
        }
        match self.inner.peek_from(buf) {
            Ok(res) => Ok(res),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                let dummy: SocketAddr = "0.0.0.0:0".parse().unwrap();
                Ok((0, dummy))
            }
            Err(e) => Err(e),
        }
    }

    /// Receives data on the connected socket without removing it from the input queue.
    pub fn peek(&self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.is_open {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "UDP socket is closed",
            ));
        }
        match self.inner.peek(buf) {
            Ok(n) => Ok(n),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Ok(0),
            Err(e) => Err(e),
        }
    }

    /// Sets the read timeout to the timeout specified.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.set_read_timeout(timeout)
    }

    /// Returns the read timeout of this socket.
    pub fn read_timeout(&self) -> io::Result<Option<Duration>> {
        self.inner.read_timeout()
    }

    /// Sets the write timeout to the timeout specified.
    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.set_write_timeout(timeout)
    }

    /// Returns the write timeout of this socket.
    pub fn write_timeout(&self) -> io::Result<Option<Duration>> {
        self.inner.write_timeout()
    }

    /// Get and clear the last socket error if any.
    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        self.inner.take_error()
    }

    /// Join an IPv4 multicast group.
    pub fn join_multicast_v4(&self, multiaddr: &Ipv4Addr, interface: &Ipv4Addr) -> io::Result<()> {
        self.inner.join_multicast_v4(multiaddr, interface)
    }

    /// Leave an IPv4 multicast group.
    pub fn leave_multicast_v4(&self, multiaddr: &Ipv4Addr, interface: &Ipv4Addr) -> io::Result<()> {
        self.inner.leave_multicast_v4(multiaddr, interface)
    }

    /// Set kernel socket receive buffer size (SO_RCVBUF).
    pub fn set_recv_buffer_size(&self, size: usize) -> io::Result<()> {
        sock_set_recv_buffer(&self.inner, size)
    }

    /// Retrieve kernel socket receive buffer size (SO_RCVBUF).
    pub fn recv_buffer_size(&self) -> io::Result<usize> {
        sock_get_recv_buffer(&self.inner)
    }

    /// Set kernel socket send buffer size (SO_SNDBUF).
    pub fn set_send_buffer_size(&self, size: usize) -> io::Result<()> {
        sock_set_send_buffer(&self.inner, size)
    }

    /// Retrieve kernel socket send buffer size (SO_SNDBUF).
    pub fn send_buffer_size(&self) -> io::Result<usize> {
        sock_get_send_buffer(&self.inner)
    }

    /// Non-blocking attempt to read a datagram message into a newly allocated `Datagram`.
    pub fn recv_datagram(&self, max_size: usize) -> io::Result<Option<Datagram>> {
        let mut buffer = vec![0u8; max_size];
        match self.poll_recv_from(&mut buffer)? {
            Some((n, sender)) => {
                buffer.truncate(n);
                Ok(Some(Datagram {
                    data: buffer,
                    sender,
                }))
            }
            None => Ok(None),
        }
    }

    /// Send a datagram message to its destination address.
    pub fn send_datagram(&self, packet: &Datagram) -> io::Result<usize> {
        self.send_to(&packet.data, packet.sender)
    }

    /// Apply standard configuration options to this socket.
    pub fn apply_config(&self, config: &SocketConfig) -> io::Result<()> {
        config.apply_udp(self)
    }

    /// Mark socket as closed.
    pub fn close(&mut self) {
        self.is_open = false;
    }

    /// Returns true if socket is currently open.
    pub fn is_open(&self) -> bool {
        self.is_open
    }
}

/// Ergonomic representation of a network datagram (data payload + remote peer address).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram {
    pub data: Vec<u8>,
    pub sender: SocketAddr,
}

impl Datagram {
    /// Create a new datagram message.
    pub fn new(data: Vec<u8>, sender: SocketAddr) -> Self {
        Self { data, sender }
    }
}

/// High-level builder to configure socket options and kernel buffer capacities.
#[derive(Debug, Clone, Default)]
pub struct SocketConfig {
    pub nodelay: Option<bool>,
    pub ttl: Option<u32>,
    pub read_timeout: Option<Option<Duration>>,
    pub write_timeout: Option<Option<Duration>>,
    pub recv_buffer_size: Option<usize>,
    pub send_buffer_size: Option<usize>,
    pub broadcast: Option<bool>,
}

impl SocketConfig {
    /// Create an empty configuration builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable or disable Nagle's algorithm (TCP_NODELAY).
    pub fn nodelay(mut self, enabled: bool) -> Self {
        self.nodelay = Some(enabled);
        self
    }

    /// Set IP Time-To-Live.
    pub fn ttl(mut self, ttl: u32) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Set socket read timeout.
    pub fn read_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.read_timeout = Some(timeout);
        self
    }

    /// Set socket write timeout.
    pub fn write_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.write_timeout = Some(timeout);
        self
    }

    /// Set kernel socket receive buffer capacity (SO_RCVBUF).
    pub fn recv_buffer_size(mut self, size: usize) -> Self {
        self.recv_buffer_size = Some(size);
        self
    }

    /// Set kernel socket send buffer capacity (SO_SNDBUF).
    pub fn send_buffer_size(mut self, size: usize) -> Self {
        self.send_buffer_size = Some(size);
        self
    }

    /// Set SO_BROADCAST option for UDP sockets.
    pub fn broadcast(mut self, enabled: bool) -> Self {
        self.broadcast = Some(enabled);
        self
    }

    /// Apply configured options to a TCP stream.
    pub fn apply_tcp(&self, stream: &TcpStream) -> io::Result<()> {
        if let Some(nd) = self.nodelay {
            stream.set_nodelay(nd)?;
        }
        if let Some(ttl) = self.ttl {
            stream.set_ttl(ttl)?;
        }
        if let Some(to) = self.read_timeout {
            stream.set_read_timeout(to)?;
        }
        if let Some(to) = self.write_timeout {
            stream.set_write_timeout(to)?;
        }
        if let Some(sz) = self.recv_buffer_size {
            stream.set_recv_buffer_size(sz)?;
        }
        if let Some(sz) = self.send_buffer_size {
            stream.set_send_buffer_size(sz)?;
        }
        Ok(())
    }

    /// Apply configured options to a UDP socket.
    pub fn apply_udp(&self, socket: &UdpSocket) -> io::Result<()> {
        if let Some(bc) = self.broadcast {
            socket.set_broadcast(bc)?;
        }
        if let Some(ttl) = self.ttl {
            socket.set_ttl(ttl)?;
        }
        if let Some(to) = self.read_timeout {
            socket.set_read_timeout(to)?;
        }
        if let Some(to) = self.write_timeout {
            socket.set_write_timeout(to)?;
        }
        if let Some(sz) = self.recv_buffer_size {
            socket.set_recv_buffer_size(sz)?;
        }
        if let Some(sz) = self.send_buffer_size {
            socket.set_send_buffer_size(sz)?;
        }
        Ok(())
    }
}

/// High-level buffered TCP stream providing ergonomic line-by-line reading and buffered writes.
pub struct BufferedTcpStream {
    reader: BufReader<TcpStream>,
    writer: BufWriter<TcpStream>,
}

impl BufferedTcpStream {
    /// Wrap a `TcpStream` with default reader and writer buffer capacities.
    pub fn new(stream: TcpStream) -> io::Result<Self> {
        let write_clone = stream.try_clone()?;
        Ok(Self {
            reader: BufReader::new(stream),
            writer: BufWriter::new(write_clone),
        })
    }

    /// Wrap a `TcpStream` with explicit reader and writer buffer capacities.
    pub fn with_capacity(read_cap: usize, write_cap: usize, stream: TcpStream) -> io::Result<Self> {
        let write_clone = stream.try_clone()?;
        Ok(Self {
            reader: BufReader::with_capacity(read_cap, stream),
            writer: BufWriter::with_capacity(write_cap, write_clone),
        })
    }

    /// Read a line of text (ending with '\n' or '\r\n') from the stream.
    /// Returns `Ok(Some(line))` without trailing newline, or `Ok(None)` on EOF or if would block with 0 bytes.
    pub fn read_line(&mut self) -> io::Result<Option<String>> {
        let mut line = String::new();
        match self.reader.read_line(&mut line) {
            Ok(0) => Ok(None),
            Ok(_) => {
                if line.ends_with('\n') {
                    line.pop();
                    if line.ends_with('\r') {
                        line.pop();
                    }
                }
                Ok(Some(line))
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Write a string slice followed by a newline and flush.
    pub fn write_line(&mut self, line: &str) -> io::Result<()> {
        self.writer.write_all(line.as_bytes())?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()
    }

    /// Write all bytes into the writer buffer.
    pub fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.writer.write_all(buf)
    }

    /// Flush buffered writes to the underlying stream.
    pub fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }

    /// Reference to the underlying read stream.
    pub fn stream(&self) -> &TcpStream {
        self.reader.get_ref()
    }

    /// Mutable reference to the underlying read stream.
    pub fn stream_mut(&mut self) -> &mut TcpStream {
        self.reader.get_mut()
    }

    /// Returns the data currently buffered in the reader without reading from the OS socket.
    pub fn buffer(&self) -> &[u8] {
        self.reader.buffer()
    }

    /// Returns the number of bytes currently buffered in the reader.
    pub fn buffer_len(&self) -> usize {
        self.reader.buffer().len()
    }

    /// Returns the reader and writer buffer capacities `(read_capacity, write_capacity)`.
    pub fn capacity(&self) -> (usize, usize) {
        (self.reader.capacity(), self.writer.capacity())
    }

    /// Returns the remote peer socket address.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.reader.get_ref().peer_addr()
    }

    /// Returns the local socket address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.reader.get_ref().local_addr()
    }

    /// Sets `TCP_NODELAY` on the underlying connection.
    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.reader.get_ref().set_nodelay(nodelay)
    }

    /// Gets `TCP_NODELAY` status of the connection.
    pub fn nodelay(&self) -> io::Result<bool> {
        self.reader.get_ref().nodelay()
    }

    /// Sets read timeout on the underlying socket.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.reader.get_ref().set_read_timeout(timeout)
    }

    /// Gets read timeout of the underlying socket.
    pub fn read_timeout(&self) -> io::Result<Option<Duration>> {
        self.reader.get_ref().read_timeout()
    }

    /// Sets write timeout on the underlying socket.
    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.writer.get_ref().set_write_timeout(timeout)
    }

    /// Gets write timeout of the underlying socket.
    pub fn write_timeout(&self) -> io::Result<Option<Duration>> {
        self.writer.get_ref().write_timeout()
    }

    /// Unwraps this buffered stream, returning the underlying reader `TcpStream`.
    pub fn into_inner(self) -> TcpStream {
        self.reader.into_inner()
    }

    /// Borrows the internal reader and writer independently.
    pub fn split_mut(&mut self) -> (&mut BufReader<TcpStream>, &mut BufWriter<TcpStream>) {
        (&mut self.reader, &mut self.writer)
    }

    /// Split this buffered stream into an owned read half and write half.
    pub fn into_split(self) -> (BufferedReaderHalf, BufferedWriterHalf) {
        (
            BufferedReaderHalf {
                reader: self.reader,
            },
            BufferedWriterHalf {
                writer: self.writer,
            },
        )
    }

    /// Reunite an owned read half and write half into a single `BufferedTcpStream`.
    pub fn reunite(reader: BufferedReaderHalf, writer: BufferedWriterHalf) -> Self {
        Self {
            reader: reader.reader,
            writer: writer.writer,
        }
    }

    /// Unwraps both underlying `TcpStream` handles (reader clone and writer clone).
    pub fn into_inner_pair(self) -> (TcpStream, io::Result<TcpStream>) {
        (
            self.reader.into_inner(),
            self.writer.into_inner().map_err(|e| e.into_error()),
        )
    }
}

/// Owned read half of a `BufferedTcpStream`.
pub struct BufferedReaderHalf {
    reader: BufReader<TcpStream>,
}

impl BufferedReaderHalf {
    /// Read a line of text (ending with '\n' or '\r\n') from the stream.
    /// Returns `Ok(Some(line))` without trailing newline, or `Ok(None)` on EOF or if would block with 0 bytes.
    pub fn read_line(&mut self) -> io::Result<Option<String>> {
        let mut line = String::new();
        match self.reader.read_line(&mut line) {
            Ok(0) => Ok(None),
            Ok(_) => {
                if line.ends_with('\n') {
                    line.pop();
                    if line.ends_with('\r') {
                        line.pop();
                    }
                }
                Ok(Some(line))
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Returns the data currently buffered in the reader without reading from the OS socket.
    pub fn buffer(&self) -> &[u8] {
        self.reader.buffer()
    }

    /// Returns the number of bytes currently buffered in the reader.
    pub fn buffer_len(&self) -> usize {
        self.reader.buffer().len()
    }

    /// Returns the reader capacity.
    pub fn capacity(&self) -> usize {
        self.reader.capacity()
    }

    /// Remote peer socket address.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.reader.get_ref().peer_addr()
    }

    /// Local socket address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.reader.get_ref().local_addr()
    }

    /// Unwraps the underlying `TcpStream`.
    pub fn into_inner(self) -> TcpStream {
        self.reader.into_inner()
    }

    /// Reunite this read half with a write half into a single `BufferedTcpStream`.
    pub fn reunite(self, writer: BufferedWriterHalf) -> BufferedTcpStream {
        BufferedTcpStream::reunite(self, writer)
    }
}

impl io::Read for BufferedReaderHalf {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buf)
    }
}

impl io::BufRead for BufferedReaderHalf {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.reader.fill_buf()
    }

    fn consume(&mut self, amt: usize) {
        self.reader.consume(amt);
    }
}

/// Owned write half of a `BufferedTcpStream`.
pub struct BufferedWriterHalf {
    writer: BufWriter<TcpStream>,
}

impl BufferedWriterHalf {
    /// Write a string slice followed by a newline and flush.
    pub fn write_line(&mut self, line: &str) -> io::Result<()> {
        self.writer.write_all(line.as_bytes())?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()
    }

    /// Write all bytes into the writer buffer.
    pub fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.writer.write_all(buf)
    }

    /// Flush buffered writes to the underlying socket.
    pub fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }

    /// Returns the writer capacity.
    pub fn capacity(&self) -> usize {
        self.writer.capacity()
    }

    /// Remote peer socket address.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.writer.get_ref().peer_addr()
    }

    /// Local socket address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.writer.get_ref().local_addr()
    }

    /// Unwraps the underlying `TcpStream`.
    pub fn into_inner(self) -> Result<TcpStream, io::IntoInnerError<BufWriter<TcpStream>>> {
        self.writer.into_inner()
    }

    /// Reunite this write half with a read half into a single `BufferedTcpStream`.
    pub fn reunite(self, reader: BufferedReaderHalf) -> BufferedTcpStream {
        BufferedTcpStream::reunite(reader, self)
    }
}

impl io::Write for BufferedWriterHalf {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

impl io::Read for BufferedTcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buf)
    }
}

impl io::BufRead for BufferedTcpStream {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.reader.fill_buf()
    }

    fn consume(&mut self, amt: usize) {
        self.reader.consume(amt);
    }
}

impl io::Write for BufferedTcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
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

/// Default maximum retained capacity for stream demux and frame decode buffers (64 KiB).
/// Buffers exceeding this size after draining are shrunk to prevent unbounded memory retention.
pub const DEFAULT_MAX_RETAINED_BUFFER_CAPACITY: usize = 65536;

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
            if self.buffer.is_empty()
                && self.buffer.capacity() > DEFAULT_MAX_RETAINED_BUFFER_CAPACITY
            {
                self.buffer.shrink_to(DEFAULT_MAX_RETAINED_BUFFER_CAPACITY);
            }
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
    /// Sec-WebSocket-Protocol negotiated during handshake, if any.
    pub subprotocol: Option<String>,
}

impl AsyncWsConnection {
    /// Create a new async WebSocket connection wrapping an async TCP stream.
    pub fn new(stream: AsyncTcpStream, is_client: bool) -> Self {
        Self {
            stream,
            demux: WsDemux::new(),
            is_client,
            is_closed: false,
            subprotocol: None,
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

    /// Perform an asynchronous RFC 6455 client handshake over an `AsyncTcpStream`.
    /// Sends the HTTP Upgrade request, awaits and verifies the HTTP 101 Switching Protocols response.
    pub fn client_handshake(
        stream: AsyncTcpStream,
        host: &str,
        port: u16,
        path: &str,
        client_key: &str,
    ) -> io::Result<Self> {
        Self::client_handshake_with_protocols(stream, host, port, path, client_key, &[])
    }

    /// Perform an asynchronous RFC 6455 client handshake with optional subprotocols (Sec-WebSocket-Protocol).
    pub fn client_handshake_with_protocols(
        mut stream: AsyncTcpStream,
        host: &str,
        port: u16,
        path: &str,
        client_key: &str,
        protocols: &[&str],
    ) -> io::Result<Self> {
        let expected_accept = crate::crypto::websocket_accept_key(client_key);
        let proto_header = if !protocols.is_empty() {
            format!("Sec-WebSocket-Protocol: {}\r\n", protocols.join(", "))
        } else {
            String::new()
        };
        let req = format!(
            "GET {} HTTP/1.1\r\nHost: {}:{}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\n{}\r\n",
            path, host, port, client_key, proto_header
        );

        stream.write_all(req.as_bytes())?;

        let mut demux = WsDemux::new();
        let mut spins = 0;

        loop {
            let mut chunk = [0u8; 1024];
            match stream.try_read(&mut chunk) {
                Ok(Some(n)) if n > 0 => {
                    demux.push_bytes(&chunk[..n]);
                    let text = String::from_utf8_lossy(&demux.buffer);
                    if let Some(idx) = text.find("\r\n\r\n") {
                        let header_part = &text[..idx];
                        if !header_part.contains("101 Switching Protocols")
                            || !header_part.contains(&expected_accept)
                        {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "WebSocket handshake rejected by server",
                            ));
                        }

                        // Parse negotiated subprotocol if present in response
                        let mut negotiated_proto = None;
                        for line in header_part.lines() {
                            if line
                                .to_ascii_lowercase()
                                .starts_with("sec-websocket-protocol:")
                            {
                                if let Some(sep) = line.find(':') {
                                    negotiated_proto = Some(line[sep + 1..].trim().to_string());
                                }
                            }
                        }

                        demux.buffer.drain(..idx + 4);
                        return Ok(Self {
                            stream,
                            demux,
                            is_client: true,
                            is_closed: false,
                            subprotocol: negotiated_proto,
                        });
                    }
                }
                Ok(Some(0)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "Server closed connection during WebSocket handshake",
                    ));
                }
                Ok(Some(_)) | Ok(None) => {}
                Err(e) => return Err(e),
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

    /// Perform an asynchronous RFC 6455 server handshake over an `AsyncTcpStream`.
    /// Reads client HTTP Upgrade request, validates `Sec-WebSocket-Key`, sends 101 Switching Protocols,
    /// and returns the active `AsyncWsConnection`.
    pub fn server_handshake(stream: AsyncTcpStream) -> io::Result<Self> {
        Self::server_handshake_with_negotiator(stream, |_| None)
    }

    /// Perform an asynchronous RFC 6455 server handshake selecting a subprotocol from offered client protocols.
    pub fn server_handshake_with_negotiator<F>(
        mut stream: AsyncTcpStream,
        negotiator: F,
    ) -> io::Result<Self>
    where
        F: FnOnce(&[String]) -> Option<String>,
    {
        let mut demux = WsDemux::new();
        let mut spins = 0;

        loop {
            let mut chunk = [0u8; 1024];
            match stream.try_read(&mut chunk) {
                Ok(Some(n)) if n > 0 => {
                    demux.push_bytes(&chunk[..n]);
                    let text = String::from_utf8_lossy(&demux.buffer);
                    if let Some(header_end) = text.find("\r\n\r\n") {
                        let header_part = &text[..header_end];
                        let mut key: Option<String> = None;
                        let mut client_protocols = Vec::new();

                        for line in header_part.lines() {
                            let lower = line.to_ascii_lowercase();
                            if lower.starts_with("sec-websocket-key:") {
                                if let Some(orig_idx) = line.find(':') {
                                    key = Some(line[orig_idx + 1..].trim().to_string());
                                }
                            } else if lower.starts_with("sec-websocket-protocol:") {
                                if let Some(orig_idx) = line.find(':') {
                                    let raw_protos = &line[orig_idx + 1..];
                                    for proto in raw_protos.split(',') {
                                        let p = proto.trim();
                                        if !p.is_empty() {
                                            client_protocols.push(p.to_string());
                                        }
                                    }
                                }
                            }
                        }

                        let client_key = key.ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "Missing Sec-WebSocket-Key in HTTP Upgrade request",
                            )
                        })?;

                        let chosen_proto = negotiator(&client_protocols);
                        let proto_header = match &chosen_proto {
                            Some(ref proto) => {
                                format!("Sec-WebSocket-Protocol: {}\r\n", proto)
                            }
                            None => String::new(),
                        };

                        let accept = crate::crypto::websocket_accept_key(&client_key);
                        let response = format!(
                            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n{}\r\n",
                            accept, proto_header
                        );
                        stream.write_all(response.as_bytes())?;

                        demux.buffer.drain(..header_end + 4);
                        return Ok(Self {
                            stream,
                            demux,
                            is_client: false,
                            is_closed: false,
                            subprotocol: chosen_proto,
                        });
                    }
                }
                Ok(Some(0)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "Client closed connection during WebSocket handshake",
                    ));
                }
                Ok(Some(_)) | Ok(None) => {}
                Err(e) => return Err(e),
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

/// Instantaneous diagnostic telemetry and runtime metrics for an [`AsyncWsPool`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsPoolStats {
    /// Target host name or IP address.
    pub host: String,
    /// Target destination port.
    pub port: u16,
    /// Requested target WebSocket path.
    pub path: String,
    /// Number of connections currently idle and available in the pool.
    pub idle_connections: usize,
    /// Number of connections actively in use or establishing.
    pub active_connections: usize,
    /// Maximum configured connection limit for this pool.
    pub max_connections: usize,
    /// Configured subprotocols negotiated by this pool.
    pub protocols: Vec<String>,
}

impl WsPoolStats {
    /// Whether the pool is currently running at its maximum configured connection capacity.
    #[inline]
    pub fn is_exhausted(&self) -> bool {
        self.active_connections >= self.max_connections
    }

    /// Total number of connections tracked by the pool (idle + active in-use).
    #[inline]
    pub fn total_connections(&self) -> usize {
        self.idle_connections + self.active_connections
    }
}

/// A connection pool for reusable asynchronous WebSocket client connections.
/// Manages connection limits, idle connection reuse, health check pings and subprotocol grouping.
pub struct AsyncWsPool {
    host: String,
    port: u16,
    path: String,
    protocols: Vec<String>,
    max_connections: usize,
    idle_pool: std::sync::Mutex<Vec<AsyncWsConnection>>,
    active_count: std::sync::atomic::AtomicUsize,
}

impl AsyncWsPool {
    /// Create a new WebSocket client connection pool.
    pub fn new(
        host: impl Into<String>,
        port: u16,
        path: impl Into<String>,
        protocols: Vec<String>,
        max_connections: usize,
    ) -> Self {
        Self {
            host: host.into(),
            port,
            path: path.into(),
            protocols,
            max_connections: max_connections.max(1),
            idle_pool: std::sync::Mutex::new(Vec::new()),
            active_count: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Number of currently idle pooled connections.
    pub fn idle_count(&self) -> usize {
        self.idle_pool.lock().map(|p| p.len()).unwrap_or(0)
    }

    /// Total count of active (checked-out or connecting) connections.
    pub fn active_count(&self) -> usize {
        self.active_count.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Snapshot the current runtime metrics and diagnostic telemetry of the WebSocket pool.
    pub fn stats(&self) -> WsPoolStats {
        WsPoolStats {
            host: self.host.clone(),
            port: self.port,
            path: self.path.clone(),
            idle_connections: self.idle_count(),
            active_connections: self.active_count(),
            max_connections: self.max_connections,
            protocols: self.protocols.clone(),
        }
    }

    /// Check out an active WebSocket connection from the pool, or establish a new one if below max_connections.
    pub fn acquire(&self) -> io::Result<AsyncWsConnection> {
        // Try to pop an existing healthy connection
        if let Ok(mut pool) = self.idle_pool.lock() {
            while let Some(mut conn) = pool.pop() {
                if !conn.is_closed() {
                    // Quick health check ping
                    if conn.send_ping(b"pool_probe").is_ok() {
                        self.active_count
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        return Ok(conn);
                    }
                }
            }
        }

        let current = self.active_count.load(std::sync::atomic::Ordering::Relaxed);
        if current >= self.max_connections {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "WebSocket connection pool capacity exhausted",
            ));
        }

        // Connect new connection
        let stream = AsyncTcpStream::connect(format!("{}:{}", self.host, self.port))?;
        let proto_refs: Vec<&str> = self.protocols.iter().map(|s| s.as_str()).collect();
        let client_key = "dGhlIHNhbXBsZSBub25jZQ==";
        let conn = AsyncWsConnection::client_handshake_with_protocols(
            stream,
            &self.host,
            self.port,
            &self.path,
            client_key,
            &proto_refs,
        )?;

        self.active_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(conn)
    }

    /// Return a connection back to the pool if healthy and space is available.
    pub fn release(&self, conn: AsyncWsConnection) {
        self.active_count
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);

        if !conn.is_closed() {
            if let Ok(mut pool) = self.idle_pool.lock() {
                if pool.len() < self.max_connections {
                    pool.push(conn);
                }
            }
        }
    }

    /// Clear all idle connections in the pool.
    pub fn clear(&self) {
        if let Ok(mut pool) = self.idle_pool.lock() {
            pool.clear();
        }
    }
}

/// Asynchronous HTTP/2 Connection running over an `AsyncTcpStream` on colorless fibers.
/// Handles preface negotiation, frame buffering, multiplexing, and bidirectional streams.
pub struct AsyncHttp2Connection {
    pub stream: AsyncTcpStream,
    pub session: crate::simd_parser::Http2Session,
    read_buf: Vec<u8>,
    is_closed: bool,
}

impl AsyncHttp2Connection {
    /// Create a new `AsyncHttp2Connection` wrapping an active `AsyncTcpStream`.
    pub fn new(stream: AsyncTcpStream, is_server: bool) -> Self {
        Self {
            stream,
            session: crate::simd_parser::Http2Session::new(is_server),
            read_buf: Vec::with_capacity(8192),
            is_closed: false,
        }
    }

    /// Whether this HTTP/2 connection is closed.
    pub fn is_closed(&self) -> bool {
        self.is_closed
    }

    /// Perform HTTP/2 client handshake: sends client connection preface and initial SETTINGS frame.
    pub fn client_handshake(mut stream: AsyncTcpStream) -> io::Result<Self> {
        // 1. Send client preface
        stream.write_all(crate::simd_parser::Http2Session::CLIENT_PREFACE)?;

        // 2. Send initial SETTINGS frame
        let session = crate::simd_parser::Http2Session::new(false);
        let settings_frame = crate::simd_parser::Http2Frame::Settings {
            ack: false,
            settings: session.local_settings.clone(),
        };
        stream.write_all(&settings_frame.encode())?;

        Ok(Self {
            stream,
            session,
            read_buf: Vec::with_capacity(8192),
            is_closed: false,
        })
    }

    /// Perform HTTP/2 server handshake: validates client preface and sends server SETTINGS frame.
    pub fn server_handshake(mut stream: AsyncTcpStream) -> io::Result<Self> {
        // Read client preface (24 bytes)
        let preface_len = crate::simd_parser::Http2Session::CLIENT_PREFACE.len();
        let mut preface_buf = vec![0u8; preface_len];
        let mut read = 0;
        let mut spins = 0;

        while read < preface_len {
            match stream.try_read(&mut preface_buf[read..]) {
                Ok(Some(n)) if n > 0 => {
                    read += n;
                    spins = 0;
                }
                Ok(Some(0)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "Client closed before completing HTTP/2 preface",
                    ));
                }
                Ok(Some(_)) | Ok(None) => {
                    spins += 1;
                    if spins < 16 {
                        std::hint::spin_loop();
                    } else {
                        GLOBAL_SCHEDULER.yield_now();
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
                Err(e) => return Err(e),
            }
        }

        if preface_buf != crate::simd_parser::Http2Session::CLIENT_PREFACE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid HTTP/2 client preface",
            ));
        }

        // Send server SETTINGS frame
        let session = crate::simd_parser::Http2Session::new(true);
        let settings_frame = crate::simd_parser::Http2Frame::Settings {
            ack: false,
            settings: session.local_settings.clone(),
        };
        stream.write_all(&settings_frame.encode())?;

        Ok(Self {
            stream,
            session,
            read_buf: Vec::with_capacity(8192),
            is_closed: false,
        })
    }

    /// Send an HTTP/2 frame over the connection.
    pub fn send_frame(&mut self, frame: &crate::simd_parser::Http2Frame) -> io::Result<()> {
        if self.is_closed {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "HTTP/2 connection is closed",
            ));
        }
        let wire = frame.encode();
        self.stream.write_all(&wire)
    }

    /// Send a DATA frame on an existing stream with active flow control chunking (max 16384 bytes)
    /// and adaptive backpressure waiting when flow control windows are exhausted.
    pub fn send_data(&mut self, stream_id: u32, data: &[u8], end_stream: bool) -> io::Result<()> {
        const MAX_FRAME_SIZE: usize = 16384;
        if data.is_empty() {
            let frame = self.session.create_data_frame(stream_id, &[], end_stream);
            return self.send_frame(&frame);
        }

        let mut offset = 0;
        let mut spins = 0;
        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(30);

        while offset < data.len() {
            // Check available outbound flow control credit
            let avail = self.session.outbound_window_available(stream_id);
            if avail <= 0 {
                // Window exhausted: process incoming frames to receive WINDOW_UPDATE
                if start.elapsed() >= timeout {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!(
                            "Timed out waiting for HTTP/2 flow control window on stream {}",
                            stream_id
                        ),
                    ));
                }

                if let Some(frame) = self.try_recv_frame()? {
                    if let crate::simd_parser::Http2Frame::RstStream {
                        stream_id: rst_id,
                        error_code,
                    } = frame
                    {
                        if rst_id == stream_id {
                            return Err(io::Error::new(
                                io::ErrorKind::ConnectionReset,
                                format!("Stream {} reset by peer: {:?}", stream_id, error_code),
                            ));
                        }
                    } else if let crate::simd_parser::Http2Frame::GoAway { error_code, .. } = frame
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            format!("Connection closed by GOAWAY: {:?}", error_code),
                        ));
                    }
                    spins = 0;
                } else {
                    if self.is_closed && self.read_buf.is_empty() {
                        return Err(io::Error::new(
                            io::ErrorKind::NotConnected,
                            "HTTP/2 connection closed while waiting for flow control credit",
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
                continue;
            }

            // Transmit at most the available credit and at most MAX_FRAME_SIZE
            let max_allowed = std::cmp::min(avail as usize, MAX_FRAME_SIZE);
            let remaining = data.len() - offset;
            let chunk_len = std::cmp::min(remaining, max_allowed);
            let is_last = end_stream && (offset + chunk_len == data.len());
            let chunk = &data[offset..offset + chunk_len];

            let frame = self.session.create_data_frame(stream_id, chunk, is_last);
            self.send_frame(&frame)?;
            offset += chunk_len;
            spins = 0;
        }
        Ok(())
    }

    /// Available outbound flow control credit for a given stream taking into account
    /// both stream-level and connection-level flow control windows.
    pub fn outbound_window_available(&self, stream_id: u32) -> i32 {
        self.session.outbound_window_available(stream_id)
    }

    /// Return current connection-level flow control window size.
    pub fn connection_window_size(&self) -> i32 {
        self.session.connection_window_size
    }

    /// Return current stream-level flow control window size if the stream exists.
    pub fn stream_window_size(&self, stream_id: u32) -> Option<i32> {
        self.session.streams.get(&stream_id).map(|s| s.window_size)
    }

    /// Initiate an HTTP/2 request on a newly opened stream.
    pub fn send_request(
        &mut self,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> io::Result<u32> {
        let has_body = body.is_some_and(|b| !b.is_empty());
        let stream_id = self.session.open_stream();
        let headers_frame = self
            .session
            .create_headers_frame(stream_id, headers, !has_body);
        self.send_frame(&headers_frame)?;

        if let Some(data) = body {
            if !data.is_empty() {
                self.send_data(stream_id, data, true)?;
            }
        }

        Ok(stream_id)
    }

    /// Send an HTTP/2 response on an existing stream.
    pub fn send_response(
        &mut self,
        stream_id: u32,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> io::Result<()> {
        let has_body = body.is_some_and(|b| !b.is_empty());
        let headers_frame = self
            .session
            .create_headers_frame(stream_id, headers, !has_body);
        self.send_frame(&headers_frame)?;

        if let Some(data) = body {
            if !data.is_empty() {
                self.send_data(stream_id, data, true)?;
            }
        }

        Ok(())
    }

    /// Stream an uncompressed or streaming body dynamically using `GzipStreamEncoder`
    /// over one or multiple chunked DATA frames, automatically setting gzip framing.
    pub fn send_streaming_gzip_chunk(
        &mut self,
        stream_id: u32,
        encoder: &mut crate::http::GzipStreamEncoder,
        chunk: &[u8],
        end_stream: bool,
    ) -> io::Result<()> {
        let mut compressed = encoder.feed(chunk);
        if end_stream {
            compressed.extend_from_slice(&encoder.finish());
        }
        if !compressed.is_empty() || end_stream {
            self.send_data(stream_id, &compressed, end_stream)?;
        }
        Ok(())
    }

    /// Progressively decompress a stream's incoming raw DATA frame chunks using `GzipStreamDecoder`.
    pub fn decompress_stream_chunk(
        &self,
        decoder: &mut crate::http::GzipStreamDecoder,
        chunk: &[u8],
    ) -> io::Result<Vec<u8>> {
        decoder
            .feed(chunk)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Non-blocking attempt to read and decode the next frame from the stream.
    /// Automatically handles Ping (replies with Pong) and Settings frames (replies with ACK).
    pub fn try_recv_frame(&mut self) -> io::Result<Option<crate::simd_parser::Http2Frame>> {
        let mut buf = [0u8; 4096];
        match self.stream.try_read(&mut buf) {
            Ok(Some(n)) if n > 0 => {
                self.read_buf.extend_from_slice(&buf[..n]);
            }
            Ok(Some(0)) => {
                self.is_closed = true;
                if self.read_buf.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "HTTP/2 connection closed by peer",
                    ));
                }
            }
            Ok(Some(_)) | Ok(None) => {}
            Err(e) => return Err(e),
        }

        // Check if full frame header (9 bytes) is available
        if self.read_buf.len() < crate::simd_parser::Http2FrameHeader::HEADER_SIZE {
            return Ok(None);
        }

        let header = match crate::simd_parser::Http2FrameHeader::decode(&self.read_buf[..9]) {
            Some(h) => h,
            None => return Ok(None),
        };

        let total_frame_len =
            crate::simd_parser::Http2FrameHeader::HEADER_SIZE + header.length as usize;
        if self.read_buf.len() < total_frame_len {
            return Ok(None);
        }

        // We have the complete frame
        let payload = &self.read_buf[9..total_frame_len];
        let frame = match crate::simd_parser::Http2Frame::decode(&header, payload) {
            Ok(f) => f,
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Failed to parse HTTP/2 frame: {:?}", e),
                ));
            }
        };

        // Drain the parsed frame from read buffer
        self.read_buf.drain(..total_frame_len);
        if self.read_buf.is_empty()
            && self.read_buf.capacity() > DEFAULT_MAX_RETAINED_BUFFER_CAPACITY
        {
            self.read_buf
                .shrink_to(DEFAULT_MAX_RETAINED_BUFFER_CAPACITY);
        }

        // If the frame is GOAWAY, mark the connection as closed
        if let crate::simd_parser::Http2Frame::GoAway { .. } = &frame {
            self.is_closed = true;
        }

        // Update internal session state
        match self.session.handle_frame(&frame) {
            Ok(Some(auto_reply)) => {
                // E.g. Settings ACK or Ping Pong ACK
                self.send_frame(&auto_reply)?;
            }
            Ok(None) => {}
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("HTTP/2 session protocol error: {:?}", e),
                ));
            }
        }

        // Active flow control window replenishment:
        // When received DATA frames consume connection or stream windows below threshold,
        // send WINDOW_UPDATE frames proactively.
        let flow_updates = self.session.replenish_flow_control_windows();
        for update_frame in flow_updates {
            self.send_frame(&update_frame)?;
        }

        Ok(Some(frame))
    }

    /// Asynchronously wait for the next frame, yielding colorless fibers cooperatively.
    pub fn recv_frame(&mut self) -> io::Result<crate::simd_parser::Http2Frame> {
        let mut spins = 0;
        loop {
            if let Some(frame) = self.try_recv_frame()? {
                return Ok(frame);
            }
            if self.is_closed && self.read_buf.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "HTTP/2 connection is closed",
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

    /// Gracefully close connection by sending a GOAWAY frame with optional debug diagnostic data.
    pub fn send_goaway_with_debug(
        &mut self,
        error_code: crate::simd_parser::Http2ErrorCode,
        debug_data: &[u8],
    ) -> io::Result<()> {
        let last_id = self.session.next_stream_id.saturating_sub(2);
        let goaway = crate::simd_parser::Http2Frame::GoAway {
            last_stream_id: last_id,
            error_code,
            debug_data: debug_data.to_vec(),
        };
        let res = self.send_frame(&goaway);
        self.is_closed = true;
        res
    }

    /// Gracefully close connection by sending a GOAWAY frame.
    pub fn send_goaway(
        &mut self,
        error_code: crate::simd_parser::Http2ErrorCode,
    ) -> io::Result<()> {
        self.send_goaway_with_debug(error_code, &[])
    }

    /// Retrieve the GOAWAY information received from peer, if any (last_stream_id, error_code, debug_data).
    pub fn last_received_goaway(&self) -> Option<(u32, crate::simd_parser::Http2ErrorCode, &[u8])> {
        self.session
            .last_received_goaway
            .as_ref()
            .map(|(sid, err, dbg)| (*sid, *err, dbg.as_slice()))
    }

    /// Read incoming frames until all active streams up to `last_stream_id` are completed
    /// or until the connection is fully closed. Any new streams initiated by peer beyond
    /// `last_stream_id` will be rejected with `StreamClosed` error.
    pub fn drain_graceful(&mut self, timeout_ms: u64) -> io::Result<()> {
        let start = std::time::Instant::now();
        let timeout = Duration::from_millis(timeout_ms);
        let mut spins = 0;

        loop {
            // Check if all existing streams in session are closed
            let all_closed = self
                .session
                .streams
                .values()
                .all(|s| s.state == crate::simd_parser::Http2StreamState::Closed);

            if all_closed || self.session.streams.is_empty() {
                return Ok(());
            }

            if start.elapsed() >= timeout {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Timed out waiting for HTTP/2 connection streams to drain gracefully",
                ));
            }

            if let Some(frame) = self.try_recv_frame()? {
                if let crate::simd_parser::Http2Frame::GoAway { error_code, .. } = frame {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        format!(
                            "Connection closed by peer GOAWAY during graceful drain: {:?}",
                            error_code
                        ),
                    ));
                }
            } else {
                if self.is_closed && self.read_buf.is_empty() {
                    return Ok(());
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

    /// Abort an active stream with a specific HTTP/2 error code and notify the peer via RST_STREAM.
    pub fn rst_stream(
        &mut self,
        stream_id: u32,
        error_code: crate::simd_parser::Http2ErrorCode,
    ) -> io::Result<()> {
        let frame = self.session.reset_stream(stream_id, error_code);
        self.send_frame(&frame)
    }

    /// Read incoming frames until the target stream is fully closed or reset, draining and discarding remaining frames.
    pub fn drain_stream(&mut self, target_stream_id: u32) -> io::Result<()> {
        let mut spins = 0;
        loop {
            if let Some(stream) = self.session.streams.get(&target_stream_id) {
                if stream.state == crate::simd_parser::Http2StreamState::Closed {
                    return Ok(());
                }
            } else {
                return Ok(());
            }

            if let Some(frame) = self.try_recv_frame()? {
                let frame_stream_id = match &frame {
                    crate::simd_parser::Http2Frame::Headers { stream_id, .. } => *stream_id,
                    crate::simd_parser::Http2Frame::Data { stream_id, .. } => *stream_id,
                    crate::simd_parser::Http2Frame::RstStream { stream_id, .. } => *stream_id,
                    crate::simd_parser::Http2Frame::GoAway { error_code, .. } => {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            format!("Connection closed by GOAWAY: {:?}", error_code),
                        ));
                    }
                    _ => 0,
                };

                if frame_stream_id == target_stream_id {
                    if let Some(stream) = self.session.streams.get(&target_stream_id) {
                        if stream.state == crate::simd_parser::Http2StreamState::Closed {
                            return Ok(());
                        }
                    }
                }
            } else {
                if self.is_closed && self.read_buf.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "HTTP/2 connection is closed during drain",
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

    /// Read incoming frames until the response for `target_stream_id` is fully received (headers and optional body).
    /// Returns the decoded headers and payload data.
    #[allow(clippy::type_complexity)]
    pub fn recv_response_for(
        &mut self,
        target_stream_id: u32,
    ) -> io::Result<(Vec<(String, String)>, Vec<u8>)> {
        loop {
            // Check if stream in session is already half-closed-remote or closed and has received headers
            if let Some(stream) = self.session.streams.get(&target_stream_id) {
                if stream.state == crate::simd_parser::Http2StreamState::HalfClosedRemote
                    || stream.state == crate::simd_parser::Http2StreamState::Closed
                {
                    return Ok((
                        stream.received_headers.clone(),
                        stream.received_data.clone(),
                    ));
                }
            }

            let frame = self.recv_frame()?;
            let frame_stream_id = match &frame {
                crate::simd_parser::Http2Frame::Headers { stream_id, .. } => *stream_id,
                crate::simd_parser::Http2Frame::Data { stream_id, .. } => *stream_id,
                crate::simd_parser::Http2Frame::RstStream {
                    stream_id,
                    error_code,
                } => {
                    if *stream_id == target_stream_id {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionReset,
                            format!("Stream {} reset with error {:?}", stream_id, error_code),
                        ));
                    }
                    *stream_id
                }
                crate::simd_parser::Http2Frame::GoAway { error_code, .. } => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        format!("Connection closed by GOAWAY: {:?}", error_code),
                    ));
                }
                _ => 0,
            };

            if frame_stream_id == target_stream_id {
                if let Some(stream) = self.session.streams.get(&target_stream_id) {
                    if stream.state == crate::simd_parser::Http2StreamState::HalfClosedRemote
                        || stream.state == crate::simd_parser::Http2StreamState::Closed
                    {
                        return Ok((
                            stream.received_headers.clone(),
                            stream.received_data.clone(),
                        ));
                    }
                }
            }
        }
    }

    /// High-level method: Send an HTTP request and await the full HTTP response.
    pub fn request(
        &mut self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> io::Result<crate::http::HttpResponse> {
        let mut pseudo_headers = vec![(":method", method), (":path", path), (":scheme", "http")];
        pseudo_headers.extend_from_slice(headers);

        let stream_id = self.send_request(&pseudo_headers, body)?;
        let (raw_headers, raw_body) = self.recv_response_for(stream_id)?;

        let mut status_code = 200u16;
        let mut resp_headers = crate::http::HttpHeaders::new();

        for (k, v) in raw_headers {
            if k == ":status" {
                if let Ok(code) = v.parse::<u16>() {
                    status_code = code;
                }
            } else if !k.starts_with(':') {
                resp_headers.set(k, v);
            }
        }

        // If trailers were received for this stream, also append them to response headers
        if let Some(trailers) = self.get_trailers(stream_id) {
            for (k, v) in trailers {
                if !k.starts_with(':') {
                    resp_headers.append(k, v);
                }
            }
        }

        let mut resp = crate::http::HttpResponse::new(crate::http::HttpStatus(status_code));
        resp.headers = resp_headers;
        resp.body = raw_body;

        // Transparent stream-level decompression if content-encoding is gzip or deflate
        if let Ok(decompressed) = resp.decompress_body() {
            resp.body = decompressed;
        }

        Ok(resp)
    }

    /// Server push: send a PUSH_PROMISE frame on an associated client stream to reserve a promised stream id,
    /// then send the promised response headers and optional body on the promised stream.
    pub fn push_promise(
        &mut self,
        associated_stream_id: u32,
        promised_request_headers: &[(&str, &str)],
        promised_response_headers: &[(&str, &str)],
        promised_body: Option<&[u8]>,
    ) -> io::Result<u32> {
        let promised_stream_id = self.session.open_stream();
        let frame = self.session.create_push_promise(
            associated_stream_id,
            promised_stream_id,
            promised_request_headers,
        );
        self.send_frame(&frame)?;

        self.send_response(promised_stream_id, promised_response_headers, promised_body)?;

        Ok(promised_stream_id)
    }

    /// Get all promised request headers for a given stream ID.
    pub fn get_push_promise_request(
        &self,
        promised_stream_id: u32,
    ) -> Option<&Vec<(String, String)>> {
        self.session.push_promises.get(&promised_stream_id)
    }

    /// Set stream priority and transmit a PRIORITY frame to the peer.
    pub fn set_priority(
        &mut self,
        stream_id: u32,
        stream_dependency: u32,
        weight: u8,
        exclusive: bool,
    ) -> io::Result<()> {
        let frame = crate::simd_parser::Http2Frame::Priority {
            stream_id,
            exclusive,
            stream_dependency,
            weight,
        };
        self.send_frame(&frame)?;
        self.session
            .set_stream_priority(stream_id, stream_dependency, weight, exclusive);
        Ok(())
    }

    /// Retrieve active stream IDs sorted in priority order (depth in dependency tree ascending, weight descending).
    pub fn prioritized_streams(&self) -> Vec<u32> {
        self.session.prioritized_stream_ids()
    }

    /// Send a PING frame with 8-byte opaque data.
    pub fn send_ping(&mut self, opaque_data: [u8; 8]) -> io::Result<()> {
        let frame = crate::simd_parser::Http2Frame::Ping {
            ack: false,
            opaque_data,
        };
        self.send_frame(&frame)
    }

    /// Send a PING frame and wait for the corresponding PING ACK response with matching payload.
    /// Yields cooperatively while waiting.
    pub fn ping(&mut self, opaque_data: [u8; 8]) -> io::Result<()> {
        self.send_ping(opaque_data)?;
        let mut spins = 0;
        loop {
            let frame = self.recv_frame()?;
            if let crate::simd_parser::Http2Frame::Ping {
                ack,
                opaque_data: resp_data,
            } = frame
            {
                if ack && resp_data == opaque_data {
                    return Ok(());
                }
            } else if let crate::simd_parser::Http2Frame::GoAway { error_code, .. } = frame {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    format!("Connection closed by GOAWAY: {:?}", error_code),
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

    /// Execute a batch of prioritized requests multiplexed over this single HTTP/2 connection.
    /// Sends PRIORITY frames for each stream, sends the requests concurrently,
    /// and collects responses in the order of the dependency tree and weights.
    pub fn execute_prioritized_batch(
        &mut self,
        requests: Vec<Http2PrioritizedRequest>,
    ) -> io::Result<Vec<(u32, io::Result<crate::http::HttpResponse>)>> {
        let mut stream_mappings = Vec::new();

        // 1. Dispatch requests and transmit PRIORITY frames
        for req in &requests {
            let mut pseudo_headers = vec![
                (":method", req.method.as_str()),
                (":path", req.path.as_str()),
                (":scheme", "http"),
            ];
            for (k, v) in &req.headers {
                pseudo_headers.push((k.as_str(), v.as_str()));
            }

            let stream_id = self.send_request(&pseudo_headers, req.body.as_deref())?;

            if req.stream_dependency != 0 || req.weight != 16 || req.exclusive {
                self.set_priority(stream_id, req.stream_dependency, req.weight, req.exclusive)?;
            }

            stream_mappings.push(stream_id);
        }

        // 2. Order stream collection according to RFC 7540 priority tree
        let prioritized_order = self.prioritized_streams();
        let mut ordered_streams = Vec::new();
        for &sid in &prioritized_order {
            if stream_mappings.contains(&sid) {
                ordered_streams.push(sid);
            }
        }
        for &sid in &stream_mappings {
            if !ordered_streams.contains(&sid) {
                ordered_streams.push(sid);
            }
        }

        // 3. Receive responses in prioritized order
        let mut results = Vec::new();
        for sid in ordered_streams {
            let res = self.recv_response_for(sid).map(|(raw_headers, raw_body)| {
                let mut status_code = 200u16;
                let mut resp_headers = crate::http::HttpHeaders::new();
                for (k, v) in raw_headers {
                    if k == ":status" {
                        if let Ok(code) = v.parse::<u16>() {
                            status_code = code;
                        }
                    } else if !k.starts_with(':') {
                        resp_headers.set(k, v);
                    }
                }
                let mut resp = crate::http::HttpResponse::new(crate::http::HttpStatus(status_code));
                resp.headers = resp_headers;
                resp.body = raw_body;
                if let Ok(decompressed) = resp.decompress_body() {
                    resp.body = decompressed;
                }
                resp
            });
            results.push((sid, res));
        }

        Ok(results)
    }

    /// Dynamically update local settings and transmit an outbound SETTINGS frame to the peer.
    pub fn send_settings(
        &mut self,
        settings: &[crate::simd_parser::Http2Setting],
    ) -> io::Result<()> {
        let frame = self.session.update_local_settings(settings);
        self.send_frame(&frame)
    }

    /// Retrieve a peer setting value if previously received and acknowledged.
    pub fn get_peer_setting(&self, id: crate::simd_parser::Http2SettingId) -> Option<u32> {
        self.session.get_peer_setting(id)
    }

    /// Retrieve a local setting value.
    pub fn get_local_setting(&self, id: crate::simd_parser::Http2SettingId) -> Option<u32> {
        self.session.get_local_setting(id)
    }

    /// Send trailing headers (Trailers) on an open stream, terminating the stream (RFC 7540 Section 8.1.2.6).
    pub fn send_trailers(&mut self, stream_id: u32, trailers: &[(&str, &str)]) -> io::Result<()> {
        let frame = self.session.create_trailers_frame(stream_id, trailers);
        self.send_frame(&frame)
    }

    /// Retrieve decoded trailing headers (Trailers) received on a stream, if any.
    pub fn get_trailers(&self, stream_id: u32) -> Option<Vec<(String, String)>> {
        self.session
            .streams
            .get(&stream_id)
            .map(|s| s.received_trailers.clone())
    }
}

/// Parameters for configuring a prioritized HTTP/2 request in a multiplexed batch.
#[derive(Debug, Clone)]
pub struct Http2PrioritizedRequest {
    /// HTTP Method (GET, POST, etc.)
    pub method: String,
    /// Request target path and query
    pub path: String,
    /// Additional request headers
    pub headers: Vec<(String, String)>,
    /// Optional request payload
    pub body: Option<Vec<u8>>,
    /// Stream dependency ID (0 for root)
    pub stream_dependency: u32,
    /// Stream weight (1 to 256, standard RFC 7540)
    pub weight: u8,
    /// Exclusive dependency flag
    pub exclusive: bool,
}

impl Http2PrioritizedRequest {
    /// Create a new prioritized request with defaults (root dependency, default weight 16).
    pub fn new(method: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            path: path.into(),
            headers: Vec::new(),
            body: None,
            stream_dependency: 0,
            weight: 16,
            exclusive: false,
        }
    }

    /// Add a request header.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Set request body payload.
    pub fn with_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = Some(body.into());
        self
    }

    /// Set stream dependency tree settings.
    pub fn with_priority(mut self, stream_dependency: u32, weight: u8, exclusive: bool) -> Self {
        self.stream_dependency = stream_dependency;
        self.weight = weight;
        self.exclusive = exclusive;
        self
    }
}

/// Representation of an outgoing request passed through HTTP/2 interceptors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Http2ClientRequest {
    /// HTTP method (e.g., "GET", "POST").
    pub method: String,
    /// Request target path and query (e.g., "/api/data?q=1").
    pub path: String,
    /// List of HTTP headers as (name, value) pairs.
    pub headers: Vec<(String, String)>,
    /// Optional binary body payload.
    pub body: Option<Vec<u8>>,
}

impl Http2ClientRequest {
    /// Create a new client request with method and path.
    pub fn new(method: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            path: path.into(),
            headers: Vec::new(),
            body: None,
        }
    }

    /// Add a request header.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Set binary payload body.
    pub fn with_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = Some(body.into());
        self
    }
}

/// HTTP/2 request interceptor invoked before dispatching a request to the server.
/// Can modify headers/body, or return `Some(HttpResponse)` to short-circuit without network I/O.
pub type Http2RequestInterceptor = std::sync::Arc<
    dyn Fn(&mut Http2ClientRequest) -> Option<crate::http::HttpResponse> + Send + Sync,
>;

/// HTTP/2 response interceptor invoked after receiving a response from the server.
/// Can inspect or mutate response status, headers, or body.
pub type Http2ResponseInterceptor =
    std::sync::Arc<dyn Fn(&Http2ClientRequest, &mut crate::http::HttpResponse) + Send + Sync>;

/// Instantaneous diagnostic telemetry and runtime metrics for an [`AsyncHttp2Pool`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Http2PoolStats {
    /// Number of connections currently idle and available in the pool.
    pub idle_connections: usize,
    /// Number of connections actively in use or establishing.
    pub active_connections: usize,
    /// Maximum configured connection limit for this pool.
    pub max_connections: usize,
    /// Maximum concurrent multiplexed streams per connection.
    pub max_concurrent_streams_per_conn: usize,
    /// Most recent GOAWAY error code observed across connections in this pool, if any.
    pub last_goaway_error: Option<crate::simd_parser::Http2ErrorCode>,
    /// Last negotiated ALPN protocol observed during TLS connection handshake, if any.
    pub last_alpn_negotiated: Option<AlpnProtocol>,
    /// Total number of idle connections evicted by TTL expiration or capacity bounds.
    pub evicted_connections: usize,
}

impl Http2PoolStats {
    /// Whether the pool is currently running at its maximum configured connection capacity.
    #[inline]
    pub fn is_exhausted(&self) -> bool {
        self.active_connections >= self.max_connections
    }

    /// Total number of connections tracked by the pool (idle + active in-use).
    #[inline]
    pub fn total_connections(&self) -> usize {
        self.idle_connections + self.active_connections
    }
}

/// An idle pooled HTTP/2 connection paired with the timestamp at which it became idle.
struct PooledConnectionEntry {
    conn: AsyncHttp2Connection,
    idle_since: std::time::Instant,
}

/// Transparently manages connection pooling, multiplexing limits, idle connection reuse,
/// and multiplexed request execution across shared or pooled HTTP/2 connections.
pub struct AsyncHttp2Pool {
    host: String,
    port: u16,
    max_connections: usize,
    max_concurrent_streams_per_conn: usize,
    idle_ttl: Option<std::time::Duration>,
    idle_pool: std::sync::Mutex<Vec<PooledConnectionEntry>>,
    active_count: std::sync::atomic::AtomicUsize,
    evicted_count: std::sync::atomic::AtomicUsize,
    last_goaway_error: std::sync::Mutex<Option<crate::simd_parser::Http2ErrorCode>>,
    last_alpn_negotiated: std::sync::Mutex<Option<AlpnProtocol>>,
    tls_config: Option<TlsConfig>,
    request_interceptors: Vec<Http2RequestInterceptor>,
    response_interceptors: Vec<Http2ResponseInterceptor>,
}

impl AsyncHttp2Pool {
    /// Default maximum concurrent streams permitted per single HTTP/2 connection.
    pub const DEFAULT_MAX_STREAMS: usize = 100;

    /// Create a new HTTP/2 client connection pool.
    pub fn new(host: impl Into<String>, port: u16, max_connections: usize) -> Self {
        Self {
            host: host.into(),
            port,
            max_connections: max_connections.max(1),
            max_concurrent_streams_per_conn: Self::DEFAULT_MAX_STREAMS,
            idle_ttl: None,
            idle_pool: std::sync::Mutex::new(Vec::new()),
            active_count: std::sync::atomic::AtomicUsize::new(0),
            evicted_count: std::sync::atomic::AtomicUsize::new(0),
            last_goaway_error: std::sync::Mutex::new(None),
            last_alpn_negotiated: std::sync::Mutex::new(None),
            tls_config: None,
            request_interceptors: Vec::new(),
            response_interceptors: Vec::new(),
        }
    }

    /// Configure an idle connection TTL (Time-To-Live).
    /// Connections that have remained idle longer than `ttl` will be discarded upon checkout or sweep.
    pub fn with_idle_ttl(mut self, ttl: std::time::Duration) -> Self {
        self.idle_ttl = Some(ttl);
        self
    }

    /// Configure TLS/ALPN negotiation configuration for connections established by this pool.
    pub fn with_tls_config(mut self, config: TlsConfig) -> Self {
        self.tls_config = Some(config);
        self
    }

    /// Register a request interceptor / middleware executed prior to dispatching each HTTP/2 request.
    /// Interceptors run in the order they were registered.
    pub fn with_request_interceptor(
        mut self,
        interceptor: impl Fn(&mut Http2ClientRequest) -> Option<crate::http::HttpResponse>
            + Send
            + Sync
            + 'static,
    ) -> Self {
        self.request_interceptors
            .push(std::sync::Arc::new(interceptor));
        self
    }

    /// Register a response interceptor / middleware executed after receiving a response.
    /// Interceptors run in the order they were registered.
    pub fn with_response_interceptor(
        mut self,
        interceptor: impl Fn(&Http2ClientRequest, &mut crate::http::HttpResponse)
            + Send
            + Sync
            + 'static,
    ) -> Self {
        self.response_interceptors
            .push(std::sync::Arc::new(interceptor));
        self
    }

    /// Add a request interceptor to an existing pool instance.
    pub fn add_request_interceptor(
        &mut self,
        interceptor: impl Fn(&mut Http2ClientRequest) -> Option<crate::http::HttpResponse>
            + Send
            + Sync
            + 'static,
    ) -> &mut Self {
        self.request_interceptors
            .push(std::sync::Arc::new(interceptor));
        self
    }

    /// Add a response interceptor to an existing pool instance.
    pub fn add_response_interceptor(
        &mut self,
        interceptor: impl Fn(&Http2ClientRequest, &mut crate::http::HttpResponse)
            + Send
            + Sync
            + 'static,
    ) -> &mut Self {
        self.response_interceptors
            .push(std::sync::Arc::new(interceptor));
        self
    }

    /// Number of registered request interceptors.
    #[inline]
    pub fn request_interceptor_count(&self) -> usize {
        self.request_interceptors.len()
    }

    /// Number of registered response interceptors.
    #[inline]
    pub fn response_interceptor_count(&self) -> usize {
        self.response_interceptors.len()
    }

    /// Configure maximum concurrent multiplexed streams per connection.
    pub fn with_max_concurrent_streams(mut self, max_streams: usize) -> Self {
        self.max_concurrent_streams_per_conn = max_streams.max(1);
        self
    }

    /// Number of currently idle pooled connections.
    pub fn idle_count(&self) -> usize {
        self.idle_pool.lock().map(|p| p.len()).unwrap_or(0)
    }

    /// Total count of active (checked-out or connecting) connections.
    pub fn active_count(&self) -> usize {
        self.active_count.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Total count of idle connections evicted by TTL or capacity bounds.
    pub fn evicted_count(&self) -> usize {
        self.evicted_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Snapshot the current runtime metrics and diagnostic telemetry of the pool.
    pub fn stats(&self) -> Http2PoolStats {
        Http2PoolStats {
            idle_connections: self.idle_count(),
            active_connections: self.active_count(),
            max_connections: self.max_connections,
            max_concurrent_streams_per_conn: self.max_concurrent_streams_per_conn,
            last_goaway_error: self.last_goaway_error(),
            last_alpn_negotiated: self.last_alpn_negotiated(),
            evicted_connections: self.evicted_count(),
        }
    }

    /// Acquire an active HTTP/2 connection from the pool, or establish a new connection if below capacity.
    ///
    /// Idle connections are reused in LRU/MRU order (most recently used popped first),
    /// and any connections exceeding `idle_ttl` or found dead/closed/GOAWAY are evicted.
    pub fn acquire(&self) -> io::Result<AsyncHttp2Connection> {
        let now = std::time::Instant::now();
        if let Ok(mut pool) = self.idle_pool.lock() {
            while let Some(entry) = pool.pop() {
                let mut conn = entry.conn;
                // Check TTL expiration
                if let Some(ttl) = self.idle_ttl {
                    if now.duration_since(entry.idle_since) > ttl {
                        self.evicted_count
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        continue;
                    }
                }
                // If the connection was already marked closed or received a GOAWAY, record error and discard it
                if let Some((_, err, _)) = conn.last_received_goaway() {
                    if let Ok(mut last_err) = self.last_goaway_error.lock() {
                        *last_err = Some(err);
                    }
                    continue;
                }
                if conn.is_closed() {
                    continue;
                }
                // Drain any pending buffered frames (e.g. late GOAWAY or SETTINGS)
                let _ = conn.try_recv_frame();
                if let Some((_, err, _)) = conn.last_received_goaway() {
                    if let Ok(mut last_err) = self.last_goaway_error.lock() {
                        *last_err = Some(err);
                    }
                    continue;
                }
                if conn.is_closed() {
                    continue;
                }
                // Quick health check ping
                if conn.send_ping(*b"h2_probe").is_ok() {
                    self.active_count
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return Ok(conn);
                }
            }
        }

        let current = self.active_count.load(std::sync::atomic::Ordering::Relaxed);
        if current >= self.max_connections {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "HTTP/2 connection pool capacity exhausted",
            ));
        }

        let stream = AsyncTcpStream::connect(format!("{}:{}", self.host, self.port))?;
        if let Some(ref tls_cfg) = self.tls_config {
            let negotiator = AlpnNegotiator::new(tls_cfg.clone());
            let negotiated = negotiator.negotiate(&tls_cfg.server_protocols);
            if let Some(proto) = negotiated.protocol() {
                self.record_alpn_negotiated(proto);
                if !proto.supports_multiplexing() {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        format!(
                            "ALPN negotiated non-HTTP/2 protocol ({}) in HTTP/2 pool",
                            proto
                        ),
                    ));
                }
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "ALPN negotiation failed: no matching protocol supported",
                ));
            }
        } else {
            self.record_alpn_negotiated(AlpnProtocol::Http2);
        }

        let conn = AsyncHttp2Connection::client_handshake(stream)?;

        self.active_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(conn)
    }

    /// Return an HTTP/2 connection back to the pool if healthy and within capacity.
    /// Connections marked as closed or having received a peer GOAWAY are automatically discarded,
    /// with any GOAWAY error recorded on the pool.
    pub fn release(&self, mut conn: AsyncHttp2Connection) {
        self.active_count
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);

        // Check if any pending frames on wire indicate GOAWAY
        let _ = conn.try_recv_frame();

        if let Some((_, err, _)) = conn.last_received_goaway() {
            if let Ok(mut last_err) = self.last_goaway_error.lock() {
                *last_err = Some(err);
            }
            return;
        }

        if !conn.is_closed() {
            if let Ok(mut pool) = self.idle_pool.lock() {
                // Evict oldest (LRU, index 0) if at capacity bound before inserting new idle entry
                while pool.len() >= self.max_connections {
                    pool.remove(0);
                    self.evicted_count
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                pool.push(PooledConnectionEntry {
                    conn,
                    idle_since: std::time::Instant::now(),
                });
            }
        }
    }

    /// Execute a batch of prioritized requests multiplexed over an acquired pooled connection,
    /// returning the connection to the pool after execution completes.
    pub fn execute_prioritized_batch(
        &self,
        requests: Vec<Http2PrioritizedRequest>,
    ) -> io::Result<Vec<(u32, io::Result<crate::http::HttpResponse>)>> {
        if requests.is_empty() {
            return Ok(Vec::new());
        }

        let mut conn = self.acquire()?;
        let result = conn.execute_prioritized_batch(requests);
        match result {
            Ok(responses) => {
                self.release(conn);
                Ok(responses)
            }
            Err(e) => {
                self.active_count
                    .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                Err(e)
            }
        }
    }

    /// Execute an HTTP/2 request transparently using a pooled connection, returning the connection to the pool.
    ///
    /// If request interceptors are registered on the pool, they are executed in order.
    /// If an interceptor returns `Some(HttpResponse)`, the network call is short-circuited
    /// and that response is returned immediately (still running any registered response interceptors).
    ///
    /// Any registered response interceptors are executed on the resulting response before returning.
    pub fn execute_request(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> io::Result<crate::http::HttpResponse> {
        let mut client_req = Http2ClientRequest::new(method, path);
        for &(k, v) in headers {
            client_req = client_req.with_header(k, v);
        }
        if let Some(b) = body {
            client_req = client_req.with_body(b);
        }

        // Run request interceptors
        for interceptor in &self.request_interceptors {
            if let Some(mut short_circuit_resp) = interceptor(&mut client_req) {
                // Run response interceptors on short-circuited response
                for resp_interceptor in &self.response_interceptors {
                    resp_interceptor(&client_req, &mut short_circuit_resp);
                }
                return Ok(short_circuit_resp);
            }
        }

        let mut conn = self.acquire()?;
        let header_refs: Vec<(&str, &str)> = client_req
            .headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let body_ref = client_req.body.as_deref();

        let result = conn.request(&client_req.method, &client_req.path, &header_refs, body_ref);
        match result {
            Ok(mut resp) => {
                self.release(conn);
                for resp_interceptor in &self.response_interceptors {
                    resp_interceptor(&client_req, &mut resp);
                }
                Ok(resp)
            }
            Err(e) => {
                // If connection failed, it is dropped and not released back to the pool
                self.active_count
                    .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                Err(e)
            }
        }
    }

    /// Clear all idle connections in the pool.
    pub fn clear(&self) {
        if let Ok(mut pool) = self.idle_pool.lock() {
            pool.clear();
        }
    }

    /// Gracefully shutdown all pooled idle connections by sending GOAWAY frames.
    pub fn shutdown(&self) {
        if let Ok(mut pool) = self.idle_pool.lock() {
            for mut entry in pool.drain(..) {
                let _ = entry
                    .conn
                    .send_goaway(crate::simd_parser::Http2ErrorCode::NoError);
            }
        }
    }

    /// Gracefully shutdown all pooled idle connections by sending GOAWAY frames and
    /// draining in-flight streams up to `timeout_ms` per connection.
    pub fn drain_and_shutdown(&self, timeout_ms: u64) {
        if let Ok(mut pool) = self.idle_pool.lock() {
            for mut entry in pool.drain(..) {
                let _ = entry
                    .conn
                    .send_goaway(crate::simd_parser::Http2ErrorCode::NoError);
                let _ = entry.conn.drain_graceful(timeout_ms);
            }
        }
    }

    /// Health-check all idle connections in the pool by transmitting PING frames,
    /// removing any dead, closed, or GOAWAY-received connections and recording errors.
    pub fn health_check(&self) -> usize {
        let mut healthy = Vec::new();
        let mut closed_count = 0;

        if let Ok(mut pool) = self.idle_pool.lock() {
            let entries: Vec<PooledConnectionEntry> = pool.drain(..).collect();
            for mut entry in entries {
                // Check if any frame (e.g. GOAWAY) arrived on wire
                let _ = entry.conn.try_recv_frame();
                if let Some((_, err, _)) = entry.conn.last_received_goaway() {
                    if let Ok(mut last_err) = self.last_goaway_error.lock() {
                        *last_err = Some(err);
                    }
                    closed_count += 1;
                    continue;
                }
                if !entry.conn.is_closed() && entry.conn.send_ping(*b"h2_probe").is_ok() {
                    healthy.push(entry);
                } else {
                    closed_count += 1;
                }
            }
            *pool = healthy;
        }

        closed_count
    }

    /// Sweep and evict any idle connections whose idle duration exceeds `ttl` (or configured pool `idle_ttl`).
    /// Returns the number of connections evicted during the sweep.
    pub fn sweep_idle_connections(&self, custom_ttl: Option<std::time::Duration>) -> usize {
        let ttl_to_use = custom_ttl.or(self.idle_ttl);
        let Some(ttl) = ttl_to_use else {
            return 0;
        };

        let now = std::time::Instant::now();
        let mut evicted = 0;
        if let Ok(mut pool) = self.idle_pool.lock() {
            let mut retained = Vec::with_capacity(pool.len());
            for entry in pool.drain(..) {
                if now.duration_since(entry.idle_since) > ttl {
                    evicted += 1;
                } else {
                    retained.push(entry);
                }
            }
            *pool = retained;
        }

        if evicted > 0 {
            self.evicted_count
                .fetch_add(evicted, std::sync::atomic::Ordering::Relaxed);
        }
        evicted
    }

    /// Retrieve the most recently observed HTTP/2 GOAWAY error code received across pooled connections.
    pub fn last_goaway_error(&self) -> Option<crate::simd_parser::Http2ErrorCode> {
        self.last_goaway_error.lock().ok().and_then(|g| *g)
    }

    /// Reset or clear the recorded last GOAWAY error code.
    pub fn clear_goaway_error(&self) {
        if let Ok(mut g) = self.last_goaway_error.lock() {
            *g = None;
        }
    }

    /// Retrieve the last negotiated ALPN protocol observed across connections in this pool.
    pub fn last_alpn_negotiated(&self) -> Option<AlpnProtocol> {
        self.last_alpn_negotiated.lock().ok().and_then(|p| *p)
    }

    /// Record an observed ALPN negotiated protocol outcome for diagnostic monitoring.
    pub fn record_alpn_negotiated(&self, protocol: AlpnProtocol) {
        if let Ok(mut slot) = self.last_alpn_negotiated.lock() {
            *slot = Some(protocol);
        }
    }

    /// Reset or clear the recorded ALPN negotiated protocol.
    pub fn clear_alpn_negotiated(&self) {
        if let Ok(mut slot) = self.last_alpn_negotiated.lock() {
            *slot = None;
        }
    }

    /// Execute an HTTP/2 request with automatic retry on retryable GOAWAY errors.
    ///
    /// When a connection is refused or a retryable GOAWAY (`NoError`, `RefusedStream`, `Cancel`)
    /// is detected, the method transparently establishes a fresh connection and retries the request,
    /// up to `max_retries` additional attempts (total attempts = `max_retries + 1`).
    ///
    /// A fatal protocol violation (`ProtocolError`, `CompressionError`, etc.) or
    /// a rate-limit signal (`EnhanceYourCalm`) is never retried — the error is returned immediately.
    ///
    /// Returns `Err` only if all attempts are exhausted or a non-retryable error is encountered.
    pub fn execute_request_with_retry(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
        max_retries: usize,
    ) -> io::Result<crate::http::HttpResponse> {
        let mut last_err: Option<io::Error> = None;
        for attempt in 0..=max_retries {
            // Before acquiring: if a fatal or rate-limit GOAWAY was recorded, bail immediately
            if let Some(err_code) = self.last_goaway_error() {
                if err_code.is_fatal_protocol_violation() || err_code.is_rate_limit_or_calm() {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        format!(
                            "HTTP/2 pool: non-retryable GOAWAY received ({})",
                            err_code.name()
                        ),
                    ));
                }
                // Retryable GOAWAY — clear and continue
                self.clear_goaway_error();
            }

            match self.execute_request(method, path, headers, body) {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    // Check if the error is a retryable GOAWAY
                    let goaway_retryable = self
                        .last_goaway_error()
                        .map(|ec| ec.is_retryable())
                        .unwrap_or(false);

                    if !goaway_retryable && attempt == max_retries {
                        return Err(e);
                    }
                    if !goaway_retryable {
                        // Non-GOAWAY transient error (e.g. WouldBlock / connection reset)
                        // only retry if it looks like a connectivity issue
                        match e.kind() {
                            io::ErrorKind::ConnectionRefused
                            | io::ErrorKind::ConnectionReset
                            | io::ErrorKind::BrokenPipe
                            | io::ErrorKind::TimedOut => {}
                            _ => return Err(e),
                        }
                    }
                    self.clear_goaway_error();
                    last_err = Some(e);
                    // Brief linear back-off: 10 ms × (attempt + 1)
                    std::thread::sleep(std::time::Duration::from_millis(10 * (attempt as u64 + 1)));
                }
            }
        }
        Err(last_err.unwrap_or_else(|| io::Error::other("HTTP/2 retry exhausted")))
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

pub use crate::http::SseEvent;

/// Server-Sent Events (SSE) incremental stream decoder / parser.
/// Parses incoming continuous chunks of `text/event-stream` data into discrete `SseEvent` messages.
#[derive(Debug, Default, Clone)]
pub struct SseDecoder {
    buffer: String,
    last_event_id: Option<String>,
}

impl SseDecoder {
    /// Create a new SSE decoder.
    pub fn new() -> Self {
        Self {
            buffer: String::new(),
            last_event_id: None,
        }
    }

    /// Get the most recently observed `id:` field (Last-Event-ID).
    pub fn last_event_id(&self) -> Option<&str> {
        self.last_event_id.as_deref()
    }

    /// Ingest a string chunk into the decoder buffer.
    pub fn push_str(&mut self, chunk: &str) {
        self.buffer.push_str(chunk);
    }

    /// Ingest raw bytes (interpreted as UTF-8 lossy) into the decoder buffer.
    pub fn push_bytes(&mut self, bytes: &[u8]) {
        self.buffer.push_str(&String::from_utf8_lossy(bytes));
    }

    /// Extract and decode the next complete `SseEvent` if available in the buffer.
    pub fn next_event(&mut self) -> Option<SseEvent> {
        // SSE blocks are delimited by two consecutive newlines ("\n\n" or "\r\n\r\n")
        let end_idx = if let Some(idx) = self.buffer.find("\r\n\r\n") {
            Some((idx, 4))
        } else {
            self.buffer.find("\n\n").map(|idx| (idx, 2))
        };

        if let Some((idx, delim_len)) = end_idx {
            let block = self.buffer[..idx].to_string();
            self.buffer.drain(..idx + delim_len);
            if self.buffer.is_empty()
                && self.buffer.capacity() > DEFAULT_MAX_RETAINED_BUFFER_CAPACITY
            {
                self.buffer.shrink_to(DEFAULT_MAX_RETAINED_BUFFER_CAPACITY);
            }

            let mut event_name: Option<String> = None;
            let mut data_lines = Vec::new();
            let mut id: Option<String> = None;
            let mut retry: Option<u64> = None;
            let mut comment_lines = Vec::new();

            for line in block.lines() {
                let trimmed_line = line.trim_end_matches('\r');
                if trimmed_line.is_empty() {
                    continue;
                }

                if let Some(stripped) = trimmed_line.strip_prefix(':') {
                    // Comment line
                    comment_lines.push(stripped.trim_start().to_string());
                } else if let Some(stripped) = trimmed_line.strip_prefix("event:") {
                    event_name = Some(stripped.trim_start().to_string());
                } else if let Some(stripped) = trimmed_line.strip_prefix("data:") {
                    data_lines.push(stripped.trim_start().to_string());
                } else if let Some(stripped) = trimmed_line.strip_prefix("id:") {
                    let parsed_id = stripped.trim_start().to_string();
                    self.last_event_id = Some(parsed_id.clone());
                    id = Some(parsed_id);
                } else if let Some(stripped) = trimmed_line.strip_prefix("retry:") {
                    if let Ok(ms) = stripped.trim_start().parse::<u64>() {
                        retry = Some(ms);
                    }
                }
            }

            // A valid SSE event must have at least data, comment, or event name
            if !data_lines.is_empty()
                || !comment_lines.is_empty()
                || event_name.is_some()
                || id.is_some()
            {
                let data = data_lines.join("\n");
                let comment = if !comment_lines.is_empty() {
                    Some(comment_lines.join("\n"))
                } else {
                    None
                };

                return Some(SseEvent {
                    event: event_name,
                    data,
                    id,
                    retry,
                    comment,
                });
            }
        }

        None
    }
}

/// Snapshot statistics and telemetry for an `AsyncSseClient` session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseClientStats {
    /// Number of discrete events successfully decoded and yielded to the client.
    pub events_received: u64,
    /// Total raw bytes ingested from the TCP transport.
    pub bytes_received: u64,
    /// Last known event ID dispatched or tracked on this connection, if any.
    pub last_event_id: Option<String>,
    /// Number of bytes currently unparsed in the decoder buffer.
    pub buffered_bytes: usize,
}

/// Snapshot statistics and telemetry for an `AsyncSseServer` session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseServerStats {
    /// Total events sent to the client.
    pub events_sent: u64,
    /// Total heartbeat comment frames sent.
    pub heartbeats_sent: u64,
    /// Total wire bytes transmitted over the TCP stream.
    pub bytes_sent: u64,
    /// Last event ID transmitted, if any.
    pub last_event_id: Option<String>,
}

/// Asynchronous Server-Sent Events (SSE) Client over colorless fibers (`AsyncTcpStream`).
pub struct AsyncSseClient {
    stream: AsyncTcpStream,
    decoder: SseDecoder,
    events_received: u64,
    bytes_received: u64,
}

impl AsyncSseClient {
    /// Create an `AsyncSseClient` wrapping an established `AsyncTcpStream`.
    pub fn new(stream: AsyncTcpStream) -> Self {
        Self {
            stream,
            decoder: SseDecoder::new(),
            events_received: 0,
            bytes_received: 0,
        }
    }

    /// Read next `SseEvent` cooperatively without blocking the operating system thread.
    pub fn read_event(&mut self) -> io::Result<Option<SseEvent>> {
        let mut spins = 0;
        let mut chunk = [0u8; 1024];

        loop {
            if let Some(event) = self.decoder.next_event() {
                self.events_received += 1;
                return Ok(Some(event));
            }

            match self.stream.try_read(&mut chunk) {
                Ok(Some(n)) if n > 0 => {
                    self.bytes_received += n as u64;
                    self.decoder.push_bytes(&chunk[..n]);
                    spins = 0;
                    if let Some(event) = self.decoder.next_event() {
                        self.events_received += 1;
                        return Ok(Some(event));
                    }
                }
                Ok(Some(0)) => {
                    // Stream closed; check if trailing event exists
                    let trailing = self.decoder.next_event();
                    if trailing.is_some() {
                        self.events_received += 1;
                    }
                    return Ok(trailing);
                }
                Ok(Some(_)) | Ok(None) => {}
                Err(e) => return Err(e),
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

    /// Return the last known event ID seen on this connection.
    pub fn last_event_id(&self) -> Option<&str> {
        self.decoder.last_event_id()
    }

    /// Number of bytes currently pending in the unparsed decoder buffer.
    pub fn buffered_bytes(&self) -> usize {
        self.decoder.buffer.len()
    }

    /// Number of events successfully received and dispatched.
    pub fn events_received(&self) -> u64 {
        self.events_received
    }

    /// Total number of raw stream bytes received from the network.
    pub fn bytes_received(&self) -> u64 {
        self.bytes_received
    }

    /// Returns a telemetry snapshot of client metrics.
    pub fn stats(&self) -> SseClientStats {
        SseClientStats {
            events_received: self.events_received,
            bytes_received: self.bytes_received,
            last_event_id: self.decoder.last_event_id.clone(),
            buffered_bytes: self.buffered_bytes(),
        }
    }

    /// Return local socket address if available.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.stream.local_addr()
    }

    /// Return remote peer address if available.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.stream.peer_addr()
    }
}

/// Asynchronous Server-Sent Events (SSE) Server stream over colorless fibers (`AsyncTcpStream`).
pub struct AsyncSseServer {
    stream: AsyncTcpStream,
    events_sent: u64,
    heartbeats_sent: u64,
    bytes_sent: u64,
    last_event_id: Option<String>,
}

impl AsyncSseServer {
    /// Initialize an HTTP response for SSE streaming (`text/event-stream`, `Cache-Control: no-cache`, `Connection: keep-alive`).
    pub fn init_response(mut stream: AsyncTcpStream) -> io::Result<Self> {
        let response_headers = concat!(
            "HTTP/1.1 200 OK\r\n",
            "Content-Type: text/event-stream\r\n",
            "Cache-Control: no-cache\r\n",
            "Connection: keep-alive\r\n",
            "X-Accel-Buffering: no\r\n",
            "\r\n"
        );
        stream.write_all(response_headers.as_bytes())?;
        let bytes_sent = response_headers.len() as u64;
        Ok(Self {
            stream,
            events_sent: 0,
            heartbeats_sent: 0,
            bytes_sent,
            last_event_id: None,
        })
    }

    /// Wrap an existing stream already initialized with headers.
    pub fn from_raw_stream(stream: AsyncTcpStream) -> Self {
        Self {
            stream,
            events_sent: 0,
            heartbeats_sent: 0,
            bytes_sent: 0,
            last_event_id: None,
        }
    }

    /// Send an `SseEvent` to the client.
    pub fn send_event(&mut self, event: &SseEvent) -> io::Result<()> {
        let payload = event.to_wire_string();
        let bytes = payload.as_bytes();
        self.stream.write_all(bytes)?;
        self.bytes_sent += bytes.len() as u64;
        self.events_sent += 1;
        if let Some(ref id) = event.id {
            self.last_event_id = Some(id.clone());
        }
        Ok(())
    }

    /// Send a keep-alive comment heartbeat `: ping\n\n`.
    pub fn send_heartbeat(&mut self) -> io::Result<()> {
        let ping_bytes = b": ping\n\n";
        self.stream.write_all(ping_bytes)?;
        self.bytes_sent += ping_bytes.len() as u64;
        self.heartbeats_sent += 1;
        Ok(())
    }

    /// Send raw text data as a default event.
    pub fn send_data(&mut self, data: &str) -> io::Result<()> {
        self.send_event(&SseEvent::new(data))
    }

    /// Return total events dispatched to client.
    pub fn events_sent(&self) -> u64 {
        self.events_sent
    }

    /// Return total heartbeats sent to client.
    pub fn heartbeats_sent(&self) -> u64 {
        self.heartbeats_sent
    }

    /// Return total bytes transmitted over wire.
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent
    }

    /// Return last event ID transmitted if any.
    pub fn last_event_id(&self) -> Option<&str> {
        self.last_event_id.as_deref()
    }

    /// Returns a telemetry snapshot of server metrics.
    pub fn stats(&self) -> SseServerStats {
        SseServerStats {
            events_sent: self.events_sent,
            heartbeats_sent: self.heartbeats_sent,
            bytes_sent: self.bytes_sent,
            last_event_id: self.last_event_id.clone(),
        }
    }

    /// Return local socket address if available.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.stream.local_addr()
    }

    /// Return remote peer address if available.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.stream.peer_addr()
    }
}

/// Unique identifier for a session registered in `EventHub`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionId(pub u64);

/// Message payload that can be published to topic channels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HubMessage {
    /// Text message.
    Text(String),
    /// Binary data.
    Binary(Vec<u8>),
    /// Server-Sent Event representation.
    Sse(SseEvent),
}

impl HubMessage {
    pub fn text(s: impl Into<String>) -> Self {
        HubMessage::Text(s.into())
    }

    pub fn binary(b: impl Into<Vec<u8>>) -> Self {
        HubMessage::Binary(b.into())
    }

    pub fn sse(event: SseEvent) -> Self {
        HubMessage::Sse(event)
    }

    /// Return bytes suitable for raw stream or SSE transmission.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            HubMessage::Text(s) => s.as_bytes().to_vec(),
            HubMessage::Binary(b) => b.clone(),
            HubMessage::Sse(evt) => evt.to_wire_string().into_bytes(),
        }
    }
}

/// Outgoing sink for a registered pub/sub session.
pub enum SessionSink {
    /// An asynchronous TCP writer half (`AsyncTcpWriteHalf`).
    Tcp(AsyncTcpWriteHalf),
    /// Raw `AsyncTcpStream` clone.
    Stream(AsyncTcpStream),
    /// WebSocket connection.
    Ws(AsyncWsConnection),
    /// Server-Sent Events output.
    Sse(AsyncSseServer),
}

impl SessionSink {
    /// Deliver a `HubMessage` to this sink.
    pub fn deliver(&mut self, msg: &HubMessage) -> io::Result<()> {
        match self {
            SessionSink::Tcp(w) => {
                let bytes = msg.to_bytes();
                w.write_all(&bytes)?;
                w.flush()
            }
            SessionSink::Stream(s) => {
                let bytes = msg.to_bytes();
                s.write_all(&bytes)?;
                s.flush()
            }
            SessionSink::Ws(ws) => match msg {
                HubMessage::Text(t) => ws.send_text(t),
                HubMessage::Binary(b) => ws.send_binary(b),
                HubMessage::Sse(evt) => ws.send_text(&evt.to_wire_string()),
            },
            SessionSink::Sse(sse) => match msg {
                HubMessage::Sse(evt) => sse.send_event(evt),
                HubMessage::Text(t) => sse.send_data(t),
                HubMessage::Binary(b) => {
                    let hex = format!("hex:{}", crate::crypto::hex_encode(b));
                    sse.send_data(&hex)
                }
            },
        }
    }
}

struct SessionEntry {
    sink: Mutex<SessionSink>,
    topics: RwLock<HashSet<String>>,
}

/// In-memory pub/sub broker and channel multiplexer across active sessions.
///
/// Supports subscribing sessions to topic channels, broadcasting messages,
/// unicast delivery to specific sessions, and auto-cleanup of disconnected sessions.
#[derive(Clone)]
pub struct EventHub {
    next_id: Arc<AtomicU64>,
    sessions: Arc<RwLock<HashMap<SessionId, Arc<SessionEntry>>>>,
    topics: Arc<RwLock<HashMap<String, HashSet<SessionId>>>>,
}

impl Default for EventHub {
    fn default() -> Self {
        Self::new()
    }
}

impl EventHub {
    /// Create a new, empty pub/sub broker.
    pub fn new() -> Self {
        Self {
            next_id: Arc::new(AtomicU64::new(1)),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            topics: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a new session with an initial sink and optional initial topics.
    pub fn register(&self, sink: SessionSink, initial_topics: &[&str]) -> SessionId {
        let id = SessionId(self.next_id.fetch_add(1, Ordering::Relaxed));
        let mut topic_set = HashSet::new();
        for &t in initial_topics {
            topic_set.insert(t.to_string());
        }

        let entry = Arc::new(SessionEntry {
            sink: Mutex::new(sink),
            topics: RwLock::new(topic_set),
        });

        {
            let mut sessions = self.sessions.write().unwrap();
            sessions.insert(id, Arc::clone(&entry));
        }

        {
            let mut topics = self.topics.write().unwrap();
            for &t in initial_topics {
                topics.entry(t.to_string()).or_default().insert(id);
            }
        }

        id
    }

    /// Unregister a session and remove it from all subscribed topics.
    pub fn unregister(&self, session_id: SessionId) -> bool {
        let entry = {
            let mut sessions = self.sessions.write().unwrap();
            sessions.remove(&session_id)
        };

        if let Some(entry) = entry {
            let subscribed_topics = {
                let guard = entry.topics.read().unwrap();
                guard.clone()
            };

            let mut topics = self.topics.write().unwrap();
            for topic in subscribed_topics {
                if let Some(set) = topics.get_mut(&topic) {
                    set.remove(&session_id);
                    if set.is_empty() {
                        topics.remove(&topic);
                    }
                }
            }
            true
        } else {
            false
        }
    }

    /// Subscribe an existing session to a topic channel.
    pub fn subscribe(&self, session_id: SessionId, topic: &str) -> bool {
        let entry = {
            let sessions = self.sessions.read().unwrap();
            sessions.get(&session_id).cloned()
        };

        if let Some(entry) = entry {
            {
                let mut topics_guard = entry.topics.write().unwrap();
                topics_guard.insert(topic.to_string());
            }
            {
                let mut topics = self.topics.write().unwrap();
                topics
                    .entry(topic.to_string())
                    .or_default()
                    .insert(session_id);
            }
            true
        } else {
            false
        }
    }

    /// Unsubscribe an existing session from a topic channel.
    pub fn unsubscribe(&self, session_id: SessionId, topic: &str) -> bool {
        let entry = {
            let sessions = self.sessions.read().unwrap();
            sessions.get(&session_id).cloned()
        };

        if let Some(entry) = entry {
            {
                let mut topics_guard = entry.topics.write().unwrap();
                topics_guard.remove(topic);
            }
            {
                let mut topics = self.topics.write().unwrap();
                if let Some(set) = topics.get_mut(topic) {
                    set.remove(&session_id);
                    if set.is_empty() {
                        topics.remove(topic);
                    }
                }
            }
            true
        } else {
            false
        }
    }

    /// Check if a session is subscribed to a topic.
    pub fn is_subscribed(&self, session_id: SessionId, topic: &str) -> bool {
        let sessions = self.sessions.read().unwrap();
        if let Some(entry) = sessions.get(&session_id) {
            let guard = entry.topics.read().unwrap();
            guard.contains(topic)
        } else {
            false
        }
    }

    /// Return all active sessions subscribed to a given topic.
    pub fn subscribers(&self, topic: &str) -> Vec<SessionId> {
        let topics = self.topics.read().unwrap();
        topics
            .get(topic)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Total number of active sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.read().unwrap().len()
    }

    /// Total number of active topics with at least one subscriber.
    pub fn topic_count(&self) -> usize {
        self.topics.read().unwrap().len()
    }

    /// Publish a message to all active sessions subscribed to a topic.
    /// Returns the number of successful deliveries. Disconnected sessions returning EPIPE or EOF are pruned.
    pub fn publish(&self, topic: &str, message: &HubMessage) -> usize {
        let target_sessions: Vec<SessionId> = {
            let topics = self.topics.read().unwrap();
            match topics.get(topic) {
                Some(set) => set.iter().copied().collect(),
                None => return 0,
            }
        };

        let mut delivered = 0;
        let mut failed = Vec::new();

        for sid in target_sessions {
            let entry = {
                let sessions = self.sessions.read().unwrap();
                sessions.get(&sid).cloned()
            };

            if let Some(entry) = entry {
                let mut sink = entry.sink.lock().unwrap();
                if sink.deliver(message).is_ok() {
                    delivered += 1;
                } else {
                    failed.push(sid);
                }
            }
        }

        for sid in failed {
            self.unregister(sid);
        }

        delivered
    }

    /// Send a message directly to a specific session (unicast).
    pub fn send_to(&self, session_id: SessionId, message: &HubMessage) -> io::Result<()> {
        let entry = {
            let sessions = self.sessions.read().unwrap();
            sessions
                .get(&session_id)
                .cloned()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "session not found"))?
        };

        let mut sink = entry.sink.lock().unwrap();
        sink.deliver(message)
    }

    /// Broadcast a message to every active session regardless of subscribed topics.
    pub fn broadcast_all(&self, message: &HubMessage) -> usize {
        let all_sessions: Vec<SessionId> = {
            let sessions = self.sessions.read().unwrap();
            sessions.keys().copied().collect()
        };

        let mut delivered = 0;
        let mut failed = Vec::new();

        for sid in all_sessions {
            let entry = {
                let sessions = self.sessions.read().unwrap();
                sessions.get(&sid).cloned()
            };

            if let Some(entry) = entry {
                let mut sink = entry.sink.lock().unwrap();
                if sink.deliver(message).is_ok() {
                    delivered += 1;
                } else {
                    failed.push(sid);
                }
            }
        }

        for sid in failed {
            self.unregister(sid);
        }

        delivered
    }
}

/// Resolves a host name to a list of IP addresses.
///
/// If `host` already represents an IP address, returns that single address.
/// For hostnames, uses the system resolver to determine associated IPv4 and IPv6 addresses.
pub fn resolve_host(host: &str) -> io::Result<Vec<IpAddr>> {
    let dummy_port = 0u16;
    let addrs: Vec<SocketAddr> = (host, dummy_port).to_socket_addrs()?.collect();
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("unable to resolve host: {host}"),
        ));
    }
    let mut ips = Vec::new();
    for addr in addrs {
        let ip = addr.ip();
        if !ips.contains(&ip) {
            ips.push(ip);
        }
    }
    Ok(ips)
}

/// Resolves a host name or IP address returning only IPv4 addresses.
pub fn resolve_host_v4(host: &str) -> io::Result<Vec<Ipv4Addr>> {
    let ips = resolve_host(host)?;
    let v4s: Vec<Ipv4Addr> = ips
        .into_iter()
        .filter_map(|ip| match ip {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        })
        .collect();
    if v4s.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no IPv4 addresses resolved for: {host}"),
        ));
    }
    Ok(v4s)
}

/// Resolves a host name or IP address returning only IPv6 addresses.
pub fn resolve_host_v6(host: &str) -> io::Result<Vec<Ipv6Addr>> {
    let ips = resolve_host(host)?;
    let v6s: Vec<Ipv6Addr> = ips
        .into_iter()
        .filter_map(|ip| match ip {
            IpAddr::V4(_) => None,
            IpAddr::V6(v6) => Some(v6),
        })
        .collect();
    if v6s.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no IPv6 addresses resolved for: {host}"),
        ));
    }
    Ok(v6s)
}

/// Resolves a host:port string into a list of socket addresses.
pub fn resolve_socket_addrs<A: ToSocketAddrs>(addr: A) -> io::Result<Vec<SocketAddr>> {
    let addrs: Vec<SocketAddr> = addr.to_socket_addrs()?.collect();
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "failed to resolve any socket addresses",
        ));
    }
    Ok(addrs)
}

// ── Profiling & Micro-Benchmarks for Network Primitives ─────────────────────

/// Results and performance telemetry for network primitive micro-benchmarks.
#[derive(Debug, Clone, PartialEq)]
pub struct NetBenchmarkResult {
    /// Identifier or descriptive name of the benchmarked primitive.
    pub name: String,
    /// Total number of operations evaluated during the benchmark run.
    pub iterations: usize,
    /// Total duration elapsed during the measurement in milliseconds.
    pub total_time_ms: f64,
    /// Average execution time per individual operation in nanoseconds.
    pub ns_per_op: f64,
    /// Number of completed operations achieved per second.
    pub ops_per_sec: f64,
}

/// Comprehensive benchmark report compiling network primitive throughput and latency metrics.
#[derive(Debug, Clone, PartialEq)]
pub struct NetBenchmarkReport {
    /// Total timestamped duration of the entire benchmark suite in milliseconds.
    pub total_duration_ms: f64,
    /// Collection of individual component benchmark measurements.
    pub benchmarks: Vec<NetBenchmarkResult>,
}

/// Runs in-memory micro-benchmarks evaluating WebSocket framing and demuxing throughput.
pub fn benchmark_websocket_framing(iterations: usize) -> NetBenchmarkResult {
    let payload = b"Hello IFA High-Concurrency Networking Benchmark!".to_vec();
    let frame = WsFrame::text(
        std::str::from_utf8(&payload).unwrap(),
        false,
        Some([0x12, 0x34, 0x56, 0x78]),
    );
    let encoded = frame.encode();

    let start = std::time::Instant::now();
    let mut demux = WsDemux::new();

    for _ in 0..iterations {
        demux.push_bytes(&encoded);
        let _ = demux.poll_frame();
    }

    let elapsed = start.elapsed();
    let total_time_ms = elapsed.as_secs_f64() * 1000.0;
    let ns_per_op = (elapsed.as_nanos() as f64) / (iterations as f64);
    let ops_per_sec = (iterations as f64) / elapsed.as_secs_f64();

    NetBenchmarkResult {
        name: "websocket_frame_encode_demux".to_string(),
        iterations,
        total_time_ms,
        ns_per_op,
        ops_per_sec,
    }
}

/// Runs in-memory micro-benchmarks evaluating SSE event encoding and stream parsing throughput.
pub fn benchmark_sse_parsing(iterations: usize) -> NetBenchmarkResult {
    let raw_sse =
        "event: metric_update\nid: 9942\ndata: {\"concurrency\": 10000, \"status\": \"ok\"}\n\n";

    let start = std::time::Instant::now();
    let mut decoder = SseDecoder::new();

    for _ in 0..iterations {
        decoder.push_str(raw_sse);
        let _ = decoder.next_event();
    }

    let elapsed = start.elapsed();
    let total_time_ms = elapsed.as_secs_f64() * 1000.0;
    let ns_per_op = (elapsed.as_nanos() as f64) / (iterations as f64);
    let ops_per_sec = (iterations as f64) / elapsed.as_secs_f64();

    NetBenchmarkResult {
        name: "sse_event_stream_parsing".to_string(),
        iterations,
        total_time_ms,
        ns_per_op,
        ops_per_sec,
    }
}

/// Runs in-memory micro-benchmarks evaluating TokenBucket rate-limiting acquisition throughput.
pub fn benchmark_token_bucket(iterations: usize) -> NetBenchmarkResult {
    let mut bucket = TokenBucket::new(1_000_000_000, 1_000_000_000, 1000);

    let start = std::time::Instant::now();

    for _ in 0..iterations {
        let _ = bucket.try_consume(1, 1000);
    }

    let elapsed = start.elapsed();
    let total_time_ms = elapsed.as_secs_f64() * 1000.0;
    let ns_per_op = (elapsed.as_nanos() as f64) / (iterations as f64);
    let ops_per_sec = (iterations as f64) / elapsed.as_secs_f64();

    NetBenchmarkResult {
        name: "token_bucket_acquisition".to_string(),
        iterations,
        total_time_ms,
        ns_per_op,
        ops_per_sec,
    }
}

/// Runs a multithreaded concurrent TCP throughput benchmark between an echo server and concurrent clients.
/// Measures aggregate round-trip requests, data volume transferred, latency per op, and total operations/sec.
pub fn benchmark_tcp_throughput(
    clients_count: usize,
    messages_per_client: usize,
    payload_size: usize,
) -> io::Result<NetBenchmarkResult> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let payload = vec![0x42u8; payload_size.max(1)];

    let total_operations = clients_count * messages_per_client;
    let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let server_running = running.clone();

    // Spawn server thread
    let server_handle = std::thread::spawn(move || {
        let mut server_handles = Vec::new();
        while server_running.load(std::sync::atomic::Ordering::Relaxed) {
            listener.set_nonblocking(true).ok();
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let h = std::thread::spawn(move || {
                        let mut buf = [0u8; 4096];
                        loop {
                            match stream.read(&mut buf) {
                                Ok(0) => break,
                                Ok(n) => {
                                    if stream.write_all(&buf[..n]).is_err() {
                                        break;
                                    }
                                }
                                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                                    std::thread::yield_now();
                                }
                                Err(_) => break,
                            }
                        }
                    });
                    server_handles.push(h);
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(_) => break,
            }
        }
        for h in server_handles {
            let _ = h.join();
        }
    });

    let start = std::time::Instant::now();
    let mut client_threads = Vec::new();

    for _ in 0..clients_count {
        let p = payload.clone();
        let handle = std::thread::spawn(move || -> io::Result<()> {
            let mut stream = std::net::TcpStream::connect(addr)?;
            let mut response_buf = vec![0u8; p.len()];
            for _ in 0..messages_per_client {
                stream.write_all(&p)?;
                stream.read_exact(&mut response_buf)?;
            }
            Ok(())
        });
        client_threads.push(handle);
    }

    for h in client_threads {
        let _ = h
            .join()
            .map_err(|_| io::Error::other("Client benchmark worker failed"))?;
    }

    let elapsed = start.elapsed();
    running.store(false, std::sync::atomic::Ordering::Relaxed);
    // Connect dummy stream to unblock listener accept loop if waiting
    let _ = std::net::TcpStream::connect(addr);
    let _ = server_handle.join();

    let total_time_ms = elapsed.as_secs_f64() * 1000.0;
    let ns_per_op = if total_operations > 0 {
        (elapsed.as_nanos() as f64) / (total_operations as f64)
    } else {
        0.0
    };
    let ops_per_sec = if elapsed.as_secs_f64() > 0.0 {
        (total_operations as f64) / elapsed.as_secs_f64()
    } else {
        0.0
    };

    Ok(NetBenchmarkResult {
        name: format!(
            "tcp_multithread_throughput_{}x{}_{}b",
            clients_count, messages_per_client, payload_size
        ),
        iterations: total_operations,
        total_time_ms,
        ns_per_op,
        ops_per_sec,
    })
}

/// Statistics and telemetry collected from an endurance stress benchmark run over async TCP streams.
#[derive(Debug, Clone, PartialEq)]
pub struct AsyncTcpEnduranceResult {
    /// Identifier or benchmark name.
    pub name: String,
    /// Number of concurrent async worker threads/tasks.
    pub concurrent_conns: usize,
    /// Total successful ping-pong echo cycles across all connections.
    pub total_cycles: usize,
    /// Total bytes transmitted over all connections.
    pub total_bytes_transferred: usize,
    /// Duration of the test in milliseconds.
    pub duration_ms: f64,
    /// Throughput in operations (request/response cycles) per second.
    pub ops_per_sec: f64,
    /// Bandwidth throughput in Megabytes per second (MB/s).
    pub throughput_mb_per_sec: f64,
    /// Average round-trip latency in nanoseconds.
    pub avg_latency_ns: f64,
    /// Count of transmission or connection errors encountered (must be 0 for resilient runs).
    pub error_count: usize,
}

/// Runs a multithreaded endurance and throughput stress benchmark for `AsyncTcpStream` under concurrent load.
///
/// Spawns an echo server listening via non-blocking TCP socket, and creates `concurrent_conns` worker
/// threads that each establish an `AsyncTcpStream`, continuously streaming `payload_size` bytes back and forth
/// for `cycles_per_conn` iterations.
pub fn benchmark_async_tcp_endurance(
    concurrent_conns: usize,
    cycles_per_conn: usize,
    payload_size: usize,
) -> io::Result<AsyncTcpEnduranceResult> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let payload = vec![0x5Au8; payload_size.max(1)];

    let _total_expected_cycles = concurrent_conns * cycles_per_conn;
    let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let server_running = running.clone();

    // Multithreaded echo server
    let server_handle = std::thread::spawn(move || {
        let mut conn_handles = Vec::new();
        while server_running.load(std::sync::atomic::Ordering::Relaxed) {
            listener.set_nonblocking(true).ok();
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let handle = std::thread::spawn(move || {
                        let mut buf = [0u8; 8192];
                        loop {
                            match stream.read(&mut buf) {
                                Ok(0) => break,
                                Ok(n) => {
                                    if stream.write_all(&buf[..n]).is_err() {
                                        break;
                                    }
                                }
                                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                                    std::thread::yield_now();
                                }
                                Err(_) => break,
                            }
                        }
                    });
                    conn_handles.push(handle);
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(_) => break,
            }
        }
        for h in conn_handles {
            let _ = h.join();
        }
    });

    let errors_counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let completed_counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let start = std::time::Instant::now();
    let mut client_handles = Vec::new();

    for _ in 0..concurrent_conns {
        let p = payload.clone();
        let errs = errors_counter.clone();
        let compl = completed_counter.clone();
        let h = std::thread::spawn(move || {
            let mut client_stream = match AsyncTcpStream::connect(addr) {
                Ok(s) => s,
                Err(_) => {
                    errs.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return;
                }
            };
            let mut echo_buf = vec![0u8; p.len()];
            for _ in 0..cycles_per_conn {
                if client_stream.write_all(&p).is_err() {
                    errs.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return;
                }
                if client_stream.read_exact(&mut echo_buf).is_err() {
                    errs.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return;
                }
                if echo_buf != p {
                    errs.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return;
                }
                compl.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        });
        client_handles.push(h);
    }

    for h in client_handles {
        let _ = h.join();
    }

    let elapsed = start.elapsed();
    running.store(false, std::sync::atomic::Ordering::Relaxed);
    // Unblock accept loop
    let _ = std::net::TcpStream::connect(addr);
    let _ = server_handle.join();

    let total_cycles = completed_counter.load(std::sync::atomic::Ordering::Relaxed);
    let error_count = errors_counter.load(std::sync::atomic::Ordering::Relaxed);
    let duration_ms = elapsed.as_secs_f64() * 1000.0;
    let duration_secs = elapsed.as_secs_f64();
    let total_bytes_transferred = total_cycles * payload_size * 2; // bidirectional (sent + received)

    let ops_per_sec = if duration_secs > 0.0 {
        (total_cycles as f64) / duration_secs
    } else {
        0.0
    };
    let throughput_mb_per_sec = if duration_secs > 0.0 {
        ((total_bytes_transferred as f64) / (1024.0 * 1024.0)) / duration_secs
    } else {
        0.0
    };
    let avg_latency_ns = if total_cycles > 0 {
        (elapsed.as_nanos() as f64) / (total_cycles as f64)
    } else {
        0.0
    };

    Ok(AsyncTcpEnduranceResult {
        name: format!(
            "async_tcp_endurance_{}conns_{}cycles_{}bytes",
            concurrent_conns, cycles_per_conn, payload_size
        ),
        concurrent_conns,
        total_cycles,
        total_bytes_transferred,
        duration_ms,
        ops_per_sec,
        throughput_mb_per_sec,
        avg_latency_ns,
        error_count,
    })
}

/// Executes the full suite of in-memory network primitive micro-benchmarks and returns a unified report.
pub fn run_net_benchmark_suite(iterations_per_test: usize) -> NetBenchmarkReport {
    let start = std::time::Instant::now();
    let mut benchmarks = vec![
        benchmark_websocket_framing(iterations_per_test),
        benchmark_sse_parsing(iterations_per_test),
        benchmark_token_bucket(iterations_per_test),
    ];

    if let Ok(tcp_bench) = benchmark_tcp_throughput(2, iterations_per_test.min(50), 64) {
        benchmarks.push(tcp_bench);
    }

    let elapsed = start.elapsed();
    NetBenchmarkReport {
        total_duration_ms: elapsed.as_secs_f64() * 1000.0,
        benchmarks,
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
    fn test_async_ws_handshake_roundtrip() {
        use ifa_runtime::reactor::AsyncTcpListener;

        let listener = AsyncTcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        let client_key = "dGhlIHNhbXBsZSBub25jZQ==";

        GLOBAL_SCHEDULER.spawn(move || {
            let stream = AsyncTcpStream::connect(addr).expect("connect client");
            let mut client = AsyncWsConnection::client_handshake(
                stream,
                "127.0.0.1",
                addr.port(),
                "/chat",
                client_key,
            )
            .expect("client handshake failed");

            client
                .send_text("HANDSHAKE_HELLO_FROM_CLIENT")
                .expect("send text");
            let reply = client.recv_message().expect("recv reply");
            assert_eq!(
                reply,
                WsMessage::Text("HANDSHAKE_ACK_FROM_SERVER".to_string())
            );

            client
                .send_close(1000, "Normal")
                .expect("client send close");
        });

        let mut server = loop {
            if let Ok(Some((stream, _))) = listener.try_accept() {
                break AsyncWsConnection::server_handshake(stream)
                    .expect("server handshake failed");
            }
            GLOBAL_SCHEDULER.yield_now();
            std::thread::sleep(Duration::from_millis(5));
        };

        let msg = server.recv_message().expect("server recv message");
        assert_eq!(
            msg,
            WsMessage::Text("HANDSHAKE_HELLO_FROM_CLIENT".to_string())
        );

        server
            .send_text("HANDSHAKE_ACK_FROM_SERVER")
            .expect("server reply text");

        let close_msg = server.recv_message().expect("server recv close");
        match close_msg {
            WsMessage::Close(code, _) => assert_eq!(code, Some(1000)),
            other => panic!("Expected close, got {:?}", other),
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

    #[test]
    fn test_websocket_concurrent_burst_and_streaming() {
        let mut server = WsServer::bind("127.0.0.1:0", 16).expect("bind ws server");
        let port = server.port().expect("port");

        let client_count = 6;
        let mut clients: Vec<WsClient> = (0..client_count)
            .map(|i| {
                WsClient::connect("127.0.0.1", port, &format!("/stream?client_id={}", i))
                    .expect("connect client")
            })
            .collect();

        // Give sockets a brief window to complete TCP accept
        std::thread::sleep(Duration::from_millis(50));

        let upgraded = server.accept_and_upgrade().expect("accept and upgrade");
        assert_eq!(upgraded, client_count);
        assert_eq!(server.session_count(), client_count);

        std::thread::sleep(Duration::from_millis(50));
        for client in &mut clients {
            assert!(client.poll_handshake().expect("client handshake"));
            assert!(client.is_upgraded());
        }

        // Concurrent multi-client broadcast burst from server
        for seq in 0..10 {
            let broadcast_msg = format!("BURST_EVENT_SEQ_{}", seq);
            let delivered = server.broadcast_text(&broadcast_msg);
            assert_eq!(delivered, client_count);
        }

        std::thread::sleep(Duration::from_millis(60));

        // Each client verifies delivery of burst messages
        for client in &mut clients {
            let mut received = Vec::new();
            while let Ok(Some(msg)) = client.poll_text_message() {
                received.push(msg);
            }
            assert_eq!(received.len(), 10);
            assert_eq!(received[0], "BURST_EVENT_SEQ_0");
            assert_eq!(received[9], "BURST_EVENT_SEQ_9");
        }

        // Concurrent response from all clients to server
        for (idx, client) in clients.iter_mut().enumerate() {
            client
                .send_text(&format!("CLIENT_{}_ACK", idx))
                .expect("send ack");
        }

        std::thread::sleep(Duration::from_millis(60));

        let acks = server.poll_all_messages();
        assert_eq!(acks.len(), client_count);

        // Teardown cleanly
        for mut client in clients {
            client.close();
        }
        server.stop();
    }

    #[test]
    fn test_udp_socket_lifecycle_and_options() {
        let mut sock_a = UdpSocket::bind("127.0.0.1:0").expect("bind udp socket a");
        let mut sock_b = UdpSocket::bind("127.0.0.1:0").expect("bind udp socket b");

        assert!(sock_a.is_open());
        assert!(sock_b.is_open());

        let addr_a = sock_a.local_addr().expect("local addr a");
        let addr_b = sock_b.local_addr().expect("local addr b");
        assert!(sock_a.port().expect("port a") > 0);
        assert!(sock_b.port().expect("port b") > 0);

        // Test socket options
        sock_a.set_ttl(64).expect("set ttl");
        assert_eq!(sock_a.ttl().expect("get ttl"), 64);

        sock_a.set_broadcast(true).expect("set broadcast true");
        assert!(sock_a.broadcast().expect("get broadcast"));
        sock_a.set_broadcast(false).expect("set broadcast false");
        assert!(!sock_a.broadcast().expect("get broadcast"));

        // Datagram communication
        let payload = b"IFA_UDP_DATAGRAM_TEST";
        let sent = sock_a
            .send_to(payload, addr_b)
            .expect("send_to datagram from a to b");
        assert_eq!(sent, payload.len());

        // Wait briefly for local socket buffer delivery
        std::thread::sleep(Duration::from_millis(20));

        let mut recv_buf = [0u8; 128];
        let poll_res = sock_b.poll_recv_from(&mut recv_buf).expect("poll recv");
        assert!(poll_res.is_some());
        let (n, from_addr) = poll_res.unwrap();
        assert_eq!(n, payload.len());
        assert_eq!(&recv_buf[..n], payload);
        assert_eq!(from_addr.port(), addr_a.port());

        // Connected mode test
        sock_a.connect(addr_b).expect("connect sock_a to sock_b");
        assert_eq!(sock_a.peer_addr().expect("peer_addr").port(), addr_b.port());

        let conn_payload = b"CONNECTED_UDP_FLOW";
        let sent_conn = sock_a.send(conn_payload).expect("send connected");
        assert_eq!(sent_conn, conn_payload.len());

        std::thread::sleep(Duration::from_millis(20));
        let (recv_n, _) = sock_b.recv_from(&mut recv_buf).expect("recv_from b");
        assert_eq!(recv_n, conn_payload.len());
        assert_eq!(&recv_buf[..recv_n], conn_payload);

        // Clone handle
        let cloned_a = sock_a.try_clone().expect("try_clone");
        assert_eq!(cloned_a.port().unwrap(), sock_a.port().unwrap());

        // Close sockets
        sock_a.close();
        sock_b.close();
        assert!(!sock_a.is_open());
        assert!(!sock_b.is_open());
        assert!(sock_a.send_to(payload, addr_b).is_err());
    }

    #[test]
    fn test_tcp_socket_extended_options() {
        let mut listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp listener");
        let port = listener.port().expect("listener port");

        listener.set_ttl(42).expect("set_ttl listener");
        assert_eq!(listener.ttl().expect("get_ttl listener"), 42);

        let cloned_listener = listener.try_clone().expect("clone listener");
        assert_eq!(cloned_listener.port().unwrap(), port);

        let mut client_stream =
            TcpStream::connect(format!("127.0.0.1:{}", port)).expect("connect client");
        client_stream.set_nodelay(true).expect("set_nodelay");
        assert!(client_stream.nodelay().expect("get nodelay"));

        client_stream.set_ttl(64).expect("set_ttl stream");
        assert_eq!(client_stream.ttl().expect("get_ttl stream"), 64);

        let cloned_client = client_stream.try_clone().expect("clone stream");
        assert_eq!(
            cloned_client.peer_addr().unwrap().port(),
            client_stream.peer_addr().unwrap().port()
        );

        let accepted = listener.try_accept().expect("try_accept");
        assert!(accepted.is_some());

        client_stream.close();
        listener.close();
    }

    #[test]
    fn test_async_transports_reexported() {
        use super::{AsyncTcpListener, AsyncTcpStream, AsyncTimer, AsyncUdpSocket};

        // UDP async transport
        let u1 = AsyncUdpSocket::bind("127.0.0.1:0").expect("bind async udp");
        let u2 = AsyncUdpSocket::bind("127.0.0.1:0").expect("bind async udp");
        let u2_addr = u2.local_addr().expect("local addr");

        u1.send_to(b"ASYNC_STDLIB_UDP", u2_addr).expect("send_to");
        let mut buf = [0u8; 32];
        let (n, from) = u2.recv_from(&mut buf).expect("recv_from");
        assert_eq!(n, 16);
        assert_eq!(&buf[..n], b"ASYNC_STDLIB_UDP");
        assert_eq!(from.port(), u1.local_addr().unwrap().port());

        // TCP async transport
        let listener = AsyncTcpListener::bind("127.0.0.1:0").expect("bind async tcp listener");
        let l_addr = listener.local_addr().expect("local addr");
        let mut client = AsyncTcpStream::connect(l_addr).expect("connect async client");
        let (mut server, _) = listener.accept().expect("accept async server");

        client.write_all(b"PING").expect("write ping");
        let mut tcp_buf = [0u8; 4];
        let read_n = server.read(&mut tcp_buf).expect("read ping");
        assert_eq!(read_n, 4);
        assert_eq!(&tcp_buf, b"PING");

        // Timer
        AsyncTimer::sleep(Duration::from_millis(1));
    }

    #[test]
    fn test_high_level_buffered_stream_and_socket_config() {
        use super::{BufferedTcpStream, Datagram, SocketConfig, TcpListener, TcpStream, UdpSocket};

        // 1. SocketConfig on TCP stream and buffered stream
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.port().expect("port");

        let config = SocketConfig::new()
            .nodelay(true)
            .ttl(64)
            .read_timeout(Some(Duration::from_millis(500)))
            .write_timeout(Some(Duration::from_millis(500)))
            .recv_buffer_size(32768)
            .send_buffer_size(32768);

        let client = TcpStream::connect(format!("127.0.0.1:{}", port)).expect("connect client");
        client.apply_config(&config).expect("apply config");
        assert!(client.nodelay().unwrap());
        assert_eq!(client.ttl().unwrap(), 64);
        assert!(client.recv_buffer_size().unwrap() >= 1024);
        assert!(client.send_buffer_size().unwrap() >= 1024);
        assert!(client.take_error().unwrap().is_none());
        assert!(listener.take_error().unwrap().is_none());

        let (server_raw, _) = listener.try_accept().expect("accept").expect("connection");
        let mut client_buf = BufferedTcpStream::new(client).expect("buffered client");
        let mut server_buf = BufferedTcpStream::new(server_raw).expect("buffered server");

        // Write lines from client
        client_buf.write_line("HELLO WORLD").expect("write line 1");
        client_buf.write_line("SECOND LINE").expect("write line 2");

        // Read lines from server (non-blocking loop with small spin/yield)
        let mut read_lines = Vec::new();
        for _ in 0..100 {
            if let Some(line) = server_buf.read_line().expect("read line") {
                read_lines.push(line);
                if read_lines.len() == 2 {
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(read_lines, vec!["HELLO WORLD", "SECOND LINE"]);

        // Peek on server stream
        let mut peek_buf = [0u8; 4];
        client_buf.write_all(b"TEST").expect("write test");
        client_buf.flush().expect("flush");
        let mut peek_n = 0;
        for _ in 0..100 {
            peek_n = server_buf.stream().peek(&mut peek_buf).unwrap();
            if peek_n > 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(peek_n, 4);
        assert_eq!(&peek_buf, b"TEST");

        // 2. Datagram and high-level UDP operations
        let udp1 = UdpSocket::bind("127.0.0.1:0").expect("bind udp1");
        let udp2 = UdpSocket::bind("127.0.0.1:0").expect("bind udp2");
        let udp2_addr = udp2.local_addr().expect("udp2 addr");

        let udp_config = SocketConfig::new()
            .ttl(32)
            .broadcast(false)
            .recv_buffer_size(32768)
            .send_buffer_size(32768);
        udp1.apply_config(&udp_config).expect("apply config udp1");
        assert_eq!(udp1.ttl().unwrap(), 32);
        assert!(!udp1.broadcast().unwrap());
        assert!(udp1.take_error().unwrap().is_none());

        let packet = Datagram::new(b"DATAGRAM_PACKET".to_vec(), udp2_addr);
        let sent = udp1.send_datagram(&packet).expect("send datagram");
        assert_eq!(sent, 15);

        // Peek from udp2
        let mut udp_peek_buf = [0u8; 32];
        let mut peeked = false;
        for _ in 0..50 {
            let (n, from) = udp2.peek_from(&mut udp_peek_buf).expect("peek_from");
            if n > 0 {
                assert_eq!(&udp_peek_buf[..n], b"DATAGRAM_PACKET");
                assert_eq!(from.port(), udp1.port().unwrap());
                peeked = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(peeked);

        // Recv datagram on udp2
        let mut received = None;
        for _ in 0..50 {
            if let Some(dg) = udp2.recv_datagram(64).expect("recv datagram") {
                received = Some(dg);
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let dg = received.expect("datagram received");
        assert_eq!(&dg.data, b"DATAGRAM_PACKET");
        assert_eq!(dg.sender.port(), udp1.port().unwrap());
    }

    #[test]
    fn test_buffered_tcp_stream_capabilities() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.port().expect("port");
        let client = TcpStream::connect(format!("127.0.0.1:{}", port)).expect("connect");
        let (server_raw, _) = listener.try_accept().expect("accept").expect("stream");

        let client_buf = BufferedTcpStream::with_capacity(8192, 4096, client).expect("client buf");
        let server_buf = BufferedTcpStream::new(server_raw).expect("server buf");

        // Capacities
        let (rcap, wcap) = client_buf.capacity();
        assert_eq!(rcap, 8192);
        assert_eq!(wcap, 4096);

        // Addresses
        let c_peer = client_buf.peer_addr().expect("peer addr");
        let s_local = server_buf.local_addr().expect("local addr");
        assert_eq!(c_peer.port(), s_local.port());

        // TCP options
        client_buf.set_nodelay(true).expect("set nodelay");
        assert!(client_buf.nodelay().expect("get nodelay"));

        // Timeouts
        client_buf
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("set read timeout");
        assert_eq!(
            client_buf.read_timeout().expect("get read timeout"),
            Some(Duration::from_millis(500))
        );

        client_buf
            .set_write_timeout(Some(Duration::from_millis(600)))
            .expect("set write timeout");
        assert_eq!(
            client_buf.write_timeout().expect("get write timeout"),
            Some(Duration::from_millis(600))
        );

        // Buffer inspections
        assert!(client_buf.buffer().is_empty());
        assert_eq!(client_buf.buffer_len(), 0);
    }

    #[test]
    fn test_buffered_tcp_stream_split_and_reunite() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.port().expect("port");
        let client = TcpStream::connect(format!("127.0.0.1:{}", port)).expect("connect");
        let (server_raw, _) = listener.try_accept().expect("accept").expect("stream");

        let client_buf = BufferedTcpStream::with_capacity(4096, 4096, client).expect("client buf");
        let mut server_buf = BufferedTcpStream::new(server_raw).expect("server buf");

        // 1. Borrowed split inspection
        {
            let (r_ref, w_ref) = server_buf.split_mut();
            assert_eq!(r_ref.buffer().len(), 0);
            w_ref.flush().expect("flush borrowed writer");
        }

        // 2. Owned split into independent halves
        let (mut r_half, mut w_half) = client_buf.into_split();

        assert_eq!(r_half.capacity(), 4096);
        assert_eq!(w_half.capacity(), 4096);
        assert!(r_half.peer_addr().is_ok());
        assert!(w_half.local_addr().is_ok());

        // 3. Independent writes and reads across halves
        w_half.write_line("COMMAND_STATUS").expect("write line");

        let server_line = server_buf.read_line().expect("read line").expect("message");
        assert_eq!(server_line, "COMMAND_STATUS");

        server_buf
            .write_line("STATUS_ACTIVE_OK")
            .expect("server write line");

        let client_line = r_half.read_line().expect("read line").expect("response");
        assert_eq!(client_line, "STATUS_ACTIVE_OK");

        // 4. Reunite halves into a single BufferedTcpStream
        let client_reunited = r_half.reunite(w_half);
        assert_eq!(client_reunited.capacity(), (4096, 4096));

        // 5. Unwrapping handles
        let (r_stream, w_stream_res) = client_reunited.into_inner_pair();
        assert!(r_stream.peer_addr().is_ok());
        assert!(w_stream_res.is_ok());
    }

    #[test]
    fn test_dns_resolution_utilities() {
        // Resolve loopback IP literals
        let ips = resolve_host("127.0.0.1").expect("resolve 127.0.0.1");
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]);

        let v4s = resolve_host_v4("127.0.0.1").expect("resolve v4 127.0.0.1");
        assert_eq!(v4s, vec![Ipv4Addr::new(127, 0, 0, 1)]);

        let v6_res = resolve_host_v6("127.0.0.1");
        assert!(v6_res.is_err());

        // Resolve IPv6 loopback
        let v6_ips = resolve_host("::1").expect("resolve ::1");
        assert_eq!(
            v6_ips,
            vec![IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))]
        );

        let v6s = resolve_host_v6("::1").expect("resolve v6 ::1");
        assert_eq!(v6s, vec![Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)]);

        // Resolve localhost hostname (usually resolves to 127.0.0.1 and/or ::1)
        let localhost_ips = resolve_host("localhost").expect("resolve localhost");
        assert!(!localhost_ips.is_empty());
        assert!(
            localhost_ips.contains(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
                || localhost_ips.contains(&IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)))
        );

        // Resolve socket address
        let addrs = resolve_socket_addrs("127.0.0.1:8080").expect("resolve socket addrs");
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].port(), 8080);
    }

    #[test]
    fn test_sse_wire_formatting_and_decoding() {
        // 1. Serialization
        let event = SseEvent::new("hello world")
            .with_event("greet")
            .with_id("42")
            .with_retry(5000)
            .with_comment("heartbeat ping");

        let wire = event.to_wire_string();
        assert!(wire.contains(": heartbeat ping\n"));
        assert!(wire.contains("event: greet\n"));
        assert!(wire.contains("id: 42\n"));
        assert!(wire.contains("retry: 5000\n"));
        assert!(wire.contains("data: hello world\n\n"));

        // 2. Multi-line data decoding
        let multi_event = SseEvent::new("line1\nline2\nline3").with_id("evt-101");
        let wire_multi = multi_event.to_wire_string();
        assert!(wire_multi.contains("data: line1\ndata: line2\ndata: line3\n\n"));

        // 3. Decoding chunks with SseDecoder
        let mut decoder = SseDecoder::new();
        decoder.push_str(&wire);
        decoder.push_str(&wire_multi);

        let parsed1 = decoder.next_event().expect("first event");
        assert_eq!(parsed1.event.as_deref(), Some("greet"));
        assert_eq!(parsed1.data, "hello world");
        assert_eq!(parsed1.id.as_deref(), Some("42"));
        assert_eq!(parsed1.retry, Some(5000));
        assert_eq!(parsed1.comment.as_deref(), Some("heartbeat ping"));
        assert_eq!(decoder.last_event_id(), Some("42"));

        let parsed2 = decoder.next_event().expect("second event");
        assert_eq!(parsed2.id.as_deref(), Some("evt-101"));
        assert_eq!(parsed2.data, "line1\nline2\nline3");
        assert_eq!(decoder.last_event_id(), Some("evt-101"));

        assert!(decoder.next_event().is_none());
    }

    #[test]
    fn test_async_sse_client_and_server_streaming() {
        let listener = AsyncTcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("port");

        GLOBAL_SCHEDULER.spawn(move || {
            let stream = AsyncTcpStream::connect(addr).expect("connect client");
            let mut client = AsyncSseClient::new(stream);
            assert_eq!(client.events_received(), 0);
            assert_eq!(client.bytes_received(), 0);

            let ev1 = client.read_event().expect("read 1").expect("some event 1");
            assert_eq!(ev1.data, "ready");
            assert_eq!(ev1.id.as_deref(), Some("msg-1"));
            assert_eq!(client.last_event_id(), Some("msg-1"));
            assert_eq!(client.events_received(), 1);
            assert!(client.bytes_received() > 0);

            let ev2 = client.read_event().expect("read 2").expect("some event 2");
            assert_eq!(ev2.comment.as_deref(), Some("ping"));
            assert_eq!(client.events_received(), 2);

            let ev3 = client.read_event().expect("read 3").expect("some event 3");
            assert_eq!(ev3.event.as_deref(), Some("telemetry"));
            assert_eq!(ev3.data, "sensor update payload");
            assert_eq!(ev3.id.as_deref(), Some("msg-2"));
            assert_eq!(client.last_event_id(), Some("msg-2"));
            assert_eq!(client.events_received(), 3);

            let stats = client.stats();
            assert_eq!(stats.events_received, 3);
            assert_eq!(stats.last_event_id.as_deref(), Some("msg-2"));
            assert!(stats.bytes_received > 0);
            assert!(client.local_addr().is_ok());
            assert!(client.peer_addr().is_ok());
        });

        let mut server = loop {
            if let Ok(Some((stream, _))) = listener.try_accept() {
                break AsyncSseServer::init_response(stream).expect("init response");
            }
            GLOBAL_SCHEDULER.yield_now();
            std::thread::sleep(Duration::from_millis(5));
        };

        assert_eq!(server.events_sent(), 0);
        assert_eq!(server.heartbeats_sent(), 0);
        assert!(server.bytes_sent() > 0); // response headers sent
        assert!(server.local_addr().is_ok());
        assert!(server.peer_addr().is_ok());

        server
            .send_event(&SseEvent::new("ready").with_id("msg-1"))
            .expect("send event 1");
        assert_eq!(server.events_sent(), 1);
        assert_eq!(server.last_event_id(), Some("msg-1"));

        server.send_heartbeat().expect("heartbeat");
        assert_eq!(server.heartbeats_sent(), 1);

        server
            .send_event(
                &SseEvent::new("sensor update payload")
                    .with_event("telemetry")
                    .with_id("msg-2"),
            )
            .expect("send event 2");
        assert_eq!(server.events_sent(), 2);
        assert_eq!(server.last_event_id(), Some("msg-2"));

        let server_stats = server.stats();
        assert_eq!(server_stats.events_sent, 2);
        assert_eq!(server_stats.heartbeats_sent, 1);
        assert_eq!(server_stats.last_event_id.as_deref(), Some("msg-2"));
        assert!(server_stats.bytes_sent > 0);
    }

    #[test]
    fn test_event_hub_pub_sub_and_channel_multiplexing() {
        let hub = EventHub::new();
        assert_eq!(hub.session_count(), 0);
        assert_eq!(hub.topic_count(), 0);

        let listener = AsyncTcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");

        // Spawn 2 client fibers
        GLOBAL_SCHEDULER.spawn(move || {
            let mut stream1 = AsyncTcpStream::connect(addr).expect("client 1 connect");
            let mut buf = [0u8; 128];
            let n = stream1.read(&mut buf).expect("client 1 read");
            assert_eq!(&buf[..n], b"market_feed:alert1\n");
        });

        GLOBAL_SCHEDULER.spawn(move || {
            let stream2 = AsyncTcpStream::connect(addr).expect("client 2 connect");
            let mut client_sse = AsyncSseClient::new(stream2);
            let event = client_sse
                .read_event()
                .expect("read sse")
                .expect("some event");
            assert_eq!(event.data, "trade_ticker");
            assert_eq!(event.event.as_deref(), Some("ticker"));
        });

        // Accept connection 1 -> Plain TCP sink subscribed to "market"
        let s1 = loop {
            if let Ok(Some((stream, _))) = listener.try_accept() {
                break stream;
            }
            GLOBAL_SCHEDULER.yield_now();
            std::thread::sleep(Duration::from_millis(5));
        };
        let sid1 = hub.register(SessionSink::Stream(s1), &["market"]);

        // Accept connection 2 -> SSE server sink subscribed to "ticker"
        let s2 = loop {
            if let Ok(Some((stream, _))) = listener.try_accept() {
                break AsyncSseServer::init_response(stream).expect("init sse response");
            }
            GLOBAL_SCHEDULER.yield_now();
            std::thread::sleep(Duration::from_millis(5));
        };
        let sid2 = hub.register(SessionSink::Sse(s2), &["ticker"]);

        assert_eq!(hub.session_count(), 2);
        assert_eq!(hub.topic_count(), 2);
        assert!(hub.is_subscribed(sid1, "market"));
        assert!(hub.is_subscribed(sid2, "ticker"));
        assert!(!hub.is_subscribed(sid1, "ticker"));

        // Subscribe sid1 to "all" as well
        assert!(hub.subscribe(sid1, "all"));
        assert!(hub.is_subscribed(sid1, "all"));
        assert_eq!(hub.subscribers("all"), vec![sid1]);

        // Publish to "market" -> sid1 gets text
        let delivered_market = hub.publish("market", &HubMessage::text("market_feed:alert1\n"));
        assert_eq!(delivered_market, 1);

        // Publish to "ticker" -> sid2 gets SSE event
        let delivered_ticker = hub.publish(
            "ticker",
            &HubMessage::sse(SseEvent::new("trade_ticker").with_event("ticker")),
        );
        assert_eq!(delivered_ticker, 1);

        // Unsubscribe & unregister
        assert!(hub.unsubscribe(sid1, "all"));
        assert!(!hub.is_subscribed(sid1, "all"));
        assert_eq!(hub.topic_count(), 2);

        assert!(hub.unregister(sid1));
        assert_eq!(hub.session_count(), 1);
        assert_eq!(hub.subscribers("market").len(), 0);
        assert_eq!(hub.topic_count(), 1);

        assert!(hub.unregister(sid2));
        assert_eq!(hub.session_count(), 0);
        assert_eq!(hub.topic_count(), 0);
    }

    #[test]
    fn test_async_ws_subprotocol_negotiation_and_pool() {
        let listener = AsyncTcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");

        // Spawn server thread/fiber handling handshakes with protocol negotiation
        GLOBAL_SCHEDULER.spawn(move || {
            let mut accepted = 0;
            while accepted < 2 {
                if let Ok(Some((stream, _))) = listener.try_accept() {
                    let mut server = AsyncWsConnection::server_handshake_with_negotiator(
                        stream,
                        |client_protos| {
                            // Negotiate protocol: prefer "v2.chat" over "v1.chat"
                            if client_protos.contains(&"v2.chat".to_string()) {
                                Some("v2.chat".to_string())
                            } else if client_protos.contains(&"v1.chat".to_string()) {
                                Some("v1.chat".to_string())
                            } else {
                                None
                            }
                        },
                    )
                    .expect("server handshake");

                    assert_eq!(server.subprotocol.as_deref(), Some("v2.chat"));

                    // Respond to ping / echo message
                    let msg = server.recv_message().expect("recv client msg");
                    if let WsMessage::Text(t) = msg {
                        server
                            .send_text(&format!("ACK:{}", t))
                            .expect("server send");
                    }
                    accepted += 1;
                }
                GLOBAL_SCHEDULER.yield_now();
                std::thread::sleep(Duration::from_millis(5));
            }
        });

        // Test connection pool
        let pool = AsyncWsPool::new(
            "127.0.0.1",
            addr.port(),
            "/chat",
            vec!["v1.chat".to_string(), "v2.chat".to_string()],
            2,
        );

        assert_eq!(pool.idle_count(), 0);
        assert_eq!(pool.active_count(), 0);

        // Acquire connection 1
        let mut conn1 = pool.acquire().expect("acquire ws conn1");
        assert_eq!(conn1.subprotocol.as_deref(), Some("v2.chat"));
        assert_eq!(pool.active_count(), 1);

        conn1.send_text("hello_pool").expect("send ws");
        let reply = conn1.recv_message().expect("recv reply");
        match reply {
            WsMessage::Text(t) => assert_eq!(t, "ACK:hello_pool"),
            _ => panic!("Expected text response"),
        }

        // Release connection 1 back to pool
        pool.release(conn1);
        assert_eq!(pool.idle_count(), 1);
        assert_eq!(pool.active_count(), 0);

        // Re-acquire from pool (reuses idle connection)
        let conn_reused = pool.acquire().expect("re-acquire ws conn");
        assert_eq!(pool.idle_count(), 0);
        assert_eq!(pool.active_count(), 1);
        assert_eq!(conn_reused.subprotocol.as_deref(), Some("v2.chat"));

        pool.release(conn_reused);
        assert_eq!(pool.idle_count(), 1);
        assert_eq!(pool.active_count(), 0);

        pool.clear();
        assert_eq!(pool.idle_count(), 0);

        // Verify diagnostic stats telemetry
        let stats = pool.stats();
        assert_eq!(stats.host, "127.0.0.1");
        assert_eq!(stats.port, addr.port());
        assert_eq!(stats.path, "/chat");
        assert_eq!(stats.idle_connections, 0);
        assert_eq!(stats.active_connections, 0);
        assert_eq!(stats.max_connections, 2);
        assert_eq!(
            stats.protocols,
            vec!["v1.chat".to_string(), "v2.chat".to_string()]
        );
        assert_eq!(stats.total_connections(), 0);
        assert!(!stats.is_exhausted());
    }

    #[test]
    fn test_async_http2_handshake_and_bidirectional_streams() {
        let listener = AsyncTcpListener::bind("127.0.0.1:0").expect("bind http2 listener");
        let addr = listener.local_addr().expect("local addr");

        let handle = std::thread::spawn(move || {
            let mut server_conn = None;
            for _ in 0..100 {
                if let Ok(Some((stream, _))) = listener.try_accept() {
                    let h2 = AsyncHttp2Connection::server_handshake(stream)
                        .expect("server h2 handshake");
                    server_conn = Some(h2);
                    break;
                }
                GLOBAL_SCHEDULER.yield_now();
                std::thread::sleep(Duration::from_millis(5));
            }

            let mut server = server_conn.expect("accepted http2 connection");

            // Server receives frames
            let mut received_requests = 0;
            while received_requests < 2 {
                let frame = server.recv_frame().expect("server recv frame");
                match frame {
                    crate::simd_parser::Http2Frame::Headers {
                        stream_id,
                        end_stream: true,
                        ..
                    } => {
                        // Send response
                        let res_headers = vec![
                            (":status", "200"),
                            ("content-type", "text/plain"),
                            ("server", "ifa-http2"),
                        ];
                        server
                            .send_response(stream_id, &res_headers, Some(b"hello h2 response"))
                            .expect("server send response");
                        received_requests += 1;
                    }
                    crate::simd_parser::Http2Frame::Data {
                        stream_id,
                        end_stream: true,
                        data,
                    } => {
                        assert_eq!(data, b"client h2 payload");
                        let res_headers = vec![
                            (":status", "201"),
                            ("content-type", "application/octet-stream"),
                        ];
                        server
                            .send_response(stream_id, &res_headers, Some(b"received payload"))
                            .expect("server send post response");
                        received_requests += 1;
                    }
                    _ => {}
                }
            }

            // Server sends Ping
            let ping = crate::simd_parser::Http2Frame::Ping {
                ack: false,
                opaque_data: [1, 2, 3, 4, 5, 6, 7, 8],
            };
            server.send_frame(&ping).expect("server send ping");

            // Receive Ping ACK
            let ack_frame = server.recv_frame().expect("server recv ping ack");
            if let crate::simd_parser::Http2Frame::Ping { ack, opaque_data } = ack_frame {
                assert!(ack);
                assert_eq!(opaque_data, [1, 2, 3, 4, 5, 6, 7, 8]);
            } else {
                panic!("Expected Ping ACK");
            }
        });

        // Client connects and performs handshake
        let stream = AsyncTcpStream::connect(addr).expect("client connect");
        let mut client =
            AsyncHttp2Connection::client_handshake(stream).expect("client h2 handshake");

        // Client receives server SETTINGS and automatically replies with ACK
        let frame1 = client.recv_frame().expect("client recv server settings");
        let frame2 = client
            .recv_frame()
            .expect("client recv server settings ack");
        // One of them is Settings { ack: false, .. } and the other is Settings { ack: true, .. }
        assert!(matches!(
            frame1,
            crate::simd_parser::Http2Frame::Settings { .. }
        ));
        assert!(matches!(
            frame2,
            crate::simd_parser::Http2Frame::Settings { .. }
        ));

        // Request 1: GET /api/status (Headers only, end_stream=true)
        let get_headers = vec![
            (":method", "GET"),
            (":path", "/api/status"),
            (":scheme", "https"),
            (":authority", "localhost"),
        ];
        let stream1 = client
            .send_request(&get_headers, None)
            .expect("client send get request");
        assert_eq!(stream1, 1);

        // Receive response for stream 1
        let resp_headers_frame = client.recv_frame().expect("client recv resp headers");
        if let crate::simd_parser::Http2Frame::Headers { stream_id, .. } = resp_headers_frame {
            assert_eq!(stream_id, 1);
        } else {
            panic!(
                "Expected Headers frame for stream 1, got {:?}",
                resp_headers_frame
            );
        }

        let resp_data_frame = client.recv_frame().expect("client recv resp data");
        if let crate::simd_parser::Http2Frame::Data {
            stream_id, data, ..
        } = resp_data_frame
        {
            assert_eq!(stream_id, 1);
            assert_eq!(data, b"hello h2 response");
        } else {
            panic!("Expected Data frame for stream 1");
        }

        // Request 2: POST /api/submit (Headers + Data)
        let post_headers = vec![
            (":method", "POST"),
            (":path", "/api/submit"),
            (":scheme", "https"),
            (":authority", "localhost"),
        ];
        let stream2 = client
            .send_request(&post_headers, Some(b"client h2 payload"))
            .expect("client send post request");
        assert_eq!(stream2, 3);

        // Receive response for stream 2
        let resp2_headers_frame = client.recv_frame().expect("client recv resp2 headers");
        if let crate::simd_parser::Http2Frame::Headers { stream_id, .. } = resp2_headers_frame {
            assert_eq!(stream_id, 3);
        } else {
            panic!("Expected Headers frame for stream 2");
        }

        let resp2_data_frame = client.recv_frame().expect("client recv resp2 data");
        if let crate::simd_parser::Http2Frame::Data {
            stream_id, data, ..
        } = resp2_data_frame
        {
            assert_eq!(stream_id, 3);
            assert_eq!(data, b"received payload");
        } else {
            panic!("Expected Data frame for stream 2");
        }

        // Handle server Ping (try_recv_frame/recv_frame auto replies with Pong)
        let ping_frame = client.recv_frame().expect("client recv server ping");
        if let crate::simd_parser::Http2Frame::Ping { ack, .. } = ping_frame {
            assert!(!ack);
        } else {
            panic!("Expected incoming Ping from server");
        }

        handle.join().expect("server thread finished");
    }

    #[test]
    fn test_http2_high_level_request_api() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");

        let handle = std::thread::spawn(move || {
            let (std_stream, _) = listener.accept().expect("accept connection");
            std_stream.set_nonblocking(true).expect("set nonblocking");
            let stream = AsyncTcpStream::from_std(std_stream).expect("async tcp stream");

            let mut server =
                AsyncHttp2Connection::server_handshake(stream).expect("server h2 handshake");

            // Accept frames and serve response
            loop {
                let frame = server.recv_frame().expect("server recv frame");
                match frame {
                    crate::simd_parser::Http2Frame::Headers {
                        stream_id,
                        end_stream,
                        ..
                    } => {
                        if end_stream {
                            let res_headers = vec![
                                (":status", "200"),
                                ("content-type", "application/json"),
                                ("server", "ifa-http2"),
                            ];
                            server
                                .send_response(
                                    stream_id,
                                    &res_headers,
                                    Some(b"{\"status\":\"ok\",\"h2\":true}"),
                                )
                                .expect("server send response");
                        }
                    }
                    crate::simd_parser::Http2Frame::GoAway { .. } => break,
                    _ => {}
                }
            }
        });

        let stream = AsyncTcpStream::connect(addr).expect("client connect");
        let mut client =
            AsyncHttp2Connection::client_handshake(stream).expect("client h2 handshake");

        // High-level request
        let resp = client
            .request(
                "GET",
                "/api/v1/health",
                &[("accept", "application/json")],
                None,
            )
            .expect("client request");

        assert_eq!(resp.status.0, 200);
        assert_eq!(resp.headers.get("content-type"), Some("application/json"));
        assert_eq!(resp.headers.get("server"), Some("ifa-http2"));
        assert_eq!(resp.body_str().unwrap(), "{\"status\":\"ok\",\"h2\":true}");

        client
            .send_goaway(crate::simd_parser::Http2ErrorCode::NoError)
            .expect("client send goaway");

        handle.join().expect("server thread finished");
    }

    #[test]
    fn test_async_http2_rst_stream_and_drain() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");

        let handle = std::thread::spawn(move || {
            let (std_stream, _) = listener.accept().expect("accept connection");
            std_stream.set_nonblocking(true).expect("set nonblocking");
            let stream = AsyncTcpStream::from_std(std_stream).expect("async tcp stream");

            let mut server =
                AsyncHttp2Connection::server_handshake(stream).expect("server h2 handshake");

            // Server receives frames
            loop {
                let frame = server.recv_frame().expect("server recv frame");
                match frame {
                    crate::simd_parser::Http2Frame::Headers {
                        stream_id,
                        end_stream,
                        ..
                    } => {
                        if end_stream {
                            // If stream_id == 1, server resets it with RefusedStream
                            if stream_id == 1 {
                                server
                                    .rst_stream(
                                        stream_id,
                                        crate::simd_parser::Http2ErrorCode::RefusedStream,
                                    )
                                    .expect("server send rst_stream");
                            } else {
                                let res_headers = vec![(":status", "200")];
                                server
                                    .send_response(stream_id, &res_headers, Some(b"ok stream 3"))
                                    .expect("server send response");
                            }
                        }
                    }
                    crate::simd_parser::Http2Frame::RstStream {
                        stream_id,
                        error_code,
                    } => {
                        assert_eq!(error_code, crate::simd_parser::Http2ErrorCode::Cancel);
                        assert_eq!(stream_id, 5);
                        break;
                    }
                    crate::simd_parser::Http2Frame::GoAway { .. } => break,
                    _ => {}
                }
            }
        });

        let stream = AsyncTcpStream::connect(addr).expect("client connect");
        let mut client =
            AsyncHttp2Connection::client_handshake(stream).expect("client h2 handshake");

        // 1. Client initiates stream 1
        let s1 = client
            .send_request(&[(":method", "GET"), (":path", "/aborted")], None)
            .expect("send req 1");
        assert_eq!(s1, 1);

        // Client attempts to recv response for stream 1, which will be reset by server
        let err = client.recv_response_for(s1).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
        assert!(err.to_string().contains("RefusedStream"));

        // Check that session stream state is Closed
        let stream_info = client.session.streams.get(&s1).unwrap();
        assert_eq!(
            stream_info.state,
            crate::simd_parser::Http2StreamState::Closed
        );
        assert_eq!(
            stream_info.reset_error,
            Some(crate::simd_parser::Http2ErrorCode::RefusedStream)
        );

        // 2. Client initiates stream 3, which succeeds normally (proving connection multiplexing intact)
        let s3 = client
            .send_request(&[(":method", "GET"), (":path", "/normal")], None)
            .expect("send req 3");
        assert_eq!(s3, 3);

        let (_headers3, body3) = client.recv_response_for(s3).expect("recv resp 3");
        assert_eq!(body3, b"ok stream 3");

        // 3. Client actively cancels stream 5 and drains it
        let s5 = client
            .send_request(&[(":method", "POST"), (":path", "/cancel-me")], None)
            .expect("send req 5");
        assert_eq!(s5, 5);

        client
            .rst_stream(s5, crate::simd_parser::Http2ErrorCode::Cancel)
            .expect("client send rst_stream");
        client.drain_stream(s5).expect("client drain stream");

        assert_eq!(
            client.session.streams.get(&s5).unwrap().state,
            crate::simd_parser::Http2StreamState::Closed
        );

        client
            .send_goaway(crate::simd_parser::Http2ErrorCode::NoError)
            .expect("client send goaway");

        handle.join().expect("server thread finished");
    }

    #[test]
    fn test_async_http2_flow_control_large_payload() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");

        // Large payload: 70,000 bytes (exceeds default initial window size 65535 bytes)
        let large_payload = vec![b'X'; 70000];
        let expected_payload = large_payload.clone();

        let handle = std::thread::spawn(move || {
            let (std_stream, _) = listener.accept().expect("accept connection");
            std_stream.set_nonblocking(true).expect("set nonblocking");
            let stream = AsyncTcpStream::from_std(std_stream).expect("async tcp stream");

            let mut server =
                AsyncHttp2Connection::server_handshake(stream).expect("server h2 handshake");

            loop {
                let frame = server.recv_frame().expect("server recv frame");
                match frame {
                    crate::simd_parser::Http2Frame::Headers {
                        stream_id,
                        end_stream,
                        ..
                    } => {
                        if end_stream {
                            let res_headers = vec![
                                (":status", "200"),
                                ("content-type", "application/octet-stream"),
                            ];
                            server
                                .send_response(stream_id, &res_headers, Some(&large_payload))
                                .expect("server send large response");
                        }
                    }
                    crate::simd_parser::Http2Frame::GoAway { .. } => break,
                    _ => {}
                }
            }
        });

        let stream = AsyncTcpStream::connect(addr).expect("client connect");
        let mut client =
            AsyncHttp2Connection::client_handshake(stream).expect("client h2 handshake");

        let resp = client
            .request("GET", "/large-data", &[], None)
            .expect("client request large data");

        assert_eq!(resp.status.0, 200);
        assert_eq!(resp.body.len(), 70000);
        assert_eq!(resp.body, expected_payload);

        client
            .send_goaway(crate::simd_parser::Http2ErrorCode::NoError)
            .expect("client send goaway");

        handle.join().expect("server thread finished");
    }

    #[test]
    fn test_async_http2_push_promise() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");

        let handle = std::thread::spawn(move || {
            let (std_stream, _) = listener.accept().expect("accept connection");
            std_stream.set_nonblocking(true).expect("set nonblocking");
            let stream = AsyncTcpStream::from_std(std_stream).expect("async tcp stream");

            let mut server =
                AsyncHttp2Connection::server_handshake(stream).expect("server h2 handshake");

            loop {
                let frame = server.recv_frame().expect("server recv frame");
                match frame {
                    crate::simd_parser::Http2Frame::Headers {
                        stream_id,
                        end_stream,
                        ..
                    } => {
                        if end_stream {
                            // 1. Send push promise for /style.css on promised stream
                            let push_req_headers = vec![
                                (":method", "GET"),
                                (":path", "/style.css"),
                                (":scheme", "http"),
                            ];
                            let push_res_headers =
                                vec![(":status", "200"), ("content-type", "text/css")];
                            let push_body = b"body { background: #000; }";

                            let promised_id = server
                                .push_promise(
                                    stream_id,
                                    &push_req_headers,
                                    &push_res_headers,
                                    Some(push_body),
                                )
                                .expect("server push promise");
                            assert_eq!(promised_id, 2);

                            // 2. Send main response for stream_id
                            let res_headers =
                                vec![(":status", "200"), ("content-type", "text/html")];
                            let main_body = b"<html><head><link rel=\"stylesheet\" href=\"/style.css\"></head></html>";
                            server
                                .send_response(stream_id, &res_headers, Some(main_body))
                                .expect("server send response");
                        }
                    }
                    crate::simd_parser::Http2Frame::GoAway { .. } => break,
                    _ => {}
                }
            }
        });

        let stream = AsyncTcpStream::connect(addr).expect("client connect");
        let mut client =
            AsyncHttp2Connection::client_handshake(stream).expect("client h2 handshake");

        // Client sends main request
        let resp = client
            .request("GET", "/index.html", &[], None)
            .expect("client request main index");

        assert_eq!(resp.status.0, 200);
        assert!(resp.body.starts_with(b"<html>"));

        // Verify that the promised stream (id = 2) was registered in push_promises cache
        let promised_req = client
            .get_push_promise_request(2)
            .expect("promised request found");
        let path_header = promised_req
            .iter()
            .find(|(k, _)| k == ":path")
            .map(|(_, v)| v.as_str());
        assert_eq!(path_header, Some("/style.css"));

        // Receive the promised response from stream 2
        let (p_headers, p_body) = client.recv_response_for(2).expect("recv promised response");
        let status = p_headers
            .iter()
            .find(|(k, _)| k == ":status")
            .map(|(_, v)| v.as_str());
        assert_eq!(status, Some("200"));
        assert_eq!(p_body, b"body { background: #000; }");

        client
            .send_goaway(crate::simd_parser::Http2ErrorCode::NoError)
            .expect("client send goaway");

        handle.join().expect("server thread finished");
    }

    #[test]
    fn test_async_http2_pool_reusability_and_multiplexing() {
        let listener = AsyncTcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        let port = addr.port();

        let handle = std::thread::spawn(move || {
            let mut server_conn = None;
            for _ in 0..100 {
                if let Ok(Some((stream, _))) = listener.try_accept() {
                    let h2 = AsyncHttp2Connection::server_handshake(stream)
                        .expect("server h2 handshake");
                    server_conn = Some(h2);
                    break;
                }
                GLOBAL_SCHEDULER.yield_now();
                std::thread::sleep(Duration::from_millis(5));
            }

            let mut server = server_conn.expect("server accepted");

            loop {
                match server.recv_frame() {
                    Ok(crate::simd_parser::Http2Frame::Headers {
                        stream_id,
                        end_stream,
                        ..
                    }) => {
                        if end_stream {
                            let res_headers =
                                vec![(":status", "200"), ("x-server-info", "h2-pool-test")];
                            let body = format!("response-for-stream-{}", stream_id);
                            server
                                .send_response(stream_id, &res_headers, Some(body.as_bytes()))
                                .expect("server send response");
                        }
                    }
                    Ok(crate::simd_parser::Http2Frame::Data {
                        stream_id,
                        end_stream: true,
                        ..
                    }) => {
                        let res_headers =
                            vec![(":status", "200"), ("x-server-info", "h2-pool-test")];
                        let body = format!("response-for-stream-{}", stream_id);
                        server
                            .send_response(stream_id, &res_headers, Some(body.as_bytes()))
                            .expect("server send response");
                    }
                    Ok(crate::simd_parser::Http2Frame::GoAway { .. }) => break,
                    Err(_) => break,
                    _ => {}
                }
            }
        });

        let pool = AsyncHttp2Pool::new("127.0.0.1", port, 2).with_max_concurrent_streams(50);
        assert_eq!(pool.idle_count(), 0);
        assert_eq!(pool.active_count(), 0);

        // 1. First request: acquires connection, runs request, releases to pool
        let resp1 = pool
            .execute_request("GET", "/api/item/1", &[], None)
            .expect("request 1 via pool");
        assert_eq!(resp1.status.0, 200);
        assert_eq!(resp1.body, b"response-for-stream-1");
        assert_eq!(pool.idle_count(), 1);
        assert_eq!(pool.active_count(), 0);

        // 2. Second request on the reused idle connection: multiplexing next stream id
        let resp2 = pool
            .execute_request("POST", "/api/item/2", &[], Some(b"ping"))
            .expect("request 2 via pool reused");
        assert_eq!(resp2.status.0, 200);
        assert_eq!(resp2.body, b"response-for-stream-3");
        assert_eq!(pool.idle_count(), 1);

        // Close and clear idle pool
        let mut conn = pool.acquire().expect("acquire to close");
        let _ = conn.send_goaway(crate::simd_parser::Http2ErrorCode::NoError);
        pool.release(conn);
        pool.clear();
        assert_eq!(pool.idle_count(), 0);

        // Connect a throwaway client to cleanly release server thread if needed
        let _ = AsyncTcpStream::connect(format!("127.0.0.1:{}", port))
            .and_then(AsyncHttp2Connection::client_handshake)
            .and_then(|mut c| c.send_goaway(crate::simd_parser::Http2ErrorCode::NoError));

        let _ = handle.join();
    }

    #[test]
    fn test_async_http2_priority_frames() {
        let listener = AsyncTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let port = listener.local_addr().expect("local addr").port();

        let handle = std::thread::spawn(move || {
            let mut server = loop {
                match listener.accept() {
                    Ok((stream, _)) => match AsyncHttp2Connection::server_handshake(stream) {
                        Ok(conn) => break conn,
                        Err(_) => continue,
                    },
                    Err(_) => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                }
            };

            loop {
                match server.recv_frame() {
                    Ok(crate::simd_parser::Http2Frame::Priority {
                        stream_id,
                        exclusive,
                        stream_dependency,
                        weight,
                    }) => {
                        assert_eq!(stream_id, 3);
                        assert_eq!(stream_dependency, 1);
                        assert_eq!(weight, 42);
                        assert!(!exclusive);
                        break;
                    }
                    Ok(crate::simd_parser::Http2Frame::GoAway { .. }) => break,
                    Err(_) => break,
                    _ => {}
                }
            }
            let _ = server.send_goaway(crate::simd_parser::Http2ErrorCode::NoError);
        });

        let client_stream =
            AsyncTcpStream::connect(format!("127.0.0.1:{}", port)).expect("connect client");
        let mut client =
            AsyncHttp2Connection::client_handshake(client_stream).expect("client handshake");

        // Set priority for stream 3 depending on stream 1 with weight 42
        client
            .set_priority(3, 1, 42, false)
            .expect("client set priority");

        let prioritized = client.prioritized_streams();
        assert!(prioritized.contains(&3));

        let _ = client.send_goaway(crate::simd_parser::Http2ErrorCode::NoError);
        let _ = handle.join();
    }

    #[test]
    fn test_async_http2_streaming_compression() {
        let listener = AsyncTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let port = listener.local_addr().expect("local addr").port();

        let handle = std::thread::spawn(move || {
            let mut server = loop {
                match listener.accept() {
                    Ok((stream, _)) => match AsyncHttp2Connection::server_handshake(stream) {
                        Ok(conn) => break conn,
                        Err(_) => continue,
                    },
                    Err(_) => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                }
            };

            // Wait for incoming HEADERS frame on stream 1
            let stream_id = loop {
                match server.recv_frame().expect("server recv frame") {
                    crate::simd_parser::Http2Frame::Headers {
                        stream_id: sid,
                        end_stream,
                        ..
                    } => {
                        if end_stream {
                            break sid;
                        }
                    }
                    crate::simd_parser::Http2Frame::GoAway { .. } => return,
                    _ => {}
                }
            };

            // Send response headers indicating gzip encoding
            let resp_headers = [(":status", "200"), ("content-encoding", "gzip")];
            let h_frame = server
                .session
                .create_headers_frame(stream_id, &resp_headers, false);
            server.send_frame(&h_frame).expect("send headers");

            // Stream response chunks compressed with GzipStreamEncoder
            let mut encoder = crate::http::GzipStreamEncoder::new();
            server
                .send_streaming_gzip_chunk(stream_id, &mut encoder, b"hello streaming ", false)
                .expect("send chunk 1");
            server
                .send_streaming_gzip_chunk(stream_id, &mut encoder, b"http2 compression!", true)
                .expect("send chunk 2 final");

            let _ = server.recv_frame();
            let _ = server.send_goaway(crate::simd_parser::Http2ErrorCode::NoError);
        });

        let client_stream =
            AsyncTcpStream::connect(format!("127.0.0.1:{}", port)).expect("connect client");
        let mut client =
            AsyncHttp2Connection::client_handshake(client_stream).expect("client handshake");

        // High-level request should automatically decode stream-level gzip
        let resp = client
            .request("GET", "/compressed-stream", &[], None)
            .expect("h2 request");

        assert_eq!(resp.status.0, 200);
        assert_eq!(resp.body, b"hello streaming http2 compression!");

        let _ = client.send_goaway(crate::simd_parser::Http2ErrorCode::NoError);
        let _ = handle.join();
    }

    #[test]
    fn test_async_http2_pool_prioritized_batch() {
        let listener = AsyncTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let port = listener.local_addr().expect("local addr").port();

        let handle = std::thread::spawn(move || {
            let mut server = loop {
                match listener.accept() {
                    Ok((stream, _)) => match AsyncHttp2Connection::server_handshake(stream) {
                        Ok(conn) => break conn,
                        Err(_) => continue,
                    },
                    Err(_) => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                }
            };

            // Respond to two requests: stream 1 and stream 3
            let mut responded = 0;
            while responded < 2 {
                match server.recv_frame().expect("server recv frame") {
                    crate::simd_parser::Http2Frame::Headers {
                        stream_id,
                        end_stream,
                        ..
                    } => {
                        if end_stream {
                            let resp_headers = [(":status", "200")];
                            let body_text = format!("response-stream-{}", stream_id);
                            server
                                .send_response(stream_id, &resp_headers, Some(body_text.as_bytes()))
                                .expect("send response");
                            responded += 1;
                        }
                    }
                    crate::simd_parser::Http2Frame::Priority { .. } => {}
                    crate::simd_parser::Http2Frame::GoAway { .. } => break,
                    _ => {}
                }
            }

            // Drain until GoAway or closure
            loop {
                match server.recv_frame() {
                    Ok(crate::simd_parser::Http2Frame::GoAway { .. }) => break,
                    Err(_) => break,
                    _ => {}
                }
            }
            let _ = server.send_goaway(crate::simd_parser::Http2ErrorCode::NoError);
        });

        let pool = AsyncHttp2Pool::new("127.0.0.1", port, 2);

        // Stream 1 (normal weight 16), Stream 2 in batch (configured with higher weight 128)
        let batch = vec![
            Http2PrioritizedRequest::new("GET", "/low-prio").with_priority(0, 10, false),
            Http2PrioritizedRequest::new("GET", "/high-prio").with_priority(0, 200, false),
        ];

        let results = pool
            .execute_prioritized_batch(batch)
            .expect("execute prioritized batch");

        assert_eq!(results.len(), 2);
        // The higher weight stream (stream 3) should be received and collected first in the ordered batch
        let first = &results[0];
        let second = &results[1];

        assert_eq!(first.0, 3);
        assert_eq!(first.1.as_ref().unwrap().body, b"response-stream-3");

        assert_eq!(second.0, 1);
        assert_eq!(second.1.as_ref().unwrap().body, b"response-stream-1");

        // Connection was released back into pool
        assert_eq!(pool.idle_count(), 1);
        assert_eq!(pool.active_count(), 0);

        let mut conn = pool.acquire().expect("acquire to close");
        let _ = conn.send_goaway(crate::simd_parser::Http2ErrorCode::NoError);
        pool.release(conn);
        pool.clear();

        let _ = handle.join();
    }

    #[test]
    fn test_async_http2_ping_and_pool_health_check() {
        let listener = AsyncTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let port = listener.local_addr().expect("local addr").port();

        let handle = std::thread::spawn(move || {
            let mut server = loop {
                match listener.accept() {
                    Ok((stream, _)) => match AsyncHttp2Connection::server_handshake(stream) {
                        Ok(conn) => break conn,
                        Err(_) => continue,
                    },
                    Err(_) => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                }
            };

            // Loop and auto-reply to PING frames (handled automatically inside recv_frame/try_recv_frame)
            loop {
                match server.recv_frame() {
                    Ok(crate::simd_parser::Http2Frame::GoAway { .. }) => break,
                    Err(_) => break,
                    _ => {}
                }
            }
        });

        let pool = AsyncHttp2Pool::new("127.0.0.1", port, 2);

        // 1. Acquire connection and verify ping RTT round-trip
        let mut conn = pool.acquire().expect("acquire connection");
        let ping_payload = *b"pingpong";
        conn.ping(ping_payload).expect("ping roundtrip");

        // 2. Release back to pool and verify idle count
        pool.release(conn);
        assert_eq!(pool.idle_count(), 1);

        // 3. Health-check idle connections in pool
        let removed = pool.health_check();
        assert_eq!(removed, 0);
        assert_eq!(pool.idle_count(), 1);

        // 4. Test shutdown
        pool.shutdown();
        assert_eq!(pool.idle_count(), 0);

        let _ = handle.join();
    }

    #[test]
    fn test_async_http2_goaway_with_debug_payload() {
        let listener = AsyncTcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let port = listener.local_addr().expect("local addr").port();

        let handle = std::thread::spawn(move || {
            let mut server = loop {
                match listener.accept() {
                    Ok((stream, _)) => match AsyncHttp2Connection::server_handshake(stream) {
                        Ok(conn) => break conn,
                        Err(_) => continue,
                    },
                    Err(_) => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                }
            };

            let frame = server.recv_frame().expect("recv goaway frame");
            match frame {
                crate::simd_parser::Http2Frame::GoAway {
                    last_stream_id,
                    error_code,
                    debug_data,
                } => {
                    assert_eq!(
                        error_code,
                        crate::simd_parser::Http2ErrorCode::InternalError
                    );
                    assert_eq!(&debug_data[..], b"fatal connection degradation");
                    assert_eq!(last_stream_id, 0);
                }
                other => panic!("Expected GoAway frame, got {:?}", other),
            }
        });

        let stream =
            AsyncTcpStream::connect(format!("127.0.0.1:{}", port)).expect("connect client");
        let mut client = AsyncHttp2Connection::client_handshake(stream).expect("client handshake");

        client
            .send_goaway_with_debug(
                crate::simd_parser::Http2ErrorCode::InternalError,
                b"fatal connection degradation",
            )
            .expect("send goaway with debug");
        assert!(client.is_closed());

        let _ = handle.join();
    }

    #[test]
    fn test_async_http2_drain_graceful_and_pool_shutdown() {
        let listener = AsyncTcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.local_addr().expect("local addr").port();

        let handle = std::thread::spawn(move || {
            let mut server = loop {
                match listener.accept() {
                    Ok((stream, _)) => match AsyncHttp2Connection::server_handshake(stream) {
                        Ok(conn) => break conn,
                        Err(_) => continue,
                    },
                    Err(_) => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                }
            };

            // Recv request frame
            let stream_id = loop {
                match server.recv_frame().expect("recv frame") {
                    crate::simd_parser::Http2Frame::Headers {
                        stream_id: sid,
                        end_stream: true,
                        ..
                    } => break sid,
                    crate::simd_parser::Http2Frame::Data {
                        stream_id: sid,
                        end_stream: true,
                        ..
                    } => break sid,
                    crate::simd_parser::Http2Frame::GoAway { .. } => return,
                    _ => {}
                }
            };

            // Send back complete response to close the stream gracefully
            let res_headers = [(":status", "200")];
            server
                .send_response(stream_id, &res_headers, Some(b"graceful drain response"))
                .expect("send response");

            // Recv GoAway (ignoring any late Settings ACK or Pings)
            loop {
                let frame = server.recv_frame().expect("recv frame");
                match frame {
                    crate::simd_parser::Http2Frame::GoAway { .. } => break,
                    crate::simd_parser::Http2Frame::Settings { .. }
                    | crate::simd_parser::Http2Frame::Ping { .. } => continue,
                    other => panic!("Expected GoAway frame, got {:?}", other),
                }
            }
        });

        let pool = AsyncHttp2Pool::new("127.0.0.1", port, 2);
        let mut conn = pool.acquire().expect("acquire connection from pool");

        // Send a request
        let req_headers = [(":method", "GET"), (":path", "/drain-test")];
        let sid = conn.send_request(&req_headers, None).expect("send request");
        assert_eq!(sid, 1);

        // Receive the response
        let (resp_headers, body) = conn.recv_response_for(sid).expect("recv response");
        assert_eq!(body, b"graceful drain response");
        assert!(resp_headers
            .iter()
            .any(|(k, v)| k == ":status" && v == "200"));

        // Test conn.drain_graceful (stream is already completed/closed)
        assert!(conn.drain_graceful(500).is_ok());

        // Release connection back to pool
        pool.release(conn);
        assert_eq!(pool.idle_count(), 1);

        // Test pool drain_and_shutdown
        pool.drain_and_shutdown(500);
        assert_eq!(pool.idle_count(), 0);

        let _ = handle.join();
    }

    #[test]
    fn test_async_http2_dynamic_settings_negotiation() {
        let listener = AsyncTcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.local_addr().expect("local addr").port();

        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept connection");
            let mut server =
                AsyncHttp2Connection::server_handshake(stream).expect("server handshake");

            // Server receives initial client settings during handshake or immediately after
            // Drain until initial settings frame is processed
            let frame = server.recv_frame().expect("server recv client settings");
            assert!(matches!(
                frame,
                crate::simd_parser::Http2Frame::Settings { .. }
            ));

            // Server inspects peer setting
            let max_streams = server
                .get_peer_setting(crate::simd_parser::Http2SettingId::MaxConcurrentStreams)
                .expect("peer max concurrent streams");
            assert_eq!(max_streams, 100);

            // Server dynamically sends custom updated settings to client
            let new_settings = [
                crate::simd_parser::Http2Setting {
                    id: crate::simd_parser::Http2SettingId::MaxConcurrentStreams,
                    value: 250,
                },
                crate::simd_parser::Http2Setting {
                    id: crate::simd_parser::Http2SettingId::HeaderTableSize,
                    value: 8192,
                },
            ];
            server
                .send_settings(&new_settings)
                .expect("server send updated settings");

            // Receive client ACK or request
            let ack_frame = server.recv_frame().expect("recv client ack");
            if let crate::simd_parser::Http2Frame::Settings { ack, .. } = ack_frame {
                assert!(ack);
            }
            // Keep connection open until client finishes
            std::thread::sleep(Duration::from_millis(50));
        });

        // Client connects and performs handshake
        let client_stream =
            AsyncTcpStream::connect(format!("127.0.0.1:{}", port)).expect("connect to server");
        let mut client =
            AsyncHttp2Connection::client_handshake(client_stream).expect("client handshake");

        // Client receives frames from server until updated settings are received
        // (the server sends initial settings, ACK for client's initial settings, and the updated settings)
        let mut received_updated_settings = false;
        for _ in 0..5 {
            let frame = client.recv_frame().expect("client recv frame");
            if let crate::simd_parser::Http2Frame::Settings {
                ack: false,
                settings,
            } = frame
            {
                if settings.iter().any(|s| {
                    s.id == crate::simd_parser::Http2SettingId::MaxConcurrentStreams
                        && s.value == 250
                }) {
                    received_updated_settings = true;
                    break;
                }
            }
        }
        assert!(
            received_updated_settings,
            "Client should receive updated settings"
        );

        // Verify client session recorded peer settings
        assert_eq!(
            client.get_peer_setting(crate::simd_parser::Http2SettingId::MaxConcurrentStreams),
            Some(250)
        );
        assert_eq!(
            client.get_peer_setting(crate::simd_parser::Http2SettingId::HeaderTableSize),
            Some(8192)
        );

        let _ = handle.join();
    }

    #[test]
    fn test_async_http2_trailers() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.local_addr().unwrap().port();

        let handle = std::thread::spawn(move || {
            let (std_stream, _) = listener.accept().expect("accept connection");
            let stream = AsyncTcpStream::from_std(std_stream).expect("async stream");
            let mut server =
                AsyncHttp2Connection::server_handshake(stream).expect("server handshake");

            // Recv request
            let stream_id = loop {
                match server.recv_frame().expect("recv frame") {
                    crate::simd_parser::Http2Frame::Headers {
                        stream_id: sid,
                        end_stream: true,
                        ..
                    } => break sid,
                    crate::simd_parser::Http2Frame::Data {
                        stream_id: sid,
                        end_stream: true,
                        ..
                    } => break sid,
                    _ => {}
                }
            };

            // Send initial response HEADERS with end_stream = false
            let headers_frame = server.session.create_headers_frame(
                stream_id,
                &[(":status", "200"), ("content-type", "text/plain")],
                false,
            );
            server.send_frame(&headers_frame).expect("send headers");

            // Send DATA with end_stream = false
            server
                .send_data(stream_id, b"chunked stream data with trailers", false)
                .expect("send data");

            // Send trailing HEADERS (trailers) with end_stream = true
            let trailers = [
                ("grpc-status", "0"),
                ("x-checksum-sha256", "abcdef0123456789"),
            ];
            server
                .send_trailers(stream_id, &trailers)
                .expect("send trailers");

            // Keep alive briefly for client to receive
            std::thread::sleep(Duration::from_millis(50));
        });

        let client_stream =
            AsyncTcpStream::connect(format!("127.0.0.1:{}", port)).expect("connect to server");
        let mut client =
            AsyncHttp2Connection::client_handshake(client_stream).expect("client handshake");

        // Send GET request
        let req_headers = [(":method", "GET"), (":path", "/stream-with-trailers")];
        let sid = client
            .send_request(&req_headers, None)
            .expect("send request");
        assert_eq!(sid, 1);

        // Receive response
        let (resp_headers, body) = client.recv_response_for(sid).expect("recv response");
        assert_eq!(body, b"chunked stream data with trailers");
        assert!(resp_headers
            .iter()
            .any(|(k, v)| k == ":status" && v == "200"));

        // Verify trailers were captured in get_trailers
        let trailers = client.get_trailers(sid).expect("trailers recorded");
        assert_eq!(trailers.len(), 2);
        assert!(trailers.iter().any(|(k, v)| k == "grpc-status" && v == "0"));
        assert!(trailers
            .iter()
            .any(|(k, v)| k == "x-checksum-sha256" && v == "abcdef0123456789"));

        let _ = handle.join();
    }

    #[test]
    fn test_async_http2_pool_goaway_handling() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.local_addr().expect("local addr").port();

        let handle = std::thread::spawn(move || {
            let (tcp_stream, _) = listener.accept().expect("accept connection");
            let async_stream = AsyncTcpStream::from_std(tcp_stream).expect("async stream");
            let mut server =
                AsyncHttp2Connection::server_handshake(async_stream).expect("server handshake");

            // Wait for request
            let req_stream_id;
            loop {
                let frame = server.recv_frame().expect("recv frame");
                if let crate::simd_parser::Http2Frame::Headers {
                    stream_id,
                    end_stream,
                    ..
                } = frame
                {
                    if end_stream {
                        req_stream_id = stream_id;
                        break;
                    }
                }
            }

            // Send 200 response
            server
                .send_response(req_stream_id, &[(":status", "200")], Some(b"first ok"))
                .expect("send response");

            // Server initiates GOAWAY with EnhanceYourCalm (rate limit warning)
            server
                .send_goaway_with_debug(
                    crate::simd_parser::Http2ErrorCode::EnhanceYourCalm,
                    b"rate limit exceeded",
                )
                .expect("send goaway");

            // Keep alive briefly
            std::thread::sleep(Duration::from_millis(50));
        });

        let pool = AsyncHttp2Pool::new("127.0.0.1", port, 2);
        assert_eq!(pool.idle_count(), 0);

        // 1. Acquire connection, send request and get response
        let mut conn = pool.acquire().expect("acquire connection");
        let sid = conn
            .send_request(&[(":method", "GET"), (":path", "/hello")], None)
            .expect("send request");
        let (_, body) = conn.recv_response_for(sid).expect("recv response");
        assert_eq!(body, b"first ok");

        // Release connection back to pool (at this point server sends GOAWAY)
        // Wait tiny bit for GOAWAY packet to arrive on socket
        std::thread::sleep(Duration::from_millis(60));

        pool.release(conn);

        // Since connection received GOAWAY, pool.release should detect it and drop it, OR
        // pool.health_check() should filter it out, OR next acquire should discard it.
        // Let's verify health_check or acquire:
        if pool.idle_count() > 0 {
            let dead = pool.health_check();
            assert_eq!(dead, 1);
            assert_eq!(pool.idle_count(), 0);
        } else {
            assert_eq!(pool.idle_count(), 0);
        }
        assert_eq!(
            pool.last_goaway_error(),
            Some(crate::simd_parser::Http2ErrorCode::EnhanceYourCalm)
        );
        pool.clear_goaway_error();
        assert_eq!(pool.last_goaway_error(), None);

        let _ = handle.join();
    }

    #[test]
    fn test_async_http2_pool_execute_with_retry_success_on_first_attempt() {
        // Server that accepts one connection, responds 200, then cleanly closes.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.local_addr().expect("local addr").port();

        let handle = std::thread::spawn(move || {
            let (tcp_stream, _) = listener.accept().expect("accept connection");
            let async_stream = AsyncTcpStream::from_std(tcp_stream).expect("async stream");
            let mut server =
                AsyncHttp2Connection::server_handshake(async_stream).expect("server handshake");

            while let Ok(frame) = server.recv_frame() {
                if let crate::simd_parser::Http2Frame::Headers {
                    stream_id,
                    end_stream,
                    ..
                } = frame
                {
                    if end_stream {
                        server
                            .send_response(stream_id, &[(":status", "200")], Some(b"retry-ok"))
                            .expect("send response");
                        // Graceful GOAWAY so pool release discards cleanly
                        let _ = server.send_goaway(crate::simd_parser::Http2ErrorCode::NoError);
                        break;
                    }
                }
            }
        });

        let pool = AsyncHttp2Pool::new("127.0.0.1", port, 2);
        let resp = pool
            .execute_request_with_retry("GET", "/", &[], None, 2)
            .expect("request with retry should succeed");
        assert_eq!(resp.status, crate::http::HttpStatus(200));
        assert_eq!(resp.body, b"retry-ok");

        let _ = handle.join();
    }

    #[test]
    fn test_async_http2_pool_execute_with_retry_fatal_goaway_no_retry() {
        // A pool whose recorded GOAWAY error is fatal must refuse with no retry.
        // We seed the error via a server that sends ProtocolError GOAWAY, then
        // verify the pool detects it before attempting the next request.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.local_addr().expect("local addr").port();

        let handle = std::thread::spawn(move || {
            // First connection: respond then send fatal GOAWAY
            if let Ok((tcp_stream, _)) = listener.accept() {
                let async_stream = AsyncTcpStream::from_std(tcp_stream).expect("async stream");
                let mut server =
                    AsyncHttp2Connection::server_handshake(async_stream).expect("server handshake");
                while let Ok(frame) = server.recv_frame() {
                    if let crate::simd_parser::Http2Frame::Headers {
                        stream_id,
                        end_stream,
                        ..
                    } = frame
                    {
                        if end_stream {
                            server
                                .send_response(stream_id, &[(":status", "200")], Some(b"seed"))
                                .ok();
                            // Send fatal protocol error GOAWAY
                            server
                                .send_goaway(crate::simd_parser::Http2ErrorCode::ProtocolError)
                                .ok();
                            break;
                        }
                    }
                }
                std::thread::sleep(Duration::from_millis(60));
            }
        });

        let pool = AsyncHttp2Pool::new("127.0.0.1", port, 2);

        // 1. First request succeeds, seeding the fatal GOAWAY into the pool
        let mut conn = pool.acquire().expect("acquire");
        let sid = conn
            .send_request(&[(":method", "GET"), (":path", "/seed")], None)
            .expect("send request");
        let _ = conn.recv_response_for(sid).expect("recv response");
        std::thread::sleep(Duration::from_millis(70));
        pool.release(conn);

        // Force health-check to flush any pending GOAWAY still buffered in socket.
        pool.health_check();

        // Pool should have recorded ProtocolError
        assert_eq!(
            pool.last_goaway_error(),
            Some(crate::simd_parser::Http2ErrorCode::ProtocolError)
        );

        // 2. execute_request_with_retry must detect the fatal GOAWAY and refuse immediately
        let result = pool.execute_request_with_retry("GET", "/", &[], None, 3);
        assert!(result.is_err(), "fatal GOAWAY must not be retried");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("PROTOCOL_ERROR") || msg.contains("non-retryable"),
            "error message should mention the error code: {msg}"
        );

        let _ = handle.join();
    }

    #[test]
    fn test_async_http2_pool_stats_telemetry() {
        let pool = AsyncHttp2Pool::new("127.0.0.1", 8080, 5).with_max_concurrent_streams(50);
        let stats = pool.stats();

        assert_eq!(stats.idle_connections, 0);
        assert_eq!(stats.active_connections, 0);
        assert_eq!(stats.max_connections, 5);
        assert_eq!(stats.max_concurrent_streams_per_conn, 50);
        assert_eq!(stats.last_goaway_error, None);
        assert_eq!(stats.last_alpn_negotiated, None);
        assert_eq!(stats.total_connections(), 0);
        assert!(!stats.is_exhausted());

        pool.record_alpn_negotiated(AlpnProtocol::Http2);
        assert_eq!(pool.last_alpn_negotiated(), Some(AlpnProtocol::Http2));
        assert_eq!(pool.stats().last_alpn_negotiated, Some(AlpnProtocol::Http2));

        pool.clear_alpn_negotiated();
        assert_eq!(pool.last_alpn_negotiated(), None);
    }

    #[test]
    fn test_async_http2_pool_alpn_config_negotiation() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.local_addr().expect("local addr").port();

        let handle = std::thread::spawn(move || {
            let (tcp_stream, _) = listener.accept().expect("accept");
            let async_stream = AsyncTcpStream::from_std(tcp_stream).expect("async");
            let mut server =
                AsyncHttp2Connection::server_handshake(async_stream).expect("server handshake");
            while let Ok(frame) = server.recv_frame() {
                if let crate::simd_parser::Http2Frame::Headers {
                    stream_id,
                    end_stream,
                    ..
                } = frame
                {
                    if end_stream {
                        server
                            .send_response(
                                stream_id,
                                &[(":status", "200"), ("content-length", "2")],
                                Some(b"ok"),
                            )
                            .expect("send response");
                        let _ = server.send_goaway(crate::simd_parser::Http2ErrorCode::NoError);
                        std::thread::sleep(Duration::from_millis(50));
                        break;
                    }
                }
            }
        });

        // 1. With default HTTP/2 ALPN config -> negotiated protocol is recorded as Http2
        let pool = AsyncHttp2Pool::new("127.0.0.1", port, 2).with_tls_config(TlsConfig::default());
        assert_eq!(pool.last_alpn_negotiated(), None);

        let resp = pool
            .execute_request("GET", "/alpn-test", &[], None)
            .expect("request");
        assert_eq!(resp.status.0, 200);
        assert_eq!(pool.last_alpn_negotiated(), Some(AlpnProtocol::Http2));
        assert_eq!(pool.stats().last_alpn_negotiated, Some(AlpnProtocol::Http2));

        let _ = handle.join();

        // 2. With HTTP/1.1-only ALPN config -> acquiring connection must fail immediately due to non-multiplexed protocol
        let listener2 = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener 2");
        let port2 = listener2.local_addr().expect("local addr 2").port();

        let pool_h11 =
            AsyncHttp2Pool::new("127.0.0.1", port2, 2).with_tls_config(TlsConfig::http11_only());
        match pool_h11.acquire() {
            Ok(_) => panic!("expected acquire to fail on http11-only ALPN config"),
            Err(err) => {
                assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
                assert_eq!(pool_h11.last_alpn_negotiated(), Some(AlpnProtocol::Http11));
            }
        }
    }

    #[test]
    fn test_async_http2_pool_interceptors() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.local_addr().expect("local addr").port();

        let handle = std::thread::spawn(move || {
            let (tcp_stream, _) = listener.accept().expect("accept connection");
            let async_stream = AsyncTcpStream::from_std(tcp_stream).expect("async stream");
            let mut server =
                AsyncHttp2Connection::server_handshake(async_stream).expect("server handshake");

            while let Ok(frame) = server.recv_frame() {
                if let crate::simd_parser::Http2Frame::Headers {
                    stream_id,
                    end_stream,
                    ..
                } = frame
                {
                    if end_stream {
                        server
                            .send_response(
                                stream_id,
                                &[(":status", "200"), ("x-server", "h2-test")],
                                Some(b"server-payload"),
                            )
                            .expect("send response");
                        let _ = server.send_goaway(crate::simd_parser::Http2ErrorCode::NoError);
                        // Give client time to read response frames before socket closes
                        std::thread::sleep(Duration::from_millis(50));
                        break;
                    }
                }
            }
        });

        // Test request & response mutation interceptors
        let pool = AsyncHttp2Pool::new("127.0.0.1", port, 2)
            .with_request_interceptor(|req| {
                req.headers
                    .push(("x-custom-auth".to_string(), "token-123".to_string()));
                None // Do not short-circuit
            })
            .with_response_interceptor(|_req, resp| {
                resp.headers.set("x-intercepted", "true");
            });

        assert_eq!(pool.request_interceptor_count(), 1);
        assert_eq!(pool.response_interceptor_count(), 1);

        let resp = pool
            .execute_request("GET", "/test-interceptor", &[], None)
            .expect("execute request with interceptors");

        assert_eq!(resp.status.0, 200);
        assert_eq!(resp.body, b"server-payload");
        assert_eq!(resp.headers.get("x-intercepted"), Some("true"));

        let _ = handle.join();
    }

    #[test]
    fn test_async_http2_pool_interceptor_short_circuit() {
        // Without any server running, a short-circuiting interceptor should return immediately without connecting
        let pool = AsyncHttp2Pool::new("127.0.0.1", 65530, 2)
            .with_request_interceptor(|req| {
                if req.path == "/cached" {
                    let mut cached = crate::http::HttpResponse::new(crate::http::HttpStatus(200));
                    cached.body = b"cached-body".to_vec();
                    cached.headers.set("x-cache", "HIT");
                    return Some(cached);
                }
                None
            })
            .with_response_interceptor(|_req, resp| {
                resp.headers.set("x-post-processed", "yes");
            });

        let resp = pool
            .execute_request("GET", "/cached", &[], None)
            .expect("short-circuit should not fail on network");

        assert_eq!(resp.status.0, 200);
        assert_eq!(resp.body, b"cached-body");
        assert_eq!(resp.headers.get("x-cache"), Some("HIT"));
        assert_eq!(resp.headers.get("x-post-processed"), Some("yes"));
        assert_eq!(pool.active_count(), 0);
        assert_eq!(pool.idle_count(), 0);
    }

    #[test]
    fn test_async_http2_pool_lru_and_ttl_eviction() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.local_addr().expect("local addr").port();

        let handle = std::thread::spawn(move || {
            // Server thread: accept connections, perform handshake, then handle incoming frames
            while let Ok((tcp_stream, _)) = listener.accept() {
                let async_stream = match AsyncTcpStream::from_std(tcp_stream) {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let mut server = match AsyncHttp2Connection::server_handshake(async_stream) {
                    Ok(s) => s,
                    Err(_) => break,
                };
                while let Ok(frame) = server.recv_frame() {
                    if let crate::simd_parser::Http2Frame::Ping { ack, opaque_data } = frame {
                        if !ack {
                            let _ = server.send_frame(&crate::simd_parser::Http2Frame::Ping {
                                ack: true,
                                opaque_data,
                            });
                        }
                    } else if let crate::simd_parser::Http2Frame::GoAway { .. } = frame {
                        break;
                    }
                }
            }
        });

        // 1. Test LRU capacity bound eviction: max_connections = 2
        let pool =
            AsyncHttp2Pool::new("127.0.0.1", port, 2).with_idle_ttl(Duration::from_millis(50));

        let conn1 = pool.acquire().expect("acquire 1");
        let conn2 = pool.acquire().expect("acquire 2");

        assert_eq!(pool.active_count(), 2);
        assert_eq!(pool.idle_count(), 0);
        assert_eq!(pool.evicted_count(), 0);

        pool.release(conn1);
        pool.release(conn2);

        assert_eq!(pool.active_count(), 0);
        assert_eq!(pool.idle_count(), 2);

        // 2. Test manual sweep before TTL expires: 0 evicted
        let swept = pool.sweep_idle_connections(Some(Duration::from_secs(10)));
        assert_eq!(swept, 0);
        assert_eq!(pool.idle_count(), 2);

        // 3. Wait for TTL to expire (50 ms) and test sweep_idle_connections
        std::thread::sleep(Duration::from_millis(70));
        let swept = pool.sweep_idle_connections(None);
        assert_eq!(swept, 2);
        assert_eq!(pool.idle_count(), 0);
        assert_eq!(pool.evicted_count(), 2);
        assert_eq!(pool.stats().evicted_connections, 2);

        // 4. Test LRU eviction when releasing more than max_connections:
        // Establish 2 connections, release them, then establish a 3rd and release it
        let c1 = pool.acquire().expect("acquire fresh 1");
        let c2 = pool.acquire().expect("acquire fresh 2");
        pool.release(c1);
        pool.release(c2);
        assert_eq!(pool.idle_count(), 2);

        let initial_evicted = pool.evicted_count();
        let c3 = AsyncHttp2Connection::client_handshake(
            AsyncTcpStream::connect(format!("127.0.0.1:{}", port)).expect("connect"),
        )
        .expect("client handshake");
        pool.release(c3); // pool capacity is 2 -> LRU (oldest) evicted!
        assert_eq!(pool.idle_count(), 2);
        assert_eq!(pool.evicted_count(), initial_evicted + 1);

        pool.shutdown();
        let _ = handle;
    }

    #[test]
    fn test_async_http2_backpressure_flow_control() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.local_addr().expect("local addr").port();

        let handle = std::thread::spawn(move || {
            let (tcp_stream, _) = listener.accept().expect("accept connection");
            let async_stream = AsyncTcpStream::from_std(tcp_stream).expect("async stream");
            let mut server =
                AsyncHttp2Connection::server_handshake(async_stream).expect("server handshake");

            let mut received_bytes = 0;
            while let Ok(frame) = server.recv_frame() {
                match frame {
                    crate::simd_parser::Http2Frame::Data {
                        stream_id,
                        end_stream,
                        data,
                    } => {
                        received_bytes += data.len();
                        if end_stream {
                            server
                                .send_response(
                                    stream_id,
                                    &[(":status", "200")],
                                    Some(b"large-data-ack"),
                                )
                                .expect("send response");
                            let _ = server.send_goaway(crate::simd_parser::Http2ErrorCode::NoError);
                            break;
                        }
                    }
                    crate::simd_parser::Http2Frame::Headers { .. } => {}
                    _ => {}
                }
            }
            assert_eq!(received_bytes, 70_000);
        });

        let stream =
            AsyncTcpStream::connect(format!("127.0.0.1:{}", port)).expect("connect client");
        let mut client = AsyncHttp2Connection::client_handshake(stream).expect("client handshake");

        // Send a 70 KB payload across stream (larger than standard initial window of 65535 bytes)
        // This exercises flow control chunking, window depletion, WINDOW_UPDATE reception and backpressure unblocking.
        let large_payload = vec![0x42u8; 70_000];
        let stream_id = client
            .send_request(&[(":method", "POST"), (":path", "/upload")], None)
            .expect("send request headers");

        assert!(client.outbound_window_available(stream_id) > 0);
        assert_eq!(client.stream_window_size(stream_id), Some(65535));
        assert_eq!(client.connection_window_size(), 65535);

        client
            .send_data(stream_id, &large_payload, true)
            .expect("send data with backpressure");

        let (resp_headers, resp_body) = client
            .recv_response_for(stream_id)
            .expect("receive response");
        assert!(resp_headers
            .iter()
            .any(|(k, v)| k == ":status" && v == "200"));
        assert_eq!(resp_body, b"large-data-ack");

        let _ = handle.join();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RFC 6265 — HTTP Cookie Management
// ─────────────────────────────────────────────────────────────────────────────

/// SameSite policy for a cookie (RFC 6265bis).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SameSite {
    Strict,
    Lax,
    None,
}

/// A single HTTP cookie with all RFC 6265 attributes.
#[derive(Debug, Clone)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    /// Restricts cookie to a domain (and sub-domains when prefixed with `.`).
    pub domain: Option<String>,
    /// Restricts cookie to a URL path prefix.
    pub path: Option<String>,
    /// Absolute expiry as seconds since Unix epoch, `None` = session cookie.
    pub expires: Option<u64>,
    /// `Max-Age` in seconds (takes precedence over `Expires` when present).
    pub max_age: Option<i64>,
    /// Only send over HTTPS.
    pub secure: bool,
    /// Not accessible via JavaScript `document.cookie`.
    pub http_only: bool,
    /// SameSite policy.
    pub same_site: Option<SameSite>,
}

impl Cookie {
    /// Create a simple session cookie with only name and value.
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Cookie {
            name: name.into(),
            value: value.into(),
            domain: None,
            path: None,
            expires: None,
            max_age: None,
            secure: false,
            http_only: false,
            same_site: None,
        }
    }

    /// Parse a `Set-Cookie` header value into a `Cookie`.
    ///
    /// Example: `session=abc123; Path=/; HttpOnly; Max-Age=3600`
    pub fn parse_set_cookie(raw: &str) -> Option<Self> {
        let mut parts = raw.splitn(2, ';');
        let name_value = parts.next()?.trim();
        let (name, value) = name_value.split_once('=')?;
        let name = name.trim().to_string();
        let value = value.trim().to_string();

        let mut cookie = Cookie::new(name, value);

        if let Some(attrs) = parts.next() {
            for attr in attrs.split(';') {
                let attr = attr.trim();
                if attr.is_empty() {
                    continue;
                }
                if let Some((k, v)) = attr.split_once('=') {
                    let k = k.trim().to_ascii_lowercase();
                    let v = v.trim();
                    match k.as_str() {
                        "domain" => {
                            cookie.domain = Some(v.to_string());
                        }
                        "path" => {
                            cookie.path = Some(v.to_string());
                        }
                        "max-age" => {
                            cookie.max_age = v.parse::<i64>().ok();
                        }
                        "expires" => {
                            // Best-effort RFC 1123 parsing: ignore parse errors
                            cookie.expires = parse_http_date(v);
                        }
                        "samesite" => {
                            cookie.same_site = match v.to_ascii_lowercase().as_str() {
                                "strict" => Some(SameSite::Strict),
                                "lax" => Some(SameSite::Lax),
                                "none" => Some(SameSite::None),
                                _ => None,
                            };
                        }
                        _ => {}
                    }
                } else {
                    match attr.to_ascii_lowercase().as_str() {
                        "httponly" => cookie.http_only = true,
                        "secure" => cookie.secure = true,
                        _ => {}
                    }
                }
            }
        }
        Some(cookie)
    }

    /// Serialize the cookie for a `Cookie:` request header (`name=value`).
    pub fn to_header_value(&self) -> String {
        format!("{}={}", self.name, self.value)
    }

    /// Returns `true` if the cookie has expired relative to `now_secs` (Unix epoch).
    pub fn is_expired(&self, now_secs: u64) -> bool {
        if let Some(max_age) = self.max_age {
            if max_age <= 0 {
                return true;
            }
        }
        if let Some(exp) = self.expires {
            return now_secs >= exp;
        }
        false
    }

    /// Returns `true` if cookie matches `domain` per RFC 6265 §5.1.3 domain matching.
    pub fn matches_domain(&self, host: &str) -> bool {
        match &self.domain {
            None => true,
            Some(d) => {
                let d = d.trim_start_matches('.');
                let host_lc = host.to_ascii_lowercase();
                let d_lc = d.to_ascii_lowercase();
                host_lc == d_lc || host_lc.ends_with(&format!(".{}", d_lc))
            }
        }
    }

    /// Returns `true` if cookie matches `path` per RFC 6265 §5.1.4.
    pub fn matches_path(&self, request_path: &str) -> bool {
        match &self.path {
            None => true,
            Some(cp) => {
                if request_path == cp {
                    return true;
                }
                if request_path.starts_with(cp.as_str()) {
                    // Cookie path must end with `/` OR request path's next char must be `/`
                    if cp.ends_with('/') {
                        return true;
                    }
                    if let Some(ch) = request_path.chars().nth(cp.len()) {
                        return ch == '/';
                    }
                }
                false
            }
        }
    }
}

/// Best-effort parser for RFC 1123 HTTP-date strings (e.g. `Thu, 01 Jan 2026 00:00:00 GMT`).
/// Returns seconds since Unix epoch, or `None` on parse failure.
fn parse_http_date(s: &str) -> Option<u64> {
    // Expected format: "Wed, 09 Jun 2021 10:18:14 GMT"
    // We parse: day month year hour:min:sec
    let s = s.trim();
    // Skip weekday prefix if present (e.g. "Thu, ")
    let s = if let Some(comma_pos) = s.find(',') {
        s[comma_pos + 1..].trim()
    } else {
        s
    };

    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() < 4 {
        return None;
    }

    let day: u64 = parts[0].parse().ok()?;
    let month: u64 = match parts[1].to_ascii_lowercase().as_str() {
        "jan" => 1,
        "feb" => 2,
        "mar" => 3,
        "apr" => 4,
        "may" => 5,
        "jun" => 6,
        "jul" => 7,
        "aug" => 8,
        "sep" => 9,
        "oct" => 10,
        "nov" => 11,
        "dec" => 12,
        _ => return None,
    };
    let year: u64 = parts[2].parse().ok()?;
    let time_parts: Vec<&str> = parts[3].splitn(3, ':').collect();
    if time_parts.len() < 3 {
        return None;
    }
    let hour: u64 = time_parts[0].parse().ok()?;
    let min: u64 = time_parts[1].parse().ok()?;
    let sec: u64 = time_parts[2].parse().ok()?;

    // Days from epoch (1970-01-01) to the given date — simplified Gregorian calculation
    let days_in_month = [0u64, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if year < 1970 || !(1..=12).contains(&month) || day < 1 {
        return None;
    }
    let is_leap = |y: u64| (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400);
    let mut total_days: u64 = 0;
    for y in 1970..year {
        total_days += if is_leap(y) { 366 } else { 365 };
    }
    for m in 1..month {
        total_days += days_in_month[m as usize];
        if m == 2 && is_leap(year) {
            total_days += 1;
        }
    }
    total_days += day - 1;

    Some(total_days * 86400 + hour * 3600 + min * 60 + sec)
}

/// An in-memory cookie store (jar) keyed by `(domain, path, name)`.
///
/// Thread-safe via internal `std::sync::Mutex`.
pub struct CookieJar {
    /// Stored as `(domain_key, path_key, cookie)` for O(n) domain matching.
    cookies: std::sync::Mutex<Vec<Cookie>>,
}

impl CookieJar {
    /// Create a new, empty cookie jar.
    pub fn new() -> Self {
        CookieJar {
            cookies: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Insert or update a cookie from a `Set-Cookie` header value.
    ///
    /// If a cookie with the same name + domain + path already exists it is replaced.
    pub fn set_from_header(&self, set_cookie_value: &str) {
        if let Some(cookie) = Cookie::parse_set_cookie(set_cookie_value) {
            self.insert(cookie);
        }
    }

    /// Insert or update a cookie directly.
    pub fn insert(&self, cookie: Cookie) {
        let mut jar = self.cookies.lock().unwrap();
        // Replace existing entry with same (name, domain, path)
        for existing in jar.iter_mut() {
            if existing.name == cookie.name
                && existing.domain == cookie.domain
                && existing.path == cookie.path
            {
                *existing = cookie;
                return;
            }
        }
        jar.push(cookie);
    }

    /// Return all cookies applicable to `(host, path)` as a `Cookie:` header value.
    ///
    /// Expired cookies (relative to `now_secs`) are automatically excluded.
    pub fn cookies_for(&self, host: &str, request_path: &str, now_secs: u64) -> String {
        let jar = self.cookies.lock().unwrap();
        let applicable: Vec<&str> = jar
            .iter()
            .filter(|c| {
                !c.is_expired(now_secs) && c.matches_domain(host) && c.matches_path(request_path)
            })
            .map(|c| c.value.as_str()) // collect names separately
            .collect();
        drop(applicable); // drop borrow before rebuilding

        let header_parts: Vec<String> = jar
            .iter()
            .filter(|c| {
                !c.is_expired(now_secs) && c.matches_domain(host) && c.matches_path(request_path)
            })
            .map(|c| c.to_header_value())
            .collect();
        header_parts.join("; ")
    }

    /// Remove all cookies from the jar.
    pub fn clear(&self) {
        self.cookies.lock().unwrap().clear();
    }

    /// Remove all expired cookies (relative to `now_secs`).
    pub fn purge_expired(&self, now_secs: u64) {
        let mut jar = self.cookies.lock().unwrap();
        jar.retain(|c| !c.is_expired(now_secs));
    }

    /// Number of cookies currently stored.
    pub fn len(&self) -> usize {
        self.cookies.lock().unwrap().len()
    }

    /// Returns `true` if the jar contains no cookies.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for CookieJar {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod cookie_tests {
    use super::*;

    // ── Cookie::parse_set_cookie ──────────────────────────────────────────────

    #[test]
    fn test_cookie_parse_simple() {
        let c = Cookie::parse_set_cookie("session=abc123").unwrap();
        assert_eq!(c.name, "session");
        assert_eq!(c.value, "abc123");
        assert!(!c.http_only);
        assert!(!c.secure);
        assert!(c.domain.is_none());
        assert!(c.path.is_none());
    }

    #[test]
    fn test_cookie_parse_full_attributes() {
        let raw =
            "id=xyz; Domain=.example.com; Path=/api; Max-Age=3600; Secure; HttpOnly; SameSite=Lax";
        let c = Cookie::parse_set_cookie(raw).unwrap();
        assert_eq!(c.name, "id");
        assert_eq!(c.value, "xyz");
        assert_eq!(c.domain.as_deref(), Some(".example.com"));
        assert_eq!(c.path.as_deref(), Some("/api"));
        assert_eq!(c.max_age, Some(3600));
        assert!(c.secure);
        assert!(c.http_only);
        assert_eq!(c.same_site, Some(SameSite::Lax));
    }

    #[test]
    fn test_cookie_parse_samesite_strict() {
        let c = Cookie::parse_set_cookie("token=tok; SameSite=Strict").unwrap();
        assert_eq!(c.same_site, Some(SameSite::Strict));
    }

    #[test]
    fn test_cookie_parse_samesite_none() {
        let c = Cookie::parse_set_cookie("sid=s; Secure; SameSite=None").unwrap();
        assert_eq!(c.same_site, Some(SameSite::None));
        assert!(c.secure);
    }

    #[test]
    fn test_cookie_to_header_value() {
        let c = Cookie {
            name: "session".into(),
            value: "abc".into(),
            domain: None,
            path: Some("/".into()),
            expires: None,
            max_age: Some(900),
            secure: true,
            http_only: true,
            same_site: Some(SameSite::Lax),
        };
        assert_eq!(c.to_header_value(), "session=abc");
    }

    // ── Cookie::is_expired ────────────────────────────────────────────────────

    #[test]
    fn test_cookie_not_expired() {
        let c = Cookie {
            name: "k".into(),
            value: "v".into(),
            domain: None,
            path: None,
            expires: Some(9_999_999_999),
            max_age: None,
            secure: false,
            http_only: false,
            same_site: None,
        };
        assert!(!c.is_expired(1_700_000_000));
    }

    #[test]
    fn test_cookie_expired_via_expires() {
        let c = Cookie {
            name: "k".into(),
            value: "v".into(),
            domain: None,
            path: None,
            expires: Some(1_000),
            max_age: None,
            secure: false,
            http_only: false,
            same_site: None,
        };
        assert!(c.is_expired(1_001));
    }

    #[test]
    fn test_cookie_expired_via_max_age_zero() {
        let c = Cookie {
            name: "k".into(),
            value: "v".into(),
            domain: None,
            path: None,
            expires: None,
            max_age: Some(0),
            secure: false,
            http_only: false,
            same_site: None,
        };
        assert!(c.is_expired(0));
    }

    #[test]
    fn test_cookie_expired_via_max_age_negative() {
        let c = Cookie {
            name: "k".into(),
            value: "v".into(),
            domain: None,
            path: None,
            expires: None,
            max_age: Some(-1),
            secure: false,
            http_only: false,
            same_site: None,
        };
        assert!(c.is_expired(0));
    }

    // ── Cookie::matches_domain ────────────────────────────────────────────────

    #[test]
    fn test_cookie_domain_exact_match() {
        let c = Cookie {
            name: "k".into(),
            value: "v".into(),
            domain: Some("example.com".into()),
            path: None,
            expires: None,
            max_age: None,
            secure: false,
            http_only: false,
            same_site: None,
        };
        assert!(c.matches_domain("example.com"));
        assert!(!c.matches_domain("other.com"));
    }

    #[test]
    fn test_cookie_domain_subdomain_match() {
        let c = Cookie {
            name: "k".into(),
            value: "v".into(),
            domain: Some(".example.com".into()),
            path: None,
            expires: None,
            max_age: None,
            secure: false,
            http_only: false,
            same_site: None,
        };
        assert!(c.matches_domain("api.example.com"));
        assert!(c.matches_domain("example.com"));
        assert!(!c.matches_domain("evil.example.com.hack.io"));
    }

    #[test]
    fn test_cookie_domain_none_always_matches() {
        let c = Cookie::new("k", "v");
        assert!(c.matches_domain("anything.example.com"));
    }

    // ── Cookie::matches_path ──────────────────────────────────────────────────

    #[test]
    fn test_cookie_path_exact() {
        let mut c = Cookie::new("k", "v");
        c.path = Some("/api".into());
        assert!(c.matches_path("/api"));
    }

    #[test]
    fn test_cookie_path_prefix_with_slash() {
        let mut c = Cookie::new("k", "v");
        c.path = Some("/api/".into());
        assert!(c.matches_path("/api/users"));
        assert!(!c.matches_path("/apiother"));
    }

    #[test]
    fn test_cookie_path_prefix_without_trailing_slash() {
        let mut c = Cookie::new("k", "v");
        c.path = Some("/api".into());
        assert!(c.matches_path("/api/users"));
        assert!(!c.matches_path("/apiother"));
    }

    #[test]
    fn test_cookie_path_none_always_matches() {
        let c = Cookie::new("k", "v");
        assert!(c.matches_path("/anything"));
    }

    // ── CookieJar ─────────────────────────────────────────────────────────────

    #[test]
    fn test_cookie_jar_insert_and_retrieve() {
        let jar = CookieJar::new();
        jar.set_from_header("session=abc123; Domain=example.com; Path=/");
        assert_eq!(jar.len(), 1);
        let header = jar.cookies_for("example.com", "/", 0);
        assert_eq!(header, "session=abc123");
    }

    #[test]
    fn test_cookie_jar_multiple_cookies() {
        let jar = CookieJar::new();
        jar.set_from_header("a=1; Domain=example.com; Path=/");
        jar.set_from_header("b=2; Domain=example.com; Path=/");
        jar.set_from_header("c=3; Domain=other.com; Path=/");
        let header = jar.cookies_for("example.com", "/", 0);
        assert!(header.contains("a=1"));
        assert!(header.contains("b=2"));
        assert!(!header.contains("c=3"));
    }

    #[test]
    fn test_cookie_jar_replace_on_duplicate_name() {
        let jar = CookieJar::new();
        jar.set_from_header("token=old; Domain=example.com; Path=/");
        jar.set_from_header("token=new; Domain=example.com; Path=/");
        assert_eq!(jar.len(), 1);
        let header = jar.cookies_for("example.com", "/", 0);
        assert!(header.contains("token=new"));
        assert!(!header.contains("token=old"));
    }

    #[test]
    fn test_cookie_jar_excludes_expired() {
        let jar = CookieJar::new();
        jar.insert(Cookie {
            name: "expired".into(),
            value: "yes".into(),
            domain: Some("example.com".into()),
            path: Some("/".into()),
            expires: Some(500),
            max_age: None,
            secure: false,
            http_only: false,
            same_site: None,
        });
        // `now_secs` is past the expiry
        let header = jar.cookies_for("example.com", "/", 1000);
        assert!(header.is_empty());
    }

    #[test]
    fn test_cookie_jar_purge_expired() {
        let jar = CookieJar::new();
        jar.insert(Cookie {
            name: "old".into(),
            value: "v".into(),
            domain: None,
            path: None,
            expires: Some(100),
            max_age: None,
            secure: false,
            http_only: false,
            same_site: None,
        });
        jar.insert(Cookie::new("fresh", "v2"));
        assert_eq!(jar.len(), 2);
        jar.purge_expired(200);
        assert_eq!(jar.len(), 1);
    }

    #[test]
    fn test_cookie_jar_clear() {
        let jar = CookieJar::new();
        jar.set_from_header("a=1");
        jar.set_from_header("b=2");
        jar.clear();
        assert!(jar.is_empty());
    }

    #[test]
    fn test_cookie_jar_subdomain_matching() {
        let jar = CookieJar::new();
        jar.set_from_header("sid=x; Domain=.example.com; Path=/");
        // Should match sub-domains
        let h1 = jar.cookies_for("api.example.com", "/", 0);
        assert!(h1.contains("sid=x"));
        // Should NOT match unrelated domain
        let h2 = jar.cookies_for("evil.com", "/", 0);
        assert!(h2.is_empty());
    }

    #[test]
    fn test_cookie_jar_path_scoping() {
        let jar = CookieJar::new();
        jar.set_from_header("admin=tok; Domain=example.com; Path=/admin");
        // /admin path → match
        let h1 = jar.cookies_for("example.com", "/admin/dashboard", 0);
        assert!(h1.contains("admin=tok"));
        // /public path → no match
        let h2 = jar.cookies_for("example.com", "/public", 0);
        assert!(h2.is_empty());
    }

    // ── parse_http_date ───────────────────────────────────────────────────────

    #[test]
    fn test_parse_http_date_epoch() {
        // 1970-01-01 00:00:00 GMT → 0
        let ts = parse_http_date("Thu, 01 Jan 1970 00:00:00 GMT").unwrap();
        assert_eq!(ts, 0);
    }

    #[test]
    fn test_parse_http_date_known_date() {
        // 2021-06-09 10:18:14 → verify it's after year 2000 epoch offset
        let ts = parse_http_date("Wed, 09 Jun 2021 10:18:14 GMT").unwrap();
        // Known value: 1623233894
        assert_eq!(ts, 1_623_233_894);
    }

    #[test]
    fn test_parse_http_date_invalid() {
        assert!(parse_http_date("not a date").is_none());
        assert!(parse_http_date("").is_none());
    }

    // ── Buffer Memory Reclaim Optimization ────────────────────────────────────

    #[test]
    fn test_ws_demux_buffer_reclaim_optimization() {
        let mut demux = WsDemux::new();
        // Allocate large capacity exceeding threshold (e.g. 128 KiB)
        demux.buffer.reserve(131072);
        assert!(demux.buffer.capacity() >= 131072);

        // Feed a frame
        let f = WsFrame::text("reclaim_test", false, None);
        demux.push_bytes(&f.encode());

        // Polling the frame consumes it completely and triggers shrink_to
        let polled = demux.poll_frame().expect("polled frame");
        assert_eq!(polled.payload, b"reclaim_test");
        assert!(demux.buffer.is_empty());
        assert!(demux.buffer.capacity() <= DEFAULT_MAX_RETAINED_BUFFER_CAPACITY * 2);
    }

    #[test]
    fn test_sse_decoder_buffer_reclaim_optimization() {
        let mut decoder = SseDecoder::new();
        decoder.buffer.reserve(131072);
        assert!(decoder.buffer.capacity() >= 131072);

        decoder.push_str("data: message\n\n");
        let ev = decoder.next_event().expect("next event");
        assert_eq!(ev.data, "message");
        assert!(decoder.buffer.is_empty());
        assert!(decoder.buffer.capacity() <= DEFAULT_MAX_RETAINED_BUFFER_CAPACITY * 2);
    }

    #[test]
    fn test_network_primitive_micro_benchmarks() {
        let report = run_net_benchmark_suite(100);
        assert!(report.total_duration_ms >= 0.0);
        assert_eq!(report.benchmarks.len(), 4);

        for b in &report.benchmarks {
            assert!(b.iterations > 0);
            assert!(b.ops_per_sec >= 0.0);
            assert!(b.ns_per_op >= 0.0);
        }

        // Direct test of multithreaded TCP throughput benchmark
        let tcp_res = benchmark_tcp_throughput(4, 50, 128).expect("tcp throughput benchmark");
        assert_eq!(tcp_res.iterations, 200);
        assert!(tcp_res.ops_per_sec > 0.0);
        assert!(tcp_res.total_time_ms > 0.0);

        // Multithreaded endurance and throughput stress benchmark for AsyncTcpStream
        let endurance_res =
            benchmark_async_tcp_endurance(4, 30, 256).expect("async tcp endurance benchmark");
        assert_eq!(endurance_res.concurrent_conns, 4);
        assert_eq!(endurance_res.total_cycles, 120);
        assert_eq!(endurance_res.error_count, 0);
        assert!(endurance_res.ops_per_sec > 0.0);
        assert!(endurance_res.throughput_mb_per_sec >= 0.0);
        assert!(endurance_res.total_bytes_transferred == 120 * 256 * 2);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TLS / ALPN — Automatic HTTP/1.1 vs HTTP/2 Protocol Negotiation
// ─────────────────────────────────────────────────────────────────────────────

/// Application-layer protocols advertised / negotiated over ALPN (RFC 7301).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlpnProtocol {
    /// HTTP/2 over TLS (`h2`).
    Http2,
    /// HTTP/1.1 over TLS (`http/1.1`).
    Http11,
    /// HTTP/1.0 (`http/1.0`).
    Http10,
    /// Unknown / unsupported protocol identifier.
    Unknown,
}

impl AlpnProtocol {
    /// Canonical ALPN wire-format identifier (RFC 7301 §3.1).
    pub fn as_wire_id(&self) -> &'static [u8] {
        match self {
            AlpnProtocol::Http2 => b"h2",
            AlpnProtocol::Http11 => b"http/1.1",
            AlpnProtocol::Http10 => b"http/1.0",
            AlpnProtocol::Unknown => b"",
        }
    }

    /// Parse a raw ALPN wire identifier into the enum variant.
    pub fn from_wire_id(id: &[u8]) -> Self {
        match id {
            b"h2" => AlpnProtocol::Http2,
            b"http/1.1" => AlpnProtocol::Http11,
            b"http/1.0" => AlpnProtocol::Http10,
            _ => AlpnProtocol::Unknown,
        }
    }

    /// Whether this protocol supports multiplexed streams (HTTP/2+).
    #[inline]
    pub fn supports_multiplexing(&self) -> bool {
        matches!(self, AlpnProtocol::Http2)
    }
}

impl std::fmt::Display for AlpnProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlpnProtocol::Http2 => f.write_str("h2"),
            AlpnProtocol::Http11 => f.write_str("http/1.1"),
            AlpnProtocol::Http10 => f.write_str("http/1.0"),
            AlpnProtocol::Unknown => f.write_str("<unknown>"),
        }
    }
}

// ── TLS ClientHello ALPN Extension Decoder ───────────────────────────────────

/// TLS record content-type constants (RFC 5246 §6.2.1).
mod tls_const {
    pub const HANDSHAKE: u8 = 0x16;
    pub const CLIENT_HELLO: u8 = 0x01;
    pub const EXT_ALPN: u16 = 0x0010;
}

/// Outcome of a TLS ClientHello ALPN parse attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlpnParseResult {
    /// ALPN extension found; contains the list of protocols advertised by the client.
    Protocols(Vec<AlpnProtocol>),
    /// TLS ClientHello contained no ALPN extension.
    NoExtension,
    /// Buffer too short or malformed — need more bytes.
    Incomplete,
    /// Buffer does not begin with a TLS ClientHello record.
    NotClientHello,
}

/// Parse the ALPN extension from a raw TLS ClientHello record byte slice.
///
/// The slice must start at the first byte of a TLS record (content-type byte).
/// Returns the list of `AlpnProtocol` values the client advertises, in order.
///
/// # Wire format (abbreviated)
/// ```text
/// TLS record header  : content_type(1) + version(2) + length(2)
/// Handshake header   : msg_type(1) + length(3)
/// ClientHello        : version(2) + random(32) + session_id(1+n)
///                    + cipher_suites(2+2n) + compression(1+n)
///                    + extensions_total_len(2) + [ext_type(2) + ext_len(2) + ext_data]*
/// ALPN extension (0x0010):
///   ext_data         : alpn_list_len(2) + [proto_len(1) + proto_id(n)]*
/// ```
pub fn parse_alpn_from_client_hello(buf: &[u8]) -> AlpnParseResult {
    // Minimum: 5 (record hdr) + 4 (handshake hdr) + 2 (version) + 32 (random) = 43 bytes
    if buf.len() < 43 {
        return AlpnParseResult::Incomplete;
    }

    // TLS record header
    if buf[0] != tls_const::HANDSHAKE {
        return AlpnParseResult::NotClientHello;
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if buf.len() < 5 + record_len {
        return AlpnParseResult::Incomplete;
    }

    let hs = &buf[5..5 + record_len];
    if hs.is_empty() || hs[0] != tls_const::CLIENT_HELLO {
        return AlpnParseResult::NotClientHello;
    }

    // Handshake body starts after msg_type(1) + length(3)
    if hs.len() < 4 {
        return AlpnParseResult::Incomplete;
    }
    let body = &hs[4..];

    // Skip: version(2) + random(32)
    let mut pos = 34usize;
    if body.len() < pos + 1 {
        return AlpnParseResult::Incomplete;
    }
    // Session ID
    let sid_len = body[pos] as usize;
    pos += 1 + sid_len;
    // Cipher suites
    if body.len() < pos + 2 {
        return AlpnParseResult::Incomplete;
    }
    let cs_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2 + cs_len;
    // Compression methods
    if body.len() < pos + 1 {
        return AlpnParseResult::Incomplete;
    }
    let comp_len = body[pos] as usize;
    pos += 1 + comp_len;

    // Extensions
    if body.len() < pos + 2 {
        return AlpnParseResult::NoExtension;
    }
    let ext_total = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_total;
    if body.len() < ext_end {
        return AlpnParseResult::Incomplete;
    }

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let ext_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > ext_end {
            break;
        }
        if ext_type == tls_const::EXT_ALPN {
            let ext_data = &body[pos..pos + ext_len];
            return decode_alpn_extension(ext_data);
        }
        pos += ext_len;
    }
    AlpnParseResult::NoExtension
}

fn decode_alpn_extension(data: &[u8]) -> AlpnParseResult {
    if data.len() < 2 {
        return AlpnParseResult::Incomplete;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + list_len {
        return AlpnParseResult::Incomplete;
    }
    let list = &data[2..2 + list_len];
    let mut protocols = Vec::new();
    let mut i = 0;
    while i < list.len() {
        let plen = list[i] as usize;
        i += 1;
        if i + plen > list.len() {
            break;
        }
        protocols.push(AlpnProtocol::from_wire_id(&list[i..i + plen]));
        i += plen;
    }
    AlpnParseResult::Protocols(protocols)
}

// ── TLS/ALPN Negotiation Configuration ───────────────────────────────────────

/// Priority-ordered list of protocols a server is willing to serve.
/// The first match against the client's preference list wins (server preference).
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Protocols the server supports, in descending priority order.
    pub server_protocols: Vec<AlpnProtocol>,
    /// Whether to fall back to HTTP/1.1 when the client sends no ALPN extension.
    pub fallback_to_http11: bool,
}

impl Default for TlsConfig {
    /// Default: prefer HTTP/2, accept HTTP/1.1, enable fallback.
    fn default() -> Self {
        Self {
            server_protocols: vec![AlpnProtocol::Http2, AlpnProtocol::Http11],
            fallback_to_http11: true,
        }
    }
}

impl TlsConfig {
    /// Create a configuration that only accepts HTTP/2 (`h2`).
    pub fn http2_only() -> Self {
        Self {
            server_protocols: vec![AlpnProtocol::Http2],
            fallback_to_http11: false,
        }
    }

    /// Create a configuration that only accepts HTTP/1.1.
    pub fn http11_only() -> Self {
        Self {
            server_protocols: vec![AlpnProtocol::Http11],
            fallback_to_http11: true,
        }
    }

    /// Build the ALPN extension bytes that a **client** would send, encoding
    /// the protocol list from `server_protocols` in wire format (RFC 7301 §3.1).
    ///
    /// Layout: `[total_list_len(2)] [proto_len(1) proto_bytes]*`
    pub fn encode_alpn_extension(&self) -> Vec<u8> {
        let mut inner: Vec<u8> = Vec::new();
        for proto in &self.server_protocols {
            let id = proto.as_wire_id();
            if id.is_empty() {
                continue;
            }
            inner.push(id.len() as u8);
            inner.extend_from_slice(id);
        }
        let mut out = Vec::with_capacity(2 + inner.len());
        let len = inner.len() as u16;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend(inner);
        out
    }
}

// ── ALPN Negotiator ───────────────────────────────────────────────────────────

/// Result of an ALPN negotiation attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NegotiatedProtocol {
    /// A mutually supported protocol was selected.
    Selected(AlpnProtocol),
    /// No common protocol found; connection should be rejected (RFC 7301 §3.2).
    NoMatch,
    /// Client sent no ALPN extension; fallback applied per `TlsConfig`.
    Fallback(AlpnProtocol),
}

impl NegotiatedProtocol {
    /// Return the selected protocol, regardless of whether it was negotiated or fell back.
    pub fn protocol(&self) -> Option<AlpnProtocol> {
        match self {
            NegotiatedProtocol::Selected(p) | NegotiatedProtocol::Fallback(p) => Some(*p),
            NegotiatedProtocol::NoMatch => None,
        }
    }

    /// Whether the connection should proceed (a protocol was selected).
    pub fn is_accepted(&self) -> bool {
        self.protocol().is_some()
    }
}

/// Stateless ALPN negotiator: matches client-offered protocols against server configuration.
///
/// Used by TLS termination code to determine which HTTP version to serve before the
/// first application byte is exchanged.
pub struct AlpnNegotiator {
    config: TlsConfig,
}

impl AlpnNegotiator {
    /// Create a negotiator from a [`TlsConfig`].
    pub fn new(config: TlsConfig) -> Self {
        Self { config }
    }

    /// Negotiate given a list of protocols offered by the client (from ALPN extension).
    ///
    /// Uses **server-preference** ordering: iterates `server_protocols` and picks the
    /// first one that also appears in `client_protocols`.
    pub fn negotiate(&self, client_protocols: &[AlpnProtocol]) -> NegotiatedProtocol {
        for server_proto in &self.config.server_protocols {
            if client_protocols.contains(server_proto) {
                return NegotiatedProtocol::Selected(*server_proto);
            }
        }
        NegotiatedProtocol::NoMatch
    }

    /// Negotiate directly from a raw TLS ClientHello byte slice.
    ///
    /// - If ALPN extension is present → runs `negotiate()`.
    /// - If no ALPN extension → applies `fallback_to_http11` policy.
    /// - If the buffer is incomplete/malformed → returns `Err` with a description.
    pub fn negotiate_from_client_hello(&self, buf: &[u8]) -> Result<NegotiatedProtocol, String> {
        match parse_alpn_from_client_hello(buf) {
            AlpnParseResult::Protocols(protos) => Ok(self.negotiate(&protos)),
            AlpnParseResult::NoExtension => {
                if self.config.fallback_to_http11 {
                    Ok(NegotiatedProtocol::Fallback(AlpnProtocol::Http11))
                } else {
                    Ok(NegotiatedProtocol::NoMatch)
                }
            }
            AlpnParseResult::Incomplete => Err("TLS ClientHello buffer is incomplete".into()),
            AlpnParseResult::NotClientHello => {
                Err("Buffer does not start with a TLS ClientHello record".into())
            }
        }
    }

    /// Encode the server's ALPN extension bytes for use in a TLS ServerHello.
    pub fn server_alpn_extension(&self) -> Vec<u8> {
        self.config.encode_alpn_extension()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TLS/ALPN — Tests
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tls_alpn_tests {
    use super::*;

    // ── AlpnProtocol ─────────────────────────────────────────────────────────

    #[test]
    fn test_alpn_protocol_wire_round_trip() {
        for proto in [
            AlpnProtocol::Http2,
            AlpnProtocol::Http11,
            AlpnProtocol::Http10,
        ] {
            assert_eq!(AlpnProtocol::from_wire_id(proto.as_wire_id()), proto);
        }
    }

    #[test]
    fn test_alpn_protocol_unknown_wire_id() {
        assert_eq!(AlpnProtocol::from_wire_id(b"h3"), AlpnProtocol::Unknown);
        assert_eq!(AlpnProtocol::from_wire_id(b""), AlpnProtocol::Unknown);
    }

    #[test]
    fn test_alpn_protocol_display() {
        assert_eq!(AlpnProtocol::Http2.to_string(), "h2");
        assert_eq!(AlpnProtocol::Http11.to_string(), "http/1.1");
        assert_eq!(AlpnProtocol::Http10.to_string(), "http/1.0");
        assert_eq!(AlpnProtocol::Unknown.to_string(), "<unknown>");
    }

    #[test]
    fn test_alpn_protocol_supports_multiplexing() {
        assert!(AlpnProtocol::Http2.supports_multiplexing());
        assert!(!AlpnProtocol::Http11.supports_multiplexing());
        assert!(!AlpnProtocol::Http10.supports_multiplexing());
    }

    // ── TlsConfig ────────────────────────────────────────────────────────────

    #[test]
    fn test_tls_config_default_prefers_http2() {
        let cfg = TlsConfig::default();
        assert_eq!(cfg.server_protocols[0], AlpnProtocol::Http2);
        assert!(cfg.fallback_to_http11);
    }

    #[test]
    fn test_tls_config_encode_alpn_extension_http2_only() {
        let cfg = TlsConfig::http2_only();
        let ext = cfg.encode_alpn_extension();
        // list_len(2) + proto_len(1) + "h2"(2) = 5 bytes
        assert_eq!(ext.len(), 5);
        // first 2 bytes = length of list = 3
        let list_len = u16::from_be_bytes([ext[0], ext[1]]);
        assert_eq!(list_len, 3);
        // proto_len byte
        assert_eq!(ext[2], 2);
        assert_eq!(&ext[3..5], b"h2");
    }

    #[test]
    fn test_tls_config_encode_alpn_extension_http11_then_h2() {
        let cfg = TlsConfig {
            server_protocols: vec![AlpnProtocol::Http11, AlpnProtocol::Http2],
            fallback_to_http11: true,
        };
        let ext = cfg.encode_alpn_extension();
        // "http/1.1" = 8 bytes  → entry = 1+8 = 9
        // "h2"       = 2 bytes  → entry = 1+2 = 3
        // list total = 12; header = 2 → ext = 14 bytes
        assert_eq!(ext.len(), 14);
        let list_len = u16::from_be_bytes([ext[0], ext[1]]);
        assert_eq!(list_len, 12);
    }

    // ── AlpnNegotiator — direct protocol list ─────────────────────────────────

    #[test]
    fn test_negotiator_selects_server_preferred_protocol() {
        let neg = AlpnNegotiator::new(TlsConfig::default());
        // Client offers both; server prefers h2 → h2 wins
        let result = neg.negotiate(&[AlpnProtocol::Http11, AlpnProtocol::Http2]);
        assert_eq!(result, NegotiatedProtocol::Selected(AlpnProtocol::Http2));
        assert!(result.is_accepted());
        assert_eq!(result.protocol(), Some(AlpnProtocol::Http2));
    }

    #[test]
    fn test_negotiator_no_match_returns_no_match() {
        let neg = AlpnNegotiator::new(TlsConfig::http2_only());
        let result = neg.negotiate(&[AlpnProtocol::Http11]);
        assert_eq!(result, NegotiatedProtocol::NoMatch);
        assert!(!result.is_accepted());
        assert_eq!(result.protocol(), None);
    }

    #[test]
    fn test_negotiator_http11_client_matches_http11_server() {
        let neg = AlpnNegotiator::new(TlsConfig::http11_only());
        let result = neg.negotiate(&[AlpnProtocol::Http11]);
        assert_eq!(result, NegotiatedProtocol::Selected(AlpnProtocol::Http11));
    }

    #[test]
    fn test_negotiator_empty_client_list_returns_no_match() {
        let neg = AlpnNegotiator::new(TlsConfig::default());
        let result = neg.negotiate(&[]);
        assert_eq!(result, NegotiatedProtocol::NoMatch);
    }

    // ── AlpnNegotiator — fallback policy ─────────────────────────────────────

    #[test]
    fn test_negotiator_fallback_enabled_when_no_alpn_extension() {
        // Craft a minimal ClientHello with NO extensions
        let hello = build_minimal_client_hello(None);
        let neg = AlpnNegotiator::new(TlsConfig::default()); // fallback = true
        let result = neg.negotiate_from_client_hello(&hello).unwrap();
        assert_eq!(result, NegotiatedProtocol::Fallback(AlpnProtocol::Http11));
        assert!(result.is_accepted());
    }

    #[test]
    fn test_negotiator_fallback_disabled_returns_no_match() {
        let hello = build_minimal_client_hello(None);
        let neg = AlpnNegotiator::new(TlsConfig {
            server_protocols: vec![AlpnProtocol::Http2],
            fallback_to_http11: false,
        });
        let result = neg.negotiate_from_client_hello(&hello).unwrap();
        assert_eq!(result, NegotiatedProtocol::NoMatch);
    }

    // ── AlpnNegotiator — from raw ClientHello with ALPN extension ────────────

    #[test]
    fn test_negotiator_selects_h2_from_client_hello_with_alpn() {
        let alpn_ext = build_alpn_extension(&[b"h2", b"http/1.1"]);
        let hello = build_minimal_client_hello(Some(&alpn_ext));
        let neg = AlpnNegotiator::new(TlsConfig::default());
        let result = neg.negotiate_from_client_hello(&hello).unwrap();
        assert_eq!(result, NegotiatedProtocol::Selected(AlpnProtocol::Http2));
    }

    #[test]
    fn test_negotiator_no_match_from_client_hello_unsupported_protocols() {
        let alpn_ext = build_alpn_extension(&[b"h3", b"spdy/3.1"]);
        let hello = build_minimal_client_hello(Some(&alpn_ext));
        let neg = AlpnNegotiator::new(TlsConfig::default());
        let result = neg.negotiate_from_client_hello(&hello).unwrap();
        assert_eq!(result, NegotiatedProtocol::NoMatch);
    }

    #[test]
    fn test_negotiator_incomplete_buffer_returns_error() {
        let neg = AlpnNegotiator::new(TlsConfig::default());
        let result = neg.negotiate_from_client_hello(&[0x16, 0x03, 0x03]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("incomplete"));
    }

    #[test]
    fn test_negotiator_non_tls_buffer_returns_error() {
        let neg = AlpnNegotiator::new(TlsConfig::default());
        let buf = vec![0x47u8; 60]; // 'G' — HTTP plaintext
        let result = neg.negotiate_from_client_hello(&buf);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("ClientHello"));
    }

    // ── parse_alpn_from_client_hello — edge cases ────────────────────────────

    #[test]
    fn test_parse_alpn_too_short_is_incomplete() {
        assert_eq!(
            parse_alpn_from_client_hello(&[]),
            AlpnParseResult::Incomplete
        );
        assert_eq!(
            parse_alpn_from_client_hello(&[0x16, 0x03, 0x03]),
            AlpnParseResult::Incomplete
        );
    }

    #[test]
    fn test_parse_alpn_not_handshake_record() {
        let mut buf = vec![0u8; 60];
        buf[0] = 0x15; // alert record type
        assert_eq!(
            parse_alpn_from_client_hello(&buf),
            AlpnParseResult::NotClientHello
        );
    }

    #[test]
    fn test_parse_alpn_multiple_protocols_decoded() {
        let alpn_ext = build_alpn_extension(&[b"h2", b"http/1.1", b"http/1.0"]);
        let hello = build_minimal_client_hello(Some(&alpn_ext));
        match parse_alpn_from_client_hello(&hello) {
            AlpnParseResult::Protocols(p) => {
                assert_eq!(p.len(), 3);
                assert_eq!(p[0], AlpnProtocol::Http2);
                assert_eq!(p[1], AlpnProtocol::Http11);
                assert_eq!(p[2], AlpnProtocol::Http10);
            }
            other => panic!("Expected Protocols, got {:?}", other),
        }
    }

    // ── Helpers for building synthetic TLS ClientHello buffers ────────────────

    /// Build the raw bytes of an ALPN extension value (the ext_data portion).
    fn build_alpn_extension(protos: &[&[u8]]) -> Vec<u8> {
        let mut inner: Vec<u8> = Vec::new();
        for p in protos {
            inner.push(p.len() as u8);
            inner.extend_from_slice(p);
        }
        let mut out = Vec::with_capacity(2 + inner.len());
        let list_len = inner.len() as u16;
        out.extend_from_slice(&list_len.to_be_bytes());
        out.extend(inner);
        out
    }

    /// Build a minimal but parseable TLS ClientHello record.
    ///
    /// `alpn_ext` is the raw ALPN extension *value* bytes; if `None`, the
    /// extensions block will be empty (no ALPN extension).
    fn build_minimal_client_hello(alpn_ext: Option<&[u8]>) -> Vec<u8> {
        // ── ClientHello body ──────────────────────────────────────────────────
        let mut body: Vec<u8> = Vec::new();
        // version: TLS 1.2 (0x03, 0x03)
        body.extend_from_slice(&[0x03, 0x03]);
        // random: 32 bytes
        body.extend_from_slice(&[0xABu8; 32]);
        // session_id: empty (len=0)
        body.push(0x00);
        // cipher_suites: one suite (len=2, suite=TLS_AES_128_GCM_SHA256)
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        // compression: 1 method (null)
        body.extend_from_slice(&[0x01, 0x00]);

        // extensions
        let mut exts: Vec<u8> = Vec::new();
        if let Some(alpn) = alpn_ext {
            // ext_type=ALPN (0x0010), ext_len, ext_data
            exts.extend_from_slice(&[0x00, 0x10]);
            let ext_len = alpn.len() as u16;
            exts.extend_from_slice(&ext_len.to_be_bytes());
            exts.extend_from_slice(alpn);
        }
        // extensions total length
        let exts_len = exts.len() as u16;
        body.extend_from_slice(&exts_len.to_be_bytes());
        body.extend(exts);

        // ── Handshake header ─────────────────────────────────────────────────
        let mut hs: Vec<u8> = Vec::new();
        hs.push(tls_const::CLIENT_HELLO); // msg_type
                                          // length: 3 bytes big-endian
        let body_len = body.len() as u32;
        hs.push(((body_len >> 16) & 0xFF) as u8);
        hs.push(((body_len >> 8) & 0xFF) as u8);
        hs.push((body_len & 0xFF) as u8);
        hs.extend(body);

        // ── TLS record header ─────────────────────────────────────────────────
        let mut record: Vec<u8> = Vec::new();
        record.push(tls_const::HANDSHAKE); // content_type
        record.extend_from_slice(&[0x03, 0x03]); // version
        let hs_len = hs.len() as u16;
        record.extend_from_slice(&hs_len.to_be_bytes()); // record length
        record.extend(hs);
        record
    }
}

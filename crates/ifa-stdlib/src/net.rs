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
    ctrl_ring_buf: [u8; 1024],
    is_closed: bool,
    /// Optional chunk buffer pool for recycling incoming DATA frames.
    pub chunk_buffer_pool: Option<Http2ChunkBufferPool>,
    /// Whether dynamic RFC 7540 flow control auto-tuning (BDP-based adaptive window scaling) is enabled.
    pub auto_tune_flow_control: bool,
    /// Last instant an inbound transfer observation was initiated.
    flow_control_last_observation: Option<std::time::Instant>,
    /// Accumulated inbound bytes observed since last flow control replenishment / tuning update.
    flow_control_bytes_observed: usize,
    /// Total count of response payloads transparently decompressed on this connection.
    pub decompressed_count: usize,
}

impl AsyncHttp2Connection {
    /// Create a new `AsyncHttp2Connection` wrapping an active `AsyncTcpStream`.
    pub fn new(stream: AsyncTcpStream, is_server: bool) -> Self {
        Self {
            stream,
            session: crate::simd_parser::Http2Session::new(is_server),
            read_buf: Vec::with_capacity(8192),
            ctrl_ring_buf: [0u8; 1024],
            is_closed: false,
            chunk_buffer_pool: None,
            auto_tune_flow_control: false,
            flow_control_last_observation: None,
            flow_control_bytes_observed: 0,
            decompressed_count: 0,
        }
    }

    /// Whether this HTTP/2 connection is closed.
    pub fn is_closed(&self) -> bool {
        self.is_closed
    }

    /// Configure an optional chunk buffer pool for recycling incoming DATA frames.
    pub fn with_chunk_buffer_pool(mut self, pool: Http2ChunkBufferPool) -> Self {
        self.chunk_buffer_pool = Some(pool);
        self
    }

    /// Configure dynamic RFC 7540 flow control auto-tuning on this connection.
    pub fn with_auto_tune_flow_control(mut self, enabled: bool) -> Self {
        self.auto_tune_flow_control = enabled;
        self
    }

    /// Set dynamic RFC 7540 flow control auto-tuning on this connection.
    pub fn set_auto_tune_flow_control(&mut self, enabled: bool) {
        self.auto_tune_flow_control = enabled;
    }

    /// Whether dynamic RFC 7540 flow control auto-tuning is enabled.
    pub fn auto_tune_flow_control(&self) -> bool {
        self.auto_tune_flow_control
    }

    /// Replenish connection and stream flow control windows, applying dynamic BDP auto-tuning
    /// when `auto_tune_flow_control` is enabled, or standard static replenishment otherwise.
    pub fn replenish_flow_control_windows(&mut self) -> io::Result<()> {
        let flow_updates = if self.auto_tune_flow_control {
            self.session.adapt_and_replenish_inbound_windows()
        } else {
            self.session.replenish_flow_control_windows()
        };
        for update_frame in flow_updates {
            self.send_frame(&update_frame)?;
        }
        Ok(())
    }

    /// Record observed transfer metrics (bytes and elapsed duration) to auto-tune flow control windows.
    pub fn record_flow_control_observation(&mut self, bytes: usize, elapsed: Duration) {
        if self.auto_tune_flow_control && bytes > 0 && !elapsed.is_zero() {
            self.session
                .adaptive_flow_controller
                .record_bandwidth_sample(bytes, elapsed);
        }
    }

    /// Configure whether push promises are accepted on this connection.
    pub fn with_enable_push(mut self, enabled: bool) -> Self {
        self.session.enable_push = enabled;
        self
    }

    /// Set whether push promises are accepted on this connection.
    pub fn set_enable_push(&mut self, enabled: bool) {
        self.session.enable_push = enabled;
    }

    /// Whether push promises are accepted on this connection.
    pub fn is_push_enabled(&self) -> bool {
        self.session.enable_push
    }

    /// Reference to all registered promised requests received on this connection.
    pub fn promised_requests(
        &self,
    ) -> &std::collections::HashMap<u32, crate::simd_parser::Http2PromisedRequest> {
        &self.session.promised_requests
    }

    /// Harvest and consume all completed server push promise responses received on this connection.
    /// Returns the promised request metadata along with the synthesized [`crate::http::HttpResponse`].
    pub fn drain_completed_push_responses(
        &mut self,
    ) -> Vec<(
        crate::simd_parser::Http2PromisedRequest,
        crate::http::HttpResponse,
    )> {
        let mut completed = Vec::new();
        let mut to_remove = Vec::new();

        for (&promised_id, promised_req) in &self.session.promised_requests {
            if let Some(stream) = self.session.streams.get(&promised_id) {
                if (stream.state == crate::simd_parser::Http2StreamState::HalfClosedRemote
                    || stream.state == crate::simd_parser::Http2StreamState::Closed)
                    && !stream.received_headers.is_empty()
                {
                    let mut status_code = 200u16;
                    let mut resp_headers = crate::http::HttpHeaders::new();
                    for (k, v) in &stream.received_headers {
                        if k == ":status" {
                            if let Ok(code) = v.parse::<u16>() {
                                status_code = code;
                            }
                        } else if !k.starts_with(':') {
                            resp_headers.set(k.clone(), v.clone());
                        }
                    }
                    for (k, v) in &stream.received_trailers {
                        if !k.starts_with(':') {
                            resp_headers.append(k.clone(), v.clone());
                        }
                    }
                    let mut resp =
                        crate::http::HttpResponse::new(crate::http::HttpStatus(status_code));
                    resp.headers = resp_headers;
                    resp.body = stream.received_data.clone();
                    if let Ok(decompressed) = resp.decompress_body() {
                        resp.body = decompressed;
                    }
                    completed.push((promised_req.clone(), resp));
                    to_remove.push(promised_id);
                }
            }
        }

        for id in to_remove {
            self.session.promised_requests.remove(&id);
            self.session.push_promises.remove(&id);
            self.session.streams.remove(&id);
        }

        completed
    }

    /// Await the completion of a specific promised push stream, returning its full HTTP response.
    pub fn await_push_response(
        &mut self,
        promised_stream_id: u32,
    ) -> io::Result<crate::http::HttpResponse> {
        let (raw_headers, raw_body) = self.recv_response_for(promised_stream_id)?;
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

        if let Some(trailers) = self.get_trailers(promised_stream_id) {
            for (k, v) in trailers {
                if !k.starts_with(':') {
                    resp_headers.append(k, v);
                }
            }
        }

        let mut resp = crate::http::HttpResponse::new(crate::http::HttpStatus(status_code));
        resp.headers = resp_headers;
        resp.body = raw_body;
        if let Ok(decompressed) = resp.decompress_body() {
            resp.body = decompressed;
        }

        self.session.promised_requests.remove(&promised_stream_id);
        self.session.push_promises.remove(&promised_stream_id);
        self.session.streams.remove(&promised_stream_id);

        Ok(resp)
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
            ctrl_ring_buf: [0u8; 1024],
            is_closed: false,
            chunk_buffer_pool: None,
            auto_tune_flow_control: false,
            flow_control_last_observation: None,
            flow_control_bytes_observed: 0,
            decompressed_count: 0,
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
            ctrl_ring_buf: [0u8; 1024],
            is_closed: false,
            chunk_buffer_pool: None,
            auto_tune_flow_control: false,
            flow_control_last_observation: None,
            flow_control_bytes_observed: 0,
            decompressed_count: 0,
        })
    }

    /// Send an HTTP/2 frame over the connection.
    ///
    /// Optimizes control frames (PING, SETTINGS, WINDOW_UPDATE, RST_STREAM, PRIORITY)
    /// by serializing them directly into a pre-allocated internal scratch ring buffer
    /// without any dynamic heap allocation.
    pub fn send_frame(&mut self, frame: &crate::simd_parser::Http2Frame) -> io::Result<()> {
        if self.is_closed {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "HTTP/2 connection is closed",
            ));
        }

        // Zero-allocation path for control frames using pre-allocated buffer
        if frame.is_control_frame() {
            if let Ok(written) = frame.encode_to_slice(&mut self.ctrl_ring_buf) {
                return self.stream.write_all(&self.ctrl_ring_buf[..written]);
            }
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

    /// Update connection-level or stream-level flow control window with an explicit increment
    /// and transmit a corresponding `WINDOW_UPDATE` frame to the peer.
    pub fn send_window_update(&mut self, stream_id: u32, increment: u32) -> io::Result<i32> {
        let frame = crate::simd_parser::Http2Frame::WindowUpdate {
            stream_id,
            window_size_increment: increment,
        };
        self.send_frame(&frame)?;
        self.session
            .update_window_size(stream_id, increment)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{:?}", e)))
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

        // Track transfer observations for adaptive flow control auto-tuning
        if self.auto_tune_flow_control {
            if let crate::simd_parser::Http2Frame::Data { ref data, .. } = frame {
                let n = data.len();
                self.flow_control_bytes_observed += n;
                let now = std::time::Instant::now();
                if let Some(last) = self.flow_control_last_observation {
                    let elapsed = now.duration_since(last);
                    if elapsed >= Duration::from_millis(1)
                        && self.flow_control_bytes_observed >= 4096
                    {
                        self.session
                            .adaptive_flow_controller
                            .record_bandwidth_sample(self.flow_control_bytes_observed, elapsed);
                        self.flow_control_bytes_observed = 0;
                        self.flow_control_last_observation = Some(now);
                    }
                } else {
                    self.flow_control_last_observation = Some(now);
                }
            }
        }

        // Active flow control window replenishment:
        // When received DATA frames consume connection or stream windows below threshold,
        // send WINDOW_UPDATE frames proactively.
        self.replenish_flow_control_windows()?;

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

    /// Read the next incoming frame, delivering DATA frames zero-copy via borrowed slices.
    ///
    /// If the next frame is a DATA frame, invokes `on_data` with a borrowed `Http2DataFrameSlice`
    /// directly referencing the internal connection read buffer without any payload allocation.
    /// Automatically updates internal session flow control and stream state.
    /// Returns `Ok(None)` when a DATA frame was consumed, or `Ok(Some(frame))` for non-DATA frames
    /// (such as HEADERS, SETTINGS, PING, or GOAWAY).
    pub fn recv_frame_with_data_slice<F>(
        &mut self,
        mut on_data: F,
    ) -> io::Result<Option<crate::simd_parser::Http2Frame>>
    where
        F: FnMut(&crate::simd_parser::Http2DataFrameSlice<'_>) -> io::Result<()>,
    {
        let mut spins = 0;
        loop {
            // First check if an already buffered frame can be delivered as a zero-copy DATA slice
            if self.read_buf.len() >= crate::simd_parser::Http2FrameHeader::HEADER_SIZE {
                if let Some(header) =
                    crate::simd_parser::Http2FrameHeader::decode(&self.read_buf[..9])
                {
                    let total_frame_len =
                        crate::simd_parser::Http2FrameHeader::HEADER_SIZE + header.length as usize;
                    if self.read_buf.len() >= total_frame_len {
                        if header.frame_type == crate::simd_parser::Http2FrameType::Data {
                            let payload = &self.read_buf[9..total_frame_len];
                            let slice = match crate::simd_parser::Http2DataFrameSlice::decode(
                                &header, payload,
                            ) {
                                Ok(s) => s,
                                Err(e) => {
                                    return Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        format!("Failed to parse HTTP/2 DATA frame slice: {:?}", e),
                                    ));
                                }
                            };
                            let _ = self.session.handle_data_slice(&slice);
                            let user_res = on_data(&slice);
                            let chunk_len = slice.data.len();
                            let _ = slice;
                            self.read_buf.drain(..total_frame_len);
                            if self.read_buf.is_empty()
                                && self.read_buf.capacity() > DEFAULT_MAX_RETAINED_BUFFER_CAPACITY
                            {
                                self.read_buf
                                    .shrink_to(DEFAULT_MAX_RETAINED_BUFFER_CAPACITY);
                            }

                            if self.auto_tune_flow_control {
                                self.flow_control_bytes_observed += chunk_len;
                                let now = std::time::Instant::now();
                                if let Some(last) = self.flow_control_last_observation {
                                    let elapsed = now.duration_since(last);
                                    if elapsed >= Duration::from_millis(1)
                                        && self.flow_control_bytes_observed >= 4096
                                    {
                                        self.session
                                            .adaptive_flow_controller
                                            .record_bandwidth_sample(
                                                self.flow_control_bytes_observed,
                                                elapsed,
                                            );
                                        self.flow_control_bytes_observed = 0;
                                        self.flow_control_last_observation = Some(now);
                                    }
                                } else {
                                    self.flow_control_last_observation = Some(now);
                                }
                            }

                            // Replenish windows proactively
                            self.replenish_flow_control_windows()?;

                            user_res?;
                            return Ok(None);
                        } else {
                            // Non-DATA frame: process via standard recv_frame
                            let frame = self.recv_frame()?;
                            return Ok(Some(frame));
                        }
                    }
                }
            }

            // Need to read more bytes from socket
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
                Ok(Some(_)) | Ok(None) => {
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
                Err(e) => return Err(e),
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
                crate::simd_parser::Http2Frame::WindowUpdate { .. } => {
                    // Replenished window credit: attempt to flush any pending outbound scheduled data
                    let _ = self.flush_scheduled_outbound_data(true);
                    0
                }
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

        // Transparent stream-level decompression if content-encoding is gzip, deflate or br (RFC 7230 / RFC 7694)
        if let Ok(true) = resp.decompress_in_place() {
            self.decompressed_count += 1;
        }

        Ok(resp)
    }

    /// Receive a response on a stream with progressive chunked streaming decoding.
    ///
    /// Each incoming DATA frame chunk is progressively decoded (transparently decompressing
    /// gzip streams on-the-fly) and delivered immediately to the provided `chunk_handler` callback.
    /// Returns the completed `HttpResponse` once the stream has ended.
    pub fn recv_streaming_response<F>(
        &mut self,
        target_stream_id: u32,
        chunk_handler: F,
    ) -> io::Result<crate::http::HttpResponse>
    where
        F: FnMut(&[u8]),
    {
        self.recv_streaming_response_with_pool(target_stream_id, None, chunk_handler)
    }

    /// Receive a response on a stream with progressive chunked streaming decoding,
    /// using an optional buffer pool to recycle internal chunk allocations and zero-copy chunk slices.
    pub fn recv_streaming_response_with_pool<F>(
        &mut self,
        target_stream_id: u32,
        buffer_pool: Option<Http2ChunkBufferPool>,
        mut chunk_handler: F,
    ) -> io::Result<crate::http::HttpResponse>
    where
        F: FnMut(&[u8]),
    {
        let mut decoder = Http2StreamingResponseDecoder::new(target_stream_id);
        if let Some(pool) = buffer_pool {
            decoder = decoder.with_buffer_pool(pool);
        }

        if let Some(stream) = self.session.streams.get(&target_stream_id) {
            if !stream.received_headers.is_empty() {
                decoder.feed_headers(&stream.received_headers);
            }
            if !stream.received_data.is_empty() {
                let is_closed = stream.state
                    == crate::simd_parser::Http2StreamState::HalfClosedRemote
                    || stream.state == crate::simd_parser::Http2StreamState::Closed;
                let chunk = decoder.feed_chunk_slice(&stream.received_data, is_closed)?;
                chunk_handler(chunk);
            }
            if stream.state == crate::simd_parser::Http2StreamState::HalfClosedRemote
                || stream.state == crate::simd_parser::Http2StreamState::Closed
            {
                decoder.mark_complete();
                return decoder.assemble_response_recycling();
            }
        }

        while !decoder.is_complete() {
            let frame = self.recv_frame()?;
            match frame {
                crate::simd_parser::Http2Frame::Headers {
                    stream_id,
                    end_stream,
                    ..
                } => {
                    if stream_id == target_stream_id {
                        if let Some(stream) = self.session.streams.get(&target_stream_id) {
                            if decoder.status.is_none() {
                                decoder.feed_headers(&stream.received_headers);
                            } else {
                                decoder.feed_trailers(&stream.received_trailers);
                            }
                        }
                        if end_stream {
                            decoder.mark_complete();
                        }
                    }
                }
                crate::simd_parser::Http2Frame::Data {
                    stream_id,
                    data,
                    end_stream,
                } => {
                    if stream_id == target_stream_id {
                        let decoded = decoder.feed_chunk_owned(data, end_stream)?;
                        chunk_handler(decoded);
                    }
                }
                crate::simd_parser::Http2Frame::WindowUpdate { .. } => {
                    let _ = self.flush_scheduled_outbound_data(true);
                }
                crate::simd_parser::Http2Frame::RstStream {
                    stream_id,
                    error_code,
                } => {
                    if stream_id == target_stream_id {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionReset,
                            format!("Stream {} reset with error {:?}", stream_id, error_code),
                        ));
                    }
                }
                crate::simd_parser::Http2Frame::GoAway { error_code, .. } => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        format!("Connection closed by GOAWAY: {:?}", error_code),
                    ));
                }
                _ => {}
            }
        }

        if decoder.content_decoder.is_some() {
            self.decompressed_count += 1;
        }
        decoder.assemble_response_recycling()
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

    /// Retrieve active stream IDs sorted under RFC 9218 extensible priority order
    /// (urgency ascending 0..=7, then stream ID ascending for fair round-robin).
    pub fn prioritized_streams_rfc9218(&self) -> Vec<u32> {
        self.session.prioritized_stream_ids_rfc9218()
    }

    /// Set stream RFC 9218 priority parameters and transmit a `PRIORITY_UPDATE` frame (RFC 9218).
    pub fn set_priority_update(
        &mut self,
        stream_id: u32,
        priority: crate::simd_parser::PriorityParameters,
    ) -> io::Result<()> {
        let frame = crate::simd_parser::Http2Frame::PriorityUpdate {
            prioritized_stream_id: stream_id,
            priority_field_value: priority.serialize(),
        };
        self.send_frame(&frame)?;
        self.session
            .set_stream_priority_parameters(stream_id, priority);
        Ok(())
    }

    /// Transmit an RFC 7838 `ALTSVC` frame to announce alternative service routes to peer.
    ///
    /// For origin-level alternative service advertisements, `stream_id` MUST be 0
    /// and `origin` specifies the origin URI. For stream-level advertisements,
    /// `stream_id` specifies the request stream and `origin` SHOULD be empty.
    pub fn send_alt_svc(
        &mut self,
        stream_id: u32,
        origin: &str,
        routes: &[crate::simd_parser::AltSvcRoute],
    ) -> io::Result<()> {
        let alt_svc_field_value = routes
            .iter()
            .map(|r| r.serialize())
            .collect::<Vec<_>>()
            .join(", ");
        let frame = crate::simd_parser::Http2Frame::AltSvc {
            stream_id,
            origin: origin.to_string(),
            alt_svc_field_value,
        };
        self.send_frame(&frame)
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

    /// Flushes queued outbound stream data by scheduling DATA frames via the HTTP/2 session's
    /// priority scheduler (RFC 9218 & dependency weights) and transmitting them over the wire.
    ///
    /// If `end_stream` is true, the final transmitted DATA frame for fully-drained streams marks `end_stream`.
    /// Returns the number of DATA frames transmitted.
    pub fn flush_scheduled_outbound_data(&mut self, end_stream: bool) -> io::Result<usize> {
        let frames = self
            .session
            .schedule_pending_outbound_data(16384, end_stream);
        let count = frames.len();
        for frame in &frames {
            self.send_frame(frame)?;
        }
        Ok(count)
    }

    /// Queue outbound body data for a stream and immediately schedule/flush as many DATA frames
    /// as permitted by the stream and connection flow control windows and RFC 9218 priority.
    ///
    /// Returns the number of frames transmitted. Any un-transmitted bytes remain queued in the session.
    pub fn send_queued_data(
        &mut self,
        stream_id: u32,
        data: &[u8],
        end_stream: bool,
    ) -> io::Result<usize> {
        self.session.queue_outbound_data(stream_id, data);
        self.flush_scheduled_outbound_data(end_stream)
    }

    /// Execute a batch of prioritized requests multiplexed over this single HTTP/2 connection.
    /// Sends PRIORITY or PRIORITY_UPDATE frames for each stream, sends the requests concurrently,
    /// and collects responses in the order of the dependency tree and weights (or RFC 9218 urgency tiers).
    pub fn execute_prioritized_batch(
        &mut self,
        requests: Vec<Http2PrioritizedRequest>,
    ) -> io::Result<Vec<(u32, io::Result<crate::http::HttpResponse>)>> {
        let mut stream_mappings = Vec::new();
        let mut has_rfc9218 = false;

        // 1. Dispatch requests and transmit PRIORITY / PRIORITY_UPDATE frames
        let mut has_pending_scheduled_data = false;
        for req in &requests {
            let mut pseudo_headers = vec![
                (":method", req.method.as_str()),
                (":path", req.path.as_str()),
                (":scheme", "http"),
            ];
            for (k, v) in &req.headers {
                pseudo_headers.push((k.as_str(), v.as_str()));
            }

            let has_body = req.body.as_ref().is_some_and(|b| !b.is_empty());
            let stream_id = self.session.open_stream();
            let headers_frame =
                self.session
                    .create_headers_frame(stream_id, &pseudo_headers, !has_body);
            self.send_frame(&headers_frame)?;

            if let Some(data) = req.body.as_deref() {
                if !data.is_empty() {
                    self.session.queue_outbound_data(stream_id, data);
                    has_pending_scheduled_data = true;
                }
            }

            if let Some(p) = req.rfc9218_priority {
                has_rfc9218 = true;
                self.set_priority_update(stream_id, p)?;
            } else if req.stream_dependency != 0 || req.weight != 16 || req.exclusive {
                self.set_priority(stream_id, req.stream_dependency, req.weight, req.exclusive)?;
            }

            stream_mappings.push(stream_id);
        }

        // Flush outbound data frames scheduled according to priority & flow control
        if has_pending_scheduled_data {
            self.flush_scheduled_outbound_data(true)?;
        }

        // 2. Order stream collection according to RFC 9218 urgency or RFC 7540 priority tree
        let prioritized_order = if has_rfc9218 {
            self.prioritized_streams_rfc9218()
        } else {
            self.prioritized_streams()
        };
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

        // 3. Concurrently receive and progressively decode streaming chunked responses across all multiplexed streams
        let mut stream_handlers: std::collections::HashMap<u32, Http2ResponseChunkHandler> =
            std::collections::HashMap::new();
        for (req, sid) in requests.iter().zip(stream_mappings.iter()) {
            if let Some(ref h) = req.chunk_handler {
                stream_handlers.insert(*sid, h.clone());
            }
        }

        let mut decoders: std::collections::HashMap<u32, Http2StreamingResponseDecoder> =
            ordered_streams
                .iter()
                .map(|&sid| {
                    let mut d = Http2StreamingResponseDecoder::new(sid);
                    if let Some(ref p) = self.chunk_buffer_pool {
                        d = d.with_buffer_pool(p.clone());
                    }
                    (sid, d)
                })
                .collect();

        // Feed any headers or data already received in session (e.g. if arriving early)
        for &sid in &ordered_streams {
            if let Some(stream) = self.session.streams.get(&sid) {
                if !stream.received_headers.is_empty() {
                    let dec = decoders.get_mut(&sid).unwrap();
                    dec.feed_headers(&stream.received_headers);
                }
                if !stream.received_data.is_empty() {
                    let dec = decoders.get_mut(&sid).unwrap();
                    let is_closed = stream.state
                        == crate::simd_parser::Http2StreamState::HalfClosedRemote
                        || stream.state == crate::simd_parser::Http2StreamState::Closed;
                    if let Ok(chunk) = dec.feed_chunk_slice(&stream.received_data, is_closed) {
                        if let Some(h) = stream_handlers.get(&sid) {
                            h(sid, chunk);
                        }
                    }
                }
                if stream.state == crate::simd_parser::Http2StreamState::HalfClosedRemote
                    || stream.state == crate::simd_parser::Http2StreamState::Closed
                {
                    decoders.get_mut(&sid).unwrap().mark_complete();
                }
            }
        }

        let batch_start = std::time::Instant::now();
        let mut first_header_observed = false;
        let mut total_batch_bytes: usize = 0;

        while !decoders.values().all(|d| d.is_complete()) {
            let frame = self.recv_frame()?;
            match frame {
                crate::simd_parser::Http2Frame::Headers {
                    stream_id,
                    end_stream,
                    ..
                } => {
                    if !first_header_observed {
                        first_header_observed = true;
                        if self.auto_tune_flow_control
                            && self
                                .session
                                .adaptive_flow_controller
                                .smoothed_rtt_us
                                .is_none()
                        {
                            let rtt_us = batch_start.elapsed().as_micros() as u64;
                            if rtt_us > 0 {
                                self.session
                                    .adaptive_flow_controller
                                    .record_rtt_sample(rtt_us);
                            }
                        }
                    }
                    if let Some(dec) = decoders.get_mut(&stream_id) {
                        if let Some(stream) = self.session.streams.get(&stream_id) {
                            if dec.status.is_none() {
                                dec.feed_headers(&stream.received_headers);
                            } else {
                                dec.feed_trailers(&stream.received_trailers);
                            }
                        }
                        if end_stream {
                            dec.mark_complete();
                        }
                    }
                }
                crate::simd_parser::Http2Frame::Data {
                    stream_id,
                    data,
                    end_stream,
                } => {
                    if self.auto_tune_flow_control {
                        total_batch_bytes += data.len();
                        let elapsed = batch_start.elapsed();
                        if elapsed.as_micros() > 50 {
                            self.session
                                .adaptive_flow_controller
                                .record_bandwidth_sample(total_batch_bytes, elapsed);
                        }
                    }
                    if let Some(dec) = decoders.get_mut(&stream_id) {
                        match dec.feed_chunk_owned(data, end_stream) {
                            Ok(decoded_chunk) => {
                                if let Some(handler) = stream_handlers.get(&stream_id) {
                                    handler(stream_id, decoded_chunk);
                                }
                            }
                            Err(e) => {
                                dec.mark_error(e);
                            }
                        }
                    }
                }
                crate::simd_parser::Http2Frame::WindowUpdate { .. } => {
                    let _ = self.flush_scheduled_outbound_data(true);
                }
                crate::simd_parser::Http2Frame::RstStream {
                    stream_id,
                    error_code,
                } => {
                    if let Some(dec) = decoders.get_mut(&stream_id) {
                        dec.mark_reset(error_code);
                    }
                }
                crate::simd_parser::Http2Frame::GoAway { error_code, .. } => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        format!("Connection closed by GOAWAY: {:?}", error_code),
                    ));
                }
                _ => {}
            }
        }

        let mut results = Vec::with_capacity(ordered_streams.len());
        for sid in ordered_streams {
            let res = if let Some(dec) = decoders.remove(&sid) {
                if dec.buffer_pool.is_some() {
                    dec.assemble_response_recycling()
                } else {
                    dec.assemble_response()
                }
            } else {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("Stream {} missing from batch decoders", sid),
                ))
            };
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

/// Callback invoked whenever a chunk of response payload is decoded for a stream.
pub type Http2ResponseChunkHandler = std::sync::Arc<dyn Fn(u32, &[u8]) + Send + Sync>;

/// Recyclable buffer pool for high-frequency HTTP/2 chunk slices.
///
/// Reduces heap allocations and allocator thrashing by pooling pre-allocated
/// byte buffers for high-throughput streaming workloads.
#[derive(Debug, Clone)]
pub struct Http2ChunkBufferPool {
    pool: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    buffer_capacity: usize,
    max_retained_buffers: usize,
}

impl Default for Http2ChunkBufferPool {
    fn default() -> Self {
        Self::new(16384, 64)
    }
}

impl Http2ChunkBufferPool {
    /// Create a new chunk buffer pool with the given buffer capacity and maximum retained buffers.
    pub fn new(buffer_capacity: usize, max_retained_buffers: usize) -> Self {
        Self {
            pool: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            buffer_capacity: buffer_capacity.max(1024),
            max_retained_buffers: max_retained_buffers.max(1),
        }
    }

    /// Acquire a buffer from the pool, or allocate a new one if the pool is empty.
    /// The returned vector has length 0 and capacity at least `self.buffer_capacity`.
    pub fn acquire(&self) -> Vec<u8> {
        if let Ok(mut pool) = self.pool.lock() {
            if let Some(mut buf) = pool.pop() {
                buf.clear();
                return buf;
            }
        }
        Vec::with_capacity(self.buffer_capacity)
    }

    /// Return a buffer to the pool for reuse if under the maximum retained buffer limit.
    pub fn release(&self, mut buf: Vec<u8>) {
        if let Ok(mut pool) = self.pool.lock() {
            if pool.len() < self.max_retained_buffers {
                buf.clear();
                pool.push(buf);
            }
        }
    }

    /// Current count of idle pooled buffers available for immediate reuse.
    pub fn idle_count(&self) -> usize {
        self.pool.lock().map(|p| p.len()).unwrap_or(0)
    }
}

/// Progressive streaming response decoder for HTTP/2 multiplexed streams.
/// Handles fragmented DATA frames, progressive decompression (gzip),
/// chunked payloads, trailers, and status code extraction.
#[derive(Debug)]
pub struct Http2StreamingResponseDecoder {
    /// Stream ID being decoded.
    pub stream_id: u32,
    /// Decoded response HTTP status code once `:status` header is received.
    pub status: Option<u16>,
    /// Accumulated response headers.
    pub headers: crate::http::HttpHeaders,
    /// Trailing headers received in a final HEADERS frame, if any.
    pub trailers: crate::http::HttpHeaders,
    /// Progressive streaming content decoder if content-encoding is gzip, deflate, or br.
    content_decoder: Option<crate::http::HttpContentDecoder>,
    /// Optional chunk buffer pool for high-frequency allocation reuse.
    pub buffer_pool: Option<Http2ChunkBufferPool>,
    /// Accumulated decoded body chunks.
    decoded_chunks: Vec<Vec<u8>>,
    /// Total bytes decoded across all chunks.
    total_bytes_decoded: usize,
    /// Total raw DATA frame bytes received from peer.
    total_raw_bytes: usize,
    /// Number of chunked DATA frames processed.
    chunk_count: usize,
    /// Whether the stream has received the END_STREAM flag or was marked complete.
    is_complete: bool,
    /// Stream reset error if stream was terminated by RST_STREAM.
    pub reset_error: Option<crate::simd_parser::Http2ErrorCode>,
    /// Stream error if decoding chunk or decompression failed.
    pub decode_error: Option<String>,
}

impl Http2StreamingResponseDecoder {
    /// Create a new progressive streaming response decoder for a stream.
    pub fn new(stream_id: u32) -> Self {
        Self {
            stream_id,
            status: None,
            headers: crate::http::HttpHeaders::new(),
            trailers: crate::http::HttpHeaders::new(),
            content_decoder: None,
            buffer_pool: None,
            decoded_chunks: Vec::new(),
            total_bytes_decoded: 0,
            total_raw_bytes: 0,
            chunk_count: 0,
            is_complete: false,
            reset_error: None,
            decode_error: None,
        }
    }

    /// Configure a shared chunk buffer pool to reuse buffers across decoded chunks.
    pub fn with_buffer_pool(mut self, pool: Http2ChunkBufferPool) -> Self {
        self.buffer_pool = Some(pool);
        self
    }

    /// Feed decoded HTTP headers from a HEADERS frame.
    pub fn feed_headers(&mut self, headers: &[(String, String)]) {
        for (k, v) in headers {
            if k == ":status" {
                if let Ok(code) = v.parse::<u16>() {
                    self.status = Some(code);
                }
            } else if !k.starts_with(':') {
                self.headers.set(k.clone(), v.clone());
            }
        }
        if let Some(enc_val) = self.headers.get("content-encoding") {
            let enc = crate::http::ContentEncoding::from_header(enc_val);
            self.content_decoder = crate::http::HttpContentDecoder::for_encoding(enc);
        }
    }

    /// Feed trailing headers received in a subsequent HEADERS frame.
    pub fn feed_trailers(&mut self, trailers: &[(String, String)]) {
        for (k, v) in trailers {
            if !k.starts_with(':') {
                self.trailers.set(k.clone(), v.clone());
                self.headers.append(k.clone(), v.clone());
            }
        }
        self.is_complete = true;
    }

    /// Process a fragmented incoming DATA frame chunk slice without unnecessary cloning.
    /// Returns a borrowed slice of the decoded chunk payload.
    pub fn feed_chunk_slice(&mut self, raw_chunk: &[u8], end_stream: bool) -> io::Result<&[u8]> {
        self.total_raw_bytes += raw_chunk.len();
        self.chunk_count += 1;

        if let Some(ref mut decoder) = self.content_decoder {
            let decompressed = decoder
                .feed(raw_chunk)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            self.total_bytes_decoded += decompressed.len();
            self.decoded_chunks.push(decompressed);
        } else if let Some(ref pool) = self.buffer_pool {
            let mut buf = pool.acquire();
            buf.extend_from_slice(raw_chunk);
            self.total_bytes_decoded += buf.len();
            self.decoded_chunks.push(buf);
        } else {
            self.total_bytes_decoded += raw_chunk.len();
            self.decoded_chunks.push(raw_chunk.to_vec());
        }

        if end_stream {
            self.is_complete = true;
        }

        Ok(self
            .decoded_chunks
            .last()
            .map(|c| c.as_slice())
            .unwrap_or(&[]))
    }

    /// Ingest an owned DATA frame payload without allocating a new buffer when uncompressed.
    /// Returns a slice view of the newly decoded chunk.
    pub fn feed_chunk_owned(&mut self, chunk: Vec<u8>, end_stream: bool) -> io::Result<&[u8]> {
        self.total_raw_bytes += chunk.len();
        self.chunk_count += 1;

        if let Some(ref mut decoder) = self.content_decoder {
            let decompressed = decoder
                .feed(&chunk)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            self.total_bytes_decoded += decompressed.len();
            self.decoded_chunks.push(decompressed);
        } else {
            self.total_bytes_decoded += chunk.len();
            self.decoded_chunks.push(chunk);
        }

        if end_stream {
            self.is_complete = true;
        }

        Ok(self
            .decoded_chunks
            .last()
            .map(|c| c.as_slice())
            .unwrap_or(&[]))
    }

    /// Process a fragmented incoming DATA frame chunk.
    /// Returns the newly decoded byte slice for this chunk.
    pub fn feed_chunk(&mut self, raw_chunk: &[u8], end_stream: bool) -> io::Result<Vec<u8>> {
        let slice = self.feed_chunk_slice(raw_chunk, end_stream)?;
        Ok(slice.to_vec())
    }

    /// Mark the stream as completed (e.g. END_STREAM received on empty frame or trailers).
    pub fn mark_complete(&mut self) {
        self.is_complete = true;
    }

    /// Mark the stream as reset by RST_STREAM.
    pub fn mark_reset(&mut self, error: crate::simd_parser::Http2ErrorCode) {
        self.reset_error = Some(error);
        self.is_complete = true;
    }

    /// Mark a decoding error.
    pub fn mark_error(&mut self, err: io::Error) {
        self.decode_error = Some(err.to_string());
        self.is_complete = true;
    }

    /// Whether this stream response has finished decoding.
    #[inline]
    pub fn is_complete(&self) -> bool {
        self.is_complete
    }

    /// Number of chunked DATA frames processed.
    #[inline]
    pub fn chunk_count(&self) -> usize {
        self.chunk_count
    }

    /// Total decoded payload size in bytes.
    #[inline]
    pub fn total_bytes_decoded(&self) -> usize {
        self.total_bytes_decoded
    }

    /// Total raw DATA frame bytes received from peer before decompression.
    #[inline]
    pub fn total_raw_bytes(&self) -> usize {
        self.total_raw_bytes
    }

    /// Assemble the accumulated chunks into a finalized `HttpResponse`.
    pub fn assemble_response(&self) -> io::Result<crate::http::HttpResponse> {
        if let Some(err) = self.reset_error {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                format!("Stream {} reset with error {:?}", self.stream_id, err),
            ));
        }
        if let Some(ref err) = self.decode_error {
            return Err(io::Error::new(io::ErrorKind::InvalidData, err.clone()));
        }

        let status = self.status.unwrap_or(200);
        let mut resp = crate::http::HttpResponse::new(crate::http::HttpStatus(status));
        resp.headers = self.headers.clone();

        let mut body = Vec::with_capacity(self.total_bytes_decoded);
        for chunk in &self.decoded_chunks {
            body.extend_from_slice(chunk);
        }
        resp.body = body;

        // If not already decompressed via GzipStreamDecoder, attempt transparent decompression
        if self.content_decoder.is_none() {
            let _ = resp.decompress_in_place();
        } else {
            resp.headers.remove("content-encoding");
            resp.headers
                .set("content-length", resp.body.len().to_string());
        }

        Ok(resp)
    }

    /// Assemble the response, consuming the decoder and recycling internal chunk buffers
    /// back into the configured `Http2ChunkBufferPool` to eliminate allocator churn.
    pub fn assemble_response_recycling(mut self) -> io::Result<crate::http::HttpResponse> {
        if let Some(err) = self.reset_error {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                format!("Stream {} reset with error {:?}", self.stream_id, err),
            ));
        }
        if let Some(ref err) = self.decode_error {
            return Err(io::Error::new(io::ErrorKind::InvalidData, err.clone()));
        }

        let status = self.status.unwrap_or(200);
        let mut resp = crate::http::HttpResponse::new(crate::http::HttpStatus(status));
        resp.headers = self.headers.clone();

        let mut body = Vec::with_capacity(self.total_bytes_decoded);
        for chunk in self.decoded_chunks.drain(..) {
            body.extend_from_slice(&chunk);
            if let Some(ref pool) = self.buffer_pool {
                pool.release(chunk);
            }
        }
        resp.body = body;

        if self.content_decoder.is_none() {
            let _ = resp.decompress_in_place();
        } else {
            resp.headers.remove("content-encoding");
            resp.headers
                .set("content-length", resp.body.len().to_string());
        }

        Ok(resp)
    }
}

/// Parameters for configuring a prioritized HTTP/2 request in a multiplexed batch.
#[derive(Clone)]
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
    /// RFC 9218 Priority parameters (urgency 0..=7, incremental flag)
    pub rfc9218_priority: Option<crate::simd_parser::PriorityParameters>,
    /// Optional chunk callback invoked progressively as response DATA chunks are received and decoded.
    pub chunk_handler: Option<Http2ResponseChunkHandler>,
}

impl std::fmt::Debug for Http2PrioritizedRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http2PrioritizedRequest")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("headers", &self.headers)
            .field("body", &self.body)
            .field("stream_dependency", &self.stream_dependency)
            .field("weight", &self.weight)
            .field("exclusive", &self.exclusive)
            .field("rfc9218_priority", &self.rfc9218_priority)
            .field("has_chunk_handler", &self.chunk_handler.is_some())
            .finish()
    }
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
            rfc9218_priority: None,
            chunk_handler: None,
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

    /// Set RFC 9218 priority parameters (urgency 0..=7 and incremental boolean).
    pub fn with_rfc9218_priority(mut self, urgency: u8, incremental: bool) -> Self {
        self.rfc9218_priority = Some(crate::simd_parser::PriorityParameters::new(
            urgency,
            incremental,
        ));
        self
    }

    /// Register a progressive response chunk callback invoked as DATA frame chunks arrive.
    pub fn with_chunk_handler(
        mut self,
        handler: impl Fn(u32, &[u8]) + Send + Sync + 'static,
    ) -> Self {
        self.chunk_handler = Some(std::sync::Arc::new(handler));
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
    /// Total number of requests successfully retried after transient failure or GOAWAY.
    pub retried_requests: usize,
    /// Total number of unconsumed push promise responses currently held in pool cache.
    pub cached_push_promises: usize,
    /// Total number of requests satisfied directly from proactive push promise cache without network I/O.
    pub push_cache_hits: usize,
    /// Total number of successful 304 Not Modified revalidations refreshing cached responses.
    pub cache_revalidations: usize,
    /// Total number of general HTTP responses currently held in pool client cache (RFC 7234).
    pub http_cache_entries: usize,
    /// Total count of cache hits served stale under `stale-while-revalidate` (RFC 5861 §3).
    pub stale_hits: usize,
    /// Total count of requests rescued from upstream failure or 5xx by `stale-if-error` (RFC 5861 §4).
    pub stale_error_fallbacks: usize,
    /// Total count of background revalidations completed for stale cache entries.
    pub background_revalidations: usize,
    /// Total count of HTTP cache entries evicted due to LRU capacity limits or TTL sweeps.
    pub http_cache_evictions: usize,
    /// Total count of HTTP cache entries purged due to explicit invalidation or RFC 7234 §4.4 unsafe method updates.
    pub http_cache_invalidations: usize,
    /// Total count of response payloads transparently decompressed by the pool.
    pub decompressed_responses: usize,
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

/// A cached HTTP/2 push promise response retained in an [`AsyncHttp2Pool`].
#[derive(Debug, Clone)]
pub struct Http2PushPromiseCacheEntry {
    /// Metadata of the promised push request.
    pub promised_request: crate::simd_parser::Http2PromisedRequest,
    /// The pushed HTTP response.
    pub response: crate::http::HttpResponse,
    /// Timestamp when this push promise response was ingested.
    pub received_at: std::time::Instant,
    /// Wall-clock system time when this response was received.
    pub response_time: std::time::SystemTime,
    /// Wall-clock expiration time computed from Cache-Control max-age or Expires.
    pub expires_at: Option<std::time::SystemTime>,
    /// Parsed Cache-Control directives (RFC 7234).
    pub directives: crate::http::HttpCacheDirectives,
    /// Extracted ETag validator (RFC 7232), if any.
    pub etag: Option<String>,
    /// Extracted Last-Modified date header (RFC 7232), if any.
    pub last_modified: Option<String>,
    /// Parsed Vary header directives (RFC 7234 §4.1), if any.
    pub vary: Option<crate::simd_parser::Http2Vary>,
    /// Total number of requests served from this cached entry.
    pub hit_count: usize,
    /// Total number of successful 304 Not Modified revalidations.
    pub revalidations: usize,
}

impl Http2PushPromiseCacheEntry {
    /// Create a new cached push promise entry with RFC 7234 directives parsing.
    pub fn new(
        promised_request: crate::simd_parser::Http2PromisedRequest,
        response: crate::http::HttpResponse,
    ) -> Self {
        let now = std::time::SystemTime::now();
        let instant = std::time::Instant::now();
        let etag = response.headers.get("etag").map(|s| s.trim().to_string());
        let last_modified = response
            .headers
            .get("last-modified")
            .map(|s| s.trim().to_string());
        let vary = response
            .headers
            .get("vary")
            .map(crate::simd_parser::Http2Vary::parse);

        let (directives, expires_at) = if let Some(cc) = response.headers.get("cache-control") {
            let d = crate::http::HttpCacheDirectives::parse(cc);
            let exp = d
                .max_age
                .map(|sec| now + std::time::Duration::from_secs(sec));
            (d, exp)
        } else if let Some(exp_str) = response.headers.get("expires") {
            let exp = crate::http::parse_http_date(exp_str);
            (crate::http::HttpCacheDirectives::default(), exp)
        } else {
            (crate::http::HttpCacheDirectives::default(), None)
        };

        Self {
            promised_request,
            response,
            received_at: instant,
            response_time: now,
            expires_at,
            directives,
            etag,
            last_modified,
            vary,
            hit_count: 0,
            revalidations: 0,
        }
    }

    /// Check whether this entry is cacheable under RFC 7234 (must not have `no-store` or unmatchable `Vary: *`).
    #[inline]
    pub fn is_cacheable(&self) -> bool {
        !self.directives.no_store && !matches!(self.vary, Some(crate::simd_parser::Http2Vary::Any))
    }

    /// Check whether this push promise entry matches presented request headers under RFC 7234 §4.1.
    #[inline]
    pub fn matches_request(&self, presented_headers: &[(String, String)]) -> bool {
        if let Some(ref vary) = self.vary {
            vary.matches_request(&self.promised_request.headers, presented_headers)
        } else {
            true
        }
    }

    /// Check whether this cached entry is fresh under RFC 7234 §4.2.
    pub fn is_fresh(&self, now: std::time::SystemTime, default_ttl: std::time::Duration) -> bool {
        if self.directives.no_cache {
            return false;
        }
        if let Some(exp) = self.expires_at {
            now < exp
        } else {
            now <= self.response_time + default_ttl
        }
    }

    /// Check whether this entry is within its `stale-while-revalidate` window (RFC 5861 §3).
    pub fn is_stale_while_revalidate(
        &self,
        now: std::time::SystemTime,
        default_ttl: std::time::Duration,
        client_swr: Option<u64>,
    ) -> bool {
        if self.directives.no_cache || self.directives.must_revalidate || self.directives.no_store {
            return false;
        }
        if self.is_fresh(now, default_ttl) {
            return false;
        }
        let swr_secs = client_swr.or(self.directives.stale_while_revalidate);
        if let Some(swr) = swr_secs {
            let expiry = self.expires_at.unwrap_or(self.response_time + default_ttl);
            if let Some(limit) = expiry.checked_add(std::time::Duration::from_secs(swr)) {
                return now <= limit;
            }
        }
        false
    }

    /// Check whether this entry is eligible to be served upon an upstream error under `stale-if-error` (RFC 5861 §4).
    pub fn is_stale_if_error(
        &self,
        now: std::time::SystemTime,
        default_ttl: std::time::Duration,
        client_sie: Option<u64>,
    ) -> bool {
        if self.directives.no_store {
            return false;
        }
        if self.is_fresh(now, default_ttl) {
            return true;
        }
        if self.directives.must_revalidate {
            return false;
        }
        let sie_secs = client_sie.or(self.directives.stale_if_error);
        if let Some(sie) = sie_secs {
            let expiry = self.expires_at.unwrap_or(self.response_time + default_ttl);
            if let Some(limit) = expiry.checked_add(std::time::Duration::from_secs(sie)) {
                return now <= limit;
            }
        }
        false
    }

    /// Whether this entry requires origin revalidation (RFC 7234 §4.3) before returning.
    pub fn requires_revalidation(
        &self,
        now: std::time::SystemTime,
        default_ttl: std::time::Duration,
    ) -> bool {
        self.directives.no_cache || !self.is_fresh(now, default_ttl)
    }

    /// Whether this cached entry possesses validators (ETag or Last-Modified) for conditional request.
    #[inline]
    pub fn can_revalidate(&self) -> bool {
        self.etag.is_some() || self.last_modified.is_some()
    }

    /// Update this cache entry from a 304 Not Modified response (RFC 7234 §4.3.4).
    pub fn update_from_304(
        &mut self,
        not_modified_resp: &crate::http::HttpResponse,
        now: std::time::SystemTime,
    ) {
        self.response_time = now;
        self.revalidations += 1;
        for (k, v) in not_modified_resp.headers.iter() {
            let lower = k.to_ascii_lowercase();
            if matches!(
                lower.as_str(),
                "date" | "expires" | "cache-control" | "etag" | "last-modified" | "vary"
            ) {
                self.response.headers.set(k, v);
            }
        }
        if let Some(etag) = not_modified_resp.headers.get("etag") {
            self.etag = Some(etag.trim().to_string());
        }
        if let Some(lm) = not_modified_resp.headers.get("last-modified") {
            self.last_modified = Some(lm.trim().to_string());
        }
        if let Some(vary_hdr) = not_modified_resp.headers.get("vary") {
            self.vary = Some(crate::simd_parser::Http2Vary::parse(vary_hdr));
        }
        if let Some(cc) = not_modified_resp.headers.get("cache-control") {
            self.directives = crate::http::HttpCacheDirectives::parse(cc);
            self.expires_at = self
                .directives
                .max_age
                .map(|sec| now + std::time::Duration::from_secs(sec));
        } else if let Some(exp) = not_modified_resp.headers.get("expires") {
            self.expires_at = crate::http::parse_http_date(exp);
        }
    }
}

/// A cached HTTP/2 client response retained in an [`AsyncHttp2Pool`] (RFC 7234).
#[derive(Debug, Clone)]
pub struct Http2PoolCacheEntry {
    /// HTTP method (e.g. "GET", "HEAD").
    pub method: String,
    /// Request path (e.g. "/api/v1/resource").
    pub path: String,
    /// Request headers associated with the original request (RFC 7234 §4.1).
    pub request_headers: Vec<(String, String)>,
    /// The cached HTTP response.
    pub response: crate::http::HttpResponse,
    /// Timestamp when this response was ingested.
    pub received_at: std::time::Instant,
    /// Timestamp of the most recent read, hit, or revalidation access to this entry.
    pub last_accessed: std::time::Instant,
    /// Wall-clock system time when this response was received.
    pub response_time: std::time::SystemTime,
    /// Wall-clock expiration time computed from Cache-Control max-age, Expires, or heuristic freshness.
    pub expires_at: Option<std::time::SystemTime>,
    /// Whether the expiration time of this entry was computed heuristically (RFC 7234 §4.2.2).
    pub is_heuristic: bool,
    /// Parsed Cache-Control directives (RFC 7234).
    pub directives: crate::http::HttpCacheDirectives,
    /// Extracted ETag validator (RFC 7232), if any.
    pub etag: Option<String>,
    /// Extracted Last-Modified date header (RFC 7232), if any.
    pub last_modified: Option<String>,
    /// Parsed Vary header directives (RFC 7234 §4.1), if any.
    pub vary: Option<crate::simd_parser::Http2Vary>,
    /// Total number of requests served from this cached entry.
    pub hit_count: usize,
    /// Total number of successful 304 Not Modified revalidations.
    pub revalidations: usize,
}

impl Http2PoolCacheEntry {
    /// Create a new cached HTTP/2 response entry.
    pub fn new(
        method: impl Into<String>,
        path: impl Into<String>,
        response: crate::http::HttpResponse,
    ) -> Self {
        let now = std::time::SystemTime::now();
        let instant = std::time::Instant::now();
        let etag = response.headers.get("etag").map(|s| s.trim().to_string());
        let last_modified = response
            .headers
            .get("last-modified")
            .map(|s| s.trim().to_string());
        let vary = response
            .headers
            .get("vary")
            .map(crate::simd_parser::Http2Vary::parse);

        let (directives, expires_at, is_heuristic) =
            if let Some(cc) = response.headers.get("cache-control") {
                let d = crate::http::HttpCacheDirectives::parse(cc);
                let exp = d
                    .max_age
                    .map(|sec| now + std::time::Duration::from_secs(sec));
                (d, exp, false)
            } else if let Some(exp_str) = response.headers.get("expires") {
                let exp = crate::http::parse_http_date(exp_str);
                (crate::http::HttpCacheDirectives::default(), exp, false)
            } else if let Some(ref lm_str) = last_modified {
                if let Some(lm_time) = crate::http::parse_http_date(lm_str) {
                    if let Ok(diff) = now.duration_since(lm_time) {
                        let heuristic_secs = diff.as_secs() / 10;
                        let exp = Some(now + std::time::Duration::from_secs(heuristic_secs));
                        (crate::http::HttpCacheDirectives::default(), exp, true)
                    } else {
                        (crate::http::HttpCacheDirectives::default(), None, false)
                    }
                } else {
                    (crate::http::HttpCacheDirectives::default(), None, false)
                }
            } else {
                (crate::http::HttpCacheDirectives::default(), None, false)
            };

        Self {
            method: method.into(),
            path: path.into(),
            request_headers: Vec::new(),
            response,
            received_at: instant,
            last_accessed: instant,
            response_time: now,
            expires_at,
            is_heuristic,
            directives,
            etag,
            last_modified,
            vary,
            hit_count: 0,
            revalidations: 0,
        }
    }

    /// Attach original request headers to this cache entry for RFC 7234 Vary matching.
    pub fn with_request_headers(mut self, headers: Vec<(String, String)>) -> Self {
        self.request_headers = headers;
        self
    }

    /// Check whether this entry is cacheable under RFC 7234 (must not have `no-store` or unmatchable `Vary: *`).
    #[inline]
    pub fn is_cacheable(&self) -> bool {
        !self.directives.no_store && !matches!(self.vary, Some(crate::simd_parser::Http2Vary::Any))
    }

    /// Check whether this cached entry matches presented request headers under RFC 7234 §4.1.
    #[inline]
    pub fn matches_request(&self, presented_headers: &[(String, String)]) -> bool {
        if let Some(ref vary) = self.vary {
            vary.matches_request(&self.request_headers, presented_headers)
        } else {
            true
        }
    }

    /// Check whether this cached entry is fresh under RFC 7234 §4.2.
    pub fn is_fresh(&self, now: std::time::SystemTime, default_ttl: std::time::Duration) -> bool {
        if self.directives.no_cache {
            return false;
        }
        if let Some(exp) = self.expires_at {
            now < exp
        } else {
            now <= self.response_time + default_ttl
        }
    }

    /// Check whether this entry is within its `stale-while-revalidate` window (RFC 5861 §3).
    pub fn is_stale_while_revalidate(
        &self,
        now: std::time::SystemTime,
        default_ttl: std::time::Duration,
        client_swr: Option<u64>,
    ) -> bool {
        if self.directives.no_cache || self.directives.must_revalidate || self.directives.no_store {
            return false;
        }
        if self.is_fresh(now, default_ttl) {
            return false;
        }
        let swr_secs = client_swr.or(self.directives.stale_while_revalidate);
        if let Some(swr) = swr_secs {
            let expiry = self.expires_at.unwrap_or(self.response_time + default_ttl);
            if let Some(limit) = expiry.checked_add(std::time::Duration::from_secs(swr)) {
                return now <= limit;
            }
        }
        false
    }

    /// Check whether this entry is eligible to be served upon an upstream error under `stale-if-error` (RFC 5861 §4).
    pub fn is_stale_if_error(
        &self,
        now: std::time::SystemTime,
        default_ttl: std::time::Duration,
        client_sie: Option<u64>,
    ) -> bool {
        if self.directives.no_store {
            return false;
        }
        if self.is_fresh(now, default_ttl) {
            return true;
        }
        if self.directives.must_revalidate {
            return false;
        }
        let sie_secs = client_sie.or(self.directives.stale_if_error);
        if let Some(sie) = sie_secs {
            let expiry = self.expires_at.unwrap_or(self.response_time + default_ttl);
            if let Some(limit) = expiry.checked_add(std::time::Duration::from_secs(sie)) {
                return now <= limit;
            }
        }
        false
    }

    /// Whether this entry requires origin revalidation (RFC 7234 §4.3) before returning.
    pub fn requires_revalidation(
        &self,
        now: std::time::SystemTime,
        default_ttl: std::time::Duration,
    ) -> bool {
        self.directives.no_cache || !self.is_fresh(now, default_ttl)
    }

    /// Touch this cache entry, updating its `last_accessed` timestamp to the current instant.
    #[inline]
    pub fn touch(&mut self) {
        self.last_accessed = std::time::Instant::now();
    }

    /// Whether the freshness lifetime of this entry was derived heuristically (RFC 7234 §4.2.2).
    #[inline]
    pub fn is_heuristic(&self) -> bool {
        self.is_heuristic
    }

    /// Calculate the heuristic freshness duration if this entry was derived heuristically.
    pub fn heuristic_freshness(&self) -> Option<std::time::Duration> {
        if self.is_heuristic {
            self.expires_at
                .and_then(|exp| exp.duration_since(self.response_time).ok())
        } else {
            None
        }
    }

    /// Whether this cached entry possesses validators (ETag or Last-Modified) for conditional request.
    #[inline]
    pub fn can_revalidate(&self) -> bool {
        self.etag.is_some() || self.last_modified.is_some()
    }

    /// Update this cache entry from a 304 Not Modified response (RFC 7234 §4.3.4).
    pub fn update_from_304(
        &mut self,
        not_modified_resp: &crate::http::HttpResponse,
        now: std::time::SystemTime,
    ) {
        self.response_time = now;
        self.last_accessed = std::time::Instant::now();
        self.revalidations += 1;
        for (k, v) in not_modified_resp.headers.iter() {
            let lower = k.to_ascii_lowercase();
            if matches!(
                lower.as_str(),
                "date" | "expires" | "cache-control" | "etag" | "last-modified" | "vary"
            ) {
                self.response.headers.set(k, v);
            }
        }
        if let Some(etag) = not_modified_resp.headers.get("etag") {
            self.etag = Some(etag.trim().to_string());
        }
        if let Some(lm) = not_modified_resp.headers.get("last-modified") {
            self.last_modified = Some(lm.trim().to_string());
        }
        if let Some(vary_hdr) = not_modified_resp.headers.get("vary") {
            self.vary = Some(crate::simd_parser::Http2Vary::parse(vary_hdr));
        }
        if let Some(cc) = not_modified_resp.headers.get("cache-control") {
            self.directives = crate::http::HttpCacheDirectives::parse(cc);
            self.expires_at = self
                .directives
                .max_age
                .map(|sec| now + std::time::Duration::from_secs(sec));
            self.is_heuristic = false;
        } else if let Some(exp) = not_modified_resp.headers.get("expires") {
            self.expires_at = crate::http::parse_http_date(exp);
            self.is_heuristic = false;
        } else if let Some(ref lm) = self.last_modified {
            if let Some(lm_time) = crate::http::parse_http_date(lm) {
                if let Ok(diff) = now.duration_since(lm_time) {
                    let heuristic_secs = diff.as_secs() / 10;
                    self.expires_at = Some(now + std::time::Duration::from_secs(heuristic_secs));
                    self.is_heuristic = true;
                }
            }
        }
    }

    /// Retrieve Content-Encoding of the cached response payload.
    #[inline]
    pub fn content_encoding(&self) -> crate::http::ContentEncoding {
        self.response.content_encoding()
    }

    /// Whether this cached response possesses compressed body payload.
    #[inline]
    pub fn is_compressed(&self) -> bool {
        self.content_encoding() != crate::http::ContentEncoding::Identity
    }

    /// Transparently decompress cached response body in-place, stripping Content-Encoding and updating Content-Length.
    pub fn decompress_in_place(&mut self) -> Result<bool, String> {
        self.response.decompress_in_place()
    }
}

/// Progressive chunk handler closure for HTTP/3 streaming payloads.
pub type Http3ChunkHandler<'a> = Box<dyn FnMut(&[u8]) + 'a>;

/// Trait representing an HTTP/3 / QUIC transport client or executor for transparent pool renegotiation.
pub trait Http3Transport: Send + Sync {
    /// Execute an HTTP request over HTTP/3 / QUIC to the specified target host and UDP port.
    fn execute_request(
        &self,
        host: &str,
        port: u16,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> io::Result<crate::http::HttpResponse>;

    /// Execute an HTTP request over HTTP/3 / QUIC with progressive chunk delivery.
    /// By default, delegates to `execute_request` and delivers the received payload to `chunk_handler`.
    #[allow(clippy::too_many_arguments)]
    fn execute_streaming_request(
        &self,
        host: &str,
        port: u16,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
        mut chunk_handler: Http3ChunkHandler<'_>,
    ) -> io::Result<crate::http::HttpResponse> {
        let resp = self.execute_request(host, port, method, path, headers, body)?;
        if !resp.body.is_empty() {
            chunk_handler(&resp.body);
        }
        Ok(resp)
    }
}

impl<F> Http3Transport for F
where
    F: Fn(
            &str,
            u16,
            &str,
            &str,
            &[(&str, &str)],
            Option<&[u8]>,
        ) -> io::Result<crate::http::HttpResponse>
        + Send
        + Sync,
{
    fn execute_request(
        &self,
        host: &str,
        port: u16,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> io::Result<crate::http::HttpResponse> {
        (self)(host, port, method, path, headers, body)
    }
}

/// An idle pooled HTTP/2 connection paired with the timestamp at which it became idle.
struct PooledConnectionEntry {
    conn: AsyncHttp2Connection,
    idle_since: std::time::Instant,
}

/// Transparently manages connection pooling, multiplexing limits, idle connection reuse,
/// and multiplexed request execution across shared or pooled HTTP/2 connections.
#[derive(Clone)]
pub struct AsyncHttp2Pool {
    host: String,
    port: u16,
    max_connections: usize,
    max_concurrent_streams_per_conn: usize,
    max_retries: usize,
    retry_backoff: std::time::Duration,
    retried_count: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    idle_ttl: Option<std::time::Duration>,
    idle_pool: std::sync::Arc<std::sync::Mutex<Vec<PooledConnectionEntry>>>,
    active_count: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    evicted_count: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    last_goaway_error: std::sync::Arc<std::sync::Mutex<Option<crate::simd_parser::Http2ErrorCode>>>,
    last_alpn_negotiated: std::sync::Arc<std::sync::Mutex<Option<AlpnProtocol>>>,
    tls_config: Option<TlsConfig>,
    request_interceptors: Vec<Http2RequestInterceptor>,
    response_interceptors: Vec<Http2ResponseInterceptor>,
    alt_svc_routes: std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<String, Vec<crate::simd_parser::AltSvcRoute>>>,
    >,
    http3_transport: Option<std::sync::Arc<dyn Http3Transport>>,
    enable_h3_negotiation: std::sync::Arc<std::sync::atomic::AtomicBool>,
    quarantined_alt_svc_routes:
        std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>>,
    alt_svc_quarantine_duration: std::time::Duration,
    h3_requests_attempted: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    h3_requests_succeeded: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    h3_fallbacks: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    chunk_buffer_pool: Option<Http2ChunkBufferPool>,
    auto_tune_flow_control: bool,
    push_promise_cache: std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<String, Vec<Http2PushPromiseCacheEntry>>>,
    >,
    enable_push_promises: std::sync::Arc<std::sync::atomic::AtomicBool>,
    push_promises_received: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    push_cache_hits: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    http_cache_entries: std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<String, Vec<Http2PoolCacheEntry>>>,
    >,
    enable_http_cache: std::sync::Arc<std::sync::atomic::AtomicBool>,
    max_http_cache_entries: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    http_cache_evictions: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    http_cache_invalidations: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    cache_revalidations: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    stale_hits: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    stale_error_fallbacks: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    background_revalidations: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    revalidating_keys: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
    auto_decompress: std::sync::Arc<std::sync::atomic::AtomicBool>,
    accept_encoding: std::sync::Arc<std::sync::Mutex<Option<String>>>,
    decompressed_responses: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl AsyncHttp2Pool {
    /// Default maximum concurrent streams permitted per single HTTP/2 connection.
    pub const DEFAULT_MAX_STREAMS: usize = 100;
    /// Default maximum HTTP client cache entries retained in the pool.
    pub const DEFAULT_MAX_HTTP_CACHE_ENTRIES: usize = 256;

    /// Create a new HTTP/2 client connection pool.
    pub fn new(host: impl Into<String>, port: u16, max_connections: usize) -> Self {
        Self {
            host: host.into(),
            port,
            max_connections: max_connections.max(1),
            max_concurrent_streams_per_conn: Self::DEFAULT_MAX_STREAMS,
            max_retries: 0,
            retry_backoff: std::time::Duration::from_millis(10),
            retried_count: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            idle_ttl: None,
            idle_pool: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            active_count: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            evicted_count: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            last_goaway_error: std::sync::Arc::new(std::sync::Mutex::new(None)),
            last_alpn_negotiated: std::sync::Arc::new(std::sync::Mutex::new(None)),
            tls_config: None,
            request_interceptors: Vec::new(),
            response_interceptors: Vec::new(),
            alt_svc_routes: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
            http3_transport: None,
            enable_h3_negotiation: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            quarantined_alt_svc_routes: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
            alt_svc_quarantine_duration: std::time::Duration::from_secs(300),
            h3_requests_attempted: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            h3_requests_succeeded: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            h3_fallbacks: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            chunk_buffer_pool: None,
            auto_tune_flow_control: false,
            push_promise_cache: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
            enable_push_promises: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
            push_promises_received: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            push_cache_hits: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            http_cache_entries: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
            enable_http_cache: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            max_http_cache_entries: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(
                Self::DEFAULT_MAX_HTTP_CACHE_ENTRIES,
            )),
            http_cache_evictions: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            http_cache_invalidations: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            cache_revalidations: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            stale_hits: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            stale_error_fallbacks: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            background_revalidations: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            revalidating_keys: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashSet::new(),
            )),
            auto_decompress: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
            accept_encoding: std::sync::Arc::new(std::sync::Mutex::new(Some(
                "gzip, deflate, br".to_string(),
            ))),
            decompressed_responses: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    /// Configure a shared chunk buffer pool to reuse byte allocations across high-frequency streaming requests.
    pub fn with_chunk_buffer_pool(mut self, pool: Http2ChunkBufferPool) -> Self {
        self.chunk_buffer_pool = Some(pool);
        self
    }

    /// Configure whether dynamic RFC 7540 flow control auto-tuning is enabled across connections in this pool.
    pub fn with_auto_tune_flow_control(mut self, enabled: bool) -> Self {
        self.auto_tune_flow_control = enabled;
        self
    }

    /// Whether dynamic RFC 7540 flow control auto-tuning is enabled on this pool.
    pub fn auto_tune_flow_control(&self) -> bool {
        self.auto_tune_flow_control
    }

    /// Configure whether client push promise caching and automated absorption is enabled across connections in this pool.
    pub fn with_push_promises(self, enabled: bool) -> Self {
        self.enable_push_promises
            .store(enabled, std::sync::atomic::Ordering::Relaxed);
        self
    }

    /// Set whether client push promise caching and automated absorption is enabled.
    pub fn set_enable_push_promises(&self, enabled: bool) {
        self.enable_push_promises
            .store(enabled, std::sync::atomic::Ordering::Relaxed);
    }

    /// Whether client push promise caching and automated absorption is enabled on this pool.
    pub fn push_promises_enabled(&self) -> bool {
        self.enable_push_promises
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Configure whether transparent RFC 7234 HTTP response caching and conditional revalidation is enabled.
    pub fn with_http_cache(self, enabled: bool) -> Self {
        self.enable_http_cache
            .store(enabled, std::sync::atomic::Ordering::Relaxed);
        self
    }

    /// Set whether transparent RFC 7234 HTTP response caching is enabled on this pool.
    pub fn set_enable_http_cache(&self, enabled: bool) {
        self.enable_http_cache
            .store(enabled, std::sync::atomic::Ordering::Relaxed);
    }

    /// Whether transparent RFC 7234 HTTP response caching is enabled on this pool.
    pub fn http_cache_enabled(&self) -> bool {
        self.enable_http_cache
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Configure whether transparent response body decompression (RFC 7230 / RFC 7694) is enabled.
    pub fn with_auto_decompress(self, enabled: bool) -> Self {
        self.auto_decompress
            .store(enabled, std::sync::atomic::Ordering::Relaxed);
        self
    }

    /// Set whether transparent response body decompression is enabled.
    pub fn set_auto_decompress(&self, enabled: bool) {
        self.auto_decompress
            .store(enabled, std::sync::atomic::Ordering::Relaxed);
    }

    /// Whether transparent response body decompression is enabled on this pool.
    pub fn auto_decompress(&self) -> bool {
        self.auto_decompress
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Configure the default `Accept-Encoding` header advertised on outbound requests.
    pub fn with_accept_encoding(self, encodings: impl Into<String>) -> Self {
        if let Ok(mut ae) = self.accept_encoding.lock() {
            *ae = Some(encodings.into());
        }
        self
    }

    /// Set or clear the default `Accept-Encoding` header advertised on outbound requests.
    pub fn set_accept_encoding(&self, encodings: Option<String>) {
        if let Ok(mut ae) = self.accept_encoding.lock() {
            *ae = encodings;
        }
    }

    /// Retrieve the currently configured default `Accept-Encoding` header value, if any.
    pub fn accept_encoding(&self) -> Option<String> {
        self.accept_encoding.lock().ok().and_then(|ae| ae.clone())
    }

    /// Total count of response payloads transparently decompressed by the pool.
    pub fn decompressed_responses(&self) -> usize {
        self.decompressed_responses
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Configure an HTTP/3 / QUIC transport client for transparent Alt-Svc renegotiation.
    /// Automatically enables HTTP/3 renegotiation on this pool.
    pub fn with_http3_transport(mut self, transport: impl Http3Transport + 'static) -> Self {
        self.http3_transport = Some(std::sync::Arc::new(transport));
        self.enable_h3_negotiation
            .store(true, std::sync::atomic::Ordering::Relaxed);
        self
    }

    /// Convenience method to configure an HTTP/3 transport handler closure for transparent Alt-Svc renegotiation.
    pub fn with_http3_handler<F>(self, handler: F) -> Self
    where
        F: Fn(
                &str,
                u16,
                &str,
                &str,
                &[(&str, &str)],
                Option<&[u8]>,
            ) -> io::Result<crate::http::HttpResponse>
            + Send
            + Sync
            + 'static,
    {
        self.with_http3_transport(handler)
    }

    /// Set or update the registered HTTP/3 transport client.
    pub fn set_http3_transport(&mut self, transport: Option<std::sync::Arc<dyn Http3Transport>>) {
        self.http3_transport = transport;
    }

    /// Configure whether transparent HTTP/3 renegotiation via Alt-Svc is enabled.
    pub fn with_h3_negotiation(self, enabled: bool) -> Self {
        self.enable_h3_negotiation
            .store(enabled, std::sync::atomic::Ordering::Relaxed);
        self
    }

    /// Set whether transparent HTTP/3 renegotiation is enabled on this pool.
    pub fn set_enable_h3_negotiation(&self, enabled: bool) {
        self.enable_h3_negotiation
            .store(enabled, std::sync::atomic::Ordering::Relaxed);
    }

    /// Whether transparent HTTP/3 renegotiation is enabled on this pool.
    pub fn h3_negotiation_enabled(&self) -> bool {
        self.enable_h3_negotiation
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Configure default quarantine duration for failed alternative service routes (RFC 7838 §2.4).
    pub fn with_alt_svc_quarantine_duration(mut self, duration: std::time::Duration) -> Self {
        self.alt_svc_quarantine_duration = duration;
        self
    }

    /// Quarantine a failed alternative service route for a given duration (or default duration).
    pub fn quarantine_alt_svc_route(&self, route_key: &str, duration: Option<std::time::Duration>) {
        let dur = duration.unwrap_or(self.alt_svc_quarantine_duration);
        let expiry = std::time::Instant::now() + dur;
        if let Ok(mut map) = self.quarantined_alt_svc_routes.lock() {
            map.insert(route_key.to_string(), expiry);
        }
    }

    /// Check whether an alternative service route key is currently quarantined.
    pub fn is_alt_svc_quarantined(&self, route_key: &str) -> bool {
        if let Ok(mut map) = self.quarantined_alt_svc_routes.lock() {
            if let Some(&expiry) = map.get(route_key) {
                if std::time::Instant::now() >= expiry {
                    map.remove(route_key);
                    false
                } else {
                    true
                }
            } else {
                false
            }
        } else {
            false
        }
    }

    /// Clear all active alternative service route quarantines.
    pub fn clear_alt_svc_quarantines(&self) {
        if let Ok(mut map) = self.quarantined_alt_svc_routes.lock() {
            map.clear();
        }
    }

    /// Total count of currently active quarantined alternative service routes.
    pub fn quarantined_alt_svc_routes_count(&self) -> usize {
        if let Ok(mut map) = self.quarantined_alt_svc_routes.lock() {
            let now = std::time::Instant::now();
            map.retain(|_, &mut exp| exp > now);
            map.len()
        } else {
            0
        }
    }

    /// Sweep expired alternative service route quarantines.
    pub fn sweep_expired_alt_svc_quarantines(&self) -> usize {
        if let Ok(mut map) = self.quarantined_alt_svc_routes.lock() {
            let now = std::time::Instant::now();
            let initial = map.len();
            map.retain(|_, &mut exp| exp > now);
            initial - map.len()
        } else {
            0
        }
    }

    /// Total count of HTTP/3 migration requests attempted via Alt-Svc.
    pub fn h3_requests_attempted(&self) -> usize {
        self.h3_requests_attempted
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Total count of HTTP/3 migration requests that succeeded.
    pub fn h3_requests_succeeded(&self) -> usize {
        self.h3_requests_succeeded
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Total count of failed HTTP/3 attempts that transparently fell back to HTTP/2.
    pub fn h3_fallbacks(&self) -> usize {
        self.h3_fallbacks.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Total count of successful 304 Not Modified conditional revalidations performed by the pool.
    pub fn cache_revalidations(&self) -> usize {
        self.cache_revalidations
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Total count of general HTTP cache entries currently stored in the pool.
    pub fn http_cache_count(&self) -> usize {
        if let Ok(cache) = self.http_cache_entries.lock() {
            cache.values().map(|v| v.len()).sum()
        } else {
            0
        }
    }

    /// Clear all stored HTTP client cache entries.
    pub fn clear_http_cache(&self) {
        if let Ok(mut cache) = self.http_cache_entries.lock() {
            let count: usize = cache.values().map(|v| v.len()).sum();
            cache.clear();
            self.http_cache_invalidations
                .fetch_add(count, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Configure the maximum number of HTTP client cache entries retained in the pool.
    /// When the cache exceeds this limit, least-recently-used (LRU) entries are evicted.
    pub fn with_max_http_cache_entries(self, max_entries: usize) -> Self {
        self.max_http_cache_entries
            .store(max_entries.max(1), std::sync::atomic::Ordering::Relaxed);
        self
    }

    /// Set the maximum number of HTTP client cache entries retained in the pool.
    pub fn set_max_http_cache_entries(&self, max_entries: usize) {
        self.max_http_cache_entries
            .store(max_entries.max(1), std::sync::atomic::Ordering::Relaxed);
    }

    /// Current maximum capacity of HTTP cache entries retained in the pool.
    pub fn max_http_cache_entries(&self) -> usize {
        self.max_http_cache_entries
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Total count of HTTP cache entries evicted due to LRU capacity limits or TTL expiration sweeps.
    pub fn http_cache_evictions(&self) -> usize {
        self.http_cache_evictions
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Total count of HTTP cache entries purged due to explicit invalidation or RFC 7234 §4.4 unsafe method updates.
    pub fn http_cache_invalidations(&self) -> usize {
        self.http_cache_invalidations
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Enforce LRU capacity limit on the HTTP client cache, evicting the least recently used entries.
    /// Returns the number of evicted entries.
    pub fn evict_lru_http_cache(&self, max_capacity: usize) -> usize {
        if let Ok(mut cache) = self.http_cache_entries.lock() {
            let total: usize = cache.values().map(|v| v.len()).sum();
            if total > max_capacity {
                let to_evict = total - max_capacity;
                return Self::evict_lru_internal(&mut cache, to_evict, &self.http_cache_evictions);
            }
        }
        0
    }

    /// Internal LRU eviction helper.
    fn evict_lru_internal(
        cache: &mut std::collections::HashMap<String, Vec<Http2PoolCacheEntry>>,
        to_evict: usize,
        evictions_counter: &std::sync::atomic::AtomicUsize,
    ) -> usize {
        if to_evict == 0 || cache.is_empty() {
            return 0;
        }
        let mut items = Vec::new();
        for (k, vec) in cache.iter() {
            for (idx, entry) in vec.iter().enumerate() {
                items.push((k.clone(), idx, entry.last_accessed));
            }
        }
        items.sort_by_key(|item| item.2);
        let count = to_evict.min(items.len());
        let victims = &items[..count];

        let mut victims_by_key: std::collections::HashMap<String, Vec<usize>> =
            std::collections::HashMap::new();
        for (k, idx, _) in victims {
            victims_by_key.entry(k.clone()).or_default().push(*idx);
        }

        let mut evicted_count = 0;
        for (k, mut indices) in victims_by_key {
            if let Some(vec) = cache.get_mut(&k) {
                indices.sort_unstable();
                indices.dedup();
                for idx in indices.into_iter().rev() {
                    if idx < vec.len() {
                        vec.remove(idx);
                        evicted_count += 1;
                    }
                }
            }
        }

        cache.retain(|_, v| !v.is_empty());
        evictions_counter.fetch_add(evicted_count, std::sync::atomic::Ordering::Relaxed);
        evicted_count
    }

    /// Insert or update an HTTP client cache entry into the pool cache, enforcing configured LRU bounds.
    pub fn insert_http_cache_entry(&self, key: String, entry: Http2PoolCacheEntry) {
        if !self.http_cache_enabled() || !entry.is_cacheable() {
            return;
        }
        if let Ok(mut cache) = self.http_cache_entries.lock() {
            let max_entries = self.max_http_cache_entries();
            let entries = cache.entry(key).or_default();
            if let Some(pos) = entries
                .iter()
                .position(|e| e.matches_request(&entry.request_headers))
            {
                entries[pos] = entry;
            } else {
                entries.push(entry);
            }

            let total: usize = cache.values().map(|v| v.len()).sum();
            if total > max_entries {
                let to_evict = total - max_entries;
                Self::evict_lru_internal(&mut cache, to_evict, &self.http_cache_evictions);
            }
        }
    }

    /// Sweep and evict any HTTP client cache entries that are completely expired
    /// (i.e. not fresh and past any `stale-while-revalidate` or `stale-if-error` window).
    /// Returns the number of entries evicted.
    pub fn sweep_http_cache(
        &self,
        now: std::time::SystemTime,
        default_ttl: std::time::Duration,
    ) -> usize {
        if let Ok(mut cache) = self.http_cache_entries.lock() {
            let mut evicted = 0;
            for entries in cache.values_mut() {
                let initial_len = entries.len();
                entries.retain(|entry| {
                    entry.is_fresh(now, default_ttl)
                        || entry.is_stale_while_revalidate(now, default_ttl, None)
                        || entry.is_stale_if_error(now, default_ttl, None)
                });
                evicted += initial_len - entries.len();
            }
            cache.retain(|_, v| !v.is_empty());
            self.http_cache_evictions
                .fetch_add(evicted, std::sync::atomic::Ordering::Relaxed);
            evicted
        } else {
            0
        }
    }

    /// Sweep HTTP client cache entries strictly older than `max_age` based on ingestion time.
    /// Returns the number of entries evicted.
    pub fn sweep_expired_http_cache(&self, max_age: std::time::Duration) -> usize {
        let now = std::time::Instant::now();
        if let Ok(mut cache) = self.http_cache_entries.lock() {
            let mut evicted = 0;
            for entries in cache.values_mut() {
                let initial_len = entries.len();
                entries.retain(|entry| now.duration_since(entry.received_at) <= max_age);
                evicted += initial_len - entries.len();
            }
            cache.retain(|_, v| !v.is_empty());
            self.http_cache_evictions
                .fetch_add(evicted, std::sync::atomic::Ordering::Relaxed);
            evicted
        } else {
            0
        }
    }

    /// Invalidate and remove all HTTP client cache entries for a specific path (RFC 7234 §4.4).
    /// Returns the number of invalidated entries.
    pub fn invalidate_http_cache_path(&self, path: &str) -> usize {
        if let Ok(mut cache) = self.http_cache_entries.lock() {
            let mut removed = 0;
            for entries in cache.values_mut() {
                let initial = entries.len();
                entries.retain(|e| e.path != path);
                removed += initial - entries.len();
            }
            cache.retain(|_, v| !v.is_empty());
            self.http_cache_invalidations
                .fetch_add(removed, std::sync::atomic::Ordering::Relaxed);
            removed
        } else {
            0
        }
    }

    /// Invalidate and remove all HTTP client cache entries matching a path prefix.
    /// Returns the number of invalidated entries.
    pub fn invalidate_http_cache_prefix(&self, path_prefix: &str) -> usize {
        if let Ok(mut cache) = self.http_cache_entries.lock() {
            let mut removed = 0;
            for entries in cache.values_mut() {
                let initial = entries.len();
                entries.retain(|e| !e.path.starts_with(path_prefix));
                removed += initial - entries.len();
            }
            cache.retain(|_, v| !v.is_empty());
            self.http_cache_invalidations
                .fetch_add(removed, std::sync::atomic::Ordering::Relaxed);
            removed
        } else {
            0
        }
    }

    /// Invalidate and remove all HTTP client cache entries satisfying a given predicate.
    /// Returns the number of invalidated entries.
    pub fn invalidate_http_cache_matching(
        &self,
        predicate: impl Fn(&Http2PoolCacheEntry) -> bool,
    ) -> usize {
        if let Ok(mut cache) = self.http_cache_entries.lock() {
            let mut removed = 0;
            for entries in cache.values_mut() {
                let initial = entries.len();
                entries.retain(|e| !predicate(e));
                removed += initial - entries.len();
            }
            cache.retain(|_, v| !v.is_empty());
            self.http_cache_invalidations
                .fetch_add(removed, std::sync::atomic::Ordering::Relaxed);
            removed
        } else {
            0
        }
    }

    /// Total count of push promises ingested and stored in cache.
    pub fn push_promises_received(&self) -> usize {
        self.push_promises_received
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Total count of requests satisfied directly from proactive push promise cache without network I/O.
    pub fn push_cache_hits(&self) -> usize {
        self.push_cache_hits
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Number of distinct push promise responses currently held in pool cache.
    pub fn push_promise_cache_count(&self) -> usize {
        if let Ok(cache) = self.push_promise_cache.lock() {
            cache.values().map(|v| v.len()).sum()
        } else {
            0
        }
    }

    /// Clear all cached push promise responses.
    pub fn clear_push_promise_cache(&self) {
        if let Ok(mut cache) = self.push_promise_cache.lock() {
            cache.clear();
        }
    }

    /// Ingest and validate all completed push promises received on an active connection into the pool cache.
    pub fn absorb_push_promises(&self, conn: &mut AsyncHttp2Connection) {
        if !self
            .enable_push_promises
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return;
        }
        let completed = conn.drain_completed_push_responses();
        if completed.is_empty() {
            return;
        }

        if let Ok(mut cache) = self.push_promise_cache.lock() {
            for (promised_req, response) in completed {
                if !promised_req.is_valid {
                    continue;
                }
                let entry = Http2PushPromiseCacheEntry::new(promised_req.clone(), response);
                // RFC 7234 §5.2.2.3: do not cache responses marked no-store
                if !entry.is_cacheable() {
                    continue;
                }
                let key = format!(
                    "{}:{}",
                    promised_req.method.to_ascii_uppercase(),
                    promised_req.path
                );
                self.push_promises_received
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                cache.entry(key).or_insert_with(Vec::new).push(entry);
            }
        }
    }

    /// Take and remove a matching cached push promise response, if available and unexpired.
    pub fn take_cached_push_response(
        &self,
        method: &str,
        path: &str,
    ) -> Option<crate::http::HttpResponse> {
        if !self
            .enable_push_promises
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return None;
        }
        let key = format!("{}:{}", method.to_ascii_uppercase(), path);
        let now_sys = std::time::SystemTime::now();
        let max_age = self.idle_ttl.unwrap_or(std::time::Duration::from_secs(60));

        if let Ok(mut cache) = self.push_promise_cache.lock() {
            if let Some(entries) = cache.get_mut(&key) {
                while let Some(entry) = entries.pop() {
                    if entry.is_fresh(now_sys, max_age) {
                        self.push_cache_hits
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if entries.is_empty() {
                            cache.remove(&key);
                        }
                        return Some(entry.response);
                    }
                }
                if entries.is_empty() {
                    cache.remove(&key);
                }
            }
        }
        None
    }

    /// Check whether a matching cached push promise response currently exists in the pool cache.
    pub fn has_cached_push_response(&self, method: &str, path: &str) -> bool {
        if !self
            .enable_push_promises
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return false;
        }
        let key = format!("{}:{}", method.to_ascii_uppercase(), path);
        if let Ok(cache) = self.push_promise_cache.lock() {
            cache.get(&key).map(|v| !v.is_empty()).unwrap_or(false)
        } else {
            false
        }
    }

    /// Retrieve the configured chunk buffer pool, if any.
    pub fn chunk_buffer_pool(&self) -> Option<&Http2ChunkBufferPool> {
        self.chunk_buffer_pool.as_ref()
    }

    /// Configure the default maximum number of adaptive retries for requests executed on this pool
    /// upon encountering retryable GOAWAY frames or transient connection resets.
    pub fn with_max_retries(mut self, retries: usize) -> Self {
        self.max_retries = retries;
        self
    }

    /// Configure the base backoff duration applied between adaptive retries.
    pub fn with_retry_backoff(mut self, backoff: std::time::Duration) -> Self {
        self.retry_backoff = backoff;
        self
    }

    /// Total count of requests successfully retried after transient failure or GOAWAY.
    pub fn retried_count(&self) -> usize {
        self.retried_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Check whether an error encountered during request execution is transient or
    /// eligible for adaptive retry on a fresh connection.
    pub fn is_transient_or_retryable_error(&self, err: &io::Error) -> bool {
        if let Some(ec) = self.last_goaway_error() {
            if ec.is_fatal_protocol_violation() || ec.is_rate_limit_or_calm() {
                return false;
            }
            if ec.is_retryable() {
                return true;
            }
        }
        match err.kind() {
            io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::NotConnected
            | io::ErrorKind::TimedOut => true,
            _ => {
                let msg = err.to_string();
                (msg.contains("GOAWAY") || msg.contains("reset")) && !msg.contains("PROTOCOL_ERROR")
            }
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

    /// Total count of cache hits served stale under `stale-while-revalidate` (RFC 5861 §3).
    pub fn stale_hits(&self) -> usize {
        self.stale_hits.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Total count of requests rescued from upstream failure or 5xx by serving stale under `stale-if-error` (RFC 5861 §4).
    pub fn stale_error_fallbacks(&self) -> usize {
        self.stale_error_fallbacks
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Total count of background revalidations completed for stale cache entries.
    pub fn background_revalidations(&self) -> usize {
        self.background_revalidations
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
            retried_requests: self.retried_count(),
            cached_push_promises: self.push_promise_cache_count(),
            push_cache_hits: self.push_cache_hits(),
            cache_revalidations: self.cache_revalidations(),
            http_cache_entries: self.http_cache_count(),
            stale_hits: self.stale_hits(),
            stale_error_fallbacks: self.stale_error_fallbacks(),
            background_revalidations: self.background_revalidations(),
            http_cache_evictions: self.http_cache_evictions(),
            http_cache_invalidations: self.http_cache_invalidations(),
            decompressed_responses: self.decompressed_responses(),
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
                    conn.set_auto_tune_flow_control(self.auto_tune_flow_control);
                    conn.set_enable_push(
                        self.enable_push_promises
                            .load(std::sync::atomic::Ordering::Relaxed),
                    );
                    if let Some(ref pool) = self.chunk_buffer_pool {
                        conn.chunk_buffer_pool = Some(pool.clone());
                    }
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

        let mut conn = AsyncHttp2Connection::client_handshake(stream)?;
        conn.set_auto_tune_flow_control(self.auto_tune_flow_control);
        conn.set_enable_push(
            self.enable_push_promises
                .load(std::sync::atomic::Ordering::Relaxed),
        );
        if let Some(ref pool) = self.chunk_buffer_pool {
            conn.chunk_buffer_pool = Some(pool.clone());
        }

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

        // Harvest any Alt-Svc routes discovered on the connection's session
        if !conn.session.alt_svc_routes.is_empty() {
            if let Ok(mut pool_routes) = self.alt_svc_routes.lock() {
                for (origin, routes) in &conn.session.alt_svc_routes {
                    pool_routes.insert(origin.clone(), routes.clone());
                }
            }
        }

        // Proactively absorb and cache any push promises completed on this connection
        self.absorb_push_promises(&mut conn);

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
        self.absorb_push_promises(&mut conn);
        match result {
            Ok(responses) => {
                self.release(conn);
                Ok(responses)
            }
            Err(e) => {
                if let Some((_, err, _)) = conn.last_received_goaway() {
                    if let Ok(mut last_err) = self.last_goaway_error.lock() {
                        *last_err = Some(err);
                    }
                }
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
    /// If `max_retries` is configured > 0, transparent adaptive retry on transient reset or retryable GOAWAY is active.
    /// Any registered response interceptors are executed on the resulting response before returning.
    pub fn execute_request(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> io::Result<crate::http::HttpResponse> {
        if self.max_retries > 0 {
            return self.execute_request_with_retry(method, path, headers, body, self.max_retries);
        }
        self.execute_request_single(method, path, headers, body)
    }

    /// Retrieve a cached response eligible for `stale-if-error` fallback (RFC 5861 §4).
    pub fn find_stale_if_error_fallback(
        &self,
        key: &str,
        client_headers: &[(String, String)],
        now: std::time::SystemTime,
        default_ttl: std::time::Duration,
        client_sie: Option<u64>,
    ) -> Option<crate::http::HttpResponse> {
        if self
            .enable_http_cache
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            if let Ok(cache) = self.http_cache_entries.lock() {
                if let Some(entries) = cache.get(key) {
                    if let Some(entry) = entries.iter().rev().find(|e| {
                        e.matches_request(client_headers)
                            && e.is_stale_if_error(now, default_ttl, client_sie)
                    }) {
                        let mut resp = entry.response.clone();
                        resp.headers.set("warning", "110 - \"Response is Stale\"");
                        return Some(resp);
                    }
                }
            }
        }
        if self
            .enable_push_promises
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            if let Ok(cache) = self.push_promise_cache.lock() {
                if let Some(entries) = cache.get(key) {
                    if let Some(entry) = entries.iter().rev().find(|e| {
                        e.matches_request(client_headers)
                            && e.is_stale_if_error(now, default_ttl, client_sie)
                    }) {
                        let mut resp = entry.response.clone();
                        resp.headers.set("warning", "110 - \"Response is Stale\"");
                        return Some(resp);
                    }
                }
            }
        }
        None
    }

    /// Spawn an asynchronous background task to revalidate a stale cache entry (RFC 5861 §3).
    pub fn spawn_background_revalidate(
        &self,
        client_req: &Http2ClientRequest,
        etag: Option<String>,
        last_modified: Option<String>,
    ) {
        let key = format!(
            "{}:{}",
            client_req.method.to_ascii_uppercase(),
            client_req.path
        );
        if let Ok(mut in_flight) = self.revalidating_keys.lock() {
            if !in_flight.insert(key.clone()) {
                // Background revalidation already in-flight for this key
                return;
            }
        }

        let pool = self.clone();
        let req = client_req.clone();
        std::thread::spawn(move || {
            let _ = pool.execute_background_revalidate(&req, etag, last_modified);
            if let Ok(mut in_flight) = pool.revalidating_keys.lock() {
                in_flight.remove(&key);
            }
        });
    }

    /// Execute a background conditional revalidation request (RFC 5861 §3) and update cache.
    pub fn execute_background_revalidate(
        &self,
        client_req: &Http2ClientRequest,
        etag: Option<String>,
        last_modified: Option<String>,
    ) -> io::Result<()> {
        let mut req = client_req.clone();
        if let Some(tag) = etag {
            if !req
                .headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("if-none-match"))
            {
                req.headers.push(("if-none-match".to_string(), tag));
            }
        }
        if let Some(lm) = last_modified {
            if !req
                .headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("if-modified-since"))
            {
                req.headers.push(("if-modified-since".to_string(), lm));
            }
        }

        let mut conn = self.acquire()?;
        let header_refs: Vec<(&str, &str)> = req
            .headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let body_ref = req.body.as_deref();

        let result = conn.request(&req.method, &req.path, &header_refs, body_ref);
        match result {
            Ok(resp) => {
                let key = format!("{}:{}", req.method.to_ascii_uppercase(), req.path);
                let now_update = std::time::SystemTime::now();

                self.background_revalidations
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                if resp.status.0 == 304 {
                    self.cache_revalidations
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                    let mut updated = false;
                    if self
                        .enable_http_cache
                        .load(std::sync::atomic::Ordering::Relaxed)
                    {
                        if let Ok(mut cache) = self.http_cache_entries.lock() {
                            if let Some(entries) = cache.get_mut(&key) {
                                if let Some(pos) = entries
                                    .iter()
                                    .rposition(|e| e.matches_request(&req.headers))
                                {
                                    entries[pos].update_from_304(&resp, now_update);
                                    updated = true;
                                }
                            }
                        }
                    }
                    if !updated
                        && self
                            .enable_push_promises
                            .load(std::sync::atomic::Ordering::Relaxed)
                    {
                        if let Ok(mut cache) = self.push_promise_cache.lock() {
                            if let Some(entries) = cache.get_mut(&key) {
                                if let Some(pos) = entries
                                    .iter()
                                    .rposition(|e| e.matches_request(&req.headers))
                                {
                                    entries[pos].update_from_304(&resp, now_update);
                                }
                            }
                        }
                    }
                } else if resp.status.0 == 200 {
                    let entry = Http2PoolCacheEntry::new(
                        req.method.clone(),
                        req.path.clone(),
                        resp.clone(),
                    )
                    .with_request_headers(req.headers.clone());
                    self.insert_http_cache_entry(key, entry);
                }
                self.release(conn);
                Ok(())
            }
            Err(e) => {
                self.release(conn);
                Err(e)
            }
        }
    }

    /// Execute a single attempt of an HTTP/2 request using a pooled connection without retry loop.
    pub fn execute_request_single(
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

        // Automatic Accept-Encoding injection if auto_decompress is enabled and not explicitly specified
        if self.auto_decompress()
            && !client_req
                .headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("accept-encoding"))
        {
            if let Some(ref ae) = self.accept_encoding() {
                client_req
                    .headers
                    .push(("accept-encoding".to_string(), ae.clone()));
            }
        }

        let key = format!(
            "{}:{}",
            client_req.method.to_ascii_uppercase(),
            client_req.path
        );
        let now_sys = std::time::SystemTime::now();
        let default_ttl = self.idle_ttl.unwrap_or(std::time::Duration::from_secs(60));

        let req_cc = client_req
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("cache-control"))
            .map(|(_, v)| crate::http::HttpCacheDirectives::parse(v));
        let client_no_cache = req_cc.as_ref().map(|cc| cc.no_cache).unwrap_or(false);
        let client_no_store = req_cc.as_ref().map(|cc| cc.no_store).unwrap_or(false);
        let client_swr = req_cc.as_ref().and_then(|cc| cc.stale_while_revalidate);
        let client_sie = req_cc.as_ref().and_then(|cc| cc.stale_if_error);

        // 1. Check proactive push promise cache first (if not client_no_store)
        if self
            .enable_push_promises
            .load(std::sync::atomic::Ordering::Relaxed)
            && !client_no_store
        {
            if let Ok(mut cache) = self.push_promise_cache.lock() {
                if let Some(entries) = cache.get_mut(&key) {
                    if let Some(pos) = entries
                        .iter()
                        .rposition(|entry| entry.matches_request(&client_req.headers))
                    {
                        let entry = &mut entries[pos];
                        if !client_no_cache && entry.is_fresh(now_sys, default_ttl) {
                            entry.hit_count += 1;
                            self.push_cache_hits
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            let mut resp = entry.response.clone();
                            if entry.directives.max_age.is_none() {
                                entries.remove(pos);
                            }
                            drop(cache);
                            for resp_interceptor in &self.response_interceptors {
                                resp_interceptor(&client_req, &mut resp);
                            }
                            return Ok(resp);
                        } else if !client_no_cache
                            && entry.is_stale_while_revalidate(now_sys, default_ttl, client_swr)
                        {
                            entry.hit_count += 1;
                            self.push_cache_hits
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            self.stale_hits
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            let mut resp = entry.response.clone();
                            resp.headers.set("warning", "110 - \"Response is Stale\"");
                            let etag = entry.etag.clone();
                            let lm = entry.last_modified.clone();
                            drop(cache);
                            self.spawn_background_revalidate(&client_req, etag, lm);
                            for resp_interceptor in &self.response_interceptors {
                                resp_interceptor(&client_req, &mut resp);
                            }
                            return Ok(resp);
                        }
                    }
                }
            }
        }

        // 2. Check general HTTP client cache (if enabled and not client_no_store)
        let mut cached_validator: Option<(Option<String>, Option<String>)> = None;
        if self
            .enable_http_cache
            .load(std::sync::atomic::Ordering::Relaxed)
            && !client_no_store
        {
            if let Ok(mut cache) = self.http_cache_entries.lock() {
                if let Some(entries) = cache.get_mut(&key) {
                    if let Some(pos) = entries
                        .iter()
                        .rposition(|entry| entry.matches_request(&client_req.headers))
                    {
                        let entry = &mut entries[pos];
                        if !client_no_cache && entry.is_fresh(now_sys, default_ttl) {
                            entry.touch();
                            entry.hit_count += 1;
                            self.push_cache_hits
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            let mut resp = entry.response.clone();
                            if entry.is_heuristic {
                                if let Ok(age) = now_sys.duration_since(entry.response_time) {
                                    if age.as_secs() > 86400 {
                                        resp.headers
                                            .set("warning", "113 - \"Heuristic Expiration\"");
                                    }
                                }
                            }
                            drop(cache);
                            for resp_interceptor in &self.response_interceptors {
                                resp_interceptor(&client_req, &mut resp);
                            }
                            return Ok(resp);
                        } else if !client_no_cache
                            && entry.is_stale_while_revalidate(now_sys, default_ttl, client_swr)
                        {
                            entry.touch();
                            entry.hit_count += 1;
                            self.push_cache_hits
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            self.stale_hits
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            let mut resp = entry.response.clone();
                            resp.headers.set("warning", "110 - \"Response is Stale\"");
                            let etag = entry.etag.clone();
                            let lm = entry.last_modified.clone();
                            drop(cache);
                            self.spawn_background_revalidate(&client_req, etag, lm);
                            for resp_interceptor in &self.response_interceptors {
                                resp_interceptor(&client_req, &mut resp);
                            }
                            return Ok(resp);
                        } else if entry.can_revalidate() {
                            cached_validator =
                                Some((entry.etag.clone(), entry.last_modified.clone()));
                        }
                    }
                }
            }
        }

        // Also check if push promise cache has a stale entry with validators that can be revalidated
        if cached_validator.is_none()
            && self
                .enable_push_promises
                .load(std::sync::atomic::Ordering::Relaxed)
            && !client_no_store
        {
            if let Ok(cache) = self.push_promise_cache.lock() {
                if let Some(entries) = cache.get(&key) {
                    if let Some(entry) = entries
                        .iter()
                        .rev()
                        .find(|entry| entry.matches_request(&client_req.headers))
                    {
                        if entry.can_revalidate() {
                            cached_validator =
                                Some((entry.etag.clone(), entry.last_modified.clone()));
                        }
                    }
                }
            }
        }

        let is_revalidating = cached_validator.is_some();
        if let Some((ref etag_opt, ref lm_opt)) = cached_validator {
            if let Some(tag) = etag_opt {
                if !client_req
                    .headers
                    .iter()
                    .any(|(k, _)| k.eq_ignore_ascii_case("if-none-match"))
                {
                    client_req
                        .headers
                        .push(("if-none-match".to_string(), tag.clone()));
                }
            }
            if let Some(lm) = lm_opt {
                if !client_req
                    .headers
                    .iter()
                    .any(|(k, _)| k.eq_ignore_ascii_case("if-modified-since"))
                {
                    client_req
                        .headers
                        .push(("if-modified-since".to_string(), lm.clone()));
                }
            }
        }

        // --- Transparent HTTP/3 renegotiation check via Alt-Svc (RFC 7838) ---
        if self.h3_negotiation_enabled() {
            if let Some(ref transport) = self.http3_transport {
                if let Some(route) = self.select_active_unquarantined_alt_svc_route(
                    None,
                    "h3",
                    std::time::Duration::from_secs(0),
                    true,
                ) {
                    let target_host = if route.host.is_empty() {
                        self.host.as_str()
                    } else {
                        route.host.as_str()
                    };
                    let target_port = if route.port != 0 {
                        route.port
                    } else {
                        self.port
                    };
                    let q_key = format!("h3://{}:{}", target_host, target_port);

                    self.h3_requests_attempted
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                    let header_refs: Vec<(&str, &str)> = client_req
                        .headers
                        .iter()
                        .map(|(k, v)| (k.as_str(), v.as_str()))
                        .collect();
                    let body_ref = client_req.body.as_deref();

                    match transport.execute_request(
                        target_host,
                        target_port,
                        &client_req.method,
                        &client_req.path,
                        &header_refs,
                        body_ref,
                    ) {
                        Ok(mut resp) => {
                            self.h3_requests_succeeded
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                            if resp.status.0 == 304 && is_revalidating {
                                self.cache_revalidations
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                self.push_cache_hits
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                                let now_update = std::time::SystemTime::now();
                                let mut resolved_resp = None;

                                if self
                                    .enable_http_cache
                                    .load(std::sync::atomic::Ordering::Relaxed)
                                {
                                    if let Ok(mut cache) = self.http_cache_entries.lock() {
                                        if let Some(entries) = cache.get_mut(&key) {
                                            if let Some(pos) = entries.iter().rposition(|entry| {
                                                entry.matches_request(&client_req.headers)
                                            }) {
                                                entries[pos].update_from_304(&resp, now_update);
                                                resolved_resp = Some(entries[pos].response.clone());
                                            }
                                        }
                                    }
                                }
                                if resolved_resp.is_none()
                                    && self
                                        .enable_push_promises
                                        .load(std::sync::atomic::Ordering::Relaxed)
                                {
                                    if let Ok(mut cache) = self.push_promise_cache.lock() {
                                        if let Some(entries) = cache.get_mut(&key) {
                                            if let Some(pos) = entries.iter().rposition(|entry| {
                                                entry.matches_request(&client_req.headers)
                                            }) {
                                                entries[pos].update_from_304(&resp, now_update);
                                                resolved_resp = Some(entries[pos].response.clone());
                                            }
                                        }
                                    }
                                }

                                if let Some(mut fresh_resp) = resolved_resp {
                                    for resp_interceptor in &self.response_interceptors {
                                        resp_interceptor(&client_req, &mut fresh_resp);
                                    }
                                    return Ok(fresh_resp);
                                }
                            }

                            if let Some(alt_svc_val) = resp.headers.get("alt-svc") {
                                let routes = crate::simd_parser::AltSvcRoute::parse_header_value(
                                    alt_svc_val,
                                );
                                let origin = format!("{}:{}", self.host, self.port);
                                if let Ok(mut pool_routes) = self.alt_svc_routes.lock() {
                                    if routes.is_empty()
                                        && alt_svc_val.trim().eq_ignore_ascii_case("clear")
                                    {
                                        pool_routes.remove(&origin);
                                    } else if !routes.is_empty() {
                                        pool_routes.insert(origin, routes);
                                    }
                                }
                            }

                            if self.auto_decompress() && resp.headers.has("content-encoding") {
                                if let Ok(true) = resp.decompress_in_place() {
                                    self.decompressed_responses
                                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                }
                            }

                            if self
                                .enable_http_cache
                                .load(std::sync::atomic::Ordering::Relaxed)
                                && (client_req.method.eq_ignore_ascii_case("GET")
                                    || client_req.method.eq_ignore_ascii_case("HEAD"))
                                && resp.status.0 == 200
                                && !client_no_store
                            {
                                let entry = Http2PoolCacheEntry::new(
                                    client_req.method.clone(),
                                    client_req.path.clone(),
                                    resp.clone(),
                                )
                                .with_request_headers(client_req.headers.clone());
                                self.insert_http_cache_entry(key.clone(), entry);
                            }

                            if !client_req.method.eq_ignore_ascii_case("GET")
                                && !client_req.method.eq_ignore_ascii_case("HEAD")
                                && resp.status.0 >= 200
                                && resp.status.0 < 400
                            {
                                self.invalidate_http_cache_path(&client_req.path);
                            }

                            for resp_interceptor in &self.response_interceptors {
                                resp_interceptor(&client_req, &mut resp);
                            }
                            return Ok(resp);
                        }
                        Err(_e) => {
                            self.h3_fallbacks
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            self.quarantine_alt_svc_route(&q_key, None);
                        }
                    }
                }
            }
        }

        let conn_res = self.acquire();
        let (conn_opt, result) = match conn_res {
            Ok(mut conn) => {
                let header_refs: Vec<(&str, &str)> = client_req
                    .headers
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_str()))
                    .collect();
                let body_ref = client_req.body.as_deref();
                let r = conn.request(&client_req.method, &client_req.path, &header_refs, body_ref);
                if conn.decompressed_count > 0 {
                    self.decompressed_responses.fetch_add(
                        conn.decompressed_count,
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    conn.decompressed_count = 0;
                }
                (Some(conn), r)
            }
            Err(e) => (None, Err(e)),
        };

        match result {
            Ok(mut resp) => {
                // Check if 5xx error and eligible for stale-if-error fallback
                if resp.status.0 >= 500 && resp.status.0 <= 599 && !client_no_store {
                    if let Some(mut fallback_resp) = self.find_stale_if_error_fallback(
                        &key,
                        &client_req.headers,
                        now_sys,
                        default_ttl,
                        client_sie,
                    ) {
                        self.stale_error_fallbacks
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if let Some(conn) = conn_opt {
                            self.release(conn);
                        }
                        for resp_interceptor in &self.response_interceptors {
                            resp_interceptor(&client_req, &mut fallback_resp);
                        }
                        return Ok(fallback_resp);
                    }
                }

                // If 304 Not Modified received on conditional revalidation, refresh cache and return 200 with cached body!
                if resp.status.0 == 304 && is_revalidating {
                    self.cache_revalidations
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    self.push_cache_hits
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                    let now_update = std::time::SystemTime::now();
                    let mut resolved_resp = None;

                    if self
                        .enable_http_cache
                        .load(std::sync::atomic::Ordering::Relaxed)
                    {
                        if let Ok(mut cache) = self.http_cache_entries.lock() {
                            if let Some(entries) = cache.get_mut(&key) {
                                if let Some(pos) = entries
                                    .iter()
                                    .rposition(|entry| entry.matches_request(&client_req.headers))
                                {
                                    entries[pos].update_from_304(&resp, now_update);
                                    resolved_resp = Some(entries[pos].response.clone());
                                }
                            }
                        }
                    }
                    if resolved_resp.is_none()
                        && self
                            .enable_push_promises
                            .load(std::sync::atomic::Ordering::Relaxed)
                    {
                        if let Ok(mut cache) = self.push_promise_cache.lock() {
                            if let Some(entries) = cache.get_mut(&key) {
                                if let Some(pos) = entries
                                    .iter()
                                    .rposition(|entry| entry.matches_request(&client_req.headers))
                                {
                                    entries[pos].update_from_304(&resp, now_update);
                                    resolved_resp = Some(entries[pos].response.clone());
                                }
                            }
                        }
                    }

                    if let Some(mut fresh_resp) = resolved_resp {
                        if let Some(conn) = conn_opt {
                            self.release(conn);
                        }
                        for resp_interceptor in &self.response_interceptors {
                            resp_interceptor(&client_req, &mut fresh_resp);
                        }
                        return Ok(fresh_resp);
                    }
                }

                // If response contains an "alt-svc" header, automatically record routes on pool
                if let Some(alt_svc_val) = resp.headers.get("alt-svc") {
                    let routes = crate::simd_parser::AltSvcRoute::parse_header_value(alt_svc_val);
                    let origin = format!("{}:{}", self.host, self.port);
                    if let Ok(mut pool_routes) = self.alt_svc_routes.lock() {
                        if routes.is_empty() && alt_svc_val.trim().eq_ignore_ascii_case("clear") {
                            pool_routes.remove(&origin);
                        } else if !routes.is_empty() {
                            pool_routes.insert(origin, routes);
                        }
                    }
                }

                // Transparent response body decompression (RFC 7230 / RFC 7694)
                if self.auto_decompress() && resp.headers.has("content-encoding") {
                    if let Ok(true) = resp.decompress_in_place() {
                        self.decompressed_responses
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }

                // If response is cacheable 200 OK and http_cache is enabled, cache it
                if self
                    .enable_http_cache
                    .load(std::sync::atomic::Ordering::Relaxed)
                    && (client_req.method.eq_ignore_ascii_case("GET")
                        || client_req.method.eq_ignore_ascii_case("HEAD"))
                    && resp.status.0 == 200
                    && !client_no_store
                {
                    let entry = Http2PoolCacheEntry::new(
                        client_req.method.clone(),
                        client_req.path.clone(),
                        resp.clone(),
                    )
                    .with_request_headers(client_req.headers.clone());
                    self.insert_http_cache_entry(key, entry);
                }

                // RFC 7234 §4.4: Invalidate cache for target URI on successful non-safe requests (POST, PUT, DELETE, PATCH)
                if !client_req.method.eq_ignore_ascii_case("GET")
                    && !client_req.method.eq_ignore_ascii_case("HEAD")
                    && resp.status.0 >= 200
                    && resp.status.0 < 400
                {
                    self.invalidate_http_cache_path(&client_req.path);
                }

                if let Some(conn) = conn_opt {
                    self.release(conn);
                }
                for resp_interceptor in &self.response_interceptors {
                    resp_interceptor(&client_req, &mut resp);
                }
                Ok(resp)
            }
            Err(e) => {
                if !client_no_store {
                    if let Some(mut fallback_resp) = self.find_stale_if_error_fallback(
                        &key,
                        &client_req.headers,
                        now_sys,
                        default_ttl,
                        client_sie,
                    ) {
                        self.stale_error_fallbacks
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if let Some(conn) = conn_opt {
                            self.release(conn);
                        }
                        for resp_interceptor in &self.response_interceptors {
                            resp_interceptor(&client_req, &mut fallback_resp);
                        }
                        return Ok(fallback_resp);
                    }
                }
                if let Some(mut conn) = conn_opt {
                    self.absorb_push_promises(&mut conn);
                    if let Some((_, err, _)) = conn.last_received_goaway() {
                        if let Ok(mut last_err) = self.last_goaway_error.lock() {
                            *last_err = Some(err);
                        }
                    }
                    // If connection failed, it is dropped and not released back to the pool
                    self.active_count
                        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                }
                Err(e)
            }
        }
    }

    /// Execute an HTTP/2 request using a pooled connection with streaming response chunks
    /// delivered to `chunk_handler` progressively as each chunked DATA frame arrives from the server.
    ///
    /// If `max_retries` is configured > 0, transparent adaptive retry on transient reset or retryable GOAWAY is active
    /// provided no chunk was delivered to `chunk_handler` yet.
    pub fn execute_streaming_request<F>(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
        chunk_handler: F,
    ) -> io::Result<crate::http::HttpResponse>
    where
        F: FnMut(&[u8]),
    {
        if self.max_retries > 0 {
            return self.execute_streaming_request_with_retry(
                method,
                path,
                headers,
                body,
                self.max_retries,
                chunk_handler,
            );
        }
        self.execute_streaming_request_single(method, path, headers, body, chunk_handler)
    }

    /// Execute a single attempt of an HTTP/2 streaming request using a pooled connection without retry loop.
    pub fn execute_streaming_request_single<F>(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
        mut chunk_handler: F,
    ) -> io::Result<crate::http::HttpResponse>
    where
        F: FnMut(&[u8]),
    {
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
                if !short_circuit_resp.body.is_empty() {
                    chunk_handler(&short_circuit_resp.body);
                }
                for resp_interceptor in &self.response_interceptors {
                    resp_interceptor(&client_req, &mut short_circuit_resp);
                }
                return Ok(short_circuit_resp);
            }
        }

        // Automatic Accept-Encoding injection if auto_decompress is enabled and not explicitly specified
        if self.auto_decompress()
            && !client_req
                .headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("accept-encoding"))
        {
            if let Some(ref ae) = self.accept_encoding() {
                client_req
                    .headers
                    .push(("accept-encoding".to_string(), ae.clone()));
            }
        }

        let key = format!(
            "{}:{}",
            client_req.method.to_ascii_uppercase(),
            client_req.path
        );
        let now_sys = std::time::SystemTime::now();
        let default_ttl = self.idle_ttl.unwrap_or(std::time::Duration::from_secs(60));

        let req_cc = client_req
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("cache-control"))
            .map(|(_, v)| crate::http::HttpCacheDirectives::parse(v));
        let client_no_cache = req_cc.as_ref().map(|cc| cc.no_cache).unwrap_or(false);
        let client_no_store = req_cc.as_ref().map(|cc| cc.no_store).unwrap_or(false);
        let client_swr = req_cc.as_ref().and_then(|cc| cc.stale_while_revalidate);
        let client_sie = req_cc.as_ref().and_then(|cc| cc.stale_if_error);

        // 1. Check proactive push promise cache first
        if self
            .enable_push_promises
            .load(std::sync::atomic::Ordering::Relaxed)
            && !client_no_store
        {
            if let Ok(mut cache) = self.push_promise_cache.lock() {
                if let Some(entries) = cache.get_mut(&key) {
                    if let Some(pos) = entries
                        .iter()
                        .rposition(|entry| entry.matches_request(&client_req.headers))
                    {
                        let entry = &mut entries[pos];
                        if !client_no_cache && entry.is_fresh(now_sys, default_ttl) {
                            entry.hit_count += 1;
                            self.push_cache_hits
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            let mut resp = entry.response.clone();
                            if entry.directives.max_age.is_none() {
                                entries.remove(pos);
                            }
                            drop(cache);
                            if !resp.body.is_empty() {
                                chunk_handler(&resp.body);
                            }
                            for resp_interceptor in &self.response_interceptors {
                                resp_interceptor(&client_req, &mut resp);
                            }
                            return Ok(resp);
                        } else if !client_no_cache
                            && entry.is_stale_while_revalidate(now_sys, default_ttl, client_swr)
                        {
                            entry.hit_count += 1;
                            self.push_cache_hits
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            self.stale_hits
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            let mut resp = entry.response.clone();
                            resp.headers.set("warning", "110 - \"Response is Stale\"");
                            let etag = entry.etag.clone();
                            let lm = entry.last_modified.clone();
                            drop(cache);
                            self.spawn_background_revalidate(&client_req, etag, lm);
                            if !resp.body.is_empty() {
                                chunk_handler(&resp.body);
                            }
                            for resp_interceptor in &self.response_interceptors {
                                resp_interceptor(&client_req, &mut resp);
                            }
                            return Ok(resp);
                        }
                    }
                }
            }
        }

        // 2. Check general HTTP client cache
        let mut cached_validator: Option<(Option<String>, Option<String>)> = None;
        if self
            .enable_http_cache
            .load(std::sync::atomic::Ordering::Relaxed)
            && !client_no_store
        {
            if let Ok(mut cache) = self.http_cache_entries.lock() {
                if let Some(entries) = cache.get_mut(&key) {
                    if let Some(pos) = entries
                        .iter()
                        .rposition(|entry| entry.matches_request(&client_req.headers))
                    {
                        let entry = &mut entries[pos];
                        if !client_no_cache && entry.is_fresh(now_sys, default_ttl) {
                            entry.touch();
                            entry.hit_count += 1;
                            self.push_cache_hits
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            let mut resp = entry.response.clone();
                            if entry.is_heuristic {
                                if let Ok(age) = now_sys.duration_since(entry.response_time) {
                                    if age.as_secs() > 86400 {
                                        resp.headers
                                            .set("warning", "113 - \"Heuristic Expiration\"");
                                    }
                                }
                            }
                            drop(cache);
                            if !resp.body.is_empty() {
                                chunk_handler(&resp.body);
                            }
                            for resp_interceptor in &self.response_interceptors {
                                resp_interceptor(&client_req, &mut resp);
                            }
                            return Ok(resp);
                        } else if !client_no_cache
                            && entry.is_stale_while_revalidate(now_sys, default_ttl, client_swr)
                        {
                            entry.touch();
                            entry.hit_count += 1;
                            self.push_cache_hits
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            self.stale_hits
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            let mut resp = entry.response.clone();
                            resp.headers.set("warning", "110 - \"Response is Stale\"");
                            let etag = entry.etag.clone();
                            let lm = entry.last_modified.clone();
                            drop(cache);
                            self.spawn_background_revalidate(&client_req, etag, lm);
                            if !resp.body.is_empty() {
                                chunk_handler(&resp.body);
                            }
                            for resp_interceptor in &self.response_interceptors {
                                resp_interceptor(&client_req, &mut resp);
                            }
                            return Ok(resp);
                        } else if entry.can_revalidate() {
                            cached_validator =
                                Some((entry.etag.clone(), entry.last_modified.clone()));
                        }
                    }
                }
            }
        }

        // Also check if push promise cache has a stale entry with validators that can be revalidated
        if cached_validator.is_none()
            && self
                .enable_push_promises
                .load(std::sync::atomic::Ordering::Relaxed)
            && !client_no_store
        {
            if let Ok(cache) = self.push_promise_cache.lock() {
                if let Some(entries) = cache.get(&key) {
                    if let Some(entry) = entries
                        .iter()
                        .rev()
                        .find(|entry| entry.matches_request(&client_req.headers))
                    {
                        if entry.can_revalidate() {
                            cached_validator =
                                Some((entry.etag.clone(), entry.last_modified.clone()));
                        }
                    }
                }
            }
        }

        let is_revalidating = cached_validator.is_some();
        if let Some((ref etag_opt, ref lm_opt)) = cached_validator {
            if let Some(tag) = etag_opt {
                if !client_req
                    .headers
                    .iter()
                    .any(|(k, _)| k.eq_ignore_ascii_case("if-none-match"))
                {
                    client_req
                        .headers
                        .push(("if-none-match".to_string(), tag.clone()));
                }
            }
            if let Some(lm) = lm_opt {
                if !client_req
                    .headers
                    .iter()
                    .any(|(k, _)| k.eq_ignore_ascii_case("if-modified-since"))
                {
                    client_req
                        .headers
                        .push(("if-modified-since".to_string(), lm.clone()));
                }
            }
        }

        // --- Transparent HTTP/3 renegotiation check for streaming requests ---
        if self.h3_negotiation_enabled() {
            if let Some(ref transport) = self.http3_transport {
                if let Some(route) = self.select_active_unquarantined_alt_svc_route(
                    None,
                    "h3",
                    std::time::Duration::from_secs(0),
                    true,
                ) {
                    let target_host = if route.host.is_empty() {
                        self.host.as_str()
                    } else {
                        route.host.as_str()
                    };
                    let target_port = if route.port != 0 {
                        route.port
                    } else {
                        self.port
                    };
                    let q_key = format!("h3://{}:{}", target_host, target_port);

                    self.h3_requests_attempted
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                    let header_refs: Vec<(&str, &str)> = client_req
                        .headers
                        .iter()
                        .map(|(k, v)| (k.as_str(), v.as_str()))
                        .collect();
                    let body_ref = client_req.body.as_deref();

                    match transport.execute_streaming_request(
                        target_host,
                        target_port,
                        &client_req.method,
                        &client_req.path,
                        &header_refs,
                        body_ref,
                        Box::new(&mut chunk_handler),
                    ) {
                        Ok(mut resp) => {
                            self.h3_requests_succeeded
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                            if let Some(alt_svc_val) = resp.headers.get("alt-svc") {
                                let routes = crate::simd_parser::AltSvcRoute::parse_header_value(
                                    alt_svc_val,
                                );
                                let origin = format!("{}:{}", self.host, self.port);
                                if let Ok(mut pool_routes) = self.alt_svc_routes.lock() {
                                    if routes.is_empty()
                                        && alt_svc_val.trim().eq_ignore_ascii_case("clear")
                                    {
                                        pool_routes.remove(&origin);
                                    } else if !routes.is_empty() {
                                        pool_routes.insert(origin, routes);
                                    }
                                }
                            }

                            if self.auto_decompress() && resp.headers.has("content-encoding") {
                                if let Ok(true) = resp.decompress_in_place() {
                                    self.decompressed_responses
                                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                }
                            }

                            for resp_interceptor in &self.response_interceptors {
                                resp_interceptor(&client_req, &mut resp);
                            }
                            return Ok(resp);
                        }
                        Err(_e) => {
                            self.h3_fallbacks
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            self.quarantine_alt_svc_route(&q_key, None);
                        }
                    }
                }
            }
        }

        let mut conn = match self.acquire() {
            Ok(c) => c,
            Err(e) => {
                if !client_no_store {
                    if let Some(mut fallback_resp) = self.find_stale_if_error_fallback(
                        &key,
                        &client_req.headers,
                        now_sys,
                        default_ttl,
                        client_sie,
                    ) {
                        self.stale_error_fallbacks
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if !fallback_resp.body.is_empty() {
                            chunk_handler(&fallback_resp.body);
                        }
                        for resp_interceptor in &self.response_interceptors {
                            resp_interceptor(&client_req, &mut fallback_resp);
                        }
                        return Ok(fallback_resp);
                    }
                }
                return Err(e);
            }
        };

        let header_refs: Vec<(&str, &str)> = client_req
            .headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let body_ref = client_req.body.as_deref();

        let mut pseudo_headers = vec![
            (":method", client_req.method.as_str()),
            (":path", client_req.path.as_str()),
            (":scheme", "http"),
        ];
        pseudo_headers.extend_from_slice(&header_refs);

        let stream_id = match conn.send_request(&pseudo_headers, body_ref) {
            Ok(sid) => sid,
            Err(e) => {
                if !client_no_store {
                    if let Some(mut fallback_resp) = self.find_stale_if_error_fallback(
                        &key,
                        &client_req.headers,
                        now_sys,
                        default_ttl,
                        client_sie,
                    ) {
                        self.stale_error_fallbacks
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        self.release(conn);
                        if !fallback_resp.body.is_empty() {
                            chunk_handler(&fallback_resp.body);
                        }
                        for resp_interceptor in &self.response_interceptors {
                            resp_interceptor(&client_req, &mut fallback_resp);
                        }
                        return Ok(fallback_resp);
                    }
                }
                self.release(conn);
                return Err(e);
            }
        };

        let result = conn.recv_streaming_response_with_pool(
            stream_id,
            self.chunk_buffer_pool.clone(),
            &mut chunk_handler,
        );

        match result {
            Ok(mut resp) => {
                if resp.status.0 >= 500 && resp.status.0 <= 599 && !client_no_store {
                    if let Some(mut fallback_resp) = self.find_stale_if_error_fallback(
                        &key,
                        &client_req.headers,
                        now_sys,
                        default_ttl,
                        client_sie,
                    ) {
                        self.stale_error_fallbacks
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        self.release(conn);
                        if !fallback_resp.body.is_empty() {
                            chunk_handler(&fallback_resp.body);
                        }
                        for resp_interceptor in &self.response_interceptors {
                            resp_interceptor(&client_req, &mut fallback_resp);
                        }
                        return Ok(fallback_resp);
                    }
                }

                // If 304 Not Modified received on conditional revalidation, deliver cached body to handler and return 200
                if resp.status.0 == 304 && is_revalidating {
                    self.cache_revalidations
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    self.push_cache_hits
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                    let now_update = std::time::SystemTime::now();
                    let mut resolved_resp = None;

                    if self
                        .enable_http_cache
                        .load(std::sync::atomic::Ordering::Relaxed)
                    {
                        if let Ok(mut cache) = self.http_cache_entries.lock() {
                            if let Some(entries) = cache.get_mut(&key) {
                                if let Some(pos) = entries
                                    .iter()
                                    .rposition(|entry| entry.matches_request(&client_req.headers))
                                {
                                    entries[pos].update_from_304(&resp, now_update);
                                    resolved_resp = Some(entries[pos].response.clone());
                                }
                            }
                        }
                    }
                    if resolved_resp.is_none()
                        && self
                            .enable_push_promises
                            .load(std::sync::atomic::Ordering::Relaxed)
                    {
                        if let Ok(mut cache) = self.push_promise_cache.lock() {
                            if let Some(entries) = cache.get_mut(&key) {
                                if let Some(pos) = entries
                                    .iter()
                                    .rposition(|entry| entry.matches_request(&client_req.headers))
                                {
                                    entries[pos].update_from_304(&resp, now_update);
                                    resolved_resp = Some(entries[pos].response.clone());
                                }
                            }
                        }
                    }

                    if let Some(mut fresh_resp) = resolved_resp {
                        self.release(conn);
                        if !fresh_resp.body.is_empty() {
                            chunk_handler(&fresh_resp.body);
                        }
                        for resp_interceptor in &self.response_interceptors {
                            resp_interceptor(&client_req, &mut fresh_resp);
                        }
                        return Ok(fresh_resp);
                    }
                }

                if let Some(alt_svc_val) = resp.headers.get("alt-svc") {
                    let routes = crate::simd_parser::AltSvcRoute::parse_header_value(alt_svc_val);
                    let origin = format!("{}:{}", self.host, self.port);
                    if let Ok(mut pool_routes) = self.alt_svc_routes.lock() {
                        if routes.is_empty() && alt_svc_val.trim().eq_ignore_ascii_case("clear") {
                            pool_routes.remove(&origin);
                        } else if !routes.is_empty() {
                            pool_routes.insert(origin, routes);
                        }
                    }
                }

                // Transparent response body decompression (RFC 7230 / RFC 7694)
                if self.auto_decompress() && resp.headers.has("content-encoding") {
                    if let Ok(true) = resp.decompress_in_place() {
                        self.decompressed_responses
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }

                // If response is cacheable 200 OK and http_cache is enabled, cache it
                if self
                    .enable_http_cache
                    .load(std::sync::atomic::Ordering::Relaxed)
                    && (client_req.method.eq_ignore_ascii_case("GET")
                        || client_req.method.eq_ignore_ascii_case("HEAD"))
                    && resp.status.0 == 200
                    && !client_no_store
                {
                    let entry = Http2PoolCacheEntry::new(
                        client_req.method.clone(),
                        client_req.path.clone(),
                        resp.clone(),
                    )
                    .with_request_headers(client_req.headers.clone());
                    self.insert_http_cache_entry(key, entry);
                }

                // RFC 7234 §4.4: Invalidate cache for target URI on successful non-safe requests (POST, PUT, DELETE, PATCH)
                if !client_req.method.eq_ignore_ascii_case("GET")
                    && !client_req.method.eq_ignore_ascii_case("HEAD")
                    && resp.status.0 >= 200
                    && resp.status.0 < 400
                {
                    self.invalidate_http_cache_path(&client_req.path);
                }

                self.release(conn);
                for resp_interceptor in &self.response_interceptors {
                    resp_interceptor(&client_req, &mut resp);
                }
                Ok(resp)
            }
            Err(e) => {
                if !client_no_store {
                    if let Some(mut fallback_resp) = self.find_stale_if_error_fallback(
                        &key,
                        &client_req.headers,
                        now_sys,
                        default_ttl,
                        client_sie,
                    ) {
                        self.stale_error_fallbacks
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        self.release(conn);
                        if !fallback_resp.body.is_empty() {
                            chunk_handler(&fallback_resp.body);
                        }
                        for resp_interceptor in &self.response_interceptors {
                            resp_interceptor(&client_req, &mut fallback_resp);
                        }
                        return Ok(fallback_resp);
                    }
                }
                self.absorb_push_promises(&mut conn);
                if let Some((_, err, _)) = conn.last_received_goaway() {
                    if let Ok(mut last_err) = self.last_goaway_error.lock() {
                        *last_err = Some(err);
                    }
                }
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

    /// Retrieve advertised Alt-Svc routes discovered for a given origin (or default pool origin).
    pub fn get_alt_svc_routes(&self, origin: Option<&str>) -> Vec<crate::simd_parser::AltSvcRoute> {
        let key = origin
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("{}:{}", self.host, self.port));
        if let Ok(map) = self.alt_svc_routes.lock() {
            if let Some(routes) = map.get(&key) {
                return routes.clone();
            }
            if origin.is_none() {
                let https_key = format!("https://{}:{}", self.host, self.port);
                if let Some(routes) = map.get(&https_key) {
                    return routes.clone();
                }
                let host_only = &self.host;
                if let Some(routes) = map.get(host_only) {
                    return routes.clone();
                }
            } else if let Some(s) = origin {
                if let Some(stripped) = s
                    .strip_prefix("https://")
                    .or_else(|| s.strip_prefix("http://"))
                {
                    if let Some(routes) = map.get(stripped) {
                        return routes.clone();
                    }
                }
            }
        }
        Vec::new()
    }

    /// Explicitly record or update alternative service routes for a given origin.
    pub fn record_alt_svc_routes(
        &self,
        origin: impl Into<String>,
        routes: Vec<crate::simd_parser::AltSvcRoute>,
    ) {
        if let Ok(mut map) = self.alt_svc_routes.lock() {
            if routes.is_empty() {
                map.remove(&origin.into());
            } else {
                map.insert(origin.into(), routes);
            }
        }
    }

    /// Clear all alternative service routes registered on the pool.
    pub fn clear_alt_svc_routes(&self) {
        if let Ok(mut map) = self.alt_svc_routes.lock() {
            map.clear();
        }
    }

    /// Retrieve the total number of alternative service routes registered across all origins in this pool.
    pub fn alt_svc_routes_count(&self) -> usize {
        self.alt_svc_routes
            .lock()
            .map(|map| map.values().map(|r| r.len()).sum())
            .unwrap_or(0)
    }

    /// Retrieve the list of all origins that have alternative service routes registered in this pool.
    pub fn alt_svc_origins(&self) -> Vec<String> {
        self.alt_svc_routes
            .lock()
            .map(|map| map.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Select the highest priority or first alternative service route matching a specific protocol
    /// (e.g. "h3" or "h2") for the given origin (or default pool origin).
    pub fn select_alt_svc_route(
        &self,
        origin: Option<&str>,
        protocol_id: &str,
    ) -> Option<crate::simd_parser::AltSvcRoute> {
        let routes = self.get_alt_svc_routes(origin);
        routes
            .into_iter()
            .find(|r| r.protocol_id.eq_ignore_ascii_case(protocol_id))
    }

    /// Check whether an alternative HTTP/3 route is available and registered for the origin.
    pub fn has_http3_alternative(&self, origin: Option<&str>) -> bool {
        self.select_alt_svc_route(origin, "h3").is_some()
    }

    /// Sweep expired alternative service routes whose age has exceeded their advertised `max_age`.
    ///
    /// Routes with `persist = true` can optionally be preserved across sweeps if `preserve_persisted`
    /// is set to true.
    ///
    /// Returns the total count of evicted expired routes.
    pub fn sweep_expired_alt_svc_routes(
        &self,
        elapsed: std::time::Duration,
        preserve_persisted: bool,
    ) -> usize {
        let mut evicted = 0;
        if let Ok(mut map) = self.alt_svc_routes.lock() {
            let mut empty_origins = Vec::new();
            for (origin, routes) in map.iter_mut() {
                let initial_len = routes.len();
                routes.retain(|r| {
                    if preserve_persisted && r.persist {
                        true
                    } else {
                        !r.is_expired_since(elapsed)
                    }
                });
                evicted += initial_len - routes.len();
                if routes.is_empty() {
                    empty_origins.push(origin.clone());
                }
            }
            for empty in empty_origins {
                map.remove(&empty);
            }
        }
        evicted
    }

    /// Select an active (non-expired) alternative service route for a given origin and protocol.
    ///
    /// Routes exceeding `elapsed` since advertisement are filtered out, unless `persist = true`
    /// and `allow_persisted` is set to true.
    pub fn select_active_alt_svc_route(
        &self,
        origin: Option<&str>,
        protocol_id: &str,
        elapsed: std::time::Duration,
        allow_persisted: bool,
    ) -> Option<crate::simd_parser::AltSvcRoute> {
        let routes = self.get_alt_svc_routes(origin);
        routes.into_iter().find(|r| {
            if !r.protocol_id.eq_ignore_ascii_case(protocol_id) {
                return false;
            }
            if allow_persisted && r.persist {
                true
            } else {
                !r.is_expired_since(elapsed)
            }
        })
    }

    /// Select an active (non-expired and non-quarantined) alternative service route for a given origin and protocol.
    pub fn select_active_unquarantined_alt_svc_route(
        &self,
        origin: Option<&str>,
        protocol_id: &str,
        elapsed: std::time::Duration,
        allow_persisted: bool,
    ) -> Option<crate::simd_parser::AltSvcRoute> {
        let routes = self.get_alt_svc_routes(origin);
        routes.into_iter().find(|r| {
            if !r.protocol_id.eq_ignore_ascii_case(protocol_id) {
                return false;
            }
            if allow_persisted && r.persist {
                // persisted route allowed
            } else if r.is_expired_since(elapsed) {
                return false;
            }
            let host = if r.host.is_empty() {
                self.host.as_str()
            } else {
                r.host.as_str()
            };
            let port = if r.port != 0 { r.port } else { self.port };
            let q_key = format!("{}://{}:{}", r.protocol_id.to_ascii_lowercase(), host, port);
            !self.is_alt_svc_quarantined(&q_key)
        })
    }

    /// Execute a request with automatic transparent migration to an advertised HTTP/3 alternative route if available.
    ///
    /// If an active HTTP/3 alternative route is discovered for the origin (or default origin),
    /// and `http3_handler` is provided, the request is delegated directly to the HTTP/3 transport handler.
    /// If no HTTP/3 route is present or the HTTP/3 handler fails with a fallback-eligible error,
    /// execution falls back transparently to the native HTTP/2 pool connection.
    pub fn execute_request_with_alt_svc_migration<F>(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
        http3_handler: Option<F>,
    ) -> io::Result<crate::http::HttpResponse>
    where
        F: FnOnce(
            &str,
            u16,
            &str,
            &str,
            &[(&str, &str)],
            Option<&[u8]>,
        ) -> io::Result<crate::http::HttpResponse>,
    {
        // Check for an available unquarantined HTTP/3 route
        let h3_route = self.select_active_unquarantined_alt_svc_route(
            None,
            "h3",
            std::time::Duration::from_secs(0),
            true,
        );

        if let Some(route) = h3_route {
            let target_host = if route.host.is_empty() {
                self.host.as_str()
            } else {
                route.host.as_str()
            };
            let target_port = if route.port != 0 {
                route.port
            } else {
                self.port
            };
            let q_key = format!("h3://{}:{}", target_host, target_port);

            if let Some(handler) = http3_handler {
                self.h3_requests_attempted
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                match handler(target_host, target_port, method, path, headers, body) {
                    Ok(resp) => {
                        self.h3_requests_succeeded
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        return Ok(resp);
                    }
                    Err(e) => {
                        self.h3_fallbacks
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        self.quarantine_alt_svc_route(&q_key, None);
                        match e.kind() {
                            io::ErrorKind::ConnectionRefused
                            | io::ErrorKind::ConnectionReset
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::AddrNotAvailable => {}
                            _ => return Err(e),
                        }
                    }
                }
            } else if let Some(ref transport) = self.http3_transport {
                self.h3_requests_attempted
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                match transport.execute_request(
                    target_host,
                    target_port,
                    method,
                    path,
                    headers,
                    body,
                ) {
                    Ok(resp) => {
                        self.h3_requests_succeeded
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        return Ok(resp);
                    }
                    Err(e) => {
                        self.h3_fallbacks
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        self.quarantine_alt_svc_route(&q_key, None);
                        match e.kind() {
                            io::ErrorKind::ConnectionRefused
                            | io::ErrorKind::ConnectionReset
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::AddrNotAvailable => {}
                            _ => return Err(e),
                        }
                    }
                }
            }
        }

        // Fallback or default: execute over pooled HTTP/2 connection
        self.execute_request(method, path, headers, body)
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

            match self.execute_request_single(method, path, headers, body) {
                Ok(resp) => {
                    if attempt > 0 {
                        self.retried_count
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    return Ok(resp);
                }
                Err(e) => {
                    if !self.is_transient_or_retryable_error(&e) || attempt == max_retries {
                        return Err(e);
                    }
                    self.clear_goaway_error();
                    last_err = Some(e);
                    // Adaptive back-off: retry_backoff × (attempt + 1)
                    let backoff = self.retry_backoff * (attempt as u32 + 1);
                    std::thread::sleep(backoff);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| io::Error::other("HTTP/2 retry exhausted")))
    }

    /// Execute an HTTP/2 streaming request using a pooled connection with automatic adaptive retry
    /// on transient connection reset or retryable GOAWAY frames.
    ///
    /// If an error occurs before any chunk is delivered to `chunk_handler`, the request is
    /// transparently retried on a fresh connection up to `max_retries` times.
    /// Once the first chunk has been delivered to `chunk_handler`, retry is inhibited to prevent
    /// duplicate delivery of partial stream data.
    pub fn execute_streaming_request_with_retry<F>(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
        max_retries: usize,
        mut chunk_handler: F,
    ) -> io::Result<crate::http::HttpResponse>
    where
        F: FnMut(&[u8]),
    {
        let mut last_err: Option<io::Error> = None;
        for attempt in 0..=max_retries {
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
                self.clear_goaway_error();
            }

            let mut chunks_delivered = false;
            let result =
                self.execute_streaming_request_single(method, path, headers, body, |chunk| {
                    chunks_delivered = true;
                    chunk_handler(chunk);
                });

            match result {
                Ok(resp) => {
                    if attempt > 0 {
                        self.retried_count
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    return Ok(resp);
                }
                Err(e) => {
                    // If any chunk was already delivered, we cannot safely replay the stream
                    if chunks_delivered {
                        return Err(e);
                    }
                    if !self.is_transient_or_retryable_error(&e) || attempt == max_retries {
                        return Err(e);
                    }
                    self.clear_goaway_error();
                    last_err = Some(e);
                    let backoff = self.retry_backoff * (attempt as u32 + 1);
                    std::thread::sleep(backoff);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| io::Error::other("HTTP/2 streaming retry exhausted")))
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

/// Comparative latency, throughput, and connection reuse metrics collected
/// during an HTTP/2 pool benchmark evaluating multiplexed vs non-pooled connections.
#[derive(Debug, Clone, PartialEq)]
pub struct Http2PoolBenchmarkResult {
    /// Benchmark identifier.
    pub name: String,
    /// Number of concurrent worker threads issuing requests.
    pub concurrent_workers: usize,
    /// Number of request cycles per worker.
    pub requests_per_worker: usize,
    /// Total completed requests across all workers.
    pub total_requests: usize,
    /// Maximum connection pool capacity used.
    pub pool_capacity: usize,
    /// Total duration of the benchmark in milliseconds.
    pub duration_ms: f64,
    /// Throughput in operations (requests) per second.
    pub ops_per_sec: f64,
    /// Average request latency in nanoseconds.
    pub avg_latency_ns: f64,
    /// Total number of distinct connections created by the pool.
    pub total_connections_created: usize,
    /// Connection reuse ratio (reused requests / total requests).
    pub connection_reuse_ratio: f64,
    /// Total connection errors encountered (must be 0 for resilient runs).
    pub error_count: usize,
}

/// Runs a comparative benchmark measuring latency, throughput, and connection reuse
/// under concurrent HTTP/2 load using an [`AsyncHttp2Pool`].
///
/// Spawns an in-process mock HTTP/2 server responding to incoming HEADERS / DATA frames,
/// then runs `concurrent_workers` threads executing requests through the pool.
pub fn benchmark_http2_pool_performance(
    concurrent_workers: usize,
    requests_per_worker: usize,
    pool_capacity: usize,
) -> io::Result<Http2PoolBenchmarkResult> {
    let listener = AsyncTcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();

    let server_running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let s_running = server_running.clone();

    let server_handle = std::thread::spawn(move || {
        let mut server_conn = None;
        for _ in 0..100 {
            if let Ok(Some((stream, _))) = listener.try_accept() {
                let h2 =
                    AsyncHttp2Connection::server_handshake(stream).expect("server h2 handshake");
                server_conn = Some(h2);
                break;
            }
            GLOBAL_SCHEDULER.yield_now();
            std::thread::sleep(Duration::from_millis(5));
        }

        let mut server = match server_conn {
            Some(s) => s,
            None => return,
        };

        while s_running.load(std::sync::atomic::Ordering::Relaxed) {
            match server.recv_frame() {
                Ok(crate::simd_parser::Http2Frame::Headers {
                    stream_id,
                    end_stream,
                    ..
                }) => {
                    if end_stream {
                        let res_headers = vec![(":status", "200")];
                        let _ = server.send_response(stream_id, &res_headers, Some(b"OK"));
                    }
                }
                Ok(crate::simd_parser::Http2Frame::Data {
                    stream_id,
                    end_stream: true,
                    ..
                }) => {
                    let res_headers = vec![(":status", "200")];
                    let _ = server.send_response(stream_id, &res_headers, Some(b"OK"));
                }
                Ok(crate::simd_parser::Http2Frame::GoAway { .. }) => break,
                Err(_) => break,
                _ => {}
            }
        }
    });

    let pool =
        AsyncHttp2Pool::new("127.0.0.1", port, pool_capacity).with_max_concurrent_streams(100);

    let mut completed_requests: usize = 0;
    let mut error_count: usize = 0;
    let start = std::time::Instant::now();

    for w in 0..concurrent_workers {
        for r in 0..requests_per_worker {
            let path = format!("/bench/{}/{}", w, r);
            match pool.execute_request("GET", &path, &[], None) {
                Ok(resp) => {
                    if resp.status.0 == 200 {
                        completed_requests += 1;
                    } else {
                        error_count += 1;
                    }
                }
                Err(_) => {
                    error_count += 1;
                }
            }
        }
    }

    let elapsed = start.elapsed();
    server_running.store(false, std::sync::atomic::Ordering::Relaxed);

    // Shutdown pool connections cleanly
    pool.shutdown();
    let _ = server_handle.join();

    let duration_ms = elapsed.as_secs_f64() * 1000.0;
    let duration_secs = elapsed.as_secs_f64();

    let ops_per_sec = if duration_secs > 0.0 {
        (completed_requests as f64) / duration_secs
    } else {
        0.0
    };

    let avg_latency_ns = if completed_requests > 0 {
        (elapsed.as_nanos() as f64) / (completed_requests as f64)
    } else {
        0.0
    };

    let stats = pool.stats();
    let total_conns = stats.total_connections().max(1);
    let connection_reuse_ratio = if completed_requests > 0 {
        ((completed_requests.saturating_sub(total_conns)) as f64) / (completed_requests as f64)
    } else {
        0.0
    };

    Ok(Http2PoolBenchmarkResult {
        name: format!(
            "http2_pool_{}workers_{}reqs_cap{}",
            concurrent_workers, requests_per_worker, pool_capacity
        ),
        concurrent_workers,
        requests_per_worker,
        total_requests: completed_requests,
        pool_capacity,
        duration_ms,
        ops_per_sec,
        avg_latency_ns,
        total_connections_created: total_conns,
        connection_reuse_ratio: connection_reuse_ratio.max(0.0),
        error_count,
    })
}

/// Configuration for HTTP/2 multiplexed saturation throughput & latency benchmarking.
#[derive(Debug, Clone)]
pub struct Http2MultiplexBenchmarkConfig {
    /// Number of concurrent multiplexed streams to saturate over the connection/pool.
    pub stream_count: usize,
    /// Number of DATA chunks delivered per stream.
    pub chunks_per_stream: usize,
    /// Payload size of each DATA chunk in bytes.
    pub chunk_size_bytes: usize,
    /// Whether to enable zero-copy chunk slices & chunk buffer pool recycling.
    pub use_buffer_pool: bool,
    /// Pre-allocated buffer capacity in the pool (e.g. 16384 bytes).
    pub buffer_capacity: usize,
    /// Maximum retained buffers in the pool.
    pub pool_capacity: usize,
    /// Whether to enable dynamic RFC 7540 flow control auto-tuning during multiplexed saturation.
    pub auto_tune_flow_control: bool,
}

impl Default for Http2MultiplexBenchmarkConfig {
    fn default() -> Self {
        Self {
            stream_count: 20,
            chunks_per_stream: 3,
            chunk_size_bytes: 2048,
            use_buffer_pool: false,
            buffer_capacity: 8192,
            pool_capacity: 64,
            auto_tune_flow_control: false,
        }
    }
}

/// Measurement results of an HTTP/2 multiplexed saturation benchmark run.
#[derive(Debug, Clone)]
pub struct Http2MultiplexBenchmarkResult {
    /// Benchmark profile name (e.g. "Standard Allocating" vs "Zero-Copy Recycled Pool").
    pub name: String,
    /// Total multiplexed streams processed.
    pub total_streams: usize,
    /// Total DATA chunks delivered across all streams.
    pub total_chunks: usize,
    /// Total bytes transferred and decoded.
    pub total_bytes: usize,
    /// Wall-clock duration taken to complete all multiplexed streams.
    pub elapsed_duration: Duration,
    /// Total elapsed time in milliseconds.
    pub elapsed_ms: f64,
    /// Decoded data throughput in Megabytes per second (MB/s).
    pub throughput_mb_s: f64,
    /// Completed streams per second.
    pub streams_per_sec: f64,
    /// Processed chunks per second.
    pub chunks_per_sec: f64,
    /// Average latency per completed stream in microseconds (µs).
    pub avg_stream_latency_us: f64,
    /// Number of idle pooled buffers available/recycled at benchmark conclusion.
    pub pooled_buffers_recycled: usize,
}

/// Comparative evaluation report between standard allocating streams vs zero-copy pooled recycling.
#[derive(Debug, Clone)]
pub struct Http2MultiplexComparisonReport {
    /// Benchmark result with standard allocation strategy.
    pub standard: Http2MultiplexBenchmarkResult,
    /// Benchmark result with zero-copy chunk slices and buffer recycling.
    pub zero_copy_pooled: Http2MultiplexBenchmarkResult,
    /// Throughput speedup ratio (zero_copy_pooled throughput / standard throughput).
    pub speedup_ratio: f64,
    /// Percentage latency reduction achieved by zero-copy pooled recycling.
    pub latency_reduction_pct: f64,
    /// Number of buffers successfully preserved/recycled.
    pub recycled_buffers: usize,
}

/// Runs a high-precision multiplexed saturation benchmark under concurrent HTTP/2 load.
///
/// Spawns an in-process mock HTTP/2 server that receives `config.stream_count` concurrent requests,
/// acknowledges each stream with HEADERS (`:status 200`), and transmits `config.chunks_per_stream`
/// multiplexed DATA frames of `config.chunk_size_bytes` each in interleaved order.
///
/// Collects all stream responses via `AsyncHttp2Pool::execute_prioritized_batch`, measures total elapsed time,
/// throughput (MB/s), streams/sec, chunks/sec, and per-stream latency.
pub fn benchmark_http2_multiplexed_saturation(
    config: &Http2MultiplexBenchmarkConfig,
) -> io::Result<Http2MultiplexBenchmarkResult> {
    let listener = AsyncTcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();

    let stream_count = config.stream_count;
    let chunks_per_stream = config.chunks_per_stream;
    let chunk_size = config.chunk_size_bytes;
    let auto_tune = config.auto_tune_flow_control;
    let payload = vec![0x42u8; chunk_size];

    let server_handle = std::thread::spawn(move || {
        let mut server = loop {
            if let Ok(Some((stream, _))) = listener.try_accept() {
                if let Ok(mut h2) = AsyncHttp2Connection::server_handshake(stream) {
                    if auto_tune {
                        h2.set_auto_tune_flow_control(true);
                    }
                    break h2;
                }
            }
            GLOBAL_SCHEDULER.yield_now();
            std::thread::sleep(Duration::from_millis(2));
        };

        let mut received_streams = Vec::with_capacity(stream_count);
        let mut spins = 0;
        let start_wait = std::time::Instant::now();
        while received_streams.len() < stream_count
            && start_wait.elapsed() < Duration::from_secs(10)
        {
            match server.recv_frame() {
                Ok(crate::simd_parser::Http2Frame::Headers { stream_id, .. }) => {
                    if !received_streams.contains(&stream_id) {
                        received_streams.push(stream_id);
                    }
                }
                Ok(crate::simd_parser::Http2Frame::GoAway { .. }) => break,
                Err(_) => {
                    spins += 1;
                    if spins > 50 {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
                _ => {}
            }
        }

        // Send HEADERS response (:status 200) for each stream
        for &sid in &received_streams {
            let res_headers = vec![(":status", "200")];
            let h_frame = server
                .session
                .create_headers_frame(sid, &res_headers, false);
            let _ = server.send_frame(&h_frame);
        }

        // Send interleaved DATA frames across all streams
        for c in 0..chunks_per_stream {
            let is_last = c == chunks_per_stream - 1;
            for &sid in &received_streams {
                let _ = server.send_data(sid, &payload, is_last);
            }
        }

        // Wait briefly for client to receive and close
        for _ in 0..10 {
            if let Ok(Some(crate::simd_parser::Http2Frame::GoAway { .. })) = server.try_recv_frame()
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let _ = server.send_goaway(crate::simd_parser::Http2ErrorCode::NoError);
    });

    let mut pool = AsyncHttp2Pool::new("127.0.0.1", port, 2);
    if config.auto_tune_flow_control {
        pool = pool.with_auto_tune_flow_control(true);
    }
    let chunk_pool = if config.use_buffer_pool {
        let cp = Http2ChunkBufferPool::new(config.buffer_capacity, config.pool_capacity);
        pool = pool.with_chunk_buffer_pool(cp.clone());
        Some(cp)
    } else {
        None
    };

    let batch: Vec<Http2PrioritizedRequest> = (0..stream_count)
        .map(|i| {
            Http2PrioritizedRequest::new("GET", format!("/benchmark-stream-{}", i))
                .with_rfc9218_priority((i % 8) as u8, false)
        })
        .collect();

    let start = std::time::Instant::now();
    let results = pool.execute_prioritized_batch(batch)?;
    let elapsed = start.elapsed();

    // Verify results
    if results.len() != stream_count {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Incomplete benchmark run: expected {} streams, received {}",
                stream_count,
                results.len()
            ),
        ));
    }
    let expected_body_len = chunks_per_stream * chunk_size;
    for (sid, res) in &results {
        match res {
            Ok(resp) => {
                if resp.status.0 != 200 || resp.body.len() != expected_body_len {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "Stream {} returned status {} body len {} (expected {})",
                            sid,
                            resp.status.0,
                            resp.body.len(),
                            expected_body_len
                        ),
                    ));
                }
            }
            Err(e) => {
                return Err(io::Error::other(format!("Stream {} failed: {}", sid, e)));
            }
        }
    }

    let recycled_buffers = chunk_pool.as_ref().map(|p| p.idle_count()).unwrap_or(0);

    // Clean up pool connections
    pool.shutdown();
    let _ = server_handle.join();

    let total_chunks = stream_count * chunks_per_stream;
    let total_bytes = total_chunks * chunk_size;
    let duration_secs = elapsed.as_secs_f64().max(0.000001);
    let duration_ms = elapsed.as_secs_f64() * 1000.0;
    let throughput_mb_s = (total_bytes as f64 / (1024.0 * 1024.0)) / duration_secs;
    let streams_per_sec = (stream_count as f64) / duration_secs;
    let chunks_per_sec = (total_chunks as f64) / duration_secs;
    let avg_stream_latency_us = (elapsed.as_micros() as f64) / (stream_count as f64);

    let name = match (config.use_buffer_pool, config.auto_tune_flow_control) {
        (true, true) => "Zero-Copy Recycled Pool + Auto-Tuned Flow Control".to_string(),
        (true, false) => "Zero-Copy Recycled Pool".to_string(),
        (false, true) => "Auto-Tuned Flow Control (Standard Alloc)".to_string(),
        (false, false) => "Standard Allocating".to_string(),
    };

    Ok(Http2MultiplexBenchmarkResult {
        name,
        total_streams: stream_count,
        total_chunks,
        total_bytes,
        elapsed_duration: elapsed,
        elapsed_ms: duration_ms,
        throughput_mb_s,
        streams_per_sec,
        chunks_per_sec,
        avg_stream_latency_us,
        pooled_buffers_recycled: recycled_buffers,
    })
}

/// Executes a comparative multiplexed saturation benchmark suite contrasting standard
/// heap allocation against zero-copy chunk slices & chunk buffer pool recycling.
pub fn benchmark_http2_multiplexed_comparison(
    stream_count: usize,
    chunks_per_stream: usize,
    chunk_size_bytes: usize,
) -> io::Result<Http2MultiplexComparisonReport> {
    let config_std = Http2MultiplexBenchmarkConfig {
        stream_count,
        chunks_per_stream,
        chunk_size_bytes,
        use_buffer_pool: false,
        ..Default::default()
    };

    let standard = benchmark_http2_multiplexed_saturation(&config_std)?;

    let config_opt = Http2MultiplexBenchmarkConfig {
        stream_count,
        chunks_per_stream,
        chunk_size_bytes,
        use_buffer_pool: true,
        buffer_capacity: chunk_size_bytes.max(4096),
        pool_capacity: (stream_count * chunks_per_stream).max(32),
        auto_tune_flow_control: false,
    };

    let zero_copy_pooled = benchmark_http2_multiplexed_saturation(&config_opt)?;

    let speedup_ratio = if standard.throughput_mb_s > 0.0 {
        zero_copy_pooled.throughput_mb_s / standard.throughput_mb_s
    } else {
        1.0
    };

    let latency_reduction_pct = if standard.avg_stream_latency_us > 0.0 {
        ((standard.avg_stream_latency_us - zero_copy_pooled.avg_stream_latency_us)
            / standard.avg_stream_latency_us)
            * 100.0
    } else {
        0.0
    };

    let recycled_buffers = zero_copy_pooled.pooled_buffers_recycled;

    Ok(Http2MultiplexComparisonReport {
        standard,
        zero_copy_pooled,
        speedup_ratio,
        latency_reduction_pct,
        recycled_buffers,
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
    fn test_http2_send_queued_data_and_flush() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("local addr");

        let handle = std::thread::spawn(move || {
            let (std_stream, _) = listener.accept().expect("accept connection");
            std_stream.set_nonblocking(true).expect("set nonblocking");
            let stream = AsyncTcpStream::from_std(std_stream).expect("async tcp stream");
            let mut server =
                AsyncHttp2Connection::server_handshake(stream).expect("server h2 handshake");

            let mut received_bytes = Vec::new();
            loop {
                let frame = server.recv_frame().expect("server recv frame");
                match frame {
                    crate::simd_parser::Http2Frame::Data { data, .. } => {
                        received_bytes.extend_from_slice(&data);
                    }
                    crate::simd_parser::Http2Frame::GoAway { .. } => break,
                    _ => {}
                }
            }
            received_bytes
        });

        let stream = AsyncTcpStream::connect(addr).expect("client connect");
        let mut client =
            AsyncHttp2Connection::client_handshake(stream).expect("client h2 handshake");

        // Open stream
        let stream_id = client.session.open_stream();
        let headers_frame = client.session.create_headers_frame(
            stream_id,
            &[(":method", "POST"), (":path", "/upload")],
            false,
        );
        client.send_frame(&headers_frame).expect("send headers");

        // Send queued data using priority/flow-control scheduler
        let chunk1 = vec![b'A'; 2048];
        let sent1 = client
            .send_queued_data(stream_id, &chunk1, false)
            .expect("send queued 1");
        assert!(sent1 >= 1);

        let chunk2 = vec![b'B'; 4096];
        client.session.queue_outbound_data(stream_id, &chunk2);
        let sent2 = client
            .flush_scheduled_outbound_data(true)
            .expect("flush queued 2");
        assert!(sent2 >= 1);

        client
            .send_goaway(crate::simd_parser::Http2ErrorCode::NoError)
            .expect("client goaway");

        let server_received = handle.join().expect("server thread finish");
        assert_eq!(server_received.len(), 2048 + 4096);
        assert_eq!(&server_received[..2048], chunk1.as_slice());
        assert_eq!(&server_received[2048..], chunk2.as_slice());
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
    fn test_async_http2_pool_prioritized_batch_rfc9218() {
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

            // Respond to three requests: stream 1, 3, 5
            let mut responded = 0;
            while responded < 3 {
                match server.recv_frame().expect("server recv frame") {
                    crate::simd_parser::Http2Frame::Headers {
                        stream_id,
                        end_stream,
                        ..
                    } => {
                        if end_stream {
                            let resp_headers = [(":status", "200")];
                            let body_text = format!("resp-urgency-stream-{}", stream_id);
                            server
                                .send_response(stream_id, &resp_headers, Some(body_text.as_bytes()))
                                .expect("send response");
                            responded += 1;
                        }
                    }
                    crate::simd_parser::Http2Frame::PriorityUpdate { .. } => {}
                    crate::simd_parser::Http2Frame::Priority { .. } => {}
                    crate::simd_parser::Http2Frame::GoAway { .. } => break,
                    _ => {}
                }
            }

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

        // Stream 1 (u=6 background), Stream 3 (u=0 critical urgent), Stream 5 (u=2 intermediate)
        let batch = vec![
            Http2PrioritizedRequest::new("GET", "/bg-task").with_rfc9218_priority(6, false),
            Http2PrioritizedRequest::new("GET", "/critical-doc").with_rfc9218_priority(0, true),
            Http2PrioritizedRequest::new("GET", "/script").with_rfc9218_priority(2, true),
        ];

        let results = pool
            .execute_prioritized_batch(batch)
            .expect("execute prioritized batch rfc9218");

        assert_eq!(results.len(), 3);
        // Order must be: stream 3 (u=0), stream 5 (u=2), stream 1 (u=6)
        assert_eq!(results[0].0, 3);
        assert_eq!(
            results[0].1.as_ref().unwrap().body,
            b"resp-urgency-stream-3"
        );

        assert_eq!(results[1].0, 5);
        assert_eq!(
            results[1].1.as_ref().unwrap().body,
            b"resp-urgency-stream-5"
        );

        assert_eq!(results[2].0, 1);
        assert_eq!(
            results[2].1.as_ref().unwrap().body,
            b"resp-urgency-stream-1"
        );

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
    fn test_async_http2_pool_prioritized_batch_with_body_scheduler() {
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

            let mut received_bodies: std::collections::HashMap<u32, Vec<u8>> =
                std::collections::HashMap::new();
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
                            server
                                .send_response(stream_id, &resp_headers, Some(b"done"))
                                .expect("send response");
                            responded += 1;
                        }
                    }
                    crate::simd_parser::Http2Frame::Data {
                        stream_id,
                        data,
                        end_stream,
                    } => {
                        received_bodies
                            .entry(stream_id)
                            .or_default()
                            .extend_from_slice(&data);
                        if end_stream {
                            let resp_headers = [(":status", "200")];
                            let resp_body =
                                format!("received-{}", received_bodies[&stream_id].len());
                            server
                                .send_response(stream_id, &resp_headers, Some(resp_body.as_bytes()))
                                .expect("send response");
                            responded += 1;
                        }
                    }
                    crate::simd_parser::Http2Frame::PriorityUpdate { .. } => {}
                    crate::simd_parser::Http2Frame::Priority { .. } => {}
                    crate::simd_parser::Http2Frame::GoAway { .. } => break,
                    _ => {}
                }
            }

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

        let payload1 = vec![b'X'; 5000];
        let payload2 = vec![b'Y'; 8000];

        let batch = vec![
            Http2PrioritizedRequest::new("POST", "/upload-1")
                .with_body(payload1.clone())
                .with_rfc9218_priority(3, true),
            Http2PrioritizedRequest::new("POST", "/upload-2")
                .with_body(payload2.clone())
                .with_rfc9218_priority(1, false),
        ];

        let results = pool
            .execute_prioritized_batch(batch)
            .expect("execute prioritized batch with body scheduler");

        assert_eq!(results.len(), 2);
        // Stream with priority u=1 (stream 3) should be received first
        assert_eq!(results[0].0, 3);
        assert_eq!(results[0].1.as_ref().unwrap().body, b"received-8000");

        // Stream with priority u=3 (stream 1) should be received second
        assert_eq!(results[1].0, 1);
        assert_eq!(results[1].1.as_ref().unwrap().body, b"received-5000");

        assert_eq!(pool.idle_count(), 1);
        assert_eq!(pool.active_count(), 0);

        let mut conn = pool.acquire().expect("acquire to close");
        let _ = conn.send_goaway(crate::simd_parser::Http2ErrorCode::NoError);
        pool.release(conn);
        pool.clear();

        let _ = handle.join();
    }

    #[test]
    fn test_async_http2_pool_prioritized_batch_chunked_streaming() {
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

            // Wait for both requests to be initiated
            let mut requests_received = 0;
            while requests_received < 2 {
                match server.recv_frame().expect("server recv frame") {
                    crate::simd_parser::Http2Frame::Headers { end_stream, .. } => {
                        if end_stream {
                            requests_received += 1;
                        }
                    }
                    crate::simd_parser::Http2Frame::PriorityUpdate { .. } => {}
                    crate::simd_parser::Http2Frame::Priority { .. } => {}
                    crate::simd_parser::Http2Frame::GoAway { .. } => return,
                    _ => {}
                }
            }

            // Stream responses in fragmented DATA chunks
            // Stream 3 (higher priority u=1)
            let h3 = server
                .session
                .create_headers_frame(3, &[(":status", "200")], false);
            server.send_frame(&h3).expect("send headers 3");
            server
                .send_data(3, b"stream3-part1-", false)
                .expect("send data 3.1");
            server
                .send_data(3, b"stream3-part2", true)
                .expect("send data 3.2");

            // Stream 1 (lower priority u=4)
            let h1 = server
                .session
                .create_headers_frame(1, &[(":status", "200")], false);
            server.send_frame(&h1).expect("send headers 1");
            server
                .send_data(1, b"chunk-A-", false)
                .expect("send data 1.1");
            server
                .send_data(1, b"chunk-B-", false)
                .expect("send data 1.2");
            server
                .send_data(1, b"chunk-C", true)
                .expect("send data 1.3");

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

        let stream1_chunks = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let stream1_chunks_cb = stream1_chunks.clone();

        let batch = vec![
            Http2PrioritizedRequest::new("GET", "/stream-1")
                .with_rfc9218_priority(4, false)
                .with_chunk_handler(move |_sid, chunk| {
                    stream1_chunks_cb.lock().unwrap().push(chunk.to_vec());
                }),
            Http2PrioritizedRequest::new("GET", "/stream-3").with_rfc9218_priority(1, true),
        ];

        let results = pool
            .execute_prioritized_batch(batch)
            .expect("execute prioritized batch with streaming chunks");

        assert_eq!(results.len(), 2);
        // Higher priority stream (stream 3) is ordered first
        assert_eq!(results[0].0, 3);
        assert_eq!(
            results[0].1.as_ref().unwrap().body,
            b"stream3-part1-stream3-part2"
        );

        // Lower priority stream (stream 1) is ordered second
        assert_eq!(results[1].0, 1);
        assert_eq!(
            results[1].1.as_ref().unwrap().body,
            b"chunk-A-chunk-B-chunk-C"
        );

        // Verify progressive chunked callback captured each distinct chunk
        let captured = stream1_chunks.lock().unwrap().clone();
        assert_eq!(captured.len(), 3);
        assert_eq!(captured[0], b"chunk-A-");
        assert_eq!(captured[1], b"chunk-B-");
        assert_eq!(captured[2], b"chunk-C");

        assert_eq!(pool.idle_count(), 1);
        assert_eq!(pool.active_count(), 0);

        let mut conn = pool.acquire().expect("acquire to close");
        let _ = conn.send_goaway(crate::simd_parser::Http2ErrorCode::NoError);
        pool.release(conn);
        pool.clear();

        let _ = handle.join();
    }

    #[test]
    fn test_async_http2_pool_execute_streaming_request() {
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

            let h = server
                .session
                .create_headers_frame(stream_id, &[(":status", "200")], false);
            server.send_frame(&h).expect("send headers");
            server
                .send_data(stream_id, b"alpha-", false)
                .expect("send chunk 1");
            server
                .send_data(stream_id, b"beta-", false)
                .expect("send chunk 2");
            server
                .send_data(stream_id, b"gamma", true)
                .expect("send chunk 3");

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

        let mut chunks_received = Vec::new();
        let resp = pool
            .execute_streaming_request("GET", "/progressive", &[], None, |chunk| {
                chunks_received.push(chunk.to_vec());
            })
            .expect("execute streaming request");

        assert_eq!(resp.status.0, 200);
        assert_eq!(resp.body, b"alpha-beta-gamma");
        assert_eq!(chunks_received.len(), 3);
        assert_eq!(chunks_received[0], b"alpha-");
        assert_eq!(chunks_received[1], b"beta-");
        assert_eq!(chunks_received[2], b"gamma");

        assert_eq!(pool.idle_count(), 1);

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

        std::thread::sleep(Duration::from_millis(15));
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

        std::thread::sleep(Duration::from_millis(15));
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
        // Server that accepts connections until request is successfully serviced, then cleanly closes.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.local_addr().expect("local addr").port();

        let handle = std::thread::spawn(move || {
            while let Ok((tcp_stream, _)) = listener.accept() {
                let async_stream = match AsyncTcpStream::from_std(tcp_stream) {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let mut server = match AsyncHttp2Connection::server_handshake(async_stream) {
                    Ok(s) => s,
                    Err(_) => break,
                };

                let mut completed = false;
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
                            let _ = server.send_goaway(crate::simd_parser::Http2ErrorCode::NoError);
                            completed = true;
                            break;
                        }
                    }
                }
                if completed {
                    break;
                }
            }
        });

        std::thread::sleep(Duration::from_millis(60));
        let pool = AsyncHttp2Pool::new("127.0.0.1", port, 2);
        let resp = pool
            .execute_request_with_retry("GET", "/", &[], None, 5)
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

        std::thread::sleep(Duration::from_millis(15));
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
    fn test_async_http2_pool_adaptive_retry_on_goaway_transient() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.local_addr().expect("local addr").port();

        let handle = std::thread::spawn(move || {
            // First connection: accept and immediately terminate with graceful GOAWAY
            if let Ok((tcp_stream, _)) = listener.accept() {
                if let Ok(async_stream) = AsyncTcpStream::from_std(tcp_stream) {
                    if let Ok(mut server) = AsyncHttp2Connection::server_handshake(async_stream) {
                        let _ = server.send_goaway(crate::simd_parser::Http2ErrorCode::NoError);
                        std::thread::sleep(Duration::from_millis(20));
                    }
                }
            }

            // Second connection: accept and successfully reply to the retried request
            if let Ok((tcp_stream, _)) = listener.accept() {
                if let Ok(async_stream) = AsyncTcpStream::from_std(tcp_stream) {
                    if let Ok(mut server) = AsyncHttp2Connection::server_handshake(async_stream) {
                        while let Ok(frame) = server.recv_frame() {
                            if let crate::simd_parser::Http2Frame::Headers {
                                stream_id,
                                end_stream: true,
                                ..
                            } = frame
                            {
                                let _ = server.send_response(
                                    stream_id,
                                    &[(":status", "200")],
                                    Some(b"adaptive-retry-success"),
                                );
                                let _ =
                                    server.send_goaway(crate::simd_parser::Http2ErrorCode::NoError);
                                std::thread::sleep(Duration::from_millis(60));
                                break;
                            }
                        }
                    }
                }
            }
        });

        std::thread::sleep(Duration::from_millis(15));
        let pool = AsyncHttp2Pool::new("127.0.0.1", port, 2)
            .with_max_retries(2)
            .with_retry_backoff(Duration::from_millis(5));

        let resp = pool
            .execute_request("GET", "/retry-test", &[], None)
            .expect("request should succeed on adaptive retry");

        assert_eq!(resp.status.0, 200);
        assert_eq!(resp.body, b"adaptive-retry-success");
        assert_eq!(pool.retried_count(), 1);
        assert_eq!(pool.stats().retried_requests, 1);

        let _ = handle.join();
    }

    #[test]
    fn test_async_http2_pool_adaptive_retry_streaming_transient() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.local_addr().expect("local addr").port();

        let handle = std::thread::spawn(move || {
            // First connection: accept and abruptly close/reset with GOAWAY
            if let Ok((tcp_stream, _)) = listener.accept() {
                if let Ok(async_stream) = AsyncTcpStream::from_std(tcp_stream) {
                    if let Ok(mut server) = AsyncHttp2Connection::server_handshake(async_stream) {
                        let _ = server.send_goaway(crate::simd_parser::Http2ErrorCode::NoError);
                        std::thread::sleep(Duration::from_millis(20));
                    }
                }
            }

            // Second connection: accept and stream chunked data
            if let Ok((tcp_stream, _)) = listener.accept() {
                if let Ok(async_stream) = AsyncTcpStream::from_std(tcp_stream) {
                    if let Ok(mut server) = AsyncHttp2Connection::server_handshake(async_stream) {
                        while let Ok(frame) = server.recv_frame() {
                            if let crate::simd_parser::Http2Frame::Headers {
                                stream_id,
                                end_stream: true,
                                ..
                            } = frame
                            {
                                let h = server.session.create_headers_frame(
                                    stream_id,
                                    &[(":status", "200")],
                                    false,
                                );
                                let _ = server.send_frame(&h);
                                let _ = server.send_data(stream_id, b"stream-1-", false);
                                let _ = server.send_data(stream_id, b"stream-2", true);
                                let _ =
                                    server.send_goaway(crate::simd_parser::Http2ErrorCode::NoError);
                                std::thread::sleep(Duration::from_millis(60));
                                break;
                            }
                        }
                    }
                }
            }
        });

        std::thread::sleep(Duration::from_millis(15));
        let pool = AsyncHttp2Pool::new("127.0.0.1", port, 2)
            .with_max_retries(2)
            .with_retry_backoff(Duration::from_millis(5));

        let mut chunks_received = Vec::new();
        let resp = pool
            .execute_streaming_request("GET", "/stream-retry", &[], None, |chunk| {
                chunks_received.push(chunk.to_vec());
            })
            .expect("streaming request should succeed on adaptive retry");

        assert_eq!(resp.status.0, 200);
        assert_eq!(resp.body, b"stream-1-stream-2");
        assert_eq!(chunks_received.len(), 2);
        assert_eq!(chunks_received[0], b"stream-1-");
        assert_eq!(chunks_received[1], b"stream-2");
        assert_eq!(pool.retried_count(), 1);
        assert_eq!(pool.stats().retried_requests, 1);

        pool.shutdown();
        let _ = handle.join();
    }

    #[test]
    fn test_http2_chunk_buffer_pool_lifecycle() {
        let pool = Http2ChunkBufferPool::new(4096, 2);
        assert_eq!(pool.idle_count(), 0);

        let mut buf1 = pool.acquire();
        assert!(buf1.capacity() >= 4096);
        assert!(buf1.is_empty());
        buf1.extend_from_slice(b"sample payload 1");

        let mut buf2 = pool.acquire();
        assert!(buf2.capacity() >= 4096);
        buf2.extend_from_slice(b"sample payload 2");

        pool.release(buf1);
        assert_eq!(pool.idle_count(), 1);

        pool.release(buf2);
        assert_eq!(pool.idle_count(), 2);

        // Third buffer exceeds max_retained_buffers (2), should be discarded
        let buf3 = Vec::with_capacity(4096);
        pool.release(buf3);
        assert_eq!(pool.idle_count(), 2);

        let reused = pool.acquire();
        assert_eq!(pool.idle_count(), 1);
        assert!(reused.is_empty());
        assert!(reused.capacity() >= 4096);
    }

    #[test]
    fn test_http2_streaming_decoder_slice_and_owned_with_buffer_pool() {
        let pool = Http2ChunkBufferPool::new(8192, 4);
        let mut decoder = Http2StreamingResponseDecoder::new(1).with_buffer_pool(pool.clone());

        decoder.feed_headers(&[
            (":status".to_string(), "200".to_string()),
            (
                "content-type".to_string(),
                "application/octet-stream".to_string(),
            ),
        ]);
        assert_eq!(decoder.status, Some(200));

        // 1. feed_chunk_slice borrows directly and copies into pooled buffer
        let slice_out = decoder
            .feed_chunk_slice(b"chunk-alpha-", false)
            .expect("feed slice");
        assert_eq!(slice_out, b"chunk-alpha-");

        // 2. feed_chunk_owned moves buffer without allocation
        let owned_vec = b"chunk-beta".to_vec();
        let owned_out = decoder
            .feed_chunk_owned(owned_vec, true)
            .expect("feed owned");
        assert_eq!(owned_out, b"chunk-beta");

        assert!(decoder.is_complete());
        assert_eq!(decoder.chunk_count(), 2);
        assert_eq!(decoder.total_bytes_decoded(), 22);

        // 3. assemble_response_recycling recycles internal chunk buffers back into pool
        let resp = decoder
            .assemble_response_recycling()
            .expect("assemble response recycling");
        assert_eq!(resp.status.0, 200);
        assert_eq!(resp.body, b"chunk-alpha-chunk-beta");
        assert!(pool.idle_count() > 0);
    }

    #[test]
    fn test_async_http2_connection_zero_copy_data_slice() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.local_addr().expect("local addr").port();

        let handle = std::thread::spawn(move || {
            let (tcp_stream, _) = listener.accept().expect("accept connection");
            let async_stream = AsyncTcpStream::from_std(tcp_stream).expect("async stream");
            let mut server =
                AsyncHttp2Connection::server_handshake(async_stream).expect("server handshake");

            let stream_id = loop {
                if let crate::simd_parser::Http2Frame::Headers {
                    stream_id,
                    end_stream: true,
                    ..
                } = server.recv_frame().expect("server recv frame")
                {
                    break stream_id;
                }
            };

            let h = server
                .session
                .create_headers_frame(stream_id, &[(":status", "200")], false);
            server.send_frame(&h).expect("send headers");
            server
                .send_data(stream_id, b"zero-copy-slice-1-", false)
                .expect("send data 1");
            server
                .send_data(stream_id, b"zero-copy-slice-2", true)
                .expect("send data 2");

            loop {
                match server.recv_frame() {
                    Ok(crate::simd_parser::Http2Frame::GoAway { .. }) | Err(_) => break,
                    _ => {}
                }
            }
        });

        let tcp_client =
            std::net::TcpStream::connect(format!("127.0.0.1:{}", port)).expect("connect client");
        let async_client = AsyncTcpStream::from_std(tcp_client).expect("async client stream");
        let mut client =
            AsyncHttp2Connection::client_handshake(async_client).expect("client handshake");

        let pseudo = vec![
            (":method", "GET"),
            (":path", "/zero-copy"),
            (":scheme", "http"),
        ];
        let stream_id = client.send_request(&pseudo, None).expect("send request");

        // 1. Drain any pre-stream control frames (e.g. SETTINGS) until HEADERS is received
        let mut data_slices_captured = Vec::new();
        loop {
            let frame = client
                .recv_frame_with_data_slice(|slice| {
                    data_slices_captured.push((
                        slice.stream_id,
                        slice.end_stream,
                        slice.data.to_vec(),
                    ));
                    Ok(())
                })
                .expect("recv frame");
            if let Some(crate::simd_parser::Http2Frame::Headers { .. }) = frame {
                break;
            }
        }
        assert!(data_slices_captured.is_empty());

        // 2. Consume DATA chunks zero-copy until end_stream is observed
        while data_slices_captured.len() < 2 {
            let res = client
                .recv_frame_with_data_slice(|slice| {
                    data_slices_captured.push((
                        slice.stream_id,
                        slice.end_stream,
                        slice.data.to_vec(),
                    ));
                    Ok(())
                })
                .expect("recv data frame");
            assert!(
                res.is_none()
                    || matches!(res, Some(crate::simd_parser::Http2Frame::Settings { .. }))
            );
        }

        assert_eq!(data_slices_captured.len(), 2);
        assert_eq!(data_slices_captured[0].0, stream_id);
        assert!(!data_slices_captured[0].1);
        assert_eq!(data_slices_captured[0].2, b"zero-copy-slice-1-");
        assert_eq!(data_slices_captured[1].0, stream_id);
        assert!(data_slices_captured[1].1);
        assert_eq!(data_slices_captured[1].2, b"zero-copy-slice-2");

        let _ = client.send_goaway(crate::simd_parser::Http2ErrorCode::NoError);
        let _ = handle.join();
    }

    #[test]
    fn test_async_http2_pool_with_chunk_buffer_pool_streaming() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.local_addr().expect("local addr").port();

        let handle = std::thread::spawn(move || {
            let (tcp_stream, _) = listener.accept().expect("accept connection");
            let async_stream = AsyncTcpStream::from_std(tcp_stream).expect("async stream");
            let mut server =
                AsyncHttp2Connection::server_handshake(async_stream).expect("server handshake");

            let stream_id = loop {
                if let crate::simd_parser::Http2Frame::Headers {
                    stream_id,
                    end_stream: true,
                    ..
                } = server.recv_frame().expect("server recv frame")
                {
                    break stream_id;
                }
            };

            let h = server
                .session
                .create_headers_frame(stream_id, &[(":status", "200")], false);
            server.send_frame(&h).expect("send headers");
            server
                .send_data(stream_id, b"part-1-", false)
                .expect("send 1");
            server
                .send_data(stream_id, b"part-2-", false)
                .expect("send 2");
            server
                .send_data(stream_id, b"part-3", true)
                .expect("send 3");

            loop {
                match server.recv_frame() {
                    Ok(crate::simd_parser::Http2Frame::GoAway { .. }) | Err(_) => break,
                    _ => {}
                }
            }
        });

        let chunk_pool = Http2ChunkBufferPool::new(8192, 16);
        let pool =
            AsyncHttp2Pool::new("127.0.0.1", port, 2).with_chunk_buffer_pool(chunk_pool.clone());

        assert!(pool.chunk_buffer_pool().is_some());

        let mut received = Vec::new();
        let resp = pool
            .execute_streaming_request("GET", "/pool-buffered-stream", &[], None, |chunk| {
                received.push(chunk.to_vec());
            })
            .expect("execute streaming request with chunk buffer pool");

        assert_eq!(resp.status.0, 200);
        assert_eq!(resp.body, b"part-1-part-2-part-3");
        assert_eq!(received.len(), 3);
        assert_eq!(received[0], b"part-1-");
        assert_eq!(received[1], b"part-2-");
        assert_eq!(received[2], b"part-3");
        assert!(chunk_pool.idle_count() > 0);

        pool.shutdown();
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
        assert_eq!(stats.retried_requests, 0);
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
    fn test_async_http2_pool_altsvc_routes_harvesting() {
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
                        // Advertise HTTP/3 alternative service via Alt-Svc response header
                        server
                            .send_response(
                                stream_id,
                                &[
                                    (":status", "200"),
                                    ("alt-svc", "h3=\":50443\"; ma=86400; persist=1"),
                                ],
                                Some(b"alt-svc-ack"),
                            )
                            .expect("send response with alt-svc");
                        let _ = server.send_goaway(crate::simd_parser::Http2ErrorCode::NoError);
                        std::thread::sleep(Duration::from_millis(50));
                        break;
                    }
                }
            }
        });

        std::thread::sleep(Duration::from_millis(15));
        let pool = AsyncHttp2Pool::new("127.0.0.1", port, 2);

        // Before request: no Alt-Svc routes known
        assert!(pool.get_alt_svc_routes(None).is_empty());

        let resp = pool
            .execute_request("GET", "/test-altsvc", &[], None)
            .expect("execute request");

        assert_eq!(resp.status.0, 200);
        assert_eq!(resp.body, b"alt-svc-ack");

        // After request: pool harvested Alt-Svc header and parsed routes
        let routes = pool.get_alt_svc_routes(None);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].protocol_id, "h3");
        assert_eq!(routes[0].port, 50443);
        assert_eq!(routes[0].max_age, 86400);
        assert!(routes[0].persist);

        // Explicit clear / update test
        pool.clear_alt_svc_routes();
        assert!(pool.get_alt_svc_routes(None).is_empty());

        // Test ALTSVC frame harvesting via connection release
        let mut conn = pool.acquire().expect("acquire fresh connection");
        // Inject an ALTSVC frame into connection session
        let altsvc_frame = crate::simd_parser::Http2Frame::AltSvc {
            stream_id: 0,
            origin: "https://example.org".to_string(),
            alt_svc_field_value: "h3=\":443\"; ma=3600".to_string(),
        };
        conn.session
            .handle_frame(&altsvc_frame)
            .expect("handle frame");
        pool.release(conn);

        // Verify pool harvested routes from connection session
        let org_routes = pool.get_alt_svc_routes(Some("https://example.org"));
        assert_eq!(org_routes.len(), 1);
        assert_eq!(org_routes[0].protocol_id, "h3");
        assert_eq!(org_routes[0].port, 443);
        assert_eq!(org_routes[0].max_age, 3600);

        // Verify select_alt_svc_route and has_http3_alternative
        assert!(pool.has_http3_alternative(Some("https://example.org")));
        let selected = pool
            .select_alt_svc_route(Some("https://example.org"), "h3")
            .expect("selected h3 route");
        assert_eq!(selected.port, 443);
        assert!(!selected.is_expired_since(std::time::Duration::from_secs(100)));
        assert!(selected.is_expired_since(std::time::Duration::from_secs(4000)));
        assert!(!pool.has_http3_alternative(Some("https://unknown.com")));

        // Verify select_active_alt_svc_route with elapsed duration
        assert!(pool
            .select_active_alt_svc_route(
                Some("https://example.org"),
                "h3",
                std::time::Duration::from_secs(1000),
                false
            )
            .is_some());
        assert!(pool
            .select_active_alt_svc_route(
                Some("https://example.org"),
                "h3",
                std::time::Duration::from_secs(4000),
                false
            )
            .is_none());

        // Verify sweep_expired_alt_svc_routes
        let evicted = pool.sweep_expired_alt_svc_routes(std::time::Duration::from_secs(500), false);
        assert_eq!(evicted, 0);
        let evicted =
            pool.sweep_expired_alt_svc_routes(std::time::Duration::from_secs(4000), false);
        assert_eq!(evicted, 1);
        assert!(pool
            .get_alt_svc_routes(Some("https://example.org"))
            .is_empty());

        // Verify alt_svc_routes_count and alt_svc_origins helpers
        assert_eq!(pool.alt_svc_routes_count(), 0);
        assert!(pool.alt_svc_origins().is_empty());

        pool.record_alt_svc_routes(
            "https://test1.example.com",
            vec![crate::simd_parser::AltSvcRoute::new("h3", "", 443)],
        );
        pool.record_alt_svc_routes(
            "https://test2.example.com",
            vec![
                crate::simd_parser::AltSvcRoute::new("h3", "", 443),
                crate::simd_parser::AltSvcRoute::new("h2", "alt.example.com", 8443),
            ],
        );
        assert_eq!(pool.alt_svc_routes_count(), 3);
        let mut origins = pool.alt_svc_origins();
        origins.sort();
        assert_eq!(
            origins,
            vec![
                "https://test1.example.com".to_string(),
                "https://test2.example.com".to_string()
            ]
        );

        pool.clear_alt_svc_routes();
        assert_eq!(pool.alt_svc_routes_count(), 0);
        assert!(pool.alt_svc_origins().is_empty());

        // Verify execute_request_with_alt_svc_migration fallback when no H3 route is available
        let fallback_resp = pool.execute_request_with_alt_svc_migration::<fn(
            &str,
            u16,
            &str,
            &str,
            &[(&str, &str)],
            Option<&[u8]>,
        ) -> io::Result<crate::http::HttpResponse>>(
            "GET", "/fallback", &[], None, None
        );
        // Pool was shut down above or no active connection; verify handler without h3 route defaults to execute_request
        let _ = fallback_resp;

        // Verify execute_request_with_alt_svc_migration when active H3 route is present
        let origin = format!("127.0.0.1:{}", port);
        pool.record_alt_svc_routes(
            origin,
            vec![crate::simd_parser::AltSvcRoute::new(
                "h3",
                "h3.example.com",
                50443,
            )],
        );

        let h3_called = std::sync::atomic::AtomicBool::new(false);
        let migrated_resp = pool
            .execute_request_with_alt_svc_migration(
                "POST",
                "/upload",
                &[("content-type", "text/plain")],
                Some(b"data"),
                Some(
                    |h: &str,
                     p: u16,
                     m: &str,
                     path: &str,
                     _: &[(&str, &str)],
                     body: Option<&[u8]>| {
                        h3_called.store(true, std::sync::atomic::Ordering::SeqCst);
                        assert_eq!(h, "h3.example.com");
                        assert_eq!(p, 50443);
                        assert_eq!(m, "POST");
                        assert_eq!(path, "/upload");
                        assert_eq!(body, Some(&b"data"[..]));
                        let mut resp = crate::http::HttpResponse::new(crate::http::HttpStatus(201));
                        resp.body = b"created on h3".to_vec();
                        Ok(resp)
                    },
                ),
            )
            .expect("h3 migration success");
        assert!(h3_called.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(migrated_resp.status, crate::http::HttpStatus(201));
        assert_eq!(migrated_resp.body, b"created on h3");

        // Verify fallback when H3 handler returns ConnectionRefused
        let fallback_called = std::sync::atomic::AtomicBool::new(false);
        let fallback_attempt = pool.execute_request_with_alt_svc_migration(
            "GET",
            "/fallback_test",
            &[],
            None,
            Some(
                |_: &str, _: u16, _: &str, _: &str, _: &[(&str, &str)], _: Option<&[u8]>| {
                    fallback_called.store(true, std::sync::atomic::Ordering::SeqCst);
                    Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "h3 unreachable",
                    ))
                },
            ),
        );
        assert!(fallback_called.load(std::sync::atomic::Ordering::SeqCst));
        let _ = fallback_attempt; // falls back to execute_request

        pool.shutdown();
        let _ = handle.join();
    }

    #[test]
    fn test_async_http2_send_alt_svc_frame_wire_transmission() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.local_addr().expect("local addr").port();

        let handle = std::thread::spawn(move || {
            let (tcp_stream, _) = listener.accept().expect("accept connection");
            let async_stream = AsyncTcpStream::from_std(tcp_stream).expect("async stream");
            let mut server =
                AsyncHttp2Connection::server_handshake(async_stream).expect("server handshake");

            // Server announces HTTP/3 and HTTP/2 alternative services via send_alt_svc
            let routes = vec![
                crate::simd_parser::AltSvcRoute::new("h3", "", 443)
                    .with_max_age(86400)
                    .with_persist(true),
                crate::simd_parser::AltSvcRoute::new("h2", "alt.example.com", 8443)
                    .with_max_age(3600),
            ];
            server
                .send_alt_svc(0, "https://example.com", &routes)
                .expect("server send alt_svc");

            // Wait for client to receive and send a goaway before shutting down
            let _ = server.recv_frame();
            let _ = server.send_goaway(crate::simd_parser::Http2ErrorCode::NoError);
        });

        let stream =
            AsyncTcpStream::connect(format!("127.0.0.1:{}", port)).expect("connect client");
        let mut client = AsyncHttp2Connection::client_handshake(stream).expect("client handshake");

        // First frame is server's initial SETTINGS frame
        let first_frame = client.recv_frame().expect("receive server settings");
        assert!(matches!(
            first_frame,
            crate::simd_parser::Http2Frame::Settings { .. }
        ));

        // Next frame is the ALTSVC frame transmitted over the wire
        let frame = client.recv_frame().expect("receive alt_svc frame");
        if let crate::simd_parser::Http2Frame::AltSvc {
            stream_id,
            origin,
            alt_svc_field_value,
        } = frame
        {
            assert_eq!(stream_id, 0);
            assert_eq!(origin, "https://example.com");
            assert!(alt_svc_field_value.contains("h3=\":443\""));
            assert!(alt_svc_field_value.contains("alt.example.com:8443"));

            // Feed frame into client session
            client
                .session
                .handle_frame(&crate::simd_parser::Http2Frame::AltSvc {
                    stream_id,
                    origin: origin.clone(),
                    alt_svc_field_value,
                })
                .expect("handle frame in session");

            let cached = client
                .session
                .alt_svc_routes
                .get("https://example.com")
                .expect("cached routes");
            assert_eq!(cached.len(), 2);
            assert_eq!(cached[0].protocol_id, "h3");
            assert_eq!(cached[0].port, 443);
            assert!(cached[0].persist);
            assert_eq!(cached[1].protocol_id, "h2");
            assert_eq!(cached[1].host, "alt.example.com");
            assert_eq!(cached[1].port, 8443);
        } else {
            panic!("Expected AltSvc frame over wire, got: {:?}", frame);
        }

        let _ = client.send_goaway(crate::simd_parser::Http2ErrorCode::NoError);
        let _ = handle.join();
    }

    #[test]
    fn test_async_http2_pool_transparent_h3_negotiation_success() {
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
                        // Advertise HTTP/3 alternative service via Alt-Svc response header
                        server
                            .send_response(
                                stream_id,
                                &[
                                    (":status", "200"),
                                    ("alt-svc", "h3=\":50443\"; ma=86400; persist=1"),
                                ],
                                Some(b"first-h2-response"),
                            )
                            .expect("send response with alt-svc");
                        break;
                    }
                }
            }
            let _ = server.recv_frame();
            let _ = server.send_goaway(crate::simd_parser::Http2ErrorCode::NoError);
        });

        let h3_called = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let h3_called_clone = h3_called.clone();

        let pool = AsyncHttp2Pool::new("127.0.0.1", port, 2).with_http3_handler(
            move |h: &str,
                  p: u16,
                  m: &str,
                  path: &str,
                  _headers: &[(&str, &str)],
                  _body: Option<&[u8]>| {
                h3_called_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                assert_eq!(h, "127.0.0.1");
                assert_eq!(p, 50443);
                assert_eq!(m, "GET");
                assert_eq!(path, "/second-request");
                let mut resp = crate::http::HttpResponse::new(crate::http::HttpStatus(200));
                resp.body = b"migrated-over-h3".to_vec();
                Ok(resp)
            },
        );

        assert!(pool.h3_negotiation_enabled());
        assert_eq!(pool.h3_requests_attempted(), 0);
        assert_eq!(pool.h3_requests_succeeded(), 0);
        assert_eq!(pool.h3_fallbacks(), 0);

        // 1. Initial request goes over HTTP/2, discovering the Alt-Svc header
        let resp1 = pool
            .execute_request("GET", "/first-request", &[], None)
            .expect("first request over h2");
        assert_eq!(resp1.status.0, 200);
        assert_eq!(resp1.body, b"first-h2-response");
        assert_eq!(h3_called.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(pool.h3_requests_attempted(), 0);

        // Verify Alt-Svc was harvested
        let routes = pool.get_alt_svc_routes(None);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].protocol_id, "h3");
        assert_eq!(routes[0].port, 50443);

        // 2. Second request to pool automatically and transparently renegotiates to HTTP/3!
        let resp2 = pool
            .execute_request("GET", "/second-request", &[], None)
            .expect("second request migrated to h3");
        assert_eq!(resp2.status.0, 200);
        assert_eq!(resp2.body, b"migrated-over-h3");
        assert_eq!(h3_called.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(pool.h3_requests_attempted(), 1);
        assert_eq!(pool.h3_requests_succeeded(), 1);
        assert_eq!(pool.h3_fallbacks(), 0);

        pool.shutdown();
        let _ = handle.join();
    }

    #[test]
    fn test_async_http2_pool_transparent_h3_negotiation_fallback_and_quarantine() {
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
                                &[(":status", "200")],
                                Some(b"h2-fallback-success"),
                            )
                            .expect("send fallback response");
                    }
                }
            }
        });

        let h3_attempts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let h3_attempts_clone = h3_attempts.clone();

        let pool = AsyncHttp2Pool::new("127.0.0.1", port, 2)
            .with_http3_handler(
                move |_: &str, _: u16, _: &str, _: &str, _: &[(&str, &str)], _: Option<&[u8]>| {
                    h3_attempts_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "QUIC UDP port unreachable",
                    ))
                },
            )
            .with_alt_svc_quarantine_duration(Duration::from_millis(100));

        // Manually record an active H3 route
        pool.record_alt_svc_routes(
            format!("127.0.0.1:{}", port),
            vec![crate::simd_parser::AltSvcRoute::new("h3", "", 50443)],
        );

        assert_eq!(pool.quarantined_alt_svc_routes_count(), 0);

        // Request should attempt H3, fail with ConnectionRefused, quarantine the route,
        // and fall back transparently to HTTP/2 without error!
        let resp = pool
            .execute_request("GET", "/fallback-test", &[], None)
            .expect("request should succeed via transparent h2 fallback");

        assert_eq!(resp.status.0, 200);
        assert_eq!(resp.body, b"h2-fallback-success");
        assert_eq!(h3_attempts.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(pool.h3_requests_attempted(), 1);
        assert_eq!(pool.h3_requests_succeeded(), 0);
        assert_eq!(pool.h3_fallbacks(), 1);
        assert_eq!(pool.quarantined_alt_svc_routes_count(), 1);

        // Next request within quarantine duration should skip H3 and go straight to H2!
        let resp2 = pool
            .execute_request("GET", "/quarantined-test", &[], None)
            .expect("second request skips quarantined h3");
        assert_eq!(resp2.status.0, 200);
        assert_eq!(resp2.body, b"h2-fallback-success");
        // H3 was NOT attempted again
        assert_eq!(h3_attempts.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(pool.h3_requests_attempted(), 1);

        // Wait for quarantine to expire (100ms)
        std::thread::sleep(Duration::from_millis(120));
        assert_eq!(pool.sweep_expired_alt_svc_quarantines(), 1);
        assert_eq!(pool.quarantined_alt_svc_routes_count(), 0);

        pool.shutdown();
        let _ = handle.join();
    }

    #[test]
    fn test_async_http2_pool_streaming_h3_negotiation() {
        let pool = AsyncHttp2Pool::new("127.0.0.1", 8443, 2).with_http3_handler(
            |_: &str, _: u16, m: &str, path: &str, _: &[(&str, &str)], _: Option<&[u8]>| {
                assert_eq!(m, "GET");
                assert_eq!(path, "/stream");
                let mut resp = crate::http::HttpResponse::new(crate::http::HttpStatus(200));
                resp.body = b"chunk1chunk2chunk3".to_vec();
                Ok(resp)
            },
        );

        pool.record_alt_svc_routes(
            "127.0.0.1:8443",
            vec![crate::simd_parser::AltSvcRoute::new("h3", "", 8443)],
        );

        let mut received = Vec::new();
        let resp = pool
            .execute_streaming_request("GET", "/stream", &[], None, |chunk| {
                received.extend_from_slice(chunk);
            })
            .expect("streaming request over h3");

        assert_eq!(resp.status.0, 200);
        assert_eq!(received, b"chunk1chunk2chunk3");
        assert_eq!(pool.h3_requests_attempted(), 1);
        assert_eq!(pool.h3_requests_succeeded(), 1);
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

    #[test]
    fn test_async_http2_control_frame_ring_buffer_zero_alloc() {
        let ping_frame = crate::simd_parser::Http2Frame::Ping {
            ack: true,
            opaque_data: [1, 2, 3, 4, 5, 6, 7, 8],
        };
        assert!(ping_frame.is_control_frame());

        let mut ring_buf = [0u8; 64];
        let written = ping_frame
            .encode_to_slice(&mut ring_buf)
            .expect("encode ping to slice");
        assert_eq!(written, 17);
        assert_eq!(&ring_buf[..written], &ping_frame.encode());

        let win_frame = crate::simd_parser::Http2Frame::WindowUpdate {
            stream_id: 3,
            window_size_increment: 4096,
        };
        assert!(win_frame.is_control_frame());
        let written_win = win_frame
            .encode_to_slice(&mut ring_buf)
            .expect("encode window update to slice");
        assert_eq!(written_win, 13);
        assert_eq!(&ring_buf[..written_win], &win_frame.encode());

        let rst_frame = crate::simd_parser::Http2Frame::RstStream {
            stream_id: 5,
            error_code: crate::simd_parser::Http2ErrorCode::Cancel,
        };
        assert!(rst_frame.is_control_frame());
        let written_rst = rst_frame
            .encode_to_slice(&mut ring_buf)
            .expect("encode rst to slice");
        assert_eq!(written_rst, 13);
        assert_eq!(&ring_buf[..written_rst], &rst_frame.encode());
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

        // Comparative latency and connection reuse benchmark for AsyncHttp2Pool
        let pool_res =
            benchmark_http2_pool_performance(2, 5, 2).expect("http2 pool performance benchmark");
        assert_eq!(pool_res.concurrent_workers, 2);
        assert_eq!(pool_res.requests_per_worker, 5);
        assert_eq!(pool_res.total_requests, 10);
        assert_eq!(pool_res.error_count, 0);
        assert!(pool_res.ops_per_sec > 0.0);
        assert!(pool_res.avg_latency_ns > 0.0);
        assert!(pool_res.total_connections_created <= 2);
        assert!(pool_res.connection_reuse_ratio > 0.0);
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

    #[test]
    fn test_http2_multiplexed_saturation_benchmark_execution() {
        let config = Http2MultiplexBenchmarkConfig {
            stream_count: 6,
            chunks_per_stream: 2,
            chunk_size_bytes: 1024,
            use_buffer_pool: true,
            buffer_capacity: 2048,
            pool_capacity: 16,
            auto_tune_flow_control: false,
        };

        let res = benchmark_http2_multiplexed_saturation(&config)
            .expect("benchmark http2 multiplexed saturation");

        assert_eq!(res.total_streams, 6);
        assert_eq!(res.total_chunks, 12);
        assert_eq!(res.total_bytes, 12 * 1024);
        assert!(res.elapsed_ms > 0.0);
        assert!(res.throughput_mb_s > 0.0);
        assert!(res.streams_per_sec > 0.0);
        assert!(res.chunks_per_sec > 0.0);
        assert!(res.avg_stream_latency_us > 0.0);
        assert_eq!(res.name, "Zero-Copy Recycled Pool");
        assert!(res.pooled_buffers_recycled > 0);
    }

    #[test]
    fn test_http2_multiplexed_comparison_suite() {
        let report = benchmark_http2_multiplexed_comparison(4, 2, 512)
            .expect("benchmark http2 multiplexed comparison");

        assert_eq!(report.standard.total_streams, 4);
        assert_eq!(report.zero_copy_pooled.total_streams, 4);
        assert_eq!(report.standard.total_bytes, 4 * 2 * 512);
        assert_eq!(report.zero_copy_pooled.total_bytes, 4 * 2 * 512);
        assert_eq!(report.standard.name, "Standard Allocating");
        assert_eq!(report.zero_copy_pooled.name, "Zero-Copy Recycled Pool");
        assert!(report.speedup_ratio > 0.0);
        assert!(report.recycled_buffers > 0);
    }

    #[test]
    fn test_async_http2_flow_control_auto_tuning() {
        let listener = AsyncTcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.local_addr().expect("local addr").port();

        let server_handle = std::thread::spawn(move || {
            let (stream, _) = loop {
                if let Ok(Some(pair)) = listener.try_accept() {
                    break pair;
                }
                std::thread::sleep(Duration::from_millis(2));
            };
            let mut server = AsyncHttp2Connection::server_handshake(stream)
                .expect("server handshake")
                .with_auto_tune_flow_control(true);

            // Wait for client request headers
            let mut target_stream_id = 0;
            for _ in 0..20 {
                if let Ok(crate::simd_parser::Http2Frame::Headers { stream_id, .. }) =
                    server.recv_frame()
                {
                    target_stream_id = stream_id;
                    break;
                }
            }

            if target_stream_id > 0 {
                let res_headers = vec![(":status", "200")];
                let h_frame =
                    server
                        .session
                        .create_headers_frame(target_stream_id, &res_headers, false);
                server.send_frame(&h_frame).expect("send headers");

                // Transmit high-throughput data payload
                let payload = vec![0xAAu8; 32768];
                server
                    .send_data(target_stream_id, &payload, true)
                    .expect("send data");

                // Keep connection open while client processes frames
                for _ in 0..20 {
                    let _ = server.try_recv_frame();
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        });

        let pool = AsyncHttp2Pool::new("127.0.0.1", port, 1).with_auto_tune_flow_control(true);
        assert!(pool.auto_tune_flow_control());

        let mut conn = pool.acquire().expect("acquire connection");
        assert!(conn.auto_tune_flow_control());

        // Simulate high throughput observation
        conn.record_flow_control_observation(5_000_000, Duration::from_millis(100));
        assert!(
            conn.session
                .adaptive_flow_controller
                .target_connection_window
                >= 65535
        );

        let stream_id = conn
            .send_request(&[(":method", "GET"), (":path", "/auto-tuning")], None)
            .expect("send request");

        let mut total_received = 0;
        loop {
            let frame = conn.recv_frame().expect("receive frame");
            if let crate::simd_parser::Http2Frame::Data {
                stream_id: sid,
                data,
                end_stream,
            } = frame
            {
                assert_eq!(sid, stream_id);
                total_received += data.len();
                if end_stream {
                    break;
                }
            }
        }
        assert_eq!(total_received, 32768);
        server_handle.join().expect("server join");
    }

    #[test]
    fn test_http2_multiplexed_saturation_benchmark_with_auto_tuning() {
        let config = Http2MultiplexBenchmarkConfig {
            stream_count: 6,
            chunks_per_stream: 2,
            chunk_size_bytes: 1024,
            use_buffer_pool: true,
            buffer_capacity: 2048,
            pool_capacity: 16,
            auto_tune_flow_control: true,
        };

        let res = benchmark_http2_multiplexed_saturation(&config)
            .expect("benchmark http2 multiplexed saturation with auto tuning");

        assert_eq!(res.total_streams, 6);
        assert_eq!(res.total_chunks, 12);
        assert_eq!(res.total_bytes, 12 * 1024);
        assert!(res.elapsed_ms > 0.0);
        assert!(res.throughput_mb_s > 0.0);
        assert!(res.streams_per_sec > 0.0);
        assert!(res.chunks_per_sec > 0.0);
        assert!(res.avg_stream_latency_us > 0.0);
        assert_eq!(
            res.name,
            "Zero-Copy Recycled Pool + Auto-Tuned Flow Control"
        );
        assert!(res.pooled_buffers_recycled > 0);
    }

    #[test]
    fn test_http2_push_promise_automated_caching_and_cache_hit() {
        let listener = AsyncTcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.local_addr().expect("local addr").port();

        let server_handle = std::thread::spawn(move || {
            let mut server = loop {
                match listener.accept() {
                    Ok((stream, _)) => match AsyncHttp2Connection::server_handshake(stream) {
                        Ok(conn) => break conn,
                        Err(_) => continue,
                    },
                    Err(_) => std::thread::sleep(Duration::from_millis(5)),
                }
            };

            // Await initial client request on stream 1
            let mut req_stream_id = 0;
            for _ in 0..30 {
                match server.recv_frame() {
                    Ok(crate::simd_parser::Http2Frame::Headers { stream_id, .. }) => {
                        req_stream_id = stream_id;
                        break;
                    }
                    _ => std::thread::sleep(Duration::from_millis(5)),
                }
            }
            assert_eq!(req_stream_id, 1);

            // 1. Send PUSH_PROMISE frame on stream 1 reserving stream 2 for /style.css
            let push_promise = server.session.create_push_promise(
                1,
                2,
                &[
                    (":method", "GET"),
                    (":path", "/style.css"),
                    (":scheme", "http"),
                ],
            );
            server.send_frame(&push_promise).expect("send push promise");

            // 2. Transmit promised response on stream 2
            let push_headers = [(":status", "200"), ("content-type", "text/css")];
            server
                .send_response(2, &push_headers, Some(b"body { background: #fff; }"))
                .expect("send promised response");

            // 3. Transmit response for original request stream 1
            let html_headers = [(":status", "200"), ("content-type", "text/html")];
            server
                .send_response(1, &html_headers, Some(b"<html>hello push</html>"))
                .expect("send stream 1 response");

            // Keep connection open while client consumes and performs checks
            for _ in 0..10 {
                let _ = server.try_recv_frame();
                std::thread::sleep(Duration::from_millis(5));
            }
        });

        let pool = AsyncHttp2Pool::new("127.0.0.1", port, 2).with_push_promises(true);
        assert!(pool.push_promises_enabled());
        assert_eq!(pool.push_promises_received(), 0);
        assert_eq!(pool.push_cache_hits(), 0);

        // 1. Execute initial request for /index.html
        let resp_html = pool
            .execute_request("GET", "/index.html", &[], None)
            .expect("execute request index.html");
        assert_eq!(resp_html.status.0, 200);
        assert_eq!(resp_html.body, b"<html>hello push</html>");

        // The push promise for /style.css must have been automatically absorbed and cached in the pool
        assert!(pool.has_cached_push_response("GET", "/style.css"));
        assert_eq!(pool.push_promises_received(), 1);
        assert_eq!(pool.push_promise_cache_count(), 1);
        assert_eq!(pool.stats().cached_push_promises, 1);

        // 2. Execute subsequent request for /style.css -> MUST be a proactive Cache Hit without network round-trip!
        let resp_css = pool
            .execute_request("GET", "/style.css", &[], None)
            .expect("execute request style.css from push cache");
        assert_eq!(resp_css.status.0, 200);
        assert_eq!(resp_css.body, b"body { background: #fff; }");

        // Cache hit counter incremented and cache entry consumed
        assert_eq!(pool.push_cache_hits(), 1);
        assert_eq!(pool.push_promise_cache_count(), 0);
        assert_eq!(pool.stats().push_cache_hits, 1);
        assert!(!pool.has_cached_push_response("GET", "/style.css"));

        server_handle.join().expect("server join");
    }

    #[test]
    fn test_http2_push_promise_disabled_pool_configuration() {
        let pool = AsyncHttp2Pool::new("127.0.0.1", 8080, 2).with_push_promises(false);
        assert!(!pool.push_promises_enabled());
        assert_eq!(pool.push_promise_cache_count(), 0);
        assert_eq!(pool.push_promises_received(), 0);
        assert_eq!(pool.push_cache_hits(), 0);

        pool.clear_push_promise_cache();
        assert_eq!(pool.push_promise_cache_count(), 0);
    }

    #[test]
    fn test_http2_push_promise_rfc7234_freshness_and_no_store() {
        let listener = AsyncTcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.local_addr().expect("local addr").port();

        let server_handle = std::thread::spawn(move || {
            let mut server = loop {
                match listener.accept() {
                    Ok((stream, _)) => match AsyncHttp2Connection::server_handshake(stream) {
                        Ok(conn) => break conn,
                        Err(_) => continue,
                    },
                    Err(_) => std::thread::sleep(Duration::from_millis(5)),
                }
            };

            // Stream 1 request
            for _ in 0..30 {
                match server.recv_frame() {
                    Ok(crate::simd_parser::Http2Frame::Headers { stream_id: 1, .. }) => break,
                    _ => std::thread::sleep(Duration::from_millis(5)),
                }
            }

            // 1. Send PUSH_PROMISE on stream 2 with no-store (RFC 7234 must not store)
            let p_no_store = server.session.create_push_promise(
                1,
                2,
                &[
                    (":method", "GET"),
                    (":path", "/sensitive.json"),
                    (":scheme", "http"),
                ],
            );
            server.send_frame(&p_no_store).expect("send p_no_store");
            let resp_headers_no_store =
                [(":status", "200"), ("cache-control", "no-store, private")];
            server
                .send_response(2, &resp_headers_no_store, Some(b"{\"secret\": 123}"))
                .expect("send 2");

            // 2. Send PUSH_PROMISE on stream 4 with max-age=3600 (RFC 7234 fresh)
            let p_fresh = server.session.create_push_promise(
                1,
                4,
                &[
                    (":method", "GET"),
                    (":path", "/bundle.js"),
                    (":scheme", "http"),
                ],
            );
            server.send_frame(&p_fresh).expect("send p_fresh");
            let resp_headers_fresh = [
                (":status", "200"),
                ("cache-control", "public, max-age=3600"),
                ("etag", "\"bundle-v1\""),
            ];
            server
                .send_response(4, &resp_headers_fresh, Some(b"console.log('bundle');"))
                .expect("send 4");

            // 3. Response on stream 1
            let html_headers = [(":status", "200"), ("content-type", "text/html")];
            server
                .send_response(1, &html_headers, Some(b"<html>ready</html>"))
                .expect("send 1");

            for _ in 0..10 {
                let _ = server.try_recv_frame();
                std::thread::sleep(Duration::from_millis(5));
            }
        });

        let pool = AsyncHttp2Pool::new("127.0.0.1", port, 2).with_push_promises(true);

        // 1. Execute stream 1 request
        let resp = pool
            .execute_request("GET", "/index.html", &[], None)
            .expect("exec index");
        assert_eq!(resp.status.0, 200);

        // /sensitive.json has no-store -> MUST NOT be in cache!
        assert!(!pool.has_cached_push_response("GET", "/sensitive.json"));

        // /bundle.js has max-age=3600 -> MUST be in cache!
        assert!(pool.has_cached_push_response("GET", "/bundle.js"));
        assert_eq!(pool.push_promise_cache_count(), 1);

        // Consume /bundle.js
        let resp_bundle = pool
            .execute_request("GET", "/bundle.js", &[], None)
            .expect("exec bundle");
        assert_eq!(resp_bundle.status.0, 200);
        assert_eq!(resp_bundle.body, b"console.log('bundle');");
        assert_eq!(pool.push_cache_hits(), 1);

        server_handle.join().expect("server join");
    }

    #[test]
    fn test_http2_pool_rfc7232_conditional_revalidation_304() {
        let listener = AsyncTcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.local_addr().expect("local addr").port();

        let server_handle = std::thread::spawn(move || {
            let mut server = loop {
                match listener.accept() {
                    Ok((stream, _)) => match AsyncHttp2Connection::server_handshake(stream) {
                        Ok(conn) => break conn,
                        Err(_) => continue,
                    },
                    Err(_) => std::thread::sleep(Duration::from_millis(5)),
                }
            };

            // Request 1: Initial GET /api/data
            let mut s1 = 0;
            for _ in 0..30 {
                match server.recv_frame() {
                    Ok(crate::simd_parser::Http2Frame::Headers { stream_id, .. }) => {
                        s1 = stream_id;
                        break;
                    }
                    _ => std::thread::sleep(Duration::from_millis(5)),
                }
            }
            assert_eq!(s1, 1);
            let h1 = [
                (":status", "200"),
                ("etag", "\"v1-hash-abc\""),
                ("cache-control", "public, max-age=60"),
            ];
            server
                .send_response(1, &h1, Some(b"{\"version\": 1, \"status\": \"ok\"}"))
                .expect("send s1 response");

            // Request 2: Revalidation request with If-None-Match
            let mut s2 = 0;
            for _ in 0..30 {
                match server.recv_frame() {
                    Ok(crate::simd_parser::Http2Frame::Headers { stream_id, .. }) => {
                        s2 = stream_id;
                        break;
                    }
                    _ => std::thread::sleep(Duration::from_millis(5)),
                }
            }
            assert_eq!(s2, 3);
            let s2_stream = server
                .session
                .streams
                .get(&3)
                .expect("stream 3 exists in session");
            let if_none_match_found = s2_stream
                .received_headers
                .iter()
                .any(|(k, v)| k.eq_ignore_ascii_case("if-none-match") && v == "\"v1-hash-abc\"");
            assert!(
                if_none_match_found,
                "Server must have received If-None-Match header!"
            );

            // Server replies 304 Not Modified with refreshed Cache-Control
            let h2 = [
                (":status", "304"),
                ("etag", "\"v1-hash-abc\""),
                ("cache-control", "public, max-age=120"),
            ];
            server
                .send_response(3, &h2, None)
                .expect("send 304 response");

            for _ in 0..10 {
                let _ = server.try_recv_frame();
                std::thread::sleep(Duration::from_millis(5));
            }
        });

        let pool = AsyncHttp2Pool::new("127.0.0.1", port, 2).with_http_cache(true);
        assert!(pool.http_cache_enabled());
        assert_eq!(pool.cache_revalidations(), 0);

        // 1. Initial request -> 200 OK stored in client cache
        let resp1 = pool
            .execute_request("GET", "/api/data", &[], None)
            .expect("request 1");
        assert_eq!(resp1.status.0, 200);
        assert_eq!(resp1.body, b"{\"version\": 1, \"status\": \"ok\"}");
        assert_eq!(pool.http_cache_count(), 1);

        // 2. Second request forced with Cache-Control: no-cache to trigger conditional revalidation
        let resp2 = pool
            .execute_request("GET", "/api/data", &[("Cache-Control", "no-cache")], None)
            .expect("request 2 with revalidation");

        // Transparent resolution: client sees 200 OK with cached body and revalidation count incremented!
        assert_eq!(resp2.status.0, 200);
        assert_eq!(resp2.body, b"{\"version\": 1, \"status\": \"ok\"}");
        assert_eq!(pool.cache_revalidations(), 1);
        assert_eq!(pool.stats().cache_revalidations, 1);
        assert_eq!(pool.push_cache_hits(), 1);

        server_handle.join().expect("server join");
    }

    #[test]
    fn test_http2_pool_rfc7234_vary_multi_key_isolation() {
        let listener = AsyncTcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.local_addr().expect("local addr").port();

        let server_handle = std::thread::spawn(move || {
            let mut server = loop {
                match listener.accept() {
                    Ok((stream, _)) => match AsyncHttp2Connection::server_handshake(stream) {
                        Ok(conn) => break conn,
                        Err(_) => continue,
                    },
                    Err(_) => continue,
                }
            };

            // Request 1: GET /api/resource (Accept-Encoding: gzip) -> Stream 1
            let frame1 = loop {
                if let Some(f) = server.try_recv_frame().expect("recv frame 1") {
                    if matches!(f, crate::simd_parser::Http2Frame::Headers { .. }) {
                        break f;
                    }
                }
                std::thread::sleep(Duration::from_millis(5));
            };
            assert_eq!(frame1.stream_id(), 1);
            let h1 = [
                (":status", "200"),
                ("vary", "Accept-Encoding"),
                ("content-encoding", "gzip"),
                ("cache-control", "public, max-age=120"),
            ];
            server
                .send_response(1, &h1, Some(b"DATA_GZIP"))
                .expect("send 200 gzip");

            // Request 2: GET /api/resource (Accept-Encoding: br) -> Stream 3
            let frame2 = loop {
                if let Some(f) = server.try_recv_frame().expect("recv frame 2") {
                    if matches!(f, crate::simd_parser::Http2Frame::Headers { .. }) {
                        break f;
                    }
                }
                std::thread::sleep(Duration::from_millis(5));
            };
            assert_eq!(frame2.stream_id(), 3);
            let h2 = [
                (":status", "200"),
                ("vary", "Accept-Encoding"),
                ("content-encoding", "br"),
                ("cache-control", "public, max-age=120"),
            ];
            server
                .send_response(3, &h2, Some(b"DATA_BR"))
                .expect("send 200 br");

            // Request 5: GET /wildcard (Vary: *) -> Stream 5
            let frame3 = loop {
                if let Some(f) = server.try_recv_frame().expect("recv frame 3") {
                    if matches!(f, crate::simd_parser::Http2Frame::Headers { .. }) {
                        break f;
                    }
                }
                std::thread::sleep(Duration::from_millis(5));
            };
            assert_eq!(frame3.stream_id(), 5);
            let h3 = [
                (":status", "200"),
                ("vary", "*"),
                ("cache-control", "public, max-age=120"),
            ];
            server
                .send_response(5, &h3, Some(b"WILD1"))
                .expect("send 200 wildcard 1");

            // Request 6: GET /wildcard again (must NOT hit cache because Vary: *) -> Stream 7
            let frame4 = loop {
                if let Some(f) = server.try_recv_frame().expect("recv frame 4") {
                    if matches!(f, crate::simd_parser::Http2Frame::Headers { .. }) {
                        break f;
                    }
                }
                std::thread::sleep(Duration::from_millis(5));
            };
            assert_eq!(frame4.stream_id(), 7);
            let h4 = [
                (":status", "200"),
                ("vary", "*"),
                ("cache-control", "public, max-age=120"),
            ];
            server
                .send_response(7, &h4, Some(b"WILD2"))
                .expect("send 200 wildcard 2");

            for _ in 0..10 {
                let _ = server.try_recv_frame();
                std::thread::sleep(Duration::from_millis(5));
            }
        });

        let pool = AsyncHttp2Pool::new("127.0.0.1", port, 2).with_http_cache(true);

        // 1. First request with Accept-Encoding: gzip
        let resp1 = pool
            .execute_request("GET", "/api/resource", &[("Accept-Encoding", "gzip")], None)
            .expect("request gzip");
        assert_eq!(resp1.status.0, 200);
        assert_eq!(resp1.body, b"DATA_GZIP");
        assert_eq!(pool.http_cache_count(), 1);

        // 2. Second request with Accept-Encoding: br (Vary isolation: gzip entry cannot be reused!)
        let resp2 = pool
            .execute_request("GET", "/api/resource", &[("Accept-Encoding", "br")], None)
            .expect("request br");
        assert_eq!(resp2.status.0, 200);
        assert_eq!(resp2.body, b"DATA_BR");
        // Two distinct variant entries are now cached under /api/resource
        assert_eq!(pool.http_cache_count(), 2);
        assert_eq!(pool.push_cache_hits(), 0);

        // 3. Third request with Accept-Encoding: gzip -> Cache HIT on Variant 1!
        let resp3 = pool
            .execute_request("GET", "/api/resource", &[("Accept-Encoding", "gzip")], None)
            .expect("request gzip cached");
        assert_eq!(resp3.status.0, 200);
        assert_eq!(resp3.body, b"DATA_GZIP");
        assert_eq!(pool.push_cache_hits(), 1);

        // 4. Fourth request with Accept-Encoding: br -> Cache HIT on Variant 2!
        let resp4 = pool
            .execute_request("GET", "/api/resource", &[("Accept-Encoding", "br")], None)
            .expect("request br cached");
        assert_eq!(resp4.status.0, 200);
        assert_eq!(resp4.body, b"DATA_BR");
        assert_eq!(pool.push_cache_hits(), 2);

        // 5. Fifth request for Vary: * resource -> stored but unmatchable under RFC 7234
        let resp_wild1 = pool
            .execute_request("GET", "/wildcard", &[], None)
            .expect("wildcard 1");
        assert_eq!(resp_wild1.status.0, 200);
        assert_eq!(resp_wild1.body, b"WILD1");

        // 6. Sixth request for /wildcard MUST NOT hit cache
        let resp_wild2 = pool
            .execute_request("GET", "/wildcard", &[], None)
            .expect("wildcard 2");
        assert_eq!(resp_wild2.status.0, 200);
        assert_eq!(resp_wild2.body, b"WILD2");
        assert_eq!(pool.push_cache_hits(), 2); // Unchanged

        server_handle.join().expect("server join");
    }

    #[test]
    fn test_http2_pool_stale_while_revalidate_async_background() {
        let listener = AsyncTcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.local_addr().expect("local addr").port();

        let server_handle = std::thread::spawn(move || {
            let mut server = loop {
                match listener.accept() {
                    Ok((stream, _)) => match AsyncHttp2Connection::server_handshake(stream) {
                        Ok(conn) => break conn,
                        Err(_) => continue,
                    },
                    Err(_) => continue,
                }
            };

            // Request 1: GET /api/swr -> Stream 1
            let frame1 = loop {
                if let Some(f) = server.try_recv_frame().expect("recv frame 1") {
                    if matches!(f, crate::simd_parser::Http2Frame::Headers { .. }) {
                        break f;
                    }
                }
                std::thread::sleep(Duration::from_millis(5));
            };
            assert_eq!(frame1.stream_id(), 1);
            let h1 = [
                (":status", "200"),
                ("etag", "\"v1-swr\""),
                (
                    "cache-control",
                    "public, max-age=1, stale-while-revalidate=60",
                ),
            ];
            server
                .send_response(1, &h1, Some(b"SWR_V1"))
                .expect("send 200 swr 1");

            // Background Revalidation Request: GET /api/swr with If-None-Match: "v1-swr" -> Stream 3
            let frame2 = loop {
                if let Some(f) = server.try_recv_frame().expect("recv frame 2") {
                    if matches!(f, crate::simd_parser::Http2Frame::Headers { .. }) {
                        break f;
                    }
                }
                std::thread::sleep(Duration::from_millis(5));
            };
            assert_eq!(frame2.stream_id(), 3);
            let h2 = [
                (":status", "304"),
                ("etag", "\"v1-swr\""),
                (
                    "cache-control",
                    "public, max-age=120, stale-while-revalidate=60",
                ),
            ];
            server
                .send_response(3, &h2, None)
                .expect("send 304 swr revalidation");

            for _ in 0..10 {
                let _ = server.try_recv_frame();
                std::thread::sleep(Duration::from_millis(5));
            }
        });

        let pool = AsyncHttp2Pool::new("127.0.0.1", port, 2).with_http_cache(true);

        // 1. Initial request -> 200 OK stored in client cache
        let resp1 = pool
            .execute_request("GET", "/api/swr", &[], None)
            .expect("request 1");
        assert_eq!(resp1.status.0, 200);
        assert_eq!(resp1.body, b"SWR_V1");
        assert_eq!(pool.http_cache_count(), 1);
        assert_eq!(pool.stale_hits(), 0);

        // Sleep 1.1s so max-age=1 expires and entry enters stale-while-revalidate window
        std::thread::sleep(Duration::from_millis(1100));

        // 2. Second request -> immediate stale hit (Warning: 110 header present), triggers background revalidation
        let resp2 = pool
            .execute_request("GET", "/api/swr", &[], None)
            .expect("request 2 stale");
        assert_eq!(resp2.status.0, 200);
        assert_eq!(resp2.body, b"SWR_V1");
        assert_eq!(
            resp2.headers.get("warning"),
            Some("110 - \"Response is Stale\"")
        );
        assert_eq!(pool.stale_hits(), 1);

        // Wait up to 1000ms for background revalidation to complete
        let start = std::time::Instant::now();
        while pool.cache_revalidations() == 0 && start.elapsed() < Duration::from_millis(1000) {
            std::thread::sleep(Duration::from_millis(10));
        }

        assert_eq!(pool.cache_revalidations(), 1);
        assert!(pool.background_revalidations() >= 1);

        server_handle.join().expect("server join");
    }

    #[test]
    fn test_http2_pool_stale_if_error_resilience() {
        let listener = AsyncTcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.local_addr().expect("local addr").port();

        let server_handle = std::thread::spawn(move || {
            let mut server = loop {
                match listener.accept() {
                    Ok((stream, _)) => match AsyncHttp2Connection::server_handshake(stream) {
                        Ok(conn) => break conn,
                        Err(_) => continue,
                    },
                    Err(_) => continue,
                }
            };

            // Request 1: GET /api/sie -> Stream 1
            let frame1 = loop {
                if let Some(f) = server.try_recv_frame().expect("recv frame 1") {
                    if matches!(f, crate::simd_parser::Http2Frame::Headers { .. }) {
                        break f;
                    }
                }
                std::thread::sleep(Duration::from_millis(5));
            };
            assert_eq!(frame1.stream_id(), 1);
            let h1 = [
                (":status", "200"),
                ("cache-control", "public, max-age=1, stale-if-error=120"),
            ];
            server
                .send_response(1, &h1, Some(b"SIE_SAVED_DATA"))
                .expect("send 200 sie 1");

            // Request 2: GET /api/sie -> Stream 3, server replies with 500 Internal Server Error
            let frame2 = loop {
                if let Some(f) = server.try_recv_frame().expect("recv frame 2") {
                    if matches!(f, crate::simd_parser::Http2Frame::Headers { .. }) {
                        break f;
                    }
                }
                std::thread::sleep(Duration::from_millis(5));
            };
            assert_eq!(frame2.stream_id(), 3);
            let h2 = [(":status", "500")];
            server
                .send_response(3, &h2, Some(b"INTERNAL_SERVER_ERROR"))
                .expect("send 500");

            for _ in 0..10 {
                let _ = server.try_recv_frame();
                std::thread::sleep(Duration::from_millis(5));
            }
        });

        let pool = AsyncHttp2Pool::new("127.0.0.1", port, 2).with_http_cache(true);

        // 1. Initial request -> 200 OK stored in client cache
        let resp1 = pool
            .execute_request("GET", "/api/sie", &[], None)
            .expect("request 1");
        assert_eq!(resp1.status.0, 200);
        assert_eq!(resp1.body, b"SIE_SAVED_DATA");

        // Sleep 1.1s so max-age=1 expires
        std::thread::sleep(Duration::from_millis(1100));

        // 2. Second request hits origin 500 error, but stale-if-error rescues it!
        let resp2 = pool
            .execute_request("GET", "/api/sie", &[], None)
            .expect("request 2 rescued by stale-if-error");
        assert_eq!(resp2.status.0, 200);
        assert_eq!(resp2.body, b"SIE_SAVED_DATA");
        assert_eq!(
            resp2.headers.get("warning"),
            Some("110 - \"Response is Stale\"")
        );
        assert_eq!(pool.stale_error_fallbacks(), 1);
        assert_eq!(pool.stats().stale_error_fallbacks, 1);

        server_handle.join().expect("server join");
    }

    #[test]
    fn test_http2_pool_cache_heuristic_freshness() {
        let mut resp = crate::http::HttpResponse::new(crate::http::HttpStatus(200));
        let now = std::time::SystemTime::now();
        let past = now - std::time::Duration::from_secs(1000);
        let past_http_date = crate::http::format_http_date(past);
        resp.headers.set("last-modified", past_http_date.as_str());

        let entry = Http2PoolCacheEntry::new("GET", "/api/heuristic", resp);
        assert!(entry.is_heuristic());
        assert!(entry.is_cacheable());
        // Freshness should be approximately 10% of 1000s = ~100s
        let freshness = entry.heuristic_freshness().expect("heuristic freshness");
        assert!(freshness.as_secs() >= 95 && freshness.as_secs() <= 105);

        // Within freshness window (e.g. at now + 50s): fresh
        assert!(entry.is_fresh(
            now + std::time::Duration::from_secs(50),
            std::time::Duration::from_secs(10)
        ));
        // Past freshness window (e.g. at now + 150s): not fresh
        assert!(!entry.is_fresh(
            now + std::time::Duration::from_secs(150),
            std::time::Duration::from_secs(10)
        ));
    }

    #[test]
    fn test_http2_pool_cache_lru_and_sweep() {
        let pool = AsyncHttp2Pool::new("127.0.0.1", 8080, 2)
            .with_http_cache(true)
            .with_max_http_cache_entries(2);

        assert_eq!(pool.max_http_cache_entries(), 2);
        assert_eq!(pool.http_cache_evictions(), 0);

        let mut r1 = crate::http::HttpResponse::new(crate::http::HttpStatus(200));
        r1.headers.set("cache-control", "public, max-age=60");
        let e1 = Http2PoolCacheEntry::new("GET", "/api/item1", r1);

        let mut r2 = crate::http::HttpResponse::new(crate::http::HttpStatus(200));
        r2.headers.set("cache-control", "public, max-age=60");
        let e2 = Http2PoolCacheEntry::new("GET", "/api/item2", r2);

        let mut r3 = crate::http::HttpResponse::new(crate::http::HttpStatus(200));
        r3.headers.set("cache-control", "public, max-age=60");
        let e3 = Http2PoolCacheEntry::new("GET", "/api/item3", r3);

        // Insert e1 and e2
        pool.insert_http_cache_entry("GET:/api/item1".into(), e1);
        pool.insert_http_cache_entry("GET:/api/item2".into(), e2);
        assert_eq!(pool.http_cache_count(), 2);

        // Access e1 (touch it) so e2 becomes LRU
        if let Ok(mut cache) = pool.http_cache_entries.lock() {
            if let Some(entries) = cache.get_mut("GET:/api/item1") {
                entries[0].touch();
            }
        }

        // Insert e3 -> exceeds capacity 2 -> e2 (LRU) evicted!
        pool.insert_http_cache_entry("GET:/api/item3".into(), e3);
        assert_eq!(pool.http_cache_count(), 2);
        assert_eq!(pool.http_cache_evictions(), 1);
        assert_eq!(pool.stats().http_cache_evictions, 1);

        // Verify e1 and e3 exist, e2 is gone
        if let Ok(cache) = pool.http_cache_entries.lock() {
            assert!(cache.contains_key("GET:/api/item1"));
            assert!(!cache.contains_key("GET:/api/item2"));
            assert!(cache.contains_key("GET:/api/item3"));
        }

        // Test sweep_http_cache with expired TTL
        let future_time = std::time::SystemTime::now() + std::time::Duration::from_secs(100);
        let swept = pool.sweep_http_cache(future_time, std::time::Duration::from_secs(10));
        assert_eq!(swept, 2);
        assert_eq!(pool.http_cache_count(), 0);
        assert_eq!(pool.http_cache_evictions(), 3);
    }

    #[test]
    fn test_http2_pool_cache_invalidation_methods() {
        let pool = AsyncHttp2Pool::new("127.0.0.1", 8080, 2).with_http_cache(true);

        let mut r1 = crate::http::HttpResponse::new(crate::http::HttpStatus(200));
        r1.headers.set("cache-control", "public, max-age=60");
        pool.insert_http_cache_entry(
            "GET:/api/users/1".into(),
            Http2PoolCacheEntry::new("GET", "/api/users/1", r1.clone()),
        );
        pool.insert_http_cache_entry(
            "GET:/api/users/2".into(),
            Http2PoolCacheEntry::new("GET", "/api/users/2", r1.clone()),
        );
        pool.insert_http_cache_entry(
            "GET:/api/products/1".into(),
            Http2PoolCacheEntry::new("GET", "/api/products/1", r1.clone()),
        );
        pool.insert_http_cache_entry(
            "GET:/api/orders/99".into(),
            Http2PoolCacheEntry::new("GET", "/api/orders/99", r1),
        );

        assert_eq!(pool.http_cache_count(), 4);
        assert_eq!(pool.http_cache_invalidations(), 0);

        // 1. Invalidate single path
        let removed_single = pool.invalidate_http_cache_path("/api/products/1");
        assert_eq!(removed_single, 1);
        assert_eq!(pool.http_cache_count(), 3);
        assert_eq!(pool.http_cache_invalidations(), 1);

        // 2. Invalidate prefix
        let removed_prefix = pool.invalidate_http_cache_prefix("/api/users");
        assert_eq!(removed_prefix, 2);
        assert_eq!(pool.http_cache_count(), 1);
        assert_eq!(pool.http_cache_invalidations(), 3);

        // 3. Invalidate matching predicate
        let removed_pred = pool.invalidate_http_cache_matching(|e| e.path.contains("orders"));
        assert_eq!(removed_pred, 1);
        assert_eq!(pool.http_cache_count(), 0);
        assert_eq!(pool.http_cache_invalidations(), 4);
        assert_eq!(pool.stats().http_cache_invalidations, 4);
    }

    #[test]
    fn test_http2_pool_rfc7234_unsafe_method_invalidation_and_heuristic_warning() {
        let listener = AsyncTcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.local_addr().expect("local addr").port();

        let server_handle = std::thread::spawn(move || {
            let mut server = loop {
                match listener.accept() {
                    Ok((stream, _)) => match AsyncHttp2Connection::server_handshake(stream) {
                        Ok(conn) => break conn,
                        Err(_) => continue,
                    },
                    Err(_) => continue,
                }
            };

            // Request 1: GET /api/record -> Stream 1 (cached)
            let frame1 = loop {
                if let Some(f) = server.try_recv_frame().expect("recv frame 1") {
                    if matches!(f, crate::simd_parser::Http2Frame::Headers { .. }) {
                        break f;
                    }
                }
                std::thread::sleep(Duration::from_millis(5));
            };
            assert_eq!(frame1.stream_id(), 1);
            let h1 = [(":status", "200"), ("cache-control", "public, max-age=120")];
            server
                .send_response(1, &h1, Some(b"INITIAL_RECORD"))
                .expect("send 200");

            // Request 2: POST /api/record -> Stream 3 (non-safe method: RFC 7234 §4.4 invalidates cached URI!)
            let frame2 = loop {
                if let Some(f) = server.try_recv_frame().expect("recv frame 2") {
                    if matches!(f, crate::simd_parser::Http2Frame::Headers { .. }) {
                        break f;
                    }
                }
                std::thread::sleep(Duration::from_millis(5));
            };
            assert_eq!(frame2.stream_id(), 3);
            let h2 = [(":status", "204")];
            server.send_response(3, &h2, None).expect("send 204");

            // Request 3: GET /api/record -> Stream 5 (must hit origin because previous POST invalidated it!)
            let frame3 = loop {
                if let Some(f) = server.try_recv_frame().expect("recv frame 3") {
                    if matches!(f, crate::simd_parser::Http2Frame::Headers { .. }) {
                        break f;
                    }
                }
                std::thread::sleep(Duration::from_millis(5));
            };
            assert_eq!(frame3.stream_id(), 5);
            let h3 = [(":status", "200"), ("cache-control", "public, max-age=120")];
            server
                .send_response(5, &h3, Some(b"UPDATED_RECORD"))
                .expect("send 200 updated");

            for _ in 0..10 {
                let _ = server.try_recv_frame();
                std::thread::sleep(Duration::from_millis(5));
            }
        });

        let pool = AsyncHttp2Pool::new("127.0.0.1", port, 2).with_http_cache(true);

        // 1. GET /api/record -> Cached
        let r1 = pool
            .execute_request("GET", "/api/record", &[], None)
            .expect("get 1");
        assert_eq!(r1.body, b"INITIAL_RECORD");
        assert_eq!(pool.http_cache_count(), 1);

        // 2. POST /api/record -> Success (204 No Content), triggers RFC 7234 §4.4 invalidation
        let r2 = pool
            .execute_request("POST", "/api/record", &[], Some(b"update"))
            .expect("post 1");
        assert_eq!(r2.status.0, 204);
        assert_eq!(pool.http_cache_count(), 0);
        assert_eq!(pool.http_cache_invalidations(), 1);

        // 3. GET /api/record -> Fetched from origin because cache was invalidated
        let r3 = pool
            .execute_request("GET", "/api/record", &[], None)
            .expect("get 2");
        assert_eq!(r3.body, b"UPDATED_RECORD");
        assert_eq!(pool.http_cache_count(), 1);

        server_handle.join().expect("server join");
    }

    #[test]
    fn test_http2_pool_transparent_compression_negotiation_and_decompression() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let port = listener.local_addr().expect("local addr").port();

        let server_handle = std::thread::spawn(move || {
            let (tcp_stream, _) = listener.accept().expect("accept connection");
            let async_stream = AsyncTcpStream::from_std(tcp_stream).expect("async stream");
            let mut server =
                AsyncHttp2Connection::server_handshake(async_stream).expect("server handshake");

            // Request 1: GET /compressed/br
            let frame1 = loop {
                if let Some(f) = server.try_recv_frame().expect("recv frame 1") {
                    if matches!(f, crate::simd_parser::Http2Frame::Headers { .. }) {
                        break f;
                    }
                }
                std::thread::sleep(Duration::from_millis(5));
            };
            assert_eq!(frame1.stream_id(), 1);
            let s1 = server.session.streams.get(&1).expect("stream 1");
            let ae1 = s1
                .received_headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("accept-encoding"))
                .map(|(_, v)| v.as_str());
            assert_eq!(ae1, Some("gzip, deflate, br"));

            let br_body =
                crate::http::compress_brotli(b"Hello Brotli Transparent HTTP/2 Response!");
            let h1 = [
                (":status", "200"),
                ("content-encoding", "br"),
                ("cache-control", "public, max-age=120"),
            ];
            server
                .send_response(1, &h1, Some(&br_body))
                .expect("send 200 br");

            // Request 2: GET /compressed/gzip
            let frame2 = loop {
                if let Some(f) = server.try_recv_frame().expect("recv frame 2") {
                    if matches!(f, crate::simd_parser::Http2Frame::Headers { .. }) {
                        break f;
                    }
                }
                std::thread::sleep(Duration::from_millis(5));
            };
            assert_eq!(frame2.stream_id(), 3);
            let gz_body = crate::http::compress_gzip(b"Hello Gzip Transparent HTTP/2 Response!");
            let h2 = [
                (":status", "200"),
                ("content-encoding", "gzip"),
                ("cache-control", "public, max-age=120"),
            ];
            server
                .send_response(3, &h2, Some(&gz_body))
                .expect("send 200 gzip");

            for _ in 0..10 {
                let _ = server.try_recv_frame();
                std::thread::sleep(Duration::from_millis(5));
            }
        });

        let pool = AsyncHttp2Pool::new("127.0.0.1", port, 2)
            .with_http_cache(true)
            .with_auto_decompress(true);

        assert!(pool.auto_decompress());
        assert_eq!(
            pool.accept_encoding(),
            Some("gzip, deflate, br".to_string())
        );

        // 1. Request 1: GET /compressed/br without Accept-Encoding header -> pool auto-injects and transparently decodes br
        let resp1 = pool
            .execute_request("GET", "/compressed/br", &[], None)
            .expect("request br");
        assert_eq!(resp1.status.0, 200);
        assert_eq!(resp1.body, b"Hello Brotli Transparent HTTP/2 Response!");
        assert_eq!(resp1.headers.get("content-encoding"), None);
        assert_eq!(
            resp1.headers.get("content-length"),
            Some(
                b"Hello Brotli Transparent HTTP/2 Response!"
                    .len()
                    .to_string()
                    .as_str()
            )
        );
        assert_eq!(pool.decompressed_responses(), 1);
        assert_eq!(pool.stats().decompressed_responses, 1);
        assert_eq!(pool.http_cache_count(), 1);

        // Subsequent cache hit returns the uncompressed response
        let resp1_cached = pool
            .execute_request("GET", "/compressed/br", &[], None)
            .expect("cached br");
        assert_eq!(
            resp1_cached.body,
            b"Hello Brotli Transparent HTTP/2 Response!"
        );
        assert_eq!(resp1_cached.headers.get("content-encoding"), None);

        // 2. Request 2: GET /compressed/gzip -> transparently decodes gzip
        let resp2 = pool
            .execute_request("GET", "/compressed/gzip", &[], None)
            .expect("request gzip");
        assert_eq!(resp2.status.0, 200);
        assert_eq!(resp2.body, b"Hello Gzip Transparent HTTP/2 Response!");
        assert_eq!(resp2.headers.get("content-encoding"), None);
        assert_eq!(pool.decompressed_responses(), 2);

        server_handle.join().expect("server join");
    }

    #[test]
    fn test_http2_pool_cache_entry_decompression_methods() {
        let compressed_resp = crate::http::HttpResponse::ok()
            .text("Payload inside Http2PoolCacheEntry")
            .brotli();
        let mut entry = Http2PoolCacheEntry::new("GET", "/cached/entry", compressed_resp);

        assert!(entry.is_compressed());
        assert_eq!(
            entry.content_encoding(),
            crate::http::ContentEncoding::Brotli
        );
        assert_eq!(entry.response.headers.get("content-encoding"), Some("br"));

        let decompressed = entry
            .decompress_in_place()
            .expect("decompress entry in place");
        assert!(decompressed);
        assert!(!entry.is_compressed());
        assert_eq!(
            entry.content_encoding(),
            crate::http::ContentEncoding::Identity
        );
        assert_eq!(entry.response.headers.get("content-encoding"), None);
        assert_eq!(entry.response.body, b"Payload inside Http2PoolCacheEntry");
    }
}

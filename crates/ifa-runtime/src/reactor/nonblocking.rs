//! Non-blocking cooperative network and timer reactor for colorless fibers.

use crate::fiber::GLOBAL_SCHEDULER;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

/// Asynchronous non-blocking TCP listener managed by the fiber reactor.
pub struct AsyncTcpListener {
    inner: TcpListener,
}

impl AsyncTcpListener {
    /// Bind to a local address and set the listener socket to non-blocking mode.
    pub fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;
        Ok(Self { inner: listener })
    }

    /// Asynchronously accept a new connection, cooperatively yielding the fiber
    /// until a connection arrives without blocking OS worker threads.
    pub fn accept(&self) -> io::Result<(AsyncTcpStream, std::net::SocketAddr)> {
        let mut spins = 0;
        loop {
            match self.inner.accept() {
                Ok((stream, addr)) => {
                    stream.set_nonblocking(true)?;
                    return Ok((AsyncTcpStream { inner: stream }, addr));
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
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

    /// Non-blocking attempt to accept an incoming connection immediately.
    pub fn try_accept(&self) -> io::Result<Option<(AsyncTcpStream, std::net::SocketAddr)>> {
        match self.inner.accept() {
            Ok((stream, addr)) => {
                stream.set_nonblocking(true)?;
                Ok(Some((AsyncTcpStream { inner: stream }, addr)))
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Retrieve local socket address.
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }

    /// Set IP Time-To-Live.
    pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        self.inner.set_ttl(ttl)
    }

    /// Retrieve IP Time-To-Live.
    pub fn ttl(&self) -> io::Result<u32> {
        self.inner.ttl()
    }
}

/// Asynchronous non-blocking TCP stream managed by the fiber reactor.
pub struct AsyncTcpStream {
    inner: TcpStream,
}

impl AsyncTcpStream {
    /// Connect asynchronously to a remote address.
    pub fn connect<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        stream.set_nonblocking(true)?;
        Ok(Self { inner: stream })
    }

    /// Wrap an existing std TcpStream.
    pub fn from_std(stream: TcpStream) -> io::Result<Self> {
        stream.set_nonblocking(true)?;
        Ok(Self { inner: stream })
    }

    /// Read data from the stream asynchronously, yielding the calling fiber
    /// when socket buffer is empty without blocking OS threads.
    pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut spins = 0;
        loop {
            match self.inner.read(buf) {
                Ok(n) => return Ok(n),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
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

    /// Non-blocking read attempt: returns `Ok(None)` if would block.
    pub fn try_read(&mut self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        match self.inner.read(buf) {
            Ok(n) => Ok(Some(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Write data to the stream asynchronously, yielding the calling fiber
    /// on backpressure until kernel send buffer accepts data.
    pub fn write_all(&mut self, mut buf: &[u8]) -> io::Result<()> {
        let mut spins = 0;
        while !buf.is_empty() {
            match self.inner.write(buf) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write whole buffer",
                    ))
                }
                Ok(n) => {
                    buf = &buf[n..];
                    spins = 0;
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
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
        self.inner.flush()?;
        Ok(())
    }

    /// Flush the TCP stream.
    pub fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }

    /// Peer address.
    pub fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.peer_addr()
    }

    /// Set TCP_NODELAY (disable Nagle's algorithm).
    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.inner.set_nodelay(nodelay)
    }

    /// Retrieve TCP_NODELAY flag.
    pub fn nodelay(&self) -> io::Result<bool> {
        self.inner.nodelay()
    }

    /// Set IP Time-To-Live.
    pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        self.inner.set_ttl(ttl)
    }

    /// Retrieve IP Time-To-Live.
    pub fn ttl(&self) -> io::Result<u32> {
        self.inner.ttl()
    }
}

/// Asynchronous non-blocking UDP socket managed by the fiber reactor.
pub struct AsyncUdpSocket {
    inner: std::net::UdpSocket,
}

impl AsyncUdpSocket {
    /// Bind UDP socket to a local address and configure non-blocking mode.
    pub fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        let socket = std::net::UdpSocket::bind(addr)?;
        socket.set_nonblocking(true)?;
        Ok(Self { inner: socket })
    }

    /// Asynchronously send datagram to remote address, yielding calling fiber if socket buffer is full.
    pub fn send_to<A: ToSocketAddrs>(&self, buf: &[u8], addr: A) -> io::Result<usize> {
        let mut spins = 0;
        loop {
            match self.inner.send_to(buf, &addr) {
                Ok(n) => return Ok(n),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
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

    /// Asynchronously receive datagram from socket, yielding calling fiber until packet arrives.
    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, std::net::SocketAddr)> {
        let mut spins = 0;
        loop {
            match self.inner.recv_from(buf) {
                Ok((n, addr)) => return Ok((n, addr)),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
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

    /// Non-blocking attempt to receive datagram immediately.
    pub fn try_recv_from(
        &self,
        buf: &mut [u8],
    ) -> io::Result<Option<(usize, std::net::SocketAddr)>> {
        match self.inner.recv_from(buf) {
            Ok((n, addr)) => Ok(Some((n, addr))),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Non-blocking attempt to send datagram immediately.
    pub fn try_send_to<A: ToSocketAddrs>(&self, buf: &[u8], addr: A) -> io::Result<Option<usize>> {
        match self.inner.send_to(buf, addr) {
            Ok(n) => Ok(Some(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Retrieve local socket address.
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }

    /// Set IP Time-To-Live.
    pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        self.inner.set_ttl(ttl)
    }

    /// Retrieve IP Time-To-Live.
    pub fn ttl(&self) -> io::Result<u32> {
        self.inner.ttl()
    }

    /// Connect socket to remote address for direct send/recv.
    pub fn connect<A: ToSocketAddrs>(&self, addr: A) -> io::Result<()> {
        self.inner.connect(addr)
    }

    /// Asynchronously send datagram on connected socket.
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        let mut spins = 0;
        loop {
            match self.inner.send(buf) {
                Ok(n) => return Ok(n),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
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

    /// Asynchronously receive datagram on connected socket.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut spins = 0;
        loop {
            match self.inner.recv(buf) {
                Ok(n) => return Ok(n),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
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

    /// Non-blocking attempt to send datagram on connected socket.
    pub fn try_send(&self, buf: &[u8]) -> io::Result<Option<usize>> {
        match self.inner.send(buf) {
            Ok(n) => Ok(Some(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Non-blocking attempt to receive datagram on connected socket.
    pub fn try_recv(&self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        match self.inner.recv(buf) {
            Ok(n) => Ok(Some(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Enable or disable SO_BROADCAST on UDP socket.
    pub fn set_broadcast(&self, on: bool) -> io::Result<()> {
        self.inner.set_broadcast(on)
    }

    /// Retrieve SO_BROADCAST status.
    pub fn broadcast(&self) -> io::Result<bool> {
        self.inner.broadcast()
    }

    /// Retrieve peer address if connected.
    pub fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.peer_addr()
    }
}

/// Asynchronous non-blocking timer for fibers.
pub struct AsyncTimer;

impl AsyncTimer {
    /// Yield execution of the calling fiber until duration has elapsed.
    pub fn sleep(duration: Duration) {
        let start = Instant::now();
        let target = start + duration;
        while Instant::now() < target {
            GLOBAL_SCHEDULER.yield_now();
            let remaining = target.saturating_duration_since(Instant::now());
            if remaining > Duration::from_millis(5) {
                std::thread::sleep(Duration::from_millis(2));
            } else {
                std::hint::spin_loop();
            }
        }
    }
}

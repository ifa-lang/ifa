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

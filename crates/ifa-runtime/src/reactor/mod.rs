//! Asynchronous I/O Reactor subsystem for IFA colorless fibers.
//!
//! Provides zero-cost abstraction over kernel-level async engines:
//! - Linux `io_uring` (submission & completion queues)
//! - Windows `IOCP` (I/O completion ports)
//! - Cooperative non-blocking network streams and timers.

#![allow(clippy::not_unsafe_ptr_arg_deref)]

pub mod io_uring;
pub mod iocp;
pub mod nonblocking;

pub use io_uring::{IoUringConnector, IoUringCqe, IoUringSqe, KernelTimespec};
pub use iocp::{IocpCompletionPacket, IocpConnector, IocpOpCode};
pub use nonblocking::{AsyncTcpListener, AsyncTcpStream, AsyncTimer};

use std::collections::HashMap;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::sync::Mutex;

/// Unified Async Reactor coordinating kernel completion drivers and fibers.
pub struct AsyncReactor {
    io_uring: IoUringConnector,
    iocp: IocpConnector,
    next_handle_id: AtomicI32,
    next_token_id: AtomicU64,
    listeners: Mutex<HashMap<i32, AsyncTcpListener>>,
    streams: Mutex<HashMap<i32, AsyncTcpStream>>,
}

impl AsyncReactor {
    pub fn new() -> Self {
        Self {
            io_uring: IoUringConnector::new(256),
            iocp: IocpConnector::new(2),
            next_handle_id: AtomicI32::new(1000),
            next_token_id: AtomicU64::new(1),
            listeners: Mutex::new(HashMap::new()),
            streams: Mutex::new(HashMap::new()),
        }
    }

    /// Access io_uring connector.
    pub fn io_uring(&self) -> &IoUringConnector {
        &self.io_uring
    }

    /// Access Windows IOCP connector.
    pub fn iocp(&self) -> &IocpConnector {
        &self.iocp
    }

    /// Generate a unique 64-bit event token for tracking asynchronous I/O completion.
    pub fn next_token(&self) -> u64 {
        self.next_token_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Submit an asynchronous io_uring read request with the specified event token.
    pub fn submit_io_uring_read(&self, fd: i32, buf: *mut u8, len: u32, offset: u64, token: u64) {
        let sqe = IoUringSqe {
            opcode: io_uring::opcodes::IORING_OP_READ,
            fd,
            addr: buf as u64,
            len,
            off: offset,
            user_data: token,
            ..Default::default()
        };
        self.io_uring.submit_sqe(sqe);
    }

    /// Submit an asynchronous io_uring write request with the specified event token.
    pub fn submit_io_uring_write(
        &self,
        fd: i32,
        buf: *const u8,
        len: u32,
        offset: u64,
        token: u64,
    ) {
        let sqe = IoUringSqe {
            opcode: io_uring::opcodes::IORING_OP_WRITE,
            fd,
            addr: buf as u64,
            len,
            off: offset,
            user_data: token,
            ..Default::default()
        };
        self.io_uring.submit_sqe(sqe);
    }

    /// Submit an asynchronous high-precision timeout via io_uring with the specified event token.
    pub fn submit_io_uring_timeout(&self, timeout_ns: u64, token: u64) {
        let sqe = IoUringSqe {
            opcode: io_uring::opcodes::IORING_OP_TIMEOUT,
            off: timeout_ns,
            user_data: token,
            ..Default::default()
        };
        self.io_uring.submit_sqe(sqe);
    }

    /// Cancel an active registered io_uring timeout by target token.
    pub fn cancel_io_uring_timeout(&self, target_token: u64, cancel_token: u64) {
        let sqe = IoUringSqe {
            opcode: io_uring::opcodes::IORING_OP_TIMEOUT_REMOVE,
            addr: target_token,
            user_data: cancel_token,
            ..Default::default()
        };
        self.io_uring.submit_sqe(sqe);
    }

    /// Submit an asynchronous socket or file poll via io_uring with the specified event token.
    pub fn submit_io_uring_poll(&self, fd: i32, events: u32, token: u64) {
        let sqe = IoUringSqe {
            opcode: io_uring::opcodes::IORING_OP_POLL_ADD,
            fd,
            len: events,
            user_data: token,
            ..Default::default()
        };
        self.io_uring.submit_sqe(sqe);
    }

    /// Cancel an active registered io_uring poll by target token.
    pub fn cancel_io_uring_poll(&self, target_token: u64, cancel_token: u64) {
        let sqe = IoUringSqe {
            opcode: io_uring::opcodes::IORING_OP_POLL_REMOVE,
            addr: target_token,
            user_data: cancel_token,
            ..Default::default()
        };
        self.io_uring.submit_sqe(sqe);
    }

    /// Submit an asynchronous Windows IOCP read completion event.
    pub fn submit_iocp_read(&self, port_key: usize, _buf: *mut u8, len: u32, token: u64) {
        let _ = self.iocp.post_completion(port_key, len, token, 0);
        crate::fiber::GLOBAL_SCHEDULER.notify_work();
    }

    /// Submit an asynchronous Windows IOCP write completion event.
    pub fn submit_iocp_write(&self, port_key: usize, _buf: *const u8, len: u32, token: u64) {
        let _ = self.iocp.post_completion(port_key, len, token, 0);
        crate::fiber::GLOBAL_SCHEDULER.notify_work();
    }

    /// Poll kernel completion queues (io_uring CQEs & IOCP packets) without blocking,
    /// waking all matching suspended fibers in the global M:N scheduler.
    pub fn poll_and_wake(&self) -> usize {
        let mut total_woken = 0;

        // 1. Flush io_uring submission ring and collect CQEs
        let _ = self.io_uring.enter(0);
        for cqe in self.io_uring.drain_completed_cqes() {
            if cqe.user_data != 0
                && crate::fiber::GLOBAL_SCHEDULER.wake_io(cqe.user_data, cqe.res as i64)
            {
                total_woken += 1;
            }
        }

        // 2. Collect IOCP packets
        for packet in self.iocp.drain_completed_packets() {
            if packet.user_data != 0 {
                let res = if packet.status == 0 {
                    packet.bytes_transferred as i64
                } else {
                    -(packet.status as i64)
                };
                if crate::fiber::GLOBAL_SCHEDULER.wake_io(packet.user_data, res) {
                    total_woken += 1;
                }
            }
        }

        while let Some(packet) = self.iocp.poll_completion(0) {
            if packet.user_data != 0 {
                let res = if packet.status == 0 {
                    packet.bytes_transferred as i64
                } else {
                    -(packet.status as i64)
                };
                if crate::fiber::GLOBAL_SCHEDULER.wake_io(packet.user_data, res) {
                    total_woken += 1;
                }
            }
        }

        total_woken
    }

    /// Wait with timeout for asynchronous completions from io_uring or IOCP, waking fibers.
    pub fn wait_and_wake(&self, timeout: std::time::Duration) -> usize {
        let mut total = self.poll_and_wake();
        if total > 0 {
            return total;
        }

        #[cfg(target_os = "linux")]
        if self.io_uring.is_available() {
            let _ = self.io_uring.enter(1);
            for cqe in self.io_uring.drain_completed_cqes() {
                if cqe.user_data != 0
                    && crate::fiber::GLOBAL_SCHEDULER.wake_io(cqe.user_data, cqe.res as i64)
                {
                    total += 1;
                }
            }
            if total > 0 {
                return total;
            }
        }

        #[cfg(target_os = "windows")]
        if self.iocp.is_active() {
            let timeout_ms = timeout.as_millis().min(u32::MAX as u128) as u32;
            if let Some(packet) = self.iocp.poll_completion(timeout_ms) {
                if packet.user_data != 0 {
                    let res = if packet.status == 0 {
                        packet.bytes_transferred as i64
                    } else {
                        -(packet.status as i64)
                    };
                    if crate::fiber::GLOBAL_SCHEDULER.wake_io(packet.user_data, res) {
                        total += 1;
                    }
                }
            }
            if total > 0 {
                return total;
            }
        }

        let start = std::time::Instant::now();
        while total == 0 && start.elapsed() < timeout {
            std::thread::sleep(std::time::Duration::from_micros(100));
            total += self.poll_and_wake();
        }

        total
    }

    /// Bind a new async TCP listener.
    pub fn tcp_listen(&self, port: u16) -> std::io::Result<i32> {
        let addr = format!("0.0.0.0:{}", port);
        let listener = AsyncTcpListener::bind(&addr)?;
        let id = self.next_handle_id.fetch_add(1, Ordering::Relaxed);
        let mut map = self.listeners.lock().unwrap();
        map.insert(id, listener);
        Ok(id)
    }

    /// Accept a new connection on an async TCP listener.
    pub fn tcp_accept(&self, listener_id: i32) -> std::io::Result<i32> {
        let (stream, _peer) = {
            let map = self.listeners.lock().unwrap();
            let listener = map.get(&listener_id).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "listener not found")
            })?;
            listener.accept()?
        };

        let stream_id = self.next_handle_id.fetch_add(1, Ordering::Relaxed);
        let mut map = self.streams.lock().unwrap();
        map.insert(stream_id, stream);
        Ok(stream_id)
    }

    /// Connect to remote host and port.
    pub fn tcp_connect(&self, host: &str, port: u16) -> std::io::Result<i32> {
        let addr = format!("{}:{}", host, port);
        let stream = AsyncTcpStream::connect(&addr)?;
        let stream_id = self.next_handle_id.fetch_add(1, Ordering::Relaxed);
        let mut map = self.streams.lock().unwrap();
        map.insert(stream_id, stream);
        Ok(stream_id)
    }

    /// Read data from stream into buffer.
    pub fn read(&self, stream_id: i32, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut map = self.streams.lock().unwrap();
        let stream = map
            .get_mut(&stream_id)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "stream not found"))?;
        stream.read(buf)
    }

    /// Write all data to stream.
    pub fn write_all(&self, stream_id: i32, buf: &[u8]) -> std::io::Result<()> {
        let mut map = self.streams.lock().unwrap();
        let stream = map
            .get_mut(&stream_id)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "stream not found"))?;
        stream.write_all(buf)
    }

    /// Close listener or stream.
    pub fn close(&self, handle_id: i32) -> bool {
        let mut listeners = self.listeners.lock().unwrap();
        if listeners.remove(&handle_id).is_some() {
            return true;
        }
        let mut streams = self.streams.lock().unwrap();
        streams.remove(&handle_id).is_some()
    }
}

impl Default for AsyncReactor {
    fn default() -> Self {
        Self::new()
    }
}

lazy_static::lazy_static! {
    /// Global Async Reactor instance driving colorless fiber I/O.
    pub static ref GLOBAL_REACTOR: AsyncReactor = AsyncReactor::new();
}

// ---------------------------------------------------------
// C-ABI FFI EXPORTS FOR IFA LANGUAGE AND FOREIGN CODE
// ---------------------------------------------------------

/// Check if Linux io_uring kernel backend is active.
#[no_mangle]
pub extern "C" fn ifa_rt_async_io_uring_supported() -> i32 {
    if GLOBAL_REACTOR.io_uring().is_available() {
        1
    } else {
        0
    }
}

/// Check if Windows IOCP kernel backend is active.
#[no_mangle]
pub extern "C" fn ifa_rt_async_iocp_supported() -> i32 {
    if GLOBAL_REACTOR.iocp().is_active() {
        1
    } else {
        0
    }
}

/// Cooperatively sleep the calling fiber for `millis` without blocking OS worker threads.
#[no_mangle]
pub extern "C" fn ifa_rt_async_sleep(millis: u64) {
    AsyncTimer::sleep(std::time::Duration::from_millis(millis));
}

/// Bind an asynchronous TCP listener on specified port.
/// Returns positive handle descriptor on success, negative error code on failure.
#[no_mangle]
pub extern "C" fn ifa_rt_async_tcp_listen(port: u16, _backlog: i32) -> i32 {
    GLOBAL_REACTOR.tcp_listen(port).unwrap_or(-1)
}

/// Asynchronously accept a connection on a TCP listener handle.
/// Returns accepted stream handle descriptor on success, negative error code on failure.
#[no_mangle]
pub extern "C" fn ifa_rt_async_tcp_accept(listener_fd: i32) -> i32 {
    GLOBAL_REACTOR.tcp_accept(listener_fd).unwrap_or(-1)
}

/// Asynchronously connect to host and port.
#[no_mangle]
pub extern "C" fn ifa_rt_async_tcp_connect(host: *const u8, port: u16) -> i32 {
    if host.is_null() {
        return -1;
    }
    let host_str = unsafe {
        match std::ffi::CStr::from_ptr(host as *const std::ffi::c_char).to_str() {
            Ok(s) => s,
            Err(_) => return -1,
        }
    };

    GLOBAL_REACTOR.tcp_connect(host_str, port).unwrap_or(-1)
}

/// Asynchronously read from an active stream handle into buffer.
#[no_mangle]
pub extern "C" fn ifa_rt_async_read(stream_fd: i32, buf: *mut u8, len: usize) -> isize {
    if buf.is_null() || len == 0 {
        return 0;
    }
    let slice = unsafe { std::slice::from_raw_parts_mut(buf, len) };
    match GLOBAL_REACTOR.read(stream_fd, slice) {
        Ok(n) => n as isize,
        Err(_) => -1,
    }
}

/// Asynchronously write to an active stream handle from buffer.
#[no_mangle]
pub extern "C" fn ifa_rt_async_write(stream_fd: i32, buf: *const u8, len: usize) -> isize {
    if buf.is_null() || len == 0 {
        return 0;
    }
    let slice = unsafe { std::slice::from_raw_parts(buf, len) };
    match GLOBAL_REACTOR.write_all(stream_fd, slice) {
        Ok(()) => len as isize,
        Err(_) => -1,
    }
}

/// Close an active async stream or listener handle.
#[no_mangle]
pub extern "C" fn ifa_rt_async_close(handle_fd: i32) -> i32 {
    if GLOBAL_REACTOR.close(handle_fd) {
        0
    } else {
        -1
    }
}

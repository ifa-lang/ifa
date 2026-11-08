//! Windows I/O Completion Ports (`IOCP`) connector.
//!
//! Provides kernel-level completion rings for scalable, non-blocking asynchronous
//! network and file I/O driving IFA colorless fibers under Windows.

use std::sync::atomic::{AtomicBool, Ordering};

/// Type of asynchronous I/O operation queued in the IOCP port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IocpOpCode {
    Read,
    Write,
    Accept,
    Connect,
    Close,
}

/// Overlapped completion packet tracked by the IOCP engine.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IocpCompletionPacket {
    pub key: usize,
    pub bytes_transferred: u32,
    pub user_data: u64,
    pub status: i32,
}

/// Windows I/O Completion Port Connector.
pub struct IocpConnector {
    #[allow(dead_code)]
    port_handle: usize,
    is_active: AtomicBool,
    #[allow(dead_code)]
    pending_queue: std::sync::Mutex<Vec<(IocpOpCode, usize, u64)>>,
    completion_queue: std::sync::Mutex<Vec<IocpCompletionPacket>>,
}

impl IocpConnector {
    /// Initialize a new IOCP completion connector.
    pub fn new(_concurrency: u32) -> Self {
        #[cfg(target_os = "windows")]
        {
            let handle = unsafe {
                windows_sys::Win32::System::IO::CreateIoCompletionPort(
                    windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE,
                    0,
                    0,
                    _concurrency,
                )
            };
            if handle != 0 {
                return Self {
                    port_handle: handle as usize,
                    is_active: AtomicBool::new(true),
                    pending_queue: std::sync::Mutex::new(Vec::new()),
                    completion_queue: std::sync::Mutex::new(Vec::new()),
                };
            }
        }

        Self {
            port_handle: 0,
            is_active: AtomicBool::new(false),
            pending_queue: std::sync::Mutex::new(Vec::new()),
            completion_queue: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Whether native Windows IOCP is active.
    pub fn is_active(&self) -> bool {
        self.is_active.load(Ordering::Relaxed)
    }

    /// Post an asynchronous completion packet directly to the completion port.
    pub fn post_completion(&self, key: usize, bytes: u32, user_data: u64, status: i32) -> bool {
        #[cfg(target_os = "windows")]
        if self.is_active() {
            let res = unsafe {
                windows_sys::Win32::System::IO::PostQueuedCompletionStatus(
                    self.port_handle as _,
                    bytes,
                    key,
                    user_data as _,
                )
            };
            return res != 0;
        }

        let mut queue = self.completion_queue.lock().unwrap();
        queue.push(IocpCompletionPacket {
            key,
            bytes_transferred: bytes,
            user_data,
            status,
        });
        true
    }

    /// Wait for or poll completion packets from the completion port.
    pub fn poll_completion(&self, timeout_ms: u32) -> Option<IocpCompletionPacket> {
        #[cfg(target_os = "windows")]
        if self.is_active() {
            let mut bytes = 0u32;
            let mut key = 0usize;
            let mut overlapped = 0usize;
            let ok = unsafe {
                windows_sys::Win32::System::IO::GetQueuedCompletionStatus(
                    self.port_handle as _,
                    &mut bytes,
                    &mut key,
                    &mut overlapped as *mut usize as _,
                    timeout_ms,
                )
            };
            if ok != 0 {
                return Some(IocpCompletionPacket {
                    key,
                    bytes_transferred: bytes,
                    user_data: overlapped as u64,
                    status: 0,
                });
            } else {
                return None;
            }
        }

        let _ = timeout_ms;
        let mut queue = self.completion_queue.lock().unwrap();
        if queue.is_empty() {
            None
        } else {
            Some(queue.remove(0))
        }
    }

    /// Drain all completed IOCP packets currently queued in software emulation or local ring.
    pub fn drain_completed_packets(&self) -> Vec<IocpCompletionPacket> {
        let mut queue = self.completion_queue.lock().unwrap();
        std::mem::take(&mut *queue)
    }
}

impl Drop for IocpConnector {
    fn drop(&mut self) {
        #[cfg(target_os = "windows")]
        if self.port_handle != 0 {
            unsafe {
                windows_sys::Win32::Foundation::CloseHandle(self.port_handle as _);
            }
        }
    }
}

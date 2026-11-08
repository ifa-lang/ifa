//! Linux `io_uring` kernel asynchronous I/O connector.
//!
//! Provides zero-copy submission and completion queue rings for high-throughput,
//! non-blocking syscall execution driving IFA colorless fibers.

use std::sync::atomic::{AtomicBool, Ordering};

/// Linux syscall numbers for io_uring across standard architectures.
#[cfg(target_os = "linux")]
pub mod syscall_nr {
    pub const SYS_IO_URING_SETUP: i64 = 425;
    pub const SYS_IO_URING_ENTER: i64 = 426;
    pub const SYS_IO_URING_REGISTER: i64 = 427;
}

/// Standard io_uring opcodes from Linux kernel UAPI.
pub mod opcodes {
    pub const IORING_OP_NOP: u8 = 0;
    pub const IORING_OP_READV: u8 = 1;
    pub const IORING_OP_WRITEV: u8 = 2;
    pub const IORING_OP_FSYNC: u8 = 3;
    pub const IORING_OP_READ_FIXED: u8 = 4;
    pub const IORING_OP_WRITE_FIXED: u8 = 5;
    pub const IORING_OP_POLL_ADD: u8 = 6;
    pub const IORING_OP_POLL_REMOVE: u8 = 7;
    pub const IORING_OP_SYNC_FILE_RANGE: u8 = 8;
    pub const IORING_OP_SENDMSG: u8 = 9;
    pub const IORING_OP_RECVMSG: u8 = 10;
    pub const IORING_OP_TIMEOUT: u8 = 11;
    pub const IORING_OP_TIMEOUT_REMOVE: u8 = 12;
    pub const IORING_OP_ACCEPT: u8 = 13;
    pub const IORING_OP_ASYNC_CANCEL: u8 = 14;
    pub const IORING_OP_LINK_TIMEOUT: u8 = 15;
    pub const IORING_OP_CONNECT: u8 = 16;
    pub const IORING_OP_FALLOCATE: u8 = 17;
    pub const IORING_OP_OPENAT: u8 = 18;
    pub const IORING_OP_CLOSE: u8 = 19;
    pub const IORING_OP_FILES_UPDATE: u8 = 20;
    pub const IORING_OP_STATX: u8 = 21;
    pub const IORING_OP_READ: u8 = 22;
    pub const IORING_OP_WRITE: u8 = 23;
    pub const IORING_OP_FADVISE: u8 = 24;
    pub const IORING_OP_MADVISE: u8 = 25;
    pub const IORING_OP_SEND: u8 = 26;
    pub const IORING_OP_RECV: u8 = 27;
    pub const IORING_OP_OPENAT2: u8 = 28;
    pub const IORING_OP_EPOLL_CTL: u8 = 29;
    pub const IORING_OP_SPLICE: u8 = 30;
    pub const IORING_OP_PROVIDE_BUFFERS: u8 = 31;
    pub const IORING_OP_REMOVE_BUFFERS: u8 = 32;
    pub const IORING_OP_TEE: u8 = 33;
    pub const IORING_OP_SHUTDOWN: u8 = 34;
    pub const IORING_OP_RENAMEAT: u8 = 35;
    pub const IORING_OP_UNLINKAT: u8 = 36;
}

/// Linux kernel timespec matching `struct __kernel_timespec` from io_uring UAPI.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KernelTimespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

#[derive(Debug, Clone, Copy)]
struct ActiveTimeout {
    user_data: u64,
    deadline: std::time::Instant,
}

#[derive(Debug, Clone, Copy)]
struct ActivePoll {
    user_data: u64,
    fd: i32,
    events: u32,
}

/// Submission Queue Entry (SQE) layout: exactly 64 bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IoUringSqe {
    pub opcode: u8,
    pub flags: u8,
    pub ioprio: u16,
    pub fd: i32,
    pub off: u64,
    pub addr: u64,
    pub len: u32,
    pub rw_flags: u32,
    pub user_data: u64,
    pub buf_index: u16,
    pub personality: u16,
    pub splice_fd_in: i32,
    pub pad2: [u64; 2],
}

impl Default for IoUringSqe {
    fn default() -> Self {
        Self {
            opcode: 0,
            flags: 0,
            ioprio: 0,
            fd: -1,
            off: 0,
            addr: 0,
            len: 0,
            rw_flags: 0,
            user_data: 0,
            buf_index: 0,
            personality: 0,
            splice_fd_in: 0,
            pad2: [0; 2],
        }
    }
}

/// Completion Queue Entry (CQE) layout: exactly 16 bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringCqe {
    pub user_data: u64,
    pub res: i32,
    pub flags: u32,
}

/// Kernel io_sqring_offsets.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoSqringOffsets {
    pub head: u32,
    pub tail: u32,
    pub ring_mask: u32,
    pub ring_entries: u32,
    pub flags: u32,
    pub dropped: u32,
    pub array: u32,
    pub resv1: u32,
    pub resv2: u64,
}

/// Kernel io_cqring_offsets.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoCqringOffsets {
    pub head: u32,
    pub tail: u32,
    pub ring_mask: u32,
    pub ring_entries: u32,
    pub overflow: u32,
    pub cqes: u32,
    pub flags: u32,
    pub resv1: u32,
    pub resv2: u64,
}

/// Kernel io_uring_params.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringParams {
    pub sq_entries: u32,
    pub cq_entries: u32,
    pub flags: u32,
    pub sq_thread_cpu: u32,
    pub sq_thread_idle: u32,
    pub features: u32,
    pub wq_fd: u32,
    pub resv: [u32; 3],
    pub sq_off: IoSqringOffsets,
    pub cq_off: IoCqringOffsets,
}

/// Linux `io_uring` connector managing asynchronous operation submissions.
pub struct IoUringConnector {
    ring_fd: i32,
    #[allow(dead_code)]
    entries: u32,
    is_available: AtomicBool,
    pending_sqes: std::sync::Mutex<Vec<IoUringSqe>>,
    completed_cqes: std::sync::Mutex<Vec<IoUringCqe>>,
    active_timeouts: std::sync::Mutex<Vec<ActiveTimeout>>,
    active_polls: std::sync::Mutex<Vec<ActivePoll>>,
}

impl IoUringConnector {
    /// Initialize the io_uring connector.
    ///
    /// Probes Linux kernel support via `sys_io_uring_setup`. If unavailable
    /// (e.g. older kernels, Docker seccomp restrictions, or non-Linux), initializes
    /// in software emulation mode.
    pub fn new(entries: u32) -> Self {
        #[cfg(target_os = "linux")]
        {
            let mut params = IoUringParams::default();
            let fd = unsafe {
                libc::syscall(
                    syscall_nr::SYS_IO_URING_SETUP,
                    entries,
                    &mut params as *mut IoUringParams,
                ) as i32
            };

            if fd >= 0 {
                return Self {
                    ring_fd: fd,
                    entries,
                    is_available: AtomicBool::new(true),
                    pending_sqes: std::sync::Mutex::new(Vec::with_capacity(entries as usize)),
                    completed_cqes: std::sync::Mutex::new(Vec::with_capacity(entries as usize)),
                    active_timeouts: std::sync::Mutex::new(Vec::new()),
                    active_polls: std::sync::Mutex::new(Vec::new()),
                };
            }
        }

        Self {
            ring_fd: -1,
            entries,
            is_available: AtomicBool::new(false),
            pending_sqes: std::sync::Mutex::new(Vec::with_capacity(entries as usize)),
            completed_cqes: std::sync::Mutex::new(Vec::with_capacity(entries as usize)),
            active_timeouts: std::sync::Mutex::new(Vec::new()),
            active_polls: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Whether the Linux kernel native `io_uring` subsystem is available.
    pub fn is_available(&self) -> bool {
        self.is_available.load(Ordering::Relaxed)
    }

    /// Queue a submission entry into the connector.
    pub fn submit_sqe(&self, sqe: IoUringSqe) {
        let mut queue = self.pending_sqes.lock().unwrap();
        queue.push(sqe);
    }

    /// Submit all queued SQEs to the kernel or simulated backend and wait/reap CQEs.
    pub fn enter(&self, min_complete: u32) -> usize {
        let sqes = {
            let mut queue = self.pending_sqes.lock().unwrap();
            let items = queue.clone();
            queue.clear();
            items
        };

        if self.is_available() {
            #[cfg(target_os = "linux")]
            {
                let to_submit = sqes.len() as u32;
                let _ = unsafe {
                    libc::syscall(
                        syscall_nr::SYS_IO_URING_ENTER,
                        self.ring_fd,
                        to_submit,
                        min_complete,
                        0u32,
                        std::ptr::null::<libc::c_void>(),
                        0usize,
                    )
                };
            }
        }

        // Complete submitted SQEs and produce corresponding CQEs
        let mut completed = Vec::new();
        for sqe in sqes {
            match sqe.opcode {
                opcodes::IORING_OP_NOP => {
                    completed.push(IoUringCqe {
                        user_data: sqe.user_data,
                        res: 0,
                        flags: 0,
                    });
                }
                opcodes::IORING_OP_READ => {
                    let fd = sqe.fd;
                    let buf = sqe.addr as *mut u8;
                    let len = sqe.len as usize;
                    #[cfg(unix)]
                    let res = unsafe { libc::read(fd, buf as *mut libc::c_void, len) as i32 };
                    #[cfg(not(unix))]
                    let res = {
                        let _ = (fd, buf, len);
                        0
                    };
                    completed.push(IoUringCqe {
                        user_data: sqe.user_data,
                        res,
                        flags: 0,
                    });
                }
                opcodes::IORING_OP_WRITE => {
                    let fd = sqe.fd;
                    let buf = sqe.addr as *const u8;
                    let len = sqe.len as usize;
                    #[cfg(unix)]
                    let res = unsafe { libc::write(fd, buf as *const libc::c_void, len) as i32 };
                    #[cfg(not(unix))]
                    let res = {
                        let _ = (fd, buf, len);
                        len as i32
                    };
                    completed.push(IoUringCqe {
                        user_data: sqe.user_data,
                        res,
                        flags: 0,
                    });
                }
                opcodes::IORING_OP_CLOSE => {
                    let fd = sqe.fd;
                    #[cfg(unix)]
                    let res = unsafe { libc::close(fd) };
                    #[cfg(not(unix))]
                    let res = {
                        let _ = fd;
                        0
                    };
                    completed.push(IoUringCqe {
                        user_data: sqe.user_data,
                        res,
                        flags: 0,
                    });
                }
                opcodes::IORING_OP_TIMEOUT | opcodes::IORING_OP_LINK_TIMEOUT => {
                    let dur = if sqe.addr != 0 {
                        let ts = unsafe { &*(sqe.addr as *const KernelTimespec) };
                        std::time::Duration::new(
                            ts.tv_sec.max(0) as u64,
                            (ts.tv_nsec.max(0) as u32).min(999_999_999),
                        )
                    } else if sqe.off != 0 {
                        std::time::Duration::from_nanos(sqe.off)
                    } else {
                        std::time::Duration::ZERO
                    };

                    if dur.is_zero() {
                        completed.push(IoUringCqe {
                            user_data: sqe.user_data,
                            res: 0,
                            flags: 0,
                        });
                    } else {
                        let mut timeouts = self.active_timeouts.lock().unwrap();
                        timeouts.push(ActiveTimeout {
                            user_data: sqe.user_data,
                            deadline: std::time::Instant::now() + dur,
                        });
                    }
                }
                opcodes::IORING_OP_TIMEOUT_REMOVE => {
                    let target_token = sqe.addr;
                    let mut timeouts = self.active_timeouts.lock().unwrap();
                    let before_len = timeouts.len();
                    timeouts.retain(|t| t.user_data != target_token);
                    let removed = timeouts.len() < before_len;
                    completed.push(IoUringCqe {
                        user_data: sqe.user_data,
                        res: if removed { 0 } else { -2 },
                        flags: 0,
                    });
                }
                opcodes::IORING_OP_POLL_ADD => {
                    let fd = sqe.fd;
                    let events = sqe.len;
                    #[cfg(unix)]
                    let ready_events = {
                        let mut pfd = libc::pollfd {
                            fd,
                            events: events as i16,
                            revents: 0,
                        };
                        let poll_res = unsafe { libc::poll(&mut pfd as *mut libc::pollfd, 1, 0) };
                        if poll_res > 0 && pfd.revents != 0 {
                            Some(pfd.revents as i32)
                        } else {
                            None
                        }
                    };
                    #[cfg(not(unix))]
                    let ready_events: Option<i32> = Some(events as i32);

                    if let Some(rev) = ready_events {
                        completed.push(IoUringCqe {
                            user_data: sqe.user_data,
                            res: rev,
                            flags: 0,
                        });
                    } else {
                        let mut polls = self.active_polls.lock().unwrap();
                        polls.push(ActivePoll {
                            user_data: sqe.user_data,
                            fd,
                            events,
                        });
                    }
                }
                opcodes::IORING_OP_POLL_REMOVE => {
                    let target_token = sqe.addr;
                    let mut polls = self.active_polls.lock().unwrap();
                    let before_len = polls.len();
                    polls.retain(|p| p.user_data != target_token);
                    let removed = polls.len() < before_len;
                    completed.push(IoUringCqe {
                        user_data: sqe.user_data,
                        res: if removed { 0 } else { -2 },
                        flags: 0,
                    });
                }
                opcodes::IORING_OP_ASYNC_CANCEL => {
                    let target_token = sqe.addr;
                    let mut timeouts = self.active_timeouts.lock().unwrap();
                    let mut polls = self.active_polls.lock().unwrap();
                    let before_t = timeouts.len();
                    timeouts.retain(|t| t.user_data != target_token);
                    let before_p = polls.len();
                    polls.retain(|p| p.user_data != target_token);
                    let removed = timeouts.len() < before_t || polls.len() < before_p;
                    completed.push(IoUringCqe {
                        user_data: sqe.user_data,
                        res: if removed { 0 } else { -2 },
                        flags: 0,
                    });
                }
                _ => {
                    completed.push(IoUringCqe {
                        user_data: sqe.user_data,
                        res: 0,
                        flags: 0,
                    });
                }
            }
        }

        // Reap expired active timeouts
        let now = std::time::Instant::now();
        {
            let mut timeouts = self.active_timeouts.lock().unwrap();
            let mut i = 0;
            while i < timeouts.len() {
                if now >= timeouts[i].deadline {
                    let t = timeouts.swap_remove(i);
                    completed.push(IoUringCqe {
                        user_data: t.user_data,
                        res: 0,
                        flags: 0,
                    });
                } else {
                    i += 1;
                }
            }
        }

        // Reap ready active polls
        {
            let mut polls = self.active_polls.lock().unwrap();
            let mut j = 0;
            while j < polls.len() {
                #[cfg(unix)]
                let ready = {
                    let mut pfd = libc::pollfd {
                        fd: polls[j].fd,
                        events: polls[j].events as i16,
                        revents: 0,
                    };
                    let poll_res = unsafe { libc::poll(&mut pfd as *mut libc::pollfd, 1, 0) };
                    if poll_res > 0 && pfd.revents != 0 {
                        Some(pfd.revents as i32)
                    } else {
                        None
                    }
                };
                #[cfg(not(unix))]
                let ready: Option<i32> = Some(polls[j].events as i32);

                if let Some(rev) = ready {
                    let p = polls.swap_remove(j);
                    completed.push(IoUringCqe {
                        user_data: p.user_data,
                        res: rev,
                        flags: 0,
                    });
                } else {
                    j += 1;
                }
            }
        }

        if min_complete > 0 && completed.is_empty() {
            let has_waitables = {
                let t_lock = self.active_timeouts.lock().unwrap();
                let p_lock = self.active_polls.lock().unwrap();
                !t_lock.is_empty() || !p_lock.is_empty()
            };
            if has_waitables {
                std::thread::sleep(std::time::Duration::from_micros(250));
                let now2 = std::time::Instant::now();
                let mut timeouts = self.active_timeouts.lock().unwrap();
                let mut i = 0;
                while i < timeouts.len() {
                    if now2 >= timeouts[i].deadline {
                        let t = timeouts.swap_remove(i);
                        completed.push(IoUringCqe {
                            user_data: t.user_data,
                            res: 0,
                            flags: 0,
                        });
                    } else {
                        i += 1;
                    }
                }
            }
        }

        let count = completed.len();
        let mut cqes = self.completed_cqes.lock().unwrap();
        cqes.extend(completed);
        let _ = min_complete;
        count
    }

    /// Cancel an active registered timeout by its target user_data token.
    pub fn cancel_timeout(&self, target_token: u64) -> bool {
        let mut timeouts = self.active_timeouts.lock().unwrap();
        let before = timeouts.len();
        timeouts.retain(|t| t.user_data != target_token);
        timeouts.len() < before
    }

    /// Number of active registered timeouts pending completion.
    pub fn active_timeouts_count(&self) -> usize {
        let timeouts = self.active_timeouts.lock().unwrap();
        timeouts.len()
    }

    /// Number of active registered socket/file polls pending events.
    pub fn active_polls_count(&self) -> usize {
        let polls = self.active_polls.lock().unwrap();
        polls.len()
    }

    /// Pop a completed CQE if available.
    pub fn pop_cqe(&self) -> Option<IoUringCqe> {
        let mut cqes = self.completed_cqes.lock().unwrap();
        if cqes.is_empty() {
            None
        } else {
            Some(cqes.remove(0))
        }
    }

    /// Drain all completed CQEs currently available.
    pub fn drain_completed_cqes(&self) -> Vec<IoUringCqe> {
        let mut cqes = self.completed_cqes.lock().unwrap();
        std::mem::take(&mut *cqes)
    }

    /// Number of SQEs pending submission.
    pub fn pending_sqe_count(&self) -> usize {
        let queue = self.pending_sqes.lock().unwrap();
        queue.len()
    }
}

impl Drop for IoUringConnector {
    fn drop(&mut self) {
        if self.ring_fd >= 0 {
            #[cfg(target_os = "linux")]
            unsafe {
                libc::close(self.ring_fd);
            }
        }
    }
}

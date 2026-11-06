//! WebAssembly System Interface (WASI) and headless runtime support (Wasmtime / Wasmer).
//!
//! Provides non-blocking fiber scheduling and zero-GC cooperative stream I/O
//! for serverless, edge, and standalone WebAssembly deployments.

#![allow(clippy::not_unsafe_ptr_arg_deref)]

use crate::fiber::GLOBAL_SCHEDULER;
use std::io::{self, Read, Write};

/// Run a single step of the WASI cooperative fiber event loop.
///
/// Returns 1 if a fiber was executed, or 0 if no runnable fibers are waiting.
#[no_mangle]
pub extern "C" fn ifa_rt_wasi_step() -> i32 {
    if GLOBAL_SCHEDULER.step() {
        1
    } else {
        0
    }
}

/// Run all waiting fibers in the cooperative scheduler until the queue is completely drained.
#[no_mangle]
pub extern "C" fn ifa_rt_wasi_run_all() {
    GLOBAL_SCHEDULER.run_until_idle();
}

/// Non-blocking read from a standard stream (0 = stdin).
///
/// If data is not immediately available, yields the calling fiber cooperatively.
#[no_mangle]
pub extern "C" fn ifa_rt_wasi_read_nonblocking(fd: i32, buffer: *mut u8, max_len: usize) -> isize {
    if buffer.is_null() || max_len == 0 {
        return 0;
    }

    match fd {
        0 => {
            let stdin = io::stdin();
            let mut handle = stdin.lock();
            let slice = unsafe { std::slice::from_raw_parts_mut(buffer, max_len) };
            match handle.read(slice) {
                Ok(n) => n as isize,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    GLOBAL_SCHEDULER.yield_now();
                    -1 // Indicating non-blocking yield requested
                }
                Err(_) => -1,
            }
        }
        _ => -1,
    }
}

/// Non-blocking write to standard output or error (1 = stdout, 2 = stderr).
#[no_mangle]
pub extern "C" fn ifa_rt_wasi_write_nonblocking(fd: i32, buffer: *const u8, len: usize) -> isize {
    if buffer.is_null() || len == 0 {
        return 0;
    }

    let slice = unsafe { std::slice::from_raw_parts(buffer, len) };

    match fd {
        1 => {
            let stdout = io::stdout();
            let mut handle = stdout.lock();
            match handle.write_all(slice) {
                Ok(_) => {
                    let _ = handle.flush();
                    len as isize
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    GLOBAL_SCHEDULER.yield_now();
                    -1
                }
                Err(_) => -1,
            }
        }
        2 => {
            let stderr = io::stderr();
            let mut handle = stderr.lock();
            match handle.write_all(slice) {
                Ok(_) => {
                    let _ = handle.flush();
                    len as isize
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    GLOBAL_SCHEDULER.yield_now();
                    -1
                }
                Err(_) => -1,
            }
        }
        _ => -1,
    }
}

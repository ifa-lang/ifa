//! Standard stream I/O runtime functions (`std::io`).

#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::ffi::CStr;
use std::io::{self, BufRead, Write};

/// Print a null-terminated UTF-8 string to standard output.
pub fn rt_print(ptr: *const u8) {
    if !ptr.is_null() {
        unsafe {
            if let Ok(s) = CStr::from_ptr(ptr as *const std::ffi::c_char).to_str() {
                print!("{}", s);
                let _ = io::stdout().flush();
            }
        }
    }
}

/// Print a null-terminated UTF-8 string followed by a newline to standard output.
pub fn rt_println(ptr: *const u8) {
    if !ptr.is_null() {
        unsafe {
            if let Ok(s) = CStr::from_ptr(ptr as *const std::ffi::c_char).to_str() {
                println!("{}", s);
            }
        }
    } else {
        println!();
    }
}

/// Print a 64-bit integer to standard output.
pub fn rt_print_i64(n: i64) {
    print!("{}", n);
    let _ = io::stdout().flush();
}

/// Print a 64-bit integer followed by a newline to standard output.
pub fn rt_println_i64(n: i64) {
    println!("{}", n);
}

/// Print a 64-bit floating point number to standard output.
pub fn rt_print_f64(v: f64) {
    print!("{}", v);
    let _ = io::stdout().flush();
}

/// Print a 64-bit floating point number followed by a newline to standard output.
pub fn rt_println_f64(v: f64) {
    println!("{}", v);
}

/// Read a line from standard input into a raw byte buffer.
pub fn rt_read_line(buffer: *mut u8, max_len: usize) -> usize {
    if buffer.is_null() || max_len == 0 {
        return 0;
    }

    let stdin = io::stdin();
    let mut handle = stdin.lock();
    let mut line = String::new();
    if handle.read_line(&mut line).is_err() {
        return 0;
    }

    let bytes = line.as_bytes();
    let copy_len = bytes.len().min(max_len - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer, copy_len);
        *buffer.add(copy_len) = 0; // null-terminator
    }

    copy_len
}

/// Flush standard output.
pub fn rt_flush() {
    let _ = io::stdout().flush();
}

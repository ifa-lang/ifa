//! C-ABI Foreign Function Interface exports for native execution and PHP 8.4+ / Symfony 8.1 FFI.

#![allow(clippy::not_unsafe_ptr_arg_deref)]

use crate::allocator::GLOBAL_ALLOCATOR;
use crate::fiber::{Channel, TryRecvError, TrySendError, GLOBAL_SCHEDULER};
use crate::header::GenHeader;

/// Allocate a generational memory slot.
///
/// Returns a pointer directly to the payload, preceded by the 64-bit `GenHeader`.
#[no_mangle]
pub extern "C" fn ifa_rt_gen_alloc(size: usize, align: usize, arena_id: u16) -> *mut u8 {
    GLOBAL_ALLOCATOR.alloc(size, align, arena_id)
}

/// Deallocate an active generational memory slot, incrementing generation counter.
#[no_mangle]
pub extern "C" fn ifa_rt_gen_free(ptr: *mut u8) {
    GLOBAL_ALLOCATOR.free(ptr);
}

/// 1-cycle CPU generation check: aborts safely on Use-After-Free detection.
#[no_mangle]
pub extern "C" fn ifa_rt_gen_check(ptr: *const u8, remembered_gen: u32) {
    if ptr.is_null() {
        ifa_rt_panic_null_ref();
    }
    unsafe {
        let header = &*(ptr.sub(std::mem::size_of::<GenHeader>()) as *const GenHeader);
        if !header.is_active() || header.generation_counter != remembered_gen {
            ifa_rt_panic_uaf(ptr, remembered_gen, header.generation_counter);
        }
    }
}

/// Intercept and abort program on detected Use-After-Free without memory corruption.
#[no_mangle]
pub extern "C" fn ifa_rt_panic_uaf(ptr: *const u8, expected_gen: u32, actual_gen: u32) -> ! {
    eprintln!(
        "\n[IFA RUNTIME ERROR: SAFE INTERCEPTION]\n\
         Use-After-Free attempt detected on slot address {:p}!\n\
         Expected generation: {}\n\
         Actual current generation: {}\n\
         Execution terminated deterministically before memory corruption.\n",
        ptr, expected_gen, actual_gen
    );
    std::process::abort();
}

/// Intercept and abort program on detected Double-Free.
#[no_mangle]
pub extern "C" fn ifa_rt_panic_double_free(ptr: *const u8) -> ! {
    eprintln!(
        "\n[IFA RUNTIME ERROR: SAFE INTERCEPTION]\n\
         Double-free attempt detected on slot address {:p}!\n\
         Execution terminated deterministically before memory corruption.\n",
        ptr
    );
    std::process::abort();
}

/// Intercept null reference dereference.
#[no_mangle]
pub extern "C" fn ifa_rt_panic_null_ref() -> ! {
    eprintln!(
        "\n[IFA RUNTIME ERROR: SAFE INTERCEPTION]\n\
         Attempted to dereference a null generational reference!\n\
         Execution terminated deterministically.\n"
    );
    std::process::abort();
}

/// Create a new scoped generational arena.
#[no_mangle]
pub extern "C" fn ifa_rt_arena_create(_capacity: usize) -> u16 {
    GLOBAL_ALLOCATOR.create_arena()
}

/// Reset an arena, invalidating all contained generational references in O(1).
#[no_mangle]
pub extern "C" fn ifa_rt_arena_reset(arena_id: u16) {
    GLOBAL_ALLOCATOR.reset_arena(arena_id);
}

/// Destroy an arena.
#[no_mangle]
pub extern "C" fn ifa_rt_arena_destroy(arena_id: u16) {
    GLOBAL_ALLOCATOR.destroy_arena(arena_id);
}

/// Spawn a new colorless fiber running an `extern "C"` function pointer with argument.
#[no_mangle]
pub extern "C" fn ifa_rt_fiber_spawn(entry: extern "C" fn(*mut u8), arg: *mut u8) -> u64 {
    let arg_addr = arg as usize;
    GLOBAL_SCHEDULER.spawn(move || {
        let raw_arg = arg_addr as *mut u8;
        entry(raw_arg);
    })
}

/// Yield current execution slice to other ready fibers.
#[no_mangle]
pub extern "C" fn ifa_rt_fiber_yield() {
    GLOBAL_SCHEDULER.yield_now();
}

/// Wait for a fiber to complete execution.
#[no_mangle]
pub extern "C" fn ifa_rt_fiber_join(fiber_id: u64) {
    GLOBAL_SCHEDULER.join(fiber_id);
}

/// Print a null-terminated UTF-8 string.
#[no_mangle]
pub extern "C" fn ifa_rt_print(ptr: *const u8) {
    crate::io::rt_print(ptr);
}

/// Print a null-terminated UTF-8 string followed by newline.
#[no_mangle]
pub extern "C" fn ifa_rt_println(ptr: *const u8) {
    crate::io::rt_println(ptr);
}

/// Print a 64-bit integer.
#[no_mangle]
pub extern "C" fn ifa_rt_print_i64(n: i64) {
    crate::io::rt_print_i64(n);
}

/// Print a 64-bit integer followed by newline.
#[no_mangle]
pub extern "C" fn ifa_rt_println_i64(n: i64) {
    crate::io::rt_println_i64(n);
}

/// Binary C-ABI representation of an IFA Error Union result (`Error!T`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IfaErrorUnion {
    pub status: i64,
    pub value: *mut u8,
}

impl IfaErrorUnion {
    pub fn ok(payload: *mut u8) -> Self {
        Self {
            status: 0,
            value: payload,
        }
    }

    pub fn err(code: i64, payload: *mut u8) -> Self {
        Self {
            status: if code == 0 { 1 } else { code },
            value: payload,
        }
    }

    pub fn is_ok(&self) -> bool {
        self.status == 0
    }

    pub fn is_err(&self) -> bool {
        self.status != 0
    }
}

/// Opaque wrapper around an IFA runtime channel for C-ABI FFI.
pub struct IfaChannelHandle(pub(crate) Channel<*mut u8>);

/// Create a new channel for message passing between fibers and foreign threads.
/// Capacity 0 indicates unbounded; >0 indicates bounded atomic ring buffer.
#[no_mangle]
pub extern "C" fn ifa_rt_channel_create(capacity: usize) -> *mut IfaChannelHandle {
    let chan = if capacity == 0 {
        Channel::new()
    } else {
        Channel::with_capacity(capacity)
    };
    Box::into_raw(Box::new(IfaChannelHandle(chan)))
}

/// Destroy an IFA runtime channel handle and release allocated resources.
#[no_mangle]
pub extern "C" fn ifa_rt_channel_destroy(chan: *mut IfaChannelHandle) {
    if !chan.is_null() {
        unsafe {
            drop(Box::from_raw(chan));
        }
    }
}

/// Send a pointer value over the channel (blocks or yields fiber on backpressure).
/// Returns 0 on success, -1 if handle is null, -2 if channel is closed.
#[no_mangle]
pub extern "C" fn ifa_rt_channel_send(chan: *mut IfaChannelHandle, val: *mut u8) -> i32 {
    if chan.is_null() {
        return -1;
    }
    let handle = unsafe { &*chan };
    match handle.0.send_checked(val) {
        Ok(()) => 0,
        Err(_) => -2,
    }
}

/// Receive a pointer value from the channel (blocks or yields fiber until data arrives).
/// Returns 0 on success, -1 if invalid argument, -2 if channel is closed and empty.
#[no_mangle]
pub extern "C" fn ifa_rt_channel_recv(chan: *mut IfaChannelHandle, out_val: *mut *mut u8) -> i32 {
    if chan.is_null() || out_val.is_null() {
        return -1;
    }
    let handle = unsafe { &*chan };
    match handle.0.recv_checked() {
        Ok(val) => {
            unsafe {
                *out_val = val;
            }
            0
        }
        Err(_) => -2,
    }
}

/// Non-blocking send: returns 0 on success, 1 if channel is full, -1 if null handle, -2 if closed.
#[no_mangle]
pub extern "C" fn ifa_rt_channel_try_send(chan: *mut IfaChannelHandle, val: *mut u8) -> i32 {
    if chan.is_null() {
        return -1;
    }
    let handle = unsafe { &*chan };
    match handle.0.try_send_checked(val) {
        Ok(()) => 0,
        Err(TrySendError::Full(_)) => 1,
        Err(TrySendError::Closed(_)) => -2,
    }
}

/// Non-blocking receive: returns 0 on success, 1 if channel is empty, -1 if null, -2 if closed.
#[no_mangle]
pub extern "C" fn ifa_rt_channel_try_recv(
    chan: *mut IfaChannelHandle,
    out_val: *mut *mut u8,
) -> i32 {
    if chan.is_null() || out_val.is_null() {
        return -1;
    }
    let handle = unsafe { &*chan };
    match handle.0.try_recv_checked() {
        Ok(val) => {
            unsafe {
                *out_val = val;
            }
            0
        }
        Err(TryRecvError::Empty) => 1,
        Err(TryRecvError::Closed) => -2,
    }
}

/// Close the channel to reject new sends and unblock waiting receivers.
#[no_mangle]
pub extern "C" fn ifa_rt_channel_close(chan: *mut IfaChannelHandle) {
    if !chan.is_null() {
        let handle = unsafe { &*chan };
        handle.0.close();
    }
}

/// Check if channel is closed. Returns 1 if closed or null, 0 if active.
#[no_mangle]
pub extern "C" fn ifa_rt_channel_is_closed(chan: *mut IfaChannelHandle) -> i32 {
    if chan.is_null() {
        return 1;
    }
    let handle = unsafe { &*chan };
    if handle.0.is_closed() {
        1
    } else {
        0
    }
}

/// Non-blocking or cooperative select over an array of channels.
///
/// Returns:
/// - index >= 0: the index of the ready channel
/// - num_channels: if `has_default != 0` and no channel is ready
/// - -2: if all channels are closed
#[no_mangle]
pub extern "C" fn ifa_rt_channel_select(
    channels: *const *mut IfaChannelHandle,
    num_channels: usize,
    has_default: i32,
) -> i64 {
    if channels.is_null() || num_channels == 0 {
        return if has_default != 0 { 0 } else { -2 };
    }

    let chan_slice = unsafe { std::slice::from_raw_parts(channels, num_channels) };
    let mut spins: u32 = 0;

    loop {
        let mut any_open = false;
        for (idx, &handle_ptr) in chan_slice.iter().enumerate() {
            if handle_ptr.is_null() {
                continue;
            }
            let handle = unsafe { &*handle_ptr };
            if !handle.0.is_closed() {
                any_open = true;
            }
            if !handle.0.is_empty() {
                return idx as i64;
            }
        }

        if has_default != 0 {
            return num_channels as i64;
        }

        if !any_open {
            return -2;
        }

        spins += 1;
        if spins < 32 {
            std::hint::spin_loop();
        } else if spins < 64 {
            GLOBAL_SCHEDULER.yield_now();
        } else {
            std::thread::yield_now();
            spins = 32;
        }
    }
}

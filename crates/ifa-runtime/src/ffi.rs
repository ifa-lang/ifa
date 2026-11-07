//! C-ABI Foreign Function Interface exports for native execution and PHP 8.4+ / Symfony 8.1 FFI.

#![allow(clippy::not_unsafe_ptr_arg_deref)]

use crate::allocator::GLOBAL_ALLOCATOR;
use crate::fiber::{
    Channel, CoroDestroyFn, CoroResumeFn, CoroStatus, FiberId, TryRecvError, TrySendError,
    GLOBAL_SCHEDULER,
};
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

/// Assertion check: terminates with deterministic diagnostic if condition is false.
#[no_mangle]
pub extern "C" fn ifa_rt_assert(cond: bool, msg: *const u8) {
    if !cond {
        ifa_rt_panic_assert(msg);
    }
}

/// Assert two 64-bit integers are equal; aborts with detailed values on mismatch.
#[no_mangle]
pub extern "C" fn ifa_rt_assert_eq_i64(actual: i64, expected: i64, msg: *const u8) {
    if actual != expected {
        eprintln!(
            "\n[IFA ASSERTION FAILED: assert_eq]\n\
             Expected : {}\n\
             Actual   : {}\n",
            expected, actual
        );
        ifa_rt_panic_assert(msg);
    }
}

/// Assert two 64-bit integers are not equal; aborts on equality.
#[no_mangle]
pub extern "C" fn ifa_rt_assert_ne_i64(actual: i64, expected: i64, msg: *const u8) {
    if actual == expected {
        eprintln!(
            "\n[IFA ASSERTION FAILED: assert_ne]\n\
             Both values are equal: {}\n",
            actual
        );
        ifa_rt_panic_assert(msg);
    }
}

/// Intercept assertion failure with custom message.
#[no_mangle]
pub extern "C" fn ifa_rt_panic_assert(msg: *const u8) -> ! {
    if !msg.is_null() {
        let c_str = unsafe { std::ffi::CStr::from_ptr(msg as *const std::ffi::c_char) };
        if let Ok(s) = c_str.to_str() {
            eprintln!("\n[IFA RUNTIME ERROR: ASSERTION FAILED]\n{}\n", s);
        } else {
            eprintln!("\n[IFA RUNTIME ERROR: ASSERTION FAILED]\n");
        }
    } else {
        eprintln!("\n[IFA RUNTIME ERROR: ASSERTION FAILED]\n");
    }
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

/// Allocate memory directly in a specified generational arena.
#[no_mangle]
pub extern "C" fn ifa_rt_arena_alloc(arena_id: u16, size: usize, align: usize) -> *mut u8 {
    GLOBAL_ALLOCATOR.alloc(size, align.max(8), arena_id)
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

/// Opaque handle representing an allocated stackless native coroutine.
pub struct IfaCoroutine {
    pub frame: *mut u8,
    pub resume_fn: CoroResumeFn,
    pub destroy_fn: Option<CoroDestroyFn>,
    pub status: CoroStatus,
    pub fiber_id: Option<FiberId>,
}

unsafe impl Send for IfaCoroutine {}
unsafe impl Sync for IfaCoroutine {}

/// Create a stackless native coroutine with an allocated memory frame.
#[no_mangle]
pub extern "C" fn ifa_rt_coro_create(
    frame_size: usize,
    resume_fn: extern "C" fn(*mut u8) -> i32,
    destroy_fn: Option<extern "C" fn(*mut u8)>,
) -> *mut IfaCoroutine {
    let actual_size = frame_size.max(16);
    let frame = GLOBAL_ALLOCATOR.alloc(actual_size, 8, 0);
    unsafe {
        std::ptr::write_bytes(frame, 0, actual_size);
    }
    let coro = Box::new(IfaCoroutine {
        frame,
        resume_fn,
        destroy_fn,
        status: CoroStatus::Suspended,
        fiber_id: None,
    });
    Box::into_raw(coro)
}

/// Resume execution of a stackless coroutine for one cooperative step.
/// Returns CoroStatus as i32 (0 = Suspended, 1 = Completed, 2 = Panicked).
#[no_mangle]
pub extern "C" fn ifa_rt_coro_resume(coro: *mut IfaCoroutine) -> i32 {
    if coro.is_null() {
        return CoroStatus::Panicked as i32;
    }
    let c = unsafe { &mut *coro };
    if c.status == CoroStatus::Completed {
        return CoroStatus::Completed as i32;
    }
    let res = (c.resume_fn)(c.frame);
    if res == CoroStatus::Completed as i32 {
        c.status = CoroStatus::Completed;
    } else if res == CoroStatus::Suspended as i32 {
        c.status = CoroStatus::Suspended;
    } else {
        c.status = CoroStatus::Panicked;
    }
    res
}

/// Spawn a stackless coroutine into the global M:N scheduler for continuous cooperative execution.
/// Returns the assigned FiberId.
#[no_mangle]
pub extern "C" fn ifa_rt_coro_spawn(coro: *mut IfaCoroutine) -> u64 {
    if coro.is_null() {
        return 0;
    }
    let c = unsafe { &mut *coro };
    let coro_ptr = coro as usize;
    let fid = GLOBAL_SCHEDULER.spawn_resumable(move || {
        let raw_coro = coro_ptr as *mut IfaCoroutine;
        let res = ifa_rt_coro_resume(raw_coro);
        if res == CoroStatus::Completed as i32 {
            CoroStatus::Completed
        } else if res == CoroStatus::Suspended as i32 {
            CoroStatus::Suspended
        } else {
            CoroStatus::Panicked
        }
    });
    c.fiber_id = Some(fid);
    fid
}

/// Destroy a stackless coroutine and free its state frame.
#[no_mangle]
pub extern "C" fn ifa_rt_coro_destroy(coro: *mut IfaCoroutine) {
    if !coro.is_null() {
        unsafe {
            let mut c = Box::from_raw(coro);
            if let Some(destroy) = c.destroy_fn {
                if !c.frame.is_null() {
                    destroy(c.frame);
                }
            }
            if !c.frame.is_null() {
                GLOBAL_ALLOCATOR.free(c.frame);
                c.frame = std::ptr::null_mut();
            }
        }
    }
}

/// Check if a stackless coroutine has completed execution.
#[no_mangle]
pub extern "C" fn ifa_rt_coro_is_done(coro: *mut IfaCoroutine) -> i32 {
    if coro.is_null() {
        return 1;
    }
    let c = unsafe { &*coro };
    if c.status == CoroStatus::Completed {
        1
    } else {
        0
    }
}

/// Get current execution status of a stackless coroutine.
#[no_mangle]
pub extern "C" fn ifa_rt_coro_status(coro: *mut IfaCoroutine) -> i32 {
    if coro.is_null() {
        return CoroStatus::Panicked as i32;
    }
    let c = unsafe { &*coro };
    c.status as i32
}

/// Get raw memory frame pointer of a stackless coroutine.
#[no_mangle]
pub extern "C" fn ifa_rt_coro_frame(coro: *mut IfaCoroutine) -> *mut u8 {
    if coro.is_null() {
        std::ptr::null_mut()
    } else {
        unsafe { (*coro).frame }
    }
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

/// Immutable contiguous byte/data slice for zero-copy FFI data exchange.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IfaSlice {
    pub ptr: *const u8,
    pub len: usize,
}

impl IfaSlice {
    pub fn new(ptr: *const u8, len: usize) -> Self {
        Self { ptr, len }
    }

    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        if self.ptr.is_null() || self.len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
        }
    }
}

/// Mutable contiguous byte/data slice with capacity for zero-copy FFI buffer exchange.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IfaMutSlice {
    pub ptr: *mut u8,
    pub len: usize,
    pub cap: usize,
}

impl IfaMutSlice {
    pub fn new(ptr: *mut u8, len: usize, cap: usize) -> Self {
        Self { ptr, len, cap }
    }

    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        if self.ptr.is_null() || self.len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
        }
    }

    #[inline(always)]
    pub fn as_capacity_bytes_mut(&mut self) -> &mut [u8] {
        if self.ptr.is_null() || self.cap == 0 {
            &mut []
        } else {
            unsafe { std::slice::from_raw_parts_mut(self.ptr, self.cap) }
        }
    }

    #[inline(always)]
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        if self.ptr.is_null() || self.len == 0 {
            &mut []
        } else {
            unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
        }
    }
}

/// Construct an immutable zero-copy byte slice from a raw pointer and length.
#[no_mangle]
pub extern "C" fn ifa_rt_slice_from_raw(ptr: *const u8, len: usize) -> IfaSlice {
    IfaSlice { ptr, len }
}

/// Allocate a mutable zero-copy buffer on the generational heap or request arena.
#[no_mangle]
pub extern "C" fn ifa_rt_slice_alloc(len: usize, arena_id: u16) -> IfaMutSlice {
    let actual_size = len.max(1);
    let ptr = GLOBAL_ALLOCATOR.alloc(actual_size, 8, arena_id);
    IfaMutSlice {
        ptr,
        len: 0,
        cap: actual_size,
    }
}

/// Release a mutable zero-copy buffer previously allocated by `ifa_rt_slice_alloc`.
#[no_mangle]
pub extern "C" fn ifa_rt_slice_free(slice: IfaMutSlice) {
    if !slice.ptr.is_null() {
        GLOBAL_ALLOCATOR.free(slice.ptr);
    }
}

/// Static IFA runtime version identifier for foreign interfaces and diagnostic health checks.
#[no_mangle]
pub extern "C" fn ifa_rt_version_string() -> *const std::os::raw::c_char {
    c"IFA Runtime 0.1.0 (Zero-GC Generational Concurrency)".as_ptr()
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

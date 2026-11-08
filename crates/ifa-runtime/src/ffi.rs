//! C-ABI Foreign Function Interface exports for native execution and cross-language FFI.

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
pub extern "C-unwind" fn ifa_rt_gen_free(ptr: *mut u8) {
    GLOBAL_ALLOCATOR.free(ptr);
}

/// 1-cycle CPU generation check: aborts safely on Use-After-Free detection.
#[no_mangle]
pub extern "C-unwind" fn ifa_rt_gen_check(ptr: *const u8, remembered_gen: u32) {
    if ptr.is_null() {
        ifa_rt_panic_null_ref();
    }
    unsafe {
        let header = &*(ptr.sub(std::mem::size_of::<GenHeader>()) as *const GenHeader);
        if !header.is_active()
            || header.is_quarantined()
            || header.generation_counter != remembered_gen
        {
            ifa_rt_panic_uaf(ptr, remembered_gen, header.generation_counter);
        }
    }
}

/// 1-cycle CPU generation and epoch check: aborts safely on Use-After-Free or epoch mismatch detection.
#[no_mangle]
pub extern "C-unwind" fn ifa_rt_gen_check_epoch(
    ptr: *const u8,
    remembered_gen: u32,
    remembered_epoch: u16,
) {
    if ptr.is_null() {
        ifa_rt_panic_null_ref();
    }
    unsafe {
        let header = &*(ptr.sub(std::mem::size_of::<GenHeader>()) as *const GenHeader);
        if !header.is_active()
            || header.is_quarantined()
            || header.generation_counter != remembered_gen
        {
            ifa_rt_panic_uaf(ptr, remembered_gen, header.generation_counter);
        }
        let current_epoch = header.allocation_flags & crate::header::FLAG_EPOCH_1;
        let expected_epoch = remembered_epoch & crate::header::FLAG_EPOCH_1;
        if current_epoch != expected_epoch {
            ifa_rt_panic_epoch_mismatch(ptr, expected_epoch, current_epoch);
        }
    }
}

/// Retrieve current runtime epoch counter.
#[no_mangle]
pub extern "C" fn ifa_rt_epoch_current() -> u64 {
    GLOBAL_ALLOCATOR.epoch_manager.current_epoch()
}

/// Manually trigger runtime epoch progression.
#[no_mangle]
pub extern "C" fn ifa_rt_epoch_advance() -> u64 {
    GLOBAL_ALLOCATOR.epoch_manager.advance_epoch()
}

/// Number of quarantined slots retired due to generation overflow.
#[no_mangle]
pub extern "C" fn ifa_rt_epoch_quarantined_count() -> usize {
    GLOBAL_ALLOCATOR.epoch_stats().quarantined_slots
}

/// Number of epoch switches caused by 32-bit generation overflows.
#[no_mangle]
pub extern "C" fn ifa_rt_epoch_transitions_count() -> usize {
    GLOBAL_ALLOCATOR.epoch_stats().epoch_transitions
}

/// Intercept and abort program on detected epoch mismatch wrap-around.
#[no_mangle]
pub extern "C-unwind" fn ifa_rt_panic_epoch_mismatch(
    ptr: *const u8,
    expected_epoch: u16,
    actual_epoch: u16,
) -> ! {
    let arena_id = unsafe {
        if !ptr.is_null() && (ptr as usize) >= std::mem::size_of::<GenHeader>() {
            let header = &*(ptr.sub(std::mem::size_of::<GenHeader>()) as *const GenHeader);
            header.arena_id
        } else {
            0
        }
    };
    let rec = crate::panic::IfaPanicRecord::new_epoch_mismatch(
        ptr as usize,
        expected_epoch,
        actual_epoch,
        arena_id,
    );
    crate::panic::dispatch_panic(rec);
}

/// Intercept and abort program on detected Use-After-Free without memory corruption.
#[no_mangle]
pub extern "C-unwind" fn ifa_rt_panic_uaf(ptr: *const u8, expected_gen: u32, actual_gen: u32) -> ! {
    let arena_id = unsafe {
        if !ptr.is_null() && (ptr as usize) >= std::mem::size_of::<GenHeader>() {
            let header = &*(ptr.sub(std::mem::size_of::<GenHeader>()) as *const GenHeader);
            header.arena_id
        } else {
            0
        }
    };
    let rec =
        crate::panic::IfaPanicRecord::new_uaf(ptr as usize, expected_gen, actual_gen, arena_id);
    crate::panic::dispatch_panic(rec);
}

/// Intercept and abort program on detected Double-Free.
#[no_mangle]
pub extern "C-unwind" fn ifa_rt_panic_double_free(ptr: *const u8) -> ! {
    let arena_id = unsafe {
        if !ptr.is_null() && (ptr as usize) >= std::mem::size_of::<GenHeader>() {
            let header = &*(ptr.sub(std::mem::size_of::<GenHeader>()) as *const GenHeader);
            header.arena_id
        } else {
            0
        }
    };
    let rec = crate::panic::IfaPanicRecord::new_double_free(ptr as usize, arena_id);
    crate::panic::dispatch_panic(rec);
}

/// Intercept null reference dereference.
#[no_mangle]
pub extern "C-unwind" fn ifa_rt_panic_null_ref() -> ! {
    let rec = crate::panic::IfaPanicRecord::new_null_deref();
    crate::panic::dispatch_panic(rec);
}

/// Register a custom global panic interception handler callback.
#[no_mangle]
pub extern "C" fn ifa_rt_set_panic_handler(
    handler: Option<extern "C" fn(*const crate::panic::IfaPanicRecord)>,
) {
    crate::panic::set_panic_handler(handler);
}

/// Reset global panic interception handler callback to default.
#[no_mangle]
pub extern "C" fn ifa_rt_reset_panic_handler() {
    crate::panic::reset_panic_handler();
}

/// Retrieve raw pointer to the last intercepted panic record.
#[no_mangle]
pub extern "C" fn ifa_rt_get_last_panic() -> *const crate::panic::IfaPanicRecord {
    crate::panic::get_last_panic_raw_ptr()
}

/// Clear the recorded panic state.
#[no_mangle]
pub extern "C" fn ifa_rt_clear_last_panic() {
    crate::panic::clear_last_panic();
}

/// Catch an execution panic within a function pointer.
/// Returns 0 on normal execution, or the panic kind (e.g. 1 for UAF) on panic.
#[no_mangle]
pub extern "C" fn ifa_rt_catch_panic(func: extern "C-unwind" fn(*mut u8), arg: *mut u8) -> i32 {
    let outcome = crate::panic::catch_panic(std::panic::AssertUnwindSafe(|| {
        func(arg);
    }));
    match outcome {
        Ok(()) => 0,
        Err(rec) => rec.kind as i32,
    }
}

/// Capture current bare-metal stack trace into user-provided buffer.
/// Returns number of frames captured.
#[no_mangle]
pub extern "C" fn ifa_rt_capture_stack_trace(buffer: *mut usize, max_depth: usize) -> usize {
    let trace = crate::panic::IfaBareMetalStackTrace::capture();
    let to_copy = trace.count.min(max_depth);
    if !buffer.is_null() && to_copy > 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(trace.frames.as_ptr(), buffer, to_copy);
        }
    }
    to_copy
}

/// Format current bare-metal stack trace into user-provided byte buffer.
/// Returns number of bytes written.
#[no_mangle]
pub extern "C" fn ifa_rt_format_stack_trace(buffer: *mut u8, buffer_len: usize) -> usize {
    if buffer.is_null() || buffer_len == 0 {
        return 0;
    }
    let trace = crate::panic::IfaBareMetalStackTrace::capture();
    let slice = unsafe { std::slice::from_raw_parts_mut(buffer, buffer_len) };
    trace.format_bare_metal(slice)
}

/// Assertion check: terminates with deterministic diagnostic if condition is false.
#[no_mangle]
pub extern "C-unwind" fn ifa_rt_assert(cond: bool, msg: *const u8) {
    if !cond {
        ifa_rt_panic_assert(msg);
    }
}

/// Assert two 64-bit integers are equal; aborts with detailed values on mismatch.
#[no_mangle]
pub extern "C-unwind" fn ifa_rt_assert_eq_i64(actual: i64, expected: i64, msg: *const u8) {
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
pub extern "C-unwind" fn ifa_rt_assert_ne_i64(actual: i64, expected: i64, msg: *const u8) {
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
pub extern "C-unwind" fn ifa_rt_panic_assert(msg: *const u8) -> ! {
    let msg_str = if !msg.is_null() {
        let c_str = unsafe { std::ffi::CStr::from_ptr(msg as *const std::ffi::c_char) };
        c_str
            .to_str()
            .unwrap_or("<invalid utf-8 assertion message>")
    } else {
        "Runtime assertion failed"
    };
    let rec = crate::panic::IfaPanicRecord::new_assertion(msg_str);
    crate::panic::dispatch_panic(rec);
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
pub extern "C" fn ifa_rt_fiber_spawn(entry: extern "C-unwind" fn(*mut u8), arg: *mut u8) -> u64 {
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

/// Retrieve execution status of a fiber (1: Completed, 2: Panicked, 3: Running, 4: Suspended, 5: WaitingIo, 0: Ready, -1: Unknown).
#[no_mangle]
pub extern "C" fn ifa_rt_fiber_status(fiber_id: u64) -> i32 {
    match GLOBAL_SCHEDULER.get_fiber_state(fiber_id) {
        Some(crate::fiber::FiberState::Completed) => 1,
        Some(crate::fiber::FiberState::Panicked) => 2,
        Some(crate::fiber::FiberState::Running) => 3,
        Some(crate::fiber::FiberState::Suspended) => 4,
        Some(crate::fiber::FiberState::WaitingIo(_)) => 5,
        Some(crate::fiber::FiberState::Ready) => 0,
        None => -1,
    }
}

/// Retrieve the identifier of the currently executing fiber on this worker thread (0 if unassigned / main thread).
#[no_mangle]
pub extern "C" fn ifa_rt_fiber_current_id() -> u64 {
    crate::fiber::current_fiber_id()
}

/// Retrieve the isolated arena ID of the currently executing fiber on this worker thread (0 if none).
#[no_mangle]
pub extern "C" fn ifa_rt_fiber_current_arena() -> u16 {
    crate::fiber::current_fiber_arena()
}

/// Verify whether the specified fiber is the registered owner of the generational arena.
#[no_mangle]
pub extern "C" fn ifa_rt_arena_verify_owner(arena_id: u16, fiber_id: u64) -> bool {
    GLOBAL_ALLOCATOR.verify_arena_owner(arena_id, fiber_id)
}

/// Spawn a new colorless fiber with an isolated, automatically managed generational arena.
#[no_mangle]
pub extern "C" fn ifa_rt_fiber_spawn_with_arena(
    entry: extern "C-unwind" fn(*mut u8),
    arg: *mut u8,
) -> u64 {
    let arg_addr = arg as usize;
    let (fiber_id, _arena_id) = GLOBAL_SCHEDULER.spawn_with_arena(move || {
        let raw_arg = arg_addr as *mut u8;
        entry(raw_arg);
    });
    fiber_id
}

/// Opaque handle representing an allocated stackless native coroutine.
pub struct IfaCoroutine {
    pub frame: *mut u8,
    pub resume_fn: CoroResumeFn,
    pub destroy_fn: Option<CoroDestroyFn>,
    pub status: CoroStatus,
    pub fiber_id: Option<FiberId>,
    pub owns_frame: bool,
    pub pending_io_token: Option<u64>,
    pub pending_result_slot: Option<*mut i64>,
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
        owns_frame: true,
        pending_io_token: None,
        pending_result_slot: None,
    });
    Box::into_raw(coro)
}

/// Create a stackless native coroutine from an externally allocated handle or LLVM coroutine frame.
#[no_mangle]
pub extern "C" fn ifa_rt_coro_create_custom(
    handle: *mut u8,
    resume_fn: extern "C" fn(*mut u8) -> i32,
    destroy_fn: Option<extern "C" fn(*mut u8)>,
) -> *mut IfaCoroutine {
    let coro = Box::new(IfaCoroutine {
        frame: handle,
        resume_fn,
        destroy_fn,
        status: CoroStatus::Suspended,
        fiber_id: None,
        owns_frame: false,
        pending_io_token: None,
        pending_result_slot: None,
    });
    Box::into_raw(coro)
}

/// Resume execution of a stackless coroutine for one cooperative step.
/// Returns CoroStatus as i32 (0 = Suspended, 1 = Completed, 2 = Panicked, 3 = WaitingIo).
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
    if c.pending_io_token.is_some() {
        c.status = CoroStatus::WaitingIo;
        return CoroStatus::WaitingIo as i32;
    }
    if res == CoroStatus::Completed as i32 {
        c.status = CoroStatus::Completed;
    } else if res == CoroStatus::WaitingIo as i32 {
        c.status = CoroStatus::WaitingIo;
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
        } else if res == CoroStatus::WaitingIo as i32 {
            let rc = unsafe { &mut *raw_coro };
            let token = rc.pending_io_token.take().unwrap_or(0);
            let slot = rc.pending_result_slot.take();
            crate::fiber::set_current_fiber_io_token(token);
            crate::fiber::set_current_fiber_result_slot(slot);
            CoroStatus::WaitingIo
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
                    c.frame = std::ptr::null_mut();
                }
            }
            if c.owns_frame && !c.frame.is_null() {
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

/// Opaque handle representing a stackless generator iterator driven by a coroutine.
#[repr(C)]
pub struct IfaCoroIterator {
    pub coro: *mut IfaCoroutine,
    pub yield_slot: *mut u8,
    pub elem_size: usize,
    pub has_next: bool,
}

unsafe impl Send for IfaCoroIterator {}
unsafe impl Sync for IfaCoroIterator {}

/// Create a new generator iterator wrapping a coroutine and its yield slot.
#[no_mangle]
pub extern "C" fn ifa_rt_coro_iter_create(
    coro: *mut IfaCoroutine,
    yield_slot: *mut u8,
    elem_size: usize,
) -> *mut IfaCoroIterator {
    let iter = Box::new(IfaCoroIterator {
        coro,
        yield_slot,
        elem_size,
        has_next: true,
    });
    Box::into_raw(iter)
}

/// Advance a generator iterator by resuming its underlying coroutine.
/// Copies the yielded element into `out_val` (if non-null and elem_size > 0).
/// Returns 1 if a new element was yielded, 0 if the generator completed, or -1 on error.
#[no_mangle]
pub extern "C" fn ifa_rt_coro_iter_next(iter: *mut IfaCoroIterator, out_val: *mut u8) -> i32 {
    if iter.is_null() {
        return -1;
    }
    let it = unsafe { &mut *iter };
    if it.coro.is_null() || !it.has_next {
        return 0;
    }
    let status = ifa_rt_coro_resume(it.coro);
    if status == CoroStatus::Suspended as i32 {
        if !out_val.is_null() && !it.yield_slot.is_null() && it.elem_size > 0 {
            unsafe {
                std::ptr::copy_nonoverlapping(it.yield_slot, out_val, it.elem_size);
            }
        }
        it.has_next = true;
        1
    } else if status == CoroStatus::Completed as i32 {
        it.has_next = false;
        0
    } else {
        it.has_next = false;
        -1
    }
}

/// Check if a generator iterator has completed execution.
#[no_mangle]
pub extern "C" fn ifa_rt_coro_iter_is_done(iter: *mut IfaCoroIterator) -> i32 {
    if iter.is_null() {
        return 1;
    }
    let it = unsafe { &*iter };
    if !it.has_next || ifa_rt_coro_is_done(it.coro) == 1 {
        1
    } else {
        0
    }
}

/// Destroy a generator iterator, freeing the underlying coroutine and iterator context.
#[no_mangle]
pub extern "C" fn ifa_rt_coro_iter_destroy(iter: *mut IfaCoroIterator) {
    if !iter.is_null() {
        unsafe {
            let it = Box::from_raw(iter);
            if !it.coro.is_null() {
                ifa_rt_coro_destroy(it.coro);
            }
        }
    }
}

/// Register an asynchronous io_uring read request on the global reactor and bind to the coroutine.
/// Returns the allocated I/O event token.
#[no_mangle]
pub extern "C" fn ifa_rt_coro_register_io_uring_read(
    coro: *mut IfaCoroutine,
    fd: i32,
    buf: *mut u8,
    len: u32,
    offset: u64,
    out_result: *mut i64,
) -> u64 {
    let token = crate::reactor::GLOBAL_REACTOR.next_token();
    crate::reactor::GLOBAL_REACTOR.submit_io_uring_read(fd, buf, len, offset, token);
    if !coro.is_null() {
        let c = unsafe { &mut *coro };
        c.pending_io_token = Some(token);
        c.pending_result_slot = if out_result.is_null() {
            None
        } else {
            Some(out_result)
        };
        c.status = CoroStatus::WaitingIo;
    }
    crate::fiber::set_current_fiber_io_token(token);
    token
}

/// Register an asynchronous io_uring write request on the global reactor and bind to the coroutine.
/// Returns the allocated I/O event token.
#[no_mangle]
pub extern "C" fn ifa_rt_coro_register_io_uring_write(
    coro: *mut IfaCoroutine,
    fd: i32,
    buf: *const u8,
    len: u32,
    offset: u64,
    out_result: *mut i64,
) -> u64 {
    let token = crate::reactor::GLOBAL_REACTOR.next_token();
    crate::reactor::GLOBAL_REACTOR.submit_io_uring_write(fd, buf, len, offset, token);
    if !coro.is_null() {
        let c = unsafe { &mut *coro };
        c.pending_io_token = Some(token);
        c.pending_result_slot = if out_result.is_null() {
            None
        } else {
            Some(out_result)
        };
        c.status = CoroStatus::WaitingIo;
    }
    crate::fiber::set_current_fiber_io_token(token);
    token
}

/// Register an asynchronous Windows IOCP read request on the global reactor and bind to the coroutine.
/// Returns the allocated I/O event token.
#[no_mangle]
pub extern "C" fn ifa_rt_coro_register_iocp_read(
    coro: *mut IfaCoroutine,
    key: usize,
    buf: *mut u8,
    len: u32,
    out_result: *mut i64,
) -> u64 {
    let token = crate::reactor::GLOBAL_REACTOR.next_token();
    crate::reactor::GLOBAL_REACTOR.submit_iocp_read(key, buf, len, token);
    if !coro.is_null() {
        let c = unsafe { &mut *coro };
        c.pending_io_token = Some(token);
        c.pending_result_slot = if out_result.is_null() {
            None
        } else {
            Some(out_result)
        };
        c.status = CoroStatus::WaitingIo;
    }
    crate::fiber::set_current_fiber_io_token(token);
    token
}

/// Register an asynchronous Windows IOCP write request on the global reactor and bind to the coroutine.
/// Returns the allocated I/O event token.
#[no_mangle]
pub extern "C" fn ifa_rt_coro_register_iocp_write(
    coro: *mut IfaCoroutine,
    key: usize,
    buf: *const u8,
    len: u32,
    out_result: *mut i64,
) -> u64 {
    let token = crate::reactor::GLOBAL_REACTOR.next_token();
    crate::reactor::GLOBAL_REACTOR.submit_iocp_write(key, buf, len, token);
    if !coro.is_null() {
        let c = unsafe { &mut *coro };
        c.pending_io_token = Some(token);
        c.pending_result_slot = if out_result.is_null() {
            None
        } else {
            Some(out_result)
        };
        c.status = CoroStatus::WaitingIo;
    }
    crate::fiber::set_current_fiber_io_token(token);
    token
}

/// Manually mark a coroutine as waiting for an I/O token with optional result slot.
#[no_mangle]
pub extern "C" fn ifa_rt_coro_set_waiting_io(
    coro: *mut IfaCoroutine,
    token: u64,
    out_result: *mut i64,
) {
    if !coro.is_null() {
        let c = unsafe { &mut *coro };
        c.pending_io_token = Some(token);
        c.pending_result_slot = if out_result.is_null() {
            None
        } else {
            Some(out_result)
        };
        c.status = CoroStatus::WaitingIo;
    }
    crate::fiber::set_current_fiber_io_token(token);
}

/// Manually wake an I/O event token across the scheduler.
#[no_mangle]
pub extern "C" fn ifa_rt_coro_wake_io(token: u64, result: i64) -> i32 {
    if GLOBAL_SCHEDULER.wake_io(token, result) {
        1
    } else {
        0
    }
}

/// Poll the global async reactor for completed io_uring and IOCP events and wake waiting fibers.
#[no_mangle]
pub extern "C" fn ifa_rt_reactor_poll(timeout_ms: u32) -> usize {
    if timeout_ms == 0 {
        crate::reactor::GLOBAL_REACTOR.poll_and_wake()
    } else {
        crate::reactor::GLOBAL_REACTOR
            .wait_and_wake(std::time::Duration::from_millis(timeout_ms as u64))
    }
}

/// Number of fibers currently parked waiting for asynchronous I/O completion.
#[no_mangle]
pub extern "C" fn ifa_rt_coro_pending_io_count() -> usize {
    GLOBAL_SCHEDULER.pending_io_count()
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

/// Concatenate two null-terminated UTF-8 C strings and return a new heap-allocated null-terminated C string.
#[no_mangle]
pub extern "C" fn ifa_rt_string_concat(a: *const u8, b: *const u8) -> *mut u8 {
    let s_a = if a.is_null() {
        ""
    } else {
        unsafe {
            std::ffi::CStr::from_ptr(a as *const std::os::raw::c_char)
                .to_str()
                .unwrap_or("")
        }
    };
    let s_b = if b.is_null() {
        ""
    } else {
        unsafe {
            std::ffi::CStr::from_ptr(b as *const std::os::raw::c_char)
                .to_str()
                .unwrap_or("")
        }
    };
    let combined = format!("{}{}\0", s_a, s_b);
    let bytes = combined.into_bytes();
    let len = bytes.len();
    let layout = std::alloc::Layout::from_size_align(len, 1).unwrap();
    unsafe {
        let mem = std::alloc::alloc(layout);
        if mem.is_null() {
            std::alloc::handle_alloc_error(layout);
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), mem, len);
        mem
    }
}

/// Convert a 64-bit integer to a heap-allocated null-terminated C string.
#[no_mangle]
pub extern "C" fn ifa_rt_string_from_i64(val: i64) -> *mut u8 {
    let s = format!("{}\0", val);
    let bytes = s.into_bytes();
    let len = bytes.len();
    let layout = std::alloc::Layout::from_size_align(len, 1).unwrap();
    unsafe {
        let mem = std::alloc::alloc(layout);
        if mem.is_null() {
            std::alloc::handle_alloc_error(layout);
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), mem, len);
        mem
    }
}

/// Convert a 64-bit float to a heap-allocated null-terminated C string.
#[no_mangle]
pub extern "C" fn ifa_rt_string_from_f64(val: f64) -> *mut u8 {
    let s = format!("{}\0", val);
    let bytes = s.into_bytes();
    let len = bytes.len();
    let layout = std::alloc::Layout::from_size_align(len, 1).unwrap();
    unsafe {
        let mem = std::alloc::alloc(layout);
        if mem.is_null() {
            std::alloc::handle_alloc_error(layout);
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), mem, len);
        mem
    }
}

/// Convert a boolean to a heap-allocated null-terminated C string.
#[no_mangle]
pub extern "C" fn ifa_rt_string_from_bool(val: bool) -> *mut u8 {
    let s = if val { "true\0" } else { "false\0" };
    let bytes = s.as_bytes();
    let len = bytes.len();
    let layout = std::alloc::Layout::from_size_align(len, 1).unwrap();
    unsafe {
        let mem = std::alloc::alloc(layout);
        if mem.is_null() {
            std::alloc::handle_alloc_error(layout);
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), mem, len);
        mem
    }
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

/// Raw memory header for dynamic lists adhering to IFA's mutable value semantics.
#[repr(C)]
pub struct IfaListRawHeader {
    pub ref_count: std::sync::atomic::AtomicUsize,
    pub len: usize,
    pub capacity: usize,
}

/// Allocate a new dynamic list with initial capacity.
#[no_mangle]
pub extern "C" fn ifa_rt_list_new(elem_size: usize, initial_cap: usize) -> *mut u8 {
    let cap = initial_cap.max(4);
    let esize = elem_size.max(1);
    let header_size = std::mem::size_of::<IfaListRawHeader>();
    let total_size = header_size + cap * esize;
    let align = 8.max(std::mem::align_of::<IfaListRawHeader>());
    let layout = std::alloc::Layout::from_size_align(total_size, align).unwrap();
    unsafe {
        let mem = std::alloc::alloc(layout);
        if mem.is_null() {
            std::alloc::handle_alloc_error(layout);
        }
        let header = mem as *mut IfaListRawHeader;
        std::ptr::write(
            header,
            IfaListRawHeader {
                ref_count: std::sync::atomic::AtomicUsize::new(1),
                len: 0,
                capacity: cap,
            },
        );
        mem
    }
}

/// Return element count of a dynamic list.
#[no_mangle]
pub extern "C" fn ifa_rt_list_len(list_handle: *const u8) -> usize {
    if list_handle.is_null() {
        return 0;
    }
    unsafe {
        let header = list_handle as *const IfaListRawHeader;
        (*header).len
    }
}

/// Return pointer to element at index `index`.
#[no_mangle]
pub extern "C" fn ifa_rt_list_get(
    list_handle: *const u8,
    index: usize,
    elem_size: usize,
) -> *const u8 {
    if list_handle.is_null() {
        return std::ptr::null();
    }
    unsafe {
        let header = list_handle as *const IfaListRawHeader;
        if index >= (*header).len {
            return std::ptr::null();
        }
        let base = list_handle.add(std::mem::size_of::<IfaListRawHeader>());
        base.add(index * elem_size.max(1))
    }
}

/// Append element to dynamic list, performing Copy-on-Write and resizing if required.
#[no_mangle]
pub extern "C" fn ifa_rt_list_push(
    list_handle_ptr: *mut *mut u8,
    elem_ptr: *const u8,
    elem_size: usize,
) {
    if list_handle_ptr.is_null() || elem_ptr.is_null() {
        return;
    }
    let esize = elem_size.max(1);
    unsafe {
        if (*list_handle_ptr).is_null() {
            *list_handle_ptr = ifa_rt_list_new(esize, 4);
        }
        let mut handle = *list_handle_ptr;
        let header = handle as *mut IfaListRawHeader;
        let current_len = (*header).len;
        let current_cap = (*header).capacity;

        if (*header)
            .ref_count
            .load(std::sync::atomic::Ordering::Acquire)
            > 1
            || current_len >= current_cap
        {
            let new_cap = if current_len >= current_cap {
                current_cap * 2
            } else {
                current_cap
            };
            let new_handle = ifa_rt_list_new(esize, new_cap);
            let new_header = new_handle as *mut IfaListRawHeader;
            let src = handle.add(std::mem::size_of::<IfaListRawHeader>());
            let dst = new_handle.add(std::mem::size_of::<IfaListRawHeader>());
            std::ptr::copy_nonoverlapping(src, dst, current_len * esize);
            (*new_header).len = current_len;

            if (*header)
                .ref_count
                .fetch_sub(1, std::sync::atomic::Ordering::Release)
                == 1
            {
                let layout = std::alloc::Layout::from_size_align(
                    std::mem::size_of::<IfaListRawHeader>() + current_cap * esize,
                    8,
                )
                .unwrap();
                std::alloc::dealloc(handle, layout);
            }

            *list_handle_ptr = new_handle;
            handle = new_handle;
        }

        let cur_header = handle as *mut IfaListRawHeader;
        let dst = handle
            .add(std::mem::size_of::<IfaListRawHeader>())
            .add(current_len * esize);
        std::ptr::copy_nonoverlapping(elem_ptr, dst, esize);
        (*cur_header).len = current_len + 1;
    }
}

/// Pop last element from dynamic list.
#[no_mangle]
pub extern "C" fn ifa_rt_list_pop(
    list_handle: *mut u8,
    out_elem_ptr: *mut u8,
    elem_size: usize,
) -> i32 {
    if list_handle.is_null() {
        return 0;
    }
    let esize = elem_size.max(1);
    unsafe {
        let header = list_handle as *mut IfaListRawHeader;
        let len = (*header).len;
        if len == 0 {
            return 0;
        }
        let last_idx = len - 1;
        if !out_elem_ptr.is_null() {
            let src = list_handle
                .add(std::mem::size_of::<IfaListRawHeader>())
                .add(last_idx * esize);
            std::ptr::copy_nonoverlapping(src, out_elem_ptr, esize);
        }
        (*header).len = last_idx;
        1
    }
}

/// Release dynamic list memory buffer.
#[no_mangle]
pub extern "C" fn ifa_rt_list_free(list_handle: *mut u8, elem_size: usize) {
    if list_handle.is_null() {
        return;
    }
    unsafe {
        let header = list_handle as *mut IfaListRawHeader;
        if (*header)
            .ref_count
            .fetch_sub(1, std::sync::atomic::Ordering::Release)
            == 1
        {
            std::sync::atomic::fence(std::sync::atomic::Ordering::Acquire);
            let cap = (*header).capacity;
            let layout = std::alloc::Layout::from_size_align(
                std::mem::size_of::<IfaListRawHeader>() + cap * elem_size.max(1),
                8,
            )
            .unwrap();
            std::alloc::dealloc(list_handle, layout);
        }
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

/// Operation mode for a zero-allocation select wait entry.
pub const IFA_SELECT_OP_RECV: u32 = 0;
pub const IFA_SELECT_OP_SEND: u32 = 1;

/// Readiness status for a zero-allocation select wait entry.
pub const IFA_SELECT_STATUS_PENDING: u32 = 0;
pub const IFA_SELECT_STATUS_READY: u32 = 1;
pub const IFA_SELECT_STATUS_CLOSED: u32 = 2;

/// A single wait entry in a zero-allocation select wait table.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IfaSelectWaitEntry {
    /// Pointer to the IFA channel handle.
    pub chan: *mut IfaChannelHandle,
    /// Operation to wait for: 0 = RECV, 1 = SEND.
    pub op: u32,
    /// Status: 0 = PENDING, 1 = READY, 2 = CLOSED.
    pub status: u32,
    /// Payload pointer (transferred value or target buffer).
    pub val: *mut u8,
}

/// A zero-allocation descriptor table representing multiple channel operations to multiplex.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IfaSelectWaitTable {
    /// Pointer to contiguous array of wait entries allocated on the stack.
    pub entries: *mut IfaSelectWaitEntry,
    /// Number of entries in the table.
    pub count: usize,
    /// Non-zero if a default fallback branch is present.
    pub has_default: i32,
}

/// Zero-allocation non-blocking multiplexing evaluation of a select wait table.
///
/// Returns:
/// - index >= 0: the index of the first satisfied entry (marked READY)
/// - table.count: if `has_default != 0` and no entry is ready
/// - -2: if all monitored channels are closed
/// - -1: if no entry is ready and `has_default == 0` (signals coroutine suspension)
#[no_mangle]
pub extern "C" fn ifa_rt_channel_select_table(table: *mut IfaSelectWaitTable) -> i64 {
    if table.is_null() {
        return -2;
    }
    let t = unsafe { &mut *table };
    if t.entries.is_null() || t.count == 0 {
        return if t.has_default != 0 { 0 } else { -2 };
    }

    let entries = unsafe { std::slice::from_raw_parts_mut(t.entries, t.count) };
    let mut any_open = false;

    for (idx, entry) in entries.iter_mut().enumerate() {
        if entry.chan.is_null() {
            continue;
        }
        let handle = unsafe { &*entry.chan };
        let is_closed = handle.0.is_closed();

        if !is_closed {
            any_open = true;
        }

        match entry.op {
            IFA_SELECT_OP_RECV => {
                if !handle.0.is_empty() {
                    entry.status = IFA_SELECT_STATUS_READY;
                    return idx as i64;
                } else if is_closed {
                    entry.status = IFA_SELECT_STATUS_CLOSED;
                } else {
                    entry.status = IFA_SELECT_STATUS_PENDING;
                }
            }
            IFA_SELECT_OP_SEND => {
                if !handle.0.is_full() && !is_closed {
                    entry.status = IFA_SELECT_STATUS_READY;
                    return idx as i64;
                } else if is_closed {
                    entry.status = IFA_SELECT_STATUS_CLOSED;
                } else {
                    entry.status = IFA_SELECT_STATUS_PENDING;
                }
            }
            _ => {
                if !handle.0.is_empty() {
                    entry.status = IFA_SELECT_STATUS_READY;
                    return idx as i64;
                }
            }
        }
    }

    if t.has_default != 0 {
        return t.count as i64;
    }

    if !any_open {
        return -2;
    }

    -1
}

/// Zero-allocation blocking/cooperative multiplexing evaluation of a select wait table.
/// Cooperatively yields the calling fiber or spins until an entry is satisfied.
#[no_mangle]
pub extern "C" fn ifa_rt_channel_select_wait_table(table: *mut IfaSelectWaitTable) -> i64 {
    if table.is_null() {
        return -2;
    }
    let mut spins: u32 = 0;
    loop {
        let res = ifa_rt_channel_select_table(table);
        if res != -1 {
            return res;
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
    let mut stack_entries = [IfaSelectWaitEntry {
        chan: std::ptr::null_mut(),
        op: IFA_SELECT_OP_RECV,
        status: IFA_SELECT_STATUS_PENDING,
        val: std::ptr::null_mut(),
    }; 32];

    if num_channels <= 32 {
        for (idx, &handle_ptr) in chan_slice.iter().enumerate() {
            stack_entries[idx].chan = handle_ptr;
        }
        let mut table = IfaSelectWaitTable {
            entries: stack_entries.as_mut_ptr(),
            count: num_channels,
            has_default,
        };
        ifa_rt_channel_select_wait_table(&mut table)
    } else {
        let mut dynamic_entries: Vec<IfaSelectWaitEntry> = chan_slice
            .iter()
            .map(|&ch| IfaSelectWaitEntry {
                chan: ch,
                op: IFA_SELECT_OP_RECV,
                status: IFA_SELECT_STATUS_PENDING,
                val: std::ptr::null_mut(),
            })
            .collect();
        let mut table = IfaSelectWaitTable {
            entries: dynamic_entries.as_mut_ptr(),
            count: num_channels,
            has_default,
        };
        ifa_rt_channel_select_wait_table(&mut table)
    }
}

/// 1-cycle CPU static and dynamic bounds verification for universal C-ABI foreign buffer access.
///
/// Aborts safely on index out of bounds detection without memory corruption or undefined behavior.
#[no_mangle]
pub extern "C-unwind" fn ifa_rt_bounds_check(index: usize, len: usize, msg: *const u8) {
    if index >= len {
        if !msg.is_null() {
            ifa_rt_panic_assert(msg);
        } else {
            ifa_rt_panic_out_of_bounds(index, len);
        }
    }
}

/// Verify that a sub-slice range `[start..end]` is strictly within bounds `[0..len]`.
#[no_mangle]
pub extern "C-unwind" fn ifa_rt_slice_bounds_check(
    start: usize,
    end: usize,
    len: usize,
    msg: *const u8,
) {
    if start > end || end > len {
        if !msg.is_null() {
            ifa_rt_panic_assert(msg);
        } else {
            ifa_rt_panic_out_of_bounds(end, len);
        }
    }
}

/// Validate external buffer pointer alignment, non-null status, and minimum byte length.
#[no_mangle]
pub extern "C" fn ifa_rt_buffer_verify_bounds(
    ptr: *const u8,
    len: usize,
    required_min: usize,
    align: usize,
) -> bool {
    if ptr.is_null() || len < required_min {
        return false;
    }
    let actual_align = if align == 0 { 1 } else { align };
    (ptr as usize).is_multiple_of(actual_align)
}

/// Validate an external `IfaSlice` passed across foreign boundaries.
#[no_mangle]
pub extern "C" fn ifa_rt_c_abi_validate_slice(
    slice: IfaSlice,
    elem_size: usize,
    min_elements: usize,
) -> bool {
    let required_bytes = elem_size.saturating_mul(min_elements);
    ifa_rt_buffer_verify_bounds(slice.ptr, slice.len, required_bytes, elem_size)
}

/// Intercept and abort program on detected buffer or slice index out-of-bounds attempt.
#[no_mangle]
pub extern "C-unwind" fn ifa_rt_panic_out_of_bounds(index: usize, len: usize) -> ! {
    let rec = crate::panic::IfaPanicRecord::new_out_of_bounds(index, len);
    crate::panic::dispatch_panic(rec);
}

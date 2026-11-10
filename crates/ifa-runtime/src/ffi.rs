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

/// Number of saturated slab pages permanently placed in quarantine.
#[no_mangle]
pub extern "C" fn ifa_rt_epoch_quarantined_slabs_count() -> usize {
    GLOBAL_ALLOCATOR.quarantined_slabs_count()
}

/// Returns the saturation ratio (quarantined slots / total capacity) for a specific size class index.
#[no_mangle]
pub extern "C" fn ifa_rt_slab_saturation_ratio(class_idx: usize) -> f64 {
    let stats = GLOBAL_ALLOCATOR.slab_saturation_stats();
    if class_idx < stats.len() {
        stats[class_idx].saturation_ratio
    } else {
        0.0
    }
}

/// Triggers automatic quarantine of slabs meeting or exceeding the specified saturation threshold.
#[no_mangle]
pub extern "C" fn ifa_rt_auto_quarantine_saturated_slabs(threshold: f64) -> usize {
    GLOBAL_ALLOCATOR.auto_quarantine_saturated_slabs(threshold)
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

/// Allocate memory in the fast thread-local call arena for bounded closure environments.
#[no_mangle]
pub extern "C" fn ifa_rt_call_arena_alloc(size: usize, align: usize) -> *mut u8 {
    crate::allocator::call_arena_alloc(size, align)
}

/// Mark the active thread's call arena bump position to establish a rewind point.
#[no_mangle]
pub extern "C" fn ifa_rt_call_arena_mark() -> usize {
    crate::allocator::call_arena_mark()
}

/// Rewind the active thread's call arena bump position, invalidating allocations above the mark.
#[no_mangle]
pub extern "C" fn ifa_rt_call_arena_rewind(mark: usize) {
    crate::allocator::call_arena_rewind(mark);
}

/// Reset the active thread's call arena completely.
#[no_mangle]
pub extern "C" fn ifa_rt_call_arena_reset() {
    crate::allocator::call_arena_reset();
}

/// Retrieve the active thread's call arena allocated capacity.
#[no_mangle]
pub extern "C" fn ifa_rt_call_arena_capacity() -> usize {
    crate::allocator::call_arena_capacity()
}

/// Retrieve the peak bump offset (high water mark) reached by the active thread's call arena.
#[no_mangle]
pub extern "C" fn ifa_rt_call_arena_high_water_mark() -> usize {
    crate::allocator::call_arena_high_water_mark()
}

/// Consolidate and shrink the active thread's call arena buffer if currently idle.
#[no_mangle]
pub extern "C" fn ifa_rt_call_arena_shrink_to_fit(max_idle_capacity: usize) {
    crate::allocator::call_arena_shrink_to_fit(max_idle_capacity);
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
    pub arena_id: u16,
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
        arena_id: 0,
    });
    Box::into_raw(coro)
}

/// Create a stackless native coroutine with an allocated memory frame inside a specified arena.
#[no_mangle]
pub extern "C" fn ifa_rt_coro_create_with_arena(
    frame_size: usize,
    arena_id: u16,
    resume_fn: extern "C" fn(*mut u8) -> i32,
    destroy_fn: Option<extern "C" fn(*mut u8)>,
) -> *mut IfaCoroutine {
    let actual_size = frame_size.max(16);
    let frame = GLOBAL_ALLOCATOR.alloc(actual_size, 8, arena_id);
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
        arena_id,
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
        arena_id: 0,
    });
    Box::into_raw(coro)
}

/// Create a stackless native coroutine from an externally allocated handle inside a specified arena.
#[no_mangle]
pub extern "C" fn ifa_rt_coro_create_custom_with_arena(
    handle: *mut u8,
    arena_id: u16,
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
        arena_id,
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

/// Spawn a stackless coroutine into the global M:N scheduler with an isolated generational arena.
/// Returns the assigned FiberId.
#[no_mangle]
pub extern "C" fn ifa_rt_coro_spawn_with_arena(coro: *mut IfaCoroutine, arena_id: u16) -> u64 {
    if coro.is_null() {
        return 0;
    }
    let c = unsafe { &mut *coro };
    c.arena_id = arena_id;
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
    GLOBAL_ALLOCATOR.set_arena_owner(arena_id, fid);
    fid
}

/// Query the generational arena ID associated with a coroutine handle.
#[no_mangle]
pub extern "C" fn ifa_rt_coro_arena_id(coro: *mut IfaCoroutine) -> u16 {
    if coro.is_null() {
        return 0;
    }
    unsafe { (*coro).arena_id }
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

/// Register an asynchronous io_uring high-precision timeout on the global reactor and bind to the coroutine.
/// Returns the allocated I/O event token.
#[no_mangle]
pub extern "C" fn ifa_rt_coro_register_io_uring_timeout(
    coro: *mut IfaCoroutine,
    timeout_ns: u64,
    out_result: *mut i64,
) -> u64 {
    let token = crate::reactor::GLOBAL_REACTOR.next_token();
    crate::reactor::GLOBAL_REACTOR.submit_io_uring_timeout(timeout_ns, token);
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

/// Cancel an active registered io_uring timeout by target token.
/// Returns 1 on success, 0 on failure.
#[no_mangle]
pub extern "C" fn ifa_rt_coro_cancel_io_uring_timeout(target_token: u64) -> i32 {
    let cancel_token = crate::reactor::GLOBAL_REACTOR.next_token();
    crate::reactor::GLOBAL_REACTOR.cancel_io_uring_timeout(target_token, cancel_token);
    1
}

/// Register an asynchronous io_uring poll request on the global reactor and bind to the coroutine.
/// Returns the allocated I/O event token.
#[no_mangle]
pub extern "C" fn ifa_rt_coro_register_io_uring_poll(
    coro: *mut IfaCoroutine,
    fd: i32,
    poll_mask: u32,
    out_result: *mut i64,
) -> u64 {
    let token = crate::reactor::GLOBAL_REACTOR.next_token();
    crate::reactor::GLOBAL_REACTOR.submit_io_uring_poll(fd, poll_mask, token);
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

/// Cancel an active registered io_uring poll by target token.
/// Returns 1 on success, 0 on failure.
#[no_mangle]
pub extern "C" fn ifa_rt_coro_cancel_io_uring_poll(target_token: u64) -> i32 {
    let cancel_token = crate::reactor::GLOBAL_REACTOR.next_token();
    crate::reactor::GLOBAL_REACTOR.cancel_io_uring_poll(target_token, cancel_token);
    1
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

/// Compare two null-terminated UTF-8 C strings for lexicographical equality.
#[no_mangle]
pub extern "C" fn ifa_rt_string_eq(a: *const u8, b: *const u8) -> bool {
    if a == b {
        return true;
    }
    if a.is_null() || b.is_null() {
        return false;
    }
    unsafe {
        let sa = match std::ffi::CStr::from_ptr(a as *const std::os::raw::c_char).to_str() {
            Ok(s) => s,
            Err(_) => return false,
        };
        let sb = match std::ffi::CStr::from_ptr(b as *const std::os::raw::c_char).to_str() {
            Ok(s) => s,
            Err(_) => return false,
        };
        sa == sb
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

/// Read an entire file into a heap-allocated null-terminated C string.
/// Returns an empty null-terminated string on error or missing file.
#[no_mangle]
pub extern "C" fn ifa_rt_fs_read_to_string(path: *const u8) -> *mut u8 {
    let path_str = if path.is_null() {
        ""
    } else {
        unsafe {
            std::ffi::CStr::from_ptr(path as *const std::os::raw::c_char)
                .to_str()
                .unwrap_or("")
        }
    };
    let content = std::fs::read_to_string(path_str).unwrap_or_default();
    let bytes = format!("{}\0", content).into_bytes();
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

/// Write a null-terminated UTF-8 string to a file on disk.
/// Returns true on success, false on error.
#[no_mangle]
pub extern "C" fn ifa_rt_fs_write_string(path: *const u8, content: *const u8) -> bool {
    if path.is_null() || content.is_null() {
        return false;
    }
    let path_str = unsafe {
        match std::ffi::CStr::from_ptr(path as *const std::os::raw::c_char).to_str() {
            Ok(s) => s,
            Err(_) => return false,
        }
    };
    let content_str = unsafe {
        match std::ffi::CStr::from_ptr(content as *const std::os::raw::c_char).to_str() {
            Ok(s) => s,
            Err(_) => return false,
        }
    };
    std::fs::write(path_str, content_str.as_bytes()).is_ok()
}

/// Check if a path exists on the filesystem.
#[no_mangle]
pub extern "C" fn ifa_rt_fs_exists(path: *const u8) -> bool {
    if path.is_null() {
        return false;
    }
    let path_str = unsafe {
        match std::ffi::CStr::from_ptr(path as *const std::os::raw::c_char).to_str() {
            Ok(s) => s,
            Err(_) => return false,
        }
    };
    std::path::Path::new(path_str).exists()
}

/// Query size in bytes of a file. Returns 0 if inaccessible.
#[no_mangle]
pub extern "C" fn ifa_rt_fs_file_size(path: *const u8) -> u64 {
    if path.is_null() {
        return 0;
    }
    let path_str = unsafe {
        match std::ffi::CStr::from_ptr(path as *const std::os::raw::c_char).to_str() {
            Ok(s) => s,
            Err(_) => return 0,
        }
    };
    std::fs::metadata(path_str).map(|m| m.len()).unwrap_or(0)
}

/// Remove a file on disk. Returns true on success, false on error.
#[no_mangle]
pub extern "C" fn ifa_rt_fs_remove_file(path: *const u8) -> bool {
    if path.is_null() {
        return false;
    }
    let path_str = unsafe {
        match std::ffi::CStr::from_ptr(path as *const std::os::raw::c_char).to_str() {
            Ok(s) => s,
            Err(_) => return false,
        }
    };
    std::fs::remove_file(path_str).is_ok()
}

/// Recursively create a directory on disk. Returns true on success, false on error.
#[no_mangle]
pub extern "C" fn ifa_rt_fs_create_dir_all(path: *const u8) -> bool {
    if path.is_null() {
        return false;
    }
    let path_str = unsafe {
        match std::ffi::CStr::from_ptr(path as *const std::os::raw::c_char).to_str() {
            Ok(s) => s,
            Err(_) => return false,
        }
    };
    std::fs::create_dir_all(path_str).is_ok()
}

/// Read entries of a directory on disk, sorted lexicographically and joined by newline '\n'.
/// Returns an empty null-terminated string on error or if the directory is empty.
#[no_mangle]
pub extern "C" fn ifa_rt_fs_read_dir(path: *const u8) -> *mut u8 {
    let path_str = if path.is_null() {
        ""
    } else {
        unsafe {
            std::ffi::CStr::from_ptr(path as *const std::os::raw::c_char)
                .to_str()
                .unwrap_or("")
        }
    };
    let mut names = Vec::new();
    if let Ok(entries) = std::fs::read_dir(path_str) {
        for entry in entries.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                names.push(name);
            }
        }
    }
    names.sort();
    let content = names.join("\n");
    let bytes = format!("{}\0", content).into_bytes();
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

/// Check if a path points to an existing directory.
#[no_mangle]
pub extern "C" fn ifa_rt_fs_is_dir(path: *const u8) -> bool {
    if path.is_null() {
        return false;
    }
    let path_str = unsafe {
        match std::ffi::CStr::from_ptr(path as *const std::os::raw::c_char).to_str() {
            Ok(s) => s,
            Err(_) => return false,
        }
    };
    std::path::Path::new(path_str).is_dir()
}

/// Copy a file on disk. Returns true on success, false on error.
#[no_mangle]
pub extern "C" fn ifa_rt_fs_copy_file(src: *const u8, dst: *const u8) -> bool {
    if src.is_null() || dst.is_null() {
        return false;
    }
    let src_str = unsafe {
        match std::ffi::CStr::from_ptr(src as *const std::os::raw::c_char).to_str() {
            Ok(s) => s,
            Err(_) => return false,
        }
    };
    let dst_str = unsafe {
        match std::ffi::CStr::from_ptr(dst as *const std::os::raw::c_char).to_str() {
            Ok(s) => s,
            Err(_) => return false,
        }
    };
    std::fs::copy(src_str, dst_str).is_ok()
}

/// Remove an empty directory on disk. Returns true on success, false on error.
#[no_mangle]
pub extern "C" fn ifa_rt_fs_remove_dir(path: *const u8) -> bool {
    if path.is_null() {
        return false;
    }
    let path_str = unsafe {
        match std::ffi::CStr::from_ptr(path as *const std::os::raw::c_char).to_str() {
            Ok(s) => s,
            Err(_) => return false,
        }
    };
    std::fs::remove_dir(path_str).is_ok()
}

/// Recursively remove a directory and all of its contents on disk. Returns true on success, false on error.
#[no_mangle]
pub extern "C" fn ifa_rt_fs_remove_dir_all(path: *const u8) -> bool {
    if path.is_null() {
        return false;
    }
    let path_str = unsafe {
        match std::ffi::CStr::from_ptr(path as *const std::os::raw::c_char).to_str() {
            Ok(s) => s,
            Err(_) => return false,
        }
    };
    std::fs::remove_dir_all(path_str).is_ok()
}

/// Rename or move a file or directory on disk. Returns true on success, false on error.
#[no_mangle]
pub extern "C" fn ifa_rt_fs_rename(src: *const u8, dst: *const u8) -> bool {
    if src.is_null() || dst.is_null() {
        return false;
    }
    let src_str = unsafe {
        match std::ffi::CStr::from_ptr(src as *const std::os::raw::c_char).to_str() {
            Ok(s) => s,
            Err(_) => return false,
        }
    };
    let dst_str = unsafe {
        match std::ffi::CStr::from_ptr(dst as *const std::os::raw::c_char).to_str() {
            Ok(s) => s,
            Err(_) => return false,
        }
    };
    std::fs::rename(src_str, dst_str).is_ok()
}

/// Return the byte-length of a null-terminated UTF-8 C string (excluding the null terminator).
/// Returns 0 for a null pointer.
#[no_mangle]
pub extern "C" fn ifa_rt_string_len(s: *const u8) -> i64 {
    if s.is_null() {
        return 0;
    }
    unsafe {
        match std::ffi::CStr::from_ptr(s as *const std::os::raw::c_char).to_str() {
            Ok(st) => st.chars().count() as i64,
            Err(_) => 0,
        }
    }
}

/// Return the Unicode scalar value (codepoint) of the character at the given index
/// in a null-terminated UTF-8 C string.  Returns -1 on out-of-bounds or null input.
#[no_mangle]
pub extern "C" fn ifa_rt_string_char_at(s: *const u8, index: i64) -> i64 {
    if s.is_null() || index < 0 {
        return -1;
    }
    let st = unsafe {
        match std::ffi::CStr::from_ptr(s as *const std::os::raw::c_char).to_str() {
            Ok(st) => st,
            Err(_) => return -1,
        }
    };
    match st.chars().nth(index as usize) {
        Some(c) => c as i64,
        None => -1,
    }
}

/// Return a substring of length `len` starting at character index `start`.
/// Returns an empty string if out-of-bounds, negative or invalid.
#[no_mangle]
pub extern "C" fn ifa_rt_string_substr(s: *const u8, start: i64, len: i64) -> *mut u8 {
    let empty_res = || {
        let bytes = b"\0";
        let layout = std::alloc::Layout::from_size_align(1, 1).unwrap();
        unsafe {
            let mem = std::alloc::alloc(layout);
            if !mem.is_null() {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), mem, 1);
            }
            mem
        }
    };

    if s.is_null() || start < 0 || len <= 0 {
        return empty_res();
    }
    let st = unsafe {
        match std::ffi::CStr::from_ptr(s as *const std::os::raw::c_char).to_str() {
            Ok(st) => st,
            Err(_) => return empty_res(),
        }
    };
    let start_idx = start as usize;
    let count = len as usize;
    let substr: String = st.chars().skip(start_idx).take(count).collect();
    let bytes = format!("{}\0", substr).into_bytes();
    let layout = std::alloc::Layout::from_size_align(bytes.len(), 1).unwrap();
    unsafe {
        let mem = std::alloc::alloc(layout);
        if mem.is_null() {
            std::alloc::handle_alloc_error(layout);
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), mem, bytes.len());
        mem
    }
}

/// Execute an external command and return exit status code (0 for success).
#[no_mangle]
pub extern "C" fn ifa_rt_process_exec(cmd: *const u8, args: *const u8) -> i64 {
    if cmd.is_null() {
        return -1;
    }
    let cmd_str = unsafe {
        match std::ffi::CStr::from_ptr(cmd as *const std::os::raw::c_char).to_str() {
            Ok(s) => s,
            Err(_) => return -1,
        }
    };
    let args_str = if args.is_null() {
        ""
    } else {
        unsafe {
            std::ffi::CStr::from_ptr(args as *const std::os::raw::c_char)
                .to_str()
                .unwrap_or("")
        }
    };
    let mut command = std::process::Command::new(cmd_str);
    if !args_str.is_empty() {
        for arg in args_str.split_whitespace() {
            command.arg(arg);
        }
    }
    match command.status() {
        Ok(status) => status.code().unwrap_or(1) as i64,
        Err(_) => -1,
    }
}

/// Execute an external command and capture stdout as a heap-allocated null-terminated C string.
#[no_mangle]
pub extern "C" fn ifa_rt_process_exec_output(cmd: *const u8, args: *const u8) -> *mut u8 {
    let empty_alloc = || {
        let layout = std::alloc::Layout::from_size_align(1, 1).unwrap();
        unsafe {
            let mem = std::alloc::alloc(layout);
            if !mem.is_null() {
                *mem = 0;
            }
            mem
        }
    };
    if cmd.is_null() {
        return empty_alloc();
    }
    let cmd_str = unsafe {
        match std::ffi::CStr::from_ptr(cmd as *const std::os::raw::c_char).to_str() {
            Ok(s) => s,
            Err(_) => return empty_alloc(),
        }
    };
    let args_str = if args.is_null() {
        ""
    } else {
        unsafe {
            std::ffi::CStr::from_ptr(args as *const std::os::raw::c_char)
                .to_str()
                .unwrap_or("")
        }
    };
    let mut command = std::process::Command::new(cmd_str);
    if !args_str.is_empty() {
        for arg in args_str.split_whitespace() {
            command.arg(arg);
        }
    }
    let output = match command.output() {
        Ok(out) => out.stdout,
        Err(_) => Vec::new(),
    };
    let mut bytes = output;
    bytes.push(0);
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

/// Execute an external command and capture stderr as a heap-allocated null-terminated C string.
#[no_mangle]
pub extern "C" fn ifa_rt_process_exec_stderr(cmd: *const u8, args: *const u8) -> *mut u8 {
    let empty_alloc = || {
        let layout = std::alloc::Layout::from_size_align(1, 1).unwrap();
        unsafe {
            let mem = std::alloc::alloc(layout);
            if !mem.is_null() {
                *mem = 0;
            }
            mem
        }
    };
    if cmd.is_null() {
        return empty_alloc();
    }
    let cmd_str = unsafe {
        match std::ffi::CStr::from_ptr(cmd as *const std::os::raw::c_char).to_str() {
            Ok(s) => s,
            Err(_) => return empty_alloc(),
        }
    };
    let args_str = if args.is_null() {
        ""
    } else {
        unsafe {
            std::ffi::CStr::from_ptr(args as *const std::os::raw::c_char)
                .to_str()
                .unwrap_or("")
        }
    };
    let mut command = std::process::Command::new(cmd_str);
    if !args_str.is_empty() {
        for arg in args_str.split_whitespace() {
            command.arg(arg);
        }
    }
    let output = match command.output() {
        Ok(out) => out.stderr,
        Err(_) => Vec::new(),
    };
    let mut bytes = output;
    bytes.push(0);
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

/// Execute an external command with standard input provided, returning exit status code.
#[no_mangle]
pub extern "C" fn ifa_rt_process_exec_with_stdin(
    cmd: *const u8,
    args: *const u8,
    stdin_str: *const u8,
) -> i64 {
    if cmd.is_null() {
        return -1;
    }
    let cmd_str = unsafe {
        match std::ffi::CStr::from_ptr(cmd as *const std::os::raw::c_char).to_str() {
            Ok(s) => s,
            Err(_) => return -1,
        }
    };
    let args_str = if args.is_null() {
        ""
    } else {
        unsafe {
            std::ffi::CStr::from_ptr(args as *const std::os::raw::c_char)
                .to_str()
                .unwrap_or("")
        }
    };
    let stdin_bytes = if stdin_str.is_null() {
        None
    } else {
        unsafe {
            std::ffi::CStr::from_ptr(stdin_str as *const std::os::raw::c_char)
                .to_str()
                .ok()
                .map(|s| s.as_bytes().to_vec())
        }
    };
    let mut command = std::process::Command::new(cmd_str);
    if !args_str.is_empty() {
        for arg in args_str.split_whitespace() {
            command.arg(arg);
        }
    }
    if let Some(ref input) = stdin_bytes {
        use std::io::Write;
        command.stdin(std::process::Stdio::piped());
        let mut child = match command.spawn() {
            Ok(c) => c,
            Err(_) => return -1,
        };
        if let Some(mut cin) = child.stdin.take() {
            let _ = cin.write_all(input);
            let _ = cin.flush();
        }
        match child.wait() {
            Ok(status) => status.code().unwrap_or(1) as i64,
            Err(_) => -1,
        }
    } else {
        match command.status() {
            Ok(status) => status.code().unwrap_or(1) as i64,
            Err(_) => -1,
        }
    }
}

/// Detect the most optimal system linker tool name (`mold`, `lld`, `clang`, or `ld`).
#[no_mangle]
pub extern "C" fn ifa_rt_process_find_linker() -> *mut u8 {
    let candidates = ["mold", "lld", "ld.lld", "clang", "gcc", "ld"];
    let mut resolved = "clang";
    for cand in candidates {
        if which_tool_exists(cand) {
            resolved = cand;
            break;
        }
    }
    let bytes = format!("{}\0", resolved).into_bytes();
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

/// Locate a tool executable on system path. Returns full path or empty string if not found.
#[no_mangle]
pub extern "C" fn ifa_rt_process_find_tool(tool_name: *const u8) -> *mut u8 {
    let empty_alloc = || {
        let layout = std::alloc::Layout::from_size_align(1, 1).unwrap();
        unsafe {
            let mem = std::alloc::alloc(layout);
            if !mem.is_null() {
                *mem = 0;
            }
            mem
        }
    };
    if tool_name.is_null() {
        return empty_alloc();
    }
    let name_str = unsafe {
        match std::ffi::CStr::from_ptr(tool_name as *const std::os::raw::c_char).to_str() {
            Ok(s) => s,
            Err(_) => return empty_alloc(),
        }
    };
    let found_path = find_tool_path(name_str).unwrap_or_default();
    let bytes = format!("{}\0", found_path).into_bytes();
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

fn which_tool_exists(name: &str) -> bool {
    find_tool_path(name).is_some()
}

fn find_tool_path(name: &str) -> Option<String> {
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = std::path::Path::new(&dir).join(name);
            if candidate.is_file() {
                return Some(candidate.to_string_lossy().into_owned());
            }
        }
    }
    for dir in &["/usr/bin", "/usr/local/bin", "/bin"] {
        let candidate = std::path::Path::new(dir).join(name);
        if candidate.is_file() {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }
    None
}

/// Read an environment variable. Returns empty string if unset.
#[no_mangle]
pub extern "C" fn ifa_rt_env_var(name: *const u8) -> *mut u8 {
    let empty_alloc = || {
        let layout = std::alloc::Layout::from_size_align(1, 1).unwrap();
        unsafe {
            let mem = std::alloc::alloc(layout);
            if !mem.is_null() {
                *mem = 0;
            }
            mem
        }
    };
    if name.is_null() {
        return empty_alloc();
    }
    let name_str = unsafe {
        match std::ffi::CStr::from_ptr(name as *const std::os::raw::c_char).to_str() {
            Ok(s) => s,
            Err(_) => return empty_alloc(),
        }
    };
    let val = std::env::var(name_str).unwrap_or_default();
    let bytes = format!("{}\0", val).into_bytes();
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

/// Query the current working directory of the process. Returns empty string on error.
#[no_mangle]
pub extern "C" fn ifa_rt_process_current_dir() -> *mut u8 {
    let empty_alloc = || {
        let layout = std::alloc::Layout::from_size_align(1, 1).unwrap();
        unsafe {
            let mem = std::alloc::alloc(layout);
            if !mem.is_null() {
                *mem = 0;
            }
            mem
        }
    };
    let cur_str = match std::env::current_dir() {
        Ok(p) => p.to_string_lossy().into_owned(),
        Err(_) => return empty_alloc(),
    };
    let bytes = format!("{}\0", cur_str).into_bytes();
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

/// Set the current working directory of the process. Returns true on success, false on error.
#[no_mangle]
pub extern "C" fn ifa_rt_process_set_current_dir(path: *const u8) -> bool {
    if path.is_null() {
        return false;
    }
    let path_str = unsafe {
        match std::ffi::CStr::from_ptr(path as *const std::os::raw::c_char).to_str() {
            Ok(s) => s,
            Err(_) => return false,
        }
    };
    std::env::set_current_dir(path_str).is_ok()
}

/// Retrieve process command-line arguments reliably across platforms.
/// On Linux, falls back to `/proc/self/cmdline` when `main` entrypoint bypassed Rust std `lang_start`.
fn get_cmdline_args() -> Vec<String> {
    let std_args: Vec<String> = std::env::args().collect();
    if std_args.len() <= 1 {
        #[cfg(target_os = "linux")]
        if let Ok(bytes) = std::fs::read("/proc/self/cmdline") {
            let mut proc_args = Vec::new();
            for part in bytes.split(|&b| b == 0) {
                if !part.is_empty() {
                    if let Ok(s) = std::str::from_utf8(part) {
                        proc_args.push(s.to_string());
                    }
                }
            }
            if proc_args.len() > std_args.len() {
                return proc_args;
            }
        }
    }
    std_args
}

/// Query the total number of command-line arguments passed to the process.
#[no_mangle]
pub extern "C" fn ifa_rt_args_count() -> i64 {
    get_cmdline_args().len() as i64
}

/// Retrieve the command-line argument at the given zero-based index as a heap-allocated C string.
/// Returns an empty string if index is out of bounds or negative.
#[no_mangle]
pub extern "C" fn ifa_rt_args_get(index: i64) -> *mut u8 {
    let empty_alloc = || {
        let layout = std::alloc::Layout::from_size_align(1, 1).unwrap();
        unsafe {
            let mem = std::alloc::alloc(layout);
            if !mem.is_null() {
                *mem = 0;
            }
            mem
        }
    };
    if index < 0 {
        return empty_alloc();
    }
    let args = get_cmdline_args();
    let arg = match args.get(index as usize) {
        Some(s) => s,
        None => return empty_alloc(),
    };
    let bytes = format!("{}\0", arg).into_bytes();
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

/// Query the number of elements currently queued in the channel.
#[no_mangle]
pub extern "C" fn ifa_rt_channel_len(chan: *mut IfaChannelHandle) -> i64 {
    if chan.is_null() {
        return 0;
    }
    let handle = unsafe { &*chan };
    handle.0.len() as i64
}

/// Query the capacity of the channel buffer.
#[no_mangle]
pub extern "C" fn ifa_rt_channel_capacity(chan: *mut IfaChannelHandle) -> i64 {
    if chan.is_null() {
        return 0;
    }
    let handle = unsafe { &*chan };
    handle.0.capacity() as i64
}

/// Send an immutable slice descriptor over the channel via an allocated message slot.
#[no_mangle]
pub extern "C" fn ifa_rt_channel_send_slice(chan: *mut IfaChannelHandle, slice: IfaSlice) -> i32 {
    if chan.is_null() {
        return -1;
    }
    let slot = GLOBAL_ALLOCATOR.alloc(std::mem::size_of::<IfaSlice>(), 8, 0) as *mut IfaSlice;
    unsafe {
        *slot = slice;
    }
    let res = ifa_rt_channel_send(chan, slot as *mut u8);
    if res != 0 {
        GLOBAL_ALLOCATOR.free(slot as *mut u8);
    }
    res
}

/// Receive an immutable slice descriptor from the channel.
#[no_mangle]
pub extern "C" fn ifa_rt_channel_recv_slice(
    chan: *mut IfaChannelHandle,
    out_slice: *mut IfaSlice,
) -> i32 {
    if chan.is_null() || out_slice.is_null() {
        return -1;
    }
    let mut msg_ptr = std::ptr::null_mut();
    let res = ifa_rt_channel_recv(chan, &mut msg_ptr);
    if res == 0 && !msg_ptr.is_null() {
        unsafe {
            *out_slice = *(msg_ptr as *const IfaSlice);
        }
        GLOBAL_ALLOCATOR.free(msg_ptr);
    }
    res
}

/// Non-blocking try send for an immutable slice descriptor over the channel.
#[no_mangle]
pub extern "C" fn ifa_rt_channel_try_send_slice(
    chan: *mut IfaChannelHandle,
    slice: IfaSlice,
) -> i32 {
    if chan.is_null() {
        return -1;
    }
    let slot = GLOBAL_ALLOCATOR.alloc(std::mem::size_of::<IfaSlice>(), 8, 0) as *mut IfaSlice;
    unsafe {
        *slot = slice;
    }
    let res = ifa_rt_channel_try_send(chan, slot as *mut u8);
    if res != 0 {
        GLOBAL_ALLOCATOR.free(slot as *mut u8);
    }
    res
}

/// Non-blocking try receive for an immutable slice descriptor from the channel.
#[no_mangle]
pub extern "C" fn ifa_rt_channel_try_recv_slice(
    chan: *mut IfaChannelHandle,
    out_slice: *mut IfaSlice,
) -> i32 {
    if chan.is_null() || out_slice.is_null() {
        return -1;
    }
    let mut msg_ptr = std::ptr::null_mut();
    let res = ifa_rt_channel_try_recv(chan, &mut msg_ptr);
    if res == 0 && !msg_ptr.is_null() {
        unsafe {
            *out_slice = *(msg_ptr as *const IfaSlice);
        }
        GLOBAL_ALLOCATOR.free(msg_ptr);
    }
    res
}

/// Send a mutable slice descriptor over the channel via an allocated message slot.
#[no_mangle]
pub extern "C" fn ifa_rt_channel_send_mut_slice(
    chan: *mut IfaChannelHandle,
    slice: IfaMutSlice,
) -> i32 {
    if chan.is_null() {
        return -1;
    }
    let slot = GLOBAL_ALLOCATOR.alloc(std::mem::size_of::<IfaMutSlice>(), 8, 0) as *mut IfaMutSlice;
    unsafe {
        *slot = slice;
    }
    let res = ifa_rt_channel_send(chan, slot as *mut u8);
    if res != 0 {
        GLOBAL_ALLOCATOR.free(slot as *mut u8);
    }
    res
}

/// Receive a mutable slice descriptor from the channel.
#[no_mangle]
pub extern "C" fn ifa_rt_channel_recv_mut_slice(
    chan: *mut IfaChannelHandle,
    out_slice: *mut IfaMutSlice,
) -> i32 {
    if chan.is_null() || out_slice.is_null() {
        return -1;
    }
    let mut msg_ptr = std::ptr::null_mut();
    let res = ifa_rt_channel_recv(chan, &mut msg_ptr);
    if res == 0 && !msg_ptr.is_null() {
        unsafe {
            *out_slice = *(msg_ptr as *const IfaMutSlice);
        }
        GLOBAL_ALLOCATOR.free(msg_ptr);
    }
    res
}

/// Transfer ownership of a pre-allocated generational arena to a target fiber.
#[no_mangle]
pub extern "C" fn ifa_rt_arena_transfer_owner(arena_id: u16, new_fiber_id: u64) -> i32 {
    if arena_id == 0 {
        return 0;
    }
    GLOBAL_ALLOCATOR.set_arena_owner(arena_id, new_fiber_id);
    1
}

/// Verify that a slice memory buffer belongs to a specified generational arena.
/// Returns 1 if slice memory is validated inside arena (or global arena), 0 on mismatch.
#[no_mangle]
pub extern "C" fn ifa_rt_slice_verify_arena(slice: IfaSlice, arena_id: u16) -> i32 {
    if slice.ptr.is_null() || slice.len == 0 {
        return 1;
    }
    if arena_id == 0 {
        return 1;
    }
    unsafe {
        let header = &*(slice
            .ptr
            .sub(std::mem::size_of::<crate::header::GenHeader>())
            as *const crate::header::GenHeader);
        if header.arena_id == arena_id || header.arena_id == crate::header::ARENA_THREAD_LOCAL_CALL
        {
            1
        } else {
            0
        }
    }
}

/// Monotonic time base reference for zero-allocation nanosecond clocks.
static MONOTONIC_BASE: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

/// Return current monotonic timestamp in nanoseconds since runtime initialization.
#[no_mangle]
pub extern "C" fn ifa_rt_now_ns() -> u64 {
    let base = MONOTONIC_BASE.get_or_init(std::time::Instant::now);
    base.elapsed().as_nanos() as u64
}

/// Operation mode for a zero-allocation select wait entry.
pub const IFA_SELECT_OP_RECV: u32 = 0;
pub const IFA_SELECT_OP_SEND: u32 = 1;
pub const IFA_SELECT_OP_TIMEOUT: u32 = 2;
pub const IFA_SELECT_OP_DEADLINE: u32 = 3;
pub const IFA_SELECT_OP_FD_READ: u32 = 4;
pub const IFA_SELECT_OP_FD_WRITE: u32 = 5;
pub const IFA_SELECT_OP_IO_TOKEN: u32 = 6;

/// Readiness status for a zero-allocation select wait entry.
pub const IFA_SELECT_STATUS_PENDING: u32 = 0;
pub const IFA_SELECT_STATUS_READY: u32 = 1;
pub const IFA_SELECT_STATUS_CLOSED: u32 = 2;
pub const IFA_SELECT_STATUS_TIMED_OUT: u32 = 3;

/// A single wait entry in a zero-allocation select wait table.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IfaSelectWaitEntry {
    /// Pointer to the IFA channel handle (or null for timeout/deadline/io arm).
    pub chan: *mut IfaChannelHandle,
    /// Operation to wait for: 0 = RECV, 1 = SEND, 2 = TIMEOUT, 3 = DEADLINE, 4 = FD_READ, 5 = FD_WRITE, 6 = IO_TOKEN.
    pub op: u32,
    /// Status: 0 = PENDING, 1 = READY, 2 = CLOSED, 3 = TIMED_OUT.
    pub status: u32,
    /// Payload pointer (transferred value or target buffer/result slot).
    pub val: *mut u8,
    /// Priority weight for deterministic selection (higher value = preferred).
    pub priority: i32,
    /// Alignment padding.
    pub _pad: u32,
    /// Timeout duration in nanoseconds (or absolute monotonic deadline, or fd/token).
    pub timeout_ns: u64,
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
    /// Alignment padding.
    pub _pad: i32,
    /// Start timestamp in nanoseconds recorded at table initialization or first poll (-1 if uninitialized).
    pub start_ns: i64,
}

/// Zero-allocation non-blocking multiplexing evaluation of a select wait table with priority and timeout.
///
/// Returns:
/// - index >= 0: the index of the satisfied entry with highest priority (marked READY)
/// - table.count: if `has_default != 0` and no entry is ready
/// - -2: if all monitored channels are closed and no timeout is pending
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

    if t.start_ns < 0 {
        t.start_ns = ifa_rt_now_ns() as i64;
    }
    let now_ns = ifa_rt_now_ns() as i64;

    let entries = unsafe { std::slice::from_raw_parts_mut(t.entries, t.count) };
    let mut any_open = false;
    let mut best_ready: Option<(usize, i32)> = None;

    for (idx, entry) in entries.iter_mut().enumerate() {
        match entry.op {
            IFA_SELECT_OP_RECV => {
                if entry.chan.is_null() {
                    continue;
                }
                let handle = unsafe { &*entry.chan };
                let is_closed = handle.0.is_closed();
                if !is_closed {
                    any_open = true;
                }

                if !handle.0.is_empty() {
                    entry.status = IFA_SELECT_STATUS_READY;
                    match best_ready {
                        None => best_ready = Some((idx, entry.priority)),
                        Some((_, best_prio)) if entry.priority > best_prio => {
                            best_ready = Some((idx, entry.priority));
                        }
                        _ => {}
                    }
                } else if is_closed {
                    entry.status = IFA_SELECT_STATUS_CLOSED;
                } else {
                    entry.status = IFA_SELECT_STATUS_PENDING;
                }
            }
            IFA_SELECT_OP_SEND => {
                if entry.chan.is_null() {
                    continue;
                }
                let handle = unsafe { &*entry.chan };
                let is_closed = handle.0.is_closed();
                if !is_closed {
                    any_open = true;
                }

                if !handle.0.is_full() && !is_closed {
                    entry.status = IFA_SELECT_STATUS_READY;
                    match best_ready {
                        None => best_ready = Some((idx, entry.priority)),
                        Some((_, best_prio)) if entry.priority > best_prio => {
                            best_ready = Some((idx, entry.priority));
                        }
                        _ => {}
                    }
                } else if is_closed {
                    entry.status = IFA_SELECT_STATUS_CLOSED;
                } else {
                    entry.status = IFA_SELECT_STATUS_PENDING;
                }
            }
            IFA_SELECT_OP_TIMEOUT => {
                any_open = true;
                if now_ns - t.start_ns >= entry.timeout_ns as i64 {
                    entry.status = IFA_SELECT_STATUS_READY;
                    match best_ready {
                        None => best_ready = Some((idx, entry.priority)),
                        Some((_, best_prio)) if entry.priority > best_prio => {
                            best_ready = Some((idx, entry.priority));
                        }
                        _ => {}
                    }
                } else {
                    entry.status = IFA_SELECT_STATUS_PENDING;
                }
            }
            IFA_SELECT_OP_DEADLINE => {
                any_open = true;
                if now_ns >= entry.timeout_ns as i64 {
                    entry.status = IFA_SELECT_STATUS_READY;
                    match best_ready {
                        None => best_ready = Some((idx, entry.priority)),
                        Some((_, best_prio)) if entry.priority > best_prio => {
                            best_ready = Some((idx, entry.priority));
                        }
                        _ => {}
                    }
                } else {
                    entry.status = IFA_SELECT_STATUS_PENDING;
                }
            }
            IFA_SELECT_OP_FD_READ => {
                any_open = true;
                let fd = entry.timeout_ns as i32;
                #[cfg(unix)]
                let is_ready = {
                    let mut pfd = libc::pollfd {
                        fd,
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    let ret = unsafe { libc::poll(&mut pfd as *mut libc::pollfd, 1, 0) };
                    ret > 0 && (pfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR)) != 0
                };
                #[cfg(not(unix))]
                let is_ready = false;

                if is_ready {
                    entry.status = IFA_SELECT_STATUS_READY;
                    match best_ready {
                        None => best_ready = Some((idx, entry.priority)),
                        Some((_, best_prio)) if entry.priority > best_prio => {
                            best_ready = Some((idx, entry.priority));
                        }
                        _ => {}
                    }
                } else {
                    entry.status = IFA_SELECT_STATUS_PENDING;
                }
            }
            IFA_SELECT_OP_FD_WRITE => {
                any_open = true;
                let fd = entry.timeout_ns as i32;
                #[cfg(unix)]
                let is_ready = {
                    let mut pfd = libc::pollfd {
                        fd,
                        events: libc::POLLOUT,
                        revents: 0,
                    };
                    let ret = unsafe { libc::poll(&mut pfd as *mut libc::pollfd, 1, 0) };
                    ret > 0 && (pfd.revents & (libc::POLLOUT | libc::POLLERR)) != 0
                };
                #[cfg(not(unix))]
                let is_ready = false;

                if is_ready {
                    entry.status = IFA_SELECT_STATUS_READY;
                    match best_ready {
                        None => best_ready = Some((idx, entry.priority)),
                        Some((_, best_prio)) if entry.priority > best_prio => {
                            best_ready = Some((idx, entry.priority));
                        }
                        _ => {}
                    }
                } else {
                    entry.status = IFA_SELECT_STATUS_PENDING;
                }
            }
            IFA_SELECT_OP_IO_TOKEN => {
                any_open = true;
                let token = entry.timeout_ns;
                if let Some(res) = GLOBAL_SCHEDULER.take_completed_io(token) {
                    if !entry.val.is_null() {
                        unsafe {
                            *(entry.val as *mut i64) = res;
                        }
                    }
                    entry.status = IFA_SELECT_STATUS_READY;
                    match best_ready {
                        None => best_ready = Some((idx, entry.priority)),
                        Some((_, best_prio)) if entry.priority > best_prio => {
                            best_ready = Some((idx, entry.priority));
                        }
                        _ => {}
                    }
                } else {
                    entry.status = IFA_SELECT_STATUS_PENDING;
                }
            }
            _ => {
                if !entry.chan.is_null() {
                    let handle = unsafe { &*entry.chan };
                    if !handle.0.is_empty() {
                        entry.status = IFA_SELECT_STATUS_READY;
                        match best_ready {
                            None => best_ready = Some((idx, entry.priority)),
                            Some((_, best_prio)) if entry.priority > best_prio => {
                                best_ready = Some((idx, entry.priority));
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    if let Some((best_idx, _)) = best_ready {
        return best_idx as i64;
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
/// Integrates with io_uring and async reactor to wake IO and timed events without busy-spinning.
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
            let woken = crate::reactor::GLOBAL_REACTOR.poll_and_wake();
            if woken > 0 {
                spins = 0;
                continue;
            }
            crate::reactor::GLOBAL_REACTOR.wait_and_wake(std::time::Duration::from_millis(1));
            spins = 32;
        }
    }
}

/// Non-blocking or cooperative select over channels with priority weights and optional timeout.
/// If `timeout_ns > 0`, waits at most `timeout_ns` nanoseconds before selecting the timeout branch (index `num_channels`).
#[no_mangle]
pub extern "C" fn ifa_rt_channel_select_timed(
    channels: *const *mut IfaChannelHandle,
    priorities: *const i32,
    num_channels: usize,
    timeout_ns: u64,
    has_default: i32,
) -> i64 {
    if (channels.is_null() && timeout_ns == 0) || (num_channels == 0 && timeout_ns == 0) {
        return if has_default != 0 { 0 } else { -2 };
    }

    let chan_slice = if !channels.is_null() && num_channels > 0 {
        unsafe { std::slice::from_raw_parts(channels, num_channels) }
    } else {
        &[]
    };
    let prio_slice = if !priorities.is_null() && num_channels > 0 {
        unsafe { std::slice::from_raw_parts(priorities, num_channels) }
    } else {
        &[]
    };

    let total_entries = num_channels + if timeout_ns > 0 { 1 } else { 0 };

    let mut stack_entries = [IfaSelectWaitEntry {
        chan: std::ptr::null_mut(),
        op: IFA_SELECT_OP_RECV,
        status: IFA_SELECT_STATUS_PENDING,
        val: std::ptr::null_mut(),
        priority: 0,
        _pad: 0,
        timeout_ns: 0,
    }; 32];

    if total_entries <= 32 {
        for (idx, &handle_ptr) in chan_slice.iter().enumerate() {
            stack_entries[idx].chan = handle_ptr;
            stack_entries[idx].priority = prio_slice.get(idx).copied().unwrap_or(0);
        }
        if timeout_ns > 0 {
            stack_entries[num_channels].chan = std::ptr::null_mut();
            stack_entries[num_channels].op = IFA_SELECT_OP_TIMEOUT;
            stack_entries[num_channels].status = IFA_SELECT_STATUS_PENDING;
            stack_entries[num_channels].val = std::ptr::null_mut();
            stack_entries[num_channels].priority = i32::MIN;
            stack_entries[num_channels].timeout_ns = timeout_ns;
        }
        let mut table = IfaSelectWaitTable {
            entries: stack_entries.as_mut_ptr(),
            count: total_entries,
            has_default,
            _pad: 0,
            start_ns: -1,
        };
        ifa_rt_channel_select_wait_table(&mut table)
    } else {
        let mut dynamic_entries: Vec<IfaSelectWaitEntry> = chan_slice
            .iter()
            .enumerate()
            .map(|(idx, &ch)| IfaSelectWaitEntry {
                chan: ch,
                op: IFA_SELECT_OP_RECV,
                status: IFA_SELECT_STATUS_PENDING,
                val: std::ptr::null_mut(),
                priority: prio_slice.get(idx).copied().unwrap_or(0),
                _pad: 0,
                timeout_ns: 0,
            })
            .collect();
        if timeout_ns > 0 {
            dynamic_entries.push(IfaSelectWaitEntry {
                chan: std::ptr::null_mut(),
                op: IFA_SELECT_OP_TIMEOUT,
                status: IFA_SELECT_STATUS_PENDING,
                val: std::ptr::null_mut(),
                priority: i32::MIN,
                _pad: 0,
                timeout_ns,
            });
        }
        let mut table = IfaSelectWaitTable {
            entries: dynamic_entries.as_mut_ptr(),
            count: total_entries,
            has_default,
            _pad: 0,
            start_ns: -1,
        };
        ifa_rt_channel_select_wait_table(&mut table)
    }
}

/// Non-blocking or cooperative select over an array of channels with explicit priorities.
#[no_mangle]
pub extern "C" fn ifa_rt_channel_select_prioritized(
    channels: *const *mut IfaChannelHandle,
    priorities: *const i32,
    num_channels: usize,
    has_default: i32,
) -> i64 {
    ifa_rt_channel_select_timed(channels, priorities, num_channels, 0, has_default)
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
    ifa_rt_channel_select_timed(channels, std::ptr::null(), num_channels, 0, has_default)
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

/// Verify that a strided sub-slice range `[start..end:stride]` is strictly within bounds `[0..len]`.
#[no_mangle]
pub extern "C-unwind" fn ifa_rt_slice_strided_bounds_check(
    start: usize,
    end: usize,
    stride: usize,
    len: usize,
    msg: *const u8,
) {
    if stride == 0 {
        if !msg.is_null() {
            ifa_rt_panic_assert(msg);
        } else {
            let err_msg = b"strided slice step must be strictly greater than zero\0";
            ifa_rt_panic_assert(err_msg.as_ptr());
        }
    }
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

// =========================================================================
// IFA Native High-Performance Multi-Arena SIMD and Stencil Kernels
// =========================================================================

/// Multi-arena 2D convolution with fused bias and optional activation (f32).
/// activation: 0 = None, 1 = ReLU, 2 = Clamp
///
/// # Safety
///
/// All raw pointers (`dst`, `img`, `weights`, `bias`) must be valid for read/write
/// operations across their computed index bounds and appropriately aligned.
#[no_mangle]
pub unsafe extern "C" fn ifa_simd_multi_arena_conv2d_f32(
    dst: *mut f32,
    img: *const f32,
    weights: *const f32,
    bias: *const f32,
    h_out: i64,
    w_out: i64,
    stride_y: i64,
    stride_x: i64,
    img_width: i64,
    activation: i32,
) {
    if dst.is_null() || img.is_null() || weights.is_null() || h_out <= 0 || w_out <= 0 {
        return;
    }
    let w0 = *weights;
    let b0 = if !bias.is_null() { *bias } else { 0.0 };
    for y in 0..h_out {
        let y_off = (y * stride_y) * img_width;
        let y_out_off = y * w_out;
        for x in 0..w_out {
            let in_idx = y_off + (x * stride_x);
            let out_idx = y_out_off + x;
            let mut accum = *img.offset(in_idx as isize) * w0 + b0;
            if activation == 1 && accum < 0.0 {
                accum = 0.0;
            }
            *dst.offset(out_idx as isize) += accum;
        }
    }
}

/// Multi-arena 2D convolution with fused bias and optional activation (f64).
///
/// # Safety
///
/// All raw pointers (`dst`, `img`, `weights`, `bias`) must be valid for read/write
/// operations across their computed index bounds and appropriately aligned.
#[no_mangle]
pub unsafe extern "C" fn ifa_simd_multi_arena_conv2d_f64(
    dst: *mut f64,
    img: *const f64,
    weights: *const f64,
    bias: *const f64,
    h_out: i64,
    w_out: i64,
    stride_y: i64,
    stride_x: i64,
    img_width: i64,
    activation: i32,
) {
    if dst.is_null() || img.is_null() || weights.is_null() || h_out <= 0 || w_out <= 0 {
        return;
    }
    let w0 = *weights;
    let b0 = if !bias.is_null() { *bias } else { 0.0 };
    for y in 0..h_out {
        let y_off = (y * stride_y) * img_width;
        let y_out_off = y * w_out;
        for x in 0..w_out {
            let in_idx = y_off + (x * stride_x);
            let out_idx = y_out_off + x;
            let mut accum = *img.offset(in_idx as isize) * w0 + b0;
            if activation == 1 && accum < 0.0 {
                accum = 0.0;
            }
            *dst.offset(out_idx as isize) += accum;
        }
    }
}

/// Multi-arena 2D convolution with fused bias and optional activation (i64).
///
/// # Safety
///
/// All raw pointers (`dst`, `img`, `weights`, `bias`) must be valid for read/write
/// operations across their computed index bounds and appropriately aligned.
#[no_mangle]
pub unsafe extern "C" fn ifa_simd_multi_arena_conv2d_i64(
    dst: *mut i64,
    img: *const i64,
    weights: *const i64,
    bias: *const i64,
    h_out: i64,
    w_out: i64,
    stride_y: i64,
    stride_x: i64,
    img_width: i64,
    activation: i32,
) {
    if dst.is_null() || img.is_null() || weights.is_null() || h_out <= 0 || w_out <= 0 {
        return;
    }
    let w0 = *weights;
    let b0 = if !bias.is_null() { *bias } else { 0 };
    for y in 0..h_out {
        let y_off = (y * stride_y) * img_width;
        let y_out_off = y * w_out;
        for x in 0..w_out {
            let in_idx = y_off + (x * stride_x);
            let out_idx = y_out_off + x;
            let mut accum = *img.offset(in_idx as isize) * w0 + b0;
            if activation == 1 && accum < 0 {
                accum = 0;
            }
            *dst.offset(out_idx as isize) += accum;
        }
    }
}

/// Multi-arena 3D volumetric convolution with fused bias and optional activation (f32).
///
/// # Safety
///
/// All raw pointers (`dst`, `volume`, `filter`, `bias`) must be valid for read/write
/// operations across computed 3D index bounds and appropriately aligned.
#[no_mangle]
pub unsafe extern "C" fn ifa_simd_multi_arena_conv3d_f32(
    dst: *mut f32,
    volume: *const f32,
    filter: *const f32,
    bias: *const f32,
    d_out: i64,
    h_out: i64,
    w_out: i64,
    stride_z: i64,
    stride_y: i64,
    stride_x: i64,
    plane_pitch: i64,
    row_pitch: i64,
    activation: i32,
) {
    if dst.is_null()
        || volume.is_null()
        || filter.is_null()
        || d_out <= 0
        || h_out <= 0
        || w_out <= 0
    {
        return;
    }
    let f0 = *filter;
    let b0 = if !bias.is_null() { *bias } else { 0.0 };
    for z in 0..d_out {
        let z_off = (z * stride_z) * plane_pitch;
        for y in 0..h_out {
            let y_off = (y * stride_y) * row_pitch;
            let out_plane_off = (z * h_out + y) * w_out;
            for x in 0..w_out {
                let in_idx = z_off + y_off + (x * stride_x);
                let out_idx = out_plane_off + x;
                let mut accum = *volume.offset(in_idx as isize) * f0 + b0;
                if activation == 1 && accum < 0.0 {
                    accum = 0.0;
                }
                *dst.offset(out_idx as isize) += accum;
            }
        }
    }
}

/// Multi-arena 3D volumetric convolution with fused bias and optional activation (f64).
///
/// # Safety
///
/// All raw pointers (`dst`, `volume`, `filter`, `bias`) must be valid for read/write
/// operations across computed 3D index bounds and appropriately aligned.
#[no_mangle]
pub unsafe extern "C" fn ifa_simd_multi_arena_conv3d_f64(
    dst: *mut f64,
    volume: *const f64,
    filter: *const f64,
    bias: *const f64,
    d_out: i64,
    h_out: i64,
    w_out: i64,
    stride_z: i64,
    stride_y: i64,
    stride_x: i64,
    plane_pitch: i64,
    row_pitch: i64,
    activation: i32,
) {
    if dst.is_null()
        || volume.is_null()
        || filter.is_null()
        || d_out <= 0
        || h_out <= 0
        || w_out <= 0
    {
        return;
    }
    let f0 = *filter;
    let b0 = if !bias.is_null() { *bias } else { 0.0 };
    for z in 0..d_out {
        let z_off = (z * stride_z) * plane_pitch;
        for y in 0..h_out {
            let y_off = (y * stride_y) * row_pitch;
            let out_plane_off = (z * h_out + y) * w_out;
            for x in 0..w_out {
                let in_idx = z_off + y_off + (x * stride_x);
                let out_idx = out_plane_off + x;
                let mut accum = *volume.offset(in_idx as isize) * f0 + b0;
                if activation == 1 && accum < 0.0 {
                    accum = 0.0;
                }
                *dst.offset(out_idx as isize) += accum;
            }
        }
    }
}

/// Multi-arena 3D volumetric convolution with fused bias and optional activation (i64).
///
/// # Safety
///
/// All raw pointers (`dst`, `volume`, `filter`, `bias`) must be valid for read/write
/// operations across computed 3D index bounds and appropriately aligned.
#[no_mangle]
pub unsafe extern "C" fn ifa_simd_multi_arena_conv3d_i64(
    dst: *mut i64,
    volume: *const i64,
    filter: *const i64,
    bias: *const i64,
    d_out: i64,
    h_out: i64,
    w_out: i64,
    stride_z: i64,
    stride_y: i64,
    stride_x: i64,
    plane_pitch: i64,
    row_pitch: i64,
    activation: i32,
) {
    if dst.is_null()
        || volume.is_null()
        || filter.is_null()
        || d_out <= 0
        || h_out <= 0
        || w_out <= 0
    {
        return;
    }
    let f0 = *filter;
    let b0 = if !bias.is_null() { *bias } else { 0 };
    for z in 0..d_out {
        let z_off = (z * stride_z) * plane_pitch;
        for y in 0..h_out {
            let y_off = (y * stride_y) * row_pitch;
            let out_plane_off = (z * h_out + y) * w_out;
            for x in 0..w_out {
                let in_idx = z_off + y_off + (x * stride_x);
                let out_idx = out_plane_off + x;
                let mut accum = *volume.offset(in_idx as isize) * f0 + b0;
                if activation == 1 && accum < 0 {
                    accum = 0;
                }
                *dst.offset(out_idx as isize) += accum;
            }
        }
    }
}

/// Multi-arena slice dot product (f32) with independent strides per arena operand.
///
/// # Safety
///
/// `src1` and `src2` must be valid for `len` strided reads and appropriately aligned.
#[no_mangle]
pub unsafe extern "C" fn ifa_simd_multi_arena_slice_dot_f32(
    src1: *const f32,
    src2: *const f32,
    len: i64,
    stride1: i64,
    stride2: i64,
) -> f32 {
    if src1.is_null() || src2.is_null() || len <= 0 {
        return 0.0;
    }
    let mut sum: f32 = 0.0;
    for i in 0..len {
        let v1 = *src1.offset((i * stride1) as isize);
        let v2 = *src2.offset((i * stride2) as isize);
        sum += v1 * v2;
    }
    sum
}

/// Multi-arena slice dot product (f64) with independent strides per arena operand.
///
/// # Safety
///
/// `src1` and `src2` must be valid for `len` strided reads and appropriately aligned.
#[no_mangle]
pub unsafe extern "C" fn ifa_simd_multi_arena_slice_dot_f64(
    src1: *const f64,
    src2: *const f64,
    len: i64,
    stride1: i64,
    stride2: i64,
) -> f64 {
    if src1.is_null() || src2.is_null() || len <= 0 {
        return 0.0;
    }
    let mut sum: f64 = 0.0;
    for i in 0..len {
        let v1 = *src1.offset((i * stride1) as isize);
        let v2 = *src2.offset((i * stride2) as isize);
        sum += v1 * v2;
    }
    sum
}

/// Multi-arena slice dot product (i64) with independent strides per arena operand.
///
/// # Safety
///
/// `src1` and `src2` must be valid for `len` strided reads and appropriately aligned.
#[no_mangle]
pub unsafe extern "C" fn ifa_simd_multi_arena_slice_dot_i64(
    src1: *const i64,
    src2: *const i64,
    len: i64,
    stride1: i64,
    stride2: i64,
) -> i64 {
    if src1.is_null() || src2.is_null() || len <= 0 {
        return 0;
    }
    let mut sum: i64 = 0;
    for i in 0..len {
        let v1 = *src1.offset((i * stride1) as isize);
        let v2 = *src2.offset((i * stride2) as isize);
        sum = sum.wrapping_add(v1.wrapping_mul(v2));
    }
    sum
}

/// Multi-arena slice dot product (i32) with independent strides per arena operand.
///
/// # Safety
///
/// `src1` and `src2` must be valid for `len` strided reads and appropriately aligned.
#[no_mangle]
pub unsafe extern "C" fn ifa_simd_multi_arena_slice_dot_i32(
    src1: *const i32,
    src2: *const i32,
    len: i64,
    stride1: i64,
    stride2: i64,
) -> i32 {
    if src1.is_null() || src2.is_null() || len <= 0 {
        return 0;
    }
    let mut sum: i32 = 0;
    for i in 0..len {
        let v1 = *src1.offset((i * stride1) as isize);
        let v2 = *src2.offset((i * stride2) as isize);
        sum = sum.wrapping_add(v1.wrapping_mul(v2));
    }
    sum
}

/// Multi-arena tripartite vector accumulation `dst[i * stride_dst] += src1[i * stride1] * src2[i * stride2]`.
///
/// # Safety
///
/// `dst`, `src1`, and `src2` must be valid for `len` strided read/write access and appropriately aligned.
#[no_mangle]
pub unsafe extern "C" fn ifa_simd_multi_arena_tripartite_f32(
    dst: *mut f32,
    src1: *const f32,
    src2: *const f32,
    len: i64,
    stride_dst: i64,
    stride1: i64,
    stride2: i64,
) {
    if dst.is_null() || src1.is_null() || src2.is_null() || len <= 0 {
        return;
    }
    for i in 0..len {
        let v1 = *src1.offset((i * stride1) as isize);
        let v2 = *src2.offset((i * stride2) as isize);
        let p_dst = dst.offset((i * stride_dst) as isize);
        *p_dst += v1 * v2;
    }
}

/// Multi-arena tripartite vector accumulation (f64).
///
/// # Safety
///
/// `dst`, `src1`, and `src2` must be valid for `len` strided read/write access and appropriately aligned.
#[no_mangle]
pub unsafe extern "C" fn ifa_simd_multi_arena_tripartite_f64(
    dst: *mut f64,
    src1: *const f64,
    src2: *const f64,
    len: i64,
    stride_dst: i64,
    stride1: i64,
    stride2: i64,
) {
    if dst.is_null() || src1.is_null() || src2.is_null() || len <= 0 {
        return;
    }
    for i in 0..len {
        let v1 = *src1.offset((i * stride1) as isize);
        let v2 = *src2.offset((i * stride2) as isize);
        let p_dst = dst.offset((i * stride_dst) as isize);
        *p_dst += v1 * v2;
    }
}

/// Arena slice count-if reduction (f32).
///
/// # Safety
///
/// `src` must be valid for `len` elements read and appropriately aligned.
#[no_mangle]
pub unsafe extern "C" fn ifa_simd_arena_slice_count_if_gt_f32(
    src: *const f32,
    len: i64,
    threshold: f32,
) -> i64 {
    if src.is_null() || len <= 0 {
        return 0;
    }
    let mut count: i64 = 0;
    for i in 0..len {
        if *src.offset(i as isize) > threshold {
            count += 1;
        }
    }
    count
}

/// Arena slice count-if reduction (f64).
///
/// # Safety
///
/// `src` must be valid for `len` elements read and appropriately aligned.
#[no_mangle]
pub unsafe extern "C" fn ifa_simd_arena_slice_count_if_gt_f64(
    src: *const f64,
    len: i64,
    threshold: f64,
) -> i64 {
    if src.is_null() || len <= 0 {
        return 0;
    }
    let mut count: i64 = 0;
    for i in 0..len {
        if *src.offset(i as isize) > threshold {
            count += 1;
        }
    }
    count
}

/// Arena slice count-if reduction (i32).
///
/// # Safety
///
/// `src` must be valid for `len` elements read and appropriately aligned.
#[no_mangle]
pub unsafe extern "C" fn ifa_simd_arena_slice_count_if_gt_i32(
    src: *const i32,
    len: i64,
    threshold: i32,
) -> i64 {
    if src.is_null() || len <= 0 {
        return 0;
    }
    let mut count: i64 = 0;
    for i in 0..len {
        if *src.offset(i as isize) > threshold {
            count += 1;
        }
    }
    count
}

/// Arena slice count-if reduction (i64).
///
/// # Safety
///
/// `src` must be valid for `len` elements read and appropriately aligned.
#[no_mangle]
pub unsafe extern "C" fn ifa_simd_arena_slice_count_if_gt_i64(
    src: *const i64,
    len: i64,
    threshold: i64,
) -> i64 {
    if src.is_null() || len <= 0 {
        return 0;
    }
    let mut count: i64 = 0;
    for i in 0..len {
        if *src.offset(i as isize) > threshold {
            count += 1;
        }
    }
    count
}

// =========================================================================
// IFA Native Dilated Convolutions & Zero-Heap Spatial Pooling Kernels
// =========================================================================

/// Multi-arena 2D dilated (atrous) convolution with fused bias and optional activation (f32).
/// activation: 0 = None, 1 = ReLU
///
/// # Safety
///
/// All raw pointers (`dst`, `img`, `weights`, `bias`) must be valid for read/write
/// operations across computed dilated index bounds and appropriately aligned.
#[no_mangle]
pub unsafe extern "C" fn ifa_simd_multi_arena_dilated_conv2d_f32(
    dst: *mut f32,
    img: *const f32,
    weights: *const f32,
    bias: *const f32,
    h_out: i64,
    w_out: i64,
    stride_y: i64,
    stride_x: i64,
    dilation_y: i64,
    dilation_x: i64,
    kernel_h: i64,
    kernel_w: i64,
    img_width: i64,
    activation: i32,
) {
    if dst.is_null()
        || img.is_null()
        || weights.is_null()
        || h_out <= 0
        || w_out <= 0
        || kernel_h <= 0
        || kernel_w <= 0
    {
        return;
    }
    let b0 = if !bias.is_null() { *bias } else { 0.0 };
    for y in 0..h_out {
        let y_base = (y * stride_y) * img_width;
        let y_out_off = y * w_out;
        for x in 0..w_out {
            let x_base = x * stride_x;
            let out_idx = y_out_off + x;
            let mut accum = 0.0f32;
            for ky in 0..kernel_h {
                let in_row = y_base + (ky * dilation_y) * img_width;
                let w_row = ky * kernel_w;
                for kx in 0..kernel_w {
                    let in_idx = in_row + x_base + (kx * dilation_x);
                    let w_idx = w_row + kx;
                    accum += *img.offset(in_idx as isize) * *weights.offset(w_idx as isize);
                }
            }
            accum += b0;
            if activation == 1 && accum < 0.0 {
                accum = 0.0;
            }
            *dst.offset(out_idx as isize) += accum;
        }
    }
}

/// Multi-arena 2D dilated (atrous) convolution with fused bias and optional activation (f64).
/// activation: 0 = None, 1 = ReLU
///
/// # Safety
///
/// All raw pointers (`dst`, `img`, `weights`, `bias`) must be valid for read/write
/// operations across computed dilated index bounds and appropriately aligned.
#[no_mangle]
pub unsafe extern "C" fn ifa_simd_multi_arena_dilated_conv2d_f64(
    dst: *mut f64,
    img: *const f64,
    weights: *const f64,
    bias: *const f64,
    h_out: i64,
    w_out: i64,
    stride_y: i64,
    stride_x: i64,
    dilation_y: i64,
    dilation_x: i64,
    kernel_h: i64,
    kernel_w: i64,
    img_width: i64,
    activation: i32,
) {
    if dst.is_null()
        || img.is_null()
        || weights.is_null()
        || h_out <= 0
        || w_out <= 0
        || kernel_h <= 0
        || kernel_w <= 0
    {
        return;
    }
    let b0 = if !bias.is_null() { *bias } else { 0.0 };
    for y in 0..h_out {
        let y_base = (y * stride_y) * img_width;
        let y_out_off = y * w_out;
        for x in 0..w_out {
            let x_base = x * stride_x;
            let out_idx = y_out_off + x;
            let mut accum = 0.0f64;
            for ky in 0..kernel_h {
                let in_row = y_base + (ky * dilation_y) * img_width;
                let w_row = ky * kernel_w;
                for kx in 0..kernel_w {
                    let in_idx = in_row + x_base + (kx * dilation_x);
                    let w_idx = w_row + kx;
                    accum += *img.offset(in_idx as isize) * *weights.offset(w_idx as isize);
                }
            }
            accum += b0;
            if activation == 1 && accum < 0.0 {
                accum = 0.0;
            }
            *dst.offset(out_idx as isize) += accum;
        }
    }
}

/// Multi-arena 2D dilated (atrous) convolution with fused bias and optional activation (i64).
/// activation: 0 = None, 1 = ReLU
///
/// # Safety
///
/// All raw pointers (`dst`, `img`, `weights`, `bias`) must be valid for read/write
/// operations across computed dilated index bounds and appropriately aligned.
#[no_mangle]
pub unsafe extern "C" fn ifa_simd_multi_arena_dilated_conv2d_i64(
    dst: *mut i64,
    img: *const i64,
    weights: *const i64,
    bias: *const i64,
    h_out: i64,
    w_out: i64,
    stride_y: i64,
    stride_x: i64,
    dilation_y: i64,
    dilation_x: i64,
    kernel_h: i64,
    kernel_w: i64,
    img_width: i64,
    activation: i32,
) {
    if dst.is_null()
        || img.is_null()
        || weights.is_null()
        || h_out <= 0
        || w_out <= 0
        || kernel_h <= 0
        || kernel_w <= 0
    {
        return;
    }
    let b0 = if !bias.is_null() { *bias } else { 0 };
    for y in 0..h_out {
        let y_base = (y * stride_y) * img_width;
        let y_out_off = y * w_out;
        for x in 0..w_out {
            let x_base = x * stride_x;
            let out_idx = y_out_off + x;
            let mut accum: i64 = 0;
            for ky in 0..kernel_h {
                let in_row = y_base + (ky * dilation_y) * img_width;
                let w_row = ky * kernel_w;
                for kx in 0..kernel_w {
                    let in_idx = in_row + x_base + (kx * dilation_x);
                    let w_idx = w_row + kx;
                    accum += *img.offset(in_idx as isize) * *weights.offset(w_idx as isize);
                }
            }
            accum += b0;
            if activation == 1 && accum < 0 {
                accum = 0;
            }
            *dst.offset(out_idx as isize) += accum;
        }
    }
}

/// Multi-arena 2D spatial max-pooling kernel (f32).
///
/// # Safety
///
/// `dst` and `img` must be valid for memory operations across computed spatial window bounds.
#[no_mangle]
pub unsafe extern "C" fn ifa_simd_multi_arena_maxpool2d_f32(
    dst: *mut f32,
    img: *const f32,
    h_out: i64,
    w_out: i64,
    stride_y: i64,
    stride_x: i64,
    pool_h: i64,
    pool_w: i64,
    img_width: i64,
) {
    if dst.is_null() || img.is_null() || h_out <= 0 || w_out <= 0 || pool_h <= 0 || pool_w <= 0 {
        return;
    }
    for y in 0..h_out {
        let y_base = (y * stride_y) * img_width;
        let y_out_off = y * w_out;
        for x in 0..w_out {
            let x_base = x * stride_x;
            let out_idx = y_out_off + x;
            let mut max_val = f32::NEG_INFINITY;
            for ky in 0..pool_h {
                let in_row = y_base + ky * img_width;
                for kx in 0..pool_w {
                    let in_idx = in_row + x_base + kx;
                    let v = *img.offset(in_idx as isize);
                    if v > max_val {
                        max_val = v;
                    }
                }
            }
            *dst.offset(out_idx as isize) = max_val;
        }
    }
}

/// Multi-arena 2D spatial max-pooling kernel (f64).
///
/// # Safety
///
/// `dst` and `img` must be valid for memory operations across computed spatial window bounds.
#[no_mangle]
pub unsafe extern "C" fn ifa_simd_multi_arena_maxpool2d_f64(
    dst: *mut f64,
    img: *const f64,
    h_out: i64,
    w_out: i64,
    stride_y: i64,
    stride_x: i64,
    pool_h: i64,
    pool_w: i64,
    img_width: i64,
) {
    if dst.is_null() || img.is_null() || h_out <= 0 || w_out <= 0 || pool_h <= 0 || pool_w <= 0 {
        return;
    }
    for y in 0..h_out {
        let y_base = (y * stride_y) * img_width;
        let y_out_off = y * w_out;
        for x in 0..w_out {
            let x_base = x * stride_x;
            let out_idx = y_out_off + x;
            let mut max_val = f64::NEG_INFINITY;
            for ky in 0..pool_h {
                let in_row = y_base + ky * img_width;
                for kx in 0..pool_w {
                    let in_idx = in_row + x_base + kx;
                    let v = *img.offset(in_idx as isize);
                    if v > max_val {
                        max_val = v;
                    }
                }
            }
            *dst.offset(out_idx as isize) = max_val;
        }
    }
}

/// Multi-arena 2D spatial max-pooling kernel (i64).
///
/// # Safety
///
/// `dst` and `img` must be valid for memory operations across computed spatial window bounds.
#[no_mangle]
pub unsafe extern "C" fn ifa_simd_multi_arena_maxpool2d_i64(
    dst: *mut i64,
    img: *const i64,
    h_out: i64,
    w_out: i64,
    stride_y: i64,
    stride_x: i64,
    pool_h: i64,
    pool_w: i64,
    img_width: i64,
) {
    if dst.is_null() || img.is_null() || h_out <= 0 || w_out <= 0 || pool_h <= 0 || pool_w <= 0 {
        return;
    }
    for y in 0..h_out {
        let y_base = (y * stride_y) * img_width;
        let y_out_off = y * w_out;
        for x in 0..w_out {
            let x_base = x * stride_x;
            let out_idx = y_out_off + x;
            let mut max_val = i64::MIN;
            for ky in 0..pool_h {
                let in_row = y_base + ky * img_width;
                for kx in 0..pool_w {
                    let in_idx = in_row + x_base + kx;
                    let v = *img.offset(in_idx as isize);
                    if v > max_val {
                        max_val = v;
                    }
                }
            }
            *dst.offset(out_idx as isize) = max_val;
        }
    }
}

/// Multi-arena 2D spatial average-pooling kernel (f32).
///
/// # Safety
///
/// `dst` and `img` must be valid for memory operations across computed spatial window bounds.
#[no_mangle]
pub unsafe extern "C" fn ifa_simd_multi_arena_avgpool2d_f32(
    dst: *mut f32,
    img: *const f32,
    h_out: i64,
    w_out: i64,
    stride_y: i64,
    stride_x: i64,
    pool_h: i64,
    pool_w: i64,
    img_width: i64,
) {
    if dst.is_null() || img.is_null() || h_out <= 0 || w_out <= 0 || pool_h <= 0 || pool_w <= 0 {
        return;
    }
    let area = (pool_h * pool_w) as f32;
    let inv_area = 1.0f32 / area;
    for y in 0..h_out {
        let y_base = (y * stride_y) * img_width;
        let y_out_off = y * w_out;
        for x in 0..w_out {
            let x_base = x * stride_x;
            let out_idx = y_out_off + x;
            let mut sum_val = 0.0f32;
            for ky in 0..pool_h {
                let in_row = y_base + ky * img_width;
                for kx in 0..pool_w {
                    let in_idx = in_row + x_base + kx;
                    sum_val += *img.offset(in_idx as isize);
                }
            }
            *dst.offset(out_idx as isize) = sum_val * inv_area;
        }
    }
}

/// Multi-arena 2D spatial average-pooling kernel (f64).
///
/// # Safety
///
/// `dst` and `img` must be valid for memory operations across computed spatial window bounds.
#[no_mangle]
pub unsafe extern "C" fn ifa_simd_multi_arena_avgpool2d_f64(
    dst: *mut f64,
    img: *const f64,
    h_out: i64,
    w_out: i64,
    stride_y: i64,
    stride_x: i64,
    pool_h: i64,
    pool_w: i64,
    img_width: i64,
) {
    if dst.is_null() || img.is_null() || h_out <= 0 || w_out <= 0 || pool_h <= 0 || pool_w <= 0 {
        return;
    }
    let area = (pool_h * pool_w) as f64;
    let inv_area = 1.0f64 / area;
    for y in 0..h_out {
        let y_base = (y * stride_y) * img_width;
        let y_out_off = y * w_out;
        for x in 0..w_out {
            let x_base = x * stride_x;
            let out_idx = y_out_off + x;
            let mut sum_val = 0.0f64;
            for ky in 0..pool_h {
                let in_row = y_base + ky * img_width;
                for kx in 0..pool_w {
                    let in_idx = in_row + x_base + kx;
                    sum_val += *img.offset(in_idx as isize);
                }
            }
            *dst.offset(out_idx as isize) = sum_val * inv_area;
        }
    }
}

/// Multi-arena 2D spatial average-pooling kernel (i64).
///
/// # Safety
///
/// `dst` and `img` must be valid for memory operations across computed spatial window bounds.
#[no_mangle]
pub unsafe extern "C" fn ifa_simd_multi_arena_avgpool2d_i64(
    dst: *mut i64,
    img: *const i64,
    h_out: i64,
    w_out: i64,
    stride_y: i64,
    stride_x: i64,
    pool_h: i64,
    pool_w: i64,
    img_width: i64,
) {
    if dst.is_null() || img.is_null() || h_out <= 0 || w_out <= 0 || pool_h <= 0 || pool_w <= 0 {
        return;
    }
    let area = pool_h * pool_w;
    for y in 0..h_out {
        let y_base = (y * stride_y) * img_width;
        let y_out_off = y * w_out;
        for x in 0..w_out {
            let x_base = x * stride_x;
            let out_idx = y_out_off + x;
            let mut sum_val: i64 = 0;
            for ky in 0..pool_h {
                let in_row = y_base + ky * img_width;
                for kx in 0..pool_w {
                    let in_idx = in_row + x_base + kx;
                    sum_val += *img.offset(in_idx as isize);
                }
            }
            *dst.offset(out_idx as isize) = sum_val / area;
        }
    }
}

/// Multi-arena 2D depthwise convolution kernel (f32).
///
/// # Safety
///
/// `dst`, `img`, and `weights` must point to valid allocations for their channel and spatial bounds.
#[no_mangle]
pub unsafe extern "C" fn ifa_simd_multi_arena_depthwise_conv2d_f32(
    dst: *mut f32,
    img: *const f32,
    weights: *const f32,
    bias: *const f32,
    channels: i64,
    h_out: i64,
    w_out: i64,
    stride_y: i64,
    stride_x: i64,
    kernel_h: i64,
    kernel_w: i64,
    img_h: i64,
    img_w: i64,
    activation: i32,
) {
    if dst.is_null()
        || img.is_null()
        || weights.is_null()
        || channels <= 0
        || h_out <= 0
        || w_out <= 0
        || kernel_h <= 0
        || kernel_w <= 0
        || img_h <= 0
        || img_w <= 0
    {
        return;
    }
    let in_area = img_h * img_w;
    let kernel_area = kernel_h * kernel_w;
    let out_area = h_out * w_out;

    for c in 0..channels {
        let c_img_off = c * in_area;
        let c_w_off = c * kernel_area;
        let c_dst_off = c * out_area;
        let b = if !bias.is_null() {
            *bias.offset(c as isize)
        } else {
            0.0f32
        };

        for y in 0..h_out {
            let y_base = (y * stride_y) * img_w;
            let y_out_off = y * w_out;
            for x in 0..w_out {
                let x_base = x * stride_x;
                let out_idx = c_dst_off + y_out_off + x;
                let mut accum = 0.0f32;

                for ky in 0..kernel_h {
                    let in_row = y_base + ky * img_w;
                    let w_row = ky * kernel_w;
                    for kx in 0..kernel_w {
                        let in_idx = c_img_off + in_row + x_base + kx;
                        let w_idx = c_w_off + w_row + kx;
                        accum += *img.offset(in_idx as isize) * *weights.offset(w_idx as isize);
                    }
                }
                accum += b;
                if activation == 1 && accum < 0.0f32 {
                    accum = 0.0f32;
                }
                *dst.offset(out_idx as isize) = accum;
            }
        }
    }
}

/// Multi-arena 2D depthwise convolution kernel (f64).
///
/// # Safety
///
/// `dst`, `img`, and `weights` must point to valid allocations for their channel and spatial bounds.
#[no_mangle]
pub unsafe extern "C" fn ifa_simd_multi_arena_depthwise_conv2d_f64(
    dst: *mut f64,
    img: *const f64,
    weights: *const f64,
    bias: *const f64,
    channels: i64,
    h_out: i64,
    w_out: i64,
    stride_y: i64,
    stride_x: i64,
    kernel_h: i64,
    kernel_w: i64,
    img_h: i64,
    img_w: i64,
    activation: i32,
) {
    if dst.is_null()
        || img.is_null()
        || weights.is_null()
        || channels <= 0
        || h_out <= 0
        || w_out <= 0
        || kernel_h <= 0
        || kernel_w <= 0
        || img_h <= 0
        || img_w <= 0
    {
        return;
    }
    let in_area = img_h * img_w;
    let kernel_area = kernel_h * kernel_w;
    let out_area = h_out * w_out;

    for c in 0..channels {
        let c_img_off = c * in_area;
        let c_w_off = c * kernel_area;
        let c_dst_off = c * out_area;
        let b = if !bias.is_null() {
            *bias.offset(c as isize)
        } else {
            0.0f64
        };

        for y in 0..h_out {
            let y_base = (y * stride_y) * img_w;
            let y_out_off = y * w_out;
            for x in 0..w_out {
                let x_base = x * stride_x;
                let out_idx = c_dst_off + y_out_off + x;
                let mut accum = 0.0f64;

                for ky in 0..kernel_h {
                    let in_row = y_base + ky * img_w;
                    let w_row = ky * kernel_w;
                    for kx in 0..kernel_w {
                        let in_idx = c_img_off + in_row + x_base + kx;
                        let w_idx = c_w_off + w_row + kx;
                        accum += *img.offset(in_idx as isize) * *weights.offset(w_idx as isize);
                    }
                }
                accum += b;
                if activation == 1 && accum < 0.0f64 {
                    accum = 0.0f64;
                }
                *dst.offset(out_idx as isize) = accum;
            }
        }
    }
}

/// Multi-arena 2D depthwise convolution kernel (i64).
///
/// # Safety
///
/// `dst`, `img`, and `weights` must point to valid allocations for their channel and spatial bounds.
#[no_mangle]
pub unsafe extern "C" fn ifa_simd_multi_arena_depthwise_conv2d_i64(
    dst: *mut i64,
    img: *const i64,
    weights: *const i64,
    bias: *const i64,
    channels: i64,
    h_out: i64,
    w_out: i64,
    stride_y: i64,
    stride_x: i64,
    kernel_h: i64,
    kernel_w: i64,
    img_h: i64,
    img_w: i64,
    activation: i32,
) {
    if dst.is_null()
        || img.is_null()
        || weights.is_null()
        || channels <= 0
        || h_out <= 0
        || w_out <= 0
        || kernel_h <= 0
        || kernel_w <= 0
        || img_h <= 0
        || img_w <= 0
    {
        return;
    }
    let in_area = img_h * img_w;
    let kernel_area = kernel_h * kernel_w;
    let out_area = h_out * w_out;

    for c in 0..channels {
        let c_img_off = c * in_area;
        let c_w_off = c * kernel_area;
        let c_dst_off = c * out_area;
        let b = if !bias.is_null() {
            *bias.offset(c as isize)
        } else {
            0i64
        };

        for y in 0..h_out {
            let y_base = (y * stride_y) * img_w;
            let y_out_off = y * w_out;
            for x in 0..w_out {
                let x_base = x * stride_x;
                let out_idx = c_dst_off + y_out_off + x;
                let mut accum: i64 = 0;

                for ky in 0..kernel_h {
                    let in_row = y_base + ky * img_w;
                    let w_row = ky * kernel_w;
                    for kx in 0..kernel_w {
                        let in_idx = c_img_off + in_row + x_base + kx;
                        let w_idx = c_w_off + w_row + kx;
                        accum += *img.offset(in_idx as isize) * *weights.offset(w_idx as isize);
                    }
                }
                accum += b;
                if activation == 1 && accum < 0 {
                    accum = 0;
                }
                *dst.offset(out_idx as isize) = accum;
            }
        }
    }
}

/// Multi-arena 2D pointwise (1x1) convolution kernel (f32).
///
/// # Safety
///
/// `dst`, `img`, and `weights` must point to valid allocations for their channel and spatial bounds.
#[no_mangle]
pub unsafe extern "C" fn ifa_simd_multi_arena_pointwise_conv2d_f32(
    dst: *mut f32,
    img: *const f32,
    weights: *const f32,
    bias: *const f32,
    c_in: i64,
    c_out: i64,
    spatial_size: i64,
    activation: i32,
) {
    if dst.is_null()
        || img.is_null()
        || weights.is_null()
        || c_in <= 0
        || c_out <= 0
        || spatial_size <= 0
    {
        return;
    }

    for co in 0..c_out {
        let w_co_off = co * c_in;
        let dst_co_off = co * spatial_size;
        let b = if !bias.is_null() {
            *bias.offset(co as isize)
        } else {
            0.0f32
        };

        for p in 0..spatial_size {
            let out_idx = dst_co_off + p;
            let mut accum = 0.0f32;

            for ci in 0..c_in {
                let in_idx = ci * spatial_size + p;
                let w_idx = w_co_off + ci;
                accum += *img.offset(in_idx as isize) * *weights.offset(w_idx as isize);
            }
            accum += b;
            if activation == 1 && accum < 0.0f32 {
                accum = 0.0f32;
            }
            *dst.offset(out_idx as isize) = accum;
        }
    }
}

/// Multi-arena 2D pointwise (1x1) convolution kernel (f64).
///
/// # Safety
///
/// `dst`, `img`, and `weights` must point to valid allocations for their channel and spatial bounds.
#[no_mangle]
pub unsafe extern "C" fn ifa_simd_multi_arena_pointwise_conv2d_f64(
    dst: *mut f64,
    img: *const f64,
    weights: *const f64,
    bias: *const f64,
    c_in: i64,
    c_out: i64,
    spatial_size: i64,
    activation: i32,
) {
    if dst.is_null()
        || img.is_null()
        || weights.is_null()
        || c_in <= 0
        || c_out <= 0
        || spatial_size <= 0
    {
        return;
    }

    for co in 0..c_out {
        let w_co_off = co * c_in;
        let dst_co_off = co * spatial_size;
        let b = if !bias.is_null() {
            *bias.offset(co as isize)
        } else {
            0.0f64
        };

        for p in 0..spatial_size {
            let out_idx = dst_co_off + p;
            let mut accum = 0.0f64;

            for ci in 0..c_in {
                let in_idx = ci * spatial_size + p;
                let w_idx = w_co_off + ci;
                accum += *img.offset(in_idx as isize) * *weights.offset(w_idx as isize);
            }
            accum += b;
            if activation == 1 && accum < 0.0f64 {
                accum = 0.0f64;
            }
            *dst.offset(out_idx as isize) = accum;
        }
    }
}

/// Multi-arena 2D pointwise (1x1) convolution kernel (i64).
///
/// # Safety
///
/// `dst`, `img`, and `weights` must point to valid allocations for their channel and spatial bounds.
#[no_mangle]
pub unsafe extern "C" fn ifa_simd_multi_arena_pointwise_conv2d_i64(
    dst: *mut i64,
    img: *const i64,
    weights: *const i64,
    bias: *const i64,
    c_in: i64,
    c_out: i64,
    spatial_size: i64,
    activation: i32,
) {
    if dst.is_null()
        || img.is_null()
        || weights.is_null()
        || c_in <= 0
        || c_out <= 0
        || spatial_size <= 0
    {
        return;
    }

    for co in 0..c_out {
        let w_co_off = co * c_in;
        let dst_co_off = co * spatial_size;
        let b = if !bias.is_null() {
            *bias.offset(co as isize)
        } else {
            0i64
        };

        for p in 0..spatial_size {
            let out_idx = dst_co_off + p;
            let mut accum: i64 = 0;

            for ci in 0..c_in {
                let in_idx = ci * spatial_size + p;
                let w_idx = w_co_off + ci;
                accum += *img.offset(in_idx as isize) * *weights.offset(w_idx as isize);
            }
            accum += b;
            if activation == 1 && accum < 0 {
                accum = 0;
            }
            *dst.offset(out_idx as isize) = accum;
        }
    }
}

/// Multi-arena 2D batch normalization kernel (f32).
///
/// # Safety
///
/// `dst`, `src`, `mean`, and `var` must point to valid allocations for their channel bounds.
#[no_mangle]
pub unsafe extern "C" fn ifa_simd_multi_arena_batch_norm2d_f32(
    dst: *mut f32,
    src: *const f32,
    gamma: *const f32,
    beta: *const f32,
    mean: *const f32,
    var: *const f32,
    channels: i64,
    spatial_size: i64,
    epsilon: f32,
    activation: i32,
) {
    if dst.is_null()
        || src.is_null()
        || mean.is_null()
        || var.is_null()
        || channels <= 0
        || spatial_size <= 0
    {
        return;
    }

    for c in 0..channels {
        let m = *mean.offset(c as isize);
        let v = *var.offset(c as isize);
        let g = if !gamma.is_null() {
            *gamma.offset(c as isize)
        } else {
            1.0f32
        };
        let b = if !beta.is_null() {
            *beta.offset(c as isize)
        } else {
            0.0f32
        };

        let inv_std = 1.0f32 / (v + epsilon).sqrt();
        let scale = g * inv_std;
        let shift = b - (m * scale);
        let c_base = c * spatial_size;

        for i in 0..spatial_size {
            let idx = c_base + i;
            let x = *src.offset(idx as isize);
            let mut y = x * scale + shift;
            if activation == 1 && y < 0.0f32 {
                y = 0.0f32;
            }
            *dst.offset(idx as isize) = y;
        }
    }
}

/// Multi-arena 2D batch normalization kernel (f64).
///
/// # Safety
///
/// `dst`, `src`, `mean`, and `var` must point to valid allocations for their channel bounds.
#[no_mangle]
pub unsafe extern "C" fn ifa_simd_multi_arena_batch_norm2d_f64(
    dst: *mut f64,
    src: *const f64,
    gamma: *const f64,
    beta: *const f64,
    mean: *const f64,
    var: *const f64,
    channels: i64,
    spatial_size: i64,
    epsilon: f64,
    activation: i32,
) {
    if dst.is_null()
        || src.is_null()
        || mean.is_null()
        || var.is_null()
        || channels <= 0
        || spatial_size <= 0
    {
        return;
    }

    for c in 0..channels {
        let m = *mean.offset(c as isize);
        let v = *var.offset(c as isize);
        let g = if !gamma.is_null() {
            *gamma.offset(c as isize)
        } else {
            1.0f64
        };
        let b = if !beta.is_null() {
            *beta.offset(c as isize)
        } else {
            0.0f64
        };

        let inv_std = 1.0f64 / (v + epsilon).sqrt();
        let scale = g * inv_std;
        let shift = b - (m * scale);
        let c_base = c * spatial_size;

        for i in 0..spatial_size {
            let idx = c_base + i;
            let x = *src.offset(idx as isize);
            let mut y = x * scale + shift;
            if activation == 1 && y < 0.0f64 {
                y = 0.0f64;
            }
            *dst.offset(idx as isize) = y;
        }
    }
}

/// Multi-arena General Matrix Multiply (GEMM) kernel (f32).
///
/// Computes `C = beta * C + alpha * (A @ B) + bias` with optional activation.
///
/// # Safety
///
/// `c`, `a`, `b`, and `bias` must point to valid allocations for matrix dimensions (M, K, N).
#[no_mangle]
pub unsafe extern "C" fn ifa_simd_multi_arena_gemm_f32(
    c: *mut f32,
    a: *const f32,
    b: *const f32,
    bias: *const f32,
    m: i64,
    k: i64,
    n: i64,
    alpha: f32,
    beta: f32,
    activation: i32,
) {
    if c.is_null() || a.is_null() || b.is_null() || m <= 0 || k <= 0 || n <= 0 {
        return;
    }

    for i in 0..m {
        let a_row_off = i * k;
        let c_row_off = i * n;
        for j in 0..n {
            let mut accum = 0.0f32;
            for p in 0..k {
                let a_val = *a.offset((a_row_off + p) as isize);
                let b_val = *b.offset((p * n + j) as isize);
                accum += a_val * b_val;
            }

            let c_idx = (c_row_off + j) as isize;
            let existing_c = if beta != 0.0f32 {
                *c.offset(c_idx)
            } else {
                0.0f32
            };
            let bias_val = if !bias.is_null() {
                *bias.offset(j as isize)
            } else {
                0.0f32
            };

            let mut out_val = (alpha * accum) + (beta * existing_c) + bias_val;
            if activation == 1 && out_val < 0.0f32 {
                out_val = 0.0f32;
            }
            *c.offset(c_idx) = out_val;
        }
    }
}

/// Multi-arena General Matrix Multiply (GEMM) kernel (f64).
///
/// Computes `C = beta * C + alpha * (A @ B) + bias` with optional activation.
///
/// # Safety
///
/// `c`, `a`, `b`, and `bias` must point to valid allocations for matrix dimensions (M, K, N).
#[no_mangle]
pub unsafe extern "C" fn ifa_simd_multi_arena_gemm_f64(
    c: *mut f64,
    a: *const f64,
    b: *const f64,
    bias: *const f64,
    m: i64,
    k: i64,
    n: i64,
    alpha: f64,
    beta: f64,
    activation: i32,
) {
    if c.is_null() || a.is_null() || b.is_null() || m <= 0 || k <= 0 || n <= 0 {
        return;
    }

    for i in 0..m {
        let a_row_off = i * k;
        let c_row_off = i * n;
        for j in 0..n {
            let mut accum = 0.0f64;
            for p in 0..k {
                let a_val = *a.offset((a_row_off + p) as isize);
                let b_val = *b.offset((p * n + j) as isize);
                accum += a_val * b_val;
            }

            let c_idx = (c_row_off + j) as isize;
            let existing_c = if beta != 0.0f64 {
                *c.offset(c_idx)
            } else {
                0.0f64
            };
            let bias_val = if !bias.is_null() {
                *bias.offset(j as isize)
            } else {
                0.0f64
            };

            let mut out_val = (alpha * accum) + (beta * existing_c) + bias_val;
            if activation == 1 && out_val < 0.0f64 {
                out_val = 0.0f64;
            }
            *c.offset(c_idx) = out_val;
        }
    }
}

/// Multi-arena General Matrix Multiply (GEMM) kernel (i64).
///
/// Computes `C = beta * C + alpha * (A @ B) + bias` with optional activation.
///
/// # Safety
///
/// `c`, `a`, `b`, and `bias` must point to valid allocations for matrix dimensions (M, K, N).
#[no_mangle]
pub unsafe extern "C" fn ifa_simd_multi_arena_gemm_i64(
    c: *mut i64,
    a: *const i64,
    b: *const i64,
    bias: *const i64,
    m: i64,
    k: i64,
    n: i64,
    alpha: i64,
    beta: i64,
    activation: i32,
) {
    if c.is_null() || a.is_null() || b.is_null() || m <= 0 || k <= 0 || n <= 0 {
        return;
    }

    for i in 0..m {
        let a_row_off = i * k;
        let c_row_off = i * n;
        for j in 0..n {
            let mut accum = 0i64;
            for p in 0..k {
                let a_val = *a.offset((a_row_off + p) as isize);
                let b_val = *b.offset((p * n + j) as isize);
                accum = accum.wrapping_add(a_val.wrapping_mul(b_val));
            }

            let c_idx = (c_row_off + j) as isize;
            let existing_c = if beta != 0 { *c.offset(c_idx) } else { 0 };
            let bias_val = if !bias.is_null() {
                *bias.offset(j as isize)
            } else {
                0
            };

            let mut out_val = (alpha.wrapping_mul(accum))
                .wrapping_add(beta.wrapping_mul(existing_c))
                .wrapping_add(bias_val);
            if activation == 1 && out_val < 0 {
                out_val = 0;
            }
            *c.offset(c_idx) = out_val;
        }
    }
}

/// Multi-arena Layer Normalization kernel (f32).
///
/// # Safety
///
/// `dst` and `src` must point to allocations of length `batch_size * norm_size`.
#[no_mangle]
pub unsafe extern "C" fn ifa_simd_multi_arena_layer_norm_f32(
    dst: *mut f32,
    src: *const f32,
    gamma: *const f32,
    beta: *const f32,
    batch_size: i64,
    norm_size: i64,
    epsilon: f32,
    activation: i32,
) {
    if dst.is_null() || src.is_null() || batch_size <= 0 || norm_size <= 0 {
        return;
    }

    let inv_n = 1.0f32 / (norm_size as f32);

    for b in 0..batch_size {
        let row_off = (b * norm_size) as isize;

        // 1. Mean
        let mut sum = 0.0f32;
        for i in 0..norm_size {
            sum += *src.offset(row_off + i as isize);
        }
        let mean = sum * inv_n;

        // 2. Variance
        let mut sq_diff_sum = 0.0f32;
        for i in 0..norm_size {
            let diff = *src.offset(row_off + i as isize) - mean;
            sq_diff_sum += diff * diff;
        }
        let var = sq_diff_sum * inv_n;
        let inv_std = 1.0f32 / (var + epsilon).sqrt();

        // 3. Normalize & scale/shift
        for i in 0..norm_size {
            let idx = row_off + i as isize;
            let x = *src.offset(idx);
            let g = if !gamma.is_null() {
                *gamma.offset(i as isize)
            } else {
                1.0f32
            };
            let b_val = if !beta.is_null() {
                *beta.offset(i as isize)
            } else {
                0.0f32
            };

            let x_hat = (x - mean) * inv_std;
            let mut y = x_hat * g + b_val;
            if activation == 1 && y < 0.0f32 {
                y = 0.0f32;
            }
            *dst.offset(idx) = y;
        }
    }
}

/// Multi-arena Layer Normalization kernel (f64).
///
/// # Safety
///
/// `dst` and `src` must point to allocations of length `batch_size * norm_size`.
#[no_mangle]
pub unsafe extern "C" fn ifa_simd_multi_arena_layer_norm_f64(
    dst: *mut f64,
    src: *const f64,
    gamma: *const f64,
    beta: *const f64,
    batch_size: i64,
    norm_size: i64,
    epsilon: f64,
    activation: i32,
) {
    if dst.is_null() || src.is_null() || batch_size <= 0 || norm_size <= 0 {
        return;
    }

    let inv_n = 1.0f64 / (norm_size as f64);

    for b in 0..batch_size {
        let row_off = (b * norm_size) as isize;

        // 1. Mean
        let mut sum = 0.0f64;
        for i in 0..norm_size {
            sum += *src.offset(row_off + i as isize);
        }
        let mean = sum * inv_n;

        // 2. Variance
        let mut sq_diff_sum = 0.0f64;
        for i in 0..norm_size {
            let diff = *src.offset(row_off + i as isize) - mean;
            sq_diff_sum += diff * diff;
        }
        let var = sq_diff_sum * inv_n;
        let inv_std = 1.0f64 / (var + epsilon).sqrt();

        // 3. Normalize & scale/shift
        for i in 0..norm_size {
            let idx = row_off + i as isize;
            let x = *src.offset(idx);
            let g = if !gamma.is_null() {
                *gamma.offset(i as isize)
            } else {
                1.0f64
            };
            let b_val = if !beta.is_null() {
                *beta.offset(i as isize)
            } else {
                0.0f64
            };

            let x_hat = (x - mean) * inv_std;
            let mut y = x_hat * g + b_val;
            if activation == 1 && y < 0.0f64 {
                y = 0.0f64;
            }
            *dst.offset(idx) = y;
        }
    }
}

/// Multi-arena Root Mean Square Normalization (RMSNorm) kernel (f32).
///
/// # Safety
///
/// `dst` and `src` must point to allocations of length `batch_size * norm_size`.
#[no_mangle]
pub unsafe extern "C" fn ifa_simd_multi_arena_rmsnorm_f32(
    dst: *mut f32,
    src: *const f32,
    gamma: *const f32,
    batch_size: i64,
    norm_size: i64,
    epsilon: f32,
    activation: i32,
) {
    if dst.is_null() || src.is_null() || batch_size <= 0 || norm_size <= 0 {
        return;
    }

    let inv_n = 1.0f32 / (norm_size as f32);

    for b in 0..batch_size {
        let row_off = (b * norm_size) as isize;

        // Mean square
        let mut sq_sum = 0.0f32;
        for i in 0..norm_size {
            let x = *src.offset(row_off + i as isize);
            sq_sum += x * x;
        }
        let mean_sq = sq_sum * inv_n;
        let inv_rms = 1.0f32 / (mean_sq + epsilon).sqrt();

        // Scale
        for i in 0..norm_size {
            let idx = row_off + i as isize;
            let x = *src.offset(idx);
            let g = if !gamma.is_null() {
                *gamma.offset(i as isize)
            } else {
                1.0f32
            };

            let mut y = (x * inv_rms) * g;
            if activation == 1 && y < 0.0f32 {
                y = 0.0f32;
            }
            *dst.offset(idx) = y;
        }
    }
}

/// Multi-arena Root Mean Square Normalization (RMSNorm) kernel (f64).
///
/// # Safety
///
/// `dst` and `src` must point to allocations of length `batch_size * norm_size`.
#[no_mangle]
pub unsafe extern "C" fn ifa_simd_multi_arena_rmsnorm_f64(
    dst: *mut f64,
    src: *const f64,
    gamma: *const f64,
    batch_size: i64,
    norm_size: i64,
    epsilon: f64,
    activation: i32,
) {
    if dst.is_null() || src.is_null() || batch_size <= 0 || norm_size <= 0 {
        return;
    }

    let inv_n = 1.0f64 / (norm_size as f64);

    for b in 0..batch_size {
        let row_off = (b * norm_size) as isize;

        // Mean square
        let mut sq_sum = 0.0f64;
        for i in 0..norm_size {
            let x = *src.offset(row_off + i as isize);
            sq_sum += x * x;
        }
        let mean_sq = sq_sum * inv_n;
        let inv_rms = 1.0f64 / (mean_sq + epsilon).sqrt();

        // Scale
        for i in 0..norm_size {
            let idx = row_off + i as isize;
            let x = *src.offset(idx);
            let g = if !gamma.is_null() {
                *gamma.offset(i as isize)
            } else {
                1.0f64
            };

            let mut y = (x * inv_rms) * g;
            if activation == 1 && y < 0.0f64 {
                y = 0.0f64;
            }
            *dst.offset(idx) = y;
        }
    }
}

// ============================================================================
// Colorless Fiber Synchronization Primitives (Mutex, CondVar, Atomics, Channel)
// ============================================================================

/// Opaque wrapper around a cooperative fiber Mutex for C-ABI FFI.
pub struct IfaMutexHandle {
    locked: std::sync::atomic::AtomicBool,
    owner: std::sync::atomic::AtomicU64,
    waiters: std::sync::atomic::AtomicUsize,
    notif: std::sync::Condvar,
    notif_mutex: std::sync::Mutex<()>,
}

/// Create a new cooperative fiber Mutex.
#[no_mangle]
pub extern "C" fn ifa_rt_mutex_create() -> *mut IfaMutexHandle {
    Box::into_raw(Box::new(IfaMutexHandle {
        locked: std::sync::atomic::AtomicBool::new(false),
        owner: std::sync::atomic::AtomicU64::new(0),
        waiters: std::sync::atomic::AtomicUsize::new(0),
        notif: std::sync::Condvar::new(),
        notif_mutex: std::sync::Mutex::new(()),
    }))
}

/// Destroy a cooperative fiber Mutex and release associated memory.
#[no_mangle]
pub extern "C" fn ifa_rt_mutex_destroy(m: *mut IfaMutexHandle) {
    if !m.is_null() {
        unsafe {
            drop(Box::from_raw(m));
        }
    }
}

/// Attempt to acquire a cooperative fiber Mutex non-blockingly.
/// Returns 1 on success, 0 if busy, -1 on null handle.
#[no_mangle]
pub extern "C" fn ifa_rt_mutex_try_lock(m: *mut IfaMutexHandle) -> i32 {
    if m.is_null() {
        return -1;
    }
    let handle = unsafe { &*m };
    if handle
        .locked
        .compare_exchange(
            false,
            true,
            std::sync::atomic::Ordering::Acquire,
            std::sync::atomic::Ordering::Relaxed,
        )
        .is_ok()
    {
        handle.owner.store(
            crate::fiber::current_fiber_id(),
            std::sync::atomic::Ordering::Release,
        );
        1
    } else {
        0
    }
}

/// Acquire a cooperative fiber Mutex, yielding fiber execution cooperatively on contention.
/// Returns 0 on success, -1 on null handle.
#[no_mangle]
pub extern "C" fn ifa_rt_mutex_lock(m: *mut IfaMutexHandle) -> i32 {
    if m.is_null() {
        return -1;
    }
    let handle = unsafe { &*m };
    let cur_id = crate::fiber::current_fiber_id();
    let mut spins: u32 = 0;
    handle
        .waiters
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    while handle
        .locked
        .compare_exchange(
            false,
            true,
            std::sync::atomic::Ordering::Acquire,
            std::sync::atomic::Ordering::Relaxed,
        )
        .is_err()
    {
        spins += 1;
        if spins < 32 {
            std::hint::spin_loop();
        } else if spins < 64 {
            GLOBAL_SCHEDULER.yield_now();
        } else {
            let guard = handle.notif_mutex.lock().unwrap();
            if handle.locked.load(std::sync::atomic::Ordering::Relaxed) {
                let _ = handle
                    .notif
                    .wait_timeout(guard, std::time::Duration::from_micros(250));
            }
        }
    }
    handle
        .owner
        .store(cur_id, std::sync::atomic::Ordering::Release);
    handle
        .waiters
        .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    0
}

/// Release a cooperative fiber Mutex and notify waiting fibers.
/// Returns 0 on success, -1 on null handle.
#[no_mangle]
pub extern "C" fn ifa_rt_mutex_unlock(m: *mut IfaMutexHandle) -> i32 {
    if m.is_null() {
        return -1;
    }
    let handle = unsafe { &*m };
    handle.owner.store(0, std::sync::atomic::Ordering::Release);
    handle
        .locked
        .store(false, std::sync::atomic::Ordering::Release);
    if handle.waiters.load(std::sync::atomic::Ordering::Acquire) > 0 {
        handle.notif.notify_one();
    }
    0
}

/// Check if a cooperative fiber Mutex is currently locked.
/// Returns 1 if locked, 0 if unlocked or null.
#[no_mangle]
pub extern "C" fn ifa_rt_mutex_is_locked(m: *mut IfaMutexHandle) -> i32 {
    if m.is_null() {
        return 0;
    }
    let handle = unsafe { &*m };
    if handle.locked.load(std::sync::atomic::Ordering::Acquire) {
        1
    } else {
        0
    }
}

/// Opaque wrapper around a cooperative fiber CondVar for C-ABI FFI.
pub struct IfaCondVarHandle {
    seq: std::sync::atomic::AtomicU64,
    waiters: std::sync::atomic::AtomicUsize,
    notif: std::sync::Condvar,
    notif_mutex: std::sync::Mutex<()>,
}

/// Create a new cooperative fiber CondVar.
#[no_mangle]
pub extern "C" fn ifa_rt_condvar_create() -> *mut IfaCondVarHandle {
    Box::into_raw(Box::new(IfaCondVarHandle {
        seq: std::sync::atomic::AtomicU64::new(0),
        waiters: std::sync::atomic::AtomicUsize::new(0),
        notif: std::sync::Condvar::new(),
        notif_mutex: std::sync::Mutex::new(()),
    }))
}

/// Destroy a cooperative fiber CondVar and release associated memory.
#[no_mangle]
pub extern "C" fn ifa_rt_condvar_destroy(cv: *mut IfaCondVarHandle) {
    if !cv.is_null() {
        unsafe {
            drop(Box::from_raw(cv));
        }
    }
}

/// Wait on a cooperative CondVar, releasing the Mutex while waiting and re-acquiring it before return.
/// Returns 0 on success, -1 on invalid argument.
#[no_mangle]
pub extern "C" fn ifa_rt_condvar_wait(cv: *mut IfaCondVarHandle, m: *mut IfaMutexHandle) -> i32 {
    if cv.is_null() || m.is_null() {
        return -1;
    }
    let cv_handle = unsafe { &*cv };
    let initial_seq = cv_handle.seq.load(std::sync::atomic::Ordering::Acquire);
    cv_handle
        .waiters
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

    ifa_rt_mutex_unlock(m);

    let mut spins: u32 = 0;
    while cv_handle.seq.load(std::sync::atomic::Ordering::Acquire) == initial_seq {
        spins += 1;
        if spins < 32 {
            std::hint::spin_loop();
        } else if spins < 64 {
            GLOBAL_SCHEDULER.yield_now();
        } else {
            let guard = cv_handle.notif_mutex.lock().unwrap();
            if cv_handle.seq.load(std::sync::atomic::Ordering::Relaxed) == initial_seq {
                let _ = cv_handle
                    .notif
                    .wait_timeout(guard, std::time::Duration::from_micros(250));
            }
        }
    }

    cv_handle
        .waiters
        .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    ifa_rt_mutex_lock(m);
    0
}

/// Timed wait on a cooperative CondVar with timeout in milliseconds.
/// Returns 1 if notified before timeout, 0 if timed out, -1 on error. Mutex is re-acquired in all cases.
#[no_mangle]
pub extern "C" fn ifa_rt_condvar_wait_timeout(
    cv: *mut IfaCondVarHandle,
    m: *mut IfaMutexHandle,
    timeout_ms: i64,
) -> i32 {
    if cv.is_null() || m.is_null() {
        return -1;
    }
    let cv_handle = unsafe { &*cv };
    let initial_seq = cv_handle.seq.load(std::sync::atomic::Ordering::Acquire);
    cv_handle
        .waiters
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

    ifa_rt_mutex_unlock(m);

    let deadline =
        std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms.max(0) as u64);
    let mut timed_out = false;
    let mut spins: u32 = 0;
    while cv_handle.seq.load(std::sync::atomic::Ordering::Acquire) == initial_seq {
        if std::time::Instant::now() >= deadline {
            timed_out = true;
            break;
        }
        spins += 1;
        if spins < 32 {
            std::hint::spin_loop();
        } else if spins < 64 {
            GLOBAL_SCHEDULER.yield_now();
        } else {
            let guard = cv_handle.notif_mutex.lock().unwrap();
            if cv_handle.seq.load(std::sync::atomic::Ordering::Relaxed) == initial_seq {
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                let _ = cv_handle
                    .notif
                    .wait_timeout(guard, remaining.min(std::time::Duration::from_millis(5)));
            }
        }
    }

    cv_handle
        .waiters
        .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    ifa_rt_mutex_lock(m);
    if timed_out {
        0
    } else {
        1
    }
}

/// Notify one waiting fiber on the CondVar.
/// Returns 0 on success, -1 on null handle.
#[no_mangle]
pub extern "C" fn ifa_rt_condvar_notify_one(cv: *mut IfaCondVarHandle) -> i32 {
    if cv.is_null() {
        return -1;
    }
    let cv_handle = unsafe { &*cv };
    cv_handle
        .seq
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    cv_handle.notif.notify_one();
    0
}

/// Notify all waiting fibers on the CondVar.
/// Returns 0 on success, -1 on null handle.
#[no_mangle]
pub extern "C" fn ifa_rt_condvar_notify_all(cv: *mut IfaCondVarHandle) -> i32 {
    if cv.is_null() {
        return -1;
    }
    let cv_handle = unsafe { &*cv };
    cv_handle
        .seq
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    cv_handle.notif.notify_all();
    0
}

/// Opaque wrapper around an atomic 64-bit integer for C-ABI FFI.
pub struct IfaAtomicHandle(pub(crate) std::sync::atomic::AtomicI64);

/// Create a new atomic 64-bit integer initialized to the specified value.
#[no_mangle]
pub extern "C" fn ifa_rt_atomic_create(initial_val: i64) -> *mut IfaAtomicHandle {
    Box::into_raw(Box::new(IfaAtomicHandle(
        std::sync::atomic::AtomicI64::new(initial_val),
    )))
}

/// Destroy an atomic 64-bit integer handle and release allocated memory.
#[no_mangle]
pub extern "C" fn ifa_rt_atomic_destroy(a: *mut IfaAtomicHandle) {
    if !a.is_null() {
        unsafe {
            drop(Box::from_raw(a));
        }
    }
}

/// Atomically load 64-bit integer value with SeqCst ordering.
#[no_mangle]
pub extern "C" fn ifa_rt_atomic_load(a: *mut IfaAtomicHandle) -> i64 {
    if a.is_null() {
        return 0;
    }
    let handle = unsafe { &*a };
    handle.0.load(std::sync::atomic::Ordering::SeqCst)
}

/// Atomically store 64-bit integer value with SeqCst ordering.
#[no_mangle]
pub extern "C" fn ifa_rt_atomic_store(a: *mut IfaAtomicHandle, val: i64) {
    if !a.is_null() {
        let handle = unsafe { &*a };
        handle.0.store(val, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Atomically add delta to 64-bit integer value and return previous value.
#[no_mangle]
pub extern "C" fn ifa_rt_atomic_fetch_add(a: *mut IfaAtomicHandle, delta: i64) -> i64 {
    if a.is_null() {
        return 0;
    }
    let handle = unsafe { &*a };
    handle
        .0
        .fetch_add(delta, std::sync::atomic::Ordering::SeqCst)
}

/// Atomically subtract delta from 64-bit integer value and return previous value.
#[no_mangle]
pub extern "C" fn ifa_rt_atomic_fetch_sub(a: *mut IfaAtomicHandle, delta: i64) -> i64 {
    if a.is_null() {
        return 0;
    }
    let handle = unsafe { &*a };
    handle
        .0
        .fetch_sub(delta, std::sync::atomic::Ordering::SeqCst)
}

/// Atomically compare and exchange 64-bit integer value.
/// Returns previous value (equals expected if exchange succeeded).
#[no_mangle]
pub extern "C" fn ifa_rt_atomic_cas(a: *mut IfaAtomicHandle, expected: i64, desired: i64) -> i64 {
    if a.is_null() {
        return 0;
    }
    let handle = unsafe { &*a };
    match handle.0.compare_exchange(
        expected,
        desired,
        std::sync::atomic::Ordering::SeqCst,
        std::sync::atomic::Ordering::SeqCst,
    ) {
        Ok(v) => v,
        Err(v) => v,
    }
}

/// Send a 64-bit integer value over the channel.
#[no_mangle]
pub extern "C" fn ifa_rt_channel_send_int(chan: *mut IfaChannelHandle, val: i64) -> i32 {
    ifa_rt_channel_send(chan, val as usize as *mut u8)
}

/// Receive a 64-bit integer value from the channel.
#[no_mangle]
pub extern "C" fn ifa_rt_channel_recv_int(chan: *mut IfaChannelHandle, out_val: *mut i64) -> i32 {
    let mut ptr: *mut u8 = std::ptr::null_mut();
    let res = ifa_rt_channel_recv(chan, &mut ptr);
    if res == 0 && !out_val.is_null() {
        unsafe {
            *out_val = ptr as usize as i64;
        }
    }
    res
}

/// Non-blocking send for a 64-bit integer value over the channel.
#[no_mangle]
pub extern "C" fn ifa_rt_channel_try_send_int(chan: *mut IfaChannelHandle, val: i64) -> i32 {
    ifa_rt_channel_try_send(chan, val as usize as *mut u8)
}

/// Non-blocking receive for a 64-bit integer value from the channel.
#[no_mangle]
pub extern "C" fn ifa_rt_channel_try_recv_int(
    chan: *mut IfaChannelHandle,
    out_val: *mut i64,
) -> i32 {
    let mut ptr: *mut u8 = std::ptr::null_mut();
    let res = ifa_rt_channel_try_recv(chan, &mut ptr);
    if res == 0 && !out_val.is_null() {
        unsafe {
            *out_val = ptr as usize as i64;
        }
    }
    res
}

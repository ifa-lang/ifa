//! C-ABI Foreign Function Interface exports for native execution and PHP 8.4+ / Symfony 8.1 FFI.

#![allow(clippy::not_unsafe_ptr_arg_deref)]

use crate::allocator::GLOBAL_ALLOCATOR;
use crate::fiber::GLOBAL_SCHEDULER;
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

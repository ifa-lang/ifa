use ifa_runtime::*;
use std::sync::Mutex;

static TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn test_uaf_interception_via_catch_panic() {
    let _guard = TEST_LOCK.lock().unwrap();
    unsafe {
        let ptr = ifa_rt_gen_alloc(64, 8, 1);
        assert!(!ptr.is_null());

        let header = &*(ptr.sub(std::mem::size_of::<GenHeader>()) as *const GenHeader);
        let remembered_gen = header.generation_counter;

        // Valid access should not trigger any panic
        ifa_rt_gen_check(ptr, remembered_gen);

        // Free the slot: increments generation and resets active flag
        ifa_rt_gen_free(ptr);

        // Accessing the freed pointer inside catch_panic should safely intercept UAF
        extern "C-unwind" fn trigger_uaf(arg: *mut u8) {
            let (target_ptr, remembered_gen) = unsafe { *(arg as *const (*const u8, u32)) };
            ifa_rt_gen_check(target_ptr, remembered_gen);
        }

        let mut args = (ptr as *const u8, remembered_gen);
        let res = ifa_rt_catch_panic(trigger_uaf, &mut args as *mut _ as *mut u8);

        // Must return IfaPanicKind::UseAfterFree (1)
        assert_eq!(res, IfaPanicKind::UseAfterFree as i32);

        // Inspect captured panic record
        let last_panic_ptr = ifa_rt_get_last_panic();
        assert!(!last_panic_ptr.is_null());
        let rec = &*last_panic_ptr;
        assert_eq!(rec.kind, IfaPanicKind::UseAfterFree);
        assert_eq!(rec.fault_address, ptr as usize);
        assert_eq!(rec.expected_gen, remembered_gen);
        assert_ne!(rec.actual_gen, remembered_gen);
        assert_eq!(rec.arena_id, 1);

        ifa_rt_clear_last_panic();
        assert!(ifa_rt_get_last_panic().is_null());
    }
}

#[test]
fn test_double_free_interception_via_catch_panic() {
    let _guard = TEST_LOCK.lock().unwrap();
    unsafe {
        let ptr = ifa_rt_gen_alloc(32, 8, 2);
        assert!(!ptr.is_null());

        // First free succeeds
        ifa_rt_gen_free(ptr);

        // Second free should trigger DoubleFree panic
        extern "C-unwind" fn trigger_double_free(arg: *mut u8) {
            let target_ptr = unsafe { *(arg as *const *mut u8) };
            ifa_rt_gen_free(target_ptr);
        }

        let mut target = ptr;
        let res = ifa_rt_catch_panic(trigger_double_free, &mut target as *mut _ as *mut u8);

        assert_eq!(res, IfaPanicKind::DoubleFree as i32);

        let last_panic_ptr = ifa_rt_get_last_panic();
        assert!(!last_panic_ptr.is_null());
        let rec = &*last_panic_ptr;
        assert_eq!(rec.kind, IfaPanicKind::DoubleFree);
        assert_eq!(rec.fault_address, ptr as usize);
        assert_eq!(rec.arena_id, 2);

        ifa_rt_clear_last_panic();
    }
}

#[test]
fn test_null_ref_interception() {
    let _guard = TEST_LOCK.lock().unwrap();
    extern "C-unwind" fn trigger_null(_arg: *mut u8) {
        ifa_rt_gen_check(std::ptr::null(), 42);
    }

    let res = ifa_rt_catch_panic(trigger_null, std::ptr::null_mut());
    assert_eq!(res, IfaPanicKind::NullDereference as i32);

    let last_panic_ptr = ifa_rt_get_last_panic();
    assert!(!last_panic_ptr.is_null());
    unsafe {
        let rec = &*last_panic_ptr;
        assert_eq!(rec.kind, IfaPanicKind::NullDereference);
    }
    ifa_rt_clear_last_panic();
}

#[test]
fn test_epoch_mismatch_interception() {
    let _guard = TEST_LOCK.lock().unwrap();
    unsafe {
        let ptr = ifa_rt_gen_alloc(48, 8, 3);
        assert!(!ptr.is_null());

        let header = &*(ptr.sub(std::mem::size_of::<GenHeader>()) as *const GenHeader);
        let remembered_gen = header.generation_counter;
        let wrong_epoch = 0x0020; // FLAG_EPOCH_1

        extern "C-unwind" fn trigger_epoch(arg: *mut u8) {
            let (target_ptr, gen, epoch) = unsafe { *(arg as *const (*const u8, u32, u16)) };
            ifa_rt_gen_check_epoch(target_ptr, gen, epoch);
        }

        let mut args = (ptr as *const u8, remembered_gen, wrong_epoch);
        let res = ifa_rt_catch_panic(trigger_epoch, &mut args as *mut _ as *mut u8);

        assert_eq!(res, IfaPanicKind::EpochMismatch as i32);

        let last_panic_ptr = ifa_rt_get_last_panic();
        assert!(!last_panic_ptr.is_null());
        let rec = &*last_panic_ptr;
        assert_eq!(rec.kind, IfaPanicKind::EpochMismatch);
        assert_eq!(rec.expected_epoch, 0x0020);
        assert_eq!(rec.arena_id, 3);

        ifa_rt_gen_free(ptr);
        ifa_rt_clear_last_panic();
    }
}

#[test]
fn test_bounds_check_interception() {
    let _guard = TEST_LOCK.lock().unwrap();
    extern "C-unwind" fn trigger_oob(_arg: *mut u8) {
        ifa_rt_bounds_check(10, 5, std::ptr::null());
    }

    let res = ifa_rt_catch_panic(trigger_oob, std::ptr::null_mut());
    assert_eq!(res, IfaPanicKind::OutOfBounds as i32);

    let last_panic_ptr = ifa_rt_get_last_panic();
    assert!(!last_panic_ptr.is_null());
    unsafe {
        let rec = &*last_panic_ptr;
        assert_eq!(rec.kind, IfaPanicKind::OutOfBounds);
        assert_eq!(rec.fault_address, 10);
        assert_eq!(rec.actual_gen, 5);
    }
    ifa_rt_clear_last_panic();
}

#[test]
fn test_bare_metal_stack_trace_ffi() {
    let mut frames = [0usize; 16];
    let count = ifa_rt_capture_stack_trace(frames.as_mut_ptr(), 16);
    assert!(count <= 16);

    let mut buf = [0u8; 512];
    let written = ifa_rt_format_stack_trace(buf.as_mut_ptr(), buf.len());
    assert!(written > 0);
    let s = std::str::from_utf8(&buf[..written]).unwrap();
    assert!(s.contains("BARE-METAL STACK TRACE"));
}

#[test]
fn test_fiber_panic_isolation_and_status() {
    extern "C-unwind" fn panicked_fiber_entry(_arg: *mut u8) {
        let ptr = ifa_rt_gen_alloc(32, 8, 4);
        ifa_rt_gen_free(ptr);
        // Will trigger UAF panic inside the fiber
        ifa_rt_gen_check(ptr, 9999);
    }

    let fiber_id = ifa_rt_fiber_spawn(panicked_fiber_entry, std::ptr::null_mut());
    assert!(fiber_id > 0);

    // Join the fiber: scheduler catches the panic without crashing the worker
    ifa_rt_fiber_join(fiber_id);

    // Status must be 2 (Panicked)
    let status = ifa_rt_fiber_status(fiber_id);
    assert_eq!(status, 2);
}

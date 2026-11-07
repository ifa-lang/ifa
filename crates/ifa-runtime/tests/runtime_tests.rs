//! Integration and unit tests for IFA runtime: generational memory, fibers, and collections.

use ifa_runtime::*;

#[test]
fn test_gen_header_and_ref_layout() {
    assert_eq!(std::mem::size_of::<GenHeader>(), 8);
    assert_eq!(std::mem::align_of::<GenHeader>(), 8);

    assert_eq!(std::mem::size_of::<GenRef>(), 16);
    assert_eq!(std::mem::align_of::<GenRef>(), 8);
}

#[test]
fn test_generational_allocation_and_1_cycle_check() {
    let payload_size = 32;
    let ptr = ifa_rt_gen_alloc(payload_size, 8, 0);
    assert!(!ptr.is_null());

    unsafe {
        // GenHeader is placed directly before payload
        let header = &*(ptr.sub(std::mem::size_of::<GenHeader>()) as *const GenHeader);
        assert!(header.is_active());
        assert_eq!(header.generation_counter, 1);
        assert_eq!(header.arena_id, 0);

        let gen_ref = GenRef::from_payload(ptr, 0);
        assert_eq!(gen_ref.remembered_gen, 1);
        assert!(gen_ref.is_valid());

        // Perform 1-cycle check
        ifa_rt_gen_check(ptr, 1);

        // Free slot
        ifa_rt_gen_free(ptr);

        // Header must now be marked freed and generation incremented
        let freed_header = &*(ptr.sub(std::mem::size_of::<GenHeader>()) as *const GenHeader);
        assert!(!freed_header.is_active());
        assert_eq!(freed_header.generation_counter, 2);

        // Old reference is now detected as invalid (Use-After-Free prevented)
        assert!(!gen_ref.is_valid());
    }
}

#[test]
fn test_scoped_arena_lifecycle() {
    let arena_id = ifa_rt_arena_create(1024);
    assert!(arena_id > 0);

    let ptr1 = ifa_rt_gen_alloc(16, 8, arena_id);
    let ptr2 = ifa_rt_gen_alloc(64, 8, arena_id);

    unsafe {
        let ref1 = GenRef::from_payload(ptr1, arena_id);
        let ref2 = GenRef::from_payload(ptr2, arena_id);

        assert!(ref1.is_valid());
        assert!(ref2.is_valid());

        // Reset arena in O(1)
        ifa_rt_arena_reset(arena_id);

        // Both references are now immediately invalid
        assert!(!ref1.is_valid());
        assert!(!ref2.is_valid());
    }

    ifa_rt_arena_destroy(arena_id);
}

#[test]
fn test_colorless_fibers_and_channels() {
    let channel = std::sync::Arc::new(Channel::<i64>::new());
    let chan_clone = std::sync::Arc::clone(&channel);

    let fiber_id = GLOBAL_SCHEDULER.spawn(move || {
        let mut sum = 0;
        for i in 1..=100 {
            sum += i;
        }
        chan_clone.send(sum);
    });

    GLOBAL_SCHEDULER.join(fiber_id);
    let received = channel.recv();
    assert_eq!(received, 5050);
}

#[test]
fn test_ifa_string_copy_on_write() {
    let s1 = IfaString::from_str("Hello");
    assert_eq!(s1.ref_count(), 1);
    assert_eq!(s1.as_str(), "Hello");

    // O(1) Clone through CoW
    let mut s2 = s1.clone();
    assert_eq!(s1.ref_count(), 2);
    assert_eq!(s2.ref_count(), 2);
    assert_eq!(s2.as_str(), "Hello");

    // Mutation on s2 triggers CoW separation
    s2.push_str(", World!");
    assert_eq!(s1.ref_count(), 1);
    assert_eq!(s2.ref_count(), 1);
    assert_eq!(s1.as_str(), "Hello");
    assert_eq!(s2.as_str(), "Hello, World!");
}

#[test]
fn test_ifa_list_operations_and_cow() {
    let mut list1 = IfaList::new();
    list1.push(10);
    list1.push(20);
    list1.push(30);

    assert_eq!(list1.len(), 3);
    assert_eq!(list1[0], 10);
    assert_eq!(list1[1], 20);
    assert_eq!(list1[2], 30);

    // Clone creates shared CoW buffer
    let mut list2 = list1.clone();
    assert_eq!(list2.len(), 3);

    // Mutate list2
    list2.push(40);
    assert_eq!(list1.len(), 3);
    assert_eq!(list2.len(), 4);
    assert_eq!(list2[3], 40);

    assert_eq!(list2.pop(), Some(40));
    assert_eq!(list2.len(), 3);
}

#[test]
fn test_ifa_map_deterministic_operations() {
    let mut map = IfaMap::new();
    assert!(map.is_empty());

    map.insert("alpha", 1);
    map.insert("beta", 2);
    map.insert("gamma", 3);

    assert_eq!(map.len(), 3);
    assert_eq!(map.get("alpha"), Some(&1));
    assert_eq!(map.get("beta"), Some(&2));
    assert_eq!(map.get("gamma"), Some(&3));
    assert_eq!(map.get("delta"), None);

    // Overwrite existing key
    let old = map.insert("alpha", 100);
    assert_eq!(old, Some(1));
    assert_eq!(map.get("alpha"), Some(&100));

    // Remove key
    let removed = map.remove("beta");
    assert_eq!(removed, Some(2));
    assert_eq!(map.len(), 2);
    assert_eq!(map.get("beta"), None);
}

#[test]
fn test_generational_benchmark_suite() {
    let report = run_generational_benchmark_suite(100_000);
    assert_eq!(report.iterations, 100_000);
    assert!(report.c_raw_pointer.ns_per_op > 0.0);
    assert!(report.rust_borrow_checker.ns_per_op > 0.0);
    assert!(report.ifa_static_elimination.ns_per_op > 0.0);
    assert!(report.ifa_generational_inlined.ns_per_op > 0.0);
    // In debug mode, verify metrics are positive and finite
    assert!(report.delta_cycles_vs_c >= 0.0);
}

#[test]
fn test_wasi_cooperative_scheduler_and_io() {
    let sched = FiberScheduler::new(1);
    let counter = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));

    let c1 = std::sync::Arc::clone(&counter);
    let fid = sched.spawn(move || {
        c1.fetch_add(10, std::sync::atomic::Ordering::SeqCst);
    });

    sched.join(fid);
    assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 10);

    // Test non-blocking WASI stream writing
    let msg = b"WASI fiber output\n";
    let written = ifa_rt_wasi_write_nonblocking(1, msg.as_ptr(), msg.len());
    assert_eq!(written, msg.len() as isize);
}

#[test]
fn test_multithread_interoperability_and_bounded_channels() {
    let sched = FiberScheduler::new(4);
    assert_eq!(sched.worker_count(), 4);
    assert!(sched.is_running());

    // 1. Test bounded channel with try_send and try_recv
    let chan = std::sync::Arc::new(Channel::with_capacity(2));
    assert_eq!(chan.try_recv(), None);

    assert!(chan.try_send(1).is_ok());
    assert!(chan.try_send(2).is_ok());
    // Capacity 2 full: try_send should fail
    assert_eq!(chan.try_send(3), Err(3));

    assert_eq!(chan.try_recv(), Some(1));
    assert_eq!(
        chan.recv_timeout(std::time::Duration::from_millis(10)),
        Some(2)
    );
    assert_eq!(chan.recv_timeout(std::time::Duration::from_millis(5)), None);

    // 2. High-concurrency producer-consumer dispatching across 4 worker threads
    let completed_count = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let mut fiber_ids = Vec::new();

    // Spawn consumer fiber to drain bounded channel concurrently
    let ch_cons = std::sync::Arc::clone(&chan);
    let consumer_fid = sched.spawn(move || {
        for _ in 0..50 {
            let _ = ch_cons.recv();
        }
    });

    for i in 0..50 {
        let counter = std::sync::Arc::clone(&completed_count);
        let ch = std::sync::Arc::clone(&chan);
        let fid = sched.spawn(move || {
            ch.send(i);
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        });
        fiber_ids.push(fid);
    }

    // Join producer fibers with timeout validation
    for fid in fiber_ids {
        let ok = sched.join_timeout(fid, std::time::Duration::from_secs(2));
        assert!(ok, "Fiber {:?} join timed out", fid);
    }

    let cons_ok = sched.join_timeout(consumer_fid, std::time::Duration::from_secs(2));
    assert!(cons_ok, "Consumer fiber join timed out");

    assert_eq!(
        completed_count.load(std::sync::atomic::Ordering::SeqCst),
        50
    );

    // 3. Graceful scheduler shutdown
    sched.shutdown();
    assert!(!sched.is_running());
}

#[test]
fn test_atomic_ring_buffer_lock_free_mpmc() {
    let ring = AtomicRingBuffer::<u64>::new(4);
    assert_eq!(ring.capacity(), 4);
    assert_eq!(ring.buffer_capacity(), 4);
    assert!(ring.is_empty());
    assert!(!ring.is_full());

    // Push 4 elements
    assert!(ring.try_push(10).is_ok());
    assert!(ring.try_push(20).is_ok());
    assert!(ring.try_push(30).is_ok());
    assert!(ring.try_push(40).is_ok());

    // 5th element should fail (full)
    assert_eq!(ring.try_push(50), Err(50));
    assert!(ring.is_full());
    assert_eq!(ring.len(), 4);

    // Pop 2 elements
    assert_eq!(ring.try_pop(), Some(10));
    assert_eq!(ring.try_pop(), Some(20));
    assert_eq!(ring.len(), 2);
    assert!(!ring.is_full());

    // Push 2 more elements (wrapping around ring)
    assert!(ring.try_push(50).is_ok());
    assert!(ring.try_push(60).is_ok());
    assert!(ring.is_full());

    // Drain all remaining
    assert_eq!(ring.try_pop(), Some(30));
    assert_eq!(ring.try_pop(), Some(40));
    assert_eq!(ring.try_pop(), Some(50));
    assert_eq!(ring.try_pop(), Some(60));
    assert_eq!(ring.try_pop(), None);
    assert!(ring.is_empty());
}

#[test]
fn test_channel_close_and_drain() {
    let chan = Channel::<i32>::with_capacity(3);
    assert!(!chan.is_closed());

    chan.send(100);
    chan.send(200);
    assert_eq!(chan.len(), 2);

    chan.close();
    assert!(chan.is_closed());

    // Sending on closed channel fails
    assert_eq!(chan.send_checked(300), Err(SendError::Closed(300)));
    assert_eq!(chan.try_send_checked(300), Err(TrySendError::Closed(300)));

    // Existing queued items can be drained
    assert_eq!(chan.recv_checked(), Ok(100));
    assert_eq!(chan.try_recv_checked(), Ok(200));

    // After draining, recv returns Closed
    assert_eq!(chan.recv_checked(), Err(RecvError::Closed));
    assert_eq!(chan.try_recv_checked(), Err(TryRecvError::Closed));
}

#[test]
fn test_channel_c_abi_ffi() {
    let chan_handle = ifa_rt_channel_create(2);
    assert!(!chan_handle.is_null());
    assert_eq!(ifa_rt_channel_is_closed(chan_handle), 0);

    let val1 = 42 as *mut u8;
    let val2 = 99 as *mut u8;

    assert_eq!(ifa_rt_channel_send(chan_handle, val1), 0);
    assert_eq!(ifa_rt_channel_try_send(chan_handle, val2), 0);

    // Buffer of size 2 is now full
    let val3 = 100 as *mut u8;
    assert_eq!(ifa_rt_channel_try_send(chan_handle, val3), 1);

    let mut out: *mut u8 = std::ptr::null_mut();
    assert_eq!(ifa_rt_channel_recv(chan_handle, &mut out), 0);
    assert_eq!(out, val1);

    let mut out2: *mut u8 = std::ptr::null_mut();
    assert_eq!(ifa_rt_channel_try_recv(chan_handle, &mut out2), 0);
    assert_eq!(out2, val2);

    // Empty channel try_recv returns 1
    let mut out3: *mut u8 = std::ptr::null_mut();
    assert_eq!(ifa_rt_channel_try_recv(chan_handle, &mut out3), 1);

    // Close channel
    ifa_rt_channel_close(chan_handle);
    assert_eq!(ifa_rt_channel_is_closed(chan_handle), 1);

    // Send fails after close (-2)
    assert_eq!(ifa_rt_channel_send(chan_handle, val1), -2);
    assert_eq!(ifa_rt_channel_try_send(chan_handle, val1), -2);

    // Recv fails after close (-2)
    assert_eq!(ifa_rt_channel_recv(chan_handle, &mut out), -2);
    assert_eq!(ifa_rt_channel_try_recv(chan_handle, &mut out), -2);

    ifa_rt_channel_destroy(chan_handle);
}

#[test]
fn test_c_abi_channel_select() {
    use ifa_runtime::ffi::ifa_rt_channel_select;

    let ch1 = ifa_rt_channel_create(4);
    let ch2 = ifa_rt_channel_create(4);

    let arr = [ch1, ch2];

    // Non-blocking select with default when empty returns 2 (num_channels)
    let res = ifa_rt_channel_select(arr.as_ptr(), 2, 1);
    assert_eq!(res, 2);

    // Send into ch2
    let val = 0xbeef as *mut u8;
    assert_eq!(ifa_rt_channel_send(ch2, val), 0);

    // Now select should immediately select channel 1 (ch2)
    let res = ifa_rt_channel_select(arr.as_ptr(), 2, 0);
    assert_eq!(res, 1);

    let mut out: *mut u8 = std::ptr::null_mut();
    assert_eq!(ifa_rt_channel_recv(ch2, &mut out), 0);
    assert_eq!(out, val);

    ifa_rt_channel_destroy(ch1);
    ifa_rt_channel_destroy(ch2);
}

#[test]
fn test_stackless_fiber_resumable_scheduler() {
    let sched = FiberScheduler::new(2);
    let counter = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));

    let c = std::sync::Arc::clone(&counter);
    let mut step = 0;
    let fid = sched.spawn_resumable(move || {
        step += 1;
        c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if step < 5 {
            CoroStatus::Suspended
        } else {
            CoroStatus::Completed
        }
    });

    sched.join(fid);
    assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 5);
    assert!(sched.is_completed(fid));
}

#[repr(C)]
struct MockCoroFrame {
    stage: i32,
    accumulator: i64,
}

extern "C" fn mock_coro_resume(frame_ptr: *mut u8) -> i32 {
    let frame = unsafe { &mut *(frame_ptr as *mut MockCoroFrame) };
    match frame.stage {
        0 => {
            frame.accumulator += 10;
            frame.stage = 1;
            0 // CoroStatus::Suspended
        }
        1 => {
            frame.accumulator += 20;
            frame.stage = 2;
            0 // CoroStatus::Suspended
        }
        2 => {
            frame.accumulator += 30;
            frame.stage = 3;
            1 // CoroStatus::Completed
        }
        _ => 1,
    }
}

static DESTROY_CALLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

extern "C" fn mock_coro_destroy(_frame_ptr: *mut u8) {
    DESTROY_CALLED.store(true, std::sync::atomic::Ordering::SeqCst);
}

#[test]
fn test_stackless_native_coroutine_c_abi() {
    DESTROY_CALLED.store(false, std::sync::atomic::Ordering::SeqCst);
    let coro = ifa_rt_coro_create(
        std::mem::size_of::<MockCoroFrame>(),
        mock_coro_resume,
        Some(mock_coro_destroy),
    );
    assert!(!coro.is_null());
    assert_eq!(ifa_rt_coro_is_done(coro), 0);
    assert_eq!(ifa_rt_coro_status(coro), 0);

    // Step 0 -> stage 1, acc = 10, Suspended
    let s1 = ifa_rt_coro_resume(coro);
    assert_eq!(s1, 0);
    assert_eq!(ifa_rt_coro_is_done(coro), 0);
    let frame1 = unsafe { &*(ifa_rt_coro_frame(coro) as *const MockCoroFrame) };
    assert_eq!(frame1.stage, 1);
    assert_eq!(frame1.accumulator, 10);

    // Step 1 -> stage 2, acc = 30, Suspended
    let s2 = ifa_rt_coro_resume(coro);
    assert_eq!(s2, 0);
    assert_eq!(ifa_rt_coro_is_done(coro), 0);
    let frame2 = unsafe { &*(ifa_rt_coro_frame(coro) as *const MockCoroFrame) };
    assert_eq!(frame2.stage, 2);
    assert_eq!(frame2.accumulator, 30);

    // Step 2 -> stage 3, acc = 60, Completed
    let s3 = ifa_rt_coro_resume(coro);
    assert_eq!(s3, 1);
    assert_eq!(ifa_rt_coro_is_done(coro), 1);
    let frame3 = unsafe { &*(ifa_rt_coro_frame(coro) as *const MockCoroFrame) };
    assert_eq!(frame3.stage, 3);
    assert_eq!(frame3.accumulator, 60);

    ifa_rt_coro_destroy(coro);
    assert!(DESTROY_CALLED.load(std::sync::atomic::Ordering::SeqCst));
}

#[test]
fn test_stackless_native_coroutine_spawn_scheduler() {
    let coro = ifa_rt_coro_create(std::mem::size_of::<MockCoroFrame>(), mock_coro_resume, None);
    assert!(!coro.is_null());

    let fid = ifa_rt_coro_spawn(coro);
    assert!(fid > 0);

    // Join should wait until the stackless coroutine transitions across all stages to Completed
    ifa_rt_fiber_join(fid);

    assert_eq!(ifa_rt_coro_is_done(coro), 1);
    let frame = unsafe { &*(ifa_rt_coro_frame(coro) as *const MockCoroFrame) };
    assert_eq!(frame.accumulator, 60);
    assert_eq!(frame.stage, 3);

    ifa_rt_coro_destroy(coro);
}

#[test]
fn test_stackless_custom_frame_coroutine_creation_and_lifecycle() {
    use ifa_runtime::ffi::{
        ifa_rt_coro_create_custom, ifa_rt_coro_destroy, ifa_rt_coro_frame, ifa_rt_coro_is_done,
        ifa_rt_coro_resume,
    };

    static DESTROY_CALLED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);

    extern "C" fn custom_destroy(ptr: *mut u8) {
        DESTROY_CALLED.store(true, std::sync::atomic::Ordering::SeqCst);
        unsafe {
            let _ = Box::from_raw(ptr as *mut MockCoroFrame);
        }
    }

    let raw_frame = Box::into_raw(Box::new(MockCoroFrame {
        accumulator: 0,
        stage: 0,
    })) as *mut u8;

    let coro = ifa_rt_coro_create_custom(raw_frame, mock_coro_resume, Some(custom_destroy));
    assert_eq!(ifa_rt_coro_is_done(coro), 0);

    let res1 = ifa_rt_coro_resume(coro);
    assert_eq!(res1, 0); // Suspended
    let res2 = ifa_rt_coro_resume(coro);
    assert_eq!(res2, 0); // Suspended
    let res3 = ifa_rt_coro_resume(coro);
    assert_eq!(res3, 1); // Completed
    assert_eq!(ifa_rt_coro_is_done(coro), 1);

    let frame = unsafe { &*(ifa_rt_coro_frame(coro) as *const MockCoroFrame) };
    assert_eq!(frame.accumulator, 60);
    assert_eq!(frame.stage, 3);

    ifa_rt_coro_destroy(coro);
    assert!(DESTROY_CALLED.load(std::sync::atomic::Ordering::SeqCst));
}

#[test]
fn test_zero_copy_slice_ffi() {
    use ifa_runtime::ffi::{
        ifa_rt_slice_alloc, ifa_rt_slice_free, ifa_rt_slice_from_raw, ifa_rt_version_string,
    };

    let sample_data = b"Zero-Copy High Performance FFI Bridge";
    let slice = ifa_rt_slice_from_raw(sample_data.as_ptr(), sample_data.len());
    assert_eq!(slice.len, sample_data.len());
    assert_eq!(slice.as_bytes(), sample_data);

    // Allocate mutable buffer in default arena (0)
    let mut mut_slice = ifa_rt_slice_alloc(64, 0);
    assert_eq!(mut_slice.len, 0);
    assert!(mut_slice.cap >= 64);
    assert!(!mut_slice.ptr.is_null());

    let payload = b"Hello from Native C-ABI FFI";
    mut_slice.as_capacity_bytes_mut()[..payload.len()].copy_from_slice(payload);
    mut_slice.len = payload.len();
    assert_eq!(&mut_slice.as_bytes()[..payload.len()], payload);

    ifa_rt_slice_free(mut_slice);

    // Verify version string
    let ver_ptr = ifa_rt_version_string();
    assert!(!ver_ptr.is_null());
    let ver_cstr = unsafe { std::ffi::CStr::from_ptr(ver_ptr) };
    assert!(ver_cstr.to_str().unwrap().contains("IFA Runtime 0.1.0"));
}

#[test]
fn test_arena_alloc_and_reset_ffi() {
    use ifa_runtime::ffi::{
        ifa_rt_arena_alloc, ifa_rt_arena_create, ifa_rt_arena_destroy, ifa_rt_arena_reset,
        ifa_rt_gen_check,
    };

    let arena = ifa_rt_arena_create(65536);
    assert!(arena > 0);

    let ptr1 = ifa_rt_arena_alloc(arena, 128, 8);
    assert!(!ptr1.is_null());

    let ptr2 = ifa_rt_arena_alloc(arena, 256, 8);
    assert!(!ptr2.is_null());
    assert_ne!(ptr1, ptr2);

    // Check generational validity
    ifa_rt_gen_check(ptr1, 1);
    ifa_rt_gen_check(ptr2, 1);

    // Reset arena
    ifa_rt_arena_reset(arena);

    // Destroy arena
    ifa_rt_arena_destroy(arena);
}

#[test]
fn test_dynamic_list_ffi_operations() {
    use ifa_runtime::ffi::{
        ifa_rt_list_free, ifa_rt_list_get, ifa_rt_list_len, ifa_rt_list_new, ifa_rt_list_pop,
        ifa_rt_list_push,
    };

    let elem_size = std::mem::size_of::<i64>();
    let mut list = ifa_rt_list_new(elem_size, 2);
    assert!(!list.is_null());
    assert_eq!(ifa_rt_list_len(list), 0);

    // Push 10 elements (forces buffer growth)
    for i in 0..10i64 {
        let val = (i + 1) * 11;
        ifa_rt_list_push(&mut list, &val as *const i64 as *const u8, elem_size);
    }

    assert_eq!(ifa_rt_list_len(list), 10);

    // Check elements
    for i in 0..10i64 {
        let ptr = ifa_rt_list_get(list, i as usize, elem_size);
        assert!(!ptr.is_null());
        let val = unsafe { *(ptr as *const i64) };
        assert_eq!(val, (i + 1) * 11);
    }

    // Pop element
    let mut popped_val: i64 = 0;
    let ok = ifa_rt_list_pop(list, &mut popped_val as *mut i64 as *mut u8, elem_size);
    assert_eq!(ok, 1);
    assert_eq!(popped_val, 110);
    assert_eq!(ifa_rt_list_len(list), 9);

    ifa_rt_list_free(list, elem_size);
}

#[test]
fn test_generational_counter_overflow_and_quarantine() {
    let mut header = GenHeader::new_active(u32::MAX, 0);
    assert!(header.is_active());
    assert_eq!(header.generation_counter, u32::MAX);

    // Free with generation at MAX: toggles epoch 1 and resets generation safely to 1
    header.mark_freed();
    assert!(!header.is_active());
    assert_eq!(header.generation_counter, 1);
    assert!((header.allocation_flags & FLAG_EPOCH_1) != 0);
    assert!(!header.is_quarantined());

    // Second time at MAX with epoch 1 already set: slot is quarantined permanently
    header.allocation_flags |= FLAG_ACTIVE;
    header.generation_counter = u32::MAX;
    header.mark_freed();
    assert!(!header.is_active());
    assert!(header.is_quarantined());
}

extern "C" fn mock_heavy_c_syscall(arg: *mut std::ffi::c_void) -> *mut std::ffi::c_void {
    let input = arg as usize;
    std::thread::sleep(std::time::Duration::from_millis(30));
    (input * 3) as *mut std::ffi::c_void
}

extern "C" fn mock_completion_callback(res: *mut std::ffi::c_void, cb_arg: *mut std::ffi::c_void) {
    let res_val = res as usize;
    let slot = unsafe { &*(cb_arg as *const std::sync::atomic::AtomicUsize) };
    slot.store(res_val, std::sync::atomic::Ordering::Release);
}

#[test]
fn test_isolated_blocking_pool_prevents_scheduler_starvation() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    let light_counter = Arc::new(AtomicUsize::new(0));
    let stop_light = Arc::new(AtomicBool::new(false));

    // Spawn 4 cooperative resumable fibers on the M:N scheduler incrementing rapidly
    let mut light_fids = Vec::new();
    for _ in 0..4 {
        let counter = Arc::clone(&light_counter);
        let stop = Arc::clone(&stop_light);
        let fid = GLOBAL_SCHEDULER.spawn_resumable(move || {
            if stop.load(Ordering::Relaxed) {
                CoroStatus::Completed
            } else {
                counter.fetch_add(1, Ordering::Relaxed);
                CoroStatus::Suspended
            }
        });
        light_fids.push(fid);
    }

    // Simultaneously, execute blocking C-ABI calls via ifa_rt_blocking_call
    // across multiple fibers. The M:N scheduler must not starve.
    let blocking_done = Arc::new(AtomicBool::new(false));
    let b_done = Arc::clone(&blocking_done);

    let fid_blocking = GLOBAL_SCHEDULER.spawn(move || {
        let res = ifa_rt_blocking_call(mock_heavy_c_syscall, 14 as *mut std::ffi::c_void);
        assert_eq!(res as usize, 42);
        b_done.store(true, Ordering::Release);
    });

    // Wait for the blocking call to finish
    GLOBAL_SCHEDULER.join(fid_blocking);
    assert!(blocking_done.load(Ordering::Acquire));

    // Cooperative light fibers must have made significant progress despite heavy blocking call
    let progress = light_counter.load(Ordering::Relaxed);
    assert!(
        progress > 10,
        "Cooperative M:N fibers must continue making progress during isolated blocking call: {}",
        progress
    );

    // Stop light fibers and wait
    stop_light.store(true, Ordering::Release);
    for fid in light_fids {
        GLOBAL_SCHEDULER.join(fid);
    }
}

#[test]
fn test_blocking_pool_c_abi_spawn_and_completion_cb() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    assert!(ifa_rt_blocking_pool_capacity() >= 4);

    let completion_slot = AtomicUsize::new(0);
    let slot_ptr = &completion_slot as *const AtomicUsize as *mut std::ffi::c_void;

    let task_id = ifa_rt_blocking_spawn(
        mock_heavy_c_syscall,
        20 as *mut std::ffi::c_void,
        Some(mock_completion_callback),
        slot_ptr,
    );
    assert!(task_id > 0);

    // Wait for completion callback to update slot
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
    while completion_slot.load(Ordering::Acquire) == 0 && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }

    assert_eq!(completion_slot.load(Ordering::Acquire), 60);
}

#[test]
fn test_fiber_arena_isolation_and_ownership() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let verified = Arc::new(AtomicBool::new(false));
    let v_clone = Arc::clone(&verified);

    let (fid, arena_id) = GLOBAL_SCHEDULER.spawn_with_arena(move || {
        let cur_fid = ifa_rt_fiber_current_id();
        let cur_arena = ifa_rt_fiber_current_arena();
        assert!(cur_fid > 0);
        assert!(cur_arena > 0);

        let is_owner = ifa_rt_arena_verify_owner(cur_arena, cur_fid);
        assert!(is_owner);

        let wrong_owner = ifa_rt_arena_verify_owner(cur_arena, cur_fid + 999);
        assert!(!wrong_owner);

        v_clone.store(true, Ordering::SeqCst);
    });

    GLOBAL_SCHEDULER.join(fid);
    assert!(verified.load(Ordering::SeqCst));
    assert!(arena_id > 0);
}

#[test]
fn test_gen_ref_epoch_consistency_and_stale_detection() {
    let header = GenHeader::new_active(u32::MAX, 1);

    // Simulate header directly preceding payload
    unsafe {
        let fake_mem = std::alloc::alloc(std::alloc::Layout::from_size_align(16, 8).unwrap());
        let h_ptr = fake_mem as *mut GenHeader;
        *h_ptr = header;
        let p_ptr = fake_mem.add(8);

        // Create reference in Epoch 0
        let ref_epoch_0 = GenRef::from_payload(p_ptr, 1);
        assert_eq!(ref_epoch_0.epoch_id(), 0);
        assert!(!ref_epoch_0.is_stale_epoch());
        assert!(ref_epoch_0.is_valid());

        // Free slot at generation u32::MAX -> transitions to Epoch 1, reset gen to 1
        let tr = (*h_ptr).mark_freed();
        assert_eq!(tr, EpochTransition::SwitchedToEpoch1);
        assert_eq!((*h_ptr).epoch_id(), 1);
        assert_eq!((*h_ptr).generation_counter, 1);

        // Reallocate slot in Epoch 1 with generation 1
        (*h_ptr).allocation_flags |= FLAG_ACTIVE;

        // Old reference recorded epoch 0; current slot is in Epoch 1!
        // Even though generation is 1 (hypothetically matching an old gen 1 ref), epoch mismatch blocks it!
        assert!(ref_epoch_0.is_stale_epoch());
        assert!(!ref_epoch_0.is_valid());

        // A new reference formed in Epoch 1 is completely valid
        let ref_epoch_1 = GenRef::from_payload(p_ptr, 1);
        assert_eq!(ref_epoch_1.epoch_id(), 1);
        assert!(!ref_epoch_1.is_stale_epoch());
        assert!(ref_epoch_1.is_valid());

        // Secondary overflow -> permanently quarantined
        (*h_ptr).generation_counter = u32::MAX;
        let tr2 = (*h_ptr).mark_freed();
        assert_eq!(tr2, EpochTransition::Quarantined);
        assert!((*h_ptr).is_quarantined());
        assert!(!ref_epoch_1.is_valid());

        std::alloc::dealloc(
            fake_mem,
            std::alloc::Layout::from_size_align(16, 8).unwrap(),
        );
    }
}

#[test]
fn test_concurrent_epoch_manager_pins_and_quarantine() {
    let stats_before = GLOBAL_ALLOCATOR.epoch_stats();
    assert!(stats_before.global_epoch >= 1);

    // Test RAII pin
    {
        let guard1 = GLOBAL_ALLOCATOR.pin_epoch();
        assert_eq!(
            guard1.pinned_epoch,
            GLOBAL_ALLOCATOR.epoch_manager.current_epoch()
        );
        assert!(GLOBAL_ALLOCATOR.epoch_stats().active_pins >= 1);

        {
            let _guard2 = GLOBAL_ALLOCATOR.pin_epoch();
            assert!(GLOBAL_ALLOCATOR.epoch_stats().active_pins >= 2);
        }

        assert!(GLOBAL_ALLOCATOR.epoch_stats().active_pins >= 1);
    }
    assert_eq!(GLOBAL_ALLOCATOR.epoch_stats().active_pins, 0);

    // Test epoch advance
    let next_epoch = GLOBAL_ALLOCATOR.advance_epoch();
    assert_eq!(next_epoch, GLOBAL_ALLOCATOR.epoch_manager.current_epoch());
    assert_eq!(ifa_rt_epoch_current(), next_epoch);

    // Test C-ABI exports
    let c_epoch = ifa_rt_epoch_advance();
    assert_eq!(c_epoch, next_epoch + 1);
}

#[test]
fn test_slab_allocator_epoch_preservation_and_quarantine() {
    // Allocate 32-byte slot
    let ptr = GLOBAL_ALLOCATOR.alloc(32, 8, 0);
    assert!(!ptr.is_null());

    unsafe {
        let header = (ptr as *mut GenHeader).sub(1);
        assert!((*header).is_active());
        assert_eq!((*header).epoch_id(), 0);

        // Force overflow to Epoch 1
        (*header).generation_counter = u32::MAX;
    }

    // Free the slot -> should trigger epoch switch to Epoch 1 and update EpochManager
    let transitions_before = GLOBAL_ALLOCATOR.epoch_stats().epoch_transitions;
    GLOBAL_ALLOCATOR.free(ptr);
    let transitions_after = GLOBAL_ALLOCATOR.epoch_stats().epoch_transitions;
    assert_eq!(transitions_after, transitions_before + 1);

    // Reallocate from slab cache -> verify preserved epoch bit
    let ptr2 = GLOBAL_ALLOCATOR.alloc(32, 8, 0);
    unsafe {
        let header2 = (ptr2 as *mut GenHeader).sub(1);
        assert!((*header2).is_active());
        // Epoch 1 must be preserved upon reallocation!
        assert_eq!((*header2).epoch_id(), 1);
        assert_eq!((*header2).allocation_flags & FLAG_EPOCH_1, FLAG_EPOCH_1);

        // Force secondary overflow on this slot to test quarantine
        (*header2).generation_counter = u32::MAX;
    }

    let quarantined_before = GLOBAL_ALLOCATOR.epoch_stats().quarantined_slots;
    GLOBAL_ALLOCATOR.free(ptr2);
    let quarantined_after = GLOBAL_ALLOCATOR.epoch_stats().quarantined_slots;
    assert_eq!(quarantined_after, quarantined_before + 1);
    assert_eq!(ifa_rt_epoch_quarantined_count(), quarantined_after);
}

#[test]
fn test_simd_vector_cacheline_alignments() {
    // 1. 16-byte alignment (ARM Neon / SSE)
    let ptr_neon = ifa_rt_gen_alloc(128, 16, 0);
    assert_eq!(
        ptr_neon as usize % 16,
        0,
        "NEON buffer must be 16-byte aligned"
    );
    unsafe {
        let header = (ptr_neon as *const GenHeader).sub(1);
        assert!((*header).is_active());
        assert_eq!((*header).generation_counter, 1);
    }
    ifa_rt_gen_free(ptr_neon);

    // 2. 32-byte alignment (AVX2 / 256-bit vector lanes)
    let ptr_avx2 = ifa_rt_gen_alloc(256, 32, 0);
    assert_eq!(
        ptr_avx2 as usize % 32,
        0,
        "AVX2 buffer must be 32-byte aligned"
    );
    unsafe {
        let header = (ptr_avx2 as *const GenHeader).sub(1);
        assert!((*header).is_active());
        assert_eq!((*header).generation_counter, 1);
    }
    ifa_rt_gen_free(ptr_avx2);

    // 3. 64-byte alignment (AVX-512 / 512-bit vector lanes / L1 Cache Line)
    let ptr_avx512 = ifa_rt_gen_alloc(512, 64, 0);
    assert_eq!(
        ptr_avx512 as usize % 64,
        0,
        "AVX-512 buffer must be 64-byte cacheline aligned"
    );
    unsafe {
        let header = (ptr_avx512 as *const GenHeader).sub(1);
        assert!((*header).is_active());
        assert_eq!((*header).generation_counter, 1);
    }
    ifa_rt_gen_free(ptr_avx512);
}

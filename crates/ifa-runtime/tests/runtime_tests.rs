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
fn test_channel_select_wait_table_zero_allocation() {
    use ifa_runtime::ffi::{
        ifa_rt_channel_close, ifa_rt_channel_create, ifa_rt_channel_destroy, ifa_rt_channel_recv,
        ifa_rt_channel_select_table, ifa_rt_channel_select_wait_table, ifa_rt_channel_send,
        IfaSelectWaitEntry, IfaSelectWaitTable, IFA_SELECT_OP_RECV, IFA_SELECT_OP_SEND,
        IFA_SELECT_STATUS_CLOSED, IFA_SELECT_STATUS_PENDING, IFA_SELECT_STATUS_READY,
    };

    let ch1 = ifa_rt_channel_create(2);
    let ch2 = ifa_rt_channel_create(2);
    let ch3 = ifa_rt_channel_create(2);

    let mut entries = [
        IfaSelectWaitEntry {
            chan: ch1,
            op: IFA_SELECT_OP_RECV,
            status: IFA_SELECT_STATUS_PENDING,
            val: std::ptr::null_mut(),
            priority: 0,
            _pad: 0,
            timeout_ns: 0,
        },
        IfaSelectWaitEntry {
            chan: ch2,
            op: IFA_SELECT_OP_RECV,
            status: IFA_SELECT_STATUS_PENDING,
            val: std::ptr::null_mut(),
            priority: 0,
            _pad: 0,
            timeout_ns: 0,
        },
    ];

    // 1. Polling without default when both channels are empty must return -1 (coroutine suspend)
    let mut table_no_def = IfaSelectWaitTable {
        entries: entries.as_mut_ptr(),
        count: 2,
        has_default: 0,
        _pad: 0,
        start_ns: -1,
    };
    assert_eq!(ifa_rt_channel_select_table(&mut table_no_def), -1);

    // 2. Polling with default when empty must return count (2)
    let mut table_with_def = IfaSelectWaitTable {
        entries: entries.as_mut_ptr(),
        count: 2,
        has_default: 1,
        _pad: 0,
        start_ns: -1,
    };
    assert_eq!(ifa_rt_channel_select_table(&mut table_with_def), 2);

    // 3. Send message into ch2
    let val2 = 0x4242 as *mut u8;
    assert_eq!(ifa_rt_channel_send(ch2, val2), 0);

    // Now table polling without default must immediately select index 1 (ch2)
    let sel_idx = ifa_rt_channel_select_table(&mut table_no_def);
    assert_eq!(sel_idx, 1);
    assert_eq!(entries[1].status, IFA_SELECT_STATUS_READY);

    // Receive the message
    let mut out: *mut u8 = std::ptr::null_mut();
    assert_eq!(ifa_rt_channel_recv(ch2, &mut out), 0);
    assert_eq!(out, val2);

    // 4. Test SEND wait operation in table
    let mut send_entries = [IfaSelectWaitEntry {
        chan: ch3,
        op: IFA_SELECT_OP_SEND,
        status: IFA_SELECT_STATUS_PENDING,
        val: 0x9999 as *mut u8,
        priority: 0,
        _pad: 0,
        timeout_ns: 0,
    }];
    let mut send_table = IfaSelectWaitTable {
        entries: send_entries.as_mut_ptr(),
        count: 1,
        has_default: 0,
        _pad: 0,
        start_ns: -1,
    };
    // ch3 is empty so SEND capacity is ready
    assert_eq!(ifa_rt_channel_select_table(&mut send_table), 0);
    assert_eq!(send_entries[0].status, IFA_SELECT_STATUS_READY);

    // 5. Test cooperative wait table execution on background thread
    let ch1_addr = ch1 as usize;
    let handle = std::thread::spawn(move || {
        let mut bg_entries = [IfaSelectWaitEntry {
            chan: ch1_addr as *mut _,
            op: IFA_SELECT_OP_RECV,
            status: IFA_SELECT_STATUS_PENDING,
            val: std::ptr::null_mut(),
            priority: 0,
            _pad: 0,
            timeout_ns: 0,
        }];
        let mut bg_table = IfaSelectWaitTable {
            entries: bg_entries.as_mut_ptr(),
            count: 1,
            has_default: 0,
            _pad: 0,
            start_ns: -1,
        };
        ifa_rt_channel_select_wait_table(&mut bg_table)
    });

    std::thread::sleep(std::time::Duration::from_millis(10));
    let val1 = 0x1111 as *mut u8;
    assert_eq!(ifa_rt_channel_send(ch1, val1), 0);

    let waited_idx = handle.join().expect("join failed");
    assert_eq!(waited_idx, 0);

    let mut out1: *mut u8 = std::ptr::null_mut();
    assert_eq!(ifa_rt_channel_recv(ch1, &mut out1), 0);
    assert_eq!(out1, val1);

    // 6. Test all closed channels returns -2
    ifa_rt_channel_close(ch1);
    ifa_rt_channel_close(ch2);
    let mut closed_entries = [
        IfaSelectWaitEntry {
            chan: ch1,
            op: IFA_SELECT_OP_RECV,
            status: IFA_SELECT_STATUS_PENDING,
            val: std::ptr::null_mut(),
            priority: 0,
            _pad: 0,
            timeout_ns: 0,
        },
        IfaSelectWaitEntry {
            chan: ch2,
            op: IFA_SELECT_OP_RECV,
            status: IFA_SELECT_STATUS_PENDING,
            val: std::ptr::null_mut(),
            priority: 0,
            _pad: 0,
            timeout_ns: 0,
        },
    ];
    let mut closed_table = IfaSelectWaitTable {
        entries: closed_entries.as_mut_ptr(),
        count: 2,
        has_default: 0,
        _pad: 0,
        start_ns: -1,
    };
    assert_eq!(ifa_rt_channel_select_table(&mut closed_table), -2);
    assert_eq!(closed_entries[0].status, IFA_SELECT_STATUS_CLOSED);
    assert_eq!(closed_entries[1].status, IFA_SELECT_STATUS_CLOSED);

    ifa_rt_channel_destroy(ch1);
    ifa_rt_channel_destroy(ch2);
    ifa_rt_channel_destroy(ch3);
}

#[test]
fn test_channel_select_priority_arbitration() {
    use ifa_runtime::ffi::{
        ifa_rt_channel_create, ifa_rt_channel_destroy, ifa_rt_channel_recv,
        ifa_rt_channel_select_prioritized, ifa_rt_channel_select_table, ifa_rt_channel_send,
        IfaSelectWaitEntry, IfaSelectWaitTable, IFA_SELECT_OP_RECV, IFA_SELECT_STATUS_PENDING,
        IFA_SELECT_STATUS_READY,
    };

    let ch_low = ifa_rt_channel_create(4);
    let ch_mid = ifa_rt_channel_create(4);
    let ch_high = ifa_rt_channel_create(4);

    // Populate messages in both ch_low and ch_high
    let val_low = 0x1010 as *mut u8;
    let val_high = 0x9090 as *mut u8;
    assert_eq!(ifa_rt_channel_send(ch_low, val_low), 0);
    assert_eq!(ifa_rt_channel_send(ch_high, val_high), 0);

    // Create table with priorities: low=10, mid=50, high=100
    let mut entries = [
        IfaSelectWaitEntry {
            chan: ch_low,
            op: IFA_SELECT_OP_RECV,
            status: IFA_SELECT_STATUS_PENDING,
            val: std::ptr::null_mut(),
            priority: 10,
            _pad: 0,
            timeout_ns: 0,
        },
        IfaSelectWaitEntry {
            chan: ch_mid,
            op: IFA_SELECT_OP_RECV,
            status: IFA_SELECT_STATUS_PENDING,
            val: std::ptr::null_mut(),
            priority: 50,
            _pad: 0,
            timeout_ns: 0,
        },
        IfaSelectWaitEntry {
            chan: ch_high,
            op: IFA_SELECT_OP_RECV,
            status: IFA_SELECT_STATUS_PENDING,
            val: std::ptr::null_mut(),
            priority: 100,
            _pad: 0,
            timeout_ns: 0,
        },
    ];

    let mut table = IfaSelectWaitTable {
        entries: entries.as_mut_ptr(),
        count: 3,
        has_default: 0,
        _pad: 0,
        start_ns: -1,
    };

    // Even though ch_low is at index 0, ch_high (index 2, prio 100) must win deterministically!
    let sel_idx = ifa_rt_channel_select_table(&mut table);
    assert_eq!(sel_idx, 2);
    assert_eq!(entries[2].status, IFA_SELECT_STATUS_READY);

    // Consume from ch_high
    let mut out: *mut u8 = std::ptr::null_mut();
    assert_eq!(ifa_rt_channel_recv(ch_high, &mut out), 0);
    assert_eq!(out, val_high);

    // Test C-ABI helper ifa_rt_channel_select_prioritized
    let channels = [ch_low, ch_mid];
    let prios = [10, 50];
    let c_sel = ifa_rt_channel_select_prioritized(channels.as_ptr(), prios.as_ptr(), 2, 0);
    assert_eq!(c_sel, 0); // ch_low has data

    let mut out_low: *mut u8 = std::ptr::null_mut();
    assert_eq!(ifa_rt_channel_recv(ch_low, &mut out_low), 0);
    assert_eq!(out_low, val_low);

    ifa_rt_channel_destroy(ch_low);
    ifa_rt_channel_destroy(ch_mid);
    ifa_rt_channel_destroy(ch_high);
}

#[test]
fn test_channel_select_timeout_deadline_zero_allocation() {
    use ifa_runtime::ffi::{
        ifa_rt_channel_create, ifa_rt_channel_destroy, ifa_rt_channel_select_table,
        ifa_rt_channel_select_timed, ifa_rt_channel_select_wait_table, IfaSelectWaitEntry,
        IfaSelectWaitTable, IFA_SELECT_OP_RECV, IFA_SELECT_OP_TIMEOUT, IFA_SELECT_STATUS_PENDING,
        IFA_SELECT_STATUS_READY,
    };

    let ch = ifa_rt_channel_create(2);

    // Table with 1 empty channel and a 15ms timeout clause
    let mut entries = [
        IfaSelectWaitEntry {
            chan: ch,
            op: IFA_SELECT_OP_RECV,
            status: IFA_SELECT_STATUS_PENDING,
            val: std::ptr::null_mut(),
            priority: 0,
            _pad: 0,
            timeout_ns: 0,
        },
        IfaSelectWaitEntry {
            chan: std::ptr::null_mut(),
            op: IFA_SELECT_OP_TIMEOUT,
            status: IFA_SELECT_STATUS_PENDING,
            val: std::ptr::null_mut(),
            priority: i32::MIN,
            _pad: 0,
            timeout_ns: 15_000_000, // 15ms
        },
    ];

    let mut table = IfaSelectWaitTable {
        entries: entries.as_mut_ptr(),
        count: 2,
        has_default: 0,
        _pad: 0,
        start_ns: -1,
    };

    // First non-blocking poll: channel empty and timeout not expired -> returns -1
    let poll_res = ifa_rt_channel_select_table(&mut table);
    assert_eq!(poll_res, -1);
    assert_eq!(entries[1].status, IFA_SELECT_STATUS_PENDING);

    // Cooperative wait: must block/yield until timeout expires and return timeout index (1)
    let wait_res = ifa_rt_channel_select_wait_table(&mut table);
    assert_eq!(wait_res, 1);
    assert_eq!(entries[1].status, IFA_SELECT_STATUS_READY);

    // Test C-ABI ifa_rt_channel_select_timed with empty channel and timeout
    let chan_arr = [ch];
    let prio_arr = [0];
    let timed_res = ifa_rt_channel_select_timed(
        chan_arr.as_ptr(),
        prio_arr.as_ptr(),
        1,
        10_000_000, // 10ms
        0,
    );
    assert_eq!(timed_res, 1); // Timeout arm selected (num_channels = 1)

    ifa_rt_channel_destroy(ch);
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
fn test_stackless_generator_iterator_lifecycle() {
    use ifa_runtime::ffi::{
        ifa_rt_coro_create_custom, ifa_rt_coro_iter_create, ifa_rt_coro_iter_destroy,
        ifa_rt_coro_iter_is_done, ifa_rt_coro_iter_next,
    };

    struct GenFrame {
        current_val: i64,
        step: usize,
    }

    extern "C" fn gen_resume(frame: *mut u8) -> i32 {
        let f = unsafe { &mut *(frame as *mut GenFrame) };
        if f.step < 3 {
            f.step += 1;
            f.current_val = (f.step * 10) as i64;
            0 // Suspended (yielded)
        } else {
            1 // Completed
        }
    }

    extern "C" fn gen_destroy(frame: *mut u8) {
        unsafe {
            let _ = Box::from_raw(frame as *mut GenFrame);
        }
    }

    let raw_frame = Box::into_raw(Box::new(GenFrame {
        current_val: 0,
        step: 0,
    }));
    let slot_ptr = unsafe { &mut (*raw_frame).current_val as *mut i64 as *mut u8 };

    let coro = ifa_rt_coro_create_custom(raw_frame as *mut u8, gen_resume, Some(gen_destroy));
    let iter = ifa_rt_coro_iter_create(coro, slot_ptr, std::mem::size_of::<i64>());
    assert_eq!(ifa_rt_coro_iter_is_done(iter), 0);

    let mut out_val: i64 = 0;
    let next1 = ifa_rt_coro_iter_next(iter, &mut out_val as *mut i64 as *mut u8);
    assert_eq!(next1, 1);
    assert_eq!(out_val, 10);

    let next2 = ifa_rt_coro_iter_next(iter, &mut out_val as *mut i64 as *mut u8);
    assert_eq!(next2, 1);
    assert_eq!(out_val, 20);

    let next3 = ifa_rt_coro_iter_next(iter, &mut out_val as *mut i64 as *mut u8);
    assert_eq!(next3, 1);
    assert_eq!(out_val, 30);

    let next4 = ifa_rt_coro_iter_next(iter, &mut out_val as *mut i64 as *mut u8);
    assert_eq!(next4, 0); // Done
    assert_eq!(ifa_rt_coro_iter_is_done(iter), 1);

    ifa_rt_coro_iter_destroy(iter);
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

#[test]
fn test_blocking_pool_cooperative_yield_and_ffi_isolation() {
    use ifa_runtime::blocking::{ifa_rt_blocking_call, GLOBAL_BLOCKING_POOL};
    use std::ffi::c_void;
    use std::sync::atomic::{AtomicBool, Ordering};

    static TASK_STARTED: AtomicBool = AtomicBool::new(false);
    static TASK_COMPLETED: AtomicBool = AtomicBool::new(false);

    #[repr(C)]
    struct AddPack {
        a: i64,
        b: i64,
        res: i64,
    }

    extern "C" fn slow_add_thunk(ctx: *mut c_void) -> *mut c_void {
        TASK_STARTED.store(true, Ordering::SeqCst);
        let pack = unsafe { &mut *(ctx as *mut AddPack) };
        std::thread::sleep(std::time::Duration::from_millis(50));
        pack.res = pack.a + pack.b;
        TASK_COMPLETED.store(true, Ordering::SeqCst);
        ctx
    }

    let mut pack = AddPack {
        a: 100,
        b: 250,
        res: 0,
    };
    assert!(GLOBAL_BLOCKING_POOL.capacity() >= 1);

    let res_ptr = ifa_rt_blocking_call(slow_add_thunk, &mut pack as *mut AddPack as *mut c_void);
    assert_eq!(res_ptr, &mut pack as *mut AddPack as *mut c_void);
    assert!(TASK_STARTED.load(Ordering::SeqCst));
    assert!(TASK_COMPLETED.load(Ordering::SeqCst));
    assert_eq!(pack.res, 350);
}

#[test]
fn test_thread_local_call_arena_alloc_and_rewind() {
    use ifa_runtime::ffi::{
        ifa_rt_call_arena_alloc, ifa_rt_call_arena_mark, ifa_rt_call_arena_reset,
        ifa_rt_call_arena_rewind, ifa_rt_gen_check,
    };
    use ifa_runtime::header::{GenHeader, ARENA_THREAD_LOCAL_CALL};

    ifa_rt_call_arena_reset();

    let mark_initial = ifa_rt_call_arena_mark();
    let ptr1 = ifa_rt_call_arena_alloc(64, 8);
    assert!(!ptr1.is_null());

    unsafe {
        let header = (ptr1 as *const GenHeader).sub(1);
        assert_eq!((*header).arena_id, ARENA_THREAD_LOCAL_CALL);
        assert_eq!((*header).generation_counter, 1);
    }
    ifa_rt_gen_check(ptr1, 1);

    let mark_after_ptr1 = ifa_rt_call_arena_mark();
    let ptr2 = ifa_rt_call_arena_alloc(128, 16);
    assert!(!ptr2.is_null());
    assert_ne!(ptr1, ptr2);
    unsafe {
        let header2 = (ptr2 as *const GenHeader).sub(1);
        assert_eq!((*header2).arena_id, ARENA_THREAD_LOCAL_CALL);
        assert_eq!((*header2).generation_counter, 2);
    }
    ifa_rt_gen_check(ptr2, 2);

    // Rewind back to ptr1 mark
    ifa_rt_call_arena_rewind(mark_after_ptr1);

    // Allocating again should reuse the memory space rewound, but with a bumped generation counter
    let ptr3 = ifa_rt_call_arena_alloc(128, 16);
    assert_eq!(ptr2, ptr3);
    unsafe {
        let header3 = (ptr3 as *const GenHeader).sub(1);
        assert_eq!((*header3).arena_id, ARENA_THREAD_LOCAL_CALL);
        assert!((*header3).generation_counter > 2);
        assert_eq!((*header3).generation_counter, 4);
    }
    ifa_rt_gen_check(ptr3, 4);

    // Reset completely
    ifa_rt_call_arena_reset();
    assert_eq!(ifa_rt_call_arena_mark(), mark_initial);
}

#[test]
fn test_call_arena_stale_reference_invalidation() {
    use ifa_runtime::ffi::{
        ifa_rt_call_arena_alloc, ifa_rt_call_arena_mark, ifa_rt_call_arena_reset,
        ifa_rt_call_arena_rewind, ifa_rt_catch_panic, ifa_rt_clear_last_panic, ifa_rt_gen_check,
        ifa_rt_get_last_panic,
    };
    use ifa_runtime::header::{GenHeader, ARENA_THREAD_LOCAL_CALL};
    use ifa_runtime::IfaPanicKind;

    ifa_rt_call_arena_reset();

    let mark = ifa_rt_call_arena_mark();
    let ptr1 = ifa_rt_call_arena_alloc(64, 8);
    let gen1 = unsafe { (*(ptr1 as *const GenHeader).sub(1)).generation_counter };
    ifa_rt_gen_check(ptr1, gen1);

    // Rewind scope
    ifa_rt_call_arena_rewind(mark);

    // Re-allocate at the same address for a new invocation
    let ptr2 = ifa_rt_call_arena_alloc(64, 8);
    assert_eq!(ptr1, ptr2);
    let gen2 = unsafe { (*(ptr2 as *const GenHeader).sub(1)).generation_counter };
    assert!(gen2 > gen1);

    // Verification of new allocation succeeds with its own generation
    ifa_rt_gen_check(ptr2, gen2);

    // Stale reference with gen1 pointing to the same address is intercepted safely via ifa_rt_catch_panic
    extern "C-unwind" fn trigger_stale(arg: *mut u8) {
        let (target_ptr, remembered_gen) = unsafe { *(arg as *const (*const u8, u32)) };
        ifa_rt_gen_check(target_ptr, remembered_gen);
    }

    let mut args = (ptr1 as *const u8, gen1);
    let res = ifa_rt_catch_panic(trigger_stale, &mut args as *mut _ as *mut u8);
    assert_eq!(res, IfaPanicKind::UseAfterFree as i32);

    let last_panic_ptr = ifa_rt_get_last_panic();
    assert!(!last_panic_ptr.is_null());
    unsafe {
        let rec = &*last_panic_ptr;
        assert_eq!(rec.kind, IfaPanicKind::UseAfterFree);
        assert_eq!(rec.fault_address, ptr1 as usize);
        assert_eq!(rec.expected_gen, gen1);
        assert_eq!(rec.actual_gen, gen2);
        assert_eq!(rec.arena_id, ARENA_THREAD_LOCAL_CALL);
    }
    ifa_rt_clear_last_panic();
}

#[test]
fn test_thread_local_call_arena_multistage_pipeline_block_reuse_and_consolidation() {
    use ifa_runtime::{
        call_arena_alloc, call_arena_capacity, call_arena_guard, call_arena_high_water_mark,
        call_arena_reset, call_arena_shrink_to_fit, call_arena_stats,
    };

    call_arena_reset();
    let initial_cap = call_arena_capacity();
    assert!(initial_cap >= 65536);

    let base_ptr_stage1;
    // Stage 1: Lexing / Parsing context allocation
    {
        let _guard = call_arena_guard();
        let ptr1 = call_arena_alloc(4096, 16);
        assert!(!ptr1.is_null());
        base_ptr_stage1 = ptr1 as usize;
        unsafe {
            std::ptr::write_bytes(ptr1, 0xAA, 4096);
        }
    } // _guard rewinds arena offset to 0

    // Stage 2: Type checking / SEMA context allocation (must reuse the same block offset)
    let base_ptr_stage2;
    {
        let _guard = call_arena_guard();
        let ptr2 = call_arena_alloc(8192, 16);
        assert!(!ptr2.is_null());
        base_ptr_stage2 = ptr2 as usize;
        assert_eq!(
            base_ptr_stage1, base_ptr_stage2,
            "Stage 2 must reuse the exact same initial memory block offset in L1/L2 cache"
        );
        unsafe {
            std::ptr::write_bytes(ptr2, 0xBB, 8192);
        }
    } // rewound

    // Stage 3: FIR SSA / JIT code buffer allocation
    {
        let _guard = call_arena_guard();
        let ptr3 = call_arena_alloc(16384, 16);
        assert!(!ptr3.is_null());
        assert_eq!(
            base_ptr_stage1, ptr3 as usize,
            "Stage 3 must reuse the exact same initial memory block offset"
        );
    }

    let stats = call_arena_stats();
    assert_eq!(stats.current_offset, 0);
    assert!(stats.total_allocations >= 3);
    assert!(stats.total_rewinds >= 3);
    assert!(stats.reused_bytes >= 4096 + 8192 + 16384);
    assert!(stats.high_water_mark >= 16384);
    assert_eq!(call_arena_high_water_mark(), stats.high_water_mark);

    // Test consolidation and shrink
    call_arena_shrink_to_fit(stats.capacity);
    assert_eq!(call_arena_capacity(), stats.capacity);
}

#[test]
fn test_slice_and_strided_bounds_check_ffi() {
    use ifa_runtime::ffi::{
        ifa_rt_catch_panic, ifa_rt_clear_last_panic, ifa_rt_slice_bounds_check,
        ifa_rt_slice_strided_bounds_check,
    };
    use ifa_runtime::panic::IfaPanicKind;

    // Valid standard slice range checks
    ifa_rt_slice_bounds_check(0, 10, 10, std::ptr::null());
    ifa_rt_slice_bounds_check(2, 7, 10, std::ptr::null());
    ifa_rt_slice_bounds_check(5, 5, 10, std::ptr::null());

    // Valid strided slice range checks
    ifa_rt_slice_strided_bounds_check(0, 10, 1, 10, std::ptr::null());
    ifa_rt_slice_strided_bounds_check(0, 10, 2, 10, std::ptr::null());
    ifa_rt_slice_strided_bounds_check(1, 9, 3, 10, std::ptr::null());
    ifa_rt_slice_strided_bounds_check(4, 4, 2, 10, std::ptr::null());

    // Invalid stride == 0 triggers assertion failure intercepted via ifa_rt_catch_panic
    extern "C-unwind" fn trigger_zero_stride(_: *mut u8) {
        ifa_rt_slice_strided_bounds_check(0, 10, 0, 10, std::ptr::null());
    }
    let res_stride = ifa_rt_catch_panic(trigger_zero_stride, std::ptr::null_mut());
    assert_eq!(res_stride, IfaPanicKind::AssertionFailed as i32);
    ifa_rt_clear_last_panic();

    // Invalid range: start > end triggers OutOfBounds panic
    extern "C-unwind" fn trigger_inverted(_: *mut u8) {
        ifa_rt_slice_strided_bounds_check(8, 4, 1, 10, std::ptr::null());
    }
    let res_inv = ifa_rt_catch_panic(trigger_inverted, std::ptr::null_mut());
    assert_eq!(res_inv, IfaPanicKind::OutOfBounds as i32);
    ifa_rt_clear_last_panic();

    // Invalid range: end > len triggers OutOfBounds panic
    extern "C-unwind" fn trigger_oob(_: *mut u8) {
        ifa_rt_slice_strided_bounds_check(0, 15, 2, 10, std::ptr::null());
    }
    let res_oob = ifa_rt_catch_panic(trigger_oob, std::ptr::null_mut());
    assert_eq!(res_oob, IfaPanicKind::OutOfBounds as i32);
    ifa_rt_clear_last_panic();
}

#[test]
fn test_voluminous_slab_allocation_cycles_and_generational_quarantine() {
    use ifa_runtime::allocator::GLOBAL_ALLOCATOR;
    use ifa_runtime::ffi::ifa_rt_epoch_quarantined_count;
    use ifa_runtime::header::{GenHeader, GenRef, FLAG_EPOCH_1};
    use std::collections::HashSet;

    let test_classes = [16, 32, 64, 128, 256, 512, 1024];
    let slots_per_class = 20;
    let initial_quarantined = GLOBAL_ALLOCATOR.epoch_stats().quarantined_slots;

    let mut all_slots: Vec<(*mut u8, usize)> = Vec::new();
    let mut quarantined_addrs: HashSet<usize> = HashSet::new();
    let mut stale_refs: Vec<GenRef> = Vec::new();

    // 1. Initial voluminous allocation cycle across all slab size classes
    for &size in &test_classes {
        for _ in 0..slots_per_class {
            let ptr = GLOBAL_ALLOCATOR.alloc(size, 8, 0);
            assert!(!ptr.is_null());
            all_slots.push((ptr, size));
        }
    }

    // 2. Select a subset of slots (one per class) to undergo two full generational lifecycles to quarantine
    let mut target_slots = Vec::new();
    for &size in &test_classes {
        if let Some(pos) = all_slots.iter().position(|(_, s)| *s == size) {
            target_slots.push(all_slots.remove(pos));
        }
    }

    let mut expected_quarantined = 0;

    for (ptr, size) in target_slots {
        unsafe {
            let header = (ptr as *mut GenHeader).sub(1);
            assert!((*header).is_active());
            assert_eq!((*header).epoch_id(), 0);

            // Record a valid reference before free
            stale_refs.push(GenRef {
                ptr,
                remembered_gen: (*header).generation_counter,
                arena_id: (*header).arena_id,
                _reserved: 0,
            });

            // Force 32-bit counter overflow to Epoch 1
            (*header).generation_counter = u32::MAX;
        }

        // Free slot -> must transition to Epoch 1
        GLOBAL_ALLOCATOR.free(ptr);

        // Reallocate from cache -> verify preserved epoch bit
        let realloc_ptr = GLOBAL_ALLOCATOR.alloc(size, 8, 0);
        assert!(!realloc_ptr.is_null());

        unsafe {
            let header2 = (realloc_ptr as *mut GenHeader).sub(1);
            assert!((*header2).is_active());
            assert_eq!((*header2).epoch_id(), 1);
            assert_eq!((*header2).allocation_flags & FLAG_EPOCH_1, FLAG_EPOCH_1);

            // Force secondary overflow on Epoch 1 -> permanent quarantine
            (*header2).generation_counter = u32::MAX;
            quarantined_addrs.insert(realloc_ptr as usize);
        }

        // Free slot -> secondary overflow permanently quarantines the slot
        GLOBAL_ALLOCATOR.free(realloc_ptr);
        expected_quarantined += 1;
    }

    // 3. Verify exact quarantine statistics in allocator and global FFI counter
    let final_quarantined = GLOBAL_ALLOCATOR.epoch_stats().quarantined_slots;
    assert_eq!(
        final_quarantined,
        initial_quarantined + expected_quarantined,
        "Total quarantined slots must match expected count"
    );
    assert_eq!(
        ifa_rt_epoch_quarantined_count(),
        final_quarantined,
        "FFI quarantined count must match global stats"
    );

    // 4. Stale references captured before the free MUST fail dereference validation
    for stale_ref in &stale_refs {
        assert!(
            stale_ref.deref_checked().is_none(),
            "Stale GenRef must return None upon deref_checked"
        );
    }

    // 5. Stress test: allocate a massive burst of new slots across all classes
    // and verify that NO newly allocated slot ever reuses a quarantined memory address!
    let mut burst_slots = Vec::new();
    for &size in &test_classes {
        for _ in 0..slots_per_class * 2 {
            let fresh_ptr = GLOBAL_ALLOCATOR.alloc(size, 8, 0);
            assert!(!fresh_ptr.is_null());
            assert!(
                !quarantined_addrs.contains(&(fresh_ptr as usize)),
                "Quarantined slot {:p} was illegally reallocated from pool!",
                fresh_ptr
            );
            burst_slots.push(fresh_ptr);
        }
    }

    // 6. Clean up active slots
    for (ptr, _) in all_slots {
        GLOBAL_ALLOCATOR.free(ptr);
    }
    for ptr in burst_slots {
        GLOBAL_ALLOCATOR.free(ptr);
    }
}

#[test]
fn test_concurrent_multithreaded_slab_allocation_quarantine_cycles() {
    use ifa_runtime::allocator::GLOBAL_ALLOCATOR;
    use ifa_runtime::header::GenHeader;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;

    const NUM_THREADS: usize = 6;
    const CYCLES_PER_THREAD: usize = 10;
    let initial_quarantined = GLOBAL_ALLOCATOR.epoch_stats().quarantined_slots;
    let quarantined_counter = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();
    for _ in 0..NUM_THREADS {
        let q_cnt = Arc::clone(&quarantined_counter);
        handles.push(thread::spawn(move || {
            let sizes = [32, 64, 128, 256];
            for i in 0..CYCLES_PER_THREAD {
                let size = sizes[i % sizes.len()];
                // 1. Allocate slot
                let ptr = GLOBAL_ALLOCATOR.alloc(size, 8, 0);
                assert!(!ptr.is_null());

                // 2. Force Epoch 1 overflow
                unsafe {
                    let header = (ptr as *mut GenHeader).sub(1);
                    (*header).generation_counter = u32::MAX;
                }
                GLOBAL_ALLOCATOR.free(ptr);

                // 3. Reallocate and force quarantine
                let ptr2 = GLOBAL_ALLOCATOR.alloc(size, 8, 0);
                assert!(!ptr2.is_null());

                unsafe {
                    let header2 = (ptr2 as *mut GenHeader).sub(1);
                    (*header2).generation_counter = u32::MAX;
                }
                GLOBAL_ALLOCATOR.free(ptr2);
                q_cnt.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }

    for h in handles {
        h.join()
            .expect("Worker thread panicked during concurrent quarantine cycle");
    }

    let final_quarantined = GLOBAL_ALLOCATOR.epoch_stats().quarantined_slots;
    let threads_quarantined = quarantined_counter.load(Ordering::Relaxed);
    assert!(
        final_quarantined >= initial_quarantined + threads_quarantined,
        "Final quarantined count {} must account for all thread retirements {}",
        final_quarantined,
        threads_quarantined
    );
}

#[test]
fn test_coroutine_with_arena_and_channel_slice_exchange() {
    use ifa_runtime::ffi::{
        ifa_rt_arena_transfer_owner, ifa_rt_channel_create, ifa_rt_channel_destroy,
        ifa_rt_channel_recv_slice, ifa_rt_channel_send_slice, ifa_rt_channel_try_recv_slice,
        ifa_rt_channel_try_send_slice, ifa_rt_coro_arena_id, ifa_rt_coro_create_with_arena,
        ifa_rt_coro_destroy, ifa_rt_coro_frame, ifa_rt_coro_spawn_with_arena, ifa_rt_fiber_join,
        ifa_rt_slice_alloc, ifa_rt_slice_free, ifa_rt_slice_verify_arena, IfaSlice,
    };
    use ifa_runtime::header::GenHeader;

    extern "C" fn dummy_coro_step(_frame: *mut u8) -> i32 {
        1 // Completed
    }

    let target_arena: u16 = 42;
    let coro = ifa_rt_coro_create_with_arena(64, target_arena, dummy_coro_step, None);
    assert!(!coro.is_null());
    assert_eq!(ifa_rt_coro_arena_id(coro), target_arena);

    let frame = ifa_rt_coro_frame(coro);
    assert!(!frame.is_null());
    unsafe {
        let header = &*(frame.sub(std::mem::size_of::<GenHeader>()) as *const GenHeader);
        assert_eq!(
            header.arena_id, target_arena,
            "Frame allocation must reside in configured arena"
        );
    }

    let fid = ifa_rt_coro_spawn_with_arena(coro, target_arena);
    assert!(fid > 0, "Spawn with arena must return positive fiber ID");

    // Test channel slice exchange with arena verification
    let chan = ifa_rt_channel_create(4);
    assert!(!chan.is_null());

    let mut_slice = ifa_rt_slice_alloc(128, target_arena);
    assert!(!mut_slice.ptr.is_null());
    let immut_slice = IfaSlice {
        ptr: mut_slice.ptr,
        len: 128,
    };

    assert_eq!(
        ifa_rt_slice_verify_arena(immut_slice, target_arena),
        1,
        "Slice must be verified in arena 42"
    );
    assert_eq!(
        ifa_rt_slice_verify_arena(immut_slice, 999),
        0,
        "Slice must NOT match disjoint arena 999"
    );

    // Send and receive slice over channel
    let send_res = ifa_rt_channel_send_slice(chan, immut_slice);
    assert_eq!(send_res, 0, "Channel send slice must succeed");

    let mut recv_slice = IfaSlice {
        ptr: std::ptr::null(),
        len: 0,
    };
    let recv_res = ifa_rt_channel_recv_slice(chan, &mut recv_slice);
    assert_eq!(recv_res, 0, "Channel recv slice must succeed");
    assert_eq!(recv_slice.ptr, immut_slice.ptr);
    assert_eq!(recv_slice.len, 128);

    // Non-blocking try send / try recv
    let try_send_res = ifa_rt_channel_try_send_slice(chan, immut_slice);
    assert_eq!(try_send_res, 0, "Channel try send slice must succeed");

    let mut try_recv_slice = IfaSlice {
        ptr: std::ptr::null(),
        len: 0,
    };
    let try_recv_res = ifa_rt_channel_try_recv_slice(chan, &mut try_recv_slice);
    assert_eq!(try_recv_res, 0, "Channel try recv slice must succeed");
    assert_eq!(try_recv_slice.ptr, immut_slice.ptr);
    assert_eq!(try_recv_slice.len, 128);

    // Arena owner transfer
    let xfer_res = ifa_rt_arena_transfer_owner(target_arena, 8888);
    assert_eq!(xfer_res, 1, "Arena owner transfer must succeed");

    // Join the fiber spawned with arena before destroying the coroutine
    ifa_rt_fiber_join(fid);

    ifa_rt_slice_free(mut_slice);
    ifa_rt_channel_destroy(chan);
    ifa_rt_coro_destroy(coro);
}

#[test]
fn test_runtime_multi_arena_conv_and_stencil_kernels() {
    use ifa_runtime::*;

    // 1. Test 2D Multi-Arena Fused Convolution with ReLU activation
    let img = [1.0f64, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0];
    let weights = [0.5f64];
    let bias = [0.1f64];
    let mut dst2d = [0.0f64; 4];

    unsafe {
        ifa_simd_multi_arena_conv2d_f64(
            dst2d.as_mut_ptr(),
            img.as_ptr(),
            weights.as_ptr(),
            bias.as_ptr(),
            2,
            2,
            1,
            1,
            3,
            1, // ReLU
        );
    }

    assert!(
        (dst2d[0] - 0.6).abs() < 1e-6,
        "dst[0] = 1.0 * 0.5 + 0.1 = 0.6"
    );
    assert!(
        (dst2d[1] - 1.1).abs() < 1e-6,
        "dst[1] = 2.0 * 0.5 + 0.1 = 1.1"
    );
    assert!(
        (dst2d[2] - 2.1).abs() < 1e-6,
        "dst[2] = 4.0 * 0.5 + 0.1 = 2.1"
    );
    assert!(
        (dst2d[3] - 2.6).abs() < 1e-6,
        "dst[3] = 5.0 * 0.5 + 0.1 = 2.6"
    );

    // 1b. Test 2D Multi-Arena Fused Convolution (i64)
    let img_i64 = [1i64, 2, 3, 4, 5, 6, 7, 8, 9];
    let weights_i64 = [2i64];
    let bias_i64 = [1i64];
    let mut dst2d_i64 = [0i64; 4];
    unsafe {
        ifa_simd_multi_arena_conv2d_i64(
            dst2d_i64.as_mut_ptr(),
            img_i64.as_ptr(),
            weights_i64.as_ptr(),
            bias_i64.as_ptr(),
            2,
            2,
            1,
            1,
            3,
            1, // ReLU
        );
    }
    assert_eq!(dst2d_i64[0], 3, "1 * 2 + 1 = 3");
    assert_eq!(dst2d_i64[1], 5, "2 * 2 + 1 = 5");
    assert_eq!(dst2d_i64[2], 9, "4 * 2 + 1 = 9");
    assert_eq!(dst2d_i64[3], 11, "5 * 2 + 1 = 11");

    // 2. Test 3D Volumetric Multi-Arena Fused Convolution with ReLU
    let volume = [1.0f64, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0];
    let filter = [2.0f64];
    let bias_neg = [-1.0f64];
    let mut dst3d = [0.0f64; 8];

    unsafe {
        ifa_simd_multi_arena_conv3d_f64(
            dst3d.as_mut_ptr(),
            volume.as_ptr(),
            filter.as_ptr(),
            bias_neg.as_ptr(),
            2,
            2,
            2,
            1,
            1,
            1,
            4,
            2,
            1, // ReLU
        );
    }

    assert!(
        (dst3d[0] - 1.0).abs() < 1e-6,
        "dst3d[0] = 1.0 * 2.0 - 1.0 = 1.0"
    );
    assert!(
        (dst3d[7] - 15.0).abs() < 1e-6,
        "dst3d[7] = 8.0 * 2.0 - 1.0 = 15.0"
    );

    // 3. Test Multi-Arena Dot Product
    let src1 = [1.0f64, 2.0, 3.0, 4.0];
    let src2 = [5.0f64, 6.0, 7.0, 8.0];
    let dot_full =
        unsafe { ifa_simd_multi_arena_slice_dot_f64(src1.as_ptr(), src2.as_ptr(), 4, 1, 1) };
    assert!(
        (dot_full - 70.0).abs() < 1e-6,
        "Dot product 1*5 + 2*6 + 3*7 + 4*8 = 70.0"
    );

    let dot_strided =
        unsafe { ifa_simd_multi_arena_slice_dot_f64(src1.as_ptr(), src2.as_ptr(), 2, 2, 2) };
    assert!(
        (dot_strided - 26.0).abs() < 1e-6,
        "Strided dot 1*5 + 3*7 = 26.0"
    );

    // 4. Test Arena Count-If Reduction
    let slice_data = [1.0f64, 5.0, 2.0, 8.0, 3.0];
    let count = unsafe { ifa_simd_arena_slice_count_if_gt_f64(slice_data.as_ptr(), 5, 2.5) };
    assert_eq!(count, 3, "Elements > 2.5 must be 3 (5.0, 8.0, 3.0)");
}

#[test]
fn test_multi_arena_dilated_conv2d_and_spatial_pooling() {
    use ifa_runtime::ffi::{
        ifa_simd_multi_arena_avgpool2d_f32, ifa_simd_multi_arena_avgpool2d_i64,
        ifa_simd_multi_arena_dilated_conv2d_f32, ifa_simd_multi_arena_dilated_conv2d_i64,
        ifa_simd_multi_arena_maxpool2d_f32, ifa_simd_multi_arena_maxpool2d_i64,
    };

    // 1. Dilated 2D Convolution (5x5 image, 2x2 kernel with dilation=2 -> 3x3 output)
    // img:
    // [ 1,  2,  3,  4,  5,
    //   6,  7,  8,  9, 10,
    //  11, 12, 13, 14, 15,
    //  16, 17, 18, 19, 20,
    //  21, 22, 23, 24, 25 ]
    let mut img = [0.0f32; 25];
    for (i, v) in img.iter_mut().enumerate() {
        *v = (i + 1) as f32;
    }
    // weights 2x2: [1.0, 2.0, 3.0, 4.0]
    let weights = [1.0f32, 2.0, 3.0, 4.0];
    let bias = 0.5f32;
    let mut dst = [0.0f32; 9]; // 3x3 output (stride=1)

    // For (y=0, x=0), receptive field with dilation=2 uses:
    // img[0,0]=1, img[0,2]=3, img[2,0]=11, img[2,2]=13
    // accum = 1*1 + 3*2 + 11*3 + 13*4 + 0.5 = 1 + 6 + 33 + 52 + 0.5 = 92.5
    unsafe {
        ifa_simd_multi_arena_dilated_conv2d_f32(
            dst.as_mut_ptr(),
            img.as_ptr(),
            weights.as_ptr(),
            &bias as *const f32,
            3,
            3,
            1,
            1,
            2, // dilation_y
            2, // dilation_x
            2, // kernel_h
            2, // kernel_w
            5, // img_width
            1, // ReLU
        );
    }
    assert!(
        (dst[0] - 92.5).abs() < 1e-4,
        "dst[0] expected 92.5, got {}",
        dst[0]
    );

    // 2. Spatial Max-Pooling 2D (4x4 image, 2x2 pool window, stride=2 -> 2x2 output)
    // [ 1,  8,  3,  4,
    //   5,  6,  7,  2,
    //   9, 10, 15, 12,
    //  13, 14, 11, 16 ]
    #[rustfmt::skip]
    let pool_img_f32 = [
        1.0f32, 8.0,  3.0,  4.0,
        5.0,    6.0,  7.0,  2.0,
        9.0,   10.0, 15.0, 12.0,
       13.0,   14.0, 11.0, 16.0,
    ];
    let mut max_out_f32 = [0.0f32; 4];
    unsafe {
        ifa_simd_multi_arena_maxpool2d_f32(
            max_out_f32.as_mut_ptr(),
            pool_img_f32.as_ptr(),
            2,
            2,
            2,
            2,
            2,
            2,
            4,
        );
    }
    // Block (0,0): max(1,8,5,6) = 8.0
    // Block (0,1): max(3,4,7,2) = 7.0
    // Block (1,0): max(9,10,13,14) = 14.0
    // Block (1,1): max(15,12,11,16) = 16.0
    assert_eq!(max_out_f32, [8.0, 7.0, 14.0, 16.0]);

    // 3. Spatial Average-Pooling 2D (4x4 image, 2x2 pool window, stride=2 -> 2x2 output)
    let mut avg_out_f32 = [0.0f32; 4];
    unsafe {
        ifa_simd_multi_arena_avgpool2d_f32(
            avg_out_f32.as_mut_ptr(),
            pool_img_f32.as_ptr(),
            2,
            2,
            2,
            2,
            2,
            2,
            4,
        );
    }
    // Block (0,0): (1+8+5+6)/4 = 20/4 = 5.0
    // Block (0,1): (3+4+7+2)/4 = 16/4 = 4.0
    // Block (1,0): (9+10+13+14)/4 = 46/4 = 11.5
    // Block (1,1): (15+12+11+16)/4 = 54/4 = 13.5
    assert_eq!(avg_out_f32, [5.0, 4.0, 11.5, 13.5]);

    // 4. Integer i64 Dilated Conv and Pooling
    #[rustfmt::skip]
    let pool_img_i64: [i64; 16] = [
        1, 8,  3,  4,
        5, 6,  7,  2,
        9, 10, 15, 12,
       13, 14, 11, 16,
    ];
    let mut max_out_i64 = [0i64; 4];
    let mut avg_out_i64 = [0i64; 4];
    unsafe {
        ifa_simd_multi_arena_maxpool2d_i64(
            max_out_i64.as_mut_ptr(),
            pool_img_i64.as_ptr(),
            2,
            2,
            2,
            2,
            2,
            2,
            4,
        );
        ifa_simd_multi_arena_avgpool2d_i64(
            avg_out_i64.as_mut_ptr(),
            pool_img_i64.as_ptr(),
            2,
            2,
            2,
            2,
            2,
            2,
            4,
        );
    }
    assert_eq!(max_out_i64, [8, 7, 14, 16]);
    assert_eq!(avg_out_i64, [5, 4, 11, 13]); // 46/4 = 11, 54/4 = 13 integer division

    // Dilated conv i64
    let mut img_i64 = [0i64; 25];
    for (i, v) in img_i64.iter_mut().enumerate() {
        *v = (i + 1) as i64;
    }
    let weights_i64 = [1i64, 2, 3, 4];
    let bias_i64 = 10i64;
    let mut dst_i64 = [0i64; 9];
    unsafe {
        ifa_simd_multi_arena_dilated_conv2d_i64(
            dst_i64.as_mut_ptr(),
            img_i64.as_ptr(),
            weights_i64.as_ptr(),
            &bias_i64 as *const i64,
            3,
            3,
            1,
            1,
            2,
            2,
            2,
            2,
            5,
            1,
        );
    }
    // 92 + 10 = 102
    assert_eq!(dst_i64[0], 102);
}

#[test]
fn test_multi_arena_depthwise_pointwise_conv_and_batch_norm() {
    use ifa_runtime::ffi::{
        ifa_simd_multi_arena_batch_norm2d_f32, ifa_simd_multi_arena_depthwise_conv2d_f32,
        ifa_simd_multi_arena_pointwise_conv2d_f32,
    };

    // 1. Depthwise 2D conv: 2 channels, 3x3 input per channel, 2x2 kernel per channel, stride 1 -> 2x2 output per channel
    let img = [
        1.0f32, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0,
        80.0, 90.0,
    ];
    let weights = [1.0f32, 0.0, 0.0, 1.0, 0.0, 1.0, 1.0, 0.0];
    let bias = [0.5f32, 1.0f32];
    let mut dst = [0.0f32; 8];

    unsafe {
        ifa_simd_multi_arena_depthwise_conv2d_f32(
            dst.as_mut_ptr(),
            img.as_ptr(),
            weights.as_ptr(),
            bias.as_ptr(),
            2, // channels
            2, // h_out
            2, // w_out
            1, // stride_y
            1, // stride_x
            2, // kernel_h
            2, // kernel_w
            3, // img_h
            3, // img_w
            1, // ReLU
        );
    }
    // Ch 0 at (0, 0): img[0]*1 + img[1]*0 + img[3]*0 + img[4]*1 + 0.5 = 1 + 5 + 0.5 = 6.5
    assert!((dst[0] - 6.5).abs() < 1e-4);
    // Ch 1 at (0, 0): img[9+0]*0 + img[9+1]*1 + img[9+3]*1 + img[9+4]*0 + 1.0 = 20 + 40 + 1.0 = 61.0
    assert!((dst[4] - 61.0).abs() < 1e-4);

    // 2. Pointwise (1x1) conv: 2 channels in -> 1 channel out, spatial size = 4
    let pw_weights = [0.5f32, 2.0f32];
    let pw_bias = [0.0f32];
    let mut pw_dst = [0.0f32; 4];
    unsafe {
        ifa_simd_multi_arena_pointwise_conv2d_f32(
            pw_dst.as_mut_ptr(),
            img.as_ptr(),
            pw_weights.as_ptr(),
            pw_bias.as_ptr(),
            2, // c_in
            1, // c_out
            4, // spatial_size
            1, // ReLU
        );
    }
    // Pixel 0: img[0]*0.5 + img[4]*2.0 + 0 = 1*0.5 + 5*2.0 = 10.5
    assert!((pw_dst[0] - 10.5).abs() < 1e-4);

    // 3. Batch Normalization: 2 channels, spatial size = 4
    let bn_src = [2.0f32, 4.0, 6.0, 8.0, 10.0, 20.0, 30.0, 40.0];
    let gamma = [1.0f32, 2.0f32];
    let beta = [0.0f32, 5.0f32];
    let mean = [5.0f32, 25.0f32];
    let var = [5.0f32, 125.0f32];
    let mut bn_dst = [0.0f32; 8];
    unsafe {
        ifa_simd_multi_arena_batch_norm2d_f32(
            bn_dst.as_mut_ptr(),
            bn_src.as_ptr(),
            gamma.as_ptr(),
            beta.as_ptr(),
            mean.as_ptr(),
            var.as_ptr(),
            2,
            4,
            1e-5,
            0,
        );
    }
    // Ch 0, pixel 0: (2.0 - 5.0) / sqrt(5.00001) * 1.0 + 0.0 = -3.0 / 2.2360679 ~= -1.34164
    assert!((bn_dst[0] - (-1.34164)).abs() < 1e-3);
}

#[test]
fn test_multi_arena_gemm_and_normalizations() {
    use ifa_runtime::ffi::{
        ifa_simd_multi_arena_gemm_f32, ifa_simd_multi_arena_gemm_f64,
        ifa_simd_multi_arena_gemm_i64, ifa_simd_multi_arena_layer_norm_f32,
        ifa_simd_multi_arena_layer_norm_f64, ifa_simd_multi_arena_rmsnorm_f32,
        ifa_simd_multi_arena_rmsnorm_f64,
    };

    // 1. GEMM (f32): C = alpha * (A @ B) + bias
    // A: 2x3, B: 3x2, C: 2x2
    // A = [[1, 2, 3], [4, 5, 6]]
    // B = [[7, 8], [9, 1], [2, 3]]
    // A @ B = [[1*7+2*9+3*2, 1*8+2*1+3*3], [4*7+5*9+6*2, 4*8+5*1+6*3]]
    //       = [[7+18+6, 8+2+9], [28+45+12, 32+5+18]]
    //       = [[31, 19], [85, 55]]
    // Bias: [10, 20]
    // C expected: [[31+10, 19+20], [85+10, 55+20]] = [[41, 39], [95, 75]]
    let a = [1.0f32, 2.0, 3.0, 4.0, 5.0, 6.0];
    let b = [7.0f32, 8.0, 9.0, 1.0, 2.0, 3.0];
    let bias = [10.0f32, 20.0];
    let mut c = [0.0f32; 4];

    unsafe {
        ifa_simd_multi_arena_gemm_f32(
            c.as_mut_ptr(),
            a.as_ptr(),
            b.as_ptr(),
            bias.as_ptr(),
            2,      // M
            3,      // K
            2,      // N
            1.0f32, // alpha
            0.0f32, // beta
            0,      // activation: none
        );
    }
    assert_eq!(c, [41.0, 39.0, 95.0, 75.0]);

    // Test GEMM i64
    let a_i64 = [1i64, 2, 3, 4, 5, 6];
    let b_i64 = [7i64, 8, 9, 1, 2, 3];
    let bias_i64 = [10i64, 20];
    let mut c_i64 = [0i64; 4];
    unsafe {
        ifa_simd_multi_arena_gemm_i64(
            c_i64.as_mut_ptr(),
            a_i64.as_ptr(),
            b_i64.as_ptr(),
            bias_i64.as_ptr(),
            2,
            3,
            2,
            1,
            0,
            0,
        );
    }
    assert_eq!(c_i64, [41, 39, 95, 75]);

    // Test GEMM f64
    let a_f64 = [1.0f64, 2.0, 3.0, 4.0, 5.0, 6.0];
    let b_f64 = [7.0f64, 8.0, 9.0, 1.0, 2.0, 3.0];
    let bias_f64 = [10.0f64, 20.0];
    let mut c_f64 = [0.0f64; 4];
    unsafe {
        ifa_simd_multi_arena_gemm_f64(
            c_f64.as_mut_ptr(),
            a_f64.as_ptr(),
            b_f64.as_ptr(),
            bias_f64.as_ptr(),
            2,
            3,
            2,
            1.0,
            0.0,
            0,
        );
    }
    assert_eq!(c_f64, [41.0, 39.0, 95.0, 75.0]);

    // 2. LayerNorm (f32)
    // Batch: 2, Norm size: 4
    // Row 0: [2, 4, 6, 8] -> Mean = 5.0, Var = ((9+1+1+9)/4) = 5.0, std = sqrt(5.0) ~= 2.236068
    // Gamma: [1, 1, 1, 1], Beta: [0, 0, 0, 0]
    let ln_src = [2.0f32, 4.0, 6.0, 8.0, 1.0, 3.0, 5.0, 7.0];
    let ln_gamma = [1.0f32; 4];
    let ln_beta = [0.0f32; 4];
    let mut ln_dst = [0.0f32; 8];

    unsafe {
        ifa_simd_multi_arena_layer_norm_f32(
            ln_dst.as_mut_ptr(),
            ln_src.as_ptr(),
            ln_gamma.as_ptr(),
            ln_beta.as_ptr(),
            2,
            4,
            0.0,
            0,
        );
    }
    // Row 0 elem 0: (2.0 - 5.0) / sqrt(5.0) = -3 / 2.236068 ~= -1.34164
    assert!((ln_dst[0] - (-1.34164)).abs() < 1e-4);
    // Row 0 elem 3: (8.0 - 5.0) / sqrt(5.0) = 3 / 2.236068 ~= 1.34164
    assert!((ln_dst[3] - 1.34164).abs() < 1e-4);

    // Test LayerNorm f64
    let ln_src_f64 = [2.0f64, 4.0, 6.0, 8.0];
    let mut ln_dst_f64 = [0.0f64; 4];
    unsafe {
        ifa_simd_multi_arena_layer_norm_f64(
            ln_dst_f64.as_mut_ptr(),
            ln_src_f64.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            4,
            0.0,
            0,
        );
    }
    assert!((ln_dst_f64[0] - (-1.34164)).abs() < 1e-4);

    // 3. RMSNorm (f32 & f64)
    let rms_src_f32 = [2.0f32, 2.0, 2.0, 2.0];
    let rms_gamma_f32 = [2.0f32, 3.0, 4.0, 5.0];
    let mut rms_dst_f32 = [0.0f32; 4];
    unsafe {
        ifa_simd_multi_arena_rmsnorm_f32(
            rms_dst_f32.as_mut_ptr(),
            rms_src_f32.as_ptr(),
            rms_gamma_f32.as_ptr(),
            1,
            4,
            0.0,
            0,
        );
    }
    assert_eq!(rms_dst_f32, [2.0, 3.0, 4.0, 5.0]);

    // 3. RMSNorm (f64)
    // Batch: 1, Norm size: 4
    // Row 0: [2, 2, 2, 2] -> Mean square = 4.0, RMS = 2.0
    // x / RMS = 1.0
    let rms_src = [2.0f64, 2.0, 2.0, 2.0];
    let rms_gamma = [2.0f64, 3.0, 4.0, 5.0];
    let mut rms_dst = [0.0f64; 4];

    unsafe {
        ifa_simd_multi_arena_rmsnorm_f64(
            rms_dst.as_mut_ptr(),
            rms_src.as_ptr(),
            rms_gamma.as_ptr(),
            1,
            4,
            0.0,
            0,
        );
    }
    assert_eq!(rms_dst, [2.0, 3.0, 4.0, 5.0]);
}

#[test]
fn test_runtime_fs_and_process_primitives() {
    let temp_dir = std::env::temp_dir().join(format!("ifa_rt_fs_test_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let test_file = temp_dir.join("test.txt");
    let test_path = std::ffi::CString::new(test_file.to_str().unwrap()).unwrap();
    let content = std::ffi::CString::new("Hello from IFA Self-Hosting Compiler Runtime!").unwrap();

    // 1. Write file
    let write_ok = ifa_rt_fs_write_string(
        test_path.as_ptr() as *const u8,
        content.as_ptr() as *const u8,
    );
    assert!(write_ok);

    // 2. Exists
    let exists = ifa_rt_fs_exists(test_path.as_ptr() as *const u8);
    assert!(exists);

    // 3. File size
    let size = ifa_rt_fs_file_size(test_path.as_ptr() as *const u8);
    assert_eq!(size, 45);

    // 4. Read to string
    let read_ptr = ifa_rt_fs_read_to_string(test_path.as_ptr() as *const u8);
    assert!(!read_ptr.is_null());
    let read_str = unsafe {
        std::ffi::CStr::from_ptr(read_ptr as *const std::os::raw::c_char)
            .to_str()
            .unwrap()
    };
    assert_eq!(read_str, "Hello from IFA Self-Hosting Compiler Runtime!");
    unsafe {
        std::alloc::dealloc(
            read_ptr,
            std::alloc::Layout::from_size_align(read_str.len() + 1, 1).unwrap(),
        );
    }

    // 4b. Test copy_file, is_dir, and read_dir
    let copied_file = temp_dir.join("test_copy.txt");
    let copied_path = std::ffi::CString::new(copied_file.to_str().unwrap()).unwrap();
    let copy_ok = ifa_rt_fs_copy_file(
        test_path.as_ptr() as *const u8,
        copied_path.as_ptr() as *const u8,
    );
    assert!(copy_ok);
    assert!(ifa_rt_fs_exists(copied_path.as_ptr() as *const u8));

    // 4c. Test rename
    let renamed_file = temp_dir.join("test_renamed.txt");
    let renamed_path = std::ffi::CString::new(renamed_file.to_str().unwrap()).unwrap();
    let rename_ok = ifa_rt_fs_rename(
        copied_path.as_ptr() as *const u8,
        renamed_path.as_ptr() as *const u8,
    );
    assert!(rename_ok);
    assert!(!ifa_rt_fs_exists(copied_path.as_ptr() as *const u8));
    assert!(ifa_rt_fs_exists(renamed_path.as_ptr() as *const u8));

    // 4d. Test remove_dir and remove_dir_all
    let sub_dir = temp_dir.join("sub_test_dir");
    let sub_dir_c = std::ffi::CString::new(sub_dir.to_str().unwrap()).unwrap();
    assert!(ifa_rt_fs_create_dir_all(sub_dir_c.as_ptr() as *const u8));
    assert!(ifa_rt_fs_is_dir(sub_dir_c.as_ptr() as *const u8));
    assert!(ifa_rt_fs_remove_dir(sub_dir_c.as_ptr() as *const u8));
    assert!(!ifa_rt_fs_exists(sub_dir_c.as_ptr() as *const u8));

    let nested_dir = temp_dir.join("nested_dir").join("child");
    let nested_root = temp_dir.join("nested_dir");
    let nested_dir_c = std::ffi::CString::new(nested_dir.to_str().unwrap()).unwrap();
    let nested_root_c = std::ffi::CString::new(nested_root.to_str().unwrap()).unwrap();
    assert!(ifa_rt_fs_create_dir_all(nested_dir_c.as_ptr() as *const u8));
    assert!(ifa_rt_fs_remove_dir_all(nested_root_c.as_ptr() as *const u8));
    assert!(!ifa_rt_fs_exists(nested_root_c.as_ptr() as *const u8));

    let temp_dir_path = std::ffi::CString::new(temp_dir.to_str().unwrap()).unwrap();
    assert!(ifa_rt_fs_is_dir(temp_dir_path.as_ptr() as *const u8));
    assert!(!ifa_rt_fs_is_dir(test_path.as_ptr() as *const u8));

    let dir_list_ptr = ifa_rt_fs_read_dir(temp_dir_path.as_ptr() as *const u8);
    assert!(!dir_list_ptr.is_null());
    let dir_list_str = unsafe {
        std::ffi::CStr::from_ptr(dir_list_ptr as *const std::os::raw::c_char)
            .to_str()
            .unwrap()
    };
    assert!(dir_list_str.contains("test.txt"));
    assert!(dir_list_str.contains("test_renamed.txt"));
    unsafe {
        std::alloc::dealloc(
            dir_list_ptr,
            std::alloc::Layout::from_size_align(dir_list_str.len() + 1, 1).unwrap(),
        );
    }

    // 5. Process exec
    let cmd = std::ffi::CString::new("echo").unwrap();
    let args = std::ffi::CString::new("IFA_DETERMINISTIC_BUILD").unwrap();
    let status = ifa_rt_process_exec(cmd.as_ptr() as *const u8, args.as_ptr() as *const u8);
    assert_eq!(status, 0);

    // 6. Process exec output
    let out_ptr = ifa_rt_process_exec_output(cmd.as_ptr() as *const u8, args.as_ptr() as *const u8);
    assert!(!out_ptr.is_null());
    let out_str = unsafe {
        std::ffi::CStr::from_ptr(out_ptr as *const std::os::raw::c_char)
            .to_str()
            .unwrap()
    };
    assert!(out_str.contains("IFA_DETERMINISTIC_BUILD"));
    unsafe {
        std::alloc::dealloc(
            out_ptr,
            std::alloc::Layout::from_size_align(out_str.len() + 1, 1).unwrap(),
        );
    }

    // 6b. Process exec stderr
    let sh_cmd = std::ffi::CString::new("sh").unwrap();
    let err_args = std::ffi::CString::new("-c echo_error_message >&2").unwrap();
    let err_ptr =
        ifa_rt_process_exec_stderr(sh_cmd.as_ptr() as *const u8, err_args.as_ptr() as *const u8);
    assert!(!err_ptr.is_null());
    let err_str = unsafe {
        std::ffi::CStr::from_ptr(err_ptr as *const std::os::raw::c_char)
            .to_str()
            .unwrap()
    };
    assert!(err_str.contains("echo_error_message"));
    unsafe {
        std::alloc::dealloc(
            err_ptr,
            std::alloc::Layout::from_size_align(err_str.len() + 1, 1).unwrap(),
        );
    }

    // 6c. Process exec with stdin
    let cat_cmd = std::ffi::CString::new("cat").unwrap();
    let empty_args = std::ffi::CString::new("").unwrap();
    let stdin_input = std::ffi::CString::new("hello_stdin_stream").unwrap();
    let cat_status = ifa_rt_process_exec_with_stdin(
        cat_cmd.as_ptr() as *const u8,
        empty_args.as_ptr() as *const u8,
        stdin_input.as_ptr() as *const u8,
    );
    assert_eq!(cat_status, 0);

    // 6d. Process find linker and tool
    let linker_ptr = ifa_rt_process_find_linker();
    assert!(!linker_ptr.is_null());
    let linker_str = unsafe {
        std::ffi::CStr::from_ptr(linker_ptr as *const std::os::raw::c_char)
            .to_str()
            .unwrap()
    };
    assert!(!linker_str.is_empty());
    unsafe {
        std::alloc::dealloc(
            linker_ptr,
            std::alloc::Layout::from_size_align(linker_str.len() + 1, 1).unwrap(),
        );
    }

    let tool_query = std::ffi::CString::new("sh").unwrap();
    let tool_ptr = ifa_rt_process_find_tool(tool_query.as_ptr() as *const u8);
    assert!(!tool_ptr.is_null());
    let tool_path_str = unsafe {
        std::ffi::CStr::from_ptr(tool_ptr as *const std::os::raw::c_char)
            .to_str()
            .unwrap()
    };
    assert!(tool_path_str.contains("sh"));
    unsafe {
        std::alloc::dealloc(
            tool_ptr,
            std::alloc::Layout::from_size_align(tool_path_str.len() + 1, 1).unwrap(),
        );
    }

    // 7. Env var
    let env_name = std::ffi::CString::new("PATH").unwrap();
    let env_ptr = ifa_rt_env_var(env_name.as_ptr() as *const u8);
    assert!(!env_ptr.is_null());
    let env_str = unsafe {
        std::ffi::CStr::from_ptr(env_ptr as *const std::os::raw::c_char)
            .to_str()
            .unwrap()
    };
    assert!(!env_str.is_empty());
    unsafe {
        std::alloc::dealloc(
            env_ptr,
            std::alloc::Layout::from_size_align(env_str.len() + 1, 1).unwrap(),
        );
    }

    // 8. Command-line args count and get
    let argc = ifa_rt_args_count();
    assert!(argc >= 1);
    let arg0_ptr = ifa_rt_args_get(0);
    assert!(!arg0_ptr.is_null());
    let arg0_str = unsafe {
        std::ffi::CStr::from_ptr(arg0_ptr as *const std::os::raw::c_char)
            .to_str()
            .unwrap()
    };
    assert!(!arg0_str.is_empty());
    unsafe {
        std::alloc::dealloc(
            arg0_ptr,
            std::alloc::Layout::from_size_align(arg0_str.len() + 1, 1).unwrap(),
        );
    }
    let invalid_arg_ptr = ifa_rt_args_get(-1);
    let invalid_str = unsafe {
        std::ffi::CStr::from_ptr(invalid_arg_ptr as *const std::os::raw::c_char)
            .to_str()
            .unwrap()
    };
    assert_eq!(invalid_str, "");
    unsafe {
        std::alloc::dealloc(
            invalid_arg_ptr,
            std::alloc::Layout::from_size_align(1, 1).unwrap(),
        );
    }

    // 9. Process current dir
    let cwd_ptr = ifa_rt_process_current_dir();
    assert!(!cwd_ptr.is_null());
    let cwd_str = unsafe {
        std::ffi::CStr::from_ptr(cwd_ptr as *const std::os::raw::c_char)
            .to_str()
            .unwrap()
    };
    assert!(!cwd_str.is_empty());
    unsafe {
        std::alloc::dealloc(
            cwd_ptr,
            std::alloc::Layout::from_size_align(cwd_str.len() + 1, 1).unwrap(),
        );
    }

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_ifa_rt_sys_resource_primitives() {
    let cpu_count = ifa_rt_sys_cpu_count();
    assert!(cpu_count >= 1);

    let max_rss = ifa_rt_sys_max_rss();
    assert!(max_rss > 0);

    let mem_resident = ifa_rt_sys_memory_resident();
    assert!(mem_resident > 0);

    let mem_virtual = ifa_rt_sys_memory_virtual();
    assert!(mem_virtual >= mem_resident);

    let cpu_time_ns = ifa_rt_sys_cpu_time_ns();
    assert!(cpu_time_ns > 0);
}

#[test]
fn test_resource_telemetry_audit_and_supervision() {
    use ifa_runtime::{supervise_command, ResourceAuditScope, ResourceUsage};
    use std::process::Command;

    let initial = ResourceUsage::current();
    assert!(initial.cpu_count >= 1);
    assert!(initial.max_rss_bytes > 0);

    let scope = ResourceAuditScope::start();
    // Do some CPU work
    let mut acc = 0u64;
    for i in 0..100_000 {
        acc = acc.wrapping_add(i);
    }
    std::hint::black_box(acc);

    let report = scope.finish();
    assert!(report.wall_time_ns > 0);
    assert!(report.max_rss_bytes > 0);
    assert!(report.cpu_count >= 1);
    let summary = report.format_summary();
    assert!(summary.contains("peak rss:"));
    assert!(summary.contains("wall:"));

    // Test subprocess supervision
    let mut echo_cmd = Command::new("echo");
    echo_cmd.arg("telemetry-test");
    let (status, cmd_usage) = supervise_command(&mut echo_cmd).expect("supervise echo");
    assert!(status.success());
    assert!(cmd_usage.wall_time_ns > 0);
    assert!(cmd_usage.max_rss_bytes > 0);
}

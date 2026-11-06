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

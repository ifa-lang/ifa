//! High-contention multithreaded allocator benchmarks and generational safety stress testing.

use ifa_runtime::benchmarks::{run_allocator_multithread_suite, AllocatorEngine};

#[test]
fn test_allocator_high_contention_multithread_throughput() {
    let threads = [1, 2, 4];
    let ops_per_thread = 10_000;
    let report = run_allocator_multithread_suite(&threads, ops_per_thread);

    assert!(report.safety_determinism_verified);
    assert_eq!(report.thread_counts, vec![1, 2, 4]);

    println!("\n=== MULTITHREAD ALLOCATOR BENCHMARK REPORT ===");
    println!("{}", report.to_markdown_table());
    println!(
        "IFA vs mimalloc ratio: {:.2}x | IFA vs jemalloc ratio: {:.2}x | IFA vs system ratio: {:.2}x",
        report.ifa_vs_mimalloc_ratio, report.ifa_vs_jemalloc_ratio, report.ifa_vs_system_ratio
    );

    // Ensure IFA Generational Slab achieves competitive throughput
    let ifa_4t = report
        .results
        .iter()
        .find(|r| r.engine == AllocatorEngine::IfaGenerational && r.threads == 4)
        .expect("Missing 4-thread IFA result");

    assert!(
        ifa_4t.throughput_mops > 1.0,
        "IFA throughput must exceed 1.0 Mops/s under 4-thread contention (actual: {:.2} Mops/s)",
        ifa_4t.throughput_mops
    );
}

#[test]
fn test_allocator_cross_thread_exchange_stress() {
    use ifa_runtime::allocator::GLOBAL_ALLOCATOR;
    use ifa_runtime::fiber::Channel;
    use ifa_runtime::header::GenHeader;
    use std::sync::Arc;

    struct PtrMsg(*mut u8);
    unsafe impl Send for PtrMsg {}

    let iterations = 5_000;
    let channel = Arc::new(Channel::<PtrMsg>::with_capacity(64));
    let chan_tx = Arc::clone(&channel);
    let chan_rx = Arc::clone(&channel);

    let producer = std::thread::spawn(move || {
        for i in 0..iterations {
            let ptr = GLOBAL_ALLOCATOR.alloc(128, 8, 0);
            unsafe {
                *ptr = (i & 0xFF) as u8;
            }
            chan_tx.send(PtrMsg(ptr));
        }
    });

    let consumer = std::thread::spawn(move || {
        let mut verified = 0;
        for i in 0..iterations {
            let PtrMsg(ptr) = chan_rx.recv();
            unsafe {
                let header = (ptr as *mut GenHeader).sub(1);
                assert!((*header).is_active());
                assert_eq!(*ptr, (i & 0xFF) as u8);
                verified += 1;
            }
            GLOBAL_ALLOCATOR.free(ptr);
        }
        verified
    });

    producer.join().unwrap();
    let verified = consumer.join().unwrap();
    assert_eq!(verified, iterations);
}

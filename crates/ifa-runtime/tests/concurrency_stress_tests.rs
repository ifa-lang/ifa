//! Stress tests and edge-case verification for IFA multithread runtime, colorless fibers, and CoW primitives.

use ifa_runtime::*;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[test]
fn test_massive_parallel_fiber_pool() {
    let worker_count = 8;
    let scheduler = Arc::new(FiberScheduler::new(worker_count));
    assert_eq!(scheduler.worker_count(), worker_count);
    assert!(scheduler.is_running());

    let num_tasks: u64 = 2_000;
    let channel = Arc::new(Channel::with_capacity(64));

    // Spawn consumer FIRST so it actively drains the bounded channel
    let accumulator = Arc::new(AtomicU64::new(0));
    let acc_clone = Arc::clone(&accumulator);
    let chan_cons = Arc::clone(&channel);

    let consumer_fid = scheduler.spawn(move || {
        let mut total: u64 = 0;
        for _ in 0..num_tasks {
            total += chan_cons.recv();
        }
        acc_clone.store(total, Ordering::SeqCst);
    });

    let mut fiber_ids = Vec::with_capacity(num_tasks as usize);
    for i in 1..=num_tasks {
        let chan = Arc::clone(&channel);
        let sched = Arc::clone(&scheduler);
        let fid = scheduler.spawn(move || {
            if i % 10 == 0 {
                sched.yield_now();
            }
            let squared = i * i;
            chan.send(squared);
        });
        fiber_ids.push(fid);
    }

    // Wait for all producer fibers
    for fid in fiber_ids {
        let completed = scheduler.join_timeout(fid, Duration::from_secs(5));
        assert!(completed, "Producer fiber {:?} timed out", fid);
    }

    let consumer_completed = scheduler.join_timeout(consumer_fid, Duration::from_secs(5));
    assert!(consumer_completed, "Consumer fiber timed out");

    // Theoretical sum of squares: n*(n+1)*(2n+1)/6
    let expected_sum: u64 = num_tasks * (num_tasks + 1) * (2 * num_tasks + 1) / 6;
    let actual_sum = accumulator.load(Ordering::SeqCst);
    assert_eq!(actual_sum, expected_sum);

    scheduler.shutdown();
    assert!(!scheduler.is_running());
}

#[test]
fn test_extreme_bounded_channel_contention() {
    // Extreme backpressure: channel capacity of 1 element tested across OS threads
    let channel = Arc::new(Channel::with_capacity(1));
    let num_pairs = 40;
    let items_per_pair = 50;

    let received_count = Arc::new(AtomicUsize::new(0));
    let mut producer_handles = Vec::new();
    let mut consumer_handles = Vec::new();

    // Spawn consumers on dedicated concurrent threads
    for _ in 0..num_pairs {
        let chan = Arc::clone(&channel);
        let counter = Arc::clone(&received_count);
        let handle = thread::spawn(move || {
            for _ in 0..items_per_pair {
                let val = chan.recv();
                assert!(val > 0);
                counter.fetch_add(1, Ordering::SeqCst);
            }
        });
        consumer_handles.push(handle);
    }

    // Spawn producers on dedicated concurrent threads
    for p in 0..num_pairs {
        let chan = Arc::clone(&channel);
        let handle = thread::spawn(move || {
            for i in 1..=items_per_pair {
                chan.send((p * items_per_pair + i) as u64);
            }
        });
        producer_handles.push(handle);
    }

    // Verify all producers finish without starvation
    for h in producer_handles {
        h.join()
            .expect("Producer panicked under channel contention");
    }

    // Verify all consumers complete
    for h in consumer_handles {
        h.join()
            .expect("Consumer panicked under channel contention");
    }

    assert_eq!(
        received_count.load(Ordering::SeqCst),
        num_pairs * items_per_pair
    );

    // Verify channel edge-case functions when drained
    assert_eq!(channel.try_recv(), None);
    assert_eq!(channel.recv_timeout(Duration::from_millis(1)), None);
    assert!(channel.try_send(999).is_ok());
    assert_eq!(channel.try_send(1000), Err(1000));
    assert_eq!(channel.try_recv(), Some(999));
}

#[test]
fn test_concurrent_cow_isolation_and_atomic_separation() {
    // Shared immutable string baseline
    let original = IfaString::from_str("IFA_DETERMINISTIC_BASE_STRING_FOR_COW_TEST");
    let thread_count = 16;
    let iterations_per_thread = 50;

    let mut handles = Vec::with_capacity(thread_count);

    for t in 0..thread_count {
        let mut local_copy = original.clone();
        handles.push(thread::spawn(move || {
            for i in 0..iterations_per_thread {
                // Mutating will trigger thread-safe CoW cloning when ref_count > 1
                local_copy.push_str(&format!("_{:02}:{:02}", t, i));
            }
            // Verify final string consistency
            assert!(local_copy
                .as_str()
                .starts_with("IFA_DETERMINISTIC_BASE_STRING_FOR_COW_TEST"));
            assert!(local_copy.as_str().contains(&format!(
                "_{:02}:{:02}",
                t,
                iterations_per_thread - 1
            )));
            local_copy.len()
        }));
    }

    let mut lengths = Vec::new();
    for h in handles {
        let len = h
            .join()
            .expect("Worker thread panicked during CoW mutation");
        lengths.push(len);
    }

    // Original string must remain completely unchanged
    assert_eq!(
        original.as_str(),
        "IFA_DETERMINISTIC_BASE_STRING_FOR_COW_TEST"
    );
    assert_eq!(original.ref_count(), 1);

    // All spawned threads must have reached identical lengths
    let first_len = lengths[0];
    for l in lengths {
        assert_eq!(l, first_len);
    }
}

#[test]
fn test_concurrent_cow_list_modifications() {
    let mut initial_list = IfaList::new();
    for i in 0..100 {
        initial_list.push(i as u64);
    }
    assert_eq!(initial_list.len(), 100);

    let thread_count = 12;
    let mut handles = Vec::with_capacity(thread_count);

    for t in 0..thread_count {
        let mut list_clone = initial_list.clone();
        handles.push(thread::spawn(move || {
            // Each thread pushes unique items, triggering CoW buffer duplication
            for k in 0..50 {
                list_clone.push((t * 1000 + k) as u64);
            }
            assert_eq!(list_clone.len(), 150);
            assert_eq!(list_clone[0], 0);
            assert_eq!(list_clone[99], 99);
            assert_eq!(list_clone[100], (t * 1000) as u64);
            assert_eq!(list_clone[149], (t * 1000 + 49) as u64);
        }));
    }

    for h in handles {
        h.join().expect("Thread failed during IfaList CoW test");
    }

    // Master list remains untouched
    assert_eq!(initial_list.len(), 100);
    assert_eq!(initial_list[0], 0);
    assert_eq!(initial_list[99], 99);
}

#[test]
fn test_fiber_scheduler_interruption_and_rapid_shutdown() {
    let scheduler = FiberScheduler::new(4);

    // Enqueue 200 tasks that sleep or loop
    for _ in 0..200 {
        let _ = scheduler.spawn(|| {
            thread::sleep(Duration::from_millis(50));
        });
    }

    // Rapid shutdown while fibers are pending or running
    let start = std::time::Instant::now();
    scheduler.shutdown();
    let elapsed = start.elapsed();

    assert!(!scheduler.is_running());
    // Shutdown should join workers gracefully in under 1 second
    assert!(
        elapsed < Duration::from_secs(1),
        "Shutdown took too long: {:?}",
        elapsed
    );
}

#[test]
fn test_generational_allocator_multithread_contention() {
    let thread_count = 8;
    let ops_per_thread = 200;

    let mut handles = Vec::new();

    for _ in 0..thread_count {
        handles.push(thread::spawn(move || {
            for _ in 0..ops_per_thread {
                // 1. Allocate payload with 64-bit GenHeader
                let ptr = ifa_rt_gen_alloc(64, 8, 0);
                assert!(!ptr.is_null());

                unsafe {
                    // Fill payload with a pattern and verify integrity
                    std::ptr::write_bytes(ptr, 0xAB, 64);

                    let header = &*(ptr.sub(std::mem::size_of::<GenHeader>()) as *const GenHeader);
                    let remembered_gen = header.generation_counter;
                    assert!(header.is_active());

                    // 2. Perform generational 1-cycle check
                    ifa_rt_gen_check(ptr, remembered_gen);

                    for i in 0..64 {
                        assert_eq!(*ptr.add(i), 0xAB);
                    }

                    // 3. Free allocation safely under multithread contention
                    ifa_rt_gen_free(ptr);
                }
            }
        }));
    }

    for h in handles {
        h.join()
            .expect("Thread panicked during generational allocator contention");
    }
}

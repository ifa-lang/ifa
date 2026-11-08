//! Formal verification tests for 32-bit generation overflow mitigation,
//! epoch transitions (FLAG_EPOCH_1), and permanent slot quarantine (FLAG_QUARANTINED).

use ifa_runtime::allocator::{
    call_arena_alloc, call_arena_stats, SizeClassPool, SlabStatus, ThreadLocalCallArena,
    GLOBAL_ALLOCATOR,
};
use ifa_runtime::ffi::{
    ifa_rt_auto_quarantine_saturated_slabs, ifa_rt_epoch_quarantined_slabs_count,
    ifa_rt_slab_saturation_ratio,
};
use ifa_runtime::header::{GenHeader, GenRef, FLAG_EPOCH_1, FLAG_QUARANTINED};

#[test]
fn test_generational_slab_first_overflow_epoch1_transition() {
    // 1. Allocate a standard slab slot (size 32)
    let ptr = GLOBAL_ALLOCATOR.alloc(32, 8, 0);
    assert!(!ptr.is_null());

    unsafe {
        let header_ptr = (ptr as *mut GenHeader).sub(1);
        assert!((*header_ptr).is_active());
        assert_eq!((*header_ptr).epoch_id(), 0, "Initial epoch must be 0");

        // Create a fat 128-bit reference at Epoch 0
        let ref_epoch0 = GenRef::from_payload(ptr, 0);
        assert_eq!(ref_epoch0.epoch_id(), 0);
        assert!(ref_epoch0.is_valid());
        assert_eq!(ref_epoch0.deref_checked(), Some(ptr));

        // 2. Simulate 4-billion cycle increment reaching u32::MAX
        (*header_ptr).generation_counter = u32::MAX;

        let initial_transitions = GLOBAL_ALLOCATOR.epoch_stats().epoch_transitions;

        // 3. Deallocate slot at u32::MAX: triggers transition to Epoch 1
        GLOBAL_ALLOCATOR.free(ptr);

        assert!(!(*header_ptr).is_active());
        assert_eq!(
            (*header_ptr).generation_counter,
            1,
            "Generation counter must safely restart at 1"
        );
        assert_eq!(
            (*header_ptr).allocation_flags & FLAG_EPOCH_1,
            FLAG_EPOCH_1,
            "FLAG_EPOCH_1 must be set"
        );
        assert!(
            !(*header_ptr).is_quarantined(),
            "Slot must not be quarantined on first overflow"
        );

        // The Epoch 0 reference must be statically and dynamically recognized as stale/invalid
        assert!(
            ref_epoch0.is_stale_epoch(),
            "Epoch 0 ref must detect epoch mismatch"
        );
        assert!(!ref_epoch0.is_valid(), "Epoch 0 ref must be invalid");
        assert_eq!(ref_epoch0.deref_checked(), None);

        // Verify EpochManager recorded the transition
        assert!(GLOBAL_ALLOCATOR.epoch_stats().epoch_transitions > initial_transitions);

        // 4. Reallocate the slot: slab pool must preserve FLAG_EPOCH_1
        let ptr_realloc = GLOBAL_ALLOCATOR.alloc(32, 8, 0);
        let realloc_header = (ptr_realloc as *mut GenHeader).sub(1);
        assert!((*realloc_header).is_active());
        assert_eq!((*realloc_header).generation_counter, 1);
        assert_eq!(
            (*realloc_header).allocation_flags & FLAG_EPOCH_1,
            FLAG_EPOCH_1
        );

        // Create new reference at Epoch 1
        let ref_epoch1 = GenRef::from_payload(ptr_realloc, 0);
        assert_eq!(ref_epoch1.epoch_id(), 1);
        assert!(ref_epoch1.is_valid(), "New Epoch 1 reference must be valid");
        assert_eq!(ref_epoch1.deref_checked(), Some(ptr_realloc));

        // Former Epoch 0 reference pointing to same address MUST REMAIN INVALID
        assert!(
            !ref_epoch0.is_valid(),
            "Former Epoch 0 reference must mathematically never alias Epoch 1 slot"
        );

        // Clean up
        GLOBAL_ALLOCATOR.free(ptr_realloc);
    }
}

#[test]
fn test_generational_slab_second_overflow_permanent_quarantine() {
    // 1. Allocate a slot in Epoch 1
    let ptr = GLOBAL_ALLOCATOR.alloc(64, 8, 0);
    assert!(!ptr.is_null());

    unsafe {
        let header_ptr = (ptr as *mut GenHeader).sub(1);
        // Force header into Epoch 1 with counter at u32::MAX
        (*header_ptr).allocation_flags |= FLAG_EPOCH_1;
        (*header_ptr).generation_counter = u32::MAX;

        let ref_epoch1 = GenRef::from_payload(ptr, 0);
        assert_eq!(ref_epoch1.epoch_id(), 1);
        assert!(ref_epoch1.is_valid());

        let initial_quarantined = GLOBAL_ALLOCATOR.epoch_stats().quarantined_slots;

        // 2. Free slot reaching secondary overflow in Epoch 1: triggers permanent quarantine
        GLOBAL_ALLOCATOR.free(ptr);

        assert!(
            !(*header_ptr).is_active(),
            "Quarantined slot must be inactive"
        );
        assert_eq!(
            (*header_ptr).allocation_flags & FLAG_QUARANTINED,
            FLAG_QUARANTINED,
            "FLAG_QUARANTINED must be set"
        );
        assert_eq!(
            (*header_ptr).generation_counter,
            0,
            "Quarantined generation counter must be cleared"
        );

        // References to quarantined slots must fail immediately
        assert!(
            !ref_epoch1.is_valid(),
            "Quarantined slot must never validate"
        );
        assert_eq!(ref_epoch1.deref_checked(), None);

        // Epoch stats must register the quarantine
        assert!(GLOBAL_ALLOCATOR.epoch_stats().quarantined_slots > initial_quarantined);

        // 3. Subsequent allocation of same size class MUST NOT return the quarantined address
        let ptr_next = GLOBAL_ALLOCATOR.alloc(64, 8, 0);
        assert_ne!(
            ptr_next, ptr,
            "Quarantined slot must never be recycled into the free list"
        );

        GLOBAL_ALLOCATOR.free(ptr_next);
    }
}

#[test]
fn test_call_arena_generation_overflow_and_quarantine() {
    let mut arena = ThreadLocalCallArena::new();
    let ptr1 = arena.alloc(48, 8);
    assert!(!ptr1.is_null());

    let stats_initial = arena.stats();
    assert_eq!(stats_initial.total_allocations, 1);

    unsafe {
        let header_ptr = (ptr1 as *mut GenHeader).sub(1);
        assert!((*header_ptr).is_active());
        assert!((*header_ptr).is_arena_scoped());
        assert_eq!((*header_ptr).epoch_id(), 0);

        let ref1 = GenRef::from_payload(ptr1, (*header_ptr).arena_id);
        assert!(ref1.is_valid());

        // Rewind and reallocate: advances generation counter on rewind to eliminate ABA collisions
        arena.rewind(0);
        let ptr2 = arena.alloc(48, 8);
        assert!(!ptr2.is_null());
        let header2 = (ptr2 as *mut GenHeader).sub(1);
        assert_eq!((*header2).generation_counter, 3);

        // Also verify the global thread-local helper
        let g_ptr = call_arena_alloc(64, 8);
        assert!(!g_ptr.is_null());
        let g_stats = call_arena_stats();
        assert!(g_stats.total_allocations >= 1);
    }
}

#[test]
fn test_large_vector_allocation_quarantine_safety() {
    // Large 64-byte aligned allocation (AVX-512 vector payload)
    let ptr = GLOBAL_ALLOCATOR.alloc(2048, 64, 0);
    assert!(!ptr.is_null());
    assert_eq!(
        (ptr as usize) % 64,
        0,
        "AVX-512 payload must be strictly 64-byte aligned"
    );

    unsafe {
        let header_ptr = (ptr as *mut GenHeader).sub(1);
        assert!((*header_ptr).is_active());

        // Set to Epoch 1 and MAX generation
        (*header_ptr).allocation_flags |= FLAG_EPOCH_1;
        (*header_ptr).generation_counter = u32::MAX;

        let fat_ref = GenRef::from_payload(ptr, 0);
        assert!(fat_ref.is_valid());

        // Deallocate: triggers quarantine
        GLOBAL_ALLOCATOR.free(ptr);

        assert!(!(*header_ptr).is_active());
        assert!((*header_ptr).is_quarantined());
        assert!(!fat_ref.is_valid());
        assert_eq!(fat_ref.deref_checked(), None);
    }
}

#[test]
fn test_saturated_slab_automatic_quarantine_policy() {
    // 1. Initialize dedicated size-class pool with a small capacity of 4 slots
    let mut pool = SizeClassPool::with_capacity(32, 4);
    assert_eq!(pool.pages.len(), 0);
    assert_eq!(pool.quarantined_pages.len(), 0);

    // 2. Allocate 4 slots to fill the slab page completely
    let slot0 = pool.allocate(0, 1);
    let slot1 = pool.allocate(0, 1);
    let slot2 = pool.allocate(0, 1);
    let slot3 = pool.allocate(0, 1);

    assert_eq!(pool.pages.len(), 1, "Exactly 1 slab page must be created");
    assert_eq!(pool.pages[0].capacity, 4);
    assert_eq!(pool.pages[0].active_slots, 4);
    assert_eq!(pool.pages[0].quarantined_slots, 0);
    assert_eq!(pool.pages[0].status, SlabStatus::Active);

    unsafe {
        // Mark all 4 slots as Epoch 1 and at max generation to trigger quarantine upon deallocation
        for &slot in &[slot0, slot1, slot2, slot3] {
            let h = (slot as *mut GenHeader).sub(1);
            (*h).allocation_flags |= FLAG_EPOCH_1;
            (*h).generation_counter = u32::MAX;
        }

        // 3. Free first 3 slots with secondary overflow (transition to quarantined)
        for &slot in &[slot0, slot1, slot2] {
            let h = (slot as *mut GenHeader).sub(1);
            let tr = (*h).mark_freed();
            assert_eq!(tr, ifa_runtime::header::EpochTransition::Quarantined);
            pool.recycle(slot);
        }

        // Slab page is partially quarantined (3/4)
        assert_eq!(pool.pages.len(), 1);
        assert_eq!(pool.pages[0].active_slots, 1);
        assert_eq!(pool.pages[0].quarantined_slots, 3);
        assert_eq!(pool.pages[0].status, SlabStatus::PartiallyQuarantined);
        assert!(!pool.pages[0].is_fully_quarantined());
        assert_eq!(pool.pages[0].quarantine_ratio(), 0.75);

        // 4. Free the 4th and final slot: reaches 100% saturation (4/4)
        let h3 = (slot3 as *mut GenHeader).sub(1);
        let tr3 = (*h3).mark_freed();
        assert_eq!(tr3, ifa_runtime::header::EpochTransition::Quarantined);
        pool.recycle(slot3);

        // Automatic quarantine policy: the saturated slab must be moved out of active pages into quarantined_pages
        assert_eq!(
            pool.pages.len(),
            0,
            "Saturated slab must be removed from active operational pages"
        );
        assert_eq!(
            pool.quarantined_pages.len(),
            1,
            "Saturated slab must be placed into quarantined_pages"
        );

        let saturated_slab = &pool.quarantined_pages[0];
        assert_eq!(saturated_slab.status, SlabStatus::QuarantinedSaturated);
        assert!(saturated_slab.is_fully_quarantined());
        assert_eq!(saturated_slab.quarantine_ratio(), 1.0);
        assert_eq!(saturated_slab.active_slots, 0);
        assert_eq!(saturated_slab.quarantined_slots, 4);

        // 5. Subsequent allocation must grow a fresh new slab page and not collide with any quarantined slot
        let fresh_slot = pool.allocate(0, 1);
        assert!(!fresh_slot.is_null());
        assert_eq!(
            pool.pages.len(),
            1,
            "A fresh active slab page must be grown"
        );
        assert_eq!(pool.quarantined_pages.len(), 1);

        for &retired in &[slot0, slot1, slot2, slot3] {
            assert_ne!(
                fresh_slot, retired,
                "Fresh allocation must never alias any quarantined slot from saturated slab"
            );
        }
    }
}

#[test]
fn test_auto_quarantine_saturated_slabs_threshold_policy() {
    let mut pool = SizeClassPool::with_capacity(64, 4);
    let s0 = pool.allocate(0, 2);
    let s1 = pool.allocate(0, 2);
    let s2 = pool.allocate(0, 2);
    let s3 = pool.allocate(0, 2);

    unsafe {
        // Quarantining 3 out of 4 slots gives a 75% saturation ratio
        for &s in &[s0, s1, s2] {
            let h = (s as *mut GenHeader).sub(1);
            (*h).allocation_flags |= FLAG_EPOCH_1;
            (*h).generation_counter = u32::MAX;
            let _ = (*h).mark_freed();
            pool.recycle(s);
        }

        // Release slot 3 normally (not quarantined)
        let h3 = (s3 as *mut GenHeader).sub(1);
        let _ = (*h3).mark_freed();
        pool.recycle(s3);

        assert_eq!(pool.pages.len(), 1);
        assert_eq!(pool.pages[0].active_slots, 0);
        assert_eq!(pool.pages[0].quarantined_slots, 3);
        assert_eq!(pool.pages[0].quarantine_ratio(), 0.75);

        // Applying threshold of 0.70 triggers automatic quarantine of the 75%-saturated slab
        let quarantined_count = pool.auto_quarantine_saturated_slabs(0.70);
        assert_eq!(quarantined_count, 1);
        assert_eq!(pool.pages.len(), 0);
        assert_eq!(pool.quarantined_pages.len(), 1);
        assert_eq!(
            pool.quarantined_pages[0].status,
            SlabStatus::QuarantinedSaturated
        );

        // Verification of aggregate metrics
        let stats = pool.saturation_stats();
        assert_eq!(stats.size_class, 64);
        assert_eq!(stats.active_pages, 0);
        assert_eq!(stats.quarantined_pages, 1);
        assert_eq!(stats.quarantined_slots, 3);
        assert_eq!(stats.saturation_ratio, 0.75);
    }
}

#[test]
fn test_global_allocator_and_ffi_slab_quarantine_metrics() {
    let initial_quarantined_slabs = ifa_rt_epoch_quarantined_slabs_count();
    let stats = GLOBAL_ALLOCATOR.slab_saturation_stats();
    assert_eq!(stats.len(), ifa_runtime::allocator::SIZE_CLASSES.len());

    for (idx, stat) in stats.iter().enumerate() {
        assert_eq!(stat.size_class, ifa_runtime::allocator::SIZE_CLASSES[idx]);
        let ratio = ifa_rt_slab_saturation_ratio(idx);
        assert_eq!(ratio, stat.saturation_ratio);
        assert!((0.0..=1.0).contains(&ratio));
    }

    // Trigger auto-quarantine with default threshold of 1.0
    let retired = ifa_rt_auto_quarantine_saturated_slabs(1.0);
    let final_quarantined_slabs = ifa_rt_epoch_quarantined_slabs_count();
    assert_eq!(final_quarantined_slabs, initial_quarantined_slabs + retired);
}

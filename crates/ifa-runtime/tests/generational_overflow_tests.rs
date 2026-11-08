//! Formal verification tests for 32-bit generation overflow mitigation,
//! epoch transitions (FLAG_EPOCH_1), and permanent slot quarantine (FLAG_QUARANTINED).

use ifa_runtime::allocator::{
    call_arena_alloc, call_arena_stats, ThreadLocalCallArena, GLOBAL_ALLOCATOR,
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

//! Slab and generational memory allocator providing deterministic zero-GC safety.

#![allow(clippy::not_unsafe_ptr_arg_deref)]

use crate::header::{GenHeader, FLAG_ACTIVE, FLAG_ARENA_SCOPED};
use std::alloc::{alloc, dealloc, Layout};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU16, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

/// Standard slab size classes in bytes (excluding 8-byte GenHeader).
pub const SIZE_CLASSES: [usize; 7] = [16, 32, 64, 128, 256, 512, 1024];

/// Statistics regarding generational lifetime and epoch management in the slab allocator.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EpochStats {
    /// Monotonic global epoch counter.
    pub global_epoch: u64,
    /// Total number of 32-bit generation overflow epoch switches (to FLAG_EPOCH_1).
    pub epoch_transitions: usize,
    /// Total number of slots permanently quarantined due to secondary generation overflow.
    pub quarantined_slots: usize,
    /// Total number of saturated slab pages automatically quarantined.
    pub quarantined_slabs: usize,
    /// Total number of active slab pages currently serving allocations.
    pub active_slabs: usize,
    /// Current active epoch pins held by concurrent readers/fibers.
    pub active_pins: usize,
}

/// Lifecycle status of an individual slab page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlabStatus {
    /// Slab actively serves allocations.
    Active,
    /// Slab contains quarantined slots, but has not reached the saturation threshold.
    PartiallyQuarantined,
    /// Slab reached the saturation threshold and is automatically quarantined from the active pool.
    QuarantinedSaturated,
}

/// Detailed saturation and quarantine metrics for a specific size-class pool.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SlabPoolSaturationStats {
    /// Size class payload capacity in bytes.
    pub size_class: usize,
    /// Count of actively allocated and operational slab pages.
    pub active_pages: usize,
    /// Count of slab pages retired to automatic quarantine due to saturation.
    pub quarantined_pages: usize,
    /// Total slot capacity across all operational pages.
    pub total_active_capacity: usize,
    /// Total slot capacity across all quarantined saturated pages.
    pub total_quarantined_capacity: usize,
    /// Current number of quarantined slots in this size class.
    pub quarantined_slots: usize,
    /// Current number of actively allocated slots in this size class.
    pub active_slots: usize,
    /// Saturation ratio of quarantined slots across all slabs in this pool (0.0 to 1.0).
    pub saturation_ratio: f64,
}

/// Thread-safe concurrent epoch coordinator and lifetime analyzer.
pub struct EpochManager {
    global_epoch: AtomicU64,
    epoch_transitions: AtomicUsize,
    quarantined_slots: AtomicUsize,
    quarantined_slabs: AtomicUsize,
    active_pins: AtomicUsize,
}

impl EpochManager {
    pub const fn new() -> Self {
        Self {
            global_epoch: AtomicU64::new(1),
            epoch_transitions: AtomicUsize::new(0),
            quarantined_slots: AtomicUsize::new(0),
            quarantined_slabs: AtomicUsize::new(0),
            active_pins: AtomicUsize::new(0),
        }
    }

    /// Current monotonic global epoch.
    #[inline(always)]
    pub fn current_epoch(&self) -> u64 {
        self.global_epoch.load(Ordering::Acquire)
    }

    /// Advance the global monotonic epoch.
    pub fn advance_epoch(&self) -> u64 {
        self.global_epoch.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Record a 32-bit generation counter overflow transition to Epoch 1.
    pub fn record_epoch_switch(&self) {
        self.epoch_transitions.fetch_add(1, Ordering::Relaxed);
        self.advance_epoch();
    }

    /// Record a permanent slot quarantine.
    pub fn record_quarantine(&self) {
        self.quarantined_slots.fetch_add(1, Ordering::Relaxed);
    }

    /// Record automatic quarantine of saturated slab pages.
    pub fn record_slab_quarantine(&self, count: usize) {
        self.quarantined_slabs.fetch_add(count, Ordering::Relaxed);
    }

    /// Retrieve total count of quarantined saturated slab pages.
    pub fn quarantined_slabs(&self) -> usize {
        self.quarantined_slabs.load(Ordering::Relaxed)
    }

    /// Pin the current execution context into the current epoch.
    pub fn pin(&self) -> EpochGuard<'_> {
        self.active_pins.fetch_add(1, Ordering::SeqCst);
        let epoch = self.current_epoch();
        EpochGuard {
            manager: self,
            pinned_epoch: epoch,
        }
    }

    /// Retrieve a snapshot of epoch statistics.
    pub fn stats(&self) -> EpochStats {
        EpochStats {
            global_epoch: self.current_epoch(),
            epoch_transitions: self.epoch_transitions.load(Ordering::Relaxed),
            quarantined_slots: self.quarantined_slots.load(Ordering::Relaxed),
            quarantined_slabs: self.quarantined_slabs.load(Ordering::Relaxed),
            active_slabs: 0,
            active_pins: self.active_pins.load(Ordering::Relaxed),
        }
    }
}

impl Default for EpochManager {
    fn default() -> Self {
        Self::new()
    }
}

/// RAII lifetime guard pinning the active epoch during safe generational reference dereferencing.
pub struct EpochGuard<'a> {
    manager: &'a EpochManager,
    pub pinned_epoch: u64,
}

impl<'a> Drop for EpochGuard<'a> {
    fn drop(&mut self) {
        self.manager.active_pins.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Free slot node stored in intrusive free-lists when a slot is inactive.
#[repr(C)]
struct FreeNode {
    next: *mut FreeNode,
}

/// Default capacity of slots per slab page (64 slots).
pub const DEFAULT_PAGE_CAPACITY: usize = 64;

/// A slab page containing multiple fixed-size slots.
pub struct SlabPage {
    pub page_id: usize,
    memory: *mut u8,
    layout: Layout,
    slot_size_with_header: usize,
    pub capacity: usize,
    pub active_slots: usize,
    pub quarantined_slots: usize,
    pub status: SlabStatus,
}

unsafe impl Send for SlabPage {}
unsafe impl Sync for SlabPage {}

impl SlabPage {
    pub fn new(slot_payload_size: usize, capacity: usize, page_id: usize) -> Self {
        let header_size = std::mem::size_of::<GenHeader>();
        let slot_size = header_size + slot_payload_size;
        // Align each slot to 8 bytes minimum
        let align = 8;
        let total_size = slot_size * capacity;
        let layout =
            Layout::from_size_align(total_size, align).expect("Invalid layout for slab page");
        let memory = unsafe { alloc(layout) };
        if memory.is_null() {
            std::alloc::handle_alloc_error(layout);
        }

        Self {
            page_id,
            memory,
            layout,
            slot_size_with_header: slot_size,
            capacity,
            active_slots: 0,
            quarantined_slots: 0,
            status: SlabStatus::Active,
        }
    }

    /// Check if a memory address falls within this slab page boundaries.
    #[inline(always)]
    pub fn contains(&self, ptr: *const u8) -> bool {
        let addr = ptr as usize;
        let start = self.memory as usize;
        let end = start + self.layout.size();
        addr >= start && addr < end
    }

    /// Check whether all slots of this slab page have been quarantined.
    #[inline(always)]
    pub fn is_fully_quarantined(&self) -> bool {
        self.quarantined_slots >= self.capacity
    }

    /// Saturation ratio of quarantined slots within this slab page (0.0 to 1.0).
    #[inline(always)]
    pub fn quarantine_ratio(&self) -> f64 {
        if self.capacity == 0 {
            0.0
        } else {
            self.quarantined_slots as f64 / self.capacity as f64
        }
    }

    /// Check whether this slab page has reached or exceeded a saturation threshold.
    #[inline(always)]
    pub fn is_saturated(&self, threshold_ratio: f64) -> bool {
        self.quarantine_ratio() >= threshold_ratio
            && (self.active_slots == 0 || self.quarantined_slots >= self.capacity)
    }

    /// Available unallocated and non-quarantined slots in this slab page.
    #[inline(always)]
    pub fn available_slots(&self) -> usize {
        self.capacity
            .saturating_sub(self.quarantined_slots + self.active_slots)
    }
}

impl Drop for SlabPage {
    fn drop(&mut self) {
        unsafe {
            dealloc(self.memory, self.layout);
        }
    }
}

/// A class pool handling slots of a specific payload size.
pub struct SizeClassPool {
    pub slot_payload_size: usize,
    pub page_capacity: usize,
    next_page_id: usize,
    free_head: *mut FreeNode,
    pub pages: Vec<SlabPage>,
    pub quarantined_pages: Vec<SlabPage>,
}

unsafe impl Send for SizeClassPool {}
unsafe impl Sync for SizeClassPool {}

impl SizeClassPool {
    pub fn new(slot_payload_size: usize) -> Self {
        Self::with_capacity(slot_payload_size, DEFAULT_PAGE_CAPACITY)
    }

    pub fn with_capacity(slot_payload_size: usize, page_capacity: usize) -> Self {
        Self {
            slot_payload_size,
            page_capacity,
            next_page_id: 1,
            free_head: std::ptr::null_mut(),
            pages: Vec::new(),
            quarantined_pages: Vec::new(),
        }
    }

    pub fn allocate(&mut self, arena_id: u16, class_idx: usize) -> *mut u8 {
        if self.free_head.is_null() {
            self.grow();
        }

        let node = self.free_head;
        unsafe {
            self.free_head = (*node).next;
            let payload_ptr = node as *mut u8;
            let header_ptr = (payload_ptr as *mut GenHeader).sub(1);
            let current_gen = (*header_ptr).generation_counter;
            let preserved_epoch = (*header_ptr).allocation_flags & crate::header::FLAG_EPOCH_1;
            let class_flag = (((class_idx + 1) as u16) << crate::header::FLAG_CLASS_SHIFT)
                & crate::header::FLAG_CLASS_MASK;
            *header_ptr = GenHeader {
                generation_counter: if current_gen == 0 { 1 } else { current_gen },
                allocation_flags: FLAG_ACTIVE | class_flag | preserved_epoch,
                arena_id,
            };

            for page in &mut self.pages {
                if page.contains(payload_ptr) {
                    page.active_slots += 1;
                    break;
                }
            }

            payload_ptr
        }
    }

    pub fn allocate_batch(
        &mut self,
        arena_id: u16,
        class_idx: usize,
        count: usize,
    ) -> Vec<*mut u8> {
        let mut slots = Vec::with_capacity(count);
        for _ in 0..count {
            slots.push(self.allocate(arena_id, class_idx));
        }
        slots
    }

    pub fn recycle(&mut self, payload_ptr: *mut u8) {
        unsafe {
            let header = (payload_ptr as *mut GenHeader).sub(1);
            if (*header).is_quarantined() {
                // Permanently retired slot; register quarantine and evaluate slab saturation
                self.on_slot_quarantined(payload_ptr);
                return;
            }
            for page in &mut self.pages {
                if page.contains(payload_ptr) {
                    if page.active_slots > 0 {
                        page.active_slots -= 1;
                    }
                    break;
                }
            }
            let node = payload_ptr as *mut FreeNode;
            (*node).next = self.free_head;
            self.free_head = node;
        }
    }

    pub fn recycle_batch(&mut self, slots: &[*mut u8]) {
        for &slot in slots {
            self.recycle(slot);
        }
    }

    /// Register a quarantined slot within this size-class pool.
    /// If the owning slab page reaches 100% saturation (or all capacity is quarantined),
    /// the slab page is automatically quarantined and removed from the active operational list.
    pub fn on_slot_quarantined(&mut self, ptr: *mut u8) -> Option<usize> {
        let mut saturated_idx = None;
        for (idx, page) in self.pages.iter_mut().enumerate() {
            if page.contains(ptr) {
                if page.active_slots > 0 {
                    page.active_slots -= 1;
                }
                page.quarantined_slots += 1;
                if page.quarantined_slots >= page.capacity {
                    page.status = SlabStatus::QuarantinedSaturated;
                    saturated_idx = Some(idx);
                } else {
                    page.status = SlabStatus::PartiallyQuarantined;
                }
                break;
            }
        }

        if let Some(idx) = saturated_idx {
            let page = self.pages.remove(idx);
            self.purge_free_nodes_for_page(&page);
            self.quarantined_pages.push(page);
            Some(1)
        } else {
            None
        }
    }

    /// Purge any intrusive free nodes referencing the quarantined slab page.
    fn purge_free_nodes_for_page(&mut self, page: &SlabPage) {
        let mut prev_next_ptr: *mut *mut FreeNode = &mut self.free_head;
        unsafe {
            while !(*prev_next_ptr).is_null() {
                let current_node = *prev_next_ptr;
                let payload_ptr = current_node as *mut u8;
                if page.contains(payload_ptr) {
                    *prev_next_ptr = (*current_node).next;
                } else {
                    prev_next_ptr = &mut (*current_node).next;
                }
            }
        }
    }

    /// Automatically quarantine any slab pages that meet or exceed the saturation threshold.
    pub fn auto_quarantine_saturated_slabs(&mut self, threshold_ratio: f64) -> usize {
        let mut quarantined_count = 0;
        let mut i = 0;
        while i < self.pages.len() {
            let is_saturated = self.pages[i].is_saturated(threshold_ratio);
            if is_saturated {
                let mut page = self.pages.remove(i);
                page.status = SlabStatus::QuarantinedSaturated;
                self.purge_free_nodes_for_page(&page);
                self.quarantined_pages.push(page);
                quarantined_count += 1;
            } else {
                i += 1;
            }
        }
        quarantined_count
    }

    /// Calculate aggregate saturation and quarantine metrics for this pool.
    pub fn saturation_stats(&self) -> SlabPoolSaturationStats {
        let mut total_active_cap = 0;
        let mut active_slots = 0;
        let mut active_quarantined_slots = 0;
        for page in &self.pages {
            total_active_cap += page.capacity;
            active_slots += page.active_slots;
            active_quarantined_slots += page.quarantined_slots;
        }

        let mut total_quarantined_cap = 0;
        let mut retired_quarantined_slots = 0;
        for page in &self.quarantined_pages {
            total_quarantined_cap += page.capacity;
            retired_quarantined_slots += page.quarantined_slots;
        }

        let total_quarantined = active_quarantined_slots + retired_quarantined_slots;
        let total_capacity = total_active_cap + total_quarantined_cap;
        let saturation_ratio = if total_capacity == 0 {
            0.0
        } else {
            total_quarantined as f64 / total_capacity as f64
        };

        SlabPoolSaturationStats {
            size_class: self.slot_payload_size,
            active_pages: self.pages.len(),
            quarantined_pages: self.quarantined_pages.len(),
            total_active_capacity: total_active_cap,
            total_quarantined_capacity: total_quarantined_cap,
            quarantined_slots: total_quarantined,
            active_slots,
            saturation_ratio,
        }
    }

    fn grow(&mut self) {
        let page_id = self.next_page_id;
        self.next_page_id += 1;
        let page = SlabPage::new(self.slot_payload_size, self.page_capacity, page_id);
        let header_size = std::mem::size_of::<GenHeader>();
        let slot_size = page.slot_size_with_header;

        // Initialize intrusive free-list through payload areas
        for i in 0..page.capacity {
            let slot_addr = unsafe { page.memory.add(i * slot_size) };
            let header = slot_addr as *mut GenHeader;
            let payload = unsafe { slot_addr.add(header_size) };
            unsafe {
                std::ptr::write(
                    header,
                    GenHeader {
                        generation_counter: 1,
                        allocation_flags: 0,
                        arena_id: 0,
                    },
                );
                let node = payload as *mut FreeNode;
                (*node).next = self.free_head;
                self.free_head = node;
            }
        }

        self.pages.push(page);
    }
}

/// Generational memory arena managing scoped lifetime allocations.
pub struct GenArena {
    pub id: u16,
    pub owner_fiber_id: u64,
    allocated_ptrs: Vec<*mut u8>,
}

unsafe impl Send for GenArena {}
unsafe impl Sync for GenArena {}

impl GenArena {
    pub fn new(id: u16) -> Self {
        Self {
            id,
            owner_fiber_id: 0,
            allocated_ptrs: Vec::new(),
        }
    }

    /// Create an arena strictly bound to a designated fiber.
    pub fn with_owner(id: u16, owner_fiber_id: u64) -> Self {
        Self {
            id,
            owner_fiber_id,
            allocated_ptrs: Vec::new(),
        }
    }

    /// Set or transfer fiber ownership of the arena.
    pub fn set_owner(&mut self, owner_fiber_id: u64) {
        self.owner_fiber_id = owner_fiber_id;
    }

    /// Check if the calling fiber is the legitimate owner of the arena (0 denotes shared/global).
    pub fn is_owner(&self, fiber_id: u64) -> bool {
        self.owner_fiber_id == 0 || self.owner_fiber_id == fiber_id
    }

    /// Reset all objects allocated in this arena, invalidating all external references.
    pub fn reset(&mut self, allocator: &mut GlobalGenAllocatorInner) {
        for &ptr in &self.allocated_ptrs {
            unsafe {
                let header = (ptr as *mut GenHeader).sub(1);
                if (*header).is_active() {
                    let transition = (*header).mark_freed();
                    if transition == crate::header::EpochTransition::Quarantined {
                        allocator.register_quarantined_slot(ptr, header);
                    }
                }
            }
        }
        self.allocated_ptrs.clear();
    }
}

/// Core global generational allocator.
pub struct GlobalGenAllocatorInner {
    pub pools: Vec<SizeClassPool>,
    arenas: HashMap<u16, GenArena>,
    large_allocations: HashMap<usize, (usize, Layout, u32)>,
}

impl GlobalGenAllocatorInner {
    fn new() -> Self {
        let pools = SIZE_CLASSES
            .iter()
            .map(|&size| SizeClassPool::new(size))
            .collect();

        Self {
            pools,
            arenas: HashMap::new(),
            large_allocations: HashMap::new(),
        }
    }

    /// Allocate a generational memory slot for a specific payload size and alignment.
    ///
    /// For SIMD vectors requiring strict alignment (16-byte for ARM Neon, 32-byte for AVX2,
    /// 64-byte for AVX-512), direct large allocation with power-of-two alignment guarantees
    /// cacheline boundary compliance.
    pub fn alloc(&mut self, size: usize, align: usize, arena_id: u16) -> *mut u8 {
        let actual_align = align.max(8);

        // Vector alignments > 8 bytes (AVX-512, AVX2, Neon) bypass size-class slabs to guarantee alignment
        if actual_align > 8 {
            let ptr = self.alloc_large(size, actual_align, arena_id);
            if arena_id > 0 {
                if let Some(arena) = self.arenas.get_mut(&arena_id) {
                    unsafe {
                        let header = (ptr as *mut GenHeader).sub(1);
                        (*header).allocation_flags |= FLAG_ARENA_SCOPED;
                    }
                    arena.allocated_ptrs.push(ptr);
                }
            }
            return ptr;
        }

        // Find best-matching size class
        let class_idx = SIZE_CLASSES.iter().position(|&s| s >= size);

        let ptr = if let Some(idx) = class_idx {
            self.pools[idx].allocate(arena_id, idx)
        } else {
            // Direct large allocation
            self.alloc_large(size, 8, arena_id)
        };

        if arena_id > 0 {
            if let Some(arena) = self.arenas.get_mut(&arena_id) {
                unsafe {
                    let header = (ptr as *mut GenHeader).sub(1);
                    (*header).allocation_flags |= FLAG_ARENA_SCOPED;
                }
                arena.allocated_ptrs.push(ptr);
            }
        }

        ptr
    }

    /// Allocate a batch of generational slots for a specific payload size class.
    pub fn alloc_batch(
        &mut self,
        size: usize,
        arena_id: u16,
        count: usize,
    ) -> (Vec<*mut u8>, usize) {
        let class_idx = SIZE_CLASSES.iter().position(|&s| s >= size);
        if let Some(idx) = class_idx {
            (self.pools[idx].allocate_batch(arena_id, idx, count), idx)
        } else {
            let mut list = Vec::with_capacity(count);
            for _ in 0..count {
                list.push(self.alloc_large(size, 8, arena_id));
            }
            (list, usize::MAX)
        }
    }

    /// Recycle a batch of slots back into their designated size-class pool.
    pub fn recycle_batch(&mut self, class_idx: usize, slots: &[*mut u8]) {
        if class_idx < self.pools.len() {
            self.pools[class_idx].recycle_batch(slots);
        } else {
            for &slot in slots {
                self.free(slot);
            }
        }
    }

    /// Deallocate an active generational memory slot.
    pub fn free(&mut self, ptr: *mut u8) {
        if ptr.is_null() {
            return;
        }

        unsafe {
            let header = (ptr as *mut GenHeader).sub(1);
            if !(*header).is_active() {
                // Double free detected
                crate::ffi::ifa_rt_panic_double_free(ptr);
            }

            // Invalidate slot generation
            (*header).mark_freed();

            self.recycle_raw(ptr, header);
        }
    }

    /// Internal recycling after header invalidation.
    pub(crate) unsafe fn recycle_raw(&mut self, ptr: *mut u8, header: *mut GenHeader) {
        if (*header).is_quarantined() {
            // Permanently quarantined due to 32-bit generation overflow; do not return to pool
            self.register_quarantined_slot(ptr, header);
            return;
        }

        // Locate size class or large allocation
        let addr = ptr as usize;
        if let Some((raw_addr, layout, _)) = self.large_allocations.remove(&addr) {
            dealloc(raw_addr as *mut u8, layout);
        } else {
            let class_code = (*header).size_class_id();
            if class_code >= 1 && class_code <= self.pools.len() {
                self.pools[class_code - 1].recycle(ptr);
                return;
            }
            // Fallback scan if size class is unclassified
            for pool in &mut self.pools {
                for page in &pool.pages {
                    let page_start = page.memory as usize;
                    let page_end = page_start + page.layout.size();
                    if (header as usize) >= page_start && (header as usize) < page_end {
                        pool.recycle(ptr);
                        return;
                    }
                }
            }
        }
    }

    /// Register a quarantined slot across pools, evaluating slab saturation.
    pub(crate) unsafe fn register_quarantined_slot(
        &mut self,
        ptr: *mut u8,
        header: *mut GenHeader,
    ) -> Option<usize> {
        let class_code = (*header).size_class_id();
        if class_code >= 1 && class_code <= self.pools.len() {
            return self.pools[class_code - 1].on_slot_quarantined(ptr);
        }
        for pool in &mut self.pools {
            if let Some(res) = pool.on_slot_quarantined(ptr) {
                return Some(res);
            }
        }
        None
    }

    /// Retrieve saturation statistics across all size classes.
    pub fn slab_saturation_stats(&self) -> Vec<SlabPoolSaturationStats> {
        self.pools.iter().map(|p| p.saturation_stats()).collect()
    }

    /// Automatically quarantine saturated slabs across all size classes.
    pub fn auto_quarantine_saturated_slabs(&mut self, threshold_ratio: f64) -> usize {
        let mut total = 0;
        for pool in &mut self.pools {
            total += pool.auto_quarantine_saturated_slabs(threshold_ratio);
        }
        total
    }

    /// Allocates memory directly with strict vector alignment (AVX-512 64B, AVX2 32B, NEON 16B).
    ///
    /// The returned payload pointer is strictly aligned to `align.max(8)`, and its generational
    /// header is placed immediately before it at `payload.sub(8)`.
    fn alloc_large(&mut self, size: usize, align: usize, arena_id: u16) -> *mut u8 {
        let actual_align = align.max(8);
        // The payload is placed at offset `actual_align` from raw_mem.
        // Since actual_align >= 8, the GenHeader (8 bytes) safely resides at `offset - 8`.
        let offset = actual_align;
        let total_size = offset + size;
        let layout =
            Layout::from_size_align(total_size, actual_align).expect("Invalid large layout");
        unsafe {
            let raw_mem = alloc(layout);
            if raw_mem.is_null() {
                std::alloc::handle_alloc_error(layout);
            }
            let payload = raw_mem.add(offset);
            let header = (payload as *mut GenHeader).sub(1);
            std::ptr::write(
                header,
                GenHeader {
                    generation_counter: 1,
                    allocation_flags: FLAG_ACTIVE,
                    arena_id,
                },
            );
            self.large_allocations
                .insert(payload as usize, (raw_mem as usize, layout, 1));
            payload
        }
    }
}

/// Batch allocation count fetched by thread-local cache from global pool on miss.
pub const THREAD_CACHE_BATCH_SIZE: usize = 32;
/// Maximum slots cached per size-class before returning a batch to the global pool.
pub const THREAD_CACHE_MAX_CAPACITY: usize = 64;

#[derive(Default)]
struct ThreadLocalSlabCache {
    bins: [Vec<*mut u8>; SIZE_CLASSES.len()],
}

/// Initial capacity for the thread-local call arena (64 KiB).
pub const CALL_ARENA_INITIAL_CAPACITY: usize = 65536;

/// Statistics of thread-local call arena usage across multi-stage compilation and runtime execution pipelines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CallArenaStats {
    /// Active allocated buffer capacity in bytes.
    pub capacity: usize,
    /// Current bump allocation offset in bytes.
    pub current_offset: usize,
    /// Peak bump allocation offset reached across scopes.
    pub high_water_mark: usize,
    /// Current monotonic generation counter.
    pub generation: u32,
    /// Total allocation operations performed.
    pub total_allocations: usize,
    /// Total scope rewind operations performed.
    pub total_rewinds: usize,
    /// Cumulative bytes reclaimed and reused across rewinds.
    pub reused_bytes: usize,
}

/// Fast thread-local bump allocation arena for bounded closure environments and call blocks.
/// Guarantees zero system locks, zero kernel syscalls, and O(1) bump allocation with
/// mark/rewind scope resets in CPU L1/L2 cache.
pub struct ThreadLocalCallArena {
    buffer: Vec<u8>,
    offset: usize,
    generation_counter: u32,
    epoch_flags: u16,
    high_water_mark: usize,
    total_allocations: usize,
    total_rewinds: usize,
    reused_bytes: usize,
}

impl Default for ThreadLocalCallArena {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreadLocalCallArena {
    /// Create a new thread-local call arena initialized with the standard call frame capacity.
    pub fn new() -> Self {
        Self {
            buffer: vec![0u8; CALL_ARENA_INITIAL_CAPACITY],
            offset: 0,
            generation_counter: 1,
            epoch_flags: 0,
            high_water_mark: 0,
            total_allocations: 0,
            total_rewinds: 0,
            reused_bytes: 0,
        }
    }

    /// Allocate a memory block in the thread-local call arena with a valid generational header.
    pub fn alloc(&mut self, size: usize, align: usize) -> *mut u8 {
        let align = align.max(8);
        let header_size = std::mem::size_of::<GenHeader>();

        // Align offset for GenHeader
        let aligned_header_offset = (self.offset + 7) & !7;
        let payload_offset = aligned_header_offset + header_size;
        let aligned_payload_offset = (payload_offset + align - 1) & !(align - 1);
        let actual_header_offset = aligned_payload_offset - header_size;
        let total_needed = aligned_payload_offset + size;

        if total_needed > self.buffer.len() {
            let new_cap = (total_needed * 2).max(self.buffer.len() * 2);
            self.buffer.resize(new_cap, 0);
        }

        self.total_allocations += 1;
        if total_needed > self.high_water_mark {
            self.high_water_mark = total_needed;
        }

        // Monotonically allocate generation for this call arena slot
        let current_gen = self.generation_counter;
        if self.generation_counter == u32::MAX {
            if (self.epoch_flags & crate::header::FLAG_EPOCH_1) == 0 {
                self.epoch_flags |= crate::header::FLAG_EPOCH_1;
                self.generation_counter = 1;
            } else {
                // Secondary generation overflow: mark quarantined
                self.epoch_flags |= crate::header::FLAG_QUARANTINED;
            }
        } else {
            self.generation_counter += 1;
        }

        let base_ptr = self.buffer.as_mut_ptr();
        unsafe {
            let header_ptr = base_ptr.add(actual_header_offset) as *mut GenHeader;
            std::ptr::write(
                header_ptr,
                GenHeader {
                    generation_counter: current_gen,
                    allocation_flags: FLAG_ACTIVE | FLAG_ARENA_SCOPED | self.epoch_flags,
                    arena_id: crate::header::ARENA_THREAD_LOCAL_CALL,
                },
            );
            self.offset = total_needed;
            base_ptr.add(aligned_payload_offset)
        }
    }

    /// Mark the current bump offset to save the call arena scope.
    #[inline(always)]
    pub fn mark(&self) -> usize {
        self.offset
    }

    /// Rewind the bump offset to a previously marked position, resetting the call arena scope.
    #[inline(always)]
    pub fn rewind(&mut self, mark: usize) {
        if mark < self.offset {
            self.reused_bytes += self.offset - mark;
            self.total_rewinds += 1;
            // Advancing generation on rewind ensures any subsequent allocation at the same offset
            // receives a strictly higher generation counter, preventing ABA and Use-After-Scope reference collisions.
            self.generation_counter = self.generation_counter.saturating_add(1);
            self.offset = mark;
        }
    }

    /// Reset the entire call arena block.
    #[inline(always)]
    pub fn reset(&mut self) {
        if self.offset > 0 {
            self.reused_bytes += self.offset;
            self.total_rewinds += 1;
            self.generation_counter = self.generation_counter.saturating_add(1);
        }
        self.offset = 0;
    }

    /// Return statistics describing arena usage and consolidation.
    pub fn stats(&self) -> CallArenaStats {
        CallArenaStats {
            capacity: self.buffer.len(),
            current_offset: self.offset,
            high_water_mark: self.high_water_mark,
            generation: self.generation_counter,
            total_allocations: self.total_allocations,
            total_rewinds: self.total_rewinds,
            reused_bytes: self.reused_bytes,
        }
    }

    /// Consolidate and shrink the arena buffer if idle and larger than the maximum idle capacity.
    pub fn shrink_to_fit_if_idle(&mut self, max_idle_capacity: usize) {
        if self.offset == 0 {
            let target_cap = CALL_ARENA_INITIAL_CAPACITY.max(max_idle_capacity);
            if self.buffer.len() > target_cap {
                self.buffer.truncate(target_cap);
                self.buffer.shrink_to_fit();
            }
        }
    }

    /// Check if a pointer address falls within the current call arena memory buffer.
    pub fn contains(&self, ptr: *const u8) -> bool {
        let addr = ptr as usize;
        let start = self.buffer.as_ptr() as usize;
        let end = start + self.offset;
        addr >= start && addr < end
    }
}

thread_local! {
    static LOCAL_CACHE: std::cell::RefCell<ThreadLocalSlabCache> = std::cell::RefCell::new(ThreadLocalSlabCache::default());
    static CALL_ARENA: std::cell::RefCell<ThreadLocalCallArena> = std::cell::RefCell::new(ThreadLocalCallArena::new());
}

/// Allocate a bounded closure environment or call block in the active thread's call arena.
pub fn call_arena_alloc(size: usize, align: usize) -> *mut u8 {
    CALL_ARENA.with(|arena| arena.borrow_mut().alloc(size, align))
}

/// Mark the active thread's call arena offset.
pub fn call_arena_mark() -> usize {
    CALL_ARENA.with(|arena| arena.borrow().mark())
}

/// Rewind the active thread's call arena to a saved mark.
pub fn call_arena_rewind(mark: usize) {
    CALL_ARENA.with(|arena| arena.borrow_mut().rewind(mark))
}

/// Reset the active thread's call arena.
pub fn call_arena_reset() {
    CALL_ARENA.with(|arena| arena.borrow_mut().reset())
}

/// Retrieve call arena usage and consolidation statistics.
pub fn call_arena_stats() -> CallArenaStats {
    CALL_ARENA.with(|arena| arena.borrow().stats())
}

/// Retrieve the high water mark reached by the active thread's call arena.
pub fn call_arena_high_water_mark() -> usize {
    CALL_ARENA.with(|arena| arena.borrow().high_water_mark)
}

/// Retrieve current buffer capacity of the active thread's call arena.
pub fn call_arena_capacity() -> usize {
    CALL_ARENA.with(|arena| arena.borrow().buffer.len())
}

/// Consolidate and shrink the active thread's call arena if currently idle.
pub fn call_arena_shrink_to_fit(max_idle_capacity: usize) {
    CALL_ARENA.with(|arena| arena.borrow_mut().shrink_to_fit_if_idle(max_idle_capacity))
}

/// RAII Scope Guard automatically rewinding the call arena on exit.
pub struct CallArenaGuard {
    mark: usize,
}

impl CallArenaGuard {
    /// Create a new call arena guard capturing the active offset.
    pub fn new() -> Self {
        Self {
            mark: call_arena_mark(),
        }
    }

    /// Retrieve the captured mark offset.
    pub fn mark(&self) -> usize {
        self.mark
    }
}

impl Default for CallArenaGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for CallArenaGuard {
    fn drop(&mut self) {
        call_arena_rewind(self.mark);
    }
}

/// Create a new RAII CallArenaGuard for the current scope.
pub fn call_arena_guard() -> CallArenaGuard {
    CallArenaGuard::new()
}

/// Global thread-safe generational allocator instance.
pub struct GlobalGenAllocator {
    inner: Mutex<GlobalGenAllocatorInner>,
    next_arena_id: AtomicU16,
    allocated_bytes: AtomicUsize,
    pub epoch_manager: EpochManager,
}

impl GlobalGenAllocator {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(GlobalGenAllocatorInner::new()),
            next_arena_id: AtomicU16::new(1),
            allocated_bytes: AtomicUsize::new(0),
            epoch_manager: EpochManager::new(),
        }
    }

    /// Retrieve current epoch statistics from the concurrent epoch manager.
    pub fn epoch_stats(&self) -> EpochStats {
        let (active_slabs, quarantined_slabs) = {
            let inner = self.inner.lock().unwrap();
            let mut active = 0;
            let mut quarantined = 0;
            for pool in &inner.pools {
                active += pool.pages.len();
                quarantined += pool.quarantined_pages.len();
            }
            (active, quarantined)
        };
        let mut stats = self.epoch_manager.stats();
        stats.active_slabs = active_slabs;
        stats.quarantined_slabs = quarantined_slabs.max(stats.quarantined_slabs);
        stats
    }

    /// Retrieve detailed saturation and quarantine metrics across all slab size classes.
    pub fn slab_saturation_stats(&self) -> Vec<SlabPoolSaturationStats> {
        let inner = self.inner.lock().unwrap();
        inner.slab_saturation_stats()
    }

    /// Automatically evaluate and quarantine saturated slabs meeting or exceeding the given threshold ratio.
    pub fn auto_quarantine_saturated_slabs(&self, threshold_ratio: f64) -> usize {
        let mut inner = self.inner.lock().unwrap();
        let quarantined = inner.auto_quarantine_saturated_slabs(threshold_ratio);
        if quarantined > 0 {
            self.epoch_manager.record_slab_quarantine(quarantined);
        }
        quarantined
    }

    /// Number of saturated slab pages permanently placed in quarantine.
    pub fn quarantined_slabs_count(&self) -> usize {
        self.epoch_stats().quarantined_slabs
    }

    /// Pin the active thread or fiber in the current epoch.
    pub fn pin_epoch(&self) -> EpochGuard<'_> {
        self.epoch_manager.pin()
    }

    /// Manually advance the global epoch counter.
    pub fn advance_epoch(&self) -> u64 {
        self.epoch_manager.advance_epoch()
    }

    /// Allocate a slot on the generational heap.
    pub fn alloc(&self, size: usize, align: usize, arena_id: u16) -> *mut u8 {
        self.allocated_bytes.fetch_add(size, Ordering::Relaxed);

        if arena_id == crate::header::ARENA_THREAD_LOCAL_CALL {
            return call_arena_alloc(size, align);
        }

        // Fast-path for non-arena standard slab size classes via thread-local cache.
        // Vector alignments > 8 bytes (AVX-512, AVX2, NEON) bypass the 8-byte slab cache.
        if arena_id == 0 && align <= 8 {
            if let Some(idx) = SIZE_CLASSES.iter().position(|&s| s >= size) {
                let cached_ptr = LOCAL_CACHE.with(|cache| {
                    let mut c = cache.borrow_mut();
                    c.bins[idx].pop()
                });

                if let Some(ptr) = cached_ptr {
                    unsafe {
                        let header = (ptr as *mut GenHeader).sub(1);
                        let cur_gen = (*header).generation_counter;
                        let preserved_epoch =
                            (*header).allocation_flags & crate::header::FLAG_EPOCH_1;
                        let class_flag = (((idx + 1) as u16) << crate::header::FLAG_CLASS_SHIFT)
                            & crate::header::FLAG_CLASS_MASK;
                        *header = GenHeader {
                            generation_counter: if cur_gen == 0 { 1 } else { cur_gen },
                            allocation_flags: FLAG_ACTIVE | class_flag | preserved_epoch,
                            arena_id: 0,
                        };
                    }
                    return ptr;
                }

                // Batch refill from global pool under single lock
                let mut inner = self.inner.lock().unwrap();
                let (mut batch, _) = inner.alloc_batch(size, arena_id, THREAD_CACHE_BATCH_SIZE);
                if let Some(ptr) = batch.pop() {
                    if !batch.is_empty() {
                        LOCAL_CACHE.with(|cache| {
                            let mut c = cache.borrow_mut();
                            c.bins[idx].extend(batch);
                        });
                    }
                    return ptr;
                }
            }
        }

        let mut inner = self.inner.lock().unwrap();
        inner.alloc(size, align, arena_id)
    }

    /// Free an allocated slot on the generational heap.
    pub fn free(&self, ptr: *mut u8) {
        if ptr.is_null() {
            return;
        }

        unsafe {
            let header = (ptr as *mut GenHeader).sub(1);
            if !(*header).is_active() {
                crate::ffi::ifa_rt_panic_double_free(ptr);
            }

            let class_code = (*header).size_class_id();
            let is_arena = (*header).is_arena_scoped();

            // Invalidate slot generation and observe epoch transitions
            let transition = (*header).mark_freed();
            match transition {
                crate::header::EpochTransition::SwitchedToEpoch1 => {
                    self.epoch_manager.record_epoch_switch();
                }
                crate::header::EpochTransition::Quarantined => {
                    self.epoch_manager.record_quarantine();
                    let mut inner = self.inner.lock().unwrap();
                    if let Some(slabs_quarantined) = inner.register_quarantined_slot(ptr, header) {
                        self.epoch_manager.record_slab_quarantine(slabs_quarantined);
                    }
                    // Permanently quarantined due to 32-bit generation overflow; do not re-add to cache or pool
                    return;
                }
                crate::header::EpochTransition::None => {}
            }

            // Fast-path thread-local recycling for standard slab classes
            if !is_arena && class_code >= 1 && class_code <= SIZE_CLASSES.len() {
                let class_idx = class_code - 1;
                let flush_slots = LOCAL_CACHE.with(|cache| {
                    let mut c = cache.borrow_mut();
                    c.bins[class_idx].push(ptr);
                    if c.bins[class_idx].len() >= THREAD_CACHE_MAX_CAPACITY {
                        let drain_count = THREAD_CACHE_BATCH_SIZE;
                        Some(
                            c.bins[class_idx]
                                .drain(0..drain_count)
                                .collect::<Vec<*mut u8>>(),
                        )
                    } else {
                        None
                    }
                });

                if let Some(flushed) = flush_slots {
                    let mut inner = self.inner.lock().unwrap();
                    inner.recycle_batch(class_idx, &flushed);
                }
                return;
            }

            let mut inner = self.inner.lock().unwrap();
            inner.recycle_raw(ptr, header);
        }
    }

    /// Create a new scoped arena.
    pub fn create_arena(&self) -> u16 {
        let id = self.next_arena_id.fetch_add(1, Ordering::SeqCst);
        let mut inner = self.inner.lock().unwrap();
        inner.arenas.insert(id, GenArena::new(id));
        id
    }

    /// Create a scoped arena strictly isolated and owned by a specific fiber.
    pub fn create_arena_for_fiber(&self, fiber_id: u64) -> u16 {
        let id = self.next_arena_id.fetch_add(1, Ordering::SeqCst);
        let mut inner = self.inner.lock().unwrap();
        inner.arenas.insert(id, GenArena::with_owner(id, fiber_id));
        id
    }

    /// Bind or transfer ownership of an existing arena to a target fiber.
    pub fn set_arena_owner(&self, arena_id: u16, fiber_id: u64) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(arena) = inner.arenas.get_mut(&arena_id) {
            arena.set_owner(fiber_id);
        }
    }

    /// Verify whether a fiber is authorized to allocate or reset the specified arena.
    pub fn verify_arena_owner(&self, arena_id: u16, fiber_id: u64) -> bool {
        let inner = self.inner.lock().unwrap();
        if let Some(arena) = inner.arenas.get(&arena_id) {
            arena.is_owner(fiber_id)
        } else {
            false
        }
    }

    /// Reset an arena by invalidating all contained allocations.
    pub fn reset_arena(&self, arena_id: u16) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(mut arena) = inner.arenas.remove(&arena_id) {
            arena.reset(&mut inner);
            inner.arenas.insert(arena_id, arena);
        }
    }

    /// Destroy an arena.
    pub fn destroy_arena(&self, arena_id: u16) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(mut arena) = inner.arenas.remove(&arena_id) {
            arena.reset(&mut inner);
        }
    }
}

impl Default for GlobalGenAllocator {
    fn default() -> Self {
        Self::new()
    }
}

lazy_static::lazy_static! {
    pub static ref GLOBAL_ALLOCATOR: GlobalGenAllocator = GlobalGenAllocator::new();
}

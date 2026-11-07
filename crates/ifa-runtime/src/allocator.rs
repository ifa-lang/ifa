//! Slab and generational memory allocator providing deterministic zero-GC safety.

#![allow(clippy::not_unsafe_ptr_arg_deref)]

use crate::header::{GenHeader, FLAG_ACTIVE, FLAG_ARENA_SCOPED};
use std::alloc::{alloc, dealloc, Layout};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::sync::Mutex;

/// Standard slab size classes in bytes (excluding 8-byte GenHeader).
pub const SIZE_CLASSES: [usize; 7] = [16, 32, 64, 128, 256, 512, 1024];

/// Free slot node stored in intrusive free-lists when a slot is inactive.
#[repr(C)]
struct FreeNode {
    next: *mut FreeNode,
}

/// A slab page containing multiple fixed-size slots.
struct SlabPage {
    memory: *mut u8,
    layout: Layout,
    slot_size_with_header: usize,
    capacity: usize,
}

unsafe impl Send for SlabPage {}
unsafe impl Sync for SlabPage {}

impl SlabPage {
    fn new(slot_payload_size: usize, capacity: usize) -> Self {
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
            memory,
            layout,
            slot_size_with_header: slot_size,
            capacity,
        }
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
struct SizeClassPool {
    slot_payload_size: usize,
    free_head: *mut FreeNode,
    pages: Vec<SlabPage>,
}

unsafe impl Send for SizeClassPool {}
unsafe impl Sync for SizeClassPool {}

impl SizeClassPool {
    fn new(slot_payload_size: usize) -> Self {
        Self {
            slot_payload_size,
            free_head: std::ptr::null_mut(),
            pages: Vec::new(),
        }
    }

    fn allocate(&mut self, arena_id: u16, class_idx: usize) -> *mut u8 {
        if self.free_head.is_null() {
            self.grow();
        }

        let node = self.free_head;
        unsafe {
            self.free_head = (*node).next;
            let payload_ptr = node as *mut u8;
            let header_ptr = (payload_ptr as *mut GenHeader).sub(1);
            let current_gen = (*header_ptr).generation_counter;
            let class_flag = (((class_idx + 1) as u16) << crate::header::FLAG_CLASS_SHIFT)
                & crate::header::FLAG_CLASS_MASK;
            *header_ptr = GenHeader {
                generation_counter: if current_gen == 0 { 1 } else { current_gen },
                allocation_flags: FLAG_ACTIVE | class_flag,
                arena_id,
            };
            payload_ptr
        }
    }

    fn allocate_batch(&mut self, arena_id: u16, class_idx: usize, count: usize) -> Vec<*mut u8> {
        let mut slots = Vec::with_capacity(count);
        for _ in 0..count {
            slots.push(self.allocate(arena_id, class_idx));
        }
        slots
    }

    fn recycle(&mut self, payload_ptr: *mut u8) {
        unsafe {
            let node = payload_ptr as *mut FreeNode;
            (*node).next = self.free_head;
            self.free_head = node;
        }
    }

    fn recycle_batch(&mut self, slots: &[*mut u8]) {
        for &slot in slots {
            self.recycle(slot);
        }
    }

    fn grow(&mut self) {
        const DEFAULT_PAGE_CAPACITY: usize = 64;
        let page = SlabPage::new(self.slot_payload_size, DEFAULT_PAGE_CAPACITY);
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
    allocated_ptrs: Vec<*mut u8>,
}

unsafe impl Send for GenArena {}
unsafe impl Sync for GenArena {}

impl GenArena {
    pub fn new(id: u16) -> Self {
        Self {
            id,
            allocated_ptrs: Vec::new(),
        }
    }

    /// Reset all objects allocated in this arena, invalidating all external references.
    pub fn reset(&mut self, allocator: &mut GlobalGenAllocatorInner) {
        for &ptr in &self.allocated_ptrs {
            unsafe {
                let header = (ptr as *mut GenHeader).sub(1);
                if (*header).is_active() {
                    (*header).mark_freed();
                }
            }
        }
        self.allocated_ptrs.clear();
        let _ = allocator;
    }
}

/// Core global generational allocator.
pub struct GlobalGenAllocatorInner {
    pools: Vec<SizeClassPool>,
    arenas: HashMap<u16, GenArena>,
    large_allocations: HashMap<usize, (Layout, u32)>,
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

    /// Allocate a generational memory slot for a specific payload size.
    pub fn alloc(&mut self, size: usize, _align: usize, arena_id: u16) -> *mut u8 {
        // Find best-matching size class
        let class_idx = SIZE_CLASSES.iter().position(|&s| s >= size);

        let ptr = if let Some(idx) = class_idx {
            self.pools[idx].allocate(arena_id, idx)
        } else {
            // Direct large allocation
            self.alloc_large(size, arena_id)
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
                list.push(self.alloc_large(size, arena_id));
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
        // Locate size class or large allocation
        let addr = ptr as usize;
        if let Some((layout, _)) = self.large_allocations.remove(&addr) {
            let raw_ptr = header as *mut u8;
            dealloc(raw_ptr, layout);
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

    fn alloc_large(&mut self, size: usize, arena_id: u16) -> *mut u8 {
        let header_size = std::mem::size_of::<GenHeader>();
        let total_size = header_size + size;
        let layout = Layout::from_size_align(total_size, 8).expect("Invalid large layout");
        unsafe {
            let raw_mem = alloc(layout);
            if raw_mem.is_null() {
                std::alloc::handle_alloc_error(layout);
            }
            let header = raw_mem as *mut GenHeader;
            std::ptr::write(
                header,
                GenHeader {
                    generation_counter: 1,
                    allocation_flags: FLAG_ACTIVE,
                    arena_id,
                },
            );
            let payload = raw_mem.add(header_size);
            self.large_allocations.insert(payload as usize, (layout, 1));
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

thread_local! {
    static LOCAL_CACHE: std::cell::RefCell<ThreadLocalSlabCache> = std::cell::RefCell::new(ThreadLocalSlabCache::default());
}

/// Global thread-safe generational allocator instance.
pub struct GlobalGenAllocator {
    inner: Mutex<GlobalGenAllocatorInner>,
    next_arena_id: AtomicU16,
    allocated_bytes: AtomicUsize,
}

impl GlobalGenAllocator {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(GlobalGenAllocatorInner::new()),
            next_arena_id: AtomicU16::new(1),
            allocated_bytes: AtomicUsize::new(0),
        }
    }

    /// Allocate a slot on the generational heap.
    pub fn alloc(&self, size: usize, align: usize, arena_id: u16) -> *mut u8 {
        self.allocated_bytes.fetch_add(size, Ordering::Relaxed);

        // Fast-path for non-arena standard slab size classes via thread-local cache
        if arena_id == 0 {
            if let Some(idx) = SIZE_CLASSES.iter().position(|&s| s >= size) {
                let cached_ptr = LOCAL_CACHE.with(|cache| {
                    let mut c = cache.borrow_mut();
                    c.bins[idx].pop()
                });

                if let Some(ptr) = cached_ptr {
                    unsafe {
                        let header = (ptr as *mut GenHeader).sub(1);
                        let cur_gen = (*header).generation_counter;
                        let class_flag = (((idx + 1) as u16) << crate::header::FLAG_CLASS_SHIFT)
                            & crate::header::FLAG_CLASS_MASK;
                        *header = GenHeader {
                            generation_counter: if cur_gen == 0 { 1 } else { cur_gen },
                            allocation_flags: FLAG_ACTIVE | class_flag,
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

            // Invalidate slot generation
            (*header).mark_freed();

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

//! Binary layout and generational header specifications for IFA runtime.
//!
//! Conforms strictly to the IFA language specification:
//! - 64-bit `GenHeader`: `generation_counter` (u32), `allocation_flags` (u16), `arena_id` (u16).
//! - 128-bit `GenRef`: pointer address (64-bit), `remembered_gen` (32-bit), `arena_id` (16-bit), `_reserved` (16-bit).

/// Allocation flags for generational memory slots.
pub const FLAG_FREE: u16 = 0x0000;
pub const FLAG_ACTIVE: u16 = 0x0001;
pub const FLAG_PINNED: u16 = 0x0002;
pub const FLAG_READONLY: u16 = 0x0004;
pub const FLAG_ARENA_SCOPED: u16 = 0x0008;

/// 64-bit Generational Header placed immediately before each allocated payload.
#[repr(C, align(8))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenHeader {
    /// 32-bit generation counter incremented on every reallocation/free.
    pub generation_counter: u32,
    /// 16-bit status flags indicating active, free, or pinned state.
    pub allocation_flags: u16,
    /// 16-bit identifier of the owning arena or thread.
    pub arena_id: u16,
}

impl GenHeader {
    /// Create a new active generational header.
    #[inline(always)]
    pub const fn new_active(generation_counter: u32, arena_id: u16) -> Self {
        Self {
            generation_counter,
            allocation_flags: FLAG_ACTIVE,
            arena_id,
        }
    }

    /// Check if the slot is currently active.
    #[inline(always)]
    pub const fn is_active(&self) -> bool {
        (self.allocation_flags & FLAG_ACTIVE) != 0
    }

    /// Mark slot as freed and increment generation counter safely.
    #[inline(always)]
    pub fn mark_freed(&mut self) {
        self.allocation_flags &= !FLAG_ACTIVE;
        self.generation_counter = self.generation_counter.wrapping_add(1);
    }
}

/// 128-bit Fat Reference representing a safe generational reference (`ref`).
#[repr(C, align(8))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenRef {
    /// 64-bit raw pointer to the object payload.
    pub ptr: *mut u8,
    /// 32-bit generation counter recorded at reference creation.
    pub remembered_gen: u32,
    /// 16-bit arena identifier.
    pub arena_id: u16,
    /// 16-bit reserved padding for strict 128-bit alignment.
    pub _reserved: u16,
}

impl GenRef {
    /// Create a null generational reference.
    #[inline(always)]
    pub const fn null() -> Self {
        Self {
            ptr: std::ptr::null_mut(),
            remembered_gen: 0,
            arena_id: 0,
            _reserved: 0,
        }
    }

    /// Check whether this reference is null.
    #[inline(always)]
    pub fn is_null(&self) -> bool {
        self.ptr.is_null()
    }

    /// Construct a reference pointing to an allocated payload.
    ///
    /// # Safety
    /// `ptr` must point to a valid payload preceded by a `GenHeader`.
    #[inline(always)]
    pub unsafe fn from_payload(ptr: *mut u8, arena_id: u16) -> Self {
        if ptr.is_null() {
            return Self::null();
        }
        let header_ptr = (ptr as *const GenHeader).sub(1);
        let remembered_gen = (*header_ptr).generation_counter;
        Self {
            ptr,
            remembered_gen,
            arena_id,
            _reserved: 0,
        }
    }

    /// Read the current header of the referenced target.
    ///
    /// # Safety
    /// Must only be called if `self.ptr` is non-null.
    #[inline(always)]
    pub unsafe fn header(&self) -> &GenHeader {
        &*(self.ptr as *const GenHeader).sub(1)
    }

    /// Validate in 1 CPU cycle that the target is still alive and has not been freed/reallocated.
    #[inline(always)]
    pub fn is_valid(&self) -> bool {
        if self.ptr.is_null() {
            return false;
        }
        unsafe {
            let header = self.header();
            header.is_active() && header.generation_counter == self.remembered_gen
        }
    }
}

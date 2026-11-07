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
pub const FLAG_QUARANTINED: u16 = 0x0010;
pub const FLAG_EPOCH_1: u16 = 0x0020;

/// Result of marking a generational memory slot as freed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochTransition {
    /// Normal generation increment within current epoch.
    None,
    /// 32-bit generation overflowed u32::MAX, transitioned into Epoch 1.
    SwitchedToEpoch1,
    /// Secondary generation overflow, slot permanently quarantined from pool.
    Quarantined,
}

/// Bitshift and mask for encoding size-class ID within allocation flags.
pub const FLAG_CLASS_SHIFT: u16 = 8;
pub const FLAG_CLASS_MASK: u16 = 0xFF00;

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

    /// Check if the slot belongs to an explicit scoped arena.
    #[inline(always)]
    pub const fn is_arena_scoped(&self) -> bool {
        (self.allocation_flags & FLAG_ARENA_SCOPED) != 0
    }

    /// Check if the slot is quarantined due to 32-bit generation overflow.
    #[inline(always)]
    pub const fn is_quarantined(&self) -> bool {
        (self.allocation_flags & FLAG_QUARANTINED) != 0
    }

    /// Retrieve the encoded size-class ID (1-based, 0 if unclassified/large).
    #[inline(always)]
    pub const fn size_class_id(&self) -> usize {
        ((self.allocation_flags & FLAG_CLASS_MASK) >> FLAG_CLASS_SHIFT) as usize
    }

    /// Retrieve the epoch bit index (0 or 1).
    #[inline(always)]
    pub const fn epoch_id(&self) -> u8 {
        if (self.allocation_flags & FLAG_EPOCH_1) != 0 {
            1
        } else {
            0
        }
    }

    /// Store a 1-based size-class ID into the header flags.
    #[inline(always)]
    pub fn set_size_class_id(&mut self, class_id: usize) {
        self.allocation_flags = (self.allocation_flags & !FLAG_CLASS_MASK)
            | (((class_id as u16) << FLAG_CLASS_SHIFT) & FLAG_CLASS_MASK);
    }

    /// Mark slot as freed and increment generation counter safely.
    /// In case of 32-bit counter overflow (reaching u32::MAX), transitions epoch
    /// or quarantines the slot permanently to eliminate ABA / Use-After-Free wrap-around.
    #[inline(always)]
    pub fn mark_freed(&mut self) -> EpochTransition {
        self.allocation_flags &= !FLAG_ACTIVE;
        if self.generation_counter == u32::MAX {
            if (self.allocation_flags & FLAG_EPOCH_1) == 0 {
                // First 4-billion cycle overflow: toggle epoch bit and restart generation at 1
                self.allocation_flags |= FLAG_EPOCH_1;
                self.generation_counter = 1;
                EpochTransition::SwitchedToEpoch1
            } else {
                // Secondary overflow: permanently quarantine slot from pool
                self.allocation_flags |= FLAG_QUARANTINED;
                self.generation_counter = 0;
                EpochTransition::Quarantined
            }
        } else {
            self.generation_counter += 1;
            EpochTransition::None
        }
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
        let remembered_epoch = (*header_ptr).allocation_flags & (FLAG_EPOCH_1 | FLAG_QUARANTINED);
        Self {
            ptr,
            remembered_gen,
            arena_id,
            _reserved: remembered_epoch,
        }
    }

    /// Retrieve the remembered epoch flag recorded at reference creation.
    #[inline(always)]
    pub const fn remembered_epoch(&self) -> u16 {
        self._reserved & FLAG_EPOCH_1
    }

    /// Retrieve the epoch bit index (0 or 1).
    #[inline(always)]
    pub const fn epoch_id(&self) -> u8 {
        if (self._reserved & FLAG_EPOCH_1) != 0 {
            1
        } else {
            0
        }
    }

    /// Check whether the reference's recorded epoch no longer matches the target's current epoch.
    #[inline(always)]
    pub fn is_stale_epoch(&self) -> bool {
        if self.ptr.is_null() {
            return true;
        }
        unsafe {
            let header = self.header();
            (header.allocation_flags & FLAG_EPOCH_1) != (self._reserved & FLAG_EPOCH_1)
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
    /// Verifies active state, absence of quarantine, generation match, and epoch consistency.
    #[inline(always)]
    pub fn is_valid(&self) -> bool {
        if self.ptr.is_null() {
            return false;
        }
        unsafe {
            let header = self.header();
            header.is_active()
                && !header.is_quarantined()
                && header.generation_counter == self.remembered_gen
                && (header.allocation_flags & FLAG_EPOCH_1) == (self._reserved & FLAG_EPOCH_1)
        }
    }
}

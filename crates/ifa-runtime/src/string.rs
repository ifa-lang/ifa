//! Native string implementation with Copy-on-Write (CoW) and mutable value semantics.

use std::alloc::{alloc, dealloc, realloc, Layout};
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};

#[repr(C)]
struct StringHeader {
    ref_count: AtomicUsize,
    len: usize,
    capacity: usize,
}

/// A native IFA UTF-8 string adhering to mutable value semantics and implicit CoW.
pub struct IfaString {
    header: *mut StringHeader,
}

unsafe impl Send for IfaString {}
unsafe impl Sync for IfaString {}

impl IfaString {
    /// Create an empty IFA string.
    pub fn new() -> Self {
        Self::with_capacity(0)
    }

    /// Create an empty IFA string with reserved capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        let cap = capacity.max(8);
        let header_size = std::mem::size_of::<StringHeader>();
        // +1 for null-terminator for seamless C-ABI interop
        let total_size = header_size + cap + 1;
        let layout = Layout::from_size_align(total_size, 8).expect("Valid string layout");

        unsafe {
            let memory = alloc(layout);
            if memory.is_null() {
                std::alloc::handle_alloc_error(layout);
            }

            let header = memory as *mut StringHeader;
            std::ptr::write(
                header,
                StringHeader {
                    ref_count: AtomicUsize::new(1),
                    len: 0,
                    capacity: cap,
                },
            );

            // Null terminator at start
            *memory.add(header_size) = 0;

            Self { header }
        }
    }

    /// Create an IFA string from a standard Rust string slice.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        let bytes = s.as_bytes();
        let len = bytes.len();
        let mut string = Self::with_capacity(len);
        unsafe {
            let data_ptr = string.data_mut_ptr();
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), data_ptr, len);
            *data_ptr.add(len) = 0;
            (*string.header).len = len;
        }
        string
    }

    /// Byte length of the string.
    #[inline(always)]
    pub fn len(&self) -> usize {
        unsafe { (*self.header).len }
    }

    /// Check if the string is empty.
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Buffer capacity.
    #[inline(always)]
    pub fn capacity(&self) -> usize {
        unsafe { (*self.header).capacity }
    }

    /// Current reference count.
    #[inline(always)]
    pub fn ref_count(&self) -> usize {
        unsafe { (*self.header).ref_count.load(Ordering::Acquire) }
    }

    /// Pointer to the UTF-8 payload data.
    #[inline(always)]
    pub fn data_ptr(&self) -> *const u8 {
        unsafe { (self.header as *const u8).add(std::mem::size_of::<StringHeader>()) }
    }

    /// Mutable pointer to the payload data.
    #[inline(always)]
    fn data_mut_ptr(&mut self) -> *mut u8 {
        unsafe { (self.header as *mut u8).add(std::mem::size_of::<StringHeader>()) }
    }

    /// Ensure this string has exclusive ownership before mutation (Copy-on-Write).
    pub fn make_unique(&mut self) {
        unsafe {
            if (*self.header).ref_count.load(Ordering::Acquire) > 1 {
                let current_str = self.as_str();
                let new_string = Self::from_str(current_str);
                // Decrement old ref count
                (*self.header).ref_count.fetch_sub(1, Ordering::Release);
                self.header = new_string.header;
                std::mem::forget(new_string);
            }
        }
    }

    /// Append a string slice, performing CoW if shared and expanding capacity if necessary.
    pub fn push_str(&mut self, s: &str) {
        self.make_unique();
        let bytes = s.as_bytes();
        let add_len = bytes.len();
        let current_len = self.len();
        let current_cap = self.capacity();

        if current_len + add_len > current_cap {
            let new_cap = (current_cap * 2).max(current_len + add_len + 8);
            self.reallocate_capacity(new_cap);
        }

        unsafe {
            let data_ptr = self.data_mut_ptr();
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), data_ptr.add(current_len), add_len);
            let total_len = current_len + add_len;
            *data_ptr.add(total_len) = 0;
            (*self.header).len = total_len;
        }
    }

    /// Push a single character.
    pub fn push(&mut self, c: char) {
        let mut buf = [0u8; 4];
        let s = c.encode_utf8(&mut buf);
        self.push_str(s);
    }

    /// Return a borrowed string slice view.
    #[inline(always)]
    pub fn as_str(&self) -> &str {
        unsafe {
            let slice = std::slice::from_raw_parts(self.data_ptr(), self.len());
            std::str::from_utf8_unchecked(slice)
        }
    }

    /// Return a null-terminated C string pointer for C-ABI interoperability.
    #[inline(always)]
    pub fn as_c_str(&self) -> *const std::ffi::c_char {
        self.data_ptr() as *const std::ffi::c_char
    }

    fn reallocate_capacity(&mut self, new_cap: usize) {
        let header_size = std::mem::size_of::<StringHeader>();
        let old_total = header_size + self.capacity() + 1;
        let new_total = header_size + new_cap + 1;
        let old_layout = Layout::from_size_align(old_total, 8).unwrap();

        unsafe {
            let new_mem = realloc(self.header as *mut u8, old_layout, new_total);
            if new_mem.is_null() {
                let new_layout = Layout::from_size_align(new_total, 8).unwrap();
                std::alloc::handle_alloc_error(new_layout);
            }
            self.header = new_mem as *mut StringHeader;
            (*self.header).capacity = new_cap;
        }
    }
}

impl Default for IfaString {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for IfaString {
    /// O(1) Clone through Copy-on-Write reference count increment.
    fn clone(&self) -> Self {
        unsafe {
            (*self.header).ref_count.fetch_add(1, Ordering::Relaxed);
        }
        Self {
            header: self.header,
        }
    }
}

impl Drop for IfaString {
    fn drop(&mut self) {
        unsafe {
            if (*self.header).ref_count.fetch_sub(1, Ordering::Release) == 1 {
                std::sync::atomic::fence(Ordering::Acquire);
                let header_size = std::mem::size_of::<StringHeader>();
                let total_size = header_size + (*self.header).capacity + 1;
                let layout = Layout::from_size_align(total_size, 8).unwrap();
                dealloc(self.header as *mut u8, layout);
            }
        }
    }
}

impl fmt::Display for IfaString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl fmt::Debug for IfaString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.as_str())
    }
}

impl PartialEq for IfaString {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for IfaString {}

//! Native dynamic list (`List`) with Copy-on-Write and mutable value semantics.

use std::alloc::{alloc, dealloc, Layout};
use std::ops::{Index, IndexMut};
use std::sync::atomic::{AtomicUsize, Ordering};

#[repr(C)]
struct ListHeader {
    ref_count: AtomicUsize,
    len: usize,
    capacity: usize,
}

/// A native IFA dynamic array adhering to mutable value semantics.
pub struct IfaList<T> {
    header: *mut ListHeader,
    _marker: std::marker::PhantomData<T>,
}

unsafe impl<T: Send> Send for IfaList<T> {}
unsafe impl<T: Sync> Sync for IfaList<T> {}

impl<T> IfaList<T> {
    /// Create an empty list.
    pub fn new() -> Self {
        Self::with_capacity(4)
    }

    /// Create an empty list with reserved initial capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        let cap = capacity.max(4);
        let header_size = std::mem::size_of::<ListHeader>();
        let elem_size = std::mem::size_of::<T>();
        let align = std::mem::align_of::<T>().max(std::mem::align_of::<ListHeader>());
        let total_size = header_size + cap * elem_size;
        let layout = Layout::from_size_align(total_size, align).expect("Valid list layout");

        unsafe {
            let memory = alloc(layout);
            if memory.is_null() {
                std::alloc::handle_alloc_error(layout);
            }

            let header = memory as *mut ListHeader;
            std::ptr::write(
                header,
                ListHeader {
                    ref_count: AtomicUsize::new(1),
                    len: 0,
                    capacity: cap,
                },
            );

            Self {
                header,
                _marker: std::marker::PhantomData,
            }
        }
    }

    /// Number of elements currently in the list.
    #[inline(always)]
    pub fn len(&self) -> usize {
        unsafe { (*self.header).len }
    }

    /// Check if the list contains zero elements.
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Capacity allocated for elements.
    #[inline(always)]
    pub fn capacity(&self) -> usize {
        unsafe { (*self.header).capacity }
    }

    /// Pointer to the elements array.
    #[inline(always)]
    fn elements_ptr(&self) -> *const T {
        unsafe { (self.header as *const u8).add(std::mem::size_of::<ListHeader>()) as *const T }
    }

    /// Mutable pointer to the elements array.
    #[inline(always)]
    fn elements_mut_ptr(&mut self) -> *mut T {
        unsafe { (self.header as *mut u8).add(std::mem::size_of::<ListHeader>()) as *mut T }
    }

    /// Get element reference at index.
    pub fn get(&self, index: usize) -> Option<&T> {
        if index < self.len() {
            unsafe { Some(&*self.elements_ptr().add(index)) }
        } else {
            None
        }
    }

    /// Borrow elements as a contiguous slice.
    pub fn as_slice(&self) -> &[T] {
        unsafe { std::slice::from_raw_parts(self.elements_ptr(), self.len()) }
    }
}

impl<T: Clone> IfaList<T> {
    /// Ensure unique ownership of buffer before mutation (Copy-on-Write).
    pub fn make_unique(&mut self) {
        unsafe {
            if (*self.header).ref_count.load(Ordering::Acquire) > 1 {
                let current_len = self.len();
                let current_cap = self.capacity();
                let mut new_list = Self::with_capacity(current_cap);

                let src = self.elements_ptr();
                let dst = new_list.elements_mut_ptr();
                for i in 0..current_len {
                    std::ptr::write(dst.add(i), (*src.add(i)).clone());
                }
                (*new_list.header).len = current_len;

                (*self.header).ref_count.fetch_sub(1, Ordering::Release);
                self.header = new_list.header;
                std::mem::forget(new_list);
            }
        }
    }

    /// Append an element to the list, expanding capacity if required.
    pub fn push(&mut self, value: T) {
        self.make_unique();
        let len = self.len();
        let cap = self.capacity();

        if len >= cap {
            self.grow();
        }

        unsafe {
            let dst = self.elements_mut_ptr().add(len);
            std::ptr::write(dst, value);
            (*self.header).len = len + 1;
        }
    }

    /// Remove and return the last element.
    pub fn pop(&mut self) -> Option<T> {
        self.make_unique();
        let len = self.len();
        if len == 0 {
            return None;
        }

        unsafe {
            let last_idx = len - 1;
            let elem = std::ptr::read(self.elements_ptr().add(last_idx));
            (*self.header).len = last_idx;
            Some(elem)
        }
    }

    /// Get mutable reference at index.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        self.make_unique();
        if index < self.len() {
            unsafe { Some(&mut *self.elements_mut_ptr().add(index)) }
        } else {
            None
        }
    }

    fn grow(&mut self) {
        let current_cap = self.capacity();
        let new_cap = current_cap * 2;
        let current_len = self.len();
        let mut new_list = Self::with_capacity(new_cap);

        unsafe {
            let src = self.elements_mut_ptr();
            let dst = new_list.elements_mut_ptr();
            for i in 0..current_len {
                std::ptr::write(dst.add(i), std::ptr::read(src.add(i)));
            }
            (*new_list.header).len = current_len;
            // Old buffer doesn't need to drop moved items
            (*self.header).len = 0;
            self.drop_buffer();
            self.header = new_list.header;
            std::mem::forget(new_list);
        }
    }

    unsafe fn drop_buffer(&mut self) {
        let header_size = std::mem::size_of::<ListHeader>();
        let elem_size = std::mem::size_of::<T>();
        let align = std::mem::align_of::<T>().max(std::mem::align_of::<ListHeader>());
        let total_size = header_size + (*self.header).capacity * elem_size;
        let layout = Layout::from_size_align(total_size, align).unwrap();
        dealloc(self.header as *mut u8, layout);
    }
}

impl<T> Default for IfaList<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Clone for IfaList<T> {
    fn clone(&self) -> Self {
        unsafe {
            (*self.header).ref_count.fetch_add(1, Ordering::Relaxed);
        }
        Self {
            header: self.header,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<T> Drop for IfaList<T> {
    fn drop(&mut self) {
        unsafe {
            if (*self.header).ref_count.fetch_sub(1, Ordering::Release) == 1 {
                std::sync::atomic::fence(Ordering::Acquire);
                let len = (*self.header).len;
                let elems = self.elements_mut_ptr();
                for i in 0..len {
                    std::ptr::drop_in_place(elems.add(i));
                }
                let header_size = std::mem::size_of::<ListHeader>();
                let elem_size = std::mem::size_of::<T>();
                let align = std::mem::align_of::<T>().max(std::mem::align_of::<ListHeader>());
                let total_size = header_size + (*self.header).capacity * elem_size;
                let layout = Layout::from_size_align(total_size, align).unwrap();
                dealloc(self.header as *mut u8, layout);
            }
        }
    }
}

impl<T> Index<usize> for IfaList<T> {
    type Output = T;
    fn index(&self, index: usize) -> &Self::Output {
        self.get(index).expect("Index out of bounds")
    }
}

impl<T: Clone> IndexMut<usize> for IfaList<T> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        self.get_mut(index).expect("Index out of bounds")
    }
}

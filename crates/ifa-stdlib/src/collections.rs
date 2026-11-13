//! Standard deterministic collections (`std::collections`).
//!
//! Provides deterministic data structures required for bit-for-bit reproducible compilation:
//! - `List<T>`: Dynamic linear buffer with value semantics.
//! - `Map<K, V>`: Deterministic key-value dictionary ordered lexicographically.
//! - `Set<T>`: Deterministic unique set ordered lexicographically.
//! - `ByteBuffer`: High-throughput binary builder with little/big-endian encoding.
//! - `StringBuilder`: Deterministic string synthesis and code formatting buffer.
//! - `RingBuffer<T>`: Fixed-capacity circular FIFO ring buffer.
//! - `BinaryHeap<T>`: Priority queue ordered by min or max comparator.
//! - `Deque<T>`: Double-ended queue with amortized O(1) front and back operations.
//! - `LruCache<K, V>`: Bounded-capacity Least Recently Used cache with deterministic eviction.

use std::collections::{btree_map, btree_set, BTreeMap, BTreeSet};
use std::fmt;
use std::ops::{Index, IndexMut};

/// Deterministic ordered map using B-Tree for guaranteed bit-by-bit iteration reproducibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Map<K: Ord, V> {
    inner: BTreeMap<K, V>,
}

impl<K: Ord, V> Default for Map<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: Ord, V> Map<K, V> {
    /// Create an empty map.
    pub fn new() -> Self {
        Self {
            inner: BTreeMap::new(),
        }
    }

    /// Return number of entries in map.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if map is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Clear all entries from the map.
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    /// Insert a key-value pair, returning previous value if key was present.
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.inner.insert(key, value)
    }

    /// Get reference to value associated with key.
    pub fn get(&self, key: &K) -> Option<&V> {
        self.inner.get(key)
    }

    /// Get mutable reference to value associated with key.
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.inner.get_mut(key)
    }

    /// Check if map contains key.
    pub fn contains_key(&self, key: &K) -> bool {
        self.inner.contains_key(key)
    }

    /// Remove a key from the map, returning previous value if present.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.inner.remove(key)
    }

    /// Deterministic iterator over key-value pairs sorted in ascending key order.
    pub fn iter(&self) -> btree_map::Iter<'_, K, V> {
        self.inner.iter()
    }

    /// Deterministic iterator over keys sorted in ascending order.
    pub fn keys(&self) -> btree_map::Keys<'_, K, V> {
        self.inner.keys()
    }

    /// Deterministic iterator over values ordered by key.
    pub fn values(&self) -> btree_map::Values<'_, K, V> {
        self.inner.values()
    }
}

impl<K: Ord, V> IntoIterator for Map<K, V> {
    type Item = (K, V);
    type IntoIter = btree_map::IntoIter<K, V>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl<'a, K: Ord, V> IntoIterator for &'a Map<K, V> {
    type Item = (&'a K, &'a V);
    type IntoIter = btree_map::Iter<'a, K, V>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.iter()
    }
}

/// Deterministic ordered set using B-Tree for guaranteed bit-by-bit iteration reproducibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Set<T: Ord> {
    inner: BTreeSet<T>,
}

impl<T: Ord> Default for Set<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Ord> Set<T> {
    /// Create an empty set.
    pub fn new() -> Self {
        Self {
            inner: BTreeSet::new(),
        }
    }

    /// Return number of unique elements in set.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if set is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Clear all elements from the set.
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    /// Insert an element into the set. Returns true if element was not present.
    pub fn insert(&mut self, value: T) -> bool {
        self.inner.insert(value)
    }

    /// Check if set contains value.
    pub fn contains(&self, value: &T) -> bool {
        self.inner.contains(value)
    }

    /// Remove a value from the set. Returns true if value was present.
    pub fn remove(&mut self, value: &T) -> bool {
        self.inner.remove(value)
    }

    /// Deterministic iterator over elements sorted in ascending order.
    pub fn iter(&self) -> btree_set::Iter<'_, T> {
        self.inner.iter()
    }
}

impl<T: Ord> IntoIterator for Set<T> {
    type Item = T;
    type IntoIter = btree_set::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl<'a, T: Ord> IntoIterator for &'a Set<T> {
    type Item = &'a T;
    type IntoIter = btree_set::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.iter()
    }
}

/// Dynamic linear list container with deterministic ordering.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct List<T> {
    inner: Vec<T>,
}

impl<T> Default for List<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> List<T> {
    /// Create an empty list.
    pub fn new() -> Self {
        Self { inner: Vec::new() }
    }

    /// Create an empty list with preallocated capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Vec::with_capacity(capacity),
        }
    }

    /// Number of elements in list.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if list is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Clear all elements from the list.
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    /// Append an element to the end of the list.
    pub fn push(&mut self, value: T) {
        self.inner.push(value);
    }

    /// Remove and return the last element, if any.
    pub fn pop(&mut self) -> Option<T> {
        self.inner.pop()
    }

    /// Insert an element at the specified index.
    pub fn insert(&mut self, index: usize, value: T) {
        self.inner.insert(index, value);
    }

    /// Remove and return the element at the specified index.
    pub fn remove(&mut self, index: usize) -> T {
        self.inner.remove(index)
    }

    /// Get reference to element at index.
    pub fn get(&self, index: usize) -> Option<&T> {
        self.inner.get(index)
    }

    /// Get mutable reference to element at index.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        self.inner.get_mut(index)
    }

    /// Access underlying contiguous slice.
    pub fn as_slice(&self) -> &[T] {
        &self.inner
    }

    /// Access underlying mutable contiguous slice.
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        &mut self.inner
    }
}

impl<T: Ord> List<T> {
    /// Deterministically sort elements in ascending order.
    pub fn sort(&mut self) {
        self.inner.sort();
    }
}

impl<T> Index<usize> for List<T> {
    type Output = T;
    fn index(&self, index: usize) -> &Self::Output {
        &self.inner[index]
    }
}

impl<T> IndexMut<usize> for List<T> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.inner[index]
    }
}

impl<T> IntoIterator for List<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl<'a, T> IntoIterator for &'a List<T> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.iter()
    }
}

impl<T> From<Vec<T>> for List<T> {
    fn from(vec: Vec<T>) -> Self {
        Self { inner: vec }
    }
}

impl<T> From<List<T>> for Vec<T> {
    fn from(list: List<T>) -> Self {
        list.inner
    }
}

/// Binary byte buffer supporting endian-aware serialization for compiler backends.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ByteBuffer {
    bytes: Vec<u8>,
}

impl ByteBuffer {
    /// Create an empty byte buffer.
    pub fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    /// Create an empty byte buffer with preallocated capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
        }
    }

    /// Current allocated capacity in bytes.
    pub fn capacity(&self) -> usize {
        self.bytes.capacity()
    }

    /// Reserve additional capacity for at least `additional` more bytes without redundant reallocations.
    pub fn reserve(&mut self, additional: usize) {
        self.bytes.reserve(additional);
    }

    /// Shrink capacity to fit current length.
    pub fn shrink_to_fit(&mut self) {
        self.bytes.shrink_to_fit();
    }

    /// Truncate buffer to specified length.
    pub fn truncate(&mut self, new_len: usize) {
        self.bytes.truncate(new_len);
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Check if buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Clear all bytes from buffer.
    pub fn clear(&mut self) {
        self.bytes.clear();
    }

    /// Access raw byte slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume buffer and return inner byte vector.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Append a single unsigned byte.
    pub fn write_u8(&mut self, val: u8) {
        self.bytes.push(val);
    }

    /// Append a signed 8-bit integer.
    pub fn write_i8(&mut self, val: i8) {
        self.bytes.push(val as u8);
    }

    /// Append a little-endian unsigned 16-bit integer.
    pub fn write_u16_le(&mut self, val: u16) {
        self.bytes.extend_from_slice(&val.to_le_bytes());
    }

    /// Append a big-endian unsigned 16-bit integer.
    pub fn write_u16_be(&mut self, val: u16) {
        self.bytes.extend_from_slice(&val.to_be_bytes());
    }

    /// Append a little-endian unsigned 32-bit integer.
    pub fn write_u32_le(&mut self, val: u32) {
        self.bytes.extend_from_slice(&val.to_le_bytes());
    }

    /// Append a big-endian unsigned 32-bit integer.
    pub fn write_u32_be(&mut self, val: u32) {
        self.bytes.extend_from_slice(&val.to_be_bytes());
    }

    /// Append a little-endian unsigned 64-bit integer.
    pub fn write_u64_le(&mut self, val: u64) {
        self.bytes.extend_from_slice(&val.to_le_bytes());
    }

    /// Append a big-endian unsigned 64-bit integer.
    pub fn write_u64_be(&mut self, val: u64) {
        self.bytes.extend_from_slice(&val.to_be_bytes());
    }

    /// Append a little-endian signed 16-bit integer.
    pub fn write_i16_le(&mut self, val: i16) {
        self.bytes.extend_from_slice(&val.to_le_bytes());
    }

    /// Append a big-endian signed 16-bit integer.
    pub fn write_i16_be(&mut self, val: i16) {
        self.bytes.extend_from_slice(&val.to_be_bytes());
    }

    /// Append a little-endian signed 32-bit integer.
    pub fn write_i32_le(&mut self, val: i32) {
        self.bytes.extend_from_slice(&val.to_le_bytes());
    }

    /// Append a big-endian signed 32-bit integer.
    pub fn write_i32_be(&mut self, val: i32) {
        self.bytes.extend_from_slice(&val.to_be_bytes());
    }

    /// Append a little-endian signed 64-bit integer.
    pub fn write_i64_le(&mut self, val: i64) {
        self.bytes.extend_from_slice(&val.to_le_bytes());
    }

    /// Append a big-endian signed 64-bit integer.
    pub fn write_i64_be(&mut self, val: i64) {
        self.bytes.extend_from_slice(&val.to_be_bytes());
    }

    /// Append a little-endian 32-bit float.
    pub fn write_f32_le(&mut self, val: f32) {
        self.bytes.extend_from_slice(&val.to_le_bytes());
    }

    /// Append a big-endian 32-bit float.
    pub fn write_f32_be(&mut self, val: f32) {
        self.bytes.extend_from_slice(&val.to_be_bytes());
    }

    /// Append a little-endian 64-bit float.
    pub fn write_f64_le(&mut self, val: f64) {
        self.bytes.extend_from_slice(&val.to_le_bytes());
    }

    /// Append a big-endian 64-bit float.
    pub fn write_f64_be(&mut self, val: f64) {
        self.bytes.extend_from_slice(&val.to_be_bytes());
    }

    /// Append arbitrary byte slice.
    pub fn write_bytes(&mut self, slice: &[u8]) {
        self.bytes.extend_from_slice(slice);
    }

    /// Append UTF-8 string bytes.
    pub fn write_str(&mut self, text: &str) {
        self.bytes.extend_from_slice(text.as_bytes());
    }

    /// Read an unsigned byte at offset.
    pub fn read_u8(&self, offset: usize) -> Option<u8> {
        self.bytes.get(offset).copied()
    }

    /// Read little-endian u16 at offset.
    pub fn read_u16_le(&self, offset: usize) -> Option<u16> {
        if offset + 2 <= self.bytes.len() {
            let slice: [u8; 2] = self.bytes[offset..offset + 2].try_into().ok()?;
            Some(u16::from_le_bytes(slice))
        } else {
            None
        }
    }

    /// Read big-endian u16 at offset.
    pub fn read_u16_be(&self, offset: usize) -> Option<u16> {
        if offset + 2 <= self.bytes.len() {
            let slice: [u8; 2] = self.bytes[offset..offset + 2].try_into().ok()?;
            Some(u16::from_be_bytes(slice))
        } else {
            None
        }
    }

    /// Read little-endian u32 at offset.
    pub fn read_u32_le(&self, offset: usize) -> Option<u32> {
        if offset + 4 <= self.bytes.len() {
            let slice: [u8; 4] = self.bytes[offset..offset + 4].try_into().ok()?;
            Some(u32::from_le_bytes(slice))
        } else {
            None
        }
    }

    /// Read big-endian u32 at offset.
    pub fn read_u32_be(&self, offset: usize) -> Option<u32> {
        if offset + 4 <= self.bytes.len() {
            let slice: [u8; 4] = self.bytes[offset..offset + 4].try_into().ok()?;
            Some(u32::from_be_bytes(slice))
        } else {
            None
        }
    }

    /// Read little-endian u64 at offset.
    pub fn read_u64_le(&self, offset: usize) -> Option<u64> {
        if offset + 8 <= self.bytes.len() {
            let slice: [u8; 8] = self.bytes[offset..offset + 8].try_into().ok()?;
            Some(u64::from_le_bytes(slice))
        } else {
            None
        }
    }

    /// Read big-endian u64 at offset.
    pub fn read_u64_be(&self, offset: usize) -> Option<u64> {
        if offset + 8 <= self.bytes.len() {
            let slice: [u8; 8] = self.bytes[offset..offset + 8].try_into().ok()?;
            Some(u64::from_be_bytes(slice))
        } else {
            None
        }
    }

    /// Read little-endian i32 at offset.
    pub fn read_i32_le(&self, offset: usize) -> Option<i32> {
        if offset + 4 <= self.bytes.len() {
            let slice: [u8; 4] = self.bytes[offset..offset + 4].try_into().ok()?;
            Some(i32::from_le_bytes(slice))
        } else {
            None
        }
    }

    /// Read big-endian i32 at offset.
    pub fn read_i32_be(&self, offset: usize) -> Option<i32> {
        if offset + 4 <= self.bytes.len() {
            let slice: [u8; 4] = self.bytes[offset..offset + 4].try_into().ok()?;
            Some(i32::from_be_bytes(slice))
        } else {
            None
        }
    }

    /// Read little-endian i64 at offset.
    pub fn read_i64_le(&self, offset: usize) -> Option<i64> {
        if offset + 8 <= self.bytes.len() {
            let slice: [u8; 8] = self.bytes[offset..offset + 8].try_into().ok()?;
            Some(i64::from_le_bytes(slice))
        } else {
            None
        }
    }

    /// Read big-endian i64 at offset.
    pub fn read_i64_be(&self, offset: usize) -> Option<i64> {
        if offset + 8 <= self.bytes.len() {
            let slice: [u8; 8] = self.bytes[offset..offset + 8].try_into().ok()?;
            Some(i64::from_be_bytes(slice))
        } else {
            None
        }
    }

    /// Read a sub-slice of bytes at offset with length.
    pub fn read_bytes(&self, offset: usize, len: usize) -> Option<&[u8]> {
        if offset + len <= self.bytes.len() {
            Some(&self.bytes[offset..offset + len])
        } else {
            None
        }
    }

    /// Encode internal buffer as hexadecimal string.
    pub fn to_hex(&self, uppercase: bool) -> String {
        crate::fmt::encode_hex(&self.bytes, uppercase)
    }

    /// Decode and append hexadecimal string directly into the byte buffer.
    pub fn write_hex_str(&mut self, hex: &str) -> Result<usize, crate::fmt::HexError> {
        let decoded = crate::fmt::decode_hex(hex)?;
        let count = decoded.len();
        self.bytes.extend(decoded);
        Ok(count)
    }
}

/// Deterministic string builder with indent management and formatting support.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StringBuilder {
    buffer: String,
    indent_level: usize,
    indent_unit: String,
}

impl StringBuilder {
    /// Create a new string builder with default 4-space indentation.
    pub fn new() -> Self {
        Self {
            buffer: String::new(),
            indent_level: 0,
            indent_unit: "    ".to_string(),
        }
    }

    /// Create with preallocated capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: String::with_capacity(capacity),
            indent_level: 0,
            indent_unit: "    ".to_string(),
        }
    }

    /// Current allocated capacity of the internal buffer.
    pub fn capacity(&self) -> usize {
        self.buffer.capacity()
    }

    /// Reserve additional space for at least `additional` more bytes without redundant reallocations.
    pub fn reserve(&mut self, additional: usize) {
        self.buffer.reserve(additional);
    }

    /// Shrink string capacity to match its current length.
    pub fn shrink_to_fit(&mut self) {
        self.buffer.shrink_to_fit();
    }

    /// Truncate string to specified byte length.
    pub fn truncate(&mut self, new_len: usize) {
        self.buffer.truncate(new_len);
    }

    /// Remove the last character from buffer and return it, if any.
    pub fn pop(&mut self) -> Option<char> {
        self.buffer.pop()
    }

    /// Number of bytes in buffer.
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Check if buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Clear buffer.
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.indent_level = 0;
    }

    /// Increase indentation level by 1.
    pub fn indent(&mut self) {
        self.indent_level += 1;
    }

    /// Decrease indentation level by 1 (minimum 0).
    pub fn dedent(&mut self) {
        if self.indent_level > 0 {
            self.indent_level -= 1;
        }
    }

    /// Append indentation spaces according to current level.
    pub fn append_indent(&mut self) {
        for _ in 0..self.indent_level {
            self.buffer.push_str(&self.indent_unit);
        }
    }

    /// Append string slice.
    pub fn push_str(&mut self, text: &str) {
        self.buffer.push_str(text);
    }

    /// Append a single character.
    pub fn push_char(&mut self, ch: char) {
        self.buffer.push(ch);
    }

    /// Append an integer formatted deterministically in decimal.
    pub fn push_int(&mut self, val: i64) {
        use std::fmt::Write;
        let _ = write!(self.buffer, "{}", val);
    }

    /// Append an integer formatted in hexadecimal with `0x` prefix.
    pub fn push_hex(&mut self, val: u64) {
        use std::fmt::Write;
        let _ = write!(self.buffer, "0x{:x}", val);
    }

    /// Append a newline character.
    pub fn push_newline(&mut self) {
        self.buffer.push('\n');
    }

    /// Append an indented line of text followed by newline.
    pub fn push_line(&mut self, text: &str) {
        self.append_indent();
        self.buffer.push_str(text);
        self.buffer.push('\n');
    }

    /// Repeat and append a string `count` times without intermediary allocations.
    pub fn push_repeat(&mut self, s: &str, count: usize) {
        self.buffer.reserve(s.len() * count);
        for _ in 0..count {
            self.buffer.push_str(s);
        }
    }

    /// Append binary representation of integer.
    pub fn push_binary(&mut self, val: u64, prefix: bool) {
        let _ = crate::fmt::write_binary(self, val, prefix);
    }

    /// Append octal representation of integer.
    pub fn push_octal(&mut self, val: u64, prefix: bool) {
        let _ = crate::fmt::write_octal(self, val, prefix);
    }

    /// Append float formatted with decimal precision.
    pub fn push_float(&mut self, val: f64, precision: usize) {
        let _ = crate::fmt::write_float_prec(self, val, precision);
    }

    /// Append raw byte slice encoded as hexadecimal.
    pub fn push_hex_bytes(&mut self, bytes: &[u8], uppercase: bool) {
        let _ = crate::fmt::write_hex_bytes(self, bytes, uppercase);
    }

    /// Append text formatted with field alignment and fill character.
    pub fn push_aligned(
        &mut self,
        s: &str,
        width: usize,
        alignment: crate::fmt::Alignment,
        pad_char: char,
    ) {
        let _ = crate::fmt::write_aligned(self, s, width, alignment, pad_char);
    }

    /// Append multiple lines indented with the current indentation level.
    pub fn push_indent_lines(&mut self, text: &str) {
        for line in text.lines() {
            self.push_line(line);
        }
    }

    /// Access inner string as byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        self.buffer.as_bytes()
    }

    /// Check if builder starts with given prefix.
    pub fn starts_with(&self, pat: &str) -> bool {
        self.buffer.starts_with(pat)
    }

    /// Check if builder ends with given suffix.
    pub fn ends_with(&self, pat: &str) -> bool {
        self.buffer.ends_with(pat)
    }

    /// Check if builder contains given substring pattern.
    pub fn contains(&self, pat: &str) -> bool {
        self.buffer.contains(pat)
    }

    /// Access inner string as slice.
    pub fn as_str(&self) -> &str {
        &self.buffer
    }

    /// Consume builder and return constructed string.
    pub fn into_string(self) -> String {
        self.buffer
    }

    /// Consume builder and return underlying byte vector without extra allocation.
    pub fn into_bytes(self) -> Vec<u8> {
        self.buffer.into_bytes()
    }
}

impl fmt::Write for StringBuilder {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.buffer.push_str(s);
        Ok(())
    }

    fn write_char(&mut self, c: char) -> fmt::Result {
        self.buffer.push(c);
        Ok(())
    }
}

impl fmt::Display for StringBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.buffer)
    }
}

/// Fixed-capacity circular ring buffer with FIFO semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingBuffer<T> {
    data: Vec<Option<T>>,
    head: usize,
    tail: usize,
    count: usize,
    capacity: usize,
}

impl<T: Clone> RingBuffer<T> {
    /// Create a new fixed-capacity ring buffer.
    pub fn new(capacity: usize) -> Self {
        assert!(
            capacity > 0,
            "RingBuffer capacity must be strictly positive"
        );
        let mut data = Vec::with_capacity(capacity);
        data.resize(capacity, None);
        Self {
            data,
            head: 0,
            tail: 0,
            count: 0,
            capacity,
        }
    }

    /// Return current number of elements.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return maximum capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Check if buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Check if buffer has reached capacity.
    pub fn is_full(&self) -> bool {
        self.count == self.capacity
    }

    /// Push an element to the back. Returns false if full.
    pub fn push(&mut self, item: T) -> bool {
        if self.is_full() {
            return false;
        }
        self.data[self.tail] = Some(item);
        self.tail = (self.tail + 1) % self.capacity;
        self.count += 1;
        true
    }

    /// Pop an element from the front. Returns None if empty.
    pub fn pop(&mut self) -> Option<T> {
        if self.is_empty() {
            return None;
        }
        let item = self.data[self.head].take();
        self.head = (self.head + 1) % self.capacity;
        self.count -= 1;
        item
    }

    /// Peek the front element without removing it.
    pub fn peek(&self) -> Option<&T> {
        if self.is_empty() {
            None
        } else {
            self.data[self.head].as_ref()
        }
    }

    /// Clear all elements.
    pub fn clear(&mut self) {
        for slot in &mut self.data {
            *slot = None;
        }
        self.head = 0;
        self.tail = 0;
        self.count = 0;
    }
}

/// Deterministic binary heap (min-heap or max-heap priority queue).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryHeap<T: Ord> {
    items: Vec<T>,
    is_min: bool,
}

impl<T: Ord> BinaryHeap<T> {
    /// Create an empty min-heap (lowest elements popped first).
    pub fn new_min() -> Self {
        Self {
            items: Vec::new(),
            is_min: true,
        }
    }

    /// Create an empty max-heap (highest elements popped first).
    pub fn new_max() -> Self {
        Self {
            items: Vec::new(),
            is_min: false,
        }
    }

    /// Return number of elements in the heap.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Check if heap is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Clear all elements.
    pub fn clear(&mut self) {
        self.items.clear();
    }

    /// Peek root element without removing it.
    pub fn peek(&self) -> Option<&T> {
        self.items.first()
    }

    /// Push an element into the heap and sift up.
    pub fn push(&mut self, item: T) {
        self.items.push(item);
        let mut idx = self.items.len() - 1;
        while idx > 0 {
            let parent = (idx - 1) / 2;
            let should_swap = if self.is_min {
                self.items[idx] < self.items[parent]
            } else {
                self.items[idx] > self.items[parent]
            };

            if should_swap {
                self.items.swap(idx, parent);
                idx = parent;
            } else {
                break;
            }
        }
    }

    /// Pop the root element and sift down.
    pub fn pop(&mut self) -> Option<T> {
        if self.items.is_empty() {
            return None;
        }
        let root = self.items.swap_remove(0);
        if !self.items.is_empty() {
            let mut idx = 0;
            let n = self.items.len();
            loop {
                let left = 2 * idx + 1;
                let right = 2 * idx + 2;
                let mut target = idx;

                if self.is_min {
                    if left < n && self.items[left] < self.items[target] {
                        target = left;
                    }
                    if right < n && self.items[right] < self.items[target] {
                        target = right;
                    }
                } else {
                    if left < n && self.items[left] > self.items[target] {
                        target = left;
                    }
                    if right < n && self.items[right] > self.items[target] {
                        target = right;
                    }
                }

                if target != idx {
                    self.items.swap(idx, target);
                    idx = target;
                } else {
                    break;
                }
            }
        }
        Some(root)
    }
}

/// Deterministic double-ended queue with amortized O(1) operations.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Deque<T> {
    inner: std::collections::VecDeque<T>,
}

impl<T> Deque<T> {
    /// Create an empty deque.
    pub fn new() -> Self {
        Self {
            inner: std::collections::VecDeque::new(),
        }
    }

    /// Return number of elements in the deque.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if deque is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Clear all elements.
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    /// Push an element to the back.
    pub fn push_back(&mut self, item: T) {
        self.inner.push_back(item);
    }

    /// Push an element to the front.
    pub fn push_front(&mut self, item: T) {
        self.inner.push_front(item);
    }

    /// Pop an element from the front.
    pub fn pop_front(&mut self) -> Option<T> {
        self.inner.pop_front()
    }

    /// Pop an element from the back.
    pub fn pop_back(&mut self) -> Option<T> {
        self.inner.pop_back()
    }

    /// Peek the front element.
    pub fn peek_front(&self) -> Option<&T> {
        self.inner.front()
    }

    /// Peek the back element.
    pub fn peek_back(&self) -> Option<&T> {
        self.inner.back()
    }
}

/// Eviction details resulting from an insertion into an [`LruCache`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Eviction<K, V> {
    /// Previous value associated with the key if the key was already present.
    pub old_value: Option<V>,
    /// Displaced key-value pair evicted from the cache if capacity was exceeded.
    pub evicted: Option<(K, V)>,
}

/// Node slot stored in [`LruCache`].
#[derive(Debug, Clone)]
struct LruNode<K, V> {
    key: K,
    value: V,
    prev: Option<usize>, // toward MRU (head)
    next: Option<usize>, // toward LRU (tail)
}

/// Deterministic Least Recently Used (LRU) Cache with bounded capacity.
///
/// Guaranteed bit-for-bit reproducibility via ordered indexing, completely safe
/// slot-indexed arena allocation, and zero raw pointers or unsafe blocks.
///
/// # Examples
/// ```
/// use ifa_stdlib::collections::LruCache;
///
/// let mut cache = LruCache::new(2);
/// cache.put("a", 1);
/// cache.put("b", 2);
/// assert_eq!(cache.get(&"a"), Some(&1));
/// cache.put("c", 3); // evicts "b" because "a" was accessed
/// assert_eq!(cache.get(&"b"), None);
/// assert_eq!(cache.get(&"a"), Some(&1));
/// assert_eq!(cache.get(&"c"), Some(&3));
/// ```
#[derive(Debug, Clone)]
pub struct LruCache<K: Ord + Clone, V> {
    capacity: usize,
    map: BTreeMap<K, usize>,
    nodes: Vec<Option<LruNode<K, V>>>,
    free_slots: Vec<usize>,
    head: Option<usize>, // MRU
    tail: Option<usize>, // LRU
}

impl<K: Ord + Clone, V> LruCache<K, V> {
    /// Create a new bounded LRU cache with non-zero capacity.
    ///
    /// # Panics
    /// Panics if `capacity == 0`.
    pub fn new(capacity: usize) -> Self {
        assert!(
            capacity > 0,
            "LruCache capacity must be strictly greater than 0"
        );
        Self {
            capacity,
            map: BTreeMap::new(),
            nodes: Vec::new(),
            free_slots: Vec::new(),
            head: None,
            tail: None,
        }
    }

    /// Return maximum capacity of the cache.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Return current number of elements in the cache.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Check if cache is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Check if cache has reached its maximum capacity.
    pub fn is_full(&self) -> bool {
        self.len() >= self.capacity
    }

    /// Clear all cached elements.
    pub fn clear(&mut self) {
        self.map.clear();
        self.nodes.clear();
        self.free_slots.clear();
        self.head = None;
        self.tail = None;
    }

    /// Check whether a key is present without altering recency.
    pub fn contains_key(&self, key: &K) -> bool {
        self.map.contains_key(key)
    }

    /// Peek value for a key without altering recency.
    pub fn peek(&self, key: &K) -> Option<&V> {
        let &idx = self.map.get(key)?;
        let node = self.nodes.get(idx)?.as_ref()?;
        Some(&node.value)
    }

    /// Peek mutable value for a key without altering recency.
    pub fn peek_mut(&mut self, key: &K) -> Option<&mut V> {
        let &idx = self.map.get(key)?;
        let node = self.nodes.get_mut(idx)?.as_mut()?;
        Some(&mut node.value)
    }

    /// Peek the Most Recently Used (MRU) entry.
    pub fn peek_mru(&self) -> Option<(&K, &V)> {
        let idx = self.head?;
        let node = self.nodes.get(idx)?.as_ref()?;
        Some((&node.key, &node.value))
    }

    /// Peek the Least Recently Used (LRU) entry.
    pub fn peek_lru(&self) -> Option<(&K, &V)> {
        let idx = self.tail?;
        let node = self.nodes.get(idx)?.as_ref()?;
        Some((&node.key, &node.value))
    }

    /// Retrieve reference to a value, promoting the key to Most Recently Used (MRU).
    pub fn get(&mut self, key: &K) -> Option<&V> {
        let &idx = self.map.get(key)?;
        self.move_to_head(idx);
        let node = self.nodes.get(idx)?.as_ref()?;
        Some(&node.value)
    }

    /// Retrieve mutable reference to a value, promoting the key to Most Recently Used (MRU).
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        let &idx = self.map.get(key)?;
        self.move_to_head(idx);
        let node = self.nodes.get_mut(idx)?.as_mut()?;
        Some(&mut node.value)
    }

    /// Insert or update a key-value pair, promoting it to Most Recently Used (MRU).
    ///
    /// If the key already exists, updates the value and returns the old value.
    /// If inserting a new key causes the cache to exceed its capacity, the LRU element is evicted.
    pub fn put(&mut self, key: K, value: V) -> Option<V> {
        self.put_with_eviction(key, value).old_value
    }

    /// Insert or update a key-value pair with complete eviction report.
    pub fn put_with_eviction(&mut self, key: K, value: V) -> Eviction<K, V> {
        if let Some(&idx) = self.map.get(&key) {
            let old_val = {
                let node = self.nodes[idx].as_mut().expect("valid node index");
                std::mem::replace(&mut node.value, value)
            };
            self.move_to_head(idx);
            Eviction {
                old_value: Some(old_val),
                evicted: None,
            }
        } else {
            let mut evicted = None;
            if self.len() >= self.capacity {
                evicted = self.pop_lru();
            }

            let idx = if let Some(free_idx) = self.free_slots.pop() {
                self.nodes[free_idx] = Some(LruNode {
                    key: key.clone(),
                    value,
                    prev: None,
                    next: None,
                });
                free_idx
            } else {
                let new_idx = self.nodes.len();
                self.nodes.push(Some(LruNode {
                    key: key.clone(),
                    value,
                    prev: None,
                    next: None,
                }));
                new_idx
            };

            self.attach_head(idx);
            self.map.insert(key, idx);

            Eviction {
                old_value: None,
                evicted,
            }
        }
    }

    /// Remove a key-value pair from the cache.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        let idx = self.map.remove(key)?;
        self.detach(idx);
        let node = self.nodes[idx].take().expect("valid node");
        self.free_slots.push(idx);
        Some(node.value)
    }

    /// Evict and return the Least Recently Used (LRU) entry.
    pub fn pop_lru(&mut self) -> Option<(K, V)> {
        let tail_idx = self.tail?;
        self.detach(tail_idx);
        let node = self.nodes[tail_idx].take().expect("valid tail node");
        self.map.remove(&node.key);
        self.free_slots.push(tail_idx);
        Some((node.key, node.value))
    }

    /// Evict and return the Most Recently Used (MRU) entry.
    pub fn pop_mru(&mut self) -> Option<(K, V)> {
        let head_idx = self.head?;
        self.detach(head_idx);
        let node = self.nodes[head_idx].take().expect("valid head node");
        self.map.remove(&node.key);
        self.free_slots.push(head_idx);
        Some((node.key, node.value))
    }

    /// Return an iterator visiting items in order from MRU (head) to LRU (tail).
    pub fn iter(&self) -> LruIter<'_, K, V> {
        LruIter {
            cache: self,
            curr: self.head,
        }
    }

    /// Return an iterator visiting keys in order from MRU (head) to LRU (tail).
    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.iter().map(|(k, _)| k)
    }

    /// Return an iterator visiting values in order from MRU (head) to LRU (tail).
    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.iter().map(|(_, v)| v)
    }

    // --- Internal doubly linked list utilities ---

    fn detach(&mut self, idx: usize) {
        let (prev, next) = {
            let node = self.nodes[idx].as_ref().expect("node exists");
            (node.prev, node.next)
        };

        if let Some(p) = prev {
            if let Some(p_node) = self.nodes[p].as_mut() {
                p_node.next = next;
            }
        } else {
            self.head = next;
        }

        if let Some(n) = next {
            if let Some(n_node) = self.nodes[n].as_mut() {
                n_node.prev = prev;
            }
        } else {
            self.tail = prev;
        }

        if let Some(node) = self.nodes[idx].as_mut() {
            node.prev = None;
            node.next = None;
        }
    }

    fn attach_head(&mut self, idx: usize) {
        let old_head = self.head;
        if let Some(node) = self.nodes[idx].as_mut() {
            node.prev = None;
            node.next = old_head;
        }

        if let Some(h) = old_head {
            if let Some(h_node) = self.nodes[h].as_mut() {
                h_node.prev = Some(idx);
            }
        } else {
            self.tail = Some(idx);
        }

        self.head = Some(idx);
    }

    fn move_to_head(&mut self, idx: usize) {
        if self.head == Some(idx) {
            return;
        }
        self.detach(idx);
        self.attach_head(idx);
    }
}

/// Iterator over entries of an [`LruCache`] from Most Recently Used to Least Recently Used.
pub struct LruIter<'a, K: Ord + Clone, V> {
    cache: &'a LruCache<K, V>,
    curr: Option<usize>,
}

impl<'a, K: Ord + Clone, V> Iterator for LruIter<'a, K, V> {
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        let idx = self.curr?;
        let node = self.cache.nodes.get(idx)?.as_ref()?;
        self.curr = node.next;
        Some((&node.key, &node.value))
    }
}

impl<K: Ord + Clone + PartialEq, V: PartialEq> PartialEq for LruCache<K, V> {
    fn eq(&self, other: &Self) -> bool {
        if self.capacity != other.capacity || self.len() != other.len() {
            return false;
        }
        self.iter().eq(other.iter())
    }
}

impl<K: Ord + Clone + Eq, V: Eq> Eq for LruCache<K, V> {}

impl<K: Ord + Clone, V> IntoIterator for LruCache<K, V> {
    type Item = (K, V);
    type IntoIter = LruIntoIter<K, V>;

    fn into_iter(self) -> Self::IntoIter {
        LruIntoIter { cache: self }
    }
}

/// Consuming iterator over entries of an [`LruCache`] from Most Recently Used to Least Recently Used.
pub struct LruIntoIter<K: Ord + Clone, V> {
    cache: LruCache<K, V>,
}

impl<K: Ord + Clone, V> Iterator for LruIntoIter<K, V> {
    type Item = (K, V);

    fn next(&mut self) -> Option<Self::Item> {
        self.cache.pop_mru()
    }
}

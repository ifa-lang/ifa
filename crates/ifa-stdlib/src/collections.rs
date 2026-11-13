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
//! - `BitSet`: Compact, deterministic bit vector for set operations and compiler dataflow analysis.

use std::collections::{btree_map, btree_set, BTreeMap, BTreeSet};
use std::fmt;
use std::ops::{
    BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Index, IndexMut, Not, Sub,
    SubAssign,
};

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

/// Errors encountered during bit set operations, parsing, or conversions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BitSetError {
    /// Encountered an invalid bit character (expected '0' or '1').
    InvalidCharacter { pos: usize, ch: char },
    /// Insufficient bytes provided to construct the requested bit set length.
    InsufficientBytes { required: usize, provided: usize },
}

impl fmt::Display for BitSetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCharacter { pos, ch } => {
                write!(f, "invalid bit character '{ch}' at position {pos}")
            }
            Self::InsufficientBytes { required, provided } => {
                write!(
                    f,
                    "insufficient bytes: required {required}, provided {provided}"
                )
            }
        }
    }
}

impl std::error::Error for BitSetError {}

/// Compact, deterministic bit vector (`BitSet`) for high-performance set operations,
/// compiler dataflow analysis (liveness, reaching definitions), and dense boolean arrays.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct BitSet {
    words: Vec<u64>,
    nbits: usize,
}

impl BitSet {
    const BITS_PER_WORD: usize = 64;

    /// Create an empty bit set with 0 bits.
    pub const fn new() -> Self {
        Self {
            words: Vec::new(),
            nbits: 0,
        }
    }

    /// Create an empty bit set pre-allocated for at least `bits` bits.
    pub fn with_capacity(bits: usize) -> Self {
        let num_words = bits.div_ceil(Self::BITS_PER_WORD);
        Self {
            words: Vec::with_capacity(num_words),
            nbits: 0,
        }
    }

    /// Create a bit set of `len` bits initialized to `val`.
    pub fn repeat(val: bool, len: usize) -> Self {
        let num_words = len.div_ceil(Self::BITS_PER_WORD);
        let word_val = if val { !0u64 } else { 0u64 };
        let mut set = Self {
            words: vec![word_val; num_words],
            nbits: len,
        };
        set.sanitize_unused_bits();
        set
    }

    /// Construct a bit set from a little-endian byte slice of `len` bits.
    pub fn from_bytes(bytes: &[u8], len: usize) -> Result<Self, BitSetError> {
        let required = len.div_ceil(8);
        if bytes.len() < required {
            return Err(BitSetError::InsufficientBytes {
                required,
                provided: bytes.len(),
            });
        }

        let num_words = len.div_ceil(Self::BITS_PER_WORD);
        let mut words = Vec::with_capacity(num_words);
        for chunk in bytes[..required].chunks(8) {
            let mut le_chunk = [0u8; 8];
            le_chunk[..chunk.len()].copy_from_slice(chunk);
            words.push(u64::from_le_bytes(le_chunk));
        }
        words.resize(num_words, 0);

        let mut set = Self { words, nbits: len };
        set.sanitize_unused_bits();
        Ok(set)
    }

    /// Parse a bit set from an ASCII binary string (e.g. `"10110"`).
    ///
    /// The bit at index `i` corresponds to character `i`.
    pub fn from_bit_string(s: &str) -> Result<Self, BitSetError> {
        let mut set = Self::with_capacity(s.len());
        for (i, ch) in s.char_indices() {
            match ch {
                '0' => {}
                '1' => {
                    set.insert(i);
                }
                _ => return Err(BitSetError::InvalidCharacter { pos: i, ch }),
            }
        }
        set.nbits = s.len();
        set.sanitize_unused_bits();
        Ok(set)
    }

    /// Return the logical length in bits.
    pub fn len(&self) -> usize {
        self.nbits
    }

    /// Check if the bit set contains 0 bits.
    pub fn is_empty(&self) -> bool {
        self.nbits == 0
    }

    /// Return allocated capacity in bits.
    pub fn capacity(&self) -> usize {
        self.words.len() * Self::BITS_PER_WORD
    }

    /// Check if bit at index `bit` is set to 1.
    pub fn contains(&self, bit: usize) -> bool {
        if bit >= self.nbits {
            return false;
        }
        let word_idx = bit / Self::BITS_PER_WORD;
        let bit_idx = bit % Self::BITS_PER_WORD;
        (self.words[word_idx] & (1u64 << bit_idx)) != 0
    }

    /// Get value of bit at index `bit`, or `None` if out of bounds.
    pub fn get(&self, bit: usize) -> Option<bool> {
        if bit < self.nbits {
            Some(self.contains(bit))
        } else {
            None
        }
    }

    /// Set bit at index `bit` to 1. Expands length if `bit >= self.len()`.
    ///
    /// Returns `true` if the bit was not previously set.
    pub fn insert(&mut self, bit: usize) -> bool {
        if bit >= self.nbits {
            self.nbits = bit + 1;
            self.ensure_capacity(self.nbits);
        }
        let word_idx = bit / Self::BITS_PER_WORD;
        let bit_idx = bit % Self::BITS_PER_WORD;
        let mask = 1u64 << bit_idx;
        let prev = (self.words[word_idx] & mask) != 0;
        self.words[word_idx] |= mask;
        !prev
    }

    /// Reset bit at index `bit` to 0. Returns `true` if bit was previously set.
    pub fn remove(&mut self, bit: usize) -> bool {
        if bit >= self.nbits {
            return false;
        }
        let word_idx = bit / Self::BITS_PER_WORD;
        let bit_idx = bit % Self::BITS_PER_WORD;
        let mask = 1u64 << bit_idx;
        let prev = (self.words[word_idx] & mask) != 0;
        self.words[word_idx] &= !mask;
        prev
    }

    /// Toggle bit at index `bit`. Expands length if `bit >= self.len()`.
    ///
    /// Returns the new state of the bit.
    pub fn toggle(&mut self, bit: usize) -> bool {
        if bit >= self.nbits {
            self.nbits = bit + 1;
            self.ensure_capacity(self.nbits);
        }
        let word_idx = bit / Self::BITS_PER_WORD;
        let bit_idx = bit % Self::BITS_PER_WORD;
        let mask = 1u64 << bit_idx;
        self.words[word_idx] ^= mask;
        (self.words[word_idx] & mask) != 0
    }

    /// Set bit at index `bit` to `val`.
    pub fn set(&mut self, bit: usize, val: bool) {
        if val {
            self.insert(bit);
        } else if bit < self.nbits {
            self.remove(bit);
        }
    }

    /// Clear all bits to 0 without altering logical length.
    pub fn clear(&mut self) {
        self.words.fill(0);
    }

    /// Fill all bits up to `len()` with `val`.
    pub fn fill(&mut self, val: bool) {
        let w_val = if val { !0u64 } else { 0u64 };
        self.words.fill(w_val);
        self.sanitize_unused_bits();
    }

    /// Truncate bit set to `new_len` bits.
    pub fn truncate(&mut self, new_len: usize) {
        if new_len < self.nbits {
            self.nbits = new_len;
            let req_words = new_len.div_ceil(Self::BITS_PER_WORD);
            self.words.truncate(req_words);
            self.sanitize_unused_bits();
        }
    }

    /// Resize bit set to `new_len` bits, filling newly added bits with `val`.
    pub fn resize(&mut self, new_len: usize, val: bool) {
        if new_len < self.nbits {
            self.truncate(new_len);
        } else if new_len > self.nbits {
            let old_len = self.nbits;
            self.nbits = new_len;
            let new_words = new_len.div_ceil(Self::BITS_PER_WORD);
            self.words.resize(new_words, 0);
            if val {
                for i in old_len..new_len {
                    let w = i / Self::BITS_PER_WORD;
                    let b = i % Self::BITS_PER_WORD;
                    self.words[w] |= 1u64 << b;
                }
            }
            self.sanitize_unused_bits();
        }
    }

    /// Return the total number of set bits (popcount).
    pub fn count_ones(&self) -> usize {
        self.words.iter().map(|&w| w.count_ones() as usize).sum()
    }

    /// Return the total number of clear bits (zeros).
    pub fn count_zeros(&self) -> usize {
        self.nbits.saturating_sub(self.count_ones())
    }

    /// Check if all bits are set to 1 (returns `false` if empty).
    pub fn all(&self) -> bool {
        !self.is_empty() && self.count_ones() == self.nbits
    }

    /// Check if at least one bit is set to 1.
    pub fn any(&self) -> bool {
        self.words.iter().any(|&w| w != 0)
    }

    /// Check if no bits are set to 1.
    pub fn none(&self) -> bool {
        !self.any()
    }

    /// In-place bitwise union with another bit set (`self |= other`).
    pub fn union_with(&mut self, other: &Self) {
        let max_len = std::cmp::max(self.nbits, other.nbits);
        self.ensure_capacity(max_len);
        self.nbits = max_len;
        for (i, &w) in other.words.iter().enumerate() {
            self.words[i] |= w;
        }
        self.sanitize_unused_bits();
    }

    /// In-place bitwise intersection with another bit set (`self &= other`).
    pub fn intersect_with(&mut self, other: &Self) {
        let min_len = std::cmp::min(self.nbits, other.nbits);
        self.nbits = min_len;
        let req_words = min_len.div_ceil(Self::BITS_PER_WORD);
        self.words.truncate(req_words);
        let common = std::cmp::min(self.words.len(), other.words.len());
        for i in 0..common {
            self.words[i] &= other.words[i];
        }
        for i in common..self.words.len() {
            self.words[i] = 0;
        }
        self.sanitize_unused_bits();
    }

    /// In-place bitwise difference with another bit set (`self &= !other`).
    pub fn difference_with(&mut self, other: &Self) {
        let common = std::cmp::min(self.words.len(), other.words.len());
        for i in 0..common {
            self.words[i] &= !other.words[i];
        }
        self.sanitize_unused_bits();
    }

    /// In-place bitwise symmetric difference with another bit set (`self ^= other`).
    pub fn symmetric_difference_with(&mut self, other: &Self) {
        let max_len = std::cmp::max(self.nbits, other.nbits);
        self.ensure_capacity(max_len);
        self.nbits = max_len;
        for (i, &w) in other.words.iter().enumerate() {
            self.words[i] ^= w;
        }
        self.sanitize_unused_bits();
    }

    /// Check if `self` and `other` have no set bits in common.
    pub fn is_disjoint(&self, other: &Self) -> bool {
        let common = std::cmp::min(self.words.len(), other.words.len());
        self.words[..common]
            .iter()
            .zip(&other.words[..common])
            .all(|(&a, &b)| (a & b) == 0)
    }

    /// Check if all set bits of `self` are also set in `other`.
    pub fn is_subset(&self, other: &Self) -> bool {
        for (i, &w) in self.words.iter().enumerate() {
            if i < other.words.len() {
                if (w & !other.words[i]) != 0 {
                    return false;
                }
            } else if w != 0 {
                return false;
            }
        }
        true
    }

    /// Check if all set bits of `other` are also set in `self`.
    pub fn is_superset(&self, other: &Self) -> bool {
        other.is_subset(self)
    }

    /// Deterministic iterator over the indices of set bits in ascending order.
    pub fn ones(&self) -> BitSetIter<'_> {
        BitSetIter {
            words: &self.words,
            word_idx: 0,
            curr_word: 0,
        }
    }

    /// Alias for [`BitSet::ones`].
    pub fn iter(&self) -> BitSetIter<'_> {
        self.ones()
    }

    /// Export bit set to little-endian bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let num_bytes = self.nbits.div_ceil(8);
        let mut out = Vec::with_capacity(num_bytes);
        for &w in &self.words {
            let bytes = w.to_le_bytes();
            for b in bytes {
                if out.len() < num_bytes {
                    out.push(b);
                } else {
                    break;
                }
            }
        }
        out
    }

    /// Convert bit set to an ASCII binary string (e.g. `"10110"`).
    pub fn to_bit_string(&self) -> String {
        let mut s = String::with_capacity(self.nbits);
        for i in 0..self.nbits {
            if self.contains(i) {
                s.push('1');
            } else {
                s.push('0');
            }
        }
        s
    }

    fn ensure_capacity(&mut self, required_bits: usize) {
        let req_words = required_bits.div_ceil(Self::BITS_PER_WORD);
        if self.words.len() < req_words {
            self.words.resize(req_words, 0);
        }
    }

    fn sanitize_unused_bits(&mut self) {
        let rem = self.nbits % Self::BITS_PER_WORD;
        if rem != 0 {
            if let Some(last) = self.words.last_mut() {
                let mask = (1u64 << rem) - 1;
                *last &= mask;
            }
        }
    }
}

/// Deterministic iterator yielding the indices of set bits (ones) in ascending order.
#[derive(Debug, Clone)]
pub struct BitSetIter<'a> {
    words: &'a [u64],
    word_idx: usize,
    curr_word: u64,
}

impl<'a> Iterator for BitSetIter<'a> {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        while self.curr_word == 0 {
            if self.word_idx >= self.words.len() {
                return None;
            }
            self.curr_word = self.words[self.word_idx];
            self.word_idx += 1;
        }

        let bit_in_word = self.curr_word.trailing_zeros() as usize;
        self.curr_word &= self.curr_word.wrapping_sub(1);
        let absolute_idx = (self.word_idx - 1) * BitSet::BITS_PER_WORD + bit_in_word;
        Some(absolute_idx)
    }
}

impl<'a> IntoIterator for &'a BitSet {
    type Item = usize;
    type IntoIter = BitSetIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.ones()
    }
}

impl Index<usize> for BitSet {
    type Output = bool;

    fn index(&self, index: usize) -> &Self::Output {
        static TRUE: bool = true;
        static FALSE: bool = false;
        if index >= self.nbits {
            panic!(
                "index out of bounds: the len is {} but the index is {}",
                self.nbits, index
            );
        }
        if self.contains(index) {
            &TRUE
        } else {
            &FALSE
        }
    }
}

impl FromIterator<usize> for BitSet {
    fn from_iter<T: IntoIterator<Item = usize>>(iter: T) -> Self {
        let mut set = Self::new();
        for item in iter {
            set.insert(item);
        }
        set
    }
}

impl Extend<usize> for BitSet {
    fn extend<T: IntoIterator<Item = usize>>(&mut self, iter: T) {
        for item in iter {
            self.insert(item);
        }
    }
}

impl BitOr for &BitSet {
    type Output = BitSet;

    fn bitor(self, rhs: Self) -> Self::Output {
        let mut res = self.clone();
        res.union_with(rhs);
        res
    }
}

impl BitOr for BitSet {
    type Output = BitSet;

    fn bitor(mut self, rhs: Self) -> Self::Output {
        self.union_with(&rhs);
        self
    }
}

impl BitOrAssign<&BitSet> for BitSet {
    fn bitor_assign(&mut self, rhs: &BitSet) {
        self.union_with(rhs);
    }
}

impl BitAnd for &BitSet {
    type Output = BitSet;

    fn bitand(self, rhs: Self) -> Self::Output {
        let mut res = self.clone();
        res.intersect_with(rhs);
        res
    }
}

impl BitAnd for BitSet {
    type Output = BitSet;

    fn bitand(mut self, rhs: Self) -> Self::Output {
        self.intersect_with(&rhs);
        self
    }
}

impl BitAndAssign<&BitSet> for BitSet {
    fn bitand_assign(&mut self, rhs: &BitSet) {
        self.intersect_with(rhs);
    }
}

impl BitXor for &BitSet {
    type Output = BitSet;

    fn bitxor(self, rhs: Self) -> Self::Output {
        let mut res = self.clone();
        res.symmetric_difference_with(rhs);
        res
    }
}

impl BitXor for BitSet {
    type Output = BitSet;

    fn bitxor(mut self, rhs: Self) -> Self::Output {
        self.symmetric_difference_with(&rhs);
        self
    }
}

impl BitXorAssign<&BitSet> for BitSet {
    fn bitxor_assign(&mut self, rhs: &BitSet) {
        self.symmetric_difference_with(rhs);
    }
}

impl Sub for &BitSet {
    type Output = BitSet;

    fn sub(self, rhs: Self) -> Self::Output {
        let mut res = self.clone();
        res.difference_with(rhs);
        res
    }
}

impl Sub for BitSet {
    type Output = BitSet;

    fn sub(mut self, rhs: Self) -> Self::Output {
        self.difference_with(&rhs);
        self
    }
}

impl SubAssign<&BitSet> for BitSet {
    fn sub_assign(&mut self, rhs: &BitSet) {
        self.difference_with(rhs);
    }
}

impl Not for &BitSet {
    type Output = BitSet;

    fn not(self) -> Self::Output {
        let mut res = self.clone();
        for w in &mut res.words {
            *w = !*w;
        }
        res.sanitize_unused_bits();
        res
    }
}

impl Not for BitSet {
    type Output = BitSet;

    fn not(mut self) -> Self::Output {
        for w in &mut self.words {
            *w = !*w;
        }
        self.sanitize_unused_bits();
        self
    }
}

impl fmt::Display for BitSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BitSet({}/{} bits: [", self.count_ones(), self.nbits)?;
        let mut first = true;
        for idx in self.ones() {
            if !first {
                write!(f, ", ")?;
            }
            write!(f, "{idx}")?;
            first = false;
        }
        write!(f, "])")
    }
}

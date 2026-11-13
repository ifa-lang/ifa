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
//! - `DisjointSet<T>`: Deterministic Union-Find forest with path compression and union by rank.
//! - `DirectedGraph<N, E>`: Deterministic directed graph for dependency resolution, DAG scheduling and SCC.
//! - `Trie<V>`: Deterministic prefix tree for ordered string indexing, predictive search and prefix matching.
//! - `TrieSet`: Deterministic prefix-based unique string set with autocompletion and longest-prefix resolution.
//! - `Interval<T>`: Half-open interval `[start, end)` with span, overlap and containment logic.
//! - `IntervalMap<K, V>`: Deterministic augmented AVL interval tree for fast overlap and point queries.
//! - `IntervalSet<K>`: Deterministic set of intervals with contiguous merging and collision testing.

use std::collections::{btree_map, btree_set, BTreeMap, BTreeSet, VecDeque};
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

/// Deterministic Disjoint-Set forest (Union-Find) with path compression and union by rank.
///
/// Guaranteed bit-by-bit reproducible ordering via lexicographic BTree mapping.
/// Used for compiler dataflow alias analysis, type unification, connected component
/// detection, and memory arena co-allocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisjointSet<T: Ord + Clone> {
    parent: BTreeMap<T, T>,
    rank: BTreeMap<T, usize>,
    size: BTreeMap<T, usize>,
    count: usize,
}

impl<T: Ord + Clone> Default for DisjointSet<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Ord + Clone> DisjointSet<T> {
    /// Create an empty disjoint-set forest.
    pub fn new() -> Self {
        Self {
            parent: BTreeMap::new(),
            rank: BTreeMap::new(),
            size: BTreeMap::new(),
            count: 0,
        }
    }

    /// Create a disjoint-set forest initialized with elements as distinct singletons.
    pub fn with_elements<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let mut ds = Self::new();
        for item in iter {
            ds.insert(item);
        }
        ds
    }

    /// Returns `true` if the disjoint-set contains no elements.
    pub fn is_empty(&self) -> bool {
        self.parent.is_empty()
    }

    /// Total number of elements across all disjoint sets.
    pub fn len(&self) -> usize {
        self.parent.len()
    }

    /// Total number of distinct connected components (disjoint sets).
    pub fn set_count(&self) -> usize {
        self.count
    }

    /// Returns `true` if `elem` is tracked in the disjoint-set forest.
    pub fn contains(&self, elem: &T) -> bool {
        self.parent.contains_key(elem)
    }

    /// Insert an element as a new singleton set if not already present.
    ///
    /// Returns `true` if the element was newly added, or `false` if it already exists.
    pub fn insert(&mut self, elem: T) -> bool {
        if self.parent.contains_key(&elem) {
            return false;
        }
        self.parent.insert(elem.clone(), elem.clone());
        self.rank.insert(elem.clone(), 0);
        self.size.insert(elem, 1);
        self.count += 1;
        true
    }

    /// Find the canonical representative (root) of the set containing `elem`,
    /// applying two-pass path compression for near-constant amortized time complexity O(α(N)).
    ///
    /// Returns `None` if `elem` is not present in the disjoint-set forest.
    pub fn find(&mut self, elem: &T) -> Option<T> {
        if !self.parent.contains_key(elem) {
            return None;
        }

        // Pass 1: Find root
        let mut root = elem.clone();
        while let Some(p) = self.parent.get(&root) {
            if p == &root {
                break;
            }
            root = p.clone();
        }

        // Pass 2: Path compression (flatten tree towards root)
        let mut curr = elem.clone();
        while let Some(p) = self.parent.get(&curr).cloned() {
            if p == root {
                break;
            }
            self.parent.insert(curr, root.clone());
            curr = p;
        }

        Some(root)
    }

    /// Find the canonical representative of `elem`, inserting `elem` as a new singleton if absent.
    pub fn find_or_insert(&mut self, elem: T) -> T {
        if !self.parent.contains_key(&elem) {
            self.insert(elem.clone());
            elem
        } else {
            self.find(&elem).unwrap_or(elem)
        }
    }

    /// Unify the disjoint sets containing `a` and `b` using union by rank.
    ///
    /// Returns:
    /// - `false` if `a` or `b` does not exist, or if they are already in the same set.
    /// - `true` if two previously disjoint sets were successfully merged.
    pub fn union(&mut self, a: &T, b: &T) -> bool {
        let root_a = match self.find(a) {
            Some(r) => r,
            None => return false,
        };
        let root_b = match self.find(b) {
            Some(r) => r,
            None => return false,
        };

        if root_a == root_b {
            return false;
        }

        let rank_a = self.rank.get(&root_a).copied().unwrap_or(0);
        let rank_b = self.rank.get(&root_b).copied().unwrap_or(0);
        let size_a = self.size.get(&root_a).copied().unwrap_or(1);
        let size_b = self.size.get(&root_b).copied().unwrap_or(1);

        if rank_a < rank_b {
            self.parent.insert(root_a.clone(), root_b.clone());
            self.size.insert(root_b, size_a + size_b);
            self.size.remove(&root_a);
        } else if rank_a > rank_b {
            self.parent.insert(root_b.clone(), root_a.clone());
            self.size.insert(root_a, size_a + size_b);
            self.size.remove(&root_b);
        } else {
            self.parent.insert(root_b.clone(), root_a.clone());
            self.rank.insert(root_a.clone(), rank_a + 1);
            self.size.insert(root_a, size_a + size_b);
            self.size.remove(&root_b);
        }

        self.count -= 1;
        true
    }

    /// Ensure both `a` and `b` are inserted into the disjoint set, then unite them.
    ///
    /// Returns `true` if a new union was formed, or `false` if they were already in the same set.
    pub fn union_insert(&mut self, a: T, b: T) -> bool {
        self.find_or_insert(a.clone());
        self.find_or_insert(b.clone());
        self.union(&a, &b)
    }

    /// Check if elements `a` and `b` belong to the same connected component / set.
    pub fn connected(&mut self, a: &T, b: &T) -> bool {
        match (self.find(a), self.find(b)) {
            (Some(ra), Some(rb)) => ra == rb,
            _ => false,
        }
    }

    /// Get the cardinality (number of elements) of the set containing `elem`.
    pub fn component_size(&mut self, elem: &T) -> Option<usize> {
        let root = self.find(elem)?;
        self.size.get(&root).copied()
    }

    /// Returns the deterministic set of canonical representatives (roots) of all components.
    pub fn roots(&mut self) -> BTreeSet<T> {
        let keys: Vec<T> = self.parent.keys().cloned().collect();
        let mut roots = BTreeSet::new();
        for key in keys {
            if let Some(root) = self.find(&key) {
                roots.insert(root);
            }
        }
        roots
    }

    /// Group all elements into their respective disjoint components.
    ///
    /// Returns a deterministic mapping from canonical root to all member elements.
    pub fn components(&mut self) -> BTreeMap<T, BTreeSet<T>> {
        let keys: Vec<T> = self.parent.keys().cloned().collect();
        let mut comp = BTreeMap::new();
        for key in keys {
            if let Some(root) = self.find(&key) {
                comp.entry(root).or_insert_with(BTreeSet::new).insert(key);
            }
        }
        comp
    }

    /// Clear all elements from the disjoint-set forest.
    pub fn clear(&mut self) {
        self.parent.clear();
        self.rank.clear();
        self.size.clear();
        self.count = 0;
    }
}

impl<T: Ord + Clone> FromIterator<T> for DisjointSet<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        Self::with_elements(iter)
    }
}

impl<T: Ord + Clone> Extend<T> for DisjointSet<T> {
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        for item in iter {
            self.insert(item);
        }
    }
}

impl<T: Ord + Clone> Extend<(T, T)> for DisjointSet<T> {
    fn extend<I: IntoIterator<Item = (T, T)>>(&mut self, iter: I) {
        for (a, b) in iter {
            self.union_insert(a, b);
        }
    }
}

/// Error indicating that a directed graph contains an unexpected cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CycleError<N> {
    /// Ordered list of nodes forming the cycle, if identified.
    pub cycle: Option<Vec<N>>,
}

impl<N: fmt::Debug> fmt::Display for CycleError<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref c) = self.cycle {
            write!(f, "Cycle detected in directed graph: {:?}", c)
        } else {
            write!(f, "Cycle detected in directed graph")
        }
    }
}

impl<N: fmt::Debug> std::error::Error for CycleError<N> {}

/// Unweighted deterministic directed graph.
pub type DiGraph<N> = DirectedGraph<N, ()>;

/// Deterministic directed graph (`DirectedGraph<N, E>`) with edge weights/labels.
///
/// All adjacency representations are stored in ordered B-Trees, guaranteeing bit-for-bit
/// reproducible iteration, deterministic topological sorting, and canonical cycle reporting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectedGraph<N: Ord + Clone, E: Clone = ()> {
    outgoing: BTreeMap<N, BTreeMap<N, E>>,
    incoming: BTreeMap<N, BTreeMap<N, E>>,
}

impl<N: Ord + Clone, E: Clone> Default for DirectedGraph<N, E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<N: Ord + Clone, E: Clone> DirectedGraph<N, E> {
    /// Create a new empty directed graph.
    pub fn new() -> Self {
        Self {
            outgoing: BTreeMap::new(),
            incoming: BTreeMap::new(),
        }
    }

    /// Create a directed graph initialized with the given nodes.
    pub fn with_nodes<I: IntoIterator<Item = N>>(nodes: I) -> Self {
        let mut graph = Self::new();
        for node in nodes {
            graph.add_node(node);
        }
        graph
    }

    /// Check if the graph has no nodes.
    pub fn is_empty(&self) -> bool {
        self.outgoing.is_empty()
    }

    /// Total number of nodes in the graph.
    pub fn node_count(&self) -> usize {
        self.outgoing.len()
    }

    /// Total number of directed edges in the graph.
    pub fn edge_count(&self) -> usize {
        self.outgoing.values().map(|m| m.len()).sum()
    }

    /// Check if a node is present in the graph.
    pub fn contains_node(&self, node: &N) -> bool {
        self.outgoing.contains_key(node)
    }

    /// Check if a directed edge exists from `from` to `to`.
    pub fn contains_edge(&self, from: &N, to: &N) -> bool {
        self.outgoing.get(from).is_some_and(|m| m.contains_key(to))
    }

    /// Add a node to the graph if not already present.
    ///
    /// Returns `true` if the node was newly added, or `false` if it already existed.
    pub fn add_node(&mut self, node: N) -> bool {
        if self.outgoing.contains_key(&node) {
            return false;
        }
        self.outgoing.insert(node.clone(), BTreeMap::new());
        self.incoming.insert(node, BTreeMap::new());
        true
    }

    /// Remove a node and all its incoming and outgoing edges from the graph.
    ///
    /// Returns `true` if the node was removed, or `false` if it was not present.
    pub fn remove_node(&mut self, node: &N) -> bool {
        if !self.contains_node(node) {
            return false;
        }

        // Remove outgoing edges from this node from predecessors' incoming lists
        if let Some(succs) = self.outgoing.remove(node) {
            for (succ, _) in succs {
                if let Some(succ_in) = self.incoming.get_mut(&succ) {
                    succ_in.remove(node);
                }
            }
        }

        // Remove incoming edges to this node from predecessors' outgoing lists
        if let Some(preds) = self.incoming.remove(node) {
            for (pred, _) in preds {
                if let Some(pred_out) = self.outgoing.get_mut(&pred) {
                    pred_out.remove(node);
                }
            }
        }

        true
    }

    /// Add a directed edge from `from` to `to` with weight `weight`.
    ///
    /// Automatically adds `from` and `to` nodes if they do not yet exist.
    /// Returns previous edge weight if the edge already existed.
    pub fn add_edge(&mut self, from: N, to: N, weight: E) -> Option<E> {
        self.add_node(from.clone());
        self.add_node(to.clone());

        self.incoming
            .get_mut(&to)
            .unwrap()
            .insert(from.clone(), weight.clone());
        self.outgoing.get_mut(&from).unwrap().insert(to, weight)
    }

    /// Remove a directed edge from `from` to `to`.
    ///
    /// Returns the removed edge weight, or `None` if the edge was not present.
    pub fn remove_edge(&mut self, from: &N, to: &N) -> Option<E> {
        let prev = self.outgoing.get_mut(from)?.remove(to);
        if prev.is_some() {
            if let Some(to_in) = self.incoming.get_mut(to) {
                to_in.remove(from);
            }
        }
        prev
    }

    /// Get a reference to the weight of the directed edge from `from` to `to`.
    pub fn edge_weight(&self, from: &N, to: &N) -> Option<&E> {
        self.outgoing.get(from)?.get(to)
    }

    /// Get a mutable reference to the weight of the directed edge from `from` to `to`.
    pub fn edge_weight_mut(&mut self, from: &N, to: &N) -> Option<&mut E> {
        self.outgoing.get_mut(from)?.get_mut(to)
    }

    /// Iterator over references to all nodes in deterministic ascending order.
    pub fn nodes(&self) -> btree_map::Keys<'_, N, BTreeMap<N, E>> {
        self.outgoing.keys()
    }

    /// Set of all nodes in the graph.
    pub fn nodes_set(&self) -> BTreeSet<N> {
        self.outgoing.keys().cloned().collect()
    }

    /// Return all directed edges `(from, to, weight)` in deterministic order.
    pub fn edges(&self) -> Vec<(&N, &N, &E)> {
        let mut list = Vec::with_capacity(self.edge_count());
        for (from, targets) in &self.outgoing {
            for (to, weight) in targets {
                list.push((from, to, weight));
            }
        }
        list
    }

    /// In-degree (number of incoming directed edges) of `node`.
    pub fn in_degree(&self, node: &N) -> usize {
        self.incoming.get(node).map_or(0, |m| m.len())
    }

    /// Out-degree (number of outgoing directed edges) of `node`.
    pub fn out_degree(&self, node: &N) -> usize {
        self.outgoing.get(node).map_or(0, |m| m.len())
    }

    /// Successors of `node` as a map of target node to edge weight.
    pub fn successors(&self, node: &N) -> Option<&BTreeMap<N, E>> {
        self.outgoing.get(node)
    }

    /// Predecessors of `node` as a map of source node to edge weight.
    pub fn predecessors(&self, node: &N) -> Option<&BTreeMap<N, E>> {
        self.incoming.get(node)
    }

    /// Deterministic list of source nodes (in-degree == 0), sorted in ascending order.
    pub fn sources(&self) -> Vec<N> {
        self.nodes()
            .filter(|n| self.in_degree(n) == 0)
            .cloned()
            .collect()
    }

    /// Deterministic list of sink nodes (out-degree == 0), sorted in ascending order.
    pub fn sinks(&self) -> Vec<N> {
        self.nodes()
            .filter(|n| self.out_degree(n) == 0)
            .cloned()
            .collect()
    }

    /// Compute a deterministic topological ordering of all nodes using Kahn's algorithm.
    ///
    /// If multiple nodes have in-degree 0 at any step, the lexicographically smallest
    /// node (according to `Ord`) is dequeued first, guaranteeing bit-for-bit reproducibility.
    ///
    /// Returns `Ok(ordered_nodes)` or `Err(CycleError)` if the graph contains at least one cycle.
    pub fn topological_sort(&self) -> Result<Vec<N>, CycleError<N>> {
        let mut in_degrees: BTreeMap<N, usize> = BTreeMap::new();
        for node in self.nodes() {
            in_degrees.insert(node.clone(), self.in_degree(node));
        }

        let mut zero_in_degree: BTreeSet<N> = BTreeSet::new();
        for (node, &deg) in &in_degrees {
            if deg == 0 {
                zero_in_degree.insert(node.clone());
            }
        }

        let mut order = Vec::with_capacity(self.node_count());

        while let Some(node) = zero_in_degree.iter().next().cloned() {
            zero_in_degree.remove(&node);
            order.push(node.clone());

            if let Some(succs) = self.successors(&node) {
                for next in succs.keys() {
                    let deg = in_degrees.get_mut(next).unwrap();
                    *deg -= 1;
                    if *deg == 0 {
                        zero_in_degree.insert(next.clone());
                    }
                }
            }
        }

        if order.len() == self.node_count() {
            Ok(order)
        } else {
            Err(CycleError {
                cycle: self.find_cycle(),
            })
        }
    }

    /// Check if the directed graph contains any cycles.
    pub fn has_cycle(&self) -> bool {
        self.topological_sort().is_err()
    }

    /// Search for a directed cycle in the graph.
    ///
    /// If a cycle exists, returns `Some(vec![n1, n2, ..., nk, n1])`.
    /// Otherwise returns `None`.
    pub fn find_cycle(&self) -> Option<Vec<N>> {
        #[derive(Copy, Clone, PartialEq, Eq)]
        enum Color {
            White,
            Gray,
            Black,
        }

        struct DfsContext<'a, N: Ord + Clone, E: Clone> {
            graph: &'a DirectedGraph<N, E>,
            colors: BTreeMap<N, Color>,
            path: Vec<N>,
            cycle: Option<Vec<N>>,
        }

        impl<'a, N: Ord + Clone, E: Clone> DfsContext<'a, N, E> {
            fn dfs(&mut self, u: N) -> bool {
                self.colors.insert(u.clone(), Color::Gray);
                self.path.push(u.clone());

                if let Some(succs) = self.graph.successors(&u) {
                    for v in succs.keys() {
                        match self.colors.get(v).copied().unwrap_or(Color::White) {
                            Color::Gray => {
                                if let Some(pos) = self.path.iter().position(|x| x == v) {
                                    let mut c = self.path[pos..].to_vec();
                                    c.push(v.clone());
                                    self.cycle = Some(c);
                                    return true;
                                }
                            }
                            Color::White => {
                                if self.dfs(v.clone()) {
                                    return true;
                                }
                            }
                            Color::Black => {}
                        }
                    }
                }

                self.path.pop();
                self.colors.insert(u, Color::Black);
                false
            }
        }

        let mut ctx = DfsContext {
            graph: self,
            colors: BTreeMap::new(),
            path: Vec::new(),
            cycle: None,
        };

        for node in self.nodes() {
            if ctx.colors.get(node).copied().unwrap_or(Color::White) == Color::White
                && ctx.dfs(node.clone())
            {
                return ctx.cycle;
            }
        }

        None
    }

    /// Compute Strongly Connected Components (SCC) using Tarjan's algorithm.
    ///
    /// Returns the components ordered deterministically, where each component
    /// is represented as a deterministic set of its nodes.
    pub fn strongly_connected_components(&self) -> Vec<BTreeSet<N>> {
        struct TarjanContext<'a, N: Ord + Clone, E: Clone> {
            graph: &'a DirectedGraph<N, E>,
            index: usize,
            indices: BTreeMap<N, usize>,
            lowlink: BTreeMap<N, usize>,
            on_stack: BTreeSet<N>,
            stack: Vec<N>,
            sccs: Vec<BTreeSet<N>>,
        }

        impl<'a, N: Ord + Clone, E: Clone> TarjanContext<'a, N, E> {
            fn strongconnect(&mut self, v: N) {
                self.indices.insert(v.clone(), self.index);
                self.lowlink.insert(v.clone(), self.index);
                self.index += 1;
                self.stack.push(v.clone());
                self.on_stack.insert(v.clone());

                if let Some(succs) = self.graph.successors(&v) {
                    for w in succs.keys() {
                        if !self.indices.contains_key(w) {
                            self.strongconnect(w.clone());
                            let w_low = self.lowlink[w];
                            let v_low = self.lowlink.get_mut(&v).unwrap();
                            *v_low = (*v_low).min(w_low);
                        } else if self.on_stack.contains(w) {
                            let w_idx = self.indices[w];
                            let v_low = self.lowlink.get_mut(&v).unwrap();
                            *v_low = (*v_low).min(w_idx);
                        }
                    }
                }

                if self.lowlink[&v] == self.indices[&v] {
                    let mut scc = BTreeSet::new();
                    while let Some(w) = self.stack.pop() {
                        self.on_stack.remove(&w);
                        let is_v = w == v;
                        scc.insert(w);
                        if is_v {
                            break;
                        }
                    }
                    self.sccs.push(scc);
                }
            }
        }

        let mut ctx = TarjanContext {
            graph: self,
            index: 0,
            indices: BTreeMap::new(),
            lowlink: BTreeMap::new(),
            on_stack: BTreeSet::new(),
            stack: Vec::new(),
            sccs: Vec::new(),
        };

        for node in self.nodes() {
            if !ctx.indices.contains_key(node) {
                ctx.strongconnect(node.clone());
            }
        }

        ctx.sccs
    }

    /// Find all nodes reachable from `start` via directed edges.
    pub fn reachable_from(&self, start: &N) -> BTreeSet<N> {
        let mut visited = BTreeSet::new();
        if !self.contains_node(start) {
            return visited;
        }

        let mut queue = VecDeque::new();
        visited.insert(start.clone());
        queue.push_back(start.clone());

        while let Some(curr) = queue.pop_front() {
            if let Some(succs) = self.successors(&curr) {
                for next in succs.keys() {
                    if visited.insert(next.clone()) {
                        queue.push_back(next.clone());
                    }
                }
            }
        }

        visited
    }

    /// Check if `to` is reachable from `from` along directed edges.
    pub fn is_reachable(&self, from: &N, to: &N) -> bool {
        if from == to {
            return self.contains_node(from);
        }
        self.reachable_from(from).contains(to)
    }

    /// Find the shortest unweighted path from `start` to `goal` using Breadth-First Search (BFS).
    ///
    /// Returns `Some([start, ..., goal])` if a path exists, or `None`.
    pub fn shortest_path(&self, start: &N, goal: &N) -> Option<Vec<N>> {
        if !self.contains_node(start) || !self.contains_node(goal) {
            return None;
        }
        if start == goal {
            return Some(vec![start.clone()]);
        }

        let mut visited = BTreeSet::new();
        let mut queue = VecDeque::new();
        let mut parent: BTreeMap<N, N> = BTreeMap::new();

        visited.insert(start.clone());
        queue.push_back(start.clone());

        while let Some(curr) = queue.pop_front() {
            if curr == *goal {
                break;
            }
            if let Some(succs) = self.successors(&curr) {
                for next in succs.keys() {
                    if visited.insert(next.clone()) {
                        parent.insert(next.clone(), curr.clone());
                        queue.push_back(next.clone());
                    }
                }
            }
        }

        if !visited.contains(goal) {
            return None;
        }

        let mut path = Vec::new();
        let mut curr = goal.clone();
        path.push(curr.clone());
        while let Some(p) = parent.get(&curr) {
            path.push(p.clone());
            if p == start {
                break;
            }
            curr = p.clone();
        }
        path.reverse();
        Some(path)
    }

    /// Create the transpose (reverse) graph where every directed edge `(u, v)` is reversed to `(v, u)`.
    pub fn transpose(&self) -> Self {
        Self {
            outgoing: self.incoming.clone(),
            incoming: self.outgoing.clone(),
        }
    }

    /// Clear all nodes and edges from the directed graph.
    pub fn clear(&mut self) {
        self.outgoing.clear();
        self.incoming.clear();
    }
}

impl<N: Ord + Clone> DirectedGraph<N, ()> {
    /// Add an unweighted directed edge from `from` to `to`.
    pub fn add_unweighted_edge(&mut self, from: N, to: N) -> bool {
        self.add_edge(from, to, ()).is_none()
    }

    /// Add an unweighted directed edge from `from` to `to` (ergonomic alias).
    pub fn add_edge_unweighted(&mut self, from: N, to: N) -> bool {
        self.add_unweighted_edge(from, to)
    }
}

impl<N: Ord + Clone, E: Clone> FromIterator<(N, N, E)> for DirectedGraph<N, E> {
    fn from_iter<I: IntoIterator<Item = (N, N, E)>>(iter: I) -> Self {
        let mut graph = Self::new();
        for (u, v, w) in iter {
            graph.add_edge(u, v, w);
        }
        graph
    }
}

impl<N: Ord + Clone> FromIterator<(N, N)> for DirectedGraph<N, ()> {
    fn from_iter<I: IntoIterator<Item = (N, N)>>(iter: I) -> Self {
        let mut graph = Self::new();
        for (u, v) in iter {
            graph.add_edge(u, v, ());
        }
        graph
    }
}

impl<N: Ord + Clone, E: Clone> Extend<(N, N, E)> for DirectedGraph<N, E> {
    fn extend<I: IntoIterator<Item = (N, N, E)>>(&mut self, iter: I) {
        for (u, v, w) in iter {
            self.add_edge(u, v, w);
        }
    }
}

impl<N: Ord + Clone> Extend<(N, N)> for DirectedGraph<N, ()> {
    fn extend<I: IntoIterator<Item = (N, N)>>(&mut self, iter: I) {
        for (u, v) in iter {
            self.add_edge(u, v, ());
        }
    }
}

/// Deterministic Prefix Tree (Trie) for associative string prefix indexing and lookup.
///
/// Uses deterministic lexicographical branching with `BTreeMap` ensuring bit-for-bit
/// reproducible traversal order. Supports prefix-matching, longest-prefix lookup,
/// predictive search (autocompletion), and subtree extraction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trie<V> {
    root: TrieNode<V>,
    len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TrieNode<V> {
    value: Option<V>,
    children: BTreeMap<char, TrieNode<V>>,
}

impl<V> Default for TrieNode<V> {
    fn default() -> Self {
        Self {
            value: None,
            children: BTreeMap::new(),
        }
    }
}

impl<V> TrieNode<V> {
    fn count_items(&self) -> usize {
        let current = if self.value.is_some() { 1 } else { 0 };
        current
            + self
                .children
                .values()
                .map(|c| c.count_items())
                .sum::<usize>()
    }
}

impl<V> Default for Trie<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V> Trie<V> {
    /// Create a new, empty prefix tree.
    pub fn new() -> Self {
        Self {
            root: TrieNode::default(),
            len: 0,
        }
    }

    /// Return the number of stored key-value pairs.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Check if the prefix tree contains no entries.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Remove all entries from the prefix tree.
    pub fn clear(&mut self) {
        self.root.children.clear();
        self.root.value = None;
        self.len = 0;
    }

    /// Insert a key-value pair, returning the old value if the key was already present.
    pub fn insert(&mut self, key: &str, value: V) -> Option<V> {
        let mut node = &mut self.root;
        for c in key.chars() {
            node = node.children.entry(c).or_default();
        }
        let old = node.value.replace(value);
        if old.is_none() {
            self.len += 1;
        }
        old
    }

    /// Retrieve an immutable reference to the value associated with `key`.
    pub fn get(&self, key: &str) -> Option<&V> {
        let mut node = &self.root;
        for c in key.chars() {
            node = node.children.get(&c)?;
        }
        node.value.as_ref()
    }

    /// Retrieve a mutable reference to the value associated with `key`.
    pub fn get_mut(&mut self, key: &str) -> Option<&mut V> {
        let mut node = &mut self.root;
        for c in key.chars() {
            node = node.children.get_mut(&c)?;
        }
        node.value.as_mut()
    }

    /// Check if the trie contains an entry for `key`.
    pub fn contains_key(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// Remove a key and its associated value, returning the removed value.
    ///
    /// Automatically prunes any unreferenced intermediate nodes to prevent memory leaks.
    pub fn remove(&mut self, key: &str) -> Option<V> {
        fn remove_node<V>(
            node: &mut TrieNode<V>,
            mut chars: std::str::Chars<'_>,
        ) -> (Option<V>, bool) {
            if let Some(c) = chars.next() {
                if let Some(child) = node.children.get_mut(&c) {
                    let (val, prune) = remove_node(child, chars);
                    if prune {
                        node.children.remove(&c);
                    }
                    let should_prune = node.value.is_none() && node.children.is_empty();
                    (val, should_prune)
                } else {
                    (None, false)
                }
            } else {
                let old = node.value.take();
                let should_prune = node.value.is_none() && node.children.is_empty();
                (old, should_prune)
            }
        }

        let (old, _) = remove_node(&mut self.root, key.chars());
        if old.is_some() {
            self.len -= 1;
        }
        old
    }

    /// Check if any key in the trie begins with `prefix`.
    pub fn starts_with(&self, prefix: &str) -> bool {
        if prefix.is_empty() {
            return !self.is_empty();
        }
        let mut node = &self.root;
        for c in prefix.chars() {
            match node.children.get(&c) {
                Some(next) => node = next,
                None => return false,
            }
        }
        true
    }

    /// Find the longest key in the trie that is a prefix of `text`.
    ///
    /// Returns `Some((matching_prefix, &value))` or `None` if no prefix matches.
    pub fn longest_prefix<'a>(&self, text: &'a str) -> Option<(&'a str, &V)> {
        let mut best: Option<(&'a str, &V)> = None;
        let mut node = &self.root;
        if let Some(ref val) = node.value {
            best = Some((&text[..0], val));
        }
        for (idx, c) in text.char_indices() {
            match node.children.get(&c) {
                Some(next) => {
                    node = next;
                    if let Some(ref val) = node.value {
                        let end_idx = idx + c.len_utf8();
                        best = Some((&text[..end_idx], val));
                    }
                }
                None => break,
            }
        }
        best
    }

    /// Find the value associated with the longest prefix of `text`.
    pub fn longest_prefix_value(&self, text: &str) -> Option<&V> {
        self.longest_prefix(text).map(|(_, v)| v)
    }

    /// Return all key-value entries starting with `prefix` in deterministic lexicographical order.
    pub fn predictive_search(&self, prefix: &str) -> Vec<(String, &V)> {
        let mut node = &self.root;
        for c in prefix.chars() {
            match node.children.get(&c) {
                Some(next) => node = next,
                None => return Vec::new(),
            }
        }
        let mut results = Vec::new();
        let mut current_key = prefix.to_string();
        Self::collect_entries(node, &mut current_key, &mut results);
        results
    }

    fn collect_entries<'a>(
        node: &'a TrieNode<V>,
        current: &mut String,
        results: &mut Vec<(String, &'a V)>,
    ) {
        if let Some(ref val) = node.value {
            results.push((current.clone(), val));
        }
        for (&c, child) in &node.children {
            current.push(c);
            Self::collect_entries(child, current, results);
            current.pop();
        }
    }

    /// Return all keys starting with `prefix` in deterministic lexicographical order.
    pub fn keys_with_prefix(&self, prefix: &str) -> Vec<String> {
        self.predictive_search(prefix)
            .into_iter()
            .map(|(k, _)| k)
            .collect()
    }

    /// Return all values whose keys start with `prefix` in deterministic lexicographical order.
    pub fn values_with_prefix(&self, prefix: &str) -> Vec<&V> {
        self.predictive_search(prefix)
            .into_iter()
            .map(|(_, v)| v)
            .collect()
    }

    /// Return all keys stored in the trie in deterministic lexicographical order.
    pub fn keys(&self) -> Vec<String> {
        self.keys_with_prefix("")
    }

    /// Return all values stored in the trie in deterministic lexicographical order.
    pub fn values(&self) -> Vec<&V> {
        self.values_with_prefix("")
    }

    /// Return all key-value pairs stored in the trie in deterministic lexicographical order.
    pub fn entries(&self) -> Vec<(String, &V)> {
        self.predictive_search("")
    }

    /// Extract a cloned subtrie rooted at `prefix`.
    ///
    /// The resulting trie's keys are relative to the subtree root (prefix is stripped).
    pub fn subtrie(&self, prefix: &str) -> Option<Self>
    where
        V: Clone,
    {
        let mut node = &self.root;
        for c in prefix.chars() {
            node = node.children.get(&c)?;
        }
        let cloned_root = node.clone();
        let len = cloned_root.count_items();
        Some(Self {
            root: cloned_root,
            len,
        })
    }
}

impl<V> Index<&str> for Trie<V> {
    type Output = V;
    fn index(&self, key: &str) -> &Self::Output {
        self.get(key).expect("no entry found for key")
    }
}

impl<'a, V> FromIterator<(&'a str, V)> for Trie<V> {
    fn from_iter<I: IntoIterator<Item = (&'a str, V)>>(iter: I) -> Self {
        let mut trie = Self::new();
        for (k, v) in iter {
            trie.insert(k, v);
        }
        trie
    }
}

impl<V> FromIterator<(String, V)> for Trie<V> {
    fn from_iter<I: IntoIterator<Item = (String, V)>>(iter: I) -> Self {
        let mut trie = Self::new();
        for (k, v) in iter {
            trie.insert(&k, v);
        }
        trie
    }
}

impl<'a, V> Extend<(&'a str, V)> for Trie<V> {
    fn extend<I: IntoIterator<Item = (&'a str, V)>>(&mut self, iter: I) {
        for (k, v) in iter {
            self.insert(k, v);
        }
    }
}

impl<V> Extend<(String, V)> for Trie<V> {
    fn extend<I: IntoIterator<Item = (String, V)>>(&mut self, iter: I) {
        for (k, v) in iter {
            self.insert(&k, v);
        }
    }
}

/// Deterministic unique string set backed by a Prefix Tree (`Trie`).
///
/// Guarantees lexicographical ordering, deterministic autocomplete / prefix matching,
/// and efficient prefix-based query operations.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TrieSet {
    inner: Trie<()>,
}

impl TrieSet {
    /// Create an empty trie set.
    pub fn new() -> Self {
        Self { inner: Trie::new() }
    }

    /// Return number of distinct keys in the set.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Clear all keys from the set.
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    /// Insert a key into the set. Returns `true` if the key was not already present.
    pub fn insert(&mut self, key: &str) -> bool {
        self.inner.insert(key, ()).is_none()
    }

    /// Check if the set contains the given key.
    pub fn contains(&self, key: &str) -> bool {
        self.inner.contains_key(key)
    }

    /// Remove a key from the set. Returns `true` if the key was present.
    pub fn remove(&mut self, key: &str) -> bool {
        self.inner.remove(key).is_some()
    }

    /// Check if any key in the set starts with `prefix`.
    pub fn starts_with(&self, prefix: &str) -> bool {
        self.inner.starts_with(prefix)
    }

    /// Return the longest key in the set that is a prefix of `text`.
    pub fn longest_prefix<'a>(&self, text: &'a str) -> Option<&'a str> {
        self.inner.longest_prefix(text).map(|(s, _)| s)
    }

    /// Return all keys starting with `prefix` in deterministic lexicographical order.
    pub fn keys_with_prefix(&self, prefix: &str) -> Vec<String> {
        self.inner.keys_with_prefix(prefix)
    }

    /// Return all keys in the set in deterministic lexicographical order.
    pub fn keys(&self) -> Vec<String> {
        self.inner.keys()
    }
}

impl<'a> FromIterator<&'a str> for TrieSet {
    fn from_iter<I: IntoIterator<Item = &'a str>>(iter: I) -> Self {
        let mut set = Self::new();
        for s in iter {
            set.insert(s);
        }
        set
    }
}

impl FromIterator<String> for TrieSet {
    fn from_iter<I: IntoIterator<Item = String>>(iter: I) -> Self {
        let mut set = Self::new();
        for s in iter {
            set.insert(&s);
        }
        set
    }
}

impl<'a> Extend<&'a str> for TrieSet {
    fn extend<I: IntoIterator<Item = &'a str>>(&mut self, iter: I) {
        for s in iter {
            self.insert(s);
        }
    }
}

impl Extend<String> for TrieSet {
    fn extend<I: IntoIterator<Item = String>>(&mut self, iter: I) {
        for s in iter {
            self.insert(&s);
        }
    }
}

/// Error returned when attempting to construct an invalid interval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntervalError<T> {
    /// The lower bound is strictly greater than the upper bound.
    InvertedBounds { start: T, end: T },
}

impl<T: fmt::Debug> fmt::Display for IntervalError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvertedBounds { start, end } => {
                write!(
                    f,
                    "Invalid interval bounds: start ({:?}) must be <= end ({:?})",
                    start, end
                )
            }
        }
    }
}

impl<T: fmt::Debug> std::error::Error for IntervalError<T> {}

/// Half-open interval `[start, end)` representing a contiguous range.
///
/// Invariant: `start <= end`. When `start == end`, the interval is considered empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Interval<T> {
    /// Start of interval (inclusive).
    pub start: T,
    /// End of interval (exclusive).
    pub end: T,
}

impl<T: fmt::Display> fmt::Display for Interval<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}, {})", self.start, self.end)
    }
}

impl<T: Ord + Clone> Interval<T> {
    /// Create a validated half-open interval `[start, end)`.
    ///
    /// Returns `Err(IntervalError::InvertedBounds)` if `start > end`.
    pub fn new(start: T, end: T) -> Result<Self, IntervalError<T>> {
        if start > end {
            Err(IntervalError::InvertedBounds { start, end })
        } else {
            Ok(Self { start, end })
        }
    }

    /// Create an interval without checking boundary invariants.
    pub const fn new_unchecked(start: T, end: T) -> Self {
        Self { start, end }
    }

    /// Check if point falls within `[start, end)`.
    pub fn contains_point(&self, point: &T) -> bool {
        self.start <= *point && *point < self.end
    }

    /// Check if this interval completely contains another interval.
    pub fn contains_interval(&self, other: &Self) -> bool {
        self.start <= other.start && other.end <= self.end
    }

    /// Check if this interval overlaps with another interval.
    ///
    /// Two half-open intervals `[a, b)` and `[c, d)` overlap if `a < d && c < b`.
    pub fn overlaps(&self, other: &Self) -> bool {
        self.start < other.end && other.start < self.end
    }

    /// Check if this interval is adjacent to another (i.e. touches borders without overlapping).
    pub fn touches(&self, other: &Self) -> bool {
        self.end == other.start || other.end == self.start
    }

    /// Return the intersection of two intervals, or `None` if they do not overlap.
    pub fn intersection(&self, other: &Self) -> Option<Self> {
        if self.overlaps(other) {
            let start = std::cmp::max(self.start.clone(), other.start.clone());
            let end = std::cmp::min(self.end.clone(), other.end.clone());
            Some(Self { start, end })
        } else {
            None
        }
    }

    /// Return the smallest bounding interval spanning both intervals.
    pub fn span(&self, other: &Self) -> Self {
        let start = std::cmp::min(self.start.clone(), other.start.clone());
        let end = std::cmp::max(self.end.clone(), other.end.clone());
        Self { start, end }
    }

    /// Return `true` if interval has zero length (`start == end`).
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IntervalNode<K, V> {
    interval: Interval<K>,
    value: V,
    max_end: K,
    height: usize,
    left: Option<Box<IntervalNode<K, V>>>,
    right: Option<Box<IntervalNode<K, V>>>,
}

type IntervalNodeBox<K, V> = Box<IntervalNode<K, V>>;
type IntervalNodeLink<K, V> = Option<IntervalNodeBox<K, V>>;
type MinExtract<K, V> = (IntervalNodeBox<K, V>, IntervalNodeLink<K, V>);

impl<K: Ord + Clone, V> IntervalNode<K, V> {
    fn new(interval: Interval<K>, value: V) -> Self {
        let max_end = interval.end.clone();
        Self {
            interval,
            value,
            max_end,
            height: 1,
            left: None,
            right: None,
        }
    }

    fn height(node: &Option<Box<Self>>) -> usize {
        node.as_ref().map_or(0, |n| n.height)
    }

    fn update(&mut self) {
        let left_h = Self::height(&self.left);
        let right_h = Self::height(&self.right);
        self.height = 1 + std::cmp::max(left_h, right_h);

        let mut max = self.interval.end.clone();
        if let Some(ref l) = self.left {
            if l.max_end > max {
                max = l.max_end.clone();
            }
        }
        if let Some(ref r) = self.right {
            if r.max_end > max {
                max = r.max_end.clone();
            }
        }
        self.max_end = max;
    }

    fn balance_factor(&self) -> isize {
        Self::height(&self.left) as isize - Self::height(&self.right) as isize
    }
}

fn rotate_right<K: Ord + Clone, V>(mut y: Box<IntervalNode<K, V>>) -> Box<IntervalNode<K, V>> {
    let mut x = y
        .left
        .take()
        .expect("left child must exist for right rotation");
    y.left = x.right.take();
    y.update();
    x.right = Some(y);
    x.update();
    x
}

fn rotate_left<K: Ord + Clone, V>(mut x: Box<IntervalNode<K, V>>) -> Box<IntervalNode<K, V>> {
    let mut y = x
        .right
        .take()
        .expect("right child must exist for left rotation");
    x.right = y.left.take();
    x.update();
    y.left = Some(x);
    y.update();
    y
}

fn rebalance<K: Ord + Clone, V>(mut node: Box<IntervalNode<K, V>>) -> Box<IntervalNode<K, V>> {
    node.update();
    let bf = node.balance_factor();

    if bf > 1 {
        if let Some(ref left) = node.left {
            if left.balance_factor() < 0 {
                let l = node.left.take().unwrap();
                node.left = Some(rotate_left(l));
            }
        }
        return rotate_right(node);
    } else if bf < -1 {
        if let Some(ref right) = node.right {
            if right.balance_factor() > 0 {
                let r = node.right.take().unwrap();
                node.right = Some(rotate_right(r));
            }
        }
        return rotate_left(node);
    }

    node
}

fn insert_node<K: Ord + Clone, V>(
    node: Option<Box<IntervalNode<K, V>>>,
    interval: Interval<K>,
    value: V,
    old_val: &mut Option<V>,
) -> Box<IntervalNode<K, V>> {
    let mut current = match node {
        Some(n) => n,
        None => return Box::new(IntervalNode::new(interval, value)),
    };

    if interval < current.interval {
        current.left = Some(insert_node(current.left.take(), interval, value, old_val));
    } else if interval > current.interval {
        current.right = Some(insert_node(current.right.take(), interval, value, old_val));
    } else {
        *old_val = Some(std::mem::replace(&mut current.value, value));
        return current;
    }

    rebalance(current)
}

fn extract_min<K: Ord + Clone, V>(mut node: IntervalNodeBox<K, V>) -> MinExtract<K, V> {
    if node.left.is_none() {
        let right = node.right.take();
        (node, right)
    } else {
        let (min_node, new_left) = extract_min(node.left.take().unwrap());
        node.left = new_left;
        (min_node, Some(rebalance(node)))
    }
}

fn remove_node<K: Ord + Clone, V>(
    node: Option<Box<IntervalNode<K, V>>>,
    key: &Interval<K>,
    removed_val: &mut Option<V>,
) -> Option<Box<IntervalNode<K, V>>> {
    let mut current = node?;

    if *key < current.interval {
        current.left = remove_node(current.left.take(), key, removed_val);
    } else if *key > current.interval {
        current.right = remove_node(current.right.take(), key, removed_val);
    } else {
        *removed_val = Some(current.value);
        if current.left.is_none() {
            return current.right;
        } else if current.right.is_none() {
            return current.left;
        } else {
            let right = current.right.take().unwrap();
            let (mut successor, new_right) = extract_min(right);
            successor.left = current.left.take();
            successor.right = new_right;
            return Some(rebalance(successor));
        }
    }

    Some(rebalance(current))
}

fn query_point_rec<'a, K: Ord + Clone, V>(
    node: &'a Option<Box<IntervalNode<K, V>>>,
    point: &K,
    results: &mut Vec<(&'a Interval<K>, &'a V)>,
) {
    if let Some(ref n) = node {
        if n.max_end <= *point {
            return;
        }
        if let Some(ref left) = n.left {
            if left.max_end > *point {
                query_point_rec(&n.left, point, results);
            }
        }
        if n.interval.contains_point(point) {
            results.push((&n.interval, &n.value));
        }
        if n.interval.start <= *point {
            query_point_rec(&n.right, point, results);
        }
    }
}

fn query_overlapping_rec<'a, K: Ord + Clone, V>(
    node: &'a Option<Box<IntervalNode<K, V>>>,
    query: &Interval<K>,
    results: &mut Vec<(&'a Interval<K>, &'a V)>,
) {
    if let Some(ref n) = node {
        if n.max_end <= query.start {
            return;
        }
        if let Some(ref left) = n.left {
            if left.max_end > query.start {
                query_overlapping_rec(&n.left, query, results);
            }
        }
        if n.interval.overlaps(query) {
            results.push((&n.interval, &n.value));
        }
        if query.end > n.interval.start {
            query_overlapping_rec(&n.right, query, results);
        }
    }
}

fn in_order_entries<'a, K: Ord + Clone, V>(
    node: &'a Option<Box<IntervalNode<K, V>>>,
    out: &mut Vec<(&'a Interval<K>, &'a V)>,
) {
    if let Some(ref n) = node {
        in_order_entries(&n.left, out);
        out.push((&n.interval, &n.value));
        in_order_entries(&n.right, out);
    }
}

/// Deterministic augmented AVL interval tree (`IntervalMap<K, V>`).
///
/// Stores key-value mappings where keys are half-open intervals `[start, end)`.
/// Provides logarithmic search, point containment lookups, and overlapping range queries
/// with guaranteed bit-for-bit deterministic traversal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntervalMap<K: Ord + Clone, V> {
    root: Option<Box<IntervalNode<K, V>>>,
    len: usize,
}

impl<K: Ord + Clone, V> Default for IntervalMap<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: Ord + Clone, V> IntervalMap<K, V> {
    /// Create an empty interval map.
    pub fn new() -> Self {
        Self { root: None, len: 0 }
    }

    /// Return the number of intervals in the map.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Check if the map is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Clear all intervals from the map.
    pub fn clear(&mut self) {
        self.root = None;
        self.len = 0;
    }

    /// Insert an interval and value into the map.
    ///
    /// If an identical interval was already present, replaces the value and returns the old one.
    pub fn insert(&mut self, interval: Interval<K>, value: V) -> Option<V> {
        let mut old = None;
        self.root = Some(insert_node(self.root.take(), interval, value, &mut old));
        if old.is_none() {
            self.len += 1;
        }
        old
    }

    /// Remove an interval from the map, returning its value if present.
    pub fn remove(&mut self, interval: &Interval<K>) -> Option<V> {
        let mut removed = None;
        self.root = remove_node(self.root.take(), interval, &mut removed);
        if removed.is_some() {
            self.len -= 1;
        }
        removed
    }

    /// Get a reference to the value associated with an exact interval.
    pub fn get(&self, interval: &Interval<K>) -> Option<&V> {
        let mut curr = self.root.as_ref();
        while let Some(node) = curr {
            if interval < &node.interval {
                curr = node.left.as_ref();
            } else if interval > &node.interval {
                curr = node.right.as_ref();
            } else {
                return Some(&node.value);
            }
        }
        None
    }

    /// Get a mutable reference to the value associated with an exact interval.
    pub fn get_mut(&mut self, interval: &Interval<K>) -> Option<&mut V> {
        let mut curr = self.root.as_mut();
        while let Some(node) = curr {
            if interval < &node.interval {
                curr = node.left.as_mut();
            } else if interval > &node.interval {
                curr = node.right.as_mut();
            } else {
                return Some(&mut node.value);
            }
        }
        None
    }

    /// Check if map contains the exact interval.
    pub fn contains_key(&self, interval: &Interval<K>) -> bool {
        self.get(interval).is_some()
    }

    /// Find all intervals containing the given point.
    pub fn query_point(&self, point: &K) -> Vec<(&Interval<K>, &V)> {
        let mut results = Vec::new();
        query_point_rec(&self.root, point, &mut results);
        results
    }

    /// Find all intervals overlapping with the given query interval.
    pub fn query_overlapping(&self, query: &Interval<K>) -> Vec<(&Interval<K>, &V)> {
        let mut results = Vec::new();
        query_overlapping_rec(&self.root, query, &mut results);
        results
    }

    /// Check if any interval overlaps with the given query interval.
    pub fn any_overlaps(&self, query: &Interval<K>) -> bool {
        !self.query_overlapping(query).is_empty()
    }

    /// Check if any interval contains the given point.
    pub fn contains_point(&self, point: &K) -> bool {
        !self.query_point(point).is_empty()
    }

    /// Return all intervals in deterministic lexicographical order.
    pub fn intervals(&self) -> Vec<Interval<K>> {
        let mut res = Vec::with_capacity(self.len);
        let mut entries = Vec::with_capacity(self.len);
        in_order_entries(&self.root, &mut entries);
        for (k, _) in entries {
            res.push(k.clone());
        }
        res
    }

    /// Return an iterator visiting all entries in ascending interval order.
    pub fn iter(&self) -> IntervalMapIter<'_, K, V> {
        IntervalMapIter::new(&self.root)
    }
}

impl<K: Ord + Clone, V> Index<&Interval<K>> for IntervalMap<K, V> {
    type Output = V;
    fn index(&self, index: &Interval<K>) -> &Self::Output {
        self.get(index).expect("no entry found for interval")
    }
}

/// Deterministic in-order iterator over entries of an `IntervalMap`.
pub struct IntervalMapIter<'a, K, V> {
    stack: Vec<&'a IntervalNode<K, V>>,
}

impl<'a, K: Ord + Clone, V> IntervalMapIter<'a, K, V> {
    fn new(root: &'a Option<Box<IntervalNode<K, V>>>) -> Self {
        let mut iter = Self { stack: Vec::new() };
        iter.push_left(root.as_deref());
        iter
    }

    fn push_left(&mut self, mut node: Option<&'a IntervalNode<K, V>>) {
        while let Some(n) = node {
            self.stack.push(n);
            node = n.left.as_deref();
        }
    }
}

impl<'a, K: Ord + Clone, V> Iterator for IntervalMapIter<'a, K, V> {
    type Item = (&'a Interval<K>, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        let node = self.stack.pop()?;
        self.push_left(node.right.as_deref());
        Some((&node.interval, &node.value))
    }
}

impl<'a, K: Ord + Clone, V> IntoIterator for &'a IntervalMap<K, V> {
    type Item = (&'a Interval<K>, &'a V);
    type IntoIter = IntervalMapIter<'a, K, V>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<K: Ord + Clone, V> FromIterator<(Interval<K>, V)> for IntervalMap<K, V> {
    fn from_iter<I: IntoIterator<Item = (Interval<K>, V)>>(iter: I) -> Self {
        let mut map = Self::new();
        for (k, v) in iter {
            map.insert(k, v);
        }
        map
    }
}

impl<K: Ord + Clone, V> Extend<(Interval<K>, V)> for IntervalMap<K, V> {
    fn extend<I: IntoIterator<Item = (Interval<K>, V)>>(&mut self, iter: I) {
        for (k, v) in iter {
            self.insert(k, v);
        }
    }
}

/// Deterministic set of intervals backed by `IntervalMap`.
///
/// Supports containment queries, overlap checks, and contiguous interval merging.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IntervalSet<K: Ord + Clone> {
    inner: IntervalMap<K, ()>,
}

impl<K: Ord + Clone> IntervalSet<K> {
    /// Create an empty interval set.
    pub fn new() -> Self {
        Self {
            inner: IntervalMap::new(),
        }
    }

    /// Return the number of intervals in the set.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Clear all intervals from the set.
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    /// Insert an interval into the set. Returns `true` if it was not already present.
    pub fn insert(&mut self, interval: Interval<K>) -> bool {
        self.inner.insert(interval, ()).is_none()
    }

    /// Remove an interval from the set. Returns `true` if it was present.
    pub fn remove(&mut self, interval: &Interval<K>) -> bool {
        self.inner.remove(interval).is_some()
    }

    /// Check if the set contains the exact interval.
    pub fn contains(&self, interval: &Interval<K>) -> bool {
        self.inner.contains_key(interval)
    }

    /// Check if any interval in the set contains the given point.
    pub fn contains_point(&self, point: &K) -> bool {
        self.inner.contains_point(point)
    }

    /// Check if any interval in the set overlaps with the given interval.
    pub fn any_overlaps(&self, interval: &Interval<K>) -> bool {
        self.inner.any_overlaps(interval)
    }

    /// Find all intervals in the set containing the given point.
    pub fn query_point(&self, point: &K) -> Vec<&Interval<K>> {
        self.inner
            .query_point(point)
            .into_iter()
            .map(|(k, _)| k)
            .collect()
    }

    /// Find all intervals in the set overlapping with the given interval.
    pub fn query_overlapping(&self, interval: &Interval<K>) -> Vec<&Interval<K>> {
        self.inner
            .query_overlapping(interval)
            .into_iter()
            .map(|(k, _)| k)
            .collect()
    }

    /// Return all intervals in deterministic lexicographical order.
    pub fn intervals(&self) -> Vec<Interval<K>> {
        self.inner.intervals()
    }

    /// Return a merged, minimal list of disjoint intervals covering the exact same points.
    ///
    /// Consecutive overlapping or adjacent (`touches`) intervals are fused together.
    pub fn merged(&self) -> Vec<Interval<K>> {
        let intervals = self.intervals();
        if intervals.is_empty() {
            return Vec::new();
        }
        let mut merged = Vec::new();
        let mut current = intervals[0].clone();

        for next in intervals.into_iter().skip(1) {
            if next.start <= current.end {
                if next.end > current.end {
                    current.end = next.end;
                }
            } else {
                merged.push(current);
                current = next;
            }
        }
        merged.push(current);
        merged
    }
}

impl<K: Ord + Clone> FromIterator<Interval<K>> for IntervalSet<K> {
    fn from_iter<I: IntoIterator<Item = Interval<K>>>(iter: I) -> Self {
        let mut set = Self::new();
        for item in iter {
            set.insert(item);
        }
        set
    }
}

impl<K: Ord + Clone> Extend<Interval<K>> for IntervalSet<K> {
    fn extend<I: IntoIterator<Item = Interval<K>>>(&mut self, iter: I) {
        for item in iter {
            self.insert(item);
        }
    }
}

/// A deterministic Fenwick Tree (Binary Indexed Tree) for prefix sums and point updates.
///
/// Operates on 0-based indices for ease of use in algorithms, while maintaining
/// standard internal 1-based indexing for efficient bit manipulation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FenwickTree<T> {
    tree: Vec<T>,
    size: usize,
}

impl<T: Default + Copy + std::ops::AddAssign + std::ops::Sub<Output = T>> FenwickTree<T> {
    /// Construct a Fenwick tree of specified length with all values initialized to zero/default.
    pub fn new(size: usize) -> Self {
        Self {
            tree: vec![T::default(); size + 1],
            size,
        }
    }

    /// Construct a Fenwick tree from a slice of initial values in O(N) time.
    pub fn from_slice(values: &[T]) -> Self {
        let size = values.len();
        let mut tree = vec![T::default(); size + 1];
        for (i, &val) in values.iter().enumerate() {
            tree[i + 1] = val;
        }
        for i in 1..=size {
            let parent = i + (i & (!i + 1));
            if parent <= size {
                let current_val = tree[i];
                tree[parent] += current_val;
            }
        }
        Self { tree, size }
    }

    /// Return the number of elements in the tree.
    pub fn len(&self) -> usize {
        self.size
    }

    /// Return `true` if the tree has length 0.
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Add `delta` to the value at index `idx` (0-based).
    ///
    /// Returns `false` if `idx >= self.len()`.
    pub fn add(&mut self, idx: usize, delta: T) -> bool {
        if idx >= self.size {
            return false;
        }
        let mut i = idx + 1;
        while i <= self.size {
            self.tree[i] += delta;
            i += i & (!i + 1);
        }
        true
    }

    /// Query the prefix sum `sum(0..=idx)` inclusive.
    ///
    /// Returns `None` if `idx >= self.len()`.
    pub fn prefix_sum(&self, idx: usize) -> Option<T> {
        if idx >= self.size {
            return None;
        }
        let mut sum = T::default();
        let mut i = idx + 1;
        while i > 0 {
            sum += self.tree[i];
            i -= i & (!i + 1);
        }
        Some(sum)
    }

    /// Query the range sum `sum(start..=end)` inclusive.
    ///
    /// Returns `None` if `start > end` or `end >= self.len()`.
    pub fn range_sum(&self, start: usize, end: usize) -> Option<T> {
        if start > end || end >= self.size {
            return None;
        }
        let end_sum = self.prefix_sum(end)?;
        if start == 0 {
            Some(end_sum)
        } else {
            let before_sum = self.prefix_sum(start - 1)?;
            Some(end_sum - before_sum)
        }
    }

    /// Reset all values in the tree to zero.
    pub fn clear(&mut self) {
        self.tree.fill(T::default());
    }
}

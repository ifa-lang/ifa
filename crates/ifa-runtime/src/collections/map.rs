//! Deterministic hash map (`Map`) without garbage collection.

use std::borrow::Borrow;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

const INITIAL_CAPACITY: usize = 16;
const LOAD_FACTOR_NUMERATOR: usize = 3;
const LOAD_FACTOR_DENOMINATOR: usize = 4; // 75% load factor

#[derive(Clone)]
struct Bucket<K, V> {
    hash: u64,
    key: K,
    value: V,
    distance: usize,
}

/// A deterministic Robin Hood hash map designed for zero-GC deterministic execution.
#[derive(Clone)]
pub struct IfaMap<K, V> {
    buckets: Vec<Option<Bucket<K, V>>>,
    len: usize,
}

impl<K, V> IfaMap<K, V>
where
    K: Eq + Hash + Clone,
    V: Clone,
{
    /// Create a new empty map.
    pub fn new() -> Self {
        Self {
            buckets: vec![None; INITIAL_CAPACITY],
            len: 0,
        }
    }

    /// Number of key-value pairs stored in the map.
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Check if the map contains no entries.
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn calculate_hash<Q: ?Sized + Hash>(key: &Q) -> u64 {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        hasher.finish()
    }

    /// Insert a key-value pair, returning the previous value if it existed.
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        if (self.len + 1) * LOAD_FACTOR_DENOMINATOR > self.buckets.len() * LOAD_FACTOR_NUMERATOR {
            self.grow();
        }

        let hash = Self::calculate_hash(&key);
        let mut bucket = Bucket {
            hash,
            key,
            value,
            distance: 0,
        };

        let cap = self.buckets.len();
        let mut idx = (hash as usize) % cap;

        loop {
            match &mut self.buckets[idx] {
                None => {
                    self.buckets[idx] = Some(bucket);
                    self.len += 1;
                    return None;
                }
                Some(existing) => {
                    if existing.hash == bucket.hash && existing.key == bucket.key {
                        let old_val = std::mem::replace(&mut existing.value, bucket.value);
                        return Some(old_val);
                    }

                    if existing.distance < bucket.distance {
                        std::mem::swap(existing, &mut bucket);
                    }

                    bucket.distance += 1;
                    idx = (idx + 1) % cap;
                }
            }
        }
    }

    /// Retrieve a reference to the value associated with the specified key.
    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        Q: ?Sized + Eq + Hash,
        K: Borrow<Q>,
    {
        if self.len == 0 {
            return None;
        }

        let hash = Self::calculate_hash(key);
        let cap = self.buckets.len();
        let mut idx = (hash as usize) % cap;
        let mut distance = 0;

        loop {
            let bucket = self.buckets[idx].as_ref()?;
            if bucket.hash == hash && bucket.key.borrow() == key {
                return Some(&bucket.value);
            }
            if distance > bucket.distance {
                return None;
            }
            distance += 1;
            idx = (idx + 1) % cap;
        }
    }

    /// Check whether a key is present in the map.
    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        Q: ?Sized + Eq + Hash,
        K: Borrow<Q>,
    {
        self.get(key).is_some()
    }

    /// Remove a key from the map and return its value.
    pub fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        Q: ?Sized + Eq + Hash,
        K: Borrow<Q>,
    {
        if self.len == 0 {
            return None;
        }

        let hash = Self::calculate_hash(key);
        let cap = self.buckets.len();
        let mut idx = (hash as usize) % cap;
        let mut distance = 0;

        loop {
            let bucket = self.buckets[idx].as_ref()?;
            if bucket.hash == hash && bucket.key.borrow() == key {
                break;
            }
            if distance > bucket.distance {
                return None;
            }
            distance += 1;
            idx = (idx + 1) % cap;
        }

        let removed = self.buckets[idx].take().unwrap();
        self.len -= 1;

        // Backward-shift deletion for Robin Hood hashing
        let mut curr = idx;
        loop {
            let next = (curr + 1) % cap;
            let should_shift = match &self.buckets[next] {
                Some(b) => b.distance > 0,
                None => false,
            };

            if !should_shift {
                break;
            }

            let mut next_bucket = self.buckets[next].take().unwrap();
            next_bucket.distance -= 1;
            self.buckets[curr] = Some(next_bucket);
            curr = next;
        }

        Some(removed.value)
    }

    fn grow(&mut self) {
        let new_capacity = self.buckets.len() * 2;
        let old_buckets = std::mem::replace(&mut self.buckets, vec![None; new_capacity]);
        self.len = 0;
        for bucket in old_buckets.into_iter().flatten() {
            self.insert(bucket.key, bucket.value);
        }
    }
}

impl<K: Eq + Hash + Clone, V: Clone> Default for IfaMap<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

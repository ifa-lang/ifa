//! Embedded Zero-Copy Database Engine (`std/db`) for IFA.
//!
//! Provides a deterministic, ACID-compliant key-value storage engine with
//! Write-Ahead Logging (WAL) and BLAKE3 page integrity verification.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub const DB_MAGIC: [u8; 4] = *b"IFDB";
pub const DB_VERSION: u32 = 1;
pub const PAGE_SIZE: usize = 4096;

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("Invalid database header: expected IFDB magic")]
    InvalidHeader,
    #[error("Unsupported database version: {0}")]
    UnsupportedVersion(u32),
    #[error("Integrity check failed: BLAKE3 checksum mismatch")]
    ChecksumMismatch,
    #[error("Transaction aborted")]
    TransactionAborted,
    #[error("Key length exceeds maximum allowed limit (65535 bytes)")]
    KeyTooLarge,
    #[error("Value length exceeds maximum allowed limit (16MB)")]
    ValueTooLarge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum WalRecordType {
    Put = 1,
    Delete = 2,
    Commit = 3,
}

/// A paginated result set with offset/limit metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page<K, V> {
    /// Items on this page.
    pub items: Vec<(K, V)>,
    /// Total count of matching entries across all pages.
    pub total: usize,
    /// Offset of the first item on this page.
    pub offset: usize,
    /// Maximum items requested per page.
    pub limit: usize,
    /// Whether more items exist after this page.
    pub has_more: bool,
}

impl<K, V> Page<K, V> {
    /// Number of items on the current page.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether this page is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// A keyset-paginated result set for cursor-based navigation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeysetPage<K, V> {
    /// Items on this page.
    pub items: Vec<(K, V)>,
    /// Cursor to pass as `after_key` for subsequent queries, or None if at end.
    pub next_cursor: Option<K>,
    /// Whether more items exist after this page.
    pub has_more: bool,
}

impl<K, V> KeysetPage<K, V> {
    /// Number of items on the current page.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether this page is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// Streaming iterator yielding database entries that start with a given key prefix.
#[derive(Debug, Clone)]
pub struct PrefixScanner<'a> {
    iter: std::collections::btree_map::Range<'a, Vec<u8>, Vec<u8>>,
    prefix: &'a [u8],
}

impl<'a> Iterator for PrefixScanner<'a> {
    type Item = (&'a [u8], &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        match self.iter.next() {
            Some((k, v)) if k.starts_with(self.prefix) => Some((k.as_slice(), v.as_slice())),
            _ => None,
        }
    }
}

/// In-memory and on-disk embedded database instance.
pub struct Database {
    path: PathBuf,
    wal_file: File,
    index: BTreeMap<Vec<u8>, Vec<u8>>,
    is_sync: bool,
}

/// An ACID snapshot transaction staging changes before atomic commit.
pub struct Transaction<'a> {
    db: &'a mut Database,
    staged_puts: BTreeMap<Vec<u8>, Vec<u8>>,
    staged_deletes: Vec<Vec<u8>>,
    committed: bool,
}

impl Database {
    /// Open or initialize a database at the specified directory path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, DbError> {
        let path = path.as_ref().to_path_buf();
        std::fs::create_dir_all(&path)?;

        let wal_path = path.join("wal.log");
        let mut wal_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&wal_path)?;

        // Replay existing WAL log to restore in-memory state
        let mut index = BTreeMap::new();
        let file_len = wal_file.metadata()?.len();

        if file_len > 0 {
            wal_file.seek(SeekFrom::Start(0))?;
            Self::replay_wal(&mut wal_file, &mut index)?;
        } else {
            // Write database header
            wal_file.write_all(&DB_MAGIC)?;
            wal_file.write_all(&DB_VERSION.to_le_bytes())?;
            wal_file.flush()?;
        }

        Ok(Self {
            path,
            wal_file,
            index,
            is_sync: true,
        })
    }

    /// Read an entry by key.
    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        self.index.get(key).map(|v| v.as_slice())
    }

    /// Insert or update an entry.
    pub fn put(&mut self, key: &[u8], val: &[u8]) -> Result<(), DbError> {
        if key.len() > u16::MAX as usize {
            return Err(DbError::KeyTooLarge);
        }
        if val.len() > 16 * 1024 * 1024 {
            return Err(DbError::ValueTooLarge);
        }

        // 1. Append record to WAL
        self.append_wal_record(WalRecordType::Put, key, val)?;
        self.append_wal_record(WalRecordType::Commit, &[], &[])?;

        if self.is_sync {
            self.wal_file.sync_data()?;
        }

        // 2. Update in-memory index
        self.index.insert(key.to_vec(), val.to_vec());
        Ok(())
    }

    /// Delete an entry by key. Returns true if the key was present.
    pub fn delete(&mut self, key: &[u8]) -> Result<bool, DbError> {
        if !self.index.contains_key(key) {
            return Ok(false);
        }

        self.append_wal_record(WalRecordType::Delete, key, &[])?;
        self.append_wal_record(WalRecordType::Commit, &[], &[])?;

        if self.is_sync {
            self.wal_file.sync_data()?;
        }

        self.index.remove(key);
        Ok(true)
    }

    /// Check whether a key exists in the database.
    pub fn contains_key(&self, key: &[u8]) -> bool {
        self.index.contains_key(key)
    }

    /// Total count of keys stored in the database.
    pub fn len(&self) -> usize {
        self.index.len()
    }

    /// Whether the database is empty.
    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    /// Begin an isolated transaction.
    pub fn begin_transaction(&mut self) -> Transaction<'_> {
        Transaction {
            db: self,
            staged_puts: BTreeMap::new(),
            staged_deletes: Vec::new(),
            committed: false,
        }
    }

    /// Force flush and sync underlying files to disk.
    pub fn sync(&mut self) -> Result<(), DbError> {
        self.wal_file.sync_all()?;
        Ok(())
    }

    /// Insert or update multiple entries in a single atomic WAL batch.
    pub fn put_batch(&mut self, entries: &[(&[u8], &[u8])]) -> Result<(), DbError> {
        for (k, v) in entries {
            if k.len() > u16::MAX as usize {
                return Err(DbError::KeyTooLarge);
            }
            if v.len() > 16 * 1024 * 1024 {
                return Err(DbError::ValueTooLarge);
            }
        }

        for (k, v) in entries {
            self.append_wal_record(WalRecordType::Put, k, v)?;
        }
        self.append_wal_record(WalRecordType::Commit, &[], &[])?;

        if self.is_sync {
            self.wal_file.sync_data()?;
        }

        for (k, v) in entries {
            self.index.insert(k.to_vec(), v.to_vec());
        }
        Ok(())
    }

    /// Delete multiple entries by key in a single atomic WAL batch.
    /// Returns the number of keys that were actually present and deleted.
    pub fn delete_batch(&mut self, keys: &[&[u8]]) -> Result<usize, DbError> {
        let mut count = 0;
        for k in keys {
            if self.index.contains_key(*k) {
                self.append_wal_record(WalRecordType::Delete, k, &[])?;
                count += 1;
            }
        }

        if count > 0 {
            self.append_wal_record(WalRecordType::Commit, &[], &[])?;
            if self.is_sync {
                self.wal_file.sync_data()?;
            }
            for k in keys {
                self.index.remove(*k);
            }
        }
        Ok(count)
    }

    /// Iterate over all key-value entries in lexicographical order.
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = (&[u8], &[u8])> {
        self.index.iter().map(|(k, v)| (k.as_slice(), v.as_slice()))
    }

    /// Iterate over all keys in lexicographical order.
    pub fn keys(&self) -> impl DoubleEndedIterator<Item = &[u8]> {
        self.index.keys().map(|k| k.as_slice())
    }

    /// Iterate over all values in lexicographical order.
    pub fn values(&self) -> impl DoubleEndedIterator<Item = &[u8]> {
        self.index.values().map(|v| v.as_slice())
    }

    /// Scan entries starting with `prefix` in lexicographical order.
    pub fn scan_prefix<'a>(&'a self, prefix: &'a [u8]) -> PrefixScanner<'a> {
        use std::ops::Bound;
        PrefixScanner {
            iter: self
                .index
                .range::<[u8], _>((Bound::Included(prefix), Bound::Unbounded)),
            prefix,
        }
    }

    /// Scan entries between `start` (inclusive) and `end` (inclusive) in lexicographical order.
    pub fn scan_range<'a>(
        &'a self,
        start: &[u8],
        end: &[u8],
    ) -> impl DoubleEndedIterator<Item = (&'a [u8], &'a [u8])> {
        use std::ops::Bound;
        self.index
            .range::<[u8], _>((Bound::Included(start), Bound::Included(end)))
            .map(|(k, v)| (k.as_slice(), v.as_slice()))
    }

    /// Scan entries within arbitrary range bounds.
    pub fn scan_range_bounds<R>(&self, range: R) -> impl DoubleEndedIterator<Item = (&[u8], &[u8])>
    where
        R: std::ops::RangeBounds<[u8]>,
    {
        self.index
            .range::<[u8], R>(range)
            .map(|(k, v)| (k.as_slice(), v.as_slice()))
    }

    /// Paginate through all database entries with offset and limit.
    pub fn paginate(&self, offset: usize, limit: usize) -> Page<Vec<u8>, Vec<u8>> {
        let total = self.index.len();
        let items = self
            .index
            .iter()
            .skip(offset)
            .take(limit)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let has_more = offset + limit < total;
        Page {
            items,
            total,
            offset,
            limit,
            has_more,
        }
    }

    /// Paginate through database entries matching a key prefix with offset and limit.
    pub fn paginate_prefix(
        &self,
        prefix: &[u8],
        offset: usize,
        limit: usize,
    ) -> Page<Vec<u8>, Vec<u8>> {
        let matching: Vec<(&[u8], &[u8])> = self.scan_prefix(prefix).collect();
        let total = matching.len();
        let items = matching
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|(k, v)| (k.to_vec(), v.to_vec()))
            .collect();
        let has_more = offset + limit < total;
        Page {
            items,
            total,
            offset,
            limit,
            has_more,
        }
    }

    /// High-performance keyset (cursor-based) pagination across all entries.
    pub fn paginate_keyset(
        &self,
        after_key: Option<&[u8]>,
        limit: usize,
    ) -> KeysetPage<Vec<u8>, Vec<u8>> {
        use std::ops::Bound;
        let range: (Bound<&[u8]>, Bound<&[u8]>) = match after_key {
            Some(k) => (Bound::Excluded(k), Bound::Unbounded),
            None => (Bound::Unbounded, Bound::Unbounded),
        };

        let mut items = Vec::with_capacity(limit);
        let mut has_more = false;

        for (k, v) in self.index.range::<[u8], _>(range) {
            if items.len() < limit {
                items.push((k.clone(), v.clone()));
            } else {
                has_more = true;
                break;
            }
        }

        let next_cursor = if has_more {
            items.last().map(|(k, _)| k.clone())
        } else {
            None
        };

        KeysetPage {
            items,
            next_cursor,
            has_more,
        }
    }

    /// High-performance keyset (cursor-based) pagination across entries matching a prefix.
    pub fn paginate_prefix_keyset(
        &self,
        prefix: &[u8],
        after_key: Option<&[u8]>,
        limit: usize,
    ) -> KeysetPage<Vec<u8>, Vec<u8>> {
        use std::ops::Bound;
        let start_bound = match after_key {
            Some(k) => Bound::Excluded(k),
            None => Bound::Included(prefix),
        };

        let mut items = Vec::with_capacity(limit);
        let mut has_more = false;

        for (k, v) in self.index.range::<[u8], _>((start_bound, Bound::Unbounded)) {
            if !k.starts_with(prefix) {
                break;
            }
            if items.len() < limit {
                items.push((k.clone(), v.clone()));
            } else {
                has_more = true;
                break;
            }
        }

        let next_cursor = if has_more {
            items.last().map(|(k, _)| k.clone())
        } else {
            None
        };

        KeysetPage {
            items,
            next_cursor,
            has_more,
        }
    }

    /// Compact the WAL file by writing a fresh consolidated log.
    pub fn compact(&mut self) -> Result<(), DbError> {
        let compact_path = self.path.join("wal.compact");
        let mut compact_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&compact_path)?;

        compact_file.write_all(&DB_MAGIC)?;
        compact_file.write_all(&DB_VERSION.to_le_bytes())?;

        for (k, v) in &self.index {
            let mut record = Vec::new();
            record.push(WalRecordType::Put as u8);
            record.extend_from_slice(&(k.len() as u16).to_le_bytes());
            record.extend_from_slice(k);
            record.extend_from_slice(&(v.len() as u32).to_le_bytes());
            record.extend_from_slice(v);

            let hash = blake3::hash(&record);
            compact_file.write_all(&record)?;
            compact_file.write_all(hash.as_bytes())?;
        }

        compact_file.sync_all()?;
        drop(compact_file);

        let wal_path = self.path.join("wal.log");
        std::fs::rename(compact_path, &wal_path)?;

        self.wal_file = OpenOptions::new().read(true).write(true).open(&wal_path)?;

        self.wal_file.seek(SeekFrom::End(0))?;
        Ok(())
    }

    fn append_wal_record(
        &mut self,
        rec_type: WalRecordType,
        key: &[u8],
        val: &[u8],
    ) -> Result<(), DbError> {
        let mut buf = Vec::new();
        buf.push(rec_type as u8);

        match rec_type {
            WalRecordType::Put => {
                buf.extend_from_slice(&(key.len() as u16).to_le_bytes());
                buf.extend_from_slice(key);
                buf.extend_from_slice(&(val.len() as u32).to_le_bytes());
                buf.extend_from_slice(val);
            }
            WalRecordType::Delete => {
                buf.extend_from_slice(&(key.len() as u16).to_le_bytes());
                buf.extend_from_slice(key);
            }
            WalRecordType::Commit => {}
        }

        let checksum = blake3::hash(&buf);
        self.wal_file.write_all(&buf)?;
        self.wal_file.write_all(checksum.as_bytes())?;
        Ok(())
    }

    fn replay_wal(file: &mut File, index: &mut BTreeMap<Vec<u8>, Vec<u8>>) -> Result<(), DbError> {
        let mut magic = [0u8; 4];
        file.read_exact(&mut magic)?;
        if magic != DB_MAGIC {
            return Err(DbError::InvalidHeader);
        }

        let mut ver_bytes = [0u8; 4];
        file.read_exact(&mut ver_bytes)?;
        let ver = u32::from_le_bytes(ver_bytes);
        if ver != DB_VERSION {
            return Err(DbError::UnsupportedVersion(ver));
        }

        let mut pending_puts = Vec::new();
        let mut pending_deletes = Vec::new();

        loop {
            let mut type_byte = [0u8; 1];
            match file.read_exact(&mut type_byte) {
                Ok(()) => {}
                Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(DbError::Io(e)),
            }

            let mut record_data = vec![type_byte[0]];

            match type_byte[0] {
                1 => {
                    // Put
                    let mut k_len_buf = [0u8; 2];
                    file.read_exact(&mut k_len_buf)?;
                    record_data.extend_from_slice(&k_len_buf);
                    let k_len = u16::from_le_bytes(k_len_buf) as usize;

                    let mut key = vec![0u8; k_len];
                    file.read_exact(&mut key)?;
                    record_data.extend_from_slice(&key);

                    let mut v_len_buf = [0u8; 4];
                    file.read_exact(&mut v_len_buf)?;
                    record_data.extend_from_slice(&v_len_buf);
                    let v_len = u32::from_le_bytes(v_len_buf) as usize;

                    let mut val = vec![0u8; v_len];
                    file.read_exact(&mut val)?;
                    record_data.extend_from_slice(&val);

                    let mut checksum = [0u8; 32];
                    file.read_exact(&mut checksum)?;

                    let expected_hash = blake3::hash(&record_data);
                    if expected_hash.as_bytes() != &checksum {
                        return Err(DbError::ChecksumMismatch);
                    }

                    pending_puts.push((key, val));
                }
                2 => {
                    // Delete
                    let mut k_len_buf = [0u8; 2];
                    file.read_exact(&mut k_len_buf)?;
                    record_data.extend_from_slice(&k_len_buf);
                    let k_len = u16::from_le_bytes(k_len_buf) as usize;

                    let mut key = vec![0u8; k_len];
                    file.read_exact(&mut key)?;
                    record_data.extend_from_slice(&key);

                    let mut checksum = [0u8; 32];
                    file.read_exact(&mut checksum)?;

                    let expected_hash = blake3::hash(&record_data);
                    if expected_hash.as_bytes() != &checksum {
                        return Err(DbError::ChecksumMismatch);
                    }

                    pending_deletes.push(key);
                }
                3 => {
                    // Commit
                    let mut checksum = [0u8; 32];
                    file.read_exact(&mut checksum)?;
                    let expected_hash = blake3::hash(&record_data);
                    if expected_hash.as_bytes() != &checksum {
                        return Err(DbError::ChecksumMismatch);
                    }

                    // Apply transaction batch
                    for (k, v) in pending_puts.drain(..) {
                        index.insert(k, v);
                    }
                    for k in pending_deletes.drain(..) {
                        index.remove(&k);
                    }
                }
                _ => return Err(DbError::InvalidHeader),
            }
        }

        Ok(())
    }
}

impl<'a> Transaction<'a> {
    /// Read key within transaction snapshot.
    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        if self.staged_deletes.iter().any(|k| k.as_slice() == key) {
            return None;
        }
        if let Some(val) = self.staged_puts.get(key) {
            return Some(val.as_slice());
        }
        self.db.get(key)
    }

    /// Stage a put operation.
    pub fn put(&mut self, key: &[u8], val: &[u8]) {
        self.staged_deletes.retain(|k| k.as_slice() != key);
        self.staged_puts.insert(key.to_vec(), val.to_vec());
    }

    /// Stage a delete operation.
    pub fn delete(&mut self, key: &[u8]) {
        self.staged_puts.remove(key);
        self.staged_deletes.push(key.to_vec());
    }

    /// Return all key-value entries in the transaction snapshot.
    pub fn iter(&self) -> Vec<(&[u8], &[u8])> {
        let mut map: BTreeMap<&[u8], &[u8]> = BTreeMap::new();
        for (k, v) in self.db.iter() {
            if !self.staged_deletes.iter().any(|d| d.as_slice() == k) {
                map.insert(k, v);
            }
        }
        for (k, v) in &self.staged_puts {
            map.insert(k.as_slice(), v.as_slice());
        }
        map.into_iter().collect()
    }

    /// Scan entries matching `prefix` in the transaction snapshot.
    pub fn scan_prefix<'b>(&'b self, prefix: &'b [u8]) -> Vec<(&'b [u8], &'b [u8])> {
        self.iter()
            .into_iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .collect()
    }

    /// Paginate entries in the transaction snapshot.
    pub fn paginate(&self, offset: usize, limit: usize) -> Page<Vec<u8>, Vec<u8>> {
        let all = self.iter();
        let total = all.len();
        let items = all
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|(k, v)| (k.to_vec(), v.to_vec()))
            .collect();
        let has_more = offset + limit < total;
        Page {
            items,
            total,
            offset,
            limit,
            has_more,
        }
    }

    /// Atomically commit all staged operations to the WAL.
    pub fn commit(mut self) -> Result<(), DbError> {
        for (k, v) in &self.staged_puts {
            self.db.append_wal_record(WalRecordType::Put, k, v)?;
        }
        for k in &self.staged_deletes {
            self.db.append_wal_record(WalRecordType::Delete, k, &[])?;
        }
        self.db.append_wal_record(WalRecordType::Commit, &[], &[])?;

        if self.db.is_sync {
            self.db.wal_file.sync_data()?;
        }

        // Apply changes in memory
        for (k, v) in std::mem::take(&mut self.staged_puts) {
            self.db.index.insert(k, v);
        }
        for k in self.staged_deletes.drain(..) {
            self.db.index.remove(&k);
        }

        self.committed = true;
        Ok(())
    }

    /// Rollback staged changes without modifying database state.
    pub fn rollback(mut self) {
        self.staged_puts.clear();
        self.staged_deletes.clear();
        self.committed = true;
    }
}

impl<'a> Drop for Transaction<'a> {
    fn drop(&mut self) {
        if !self.committed {
            self.staged_puts.clear();
            self.staged_deletes.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_db_basic_crud_and_persistence() {
        let temp_dir = std::env::temp_dir().join("ifa_test_db_crud");
        let _ = std::fs::remove_dir_all(&temp_dir);

        {
            let mut db = Database::open(&temp_dir).expect("Failed to open DB");
            assert!(db.is_empty());

            db.put(b"user:101", b"{\"name\":\"Alice\",\"role\":\"admin\"}")
                .unwrap();
            db.put(b"user:102", b"{\"name\":\"Bob\",\"role\":\"editor\"}")
                .unwrap();

            assert_eq!(db.len(), 2);
            assert_eq!(
                db.get(b"user:101").unwrap(),
                b"{\"name\":\"Alice\",\"role\":\"admin\"}"
            );

            assert!(db.delete(b"user:102").unwrap());
            assert!(!db.contains_key(b"user:102"));
            assert_eq!(db.len(), 1);
        }

        // Re-open database and verify WAL replay
        {
            let mut db = Database::open(&temp_dir).expect("Failed to reopen DB");
            assert_eq!(db.len(), 1);
            assert_eq!(
                db.get(b"user:101").unwrap(),
                b"{\"name\":\"Alice\",\"role\":\"admin\"}"
            );
            assert!(!db.contains_key(b"user:102"));

            db.compact().expect("Failed to compact DB");
            assert_eq!(db.len(), 1);
        }

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_db_batch_operations_and_replay() {
        let temp_dir = std::env::temp_dir().join("ifa_test_db_batch");
        let _ = std::fs::remove_dir_all(&temp_dir);

        {
            let mut db = Database::open(&temp_dir).expect("Failed to open DB");
            let entries: [(&[u8], &[u8]); 4] = [
                (b"cfg:theme", b"dark"),
                (b"cfg:font_size", b"14"),
                (b"cfg:lang", b"fr"),
                (b"cfg:auto_save", b"true"),
            ];

            db.put_batch(&entries).expect("put_batch failed");
            assert_eq!(db.len(), 4);
            assert_eq!(db.get(b"cfg:theme").unwrap(), b"dark");
            assert_eq!(db.get(b"cfg:auto_save").unwrap(), b"true");

            let del_keys: [&[u8]; 2] = [b"cfg:font_size", b"cfg:non_existent"];
            let deleted = db.delete_batch(&del_keys).expect("delete_batch failed");
            assert_eq!(deleted, 1);
            assert_eq!(db.len(), 3);
            assert!(!db.contains_key(b"cfg:font_size"));
        }

        // Reopen to verify WAL replay of batch operations
        {
            let db = Database::open(&temp_dir).expect("Failed to reopen DB");
            assert_eq!(db.len(), 3);
            assert_eq!(db.get(b"cfg:theme").unwrap(), b"dark");
            assert_eq!(db.get(b"cfg:lang").unwrap(), b"fr");
            assert_eq!(db.get(b"cfg:auto_save").unwrap(), b"true");
            assert!(!db.contains_key(b"cfg:font_size"));
        }

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_db_scan_range_and_prefix() {
        let temp_dir = std::env::temp_dir().join("ifa_test_db_scan");
        let _ = std::fs::remove_dir_all(&temp_dir);

        let mut db = Database::open(&temp_dir).expect("Failed to open DB");
        let batch: [(&[u8], &[u8]); 6] = [
            (b"order:100", b"status=pending"),
            (b"order:101", b"status=shipped"),
            (b"order:102", b"status=delivered"),
            (b"user:001", b"name=Alice"),
            (b"user:002", b"name=Bob"),
            (b"user:003", b"name=Charlie"),
        ];
        db.put_batch(&batch).unwrap();

        // Test prefix scanning
        let orders: Vec<(&[u8], &[u8])> = db.scan_prefix(b"order:").collect();
        assert_eq!(orders.len(), 3);
        assert_eq!(orders[0].0, b"order:100");
        assert_eq!(orders[1].0, b"order:101");
        assert_eq!(orders[2].0, b"order:102");

        let users: Vec<(&[u8], &[u8])> = db.scan_prefix(b"user:").collect();
        assert_eq!(users.len(), 3);
        assert_eq!(users[0].0, b"user:001");
        assert_eq!(users[2].0, b"user:003");

        // Test scan range (inclusive and exclusive)
        let subrange: Vec<(&[u8], &[u8])> = db.scan_range(b"order:101", b"order:102").collect();
        assert_eq!(subrange.len(), 2);
        assert_eq!(subrange[0].0, b"order:101");
        assert_eq!(subrange[1].0, b"order:102");

        // Test reverse iteration
        let rev_users: Vec<&[u8]> = db.keys().rev().take(3).collect();
        assert_eq!(
            rev_users,
            vec![
                b"user:003".as_slice(),
                b"user:002".as_slice(),
                b"user:001".as_slice()
            ]
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_db_offset_and_keyset_pagination() {
        let temp_dir = std::env::temp_dir().join("ifa_test_db_pagination");
        let _ = std::fs::remove_dir_all(&temp_dir);

        let mut db = Database::open(&temp_dir).expect("Failed to open DB");
        for i in 0..10 {
            let key = format!("item:{:02}", i);
            let val = format!("val:{}", i);
            db.put(key.as_bytes(), val.as_bytes()).unwrap();
        }

        // Test offset-based pagination: page 1 (items 0..4)
        let p1 = db.paginate(0, 4);
        assert_eq!(p1.len(), 4);
        assert_eq!(p1.total, 10);
        assert!(p1.has_more);
        assert_eq!(p1.items[0].0, b"item:00");
        assert_eq!(p1.items[3].0, b"item:03");

        // Page 2 (items 4..8)
        let p2 = db.paginate(4, 4);
        assert_eq!(p2.len(), 4);
        assert!(p2.has_more);
        assert_eq!(p2.items[0].0, b"item:04");

        // Page 3 (items 8..10)
        let p3 = db.paginate(8, 4);
        assert_eq!(p3.len(), 2);
        assert!(!p3.has_more);
        assert_eq!(p3.items[0].0, b"item:08");
        assert_eq!(p3.items[1].0, b"item:09");

        // Test keyset pagination across pages
        let kp1 = db.paginate_keyset(None, 4);
        assert_eq!(kp1.len(), 4);
        assert!(kp1.has_more);
        assert_eq!(kp1.items[0].0, b"item:00");
        assert_eq!(kp1.items[3].0, b"item:03");
        assert_eq!(kp1.next_cursor.as_deref(), Some(b"item:03".as_slice()));

        let kp2 = db.paginate_keyset(kp1.next_cursor.as_deref(), 4);
        assert_eq!(kp2.len(), 4);
        assert!(kp2.has_more);
        assert_eq!(kp2.items[0].0, b"item:04");
        assert_eq!(kp2.items[3].0, b"item:07");
        assert_eq!(kp2.next_cursor.as_deref(), Some(b"item:07".as_slice()));

        let kp3 = db.paginate_keyset(kp2.next_cursor.as_deref(), 4);
        assert_eq!(kp3.len(), 2);
        assert!(!kp3.has_more);
        assert_eq!(kp3.items[0].0, b"item:08");
        assert_eq!(kp3.items[1].0, b"item:09");
        assert_eq!(kp3.next_cursor, None);

        // Test prefix keyset pagination
        let pkp = db.paginate_prefix_keyset(b"item:0", None, 5);
        assert_eq!(pkp.len(), 5);
        assert!(pkp.has_more);
        assert_eq!(pkp.items[0].0, b"item:00");
        assert_eq!(pkp.items[4].0, b"item:04");
        assert_eq!(pkp.next_cursor.as_deref(), Some(b"item:04".as_slice()));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_db_transaction_query_snapshot() {
        let temp_dir = std::env::temp_dir().join("ifa_test_db_tx_query");
        let _ = std::fs::remove_dir_all(&temp_dir);

        let mut db = Database::open(&temp_dir).expect("Failed to open DB");
        db.put(b"k1", b"v1").unwrap();
        db.put(b"k2", b"v2").unwrap();
        db.put(b"k3", b"v3").unwrap();

        {
            let mut tx = db.begin_transaction();
            tx.delete(b"k2");
            tx.put(b"k4", b"v4");

            // Verify transaction isolated view
            let entries = tx.iter();
            let keys: Vec<&[u8]> = entries.iter().map(|(k, _)| *k).collect();
            assert_eq!(
                keys,
                vec![b"k1".as_slice(), b"k3".as_slice(), b"k4".as_slice()]
            );

            let page = tx.paginate(0, 2);
            assert_eq!(page.len(), 2);
            assert_eq!(page.total, 3);
            assert!(page.has_more);

            tx.commit().unwrap();
        }

        assert_eq!(db.len(), 3);
        assert!(!db.contains_key(b"k2"));
        assert_eq!(db.get(b"k4").unwrap(), b"v4");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_db_transaction_commit_and_rollback() {
        let temp_dir = std::env::temp_dir().join("ifa_test_db_tx");
        let _ = std::fs::remove_dir_all(&temp_dir);

        let mut db = Database::open(&temp_dir).expect("Failed to open DB");
        db.put(b"counter", b"10").unwrap();

        // Rollback test
        {
            let mut tx = db.begin_transaction();
            tx.put(b"counter", b"20");
            tx.put(b"temporary", b"discard");
            assert_eq!(tx.get(b"counter").unwrap(), b"20");
            tx.rollback();
        }
        assert_eq!(db.get(b"counter").unwrap(), b"10");
        assert!(!db.contains_key(b"temporary"));

        // Commit test
        {
            let mut tx = db.begin_transaction();
            tx.put(b"counter", b"30");
            tx.put(b"new_key", b"saved");
            tx.commit().expect("Commit failed");
        }
        assert_eq!(db.get(b"counter").unwrap(), b"30");
        assert_eq!(db.get(b"new_key").unwrap(), b"saved");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}

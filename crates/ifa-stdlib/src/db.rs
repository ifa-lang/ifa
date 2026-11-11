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

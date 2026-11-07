//! Deterministic file system primitives (`std::fs`).

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Metadata representation of a file or directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMetadata {
    pub is_file: bool,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub size: u64,
    pub readonly: bool,
}

/// Read an entire file into a UTF-8 String.
pub fn read_to_string<P: AsRef<Path>>(path: P) -> io::Result<String> {
    fs::read_to_string(path)
}

/// Read an entire file into a byte vector.
pub fn read<P: AsRef<Path>>(path: P) -> io::Result<Vec<u8>> {
    fs::read(path)
}

/// Write bytes to a file, replacing existing contents or creating the file.
pub fn write<P: AsRef<Path>, C: AsRef<[u8]>>(path: P, contents: C) -> io::Result<()> {
    fs::write(path, contents)
}

/// Write a string slice to a file, replacing existing contents.
pub fn write_string<P: AsRef<Path>>(path: P, contents: &str) -> io::Result<()> {
    fs::write(path, contents.as_bytes())
}

/// Append bytes to the end of a file, creating it if it does not exist.
pub fn append<P: AsRef<Path>, C: AsRef<[u8]>>(path: P, contents: C) -> io::Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(contents.as_ref())
}

/// Check if a path exists on the filesystem.
pub fn exists<P: AsRef<Path>>(path: P) -> bool {
    path.as_ref().exists()
}

/// Check if a path points to an existing regular file.
pub fn is_file<P: AsRef<Path>>(path: P) -> bool {
    path.as_ref().is_file()
}

/// Check if a path points to an existing directory.
pub fn is_dir<P: AsRef<Path>>(path: P) -> bool {
    path.as_ref().is_dir()
}

/// Create a single directory.
pub fn create_dir<P: AsRef<Path>>(path: P) -> io::Result<()> {
    fs::create_dir(path)
}

/// Recursively create a directory and all of its parent components if missing.
pub fn create_dir_all<P: AsRef<Path>>(path: P) -> io::Result<()> {
    fs::create_dir_all(path)
}

/// Remove a single file.
pub fn remove_file<P: AsRef<Path>>(path: P) -> io::Result<()> {
    fs::remove_file(path)
}

/// Remove an empty directory.
pub fn remove_dir<P: AsRef<Path>>(path: P) -> io::Result<()> {
    fs::remove_dir(path)
}

/// Recursively remove a directory and all its contents.
pub fn remove_dir_all<P: AsRef<Path>>(path: P) -> io::Result<()> {
    fs::remove_dir_all(path)
}

/// Copy the contents of one file to another.
pub fn copy<P: AsRef<Path>, Q: AsRef<Path>>(from: P, to: Q) -> io::Result<u64> {
    fs::copy(from, to)
}

/// Rename / move a file or directory from one path to another.
pub fn rename<P: AsRef<Path>, Q: AsRef<Path>>(from: P, to: Q) -> io::Result<()> {
    fs::rename(from, to)
}

/// Query size in bytes of a file.
pub fn file_size<P: AsRef<Path>>(path: P) -> io::Result<u64> {
    fs::metadata(path).map(|m| m.len())
}

/// List all entries within a directory.
pub fn list_dir<P: AsRef<Path>>(path: P) -> io::Result<Vec<PathBuf>> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        entries.push(entry.path());
    }
    entries.sort();
    Ok(entries)
}

/// Query full file metadata.
pub fn metadata<P: AsRef<Path>>(path: P) -> io::Result<FileMetadata> {
    let meta = fs::metadata(path)?;
    Ok(FileMetadata {
        is_file: meta.is_file(),
        is_dir: meta.is_dir(),
        is_symlink: meta.file_type().is_symlink(),
        size: meta.len(),
        readonly: meta.permissions().readonly(),
    })
}

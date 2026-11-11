//! Deterministic file system primitives (`std::fs`) with multi-target POSIX and WASI capability support.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

/// Target filesystem execution kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetKind {
    /// Host operating system filesystem (POSIX on Linux/macOS/Unix, native Windows).
    Posix,
    /// WebAssembly System Interface (WASI) sandboxed filesystem with capability rights.
    Wasi,
    /// In-memory deterministic virtual filesystem (ideal for standalone WASM & tests).
    Virtual,
}

/// Capability rights governing file and directory operations in WASI sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WasiRights {
    pub read: bool,
    pub write: bool,
    pub create: bool,
    pub delete: bool,
    pub list: bool,
    pub traverse: bool,
}

impl WasiRights {
    pub const NONE: Self = Self {
        read: false,
        write: false,
        create: false,
        delete: false,
        list: false,
        traverse: false,
    };

    pub const READ_ONLY: Self = Self {
        read: true,
        write: false,
        create: false,
        delete: false,
        list: true,
        traverse: true,
    };

    pub const READ_WRITE: Self = Self {
        read: true,
        write: true,
        create: true,
        delete: true,
        list: true,
        traverse: true,
    };
}

/// Preopened directory mapping for WASI capability-based access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasiPreopen {
    /// Guest mount path inside the WASI container (e.g. `"/sandbox"` or `"/"`).
    pub guest_path: PathBuf,
    /// Host directory backing this preopen, if mapped to physical disk.
    pub host_path: Option<PathBuf>,
    /// Permissions and capabilities granted within this preopen.
    pub rights: WasiRights,
}

/// Metadata representation of a file or directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMetadata {
    pub is_file: bool,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub size: u64,
    pub readonly: bool,
}

/// Abstract filesystem trait supporting multiple targets (POSIX, WASI, Virtual).
pub trait FileSystem: Send + Sync {
    /// Target execution environment kind.
    fn target_kind(&self) -> TargetKind;

    /// Read an entire file into a byte vector.
    fn read(&self, path: &Path) -> io::Result<Vec<u8>>;

    /// Read an entire file into a UTF-8 String.
    fn read_to_string(&self, path: &Path) -> io::Result<String> {
        let bytes = self.read(path)?;
        String::from_utf8(bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Write bytes to a file, replacing existing contents or creating the file.
    fn write(&self, path: &Path, contents: &[u8]) -> io::Result<()>;

    /// Append bytes to the end of a file, creating it if it does not exist.
    fn append(&self, path: &Path, contents: &[u8]) -> io::Result<()>;

    /// Check if a path exists on the filesystem.
    fn exists(&self, path: &Path) -> bool;

    /// Check if a path points to an existing regular file.
    fn is_file(&self, path: &Path) -> bool;

    /// Check if a path points to an existing directory.
    fn is_dir(&self, path: &Path) -> bool;

    /// Create a single directory.
    fn create_dir(&self, path: &Path) -> io::Result<()>;

    /// Recursively create a directory and all parent components.
    fn create_dir_all(&self, path: &Path) -> io::Result<()>;

    /// Remove a single file.
    fn remove_file(&self, path: &Path) -> io::Result<()>;

    /// Remove an empty directory.
    fn remove_dir(&self, path: &Path) -> io::Result<()>;

    /// Recursively remove a directory and all its contents.
    fn remove_dir_all(&self, path: &Path) -> io::Result<()>;

    /// Copy the contents of one file to another.
    fn copy(&self, from: &Path, to: &Path) -> io::Result<u64>;

    /// Rename / move a file or directory from one path to another.
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()>;

    /// Query size in bytes of a file.
    fn file_size(&self, path: &Path) -> io::Result<u64>;

    /// Query full file metadata.
    fn metadata(&self, path: &Path) -> io::Result<FileMetadata>;

    /// List all immediate entries within a directory in deterministic order.
    fn list_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>>;

    /// Recursively walk a directory tree in deterministic order.
    fn walk_dir(&self, root: &Path) -> io::Result<Vec<PathBuf>>;
}

/// Normalizes any path by resolving `.` and `..` components cleanly without OS syscalls.
pub fn normalize_path(path: &Path) -> PathBuf {
    let is_absolute = path.is_absolute();
    let mut components = Vec::new();

    for comp in path.components() {
        match comp {
            std::path::Component::Prefix(p) => {
                components.push(p.as_os_str().to_string_lossy().to_string());
            }
            std::path::Component::RootDir => {
                components.clear();
            }
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                components.pop();
            }
            std::path::Component::Normal(n) => {
                components.push(n.to_string_lossy().to_string());
            }
        }
    }

    let mut buf = PathBuf::new();
    if is_absolute {
        buf.push(std::path::MAIN_SEPARATOR.to_string());
    }
    for comp in components {
        buf.push(comp);
    }
    if buf.as_os_str().is_empty() {
        PathBuf::from(if is_absolute { "/" } else { "." })
    } else {
        buf
    }
}

/// Helper to normalize virtual paths into root-prefixed canonical forms (e.g. `"/sub/test.txt"`).
fn normalize_virtual_path(path: &Path) -> PathBuf {
    let mut components = Vec::new();

    for comp in path.components() {
        match comp {
            std::path::Component::Prefix(_) | std::path::Component::RootDir => {
                components.clear();
            }
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                components.pop();
            }
            std::path::Component::Normal(n) => {
                components.push(n.to_string_lossy().to_string());
            }
        }
    }

    let mut buf = PathBuf::from("/");
    for comp in components {
        buf.push(comp);
    }
    buf
}

// ---------------------------------------------------------------------------
// Native POSIX Driver
// ---------------------------------------------------------------------------

/// Host operating system filesystem driver (POSIX & Windows).
#[derive(Debug, Default, Clone)]
pub struct PosixFs;

impl PosixFs {
    pub fn new() -> Self {
        Self
    }
}

impl FileSystem for PosixFs {
    fn target_kind(&self) -> TargetKind {
        TargetKind::Posix
    }

    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        fs::read(path)
    }

    fn read_to_string(&self, path: &Path) -> io::Result<String> {
        fs::read_to_string(path)
    }

    fn write(&self, path: &Path, contents: &[u8]) -> io::Result<()> {
        fs::write(path, contents)
    }

    fn append(&self, path: &Path, contents: &[u8]) -> io::Result<()> {
        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        file.write_all(contents)
    }

    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn is_file(&self, path: &Path) -> bool {
        path.is_file()
    }

    fn is_dir(&self, path: &Path) -> bool {
        path.is_dir()
    }

    fn create_dir(&self, path: &Path) -> io::Result<()> {
        fs::create_dir(path)
    }

    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        fs::create_dir_all(path)
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        fs::remove_file(path)
    }

    fn remove_dir(&self, path: &Path) -> io::Result<()> {
        fs::remove_dir(path)
    }

    fn remove_dir_all(&self, path: &Path) -> io::Result<()> {
        fs::remove_dir_all(path)
    }

    fn copy(&self, from: &Path, to: &Path) -> io::Result<u64> {
        fs::copy(from, to)
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        fs::rename(from, to)
    }

    fn file_size(&self, path: &Path) -> io::Result<u64> {
        fs::metadata(path).map(|m| m.len())
    }

    fn metadata(&self, path: &Path) -> io::Result<FileMetadata> {
        let meta = fs::metadata(path)?;
        Ok(FileMetadata {
            is_file: meta.is_file(),
            is_dir: meta.is_dir(),
            is_symlink: meta.file_type().is_symlink(),
            size: meta.len(),
            readonly: meta.permissions().readonly(),
        })
    }

    fn list_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        let mut entries = Vec::new();
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            entries.push(entry.path());
        }
        entries.sort();
        Ok(entries)
    }

    fn walk_dir(&self, root: &Path) -> io::Result<Vec<PathBuf>> {
        let mut results = Vec::new();
        walk_dir_internal(root, &mut results)?;
        results.sort();
        Ok(results)
    }
}

fn walk_dir_internal(dir: &Path, acc: &mut Vec<PathBuf>) -> io::Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    let mut sub_entries = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        sub_entries.push(entry.path());
    }
    sub_entries.sort();
    for entry_path in sub_entries {
        let is_directory = entry_path.is_dir();
        acc.push(entry_path.clone());
        if is_directory {
            walk_dir_internal(&entry_path, acc)?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Virtual In-Memory Driver
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum VirtualNode {
    File { data: Vec<u8>, readonly: bool },
    Dir,
}

/// In-memory deterministic virtual filesystem.
#[derive(Debug)]
pub struct VirtualFs {
    nodes: RwLock<BTreeMap<PathBuf, VirtualNode>>,
}

impl Default for VirtualFs {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtualFs {
    pub fn new() -> Self {
        let mut map = BTreeMap::new();
        map.insert(PathBuf::from("/"), VirtualNode::Dir);
        Self {
            nodes: RwLock::new(map),
        }
    }

    /// Set readonly flag on a virtual file.
    pub fn set_readonly(&self, path: &Path, readonly: bool) -> io::Result<()> {
        let norm = normalize_virtual_path(path);
        let mut nodes = self.nodes.write().unwrap();
        match nodes.get_mut(&norm) {
            Some(VirtualNode::File { readonly: ro, .. }) => {
                *ro = readonly;
                Ok(())
            }
            Some(VirtualNode::Dir) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Cannot set readonly on a directory",
            )),
            None => Err(io::Error::new(io::ErrorKind::NotFound, "File not found")),
        }
    }
}

impl FileSystem for VirtualFs {
    fn target_kind(&self) -> TargetKind {
        TargetKind::Virtual
    }

    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        let norm = normalize_virtual_path(path);
        let nodes = self.nodes.read().unwrap();
        match nodes.get(&norm) {
            Some(VirtualNode::File { data, .. }) => Ok(data.clone()),
            Some(VirtualNode::Dir) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Is a directory: {}", path.display()),
            )),
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("File not found: {}", path.display()),
            )),
        }
    }

    fn write(&self, path: &Path, contents: &[u8]) -> io::Result<()> {
        let norm = normalize_virtual_path(path);
        let parent = norm.parent().unwrap_or_else(|| Path::new("/"));

        let mut nodes = self.nodes.write().unwrap();
        if !nodes.contains_key(parent) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Parent directory does not exist: {}", parent.display()),
            ));
        }

        if let Some(VirtualNode::Dir) = nodes.get(&norm) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("Path is already a directory: {}", norm.display()),
            ));
        }

        if let Some(VirtualNode::File { readonly: true, .. }) = nodes.get(&norm) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("File is read-only: {}", norm.display()),
            ));
        }

        nodes.insert(
            norm,
            VirtualNode::File {
                data: contents.to_vec(),
                readonly: false,
            },
        );
        Ok(())
    }

    fn append(&self, path: &Path, contents: &[u8]) -> io::Result<()> {
        let norm = normalize_virtual_path(path);
        let parent = norm.parent().unwrap_or_else(|| Path::new("/"));

        let mut nodes = self.nodes.write().unwrap();
        if !nodes.contains_key(parent) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Parent directory does not exist: {}", parent.display()),
            ));
        }

        match nodes.get_mut(&norm) {
            Some(VirtualNode::File {
                data,
                readonly: false,
            }) => {
                data.extend_from_slice(contents);
                Ok(())
            }
            Some(VirtualNode::File {
                readonly: true, ..
            }) => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("File is read-only: {}", norm.display()),
            )),
            Some(VirtualNode::Dir) => Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("Path is a directory: {}", norm.display()),
            )),
            None => {
                nodes.insert(
                    norm,
                    VirtualNode::File {
                        data: contents.to_vec(),
                        readonly: false,
                    },
                );
                Ok(())
            }
        }
    }

    fn exists(&self, path: &Path) -> bool {
        let norm = normalize_virtual_path(path);
        let nodes = self.nodes.read().unwrap();
        nodes.contains_key(&norm)
    }

    fn is_file(&self, path: &Path) -> bool {
        let norm = normalize_virtual_path(path);
        let nodes = self.nodes.read().unwrap();
        matches!(nodes.get(&norm), Some(VirtualNode::File { .. }))
    }

    fn is_dir(&self, path: &Path) -> bool {
        let norm = normalize_virtual_path(path);
        if norm == Path::new("/") {
            return true;
        }
        let nodes = self.nodes.read().unwrap();
        matches!(nodes.get(&norm), Some(VirtualNode::Dir))
    }

    fn create_dir(&self, path: &Path) -> io::Result<()> {
        let norm = normalize_virtual_path(path);
        if norm == Path::new("/") {
            return Ok(());
        }

        let parent = norm.parent().unwrap_or_else(|| Path::new("/"));
        let mut nodes = self.nodes.write().unwrap();

        if !nodes.contains_key(parent) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Parent directory does not exist: {}", parent.display()),
            ));
        }

        if nodes.contains_key(&norm) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("Directory already exists: {}", norm.display()),
            ));
        }

        nodes.insert(norm, VirtualNode::Dir);
        Ok(())
    }

    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        let norm = normalize_virtual_path(path);
        if norm == Path::new("/") {
            return Ok(());
        }

        let mut nodes = self.nodes.write().unwrap();
        let mut current = PathBuf::from("/");

        for comp in norm.components() {
            if let std::path::Component::Normal(c) = comp {
                current.push(c);
                if let Some(VirtualNode::File { .. }) = nodes.get(&current) {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        format!("Component is a file: {}", current.display()),
                    ));
                }
                nodes.entry(current.clone()).or_insert(VirtualNode::Dir);
            }
        }
        Ok(())
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        let norm = normalize_virtual_path(path);
        let mut nodes = self.nodes.write().unwrap();
        match nodes.get(&norm) {
            Some(VirtualNode::File { .. }) => {
                nodes.remove(&norm);
                Ok(())
            }
            Some(VirtualNode::Dir) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Cannot remove directory as file: {}", norm.display()),
            )),
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("File not found: {}", norm.display()),
            )),
        }
    }

    fn remove_dir(&self, path: &Path) -> io::Result<()> {
        let norm = normalize_virtual_path(path);
        if norm == Path::new("/") {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Cannot remove root directory",
            ));
        }

        let mut nodes = self.nodes.write().unwrap();
        match nodes.get(&norm) {
            Some(VirtualNode::Dir) => {
                // Check if directory has any children
                let has_children = nodes.keys().any(|k| k != &norm && k.starts_with(&norm));
                if has_children {
                    return Err(io::Error::new(
                        io::ErrorKind::DirectoryNotEmpty,
                        format!("Directory not empty: {}", norm.display()),
                    ));
                }
                nodes.remove(&norm);
                Ok(())
            }
            Some(VirtualNode::File { .. }) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Not a directory: {}", norm.display()),
            )),
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Directory not found: {}", norm.display()),
            )),
        }
    }

    fn remove_dir_all(&self, path: &Path) -> io::Result<()> {
        let norm = normalize_virtual_path(path);
        if norm == Path::new("/") {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Cannot remove root directory",
            ));
        }

        let mut nodes = self.nodes.write().unwrap();
        if !nodes.contains_key(&norm) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Directory not found: {}", norm.display()),
            ));
        }

        let keys_to_remove: Vec<PathBuf> = nodes
            .keys()
            .filter(|k| *k == &norm || k.starts_with(&norm))
            .cloned()
            .collect();

        for key in keys_to_remove {
            nodes.remove(&key);
        }
        Ok(())
    }

    fn copy(&self, from: &Path, to: &Path) -> io::Result<u64> {
        let bytes = self.read(from)?;
        self.write(to, &bytes)?;
        Ok(bytes.len() as u64)
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        let from_norm = normalize_virtual_path(from);
        let to_norm = normalize_virtual_path(to);

        if from_norm == to_norm {
            return Ok(());
        }

        let mut nodes = self.nodes.write().unwrap();
        let node = nodes.get(&from_norm).cloned().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("Source path not found: {}", from_norm.display()),
            )
        })?;

        match node {
            VirtualNode::File { .. } => {
                nodes.remove(&from_norm);
                nodes.insert(to_norm, node);
            }
            VirtualNode::Dir => {
                let descendant_keys: Vec<PathBuf> = nodes
                    .keys()
                    .filter(|k| *k == &from_norm || k.starts_with(&from_norm))
                    .cloned()
                    .collect();

                for old_key in descendant_keys {
                    let old_node = nodes.remove(&old_key).unwrap();
                    let suffix = old_key.strip_prefix(&from_norm).unwrap();
                    let new_key = to_norm.join(suffix);
                    nodes.insert(new_key, old_node);
                }
            }
        }
        Ok(())
    }

    fn file_size(&self, path: &Path) -> io::Result<u64> {
        let norm = normalize_virtual_path(path);
        let nodes = self.nodes.read().unwrap();
        match nodes.get(&norm) {
            Some(VirtualNode::File { data, .. }) => Ok(data.len() as u64),
            Some(VirtualNode::Dir) => Ok(0),
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("File not found: {}", norm.display()),
            )),
        }
    }

    fn metadata(&self, path: &Path) -> io::Result<FileMetadata> {
        let norm = normalize_virtual_path(path);
        if norm == Path::new("/") {
            return Ok(FileMetadata {
                is_file: false,
                is_dir: true,
                is_symlink: false,
                size: 0,
                readonly: false,
            });
        }

        let nodes = self.nodes.read().unwrap();
        match nodes.get(&norm) {
            Some(VirtualNode::File { data, readonly }) => Ok(FileMetadata {
                is_file: true,
                is_dir: false,
                is_symlink: false,
                size: data.len() as u64,
                readonly: *readonly,
            }),
            Some(VirtualNode::Dir) => Ok(FileMetadata {
                is_file: false,
                is_dir: true,
                is_symlink: false,
                size: 0,
                readonly: false,
            }),
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Path not found: {}", norm.display()),
            )),
        }
    }

    fn list_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        let norm = normalize_virtual_path(path);
        let nodes = self.nodes.read().unwrap();

        if norm != Path::new("/") && !matches!(nodes.get(&norm), Some(VirtualNode::Dir)) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Directory not found: {}", norm.display()),
            ));
        }

        let mut entries = Vec::new();
        for key in nodes.keys() {
            if key != &norm && key.parent() == Some(&norm) {
                entries.push(key.clone());
            }
        }
        entries.sort();
        Ok(entries)
    }

    fn walk_dir(&self, root: &Path) -> io::Result<Vec<PathBuf>> {
        let norm = normalize_virtual_path(root);
        let nodes = self.nodes.read().unwrap();

        if norm != Path::new("/") && !matches!(nodes.get(&norm), Some(VirtualNode::Dir)) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Directory not found: {}", norm.display()),
            ));
        }

        let mut results = Vec::new();
        for key in nodes.keys() {
            if key != &norm && key.starts_with(&norm) {
                results.push(key.clone());
            }
        }
        results.sort();
        Ok(results)
    }
}

// ---------------------------------------------------------------------------
// Sandboxed WASI Driver
// ---------------------------------------------------------------------------

/// WebAssembly System Interface (WASI) capability-based sandboxed driver.
#[derive(Debug)]
pub struct WasiFs {
    preopens: RwLock<Vec<WasiPreopen>>,
    virtual_fs: Arc<VirtualFs>,
}

impl Default for WasiFs {
    fn default() -> Self {
        Self::new_sandbox()
    }
}

impl WasiFs {
    /// Create a standard sandboxed WASI filesystem with preopened `/sandbox` and `/tmp`.
    pub fn new_sandbox() -> Self {
        let virtual_fs = Arc::new(VirtualFs::new());
        let preopens = vec![
            WasiPreopen {
                guest_path: PathBuf::from("/sandbox"),
                host_path: None,
                rights: WasiRights::READ_WRITE,
            },
            WasiPreopen {
                guest_path: PathBuf::from("/tmp"),
                host_path: None,
                rights: WasiRights::READ_WRITE,
            },
            WasiPreopen {
                guest_path: PathBuf::from("/"),
                host_path: None,
                rights: WasiRights::READ_ONLY,
            },
        ];

        // Pre-create initial sandbox directories in virtual store
        let _ = virtual_fs.create_dir_all(Path::new("/sandbox"));
        let _ = virtual_fs.create_dir_all(Path::new("/tmp"));

        Self {
            preopens: RwLock::new(preopens),
            virtual_fs,
        }
    }

    /// Builder for configuring preopened mounts and capabilities.
    pub fn builder() -> WasiFsBuilder {
        WasiFsBuilder::new()
    }

    /// Add a preopened directory mount dynamically.
    pub fn preopen_dir(
        &self,
        guest_path: impl AsRef<Path>,
        host_path: Option<PathBuf>,
        rights: WasiRights,
    ) {
        let guest_norm = normalize_virtual_path(guest_path.as_ref());
        let mut preopens = self.preopens.write().unwrap();
        // Insert at beginning for precedence over wider mounts
        preopens.insert(
            0,
            WasiPreopen {
                guest_path: guest_norm,
                host_path,
                rights,
            },
        );
    }

    /// Resolve a guest path against preopened capabilities.
    fn resolve_capability(
        &self,
        guest_path: &Path,
    ) -> io::Result<(PathBuf, WasiRights, Option<PathBuf>)> {
        let norm_guest = normalize_virtual_path(guest_path);
        let preopens = self.preopens.read().unwrap();

        // Find the most specific matching preopened directory
        let mut best_match: Option<&WasiPreopen> = None;
        for pre in preopens.iter() {
            if norm_guest.starts_with(&pre.guest_path) {
                match best_match {
                    Some(cur) => {
                        if pre.guest_path.components().count() > cur.guest_path.components().count()
                        {
                            best_match = Some(pre);
                        }
                    }
                    None => {
                        best_match = Some(pre);
                    }
                }
            }
        }

        let preopen = best_match.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "WASI capability violation: path '{}' is not within any preopened directory",
                    guest_path.display()
                ),
            )
        })?;

        let resolved_host = preopen.host_path.as_ref().map(|host_base| {
            let rel = norm_guest
                .strip_prefix(&preopen.guest_path)
                .unwrap_or(Path::new(""));
            host_base.join(rel)
        });

        Ok((norm_guest, preopen.rights, resolved_host))
    }
}

/// Builder pattern for `WasiFs`.
#[derive(Debug, Default)]
pub struct WasiFsBuilder {
    preopens: Vec<WasiPreopen>,
}

impl WasiFsBuilder {
    pub fn new() -> Self {
        Self {
            preopens: Vec::new(),
        }
    }

    pub fn preopen(
        mut self,
        guest_path: impl AsRef<Path>,
        host_path: Option<PathBuf>,
        rights: WasiRights,
    ) -> Self {
        self.preopens.push(WasiPreopen {
            guest_path: normalize_virtual_path(guest_path.as_ref()),
            host_path,
            rights,
        });
        self
    }

    pub fn build(self) -> WasiFs {
        let virtual_fs = Arc::new(VirtualFs::new());
        for p in &self.preopens {
            if p.host_path.is_none() {
                let _ = virtual_fs.create_dir_all(&p.guest_path);
            }
        }
        WasiFs {
            preopens: RwLock::new(self.preopens),
            virtual_fs,
        }
    }
}

impl FileSystem for WasiFs {
    fn target_kind(&self) -> TargetKind {
        TargetKind::Wasi
    }

    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        let (norm, rights, host_opt) = self.resolve_capability(path)?;
        if !rights.read {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("WASI capability error: read not permitted on {}", path.display()),
            ));
        }
        if let Some(host_path) = host_opt {
            fs::read(host_path)
        } else {
            self.virtual_fs.read(&norm)
        }
    }

    fn write(&self, path: &Path, contents: &[u8]) -> io::Result<()> {
        let (norm, rights, host_opt) = self.resolve_capability(path)?;
        if !rights.write {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("WASI capability error: write not permitted on {}", path.display()),
            ));
        }
        if let Some(host_path) = host_opt {
            fs::write(host_path, contents)
        } else {
            self.virtual_fs.write(&norm, contents)
        }
    }

    fn append(&self, path: &Path, contents: &[u8]) -> io::Result<()> {
        let (norm, rights, host_opt) = self.resolve_capability(path)?;
        if !rights.write {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("WASI capability error: write not permitted on {}", path.display()),
            ));
        }
        if let Some(host_path) = host_opt {
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(host_path)?;
            file.write_all(contents)
        } else {
            self.virtual_fs.append(&norm, contents)
        }
    }

    fn exists(&self, path: &Path) -> bool {
        match self.resolve_capability(path) {
            Ok((norm, rights, host_opt)) => {
                if !rights.traverse && !rights.read {
                    return false;
                }
                if let Some(host_path) = host_opt {
                    host_path.exists()
                } else {
                    self.virtual_fs.exists(&norm)
                }
            }
            Err(_) => false,
        }
    }

    fn is_file(&self, path: &Path) -> bool {
        match self.resolve_capability(path) {
            Ok((norm, rights, host_opt)) => {
                if !rights.traverse && !rights.read {
                    return false;
                }
                if let Some(host_path) = host_opt {
                    host_path.is_file()
                } else {
                    self.virtual_fs.is_file(&norm)
                }
            }
            Err(_) => false,
        }
    }

    fn is_dir(&self, path: &Path) -> bool {
        match self.resolve_capability(path) {
            Ok((norm, rights, host_opt)) => {
                if !rights.traverse && !rights.read {
                    return false;
                }
                if let Some(host_path) = host_opt {
                    host_path.is_dir()
                } else {
                    self.virtual_fs.is_dir(&norm)
                }
            }
            Err(_) => false,
        }
    }

    fn create_dir(&self, path: &Path) -> io::Result<()> {
        let (norm, rights, host_opt) = self.resolve_capability(path)?;
        if !rights.create {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("WASI capability error: create not permitted on {}", path.display()),
            ));
        }
        if let Some(host_path) = host_opt {
            fs::create_dir(host_path)
        } else {
            self.virtual_fs.create_dir(&norm)
        }
    }

    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        let (norm, rights, host_opt) = self.resolve_capability(path)?;
        if !rights.create {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("WASI capability error: create not permitted on {}", path.display()),
            ));
        }
        if let Some(host_path) = host_opt {
            fs::create_dir_all(host_path)
        } else {
            self.virtual_fs.create_dir_all(&norm)
        }
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        let (norm, rights, host_opt) = self.resolve_capability(path)?;
        if !rights.delete {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("WASI capability error: delete not permitted on {}", path.display()),
            ));
        }
        if let Some(host_path) = host_opt {
            fs::remove_file(host_path)
        } else {
            self.virtual_fs.remove_file(&norm)
        }
    }

    fn remove_dir(&self, path: &Path) -> io::Result<()> {
        let (norm, rights, host_opt) = self.resolve_capability(path)?;
        if !rights.delete {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("WASI capability error: delete not permitted on {}", path.display()),
            ));
        }
        if let Some(host_path) = host_opt {
            fs::remove_dir(host_path)
        } else {
            self.virtual_fs.remove_dir(&norm)
        }
    }

    fn remove_dir_all(&self, path: &Path) -> io::Result<()> {
        let (norm, rights, host_opt) = self.resolve_capability(path)?;
        if !rights.delete {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("WASI capability error: delete not permitted on {}", path.display()),
            ));
        }
        if let Some(host_path) = host_opt {
            fs::remove_dir_all(host_path)
        } else {
            self.virtual_fs.remove_dir_all(&norm)
        }
    }

    fn copy(&self, from: &Path, to: &Path) -> io::Result<u64> {
        let bytes = self.read(from)?;
        self.write(to, &bytes)?;
        Ok(bytes.len() as u64)
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        let (_, from_rights, from_host) = self.resolve_capability(from)?;
        let (_, to_rights, to_host) = self.resolve_capability(to)?;

        if !from_rights.delete || !to_rights.create || !to_rights.write {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "WASI capability error: rename requires delete on source and create/write on destination",
            ));
        }

        match (from_host, to_host) {
            (Some(h_from), Some(h_to)) => fs::rename(h_from, h_to),
            (None, None) => self.virtual_fs.rename(from, to),
            _ => {
                // Cross-device/mount copy and remove
                let bytes = self.read(from)?;
                self.write(to, &bytes)?;
                self.remove_file(from)
            }
        }
    }

    fn file_size(&self, path: &Path) -> io::Result<u64> {
        let (norm, rights, host_opt) = self.resolve_capability(path)?;
        if !rights.read && !rights.traverse {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "WASI capability error: read permission required to query size",
            ));
        }
        if let Some(host_path) = host_opt {
            fs::metadata(host_path).map(|m| m.len())
        } else {
            self.virtual_fs.file_size(&norm)
        }
    }

    fn metadata(&self, path: &Path) -> io::Result<FileMetadata> {
        let (norm, rights, host_opt) = self.resolve_capability(path)?;
        if !rights.read && !rights.traverse {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "WASI capability error: read permission required to query metadata",
            ));
        }
        if let Some(host_path) = host_opt {
            let meta = fs::metadata(host_path)?;
            Ok(FileMetadata {
                is_file: meta.is_file(),
                is_dir: meta.is_dir(),
                is_symlink: meta.file_type().is_symlink(),
                size: meta.len(),
                readonly: meta.permissions().readonly() || !rights.write,
            })
        } else {
            self.virtual_fs.metadata(&norm)
        }
    }

    fn list_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        let (norm, rights, host_opt) = self.resolve_capability(path)?;
        if !rights.list {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("WASI capability error: list not permitted on {}", path.display()),
            ));
        }
        if let Some(host_path) = host_opt {
            let mut entries = Vec::new();
            for entry in fs::read_dir(host_path)? {
                let entry = entry?;
                entries.push(entry.path());
            }
            entries.sort();
            Ok(entries)
        } else {
            self.virtual_fs.list_dir(&norm)
        }
    }

    fn walk_dir(&self, root: &Path) -> io::Result<Vec<PathBuf>> {
        let (norm, rights, host_opt) = self.resolve_capability(root)?;
        if !rights.list {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("WASI capability error: list not permitted on {}", root.display()),
            ));
        }
        if let Some(host_path) = host_opt {
            let mut results = Vec::new();
            walk_dir_internal(&host_path, &mut results)?;
            results.sort();
            Ok(results)
        } else {
            self.virtual_fs.walk_dir(&norm)
        }
    }
}

// ---------------------------------------------------------------------------
// Global and Thread-Local Target FS Dispatcher
// ---------------------------------------------------------------------------

static GLOBAL_FS: RwLock<Option<Arc<dyn FileSystem + Send + Sync>>> = RwLock::new(None);

thread_local! {
    static SCOPED_FS: std::cell::RefCell<Option<Arc<dyn FileSystem + Send + Sync>>> = const { std::cell::RefCell::new(None) };
}

/// Retrieve the active filesystem for the current execution context.
pub fn current_fs() -> Arc<dyn FileSystem + Send + Sync> {
    if let Some(scoped) = SCOPED_FS.with(|c| c.borrow().clone()) {
        return scoped;
    }
    if let Ok(guard) = GLOBAL_FS.read() {
        if let Some(ref global) = *guard {
            return Arc::clone(global);
        }
    }
    // Default fallback based on compilation target
    if cfg!(target_os = "wasi") {
        Arc::new(WasiFs::new_sandbox())
    } else {
        Arc::new(PosixFs::new())
    }
}

/// Current active target kind.
pub fn current_target_kind() -> TargetKind {
    current_fs().target_kind()
}

/// Set a globally active filesystem.
pub fn set_global_fs(fs: Arc<dyn FileSystem + Send + Sync>) {
    if let Ok(mut guard) = GLOBAL_FS.write() {
        *guard = Some(fs);
    }
}

/// Reset globally active filesystem to default target behavior.
pub fn reset_global_fs() {
    if let Ok(mut guard) = GLOBAL_FS.write() {
        *guard = None;
    }
}

/// RAII Guard restoring previous scoped filesystem when dropped.
pub struct ScopedFsGuard {
    previous: Option<Arc<dyn FileSystem + Send + Sync>>,
}

impl Drop for ScopedFsGuard {
    fn drop(&mut self) {
        SCOPED_FS.with(|c| {
            *c.borrow_mut() = self.previous.take();
        });
    }
}

/// Execute a closure within a specific scoped filesystem target.
pub fn with_target_fs<F, R>(fs: Arc<dyn FileSystem + Send + Sync>, f: F) -> R
where
    F: FnOnce() -> R,
{
    let previous = SCOPED_FS.with(|c| {
        let mut b = c.borrow_mut();
        let old = b.clone();
        *b = Some(fs);
        old
    });
    let _guard = ScopedFsGuard { previous };
    f()
}

// ---------------------------------------------------------------------------
// Public Transparent Convenience API
// ---------------------------------------------------------------------------

/// Read an entire file into a UTF-8 String via the active target filesystem.
pub fn read_to_string<P: AsRef<Path>>(path: P) -> io::Result<String> {
    current_fs().read_to_string(path.as_ref())
}

/// Read an entire file into a byte vector via the active target filesystem.
pub fn read<P: AsRef<Path>>(path: P) -> io::Result<Vec<u8>> {
    current_fs().read(path.as_ref())
}

/// Write bytes to a file via the active target filesystem.
pub fn write<P: AsRef<Path>, C: AsRef<[u8]>>(path: P, contents: C) -> io::Result<()> {
    current_fs().write(path.as_ref(), contents.as_ref())
}

/// Write a string slice to a file via the active target filesystem.
pub fn write_string<P: AsRef<Path>>(path: P, contents: &str) -> io::Result<()> {
    current_fs().write(path.as_ref(), contents.as_bytes())
}

/// Append bytes to the end of a file via the active target filesystem.
pub fn append<P: AsRef<Path>, C: AsRef<[u8]>>(path: P, contents: C) -> io::Result<()> {
    current_fs().append(path.as_ref(), contents.as_ref())
}

/// Check if a path exists on the active target filesystem.
pub fn exists<P: AsRef<Path>>(path: P) -> bool {
    current_fs().exists(path.as_ref())
}

/// Check if a path points to an existing regular file via the active target filesystem.
pub fn is_file<P: AsRef<Path>>(path: P) -> bool {
    current_fs().is_file(path.as_ref())
}

/// Check if a path points to an existing directory via the active target filesystem.
pub fn is_dir<P: AsRef<Path>>(path: P) -> bool {
    current_fs().is_dir(path.as_ref())
}

/// Create a single directory via the active target filesystem.
pub fn create_dir<P: AsRef<Path>>(path: P) -> io::Result<()> {
    current_fs().create_dir(path.as_ref())
}

/// Recursively create a directory and all parent components via the active target filesystem.
pub fn create_dir_all<P: AsRef<Path>>(path: P) -> io::Result<()> {
    current_fs().create_dir_all(path.as_ref())
}

/// Remove a single file via the active target filesystem.
pub fn remove_file<P: AsRef<Path>>(path: P) -> io::Result<()> {
    current_fs().remove_file(path.as_ref())
}

/// Remove an empty directory via the active target filesystem.
pub fn remove_dir<P: AsRef<Path>>(path: P) -> io::Result<()> {
    current_fs().remove_dir(path.as_ref())
}

/// Recursively remove a directory and all its contents via the active target filesystem.
pub fn remove_dir_all<P: AsRef<Path>>(path: P) -> io::Result<()> {
    current_fs().remove_dir_all(path.as_ref())
}

/// Copy the contents of one file to another via the active target filesystem.
pub fn copy<P: AsRef<Path>, Q: AsRef<Path>>(from: P, to: Q) -> io::Result<u64> {
    current_fs().copy(from.as_ref(), to.as_ref())
}

/// Rename / move a file or directory via the active target filesystem.
pub fn rename<P: AsRef<Path>, Q: AsRef<Path>>(from: P, to: Q) -> io::Result<()> {
    current_fs().rename(from.as_ref(), to.as_ref())
}

/// Query size in bytes of a file via the active target filesystem.
pub fn file_size<P: AsRef<Path>>(path: P) -> io::Result<u64> {
    current_fs().file_size(path.as_ref())
}

/// List all entries within a directory via the active target filesystem.
pub fn list_dir<P: AsRef<Path>>(path: P) -> io::Result<Vec<PathBuf>> {
    current_fs().list_dir(path.as_ref())
}

/// Query full file metadata via the active target filesystem.
pub fn metadata<P: AsRef<Path>>(path: P) -> io::Result<FileMetadata> {
    current_fs().metadata(path.as_ref())
}

/// Recursively walk a directory tree in deterministic order via the active target filesystem.
pub fn walk_dir<P: AsRef<Path>>(root: P) -> io::Result<Vec<PathBuf>> {
    current_fs().walk_dir(root.as_ref())
}

/// Recursively walk a directory tree and return only regular files.
pub fn walk_dir_files<P: AsRef<Path>>(root: P) -> io::Result<Vec<PathBuf>> {
    let all = walk_dir(root)?;
    Ok(all.into_iter().filter(|p| is_file(p)).collect())
}

/// Recursively walk a directory tree and return entries matching a predicate.
pub fn walk_dir_matching<P: AsRef<Path>, F: Fn(&Path) -> bool>(
    root: P,
    predicate: F,
) -> io::Result<Vec<PathBuf>> {
    let all = walk_dir(root)?;
    Ok(all.into_iter().filter(|p| predicate(p.as_path())).collect())
}

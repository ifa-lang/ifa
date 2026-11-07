//! Deterministic package archiver, checksum generator, and registry distributor for IFA libraries.

use crate::error::KoriError;
use crate::manifest::{DependencySpec, Manifest};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

const KORI_MAGIC: &[u8; 6] = b"KORI\x01\x00";

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Compute standard NIST SHA-256 hash digest.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut h_var = h[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h_var
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h_var = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(h_var);
    }

    let mut out = String::with_capacity(64);
    for val in h {
        for byte in val.to_be_bytes() {
            out.push_str(&format!("{:02x}", byte));
        }
    }
    out
}

/// Package index metadata stored in package registries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageIndexEntry {
    pub name: String,
    pub version: String,
    pub checksum: String,
    #[serde(default)]
    pub dependencies: BTreeMap<String, DependencySpec>,
    pub description: Option<String>,
    #[serde(default)]
    pub authors: Vec<String>,
    pub license: Option<String>,
    #[serde(default)]
    pub keywords: Vec<String>,
}

/// Report produced after packaging an IFA library.
#[derive(Debug, Clone)]
pub struct PackageReport {
    pub name: String,
    pub version: String,
    pub package_path: PathBuf,
    pub checksum_path: PathBuf,
    pub checksum: String,
    pub file_count: usize,
    pub total_bytes: usize,
}

/// Report produced after publishing an IFA library.
#[derive(Debug, Clone)]
pub struct PublishReport {
    pub name: String,
    pub version: String,
    pub checksum: String,
    pub registry_path: PathBuf,
    pub dry_run: bool,
}

/// Package orchestrator for packaging and publishing third-party IFA libraries.
pub struct Packager;

impl Packager {
    /// Validates package integrity and metadata in the specified project directory.
    pub fn validate(project_dir: &Path) -> Result<Manifest, KoriError> {
        let manifest_path = project_dir.join("kori.toml");
        if !manifest_path.exists() {
            return Err(KoriError::Packaging(format!(
                "kori.toml not found in `{}`",
                project_dir.display()
            )));
        }

        let manifest = Manifest::from_file(&manifest_path)?;

        // Validate package name
        let name = &manifest.package.name;
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(KoriError::Packaging(format!(
                "invalid package name `{}`: must contain only alphanumeric characters, dashes, and underscores",
                name
            )));
        }

        // Validate SemVer version
        if semver::Version::parse(&manifest.package.version).is_err() {
            return Err(KoriError::Packaging(format!(
                "invalid SemVer version `{}` in package `{}`",
                manifest.package.version, name
            )));
        }

        // Validate authors
        if manifest.package.authors.is_empty() {
            return Err(KoriError::Packaging(format!(
                "package `{}` must specify at least one author in kori.toml",
                name
            )));
        }

        // Validate entry point existence
        let mut has_entry = false;
        if let Some(lib) = &manifest.targets.lib {
            if project_dir.join(&lib.path).exists() {
                has_entry = true;
            }
        }
        for bin in &manifest.targets.bin {
            if project_dir.join(&bin.path).exists() {
                has_entry = true;
            }
        }
        if !has_entry
            && (project_dir.join("src/lib.ifa").exists()
                || project_dir.join("src/main.ifa").exists())
        {
            has_entry = true;
        }
        if !has_entry {
            return Err(KoriError::Packaging(format!(
                "package `{}` has no valid source entry points found in `{}`",
                name,
                project_dir.display()
            )));
        }

        Ok(manifest)
    }

    /// Recursively collects all distribution files deterministically.
    pub fn collect_files(project_dir: &Path) -> Result<Vec<(String, Vec<u8>)>, KoriError> {
        let mut files = Vec::new();

        fn walk(
            root: &Path,
            current: &Path,
            collected: &mut Vec<(String, Vec<u8>)>,
        ) -> Result<(), KoriError> {
            let entries = match fs::read_dir(current) {
                Ok(rd) => rd,
                Err(e) => return Err(KoriError::Io(e)),
            };

            let mut sorted_entries = Vec::new();
            for entry_res in entries {
                let entry = entry_res?;
                sorted_entries.push(entry.path());
            }
            sorted_entries.sort();

            for path in sorted_entries {
                let file_name = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or_default();

                // Exclude build artifacts, git repositories, and caches
                if file_name == "target"
                    || file_name == ".git"
                    || file_name == ".kori-cache"
                    || file_name.ends_with(".lock")
                    || file_name.starts_with('.')
                {
                    continue;
                }

                if path.is_dir() {
                    walk(root, &path, collected)?;
                } else if path.is_file() {
                    let rel = path
                        .strip_prefix(root)
                        .map_err(|_| {
                            KoriError::Packaging("failed to strip relative path prefix".to_string())
                        })?
                        .to_string_lossy()
                        .replace('\\', "/");

                    let content = fs::read(&path)?;
                    collected.push((rel, content));
                }
            }
            Ok(())
        }

        walk(project_dir, project_dir, &mut files)?;
        files.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(files)
    }

    /// Packs collected files into a deterministic `.kori` binary archive.
    pub fn create_archive(files: &[(String, Vec<u8>)]) -> Vec<u8> {
        let mut archive = Vec::new();
        archive.extend_from_slice(KORI_MAGIC);

        let file_count = files.len() as u32;
        archive.extend_from_slice(&file_count.to_be_bytes());

        for (rel_path, content) in files {
            let path_bytes = rel_path.as_bytes();
            archive.extend_from_slice(&(path_bytes.len() as u32).to_be_bytes());
            archive.extend_from_slice(path_bytes);

            archive.extend_from_slice(&(content.len() as u64).to_be_bytes());
            archive.extend_from_slice(content);
        }

        archive
    }

    /// Unpacks a `.kori` binary archive into a destination directory.
    pub fn unpack_archive(archive_data: &[u8], dest_dir: &Path) -> Result<Vec<PathBuf>, KoriError> {
        if archive_data.len() < 10 || &archive_data[0..6] != KORI_MAGIC {
            return Err(KoriError::Packaging(
                "invalid .kori package archive header".to_string(),
            ));
        }

        let mut offset = 6;
        let file_count =
            u32::from_be_bytes(archive_data[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;

        let mut unpacked_paths = Vec::with_capacity(file_count);

        for _ in 0..file_count {
            if offset + 4 > archive_data.len() {
                return Err(KoriError::Packaging(
                    "corrupt package archive: truncated path length".to_string(),
                ));
            }
            let path_len =
                u32::from_be_bytes(archive_data[offset..offset + 4].try_into().unwrap()) as usize;
            offset += 4;

            if offset + path_len > archive_data.len() {
                return Err(KoriError::Packaging(
                    "corrupt package archive: truncated relative path".to_string(),
                ));
            }
            let rel_path = String::from_utf8(archive_data[offset..offset + path_len].to_vec())
                .map_err(|e| KoriError::Packaging(format!("invalid UTF-8 path: {}", e)))?;
            offset += path_len;

            if offset + 8 > archive_data.len() {
                return Err(KoriError::Packaging(
                    "corrupt package archive: truncated file size".to_string(),
                ));
            }
            let file_size =
                u64::from_be_bytes(archive_data[offset..offset + 8].try_into().unwrap()) as usize;
            offset += 8;

            if offset + file_size > archive_data.len() {
                return Err(KoriError::Packaging(
                    "corrupt package archive: truncated content bytes".to_string(),
                ));
            }
            let content = &archive_data[offset..offset + file_size];
            offset += file_size;

            let dest_path = dest_dir.join(&rel_path);
            if let Some(parent) = dest_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&dest_path, content)?;
            unpacked_paths.push(dest_path);
        }

        Ok(unpacked_paths)
    }

    /// Package the project into a deterministic `.kori` distributable bundle.
    pub fn pack(project_dir: &Path, out_dir: Option<&Path>) -> Result<PackageReport, KoriError> {
        let manifest = Self::validate(project_dir)?;
        let files = Self::collect_files(project_dir)?;
        let archive_bytes = Self::create_archive(&files);
        let checksum = sha256_hex(&archive_bytes);

        let target_dir = match out_dir {
            Some(p) => p.to_path_buf(),
            None => project_dir.join("target").join("package"),
        };
        fs::create_dir_all(&target_dir)?;

        let filename_base = format!("{}-{}", manifest.package.name, manifest.package.version);
        let package_path = target_dir.join(format!("{}.kori", filename_base));
        let checksum_path = target_dir.join(format!("{}.kori.sha256", filename_base));

        fs::write(&package_path, &archive_bytes)?;
        fs::write(
            &checksum_path,
            format!("{}  {}.kori\n", checksum, filename_base),
        )?;

        // Write local index entry descriptor
        let index_entry = PackageIndexEntry {
            name: manifest.package.name.clone(),
            version: manifest.package.version.clone(),
            checksum: checksum.clone(),
            dependencies: manifest.dependencies.clone(),
            description: manifest.package.description.clone(),
            authors: manifest.package.authors.clone(),
            license: manifest.package.license.clone(),
            keywords: manifest.package.keywords.clone(),
        };
        let index_json = serde_json::to_string_pretty(&index_entry)
            .map_err(|e| KoriError::Packaging(format!("failed to serialize index entry: {}", e)))?;
        fs::write(target_dir.join("kori-index.json"), index_json)?;

        Ok(PackageReport {
            name: manifest.package.name,
            version: manifest.package.version,
            package_path,
            checksum_path,
            checksum,
            file_count: files.len(),
            total_bytes: archive_bytes.len(),
        })
    }

    /// Resolve registry root directory (defaults to ~/.kori/registry).
    pub fn default_registry_dir() -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join(".kori").join("registry")
    }

    /// Publish the package to a local or configured registry.
    pub fn publish(
        project_dir: &Path,
        registry_path: Option<&Path>,
        dry_run: bool,
    ) -> Result<PublishReport, KoriError> {
        let manifest = Self::validate(project_dir)?;
        let report = Self::pack(project_dir, None)?;

        let reg_root = match registry_path {
            Some(p) => p.to_path_buf(),
            None => Self::default_registry_dir(),
        };

        if dry_run {
            return Ok(PublishReport {
                name: manifest.package.name,
                version: manifest.package.version,
                checksum: report.checksum,
                registry_path: reg_root,
                dry_run: true,
            });
        }

        let packages_dir = reg_root.join("packages").join(&manifest.package.name);
        let index_dir = reg_root.join("index");
        fs::create_dir_all(&packages_dir)?;
        fs::create_dir_all(&index_dir)?;

        // Copy .kori archive
        let dest_package = packages_dir.join(format!(
            "{}-{}.kori",
            manifest.package.name, manifest.package.version
        ));
        fs::copy(&report.package_path, &dest_package)?;

        // Update registry index entry
        let index_file = index_dir.join(format!("{}.json", manifest.package.name));
        let mut entries: Vec<PackageIndexEntry> = if index_file.exists() {
            let data = fs::read_to_string(&index_file)?;
            serde_json::from_str(&data).unwrap_or_default()
        } else {
            Vec::new()
        };

        let new_entry = PackageIndexEntry {
            name: manifest.package.name.clone(),
            version: manifest.package.version.clone(),
            checksum: report.checksum.clone(),
            dependencies: manifest.dependencies.clone(),
            description: manifest.package.description.clone(),
            authors: manifest.package.authors.clone(),
            license: manifest.package.license.clone(),
            keywords: manifest.package.keywords.clone(),
        };

        entries.retain(|e| e.version != manifest.package.version);
        entries.push(new_entry);

        let updated_index = serde_json::to_string_pretty(&entries).map_err(|e| {
            KoriError::Registry(format!("failed to serialize registry index: {}", e))
        })?;
        fs::write(&index_file, updated_index)?;

        Ok(PublishReport {
            name: manifest.package.name,
            version: manifest.package.version,
            checksum: report.checksum,
            registry_path: reg_root,
            dry_run: false,
        })
    }

    /// Search for packages matching a query in the registry.
    pub fn search(
        query: &str,
        registry_path: Option<&Path>,
    ) -> Result<Vec<PackageIndexEntry>, KoriError> {
        let reg_root = match registry_path {
            Some(p) => p.to_path_buf(),
            None => Self::default_registry_dir(),
        };
        let index_dir = reg_root.join("index");
        if !index_dir.exists() {
            return Ok(Vec::new());
        }

        let q = query.to_lowercase();
        let mut results = Vec::new();

        let entries = fs::read_dir(index_dir)?;
        for entry_res in entries {
            let entry = entry_res?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Ok(data) = fs::read_to_string(&path) {
                    if let Ok(pkg_entries) = serde_json::from_str::<Vec<PackageIndexEntry>>(&data) {
                        for pe in pkg_entries {
                            let match_name = pe.name.to_lowercase().contains(&q);
                            let match_desc = pe
                                .description
                                .as_deref()
                                .map(|d| d.to_lowercase().contains(&q))
                                .unwrap_or(false);
                            let match_kw =
                                pe.keywords.iter().any(|k| k.to_lowercase().contains(&q));

                            if match_name || match_desc || match_kw {
                                results.push(pe);
                            }
                        }
                    }
                }
            }
        }

        Ok(results)
    }

    /// Fetch package versions and metadata from registry.
    pub fn info(
        package_name: &str,
        registry_path: Option<&Path>,
    ) -> Result<Vec<PackageIndexEntry>, KoriError> {
        let reg_root = match registry_path {
            Some(p) => p.to_path_buf(),
            None => Self::default_registry_dir(),
        };
        let index_file = reg_root
            .join("index")
            .join(format!("{}.json", package_name));
        if !index_file.exists() {
            return Err(KoriError::PackageNotFound(package_name.to_string()));
        }

        let data = fs::read_to_string(&index_file)?;
        let entries: Vec<PackageIndexEntry> = serde_json::from_str(&data)
            .map_err(|e| KoriError::Registry(format!("failed to parse index file: {}", e)))?;

        Ok(entries)
    }

    /// Resolve package download cache directory (defaults to ~/.kori/cache/packages).
    pub fn default_cache_dir() -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home)
            .join(".kori")
            .join("cache")
            .join("packages")
    }

    /// Fetch and unpack a package archive from the registry into the local cache directory.
    ///
    /// Verifies the SHA-256 integrity checksum against the index entry before extracting.
    pub fn fetch_and_unpack(
        package_name: &str,
        version_req: Option<&str>,
        registry_path: Option<&Path>,
        cache_dir: Option<&Path>,
    ) -> Result<(PathBuf, PackageIndexEntry), KoriError> {
        let reg_root = match registry_path {
            Some(p) => p.to_path_buf(),
            None => Self::default_registry_dir(),
        };

        let entries = Self::info(package_name, Some(&reg_root))?;
        if entries.is_empty() {
            return Err(KoriError::PackageNotFound(format!(
                "Package `{}` not found in registry at `{}`",
                package_name,
                reg_root.display()
            )));
        }

        // Match version according to semver requirements
        let mut candidates: Vec<PackageIndexEntry> = if let Some(req_str) = version_req {
            if let Ok(req) = semver::VersionReq::parse(req_str) {
                entries
                    .into_iter()
                    .filter(|e| {
                        semver::Version::parse(&e.version)
                            .map(|v| req.matches(&v))
                            .unwrap_or(false)
                    })
                    .collect()
            } else {
                entries
                    .into_iter()
                    .filter(|e| e.version == req_str)
                    .collect()
            }
        } else {
            entries
        };

        if candidates.is_empty() {
            return Err(KoriError::VersionMismatch {
                package: package_name.to_string(),
                required: version_req.unwrap_or("*").to_string(),
                found: "no matching version found in registry".to_string(),
            });
        }

        candidates.sort_by(|a, b| {
            let va = semver::Version::parse(&a.version).ok();
            let vb = semver::Version::parse(&b.version).ok();
            vb.cmp(&va)
        });

        let chosen = candidates.remove(0);

        let cache_root = match cache_dir {
            Some(p) => p.to_path_buf(),
            None => Self::default_cache_dir(),
        };

        let target_dir = cache_root.join(format!("{}-{}", chosen.name, chosen.version));
        let manifest_path = target_dir.join("kori.toml");

        if target_dir.exists() && manifest_path.exists() {
            return Ok((target_dir, chosen));
        }

        let archive_path = reg_root
            .join("packages")
            .join(&chosen.name)
            .join(format!("{}-{}.kori", chosen.name, chosen.version));

        if !archive_path.exists() {
            return Err(KoriError::PackageNotFound(format!(
                "Archive file not found for package `{}-{}` at `{}`",
                chosen.name,
                chosen.version,
                archive_path.display()
            )));
        }

        let archive_bytes = fs::read(&archive_path)?;
        let actual_checksum = sha256_hex(&archive_bytes);
        if actual_checksum != chosen.checksum {
            return Err(KoriError::Registry(format!(
                "Integrity verification failed for `{}`: expected SHA-256 `{}` but computed `{}`",
                archive_path.display(),
                chosen.checksum,
                actual_checksum
            )));
        }

        fs::create_dir_all(&target_dir)?;
        Self::unpack_archive(&archive_bytes, &target_dir)?;

        Ok((target_dir, chosen))
    }
}

/// Alias for package archive manager.
pub type PackageArchive = Packager;

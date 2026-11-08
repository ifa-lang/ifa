use crate::error::KoriError;
use crate::manifest::ProfileConfig;
use crate::module_metadata::ModuleMetadata;
use crate::resolver::ResolvedPackage;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Cached entry metadata for build artifacts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    pub target_key: String,
    pub fingerprint: String,
    pub timestamp_unix: u64,
    pub output_files: Vec<PathBuf>,
}

/// Deterministic build cache manager preventing redundant recompilations.
pub struct BuildCache {
    cache_dir: PathBuf,
    modules_dir: PathBuf,
    index_file: PathBuf,
    entries: HashMap<String, CacheEntry>,
}

impl BuildCache {
    /// Initialize the build cache within the specified target directory.
    pub fn new(target_dir: &Path) -> Result<Self, KoriError> {
        let cache_dir = target_dir.join(".kori-cache");
        let modules_dir = cache_dir.join("modules");
        fs::create_dir_all(&modules_dir)?;
        let index_file = cache_dir.join("index.json");

        let entries = if index_file.exists() {
            let data = fs::read_to_string(&index_file)?;
            serde_json::from_str(&data).unwrap_or_default()
        } else {
            HashMap::new()
        };

        Ok(Self {
            cache_dir,
            modules_dir,
            index_file,
            entries,
        })
    }

    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    pub fn modules_dir(&self) -> &Path {
        &self.modules_dir
    }

    /// Compute cryptographic fingerprint for a file on disk.
    pub fn compute_file_fingerprint(path: &Path) -> Result<String, KoriError> {
        let bytes = fs::read(path).map_err(|e| {
            KoriError::Codegen(format!("Failed to read file for fingerprinting: {}", e))
        })?;
        let hash = blake3::hash(&bytes);
        Ok(hash.to_hex().to_string())
    }

    /// Retrieve cached binary module metadata if present and matching fingerprint.
    pub fn get_module_metadata(
        &self,
        module_key: &str,
        current_fingerprint: &str,
    ) -> Option<ModuleMetadata> {
        let sanitized_key = module_key.replace("::", "_").replace('/', "_");
        let meta_file = self
            .modules_dir
            .join(format!("{}_{}.ifameta", sanitized_key, current_fingerprint));

        if meta_file.is_file() {
            if let Ok(bytes) = fs::read(&meta_file) {
                if let Ok(metadata) = ModuleMetadata::deserialize_from_binary(&bytes) {
                    if metadata.fingerprint == current_fingerprint {
                        return Some(metadata);
                    }
                }
            }
        }
        None
    }

    /// Store compiled binary module metadata into cache directory with `IFAM` format.
    pub fn store_module_metadata(
        &self,
        module_key: &str,
        metadata: &ModuleMetadata,
    ) -> Result<PathBuf, KoriError> {
        let sanitized_key = module_key.replace("::", "_").replace('/', "_");
        let meta_file = self.modules_dir.join(format!(
            "{}_{}.ifameta",
            sanitized_key, metadata.fingerprint
        ));

        let binary_data = metadata.serialize_to_binary()?;
        fs::write(&meta_file, binary_data)?;
        Ok(meta_file)
    }

    /// Compute cryptographic fingerprint for a package target under a specific profile.
    pub fn compute_target_fingerprint(
        &self,
        pkg: &ResolvedPackage,
        profile: &ProfileConfig,
        dep_checksums: &[String],
    ) -> String {
        let mut hasher = blake3::Hasher::new();

        // Include package sources checksum
        if let Some(cs) = &pkg.checksum {
            hasher.update(cs.as_bytes());
        } else {
            hasher.update(pkg.name.as_bytes());
            hasher.update(pkg.version.as_bytes());
        }

        // Include compilation profile configuration
        hasher.update(format!("{:?}", profile.backend).as_bytes());
        hasher.update(&[profile.opt_level]);
        hasher.update(&[profile.debug_assertions as u8]);
        hasher.update(profile.lto.as_bytes());
        hasher.update(&[profile.strip_symbols as u8]);
        hasher.update(&[profile.gen_checks as u8]);

        // Include dependencies checksums
        for dep_cs in dep_checksums {
            hasher.update(dep_cs.as_bytes());
        }

        hasher.finalize().to_hex().to_string()
    }

    /// Check if target artifacts exist and match the recorded fingerprint.
    pub fn is_up_to_date(
        &self,
        target_key: &str,
        current_fingerprint: &str,
        expected_outputs: &[&Path],
    ) -> bool {
        if let Some(entry) = self.entries.get(target_key) {
            if entry.fingerprint != current_fingerprint {
                return false;
            }

            // Ensure all expected output files exist on disk
            for path in expected_outputs {
                if !path.exists() {
                    return false;
                }
            }

            true
        } else {
            false
        }
    }

    /// Record a successful compilation run in the cache.
    pub fn record_success(
        &mut self,
        target_key: &str,
        fingerprint: String,
        outputs: Vec<PathBuf>,
    ) -> Result<(), KoriError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let entry = CacheEntry {
            target_key: target_key.to_string(),
            fingerprint,
            timestamp_unix: now,
            output_files: outputs,
        };

        self.entries.insert(target_key.to_string(), entry);

        let json = serde_json::to_string_pretty(&self.entries)
            .map_err(|e| KoriError::Codegen(format!("Failed to serialize cache index: {}", e)))?;
        fs::write(&self.index_file, json)?;

        Ok(())
    }

    /// Clear all cached compilation records.
    pub fn clear(&mut self) -> Result<(), KoriError> {
        self.entries.clear();
        if self.index_file.exists() {
            fs::remove_file(&self.index_file)?;
        }
        Ok(())
    }
}

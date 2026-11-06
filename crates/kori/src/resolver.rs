use crate::error::KoriError;
use crate::lockfile::{LockedPackage, Lockfile};
use crate::manifest::{DependencySpec, Manifest};
use petgraph::algo::toposort;
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// A resolved package node ready for compilation scheduling.
#[derive(Debug, Clone)]
pub struct ResolvedPackage {
    pub name: String,
    pub version: String,
    pub root_dir: PathBuf,
    pub manifest: Manifest,
    pub source: String,
    pub checksum: Option<String>,
}

/// Dependency graph resolver producing a deterministic topological build plan.
pub struct DependencyResolver {
    root_dir: PathBuf,
}

impl DependencyResolver {
    /// Create a resolver with the specified root project workspace directory.
    pub fn new(root_dir: PathBuf) -> Self {
        Self { root_dir }
    }

    /// Compute cryptographic BLAKE3 checksum for all `.ifa` source files and `kori.toml` in package.
    pub fn compute_package_checksum(root_dir: &Path) -> Result<String, KoriError> {
        let mut hasher = blake3::Hasher::new();

        let manifest_path = root_dir.join("kori.toml");
        if manifest_path.exists() {
            let manifest_bytes = fs::read(&manifest_path)?;
            hasher.update(&manifest_bytes);
        }

        let src_dir = root_dir.join("src");
        if src_dir.exists() {
            let mut entries = Vec::new();
            Self::collect_ifa_files(&src_dir, &mut entries)?;
            entries.sort();

            for path in entries {
                let content = fs::read(&path)?;
                hasher.update(path.to_string_lossy().as_bytes());
                hasher.update(&content);
            }
        }

        Ok(hasher.finalize().to_hex().to_string())
    }

    fn collect_ifa_files(dir: &Path, acc: &mut Vec<PathBuf>) -> std::io::Result<()> {
        if dir.is_dir() {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    Self::collect_ifa_files(&path, acc)?;
                } else if path.extension().and_then(|s| s.to_str()) == Some("ifa") {
                    acc.push(path);
                }
            }
        }
        Ok(())
    }

    /// Resolve all dependencies recursively and return the compilation order and updated lockfile.
    pub fn resolve(
        &self,
        root_manifest: &Manifest,
        existing_lock: Option<&Lockfile>,
    ) -> Result<(Vec<ResolvedPackage>, Lockfile), KoriError> {
        let mut graph = DiGraph::<ResolvedPackage, ()>::new();
        let mut visited = HashMap::<String, NodeIndex>::new();

        let root_checksum = Self::compute_package_checksum(&self.root_dir).ok();
        let root_node = graph.add_node(ResolvedPackage {
            name: root_manifest.package.name.clone(),
            version: root_manifest.package.version.clone(),
            root_dir: self.root_dir.clone(),
            manifest: root_manifest.clone(),
            source: "root".to_string(),
            checksum: root_checksum,
        });
        visited.insert(root_manifest.package.name.clone(), root_node);

        // Queue for breadth-first traversal
        let mut queue = vec![(root_node, self.root_dir.clone(), root_manifest.clone())];

        while let Some((parent_idx, parent_dir, manifest)) = queue.pop() {
            for (dep_name, dep_spec) in &manifest.dependencies {
                let child_idx = if let Some(&idx) = visited.get(dep_name) {
                    idx
                } else {
                    let (child_pkg, child_manifest) =
                        self.resolve_dependency(dep_name, dep_spec, &parent_dir, existing_lock)?;
                    let child_dir = child_pkg.root_dir.clone();
                    let idx = graph.add_node(child_pkg);
                    visited.insert(dep_name.clone(), idx);
                    queue.push((idx, child_dir, child_manifest));
                    idx
                };

                // Add dependency edge: parent depends on child (parent -> child)
                graph.add_edge(parent_idx, child_idx, ());
            }
        }

        // Check for cycles using toposort. In DiGraph with A -> B, toposort orders prerequisites last.
        // Reversing toposort gives leaves (dependencies with 0 outgoing edges) first.
        let sorted_indices = toposort(&graph, None).map_err(|_| {
            KoriError::CyclicDependency(
                "Circular dependency encountered between packages in workspace".to_string(),
            )
        })?;

        let mut build_order = Vec::new();
        for &idx in sorted_indices.iter().rev() {
            build_order.push(graph[idx].clone());
        }

        // Generate updated lockfile
        let mut new_lock = Lockfile::default();
        for pkg in &build_order {
            let mut dep_names = Vec::new();
            for dep_name in pkg.manifest.dependencies.keys() {
                dep_names.push(dep_name.clone());
            }
            dep_names.sort();

            new_lock.packages.push(LockedPackage {
                name: pkg.name.clone(),
                version: pkg.version.clone(),
                source: pkg.source.clone(),
                checksum: pkg.checksum.clone(),
                dependencies: dep_names,
            });
        }

        Ok((build_order, new_lock))
    }

    fn resolve_dependency(
        &self,
        name: &str,
        spec: &DependencySpec,
        parent_dir: &Path,
        _existing_lock: Option<&Lockfile>,
    ) -> Result<(ResolvedPackage, Manifest), KoriError> {
        match spec {
            DependencySpec::Simple(ver_req_str) => {
                // If a local sibling directory with matching name and manifest exists, use it
                let local_path = parent_dir.join(name);
                if local_path.join("kori.toml").exists() {
                    self.load_local_package(name, &local_path, Some(ver_req_str))
                } else {
                    Err(KoriError::PackageNotFound(format!(
                        "Dependency `{}` ({}) could not be resolved locally. Remote registries will be supported in future releases.",
                        name, ver_req_str
                    )))
                }
            }
            DependencySpec::Detailed(detailed) => {
                if let Some(path) = &detailed.path {
                    let target_path = if path.is_absolute() {
                        path.clone()
                    } else {
                        parent_dir.join(path)
                    };
                    self.load_local_package(name, &target_path, detailed.version.as_deref())
                } else if let Some(git_url) = &detailed.git {
                    Err(KoriError::PackageNotFound(format!(
                        "Git dependency `{}` ({}) requires git fetcher module.",
                        name, git_url
                    )))
                } else {
                    Err(KoriError::InvalidManifest(format!(
                        "Dependency `{}` must specify either `path` or `version`",
                        name
                    )))
                }
            }
        }
    }

    fn load_local_package(
        &self,
        name: &str,
        path: &Path,
        version_req: Option<&str>,
    ) -> Result<(ResolvedPackage, Manifest), KoriError> {
        let manifest_path = path.join("kori.toml");
        if !manifest_path.exists() {
            return Err(KoriError::PackageNotFound(format!(
                "Manifest not found at `{}` for package `{}`",
                manifest_path.display(),
                name
            )));
        }

        let manifest = Manifest::from_file(&manifest_path)?;
        if manifest.package.name != name {
            return Err(KoriError::InvalidManifest(format!(
                "Expected package `{}` at `{}` but found `{}`",
                name,
                path.display(),
                manifest.package.name
            )));
        }

        if let Some(req_str) = version_req {
            if let (Ok(req), Ok(actual_ver)) = (
                semver::VersionReq::parse(req_str),
                semver::Version::parse(&manifest.package.version),
            ) {
                if !req.matches(&actual_ver) {
                    return Err(KoriError::VersionMismatch {
                        package: name.to_string(),
                        required: req_str.to_string(),
                        found: manifest.package.version.clone(),
                    });
                }
            }
        }

        let checksum = Self::compute_package_checksum(path).ok();
        let rel_source = format!("path+{}", path.display());

        let pkg = ResolvedPackage {
            name: name.to_string(),
            version: manifest.package.version.clone(),
            root_dir: path.to_path_buf(),
            manifest: manifest.clone(),
            source: rel_source,
            checksum,
        };

        Ok((pkg, manifest))
    }
}

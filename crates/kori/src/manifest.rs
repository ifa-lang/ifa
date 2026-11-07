use crate::error::KoriError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Root configuration representation of a `kori.toml` manifest file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub package: PackageMetadata,
    #[serde(default)]
    pub targets: TargetsConfig,
    #[serde(default)]
    pub dependencies: BTreeMap<String, DependencySpec>,
    #[serde(default, rename = "dev-dependencies")]
    pub dev_dependencies: BTreeMap<String, DependencySpec>,
    #[serde(default)]
    pub registries: BTreeMap<String, String>,
    #[serde(default)]
    pub profiles: ProfilesConfig,
    #[serde(default)]
    pub ffi: Option<FfiConfig>,
}

/// Package identity and publishing metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageMetadata {
    pub name: String,
    pub version: String,
    #[serde(default = "default_edition")]
    pub edition: String,
    #[serde(default)]
    pub authors: Vec<String>,
    pub license: Option<String>,
    pub description: Option<String>,
    pub repository: Option<String>,
    pub homepage: Option<String>,
    #[serde(default)]
    pub keywords: Vec<String>,
}

fn default_edition() -> String {
    "2026".to_string()
}

/// Compilation targets defined for the project.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TargetsConfig {
    #[serde(default)]
    pub bin: Vec<BinTarget>,
    #[serde(default)]
    pub lib: Option<LibTarget>,
}

/// Executable binary target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinTarget {
    pub name: String,
    pub path: PathBuf,
}

/// Library target supporting multiple output formats.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LibTarget {
    pub name: String,
    pub path: PathBuf,
    #[serde(default = "default_crate_types")]
    pub crate_types: Vec<CrateType>,
}

fn default_crate_types() -> Vec<CrateType> {
    vec![CrateType::IfaLib]
}

/// Artifact types produced for a library target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CrateType {
    /// Native IFA library module for import by other IFA packages
    IfaLib,
    /// C-compatible dynamic shared library (.so, .dll, .dylib)
    Cdylib,
    /// Static C-compatible archive (.a, .lib)
    Staticlib,
    /// WebAssembly target module (wasm32-wasi)
    Wasm,
}

/// Flexible dependency specification (concise version string or detailed struct).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DependencySpec {
    Simple(String),
    Detailed(DetailedDependency),
}

impl DependencySpec {
    /// Return the required SemVer constraint if specified.
    pub fn version(&self) -> Option<&str> {
        match self {
            Self::Simple(v) => Some(v.as_str()),
            Self::Detailed(d) => d.version.as_deref(),
        }
    }

    /// Return the local file system path if specified.
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::Simple(_) => None,
            Self::Detailed(d) => d.path.as_deref(),
        }
    }

    /// Return the Git repository URL if specified.
    pub fn git(&self) -> Option<&str> {
        match self {
            Self::Simple(_) => None,
            Self::Detailed(d) => d.git.as_deref(),
        }
    }
}

/// Detailed specification for a package dependency.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DetailedDependency {
    pub version: Option<String>,
    pub path: Option<PathBuf>,
    pub git: Option<String>,
    pub branch: Option<String>,
    pub tag: Option<String>,
    pub registry: Option<String>,
    #[serde(default)]
    pub features: Vec<String>,
}

/// Compilation profile configurations (`[profiles.dev]` and `[profiles.release]`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfilesConfig {
    #[serde(default = "ProfileConfig::default_dev")]
    pub dev: ProfileConfig,
    #[serde(default = "ProfileConfig::default_release")]
    pub release: ProfileConfig,
}

impl Default for ProfilesConfig {
    fn default() -> Self {
        Self {
            dev: ProfileConfig::default_dev(),
            release: ProfileConfig::default_release(),
        }
    }
}

/// Backend engine chosen for code generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendKind {
    Cranelift,
    Llvm,
}

/// Granular compilation flags and optimization profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileConfig {
    pub backend: BackendKind,
    pub opt_level: u8,
    pub debug_assertions: bool,
    pub lto: String,
    pub strip_symbols: bool,
    pub gen_checks: bool,
}

impl ProfileConfig {
    /// Canonical development profile: instant Cranelift compilation with runtime safety checks.
    pub fn default_dev() -> Self {
        Self {
            backend: BackendKind::Cranelift,
            opt_level: 0,
            debug_assertions: true,
            lto: "none".to_string(),
            strip_symbols: false,
            gen_checks: true,
        }
    }

    /// Canonical release profile: maximum optimizations and thin LTO.
    pub fn default_release() -> Self {
        Self {
            backend: BackendKind::Llvm,
            opt_level: 3,
            debug_assertions: false,
            lto: "thin".to_string(),
            strip_symbols: true,
            gen_checks: false,
        }
    }
}

/// Foreign Function Interface (FFI) and bridge generation configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FfiConfig {
    #[serde(default = "default_true")]
    pub generate_c_headers: bool,
    #[serde(default = "default_true")]
    pub generate_php_binding: bool,
    #[serde(default = "default_php_namespace")]
    pub php_namespace: String,
    pub php_class_name: Option<String>,
    pub output_dir: Option<PathBuf>,
}

fn default_true() -> bool {
    true
}

fn default_php_namespace() -> String {
    "App\\Bridge\\Ifa".to_string()
}

impl Default for FfiConfig {
    fn default() -> Self {
        Self {
            generate_c_headers: true,
            generate_php_binding: true,
            php_namespace: default_php_namespace(),
            php_class_name: None,
            output_dir: None,
        }
    }
}

impl std::str::FromStr for Manifest {
    type Err = KoriError;

    fn from_str(toml_str: &str) -> Result<Self, Self::Err> {
        let manifest: Manifest = toml::from_str(toml_str)?;
        manifest.validate()?;
        Ok(manifest)
    }
}

impl Manifest {
    /// Read and deserialize a `kori.toml` manifest file from disk.
    pub fn from_file(path: &Path) -> Result<Self, KoriError> {
        let content = fs::read_to_string(path)?;
        content.parse()
    }

    /// Serialize the manifest into a formatted TOML string.
    pub fn to_string_pretty(&self) -> Result<String, KoriError> {
        toml::to_string_pretty(self).map_err(KoriError::ManifestSerialize)
    }

    /// Write the manifest to disk.
    pub fn save(&self, path: &Path) -> Result<(), KoriError> {
        let s = self.to_string_pretty()?;
        fs::write(path, s)?;
        Ok(())
    }

    /// Perform semantic validation on the manifest values.
    pub fn validate(&self) -> Result<(), KoriError> {
        if self.package.name.trim().is_empty() {
            return Err(KoriError::InvalidManifest(
                "Package `name` cannot be empty".to_string(),
            ));
        }

        // Validate SemVer conformance of the package version
        if semver::Version::parse(&self.package.version).is_err() {
            return Err(KoriError::InvalidManifest(format!(
                "Package version `{}` is not a valid SemVer string",
                self.package.version
            )));
        }

        Ok(())
    }

    /// Discover or derive targets when not explicitly provided in the manifest.
    pub fn resolve_targets(&mut self, root: &Path) {
        if self.targets.bin.is_empty() && self.targets.lib.is_none() {
            let main_ifa = root.join("src").join("main.ifa");
            let lib_ifa = root.join("src").join("lib.ifa");

            if main_ifa.exists() {
                self.targets.bin.push(BinTarget {
                    name: self.package.name.clone(),
                    path: PathBuf::from("src/main.ifa"),
                });
            }

            if lib_ifa.exists() {
                self.targets.lib = Some(LibTarget {
                    name: self.package.name.clone(),
                    path: PathBuf::from("src/lib.ifa"),
                    crate_types: vec![CrateType::IfaLib],
                });
            }
        }
    }
}

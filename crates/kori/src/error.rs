use thiserror::Error;

/// Unified error types encountered during Kori package management, build orchestration, and FFI generation.
#[derive(Debug, Error)]
pub enum KoriError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Failed to parse manifest `kori.toml`: {0}")]
    ManifestParse(#[from] toml::de::Error),

    #[error("Failed to serialize manifest: {0}")]
    ManifestSerialize(#[from] toml::ser::Error),

    #[error("Invalid manifest configuration: {0}")]
    InvalidManifest(String),

    #[error("Lockfile error: {0}")]
    Lockfile(String),

    #[error("Cyclic dependency detected in package graph: {0}")]
    CyclicDependency(String),

    #[error("Package `{0}` not found")]
    PackageNotFound(String),

    #[error(
        "Version resolution mismatch for package `{package}`: required {required}, found {found}"
    )]
    VersionMismatch {
        package: String,
        required: String,
        found: String,
    },

    #[error("Compilation error in package `{package}`: {message}")]
    CompilationError { package: String, message: String },

    #[error("Code generation error: {0}")]
    Codegen(String),

    #[error("FFI generation error: {0}")]
    Ffi(String),

    #[error("Packaging error: {0}")]
    Packaging(String),

    #[error("Registry error: {0}")]
    Registry(String),

    #[error(
        "Checksum mismatch for package `{package}`: expected {expected}, calculated {calculated}"
    )]
    ChecksumMismatch {
        package: String,
        expected: String,
        calculated: String,
    },
}

//! Kori: Deterministic package manager, build orchestrator, and FFI bridge generator for IFA.

pub mod builder;
pub mod cache;
pub mod error;
pub mod ffi_gen;
pub mod lockfile;
pub mod manifest;
pub mod packager;
pub mod resolver;
pub mod test_runner;

pub use builder::{ArtifactKind, BuildOrchestrator, BuildReport, BuiltArtifact};
pub use cache::BuildCache;
pub use error::KoriError;
pub use ffi_gen::{ExportedFunction, FfiBridgeGenerator};
pub use lockfile::{LockedPackage, Lockfile};
pub use manifest::{
    BackendKind, BinTarget, CrateType, DependencySpec, LibTarget, Manifest, PackageMetadata,
    ProfileConfig, ProfilesConfig,
};
pub use packager::{PackageIndexEntry, PackageReport, Packager, PublishReport};
pub use resolver::{DependencyResolver, ResolvedPackage};
pub use test_runner::{TestCaseResult, TestRunner, TestStatus, TestSuiteResult, TestSummary};

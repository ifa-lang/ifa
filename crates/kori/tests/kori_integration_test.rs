use ifa_fir::FirType;
use ifa_sema::types::IntType;
use kori::builder::BuildOrchestrator;
use kori::cache::BuildCache;
use kori::ffi_gen::{ExportedFunction, ExportedParam, FfiBridgeGenerator};
use kori::lockfile::{LockedPackage, Lockfile};
use kori::manifest::{
    CrateType, DependencySpec, Manifest, PackageMetadata, ProfileConfig, TargetsConfig,
};
use kori::resolver::DependencyResolver;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

#[test]
fn test_manifest_parse_and_validate() {
    let toml_content = r#"
[package]
name = "fintech-core"
version = "0.1.0"
edition = "2026"
authors = ["ASSOGBA Prudence Dieudonné <jprud67@gmail.com>"]
license = "MIT OR Apache-2.0"
description = "Deterministic high-throughput financial calculation engine"

[targets]
bin = [
    { name = "fintech-cli", path = "src/main.ifa" }
]

[targets.lib]
name = "fintech_native"
path = "src/lib.ifa"
crate_types = ["cdylib", "ifalib"]

[dependencies]
ifa-math = "0.1.0"
ifa-crypto = { version = "0.2.0", path = "../crypto" }

[profiles.dev]
backend = "cranelift"
opt_level = 0
debug_assertions = true
lto = "none"
strip_symbols = false
gen_checks = true

[profiles.release]
backend = "llvm"
opt_level = 3
debug_assertions = false
lto = "thin"
strip_symbols = true
gen_checks = false

[ffi]
generate_c_headers = true
generate_php_binding = true
php_namespace = "App\\Fintech\\Bridge"
php_class_name = "FintechNativeBridge"
"#;

    let manifest: Manifest = toml_content.parse().expect("Failed to parse manifest");
    assert_eq!(manifest.package.name, "fintech-core");
    assert_eq!(manifest.package.version, "0.1.0");
    assert_eq!(manifest.package.edition, "2026");
    assert_eq!(manifest.targets.bin.len(), 1);
    assert_eq!(manifest.targets.bin[0].name, "fintech-cli");

    let lib = manifest.targets.lib.expect("Expected lib target");
    assert_eq!(lib.name, "fintech_native");
    assert_eq!(lib.crate_types, vec![CrateType::Cdylib, CrateType::IfaLib]);

    assert_eq!(manifest.dependencies.len(), 2);
    assert_eq!(
        manifest.dependencies["ifa-math"],
        DependencySpec::Simple("0.1.0".to_string())
    );

    let crypto_dep = &manifest.dependencies["ifa-crypto"];
    assert_eq!(crypto_dep.version(), Some("0.2.0"));
    assert_eq!(crypto_dep.path(), Some(Path::new("../crypto")));

    let ffi = manifest.ffi.expect("Expected FFI config");
    assert_eq!(ffi.php_namespace, "App\\Fintech\\Bridge");
    assert_eq!(ffi.php_class_name.as_deref(), Some("FintechNativeBridge"));
}

#[test]
fn test_lockfile_deterministic_ordering() {
    let mut lock = Lockfile::default();

    lock.packages.push(LockedPackage {
        name: "zebra".to_string(),
        version: "1.0.0".to_string(),
        source: "path+../zebra".to_string(),
        checksum: Some(
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9".to_string(),
        ),
        dependencies: vec!["alpha".to_string(), "gamma".to_string()],
    });

    lock.packages.push(LockedPackage {
        name: "alpha".to_string(),
        version: "0.1.0".to_string(),
        source: "root".to_string(),
        checksum: None,
        dependencies: vec![],
    });

    let toml_str = lock
        .to_string_pretty()
        .expect("Lockfile serialization failed");

    // "alpha" must appear before "zebra" in deterministic output
    let alpha_pos = toml_str.find("name = \"alpha\"").unwrap();
    let zebra_pos = toml_str.find("name = \"zebra\"").unwrap();
    assert!(alpha_pos < zebra_pos);

    // Dependencies of zebra must be sorted: alpha before gamma
    let alpha_dep_pos = toml_str.find("\"alpha\"").unwrap();
    let gamma_dep_pos = toml_str.find("\"gamma\"").unwrap();
    assert!(alpha_dep_pos < gamma_dep_pos);

    // Round-trip parse test
    let parsed: Lockfile = toml_str.parse().expect("Failed to parse lockfile back");
    assert_eq!(parsed.packages.len(), 2);
    assert_eq!(parsed.packages[0].name, "alpha");
    assert_eq!(parsed.packages[1].name, "zebra");
}

#[test]
fn test_dependency_resolver_and_cycle_detection() {
    let temp_dir = std::env::temp_dir().join(format!("kori_test_cycle_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(temp_dir.join("pkg_a")).unwrap();
    fs::create_dir_all(temp_dir.join("pkg_b")).unwrap();

    let manifest_a = r#"
[package]
name = "pkg_a"
version = "0.1.0"
edition = "2026"

[dependencies]
pkg_b = { path = "../pkg_b" }
"#;

    let manifest_b = r#"
[package]
name = "pkg_b"
version = "0.1.0"
edition = "2026"

[dependencies]
pkg_a = { path = "../pkg_a" }
"#;

    fs::write(temp_dir.join("pkg_a").join("kori.toml"), manifest_a).unwrap();
    fs::write(temp_dir.join("pkg_b").join("kori.toml"), manifest_b).unwrap();

    let root_manifest: Manifest = manifest_a.parse().unwrap();
    let resolver = DependencyResolver::new(temp_dir.join("pkg_a"));
    let res = resolver.resolve(&root_manifest, None);

    assert!(res.is_err());
    match res.unwrap_err() {
        kori::KoriError::CyclicDependency(msg) => {
            assert!(msg.contains("Circular dependency"));
        }
        other => panic!("Expected CyclicDependency, got {:?}", other),
    }

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_build_cache_fingerprint_and_staleness() {
    let temp_dir = std::env::temp_dir().join(format!("kori_test_cache_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let mut cache = BuildCache::new(&temp_dir).expect("Failed to initialize BuildCache");

    let profile = ProfileConfig::default_dev();
    let pkg = kori::ResolvedPackage {
        name: "test-pkg".to_string(),
        version: "0.1.0".to_string(),
        root_dir: temp_dir.clone(),
        manifest: Manifest {
            package: PackageMetadata {
                name: "test-pkg".to_string(),
                version: "0.1.0".to_string(),
                edition: "2026".to_string(),
                authors: vec![],
                license: None,
                description: None,
                repository: None,
                homepage: None,
                keywords: vec![],
            },
            targets: TargetsConfig::default(),
            dependencies: BTreeMap::new(),
            dev_dependencies: BTreeMap::new(),
            profiles: Default::default(),
            ffi: None,
        },
        source: "root".to_string(),
        checksum: Some(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        ),
    };

    let fp1 = cache.compute_target_fingerprint(&pkg, &profile, &[]);
    let fp2 = cache.compute_target_fingerprint(&pkg, &profile, &[]);
    assert_eq!(fp1, fp2);

    let dummy_output = temp_dir.join("dummy_bin");
    fs::write(&dummy_output, "binary_data").unwrap();

    assert!(!cache.is_up_to_date("test-pkg:bin:test", &fp1, &[&dummy_output]));

    cache
        .record_success("test-pkg:bin:test", fp1.clone(), vec![dummy_output.clone()])
        .unwrap();

    assert!(cache.is_up_to_date("test-pkg:bin:test", &fp1, &[&dummy_output]));

    // Modifying fingerprint makes cache stale
    let mut modified_profile = profile.clone();
    modified_profile.opt_level = 3;
    let fp_modified = cache.compute_target_fingerprint(&pkg, &modified_profile, &[]);
    assert_ne!(fp1, fp_modified);
    assert!(!cache.is_up_to_date("test-pkg:bin:test", &fp_modified, &[&dummy_output]));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_ffi_c_header_and_php_bridge_generation() {
    let ffi_config = kori::manifest::FfiConfig {
        generate_c_headers: true,
        generate_php_binding: true,
        php_namespace: "App\\Bridge\\NativeBridge".to_string(),
        php_class_name: Some("NativeCryptoService".to_string()),
        output_dir: None,
    };

    let gen = FfiBridgeGenerator::new("crypto-engine", ffi_config);

    let exported_fns = vec![
        ExportedFunction {
            name: "hash_transaction".to_string(),
            is_strict: true,
            params: vec![
                ExportedParam {
                    name: "amount".to_string(),
                    ty: FirType::Int(IntType::I64),
                },
                ExportedParam {
                    name: "currency_code".to_string(),
                    ty: FirType::Int(IntType::I32),
                },
            ],
            return_type: FirType::Int(IntType::I64),
        },
        ExportedFunction {
            name: "validate_signature".to_string(),
            is_strict: true,
            params: vec![ExportedParam {
                name: "signature".to_string(),
                ty: FirType::Str,
            }],
            return_type: FirType::Bool,
        },
    ];

    let c_header = gen.generate_c_header(&exported_fns);
    assert!(c_header.contains("#ifndef CRYPTO_ENGINE_H"));
    assert!(c_header.contains("#define CRYPTO_ENGINE_H"));
    assert!(c_header.contains("int64_t hash_transaction(int64_t amount, int32_t currency_code);"));
    assert!(c_header.contains("bool validate_signature(const char* signature);"));

    let php_class = gen.generate_php_class(
        "NativeCryptoService",
        &exported_fns,
        "crypto_engine.h",
        "libcrypto_engine.so",
    );

    assert!(php_class.contains("namespace App\\Bridge\\NativeBridge;"));
    assert!(php_class.contains("final class NativeCryptoService"));
    assert!(php_class
        .contains("public function hash_transaction(int $amount, int $currency_code): int"));
    assert!(php_class.contains("return $this->ffi->hash_transaction($amount, $currency_code);"));
    assert!(php_class.contains("public function validate_signature(string $signature): bool"));
    assert!(php_class.contains("public static function setPreloadedInstance(FFI $ffi): void"));
}

#[test]
fn test_build_orchestrator_project_creation_and_compilation() {
    let temp_dir = std::env::temp_dir().join(format!("kori_test_e2e_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(temp_dir.join("src")).unwrap();

    let manifest = r#"
[package]
name = "math_service"
version = "0.1.0"
edition = "2026"
authors = ["ASSOGBA Prudence Dieudonné <jprud67@gmail.com>"]

[targets]
bin = [
    { name = "math_service", path = "src/main.ifa" }
]

[targets.lib]
name = "math_service"
path = "src/lib.ifa"
crate_types = ["cdylib"]

[ffi]
generate_c_headers = true
generate_php_binding = true
php_namespace = "App\\Service\\Native"
php_class_name = "MathBridge"
"#;

    let main_ifa = r#"
pub fn main() -> () {
    let val = 42
    println("Math service initialized.")
}
"#;

    let lib_ifa = r#"
pub extern "C" strict fn compute_hash(seed: i64, multiplier: i64) -> i64 {
    return seed * multiplier + 7
}
"#;

    fs::write(temp_dir.join("kori.toml"), manifest).unwrap();
    fs::write(temp_dir.join("src").join("main.ifa"), main_ifa).unwrap();
    fs::write(temp_dir.join("src").join("lib.ifa"), lib_ifa).unwrap();

    let orchestrator =
        BuildOrchestrator::new(temp_dir.clone()).expect("Failed to initialize orchestrator");
    let report = orchestrator.build(false, None, true).expect("Build failed");

    assert!(report.packages_resolved >= 1);
    assert!(!report.artifacts.is_empty());

    // Verify binary artifact was created
    let bin_art = report
        .artifacts
        .iter()
        .find(|a| a.kind == kori::ArtifactKind::Executable)
        .expect("Executable artifact missing");
    assert!(bin_art.path.exists());

    // Verify shared library (.so) artifact was created
    let so_art = report
        .artifacts
        .iter()
        .find(|a| a.kind == kori::ArtifactKind::SharedLibrary)
        .expect("Shared library artifact missing");
    assert!(so_art.path.exists());

    // Verify C header artifact was created
    let header_art = report
        .artifacts
        .iter()
        .find(|a| a.kind == kori::ArtifactKind::CHeader)
        .expect("C Header artifact missing");
    assert!(header_art.path.exists());
    let header_content = fs::read_to_string(&header_art.path).unwrap();
    assert!(header_content.contains("int64_t compute_hash(int64_t seed, int64_t multiplier);"));

    // Verify PHP 8.4+ / Symfony 8.1 FFI bridge artifact was created
    let php_art = report
        .artifacts
        .iter()
        .find(|a| a.kind == kori::ArtifactKind::PhpBridge)
        .expect("PHP Bridge artifact missing");
    assert!(php_art.path.exists());
    let php_content = fs::read_to_string(&php_art.path).unwrap();
    assert!(php_content.contains("namespace App\\Service\\Native;"));
    assert!(php_content.contains("final class MathBridge"));
    assert!(php_content.contains("public function compute_hash(int $seed, int $multiplier): int"));

    // Verify lockfile was generated
    let lock_file = temp_dir.join("kori.lock");
    assert!(lock_file.exists());

    // Test second run with cache enabled
    let cached_report = orchestrator
        .build(false, None, false)
        .expect("Cached build failed");
    let cached_bin = cached_report
        .artifacts
        .iter()
        .find(|a| a.kind == kori::ArtifactKind::Executable)
        .expect("Executable missing in cached run");
    assert!(cached_bin.cached);

    let _ = fs::remove_dir_all(&temp_dir);
}

use kori::builder::BuildOrchestrator;
use std::fs;
use std::process::Command;

#[test]
fn test_multi_module_package_build_and_run() {
    let temp_dir = std::env::temp_dir().join(format!("kori_multi_mod_test_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(temp_dir.join("src/math")).unwrap();
    fs::create_dir_all(temp_dir.join("src/services")).unwrap();

    // 1. Write kori.toml manifest
    let manifest = r#"
[package]
name = "multi-mod-app"
version = "0.1.0"
edition = "2026"
authors = ["ASSOGBA Prudence Dieudonné <jprud67@gmail.com>"]
license = "MIT"
description = "Multi-module hierarchical IFA application"

[targets]
bin = [
    { name = "app_runner", path = "src/main.ifa" }
]

[profiles.dev]
backend = "cranelift"
opt_level = 0
debug_assertions = true
lto = "none"
strip_symbols = false
gen_checks = true

[profiles.release]
backend = "cranelift"
opt_level = 2
debug_assertions = false
lto = "none"
strip_symbols = false
gen_checks = false
"#;
    fs::write(temp_dir.join("kori.toml"), manifest).unwrap();

    // 2. Write src/math/geometry.ifa
    let geometry_src = r#"
pub struct Rectangle {
    width: i64,
    height: i64,
}

pub fn calculate_area(r: Rectangle) -> i64 {
    return r.width * r.height;
}

pub fn calculate_perimeter(r: Rectangle) -> i64 {
    return (r.width + r.height) * 2;
}

fn internal_secret() -> i64 {
    return 999;
}
"#;
    fs::write(temp_dir.join("src/math/geometry.ifa"), geometry_src).unwrap();

    // 3. Write src/services/billing.ifa
    let billing_src = r#"
pub fn compute_bill(area: i64, unit_rate: i64) -> i64 {
    return area * unit_rate;
}
"#;
    fs::write(temp_dir.join("src/services/billing.ifa"), billing_src).unwrap();

    // 4. Write src/main.ifa importing both local modules
    let main_src = r#"
import math::geometry as geo;
import services::billing;
import std::io;

pub fn main() {
    let rect = geo::Rectangle(width: 20, height: 10);
    let area = geo::calculate_area(rect);
    let perimeter = geo::calculate_perimeter(rect);
    let total_cost = billing::compute_bill(area, 5);

    io::println("Successfully calculated multi-module area and billing");
}
"#;
    fs::write(temp_dir.join("src/main.ifa"), main_src).unwrap();

    // 5. Build the multi-module project via BuildOrchestrator
    let orchestrator =
        BuildOrchestrator::new(temp_dir.clone()).expect("Failed to initialize orchestrator");
    let report = orchestrator
        .build(false, None, true)
        .expect("Multi-module build must succeed");

    assert_eq!(report.artifacts.len(), 1);
    let exe_artifact = &report.artifacts[0];
    assert_eq!(exe_artifact.name, "app_runner");
    assert!(exe_artifact.path.exists());

    // 6. Execute compiled binary
    let status = Command::new(&exe_artifact.path)
        .status()
        .expect("Failed to execute compiled multi-module binary");
    assert!(
        status.success(),
        "Compiled multi-module binary should exit successfully"
    );

    // Clean up
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_multi_module_private_member_violation() {
    let temp_dir = std::env::temp_dir().join(format!("kori_priv_mod_test_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(temp_dir.join("src/security")).unwrap();

    let manifest = r#"
[package]
name = "priv-test-app"
version = "0.1.0"
edition = "2026"
authors = ["ASSOGBA Prudence Dieudonné <jprud67@gmail.com>"]
license = "MIT"
description = "Privacy violation test"

[targets]
bin = [
    { name = "priv_runner", path = "src/main.ifa" }
]

[profiles.dev]
backend = "cranelift"
opt_level = 0
debug_assertions = true
lto = "none"
strip_symbols = false
gen_checks = true
"#;
    fs::write(temp_dir.join("kori.toml"), manifest).unwrap();

    let security_src = r#"
pub fn public_check() -> bool {
    return true;
}

fn internal_key() -> i64 {
    return 1337;
}
"#;
    fs::write(temp_dir.join("src/security/vault.ifa"), security_src).unwrap();

    let main_src = r#"
import security::vault;

pub fn main() {
    let key = vault::internal_key();
}
"#;
    fs::write(temp_dir.join("src/main.ifa"), main_src).unwrap();

    let orchestrator =
        BuildOrchestrator::new(temp_dir.clone()).expect("Failed to initialize orchestrator");
    let result = orchestrator.build(false, None, true);

    assert!(
        result.is_err(),
        "Accessing private module member must fail the build"
    );
    let err_msg = format!("{:?}", result.err().unwrap());
    assert!(
        err_msg.contains("E0011") || err_msg.contains("privée"),
        "Error must report privacy violation: {}",
        err_msg
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_multi_module_package_llvm_release_build() {
    let temp_dir =
        std::env::temp_dir().join(format!("kori_multi_mod_llvm_test_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(temp_dir.join("src/math")).unwrap();

    let manifest = r#"
[package]
name = "llvm-multi-app"
version = "0.1.0"
edition = "2026"
authors = ["ASSOGBA Prudence Dieudonné <jprud67@gmail.com>"]
license = "MIT"
description = "LLVM optimized multi-module IFA application"

[targets]
bin = [
    { name = "llvm_runner", path = "src/main.ifa" }
]

[profiles.release]
backend = "llvm"
opt_level = 3
debug_assertions = false
lto = "thin"
strip_symbols = false
gen_checks = false
"#;
    fs::write(temp_dir.join("kori.toml"), manifest).unwrap();

    let geometry_src = r#"
pub struct Point {
    x: i64,
    y: i64,
}

pub fn manhattan_distance(p1: Point, p2: Point) -> i64 {
    let dx = if p1.x > p2.x { p1.x - p2.x } else { p2.x - p1.x };
    let dy = if p1.y > p2.y { p1.y - p2.y } else { p2.y - p1.y };
    return dx + dy;
}
"#;
    fs::write(temp_dir.join("src/math/geometry.ifa"), geometry_src).unwrap();

    let main_src = r#"
import math::geometry as geo;
import std::io;

pub fn main() {
    let a = geo::Point(x: 10, y: 20);
    let b = geo::Point(x: 40, y: 60);
    let dist = geo::manhattan_distance(a, b);

    io::println("LLVM multi-module Manhattan distance calculated");
}
"#;
    fs::write(temp_dir.join("src/main.ifa"), main_src).unwrap();

    let orchestrator =
        BuildOrchestrator::new(temp_dir.clone()).expect("Failed to initialize orchestrator");
    let report = orchestrator
        .build(true, None, true)
        .expect("LLVM multi-module release build must succeed");

    assert_eq!(report.artifacts.len(), 1);
    let exe_artifact = &report.artifacts[0];
    assert_eq!(exe_artifact.name, "llvm_runner");
    assert!(exe_artifact.path.exists());

    let status = Command::new(&exe_artifact.path)
        .status()
        .expect("Failed to execute LLVM compiled multi-module binary");
    assert!(
        status.success(),
        "LLVM multi-module binary should exit successfully"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_binary_module_metadata_incremental_cache() {
    use kori::module_metadata::{ModuleMetadata, IFAM_MAGIC};

    let temp_dir =
        std::env::temp_dir().join(format!("kori_incremental_meta_test_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(temp_dir.join("src/algo")).unwrap();

    let manifest = r#"
[package]
name = "cached-meta-app"
version = "0.1.0"
edition = "2026"
authors = ["ASSOGBA Prudence Dieudonné <jprud67@gmail.com>"]
license = "MIT"
description = "Incremental binary metadata cache test"

[targets]
bin = [
    { name = "cached_app", path = "src/main.ifa" }
]

[profiles.dev]
backend = "cranelift"
opt_level = 0
debug_assertions = true
lto = "none"
strip_symbols = false
gen_checks = true
"#;
    fs::write(temp_dir.join("kori.toml"), manifest).unwrap();

    let sort_src = r#"
pub fn compute_sum(a: i64, b: i64) -> i64 {
    return a + b;
}
"#;
    fs::write(temp_dir.join("src/algo/sort.ifa"), sort_src).unwrap();

    let main_src = r#"
import algo::sort;

pub fn main() {
    let s = sort::compute_sum(10, 20);
}
"#;
    fs::write(temp_dir.join("src/main.ifa"), main_src).unwrap();

    // 1. First build: must compile submodule and populate .kori-cache/modules with IFAM metadata
    let orchestrator = BuildOrchestrator::new(temp_dir.clone()).unwrap();
    let report1 = orchestrator.build(false, None, false).unwrap();
    assert_eq!(report1.artifacts.len(), 1);

    let cache_modules_dir = temp_dir.join("target/.kori-cache/modules");
    assert!(
        cache_modules_dir.exists(),
        "Binary module cache directory must exist"
    );

    let meta_files: Vec<_> = fs::read_dir(&cache_modules_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "ifameta"))
        .collect();
    assert!(
        !meta_files.is_empty(),
        "At least one .ifameta binary file must be created"
    );

    let meta_path = &meta_files[0].path();
    let meta_bytes = fs::read(meta_path).unwrap();
    assert_eq!(
        &meta_bytes[0..4],
        &IFAM_MAGIC,
        "Binary metadata header must match IFAM"
    );

    let deserialized = ModuleMetadata::deserialize_from_binary(&meta_bytes)
        .expect("Should deserialize cached binary metadata successfully");
    assert!(
        deserialized
            .functions
            .iter()
            .any(|f| f.name == "compute_sum"),
        "Exported function compute_sum must be recorded in binary metadata"
    );

    // 2. Second build: must load submodule metadata from cache without errors
    let report2 = orchestrator.build(false, None, false).unwrap();
    assert_eq!(report2.artifacts.len(), 1);

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_multi_module_submodule_semantic_error_reporting() {
    let temp_dir =
        std::env::temp_dir().join(format!("kori_submod_err_test_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(temp_dir.join("src/calc")).unwrap();

    let manifest = r#"
[package]
name = "submod-err-app"
version = "0.1.0"
edition = "2026"
authors = ["ASSOGBA Prudence Dieudonné <jprud67@gmail.com>"]
license = "MIT"
description = "Submodule semantic error propagation test"

[targets]
bin = [
    { name = "err_runner", path = "src/main.ifa" }
]

[profiles.dev]
backend = "cranelift"
opt_level = 0
debug_assertions = true
lto = "none"
strip_symbols = false
gen_checks = true
"#;
    fs::write(temp_dir.join("kori.toml"), manifest).unwrap();

    // Submodule contains a semantic type mismatch
    let bad_math_src = r#"
pub fn broken_add(a: i64, b: i64) -> i64 {
    return "invalid_string_type";
}
"#;
    fs::write(temp_dir.join("src/calc/bad_math.ifa"), bad_math_src).unwrap();

    let main_src = r#"
import calc::bad_math;

pub fn main() {
    let x = bad_math::broken_add(1, 2);
}
"#;
    fs::write(temp_dir.join("src/main.ifa"), main_src).unwrap();

    let orchestrator =
        BuildOrchestrator::new(temp_dir.clone()).expect("Failed to initialize orchestrator");
    let result = orchestrator.build(false, None, true);

    assert!(
        result.is_err(),
        "Build must fail when submodule contains semantic errors"
    );
    let err_str = format!("{:?}", result.err().unwrap());
    assert!(
        err_str.contains("E0002") || err_str.contains("Type mismatch") || err_str.contains("type"),
        "Error diagnostic must report type mismatch in submodule: {}",
        err_str
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_multi_module_orchestrator_check() {
    let temp_dir = std::env::temp_dir().join(format!("kori_check_test_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(temp_dir.join("src/domain")).unwrap();

    let manifest = r#"
[package]
name = "check-demo-app"
version = "0.1.0"
edition = "2026"
authors = ["ASSOGBA Prudence Dieudonné <jprud67@gmail.com>"]
license = "MIT"
description = "Fast semantic check test"

[targets]
bin = [
    { name = "check_runner", path = "src/main.ifa" }
]
"#;
    fs::write(temp_dir.join("kori.toml"), manifest).unwrap();

    let domain_src = r#"
pub struct User {
    id: i64,
    active: bool,
}

pub fn create_user(id: i64) -> User {
    return User(id: id, active: true);
}
"#;
    fs::write(temp_dir.join("src/domain/user.ifa"), domain_src).unwrap();

    let main_src = r#"
import domain::user;

pub fn main() {
    let u = user::create_user(42);
}
"#;
    fs::write(temp_dir.join("src/main.ifa"), main_src).unwrap();

    let orchestrator =
        BuildOrchestrator::new(temp_dir.clone()).expect("Failed to initialize orchestrator");
    let report = orchestrator.check().expect("Semantic check must succeed");
    assert_eq!(report.package, "check-demo-app");
    assert_eq!(report.targets_checked, 1);

    // Now introduce an error in user.ifa and ensure check() catches it
    let bad_domain_src = r#"
pub fn create_user(id: i64) -> i64 {
    return "invalid_type";
}
"#;
    fs::write(temp_dir.join("src/domain/user.ifa"), bad_domain_src).unwrap();

    let bad_check = orchestrator.check();
    assert!(
        bad_check.is_err(),
        "Check must fail when submodule has errors"
    );
    let err_msg = format!("{:?}", bad_check.err().unwrap());
    assert!(
        err_msg.contains("Type mismatch") || err_msg.contains("E0002") || err_msg.contains("type"),
        "Diagnostic must report type error: {}",
        err_msg
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

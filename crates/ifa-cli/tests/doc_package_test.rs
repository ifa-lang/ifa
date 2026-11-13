use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn get_ifa_binary() -> PathBuf {
    if let Some(bin) = option_env!("CARGO_BIN_EXE_ifa") {
        let p = PathBuf::from(bin);
        if p.exists() {
            return p;
        }
    }
    let mut path = std::env::current_exe().expect("current exe");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.push(if cfg!(windows) { "ifa.exe" } else { "ifa" });
    path
}

#[test]
fn test_package_multi_module_doc_generation() {
    let ifa_bin = get_ifa_binary();
    let temp_pkg_dir =
        std::env::temp_dir().join(format!("ifa_doc_pkg_test_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_pkg_dir);

    let src_dir = temp_pkg_dir.join("src");
    fs::create_dir_all(&src_dir).unwrap();

    let kori_toml = r#"
[package]
name = "math_engine"
version = "0.2.0"
authors = ["ASSOGBA Prudence Dieudonné <jprud67@gmail.com>"]
description = "High-performance computational algorithms and vector primitives"
license = "MIT OR Apache-2.0"
"#;
    fs::write(temp_pkg_dir.join("kori.toml"), kori_toml).unwrap();

    let math_ifa = r#"
//! Core mathematical transformations and vector arithmetic.

/// Fast 2D vector representation for linear algebra.
pub struct Vector2 {
    pub x: i64,
    pub y: i64,
}

/// Compute scalar dot product between two 2D vectors.
pub fn dot_product(in a: Vector2, in b: Vector2) -> i64 {
    return a.x * b.x + a.y * b.y;
}
"#;
    fs::write(src_dir.join("math.ifa"), math_ifa).unwrap();

    let utils_ifa = r#"
//! General string and buffer formatting utilities.

/// Check if a given string contains content.
pub fn is_valid_identifier(id: String) -> bool {
    return id.len() > 0;
}
"#;
    fs::write(src_dir.join("utils.ifa"), utils_ifa).unwrap();

    let docs_output_dir = temp_pkg_dir.join("docs");

    let output = Command::new(&ifa_bin)
        .arg("doc")
        .arg(&temp_pkg_dir)
        .arg("-o")
        .arg(&docs_output_dir)
        .output()
        .expect("Failed to execute `ifa doc` on multi-module package");

    assert!(
        output.status.success(),
        "ifa doc failed with code {:?}\nstdout: {}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify per-module documentation
    assert!(docs_output_dir.join("math.md").exists());
    assert!(docs_output_dir.join("math.html").exists());
    assert!(docs_output_dir.join("utils.md").exists());
    assert!(docs_output_dir.join("utils.html").exists());

    // Verify package book index
    let index_md = docs_output_dir.join("index.md");
    let index_html = docs_output_dir.join("index.html");
    assert!(index_md.exists(), "index.md must be generated for package");
    assert!(
        index_html.exists(),
        "index.html must be generated for package"
    );

    let md_content = fs::read_to_string(&index_md).unwrap();
    assert!(md_content.contains("# Package `math_engine` v0.2.0"));
    assert!(md_content.contains("### [math](math.md)"));
    assert!(md_content.contains("### [utils](utils.md)"));
    assert!(md_content.contains("Core mathematical transformations"));

    let html_content = fs::read_to_string(&index_html).unwrap();
    assert!(html_content.contains("Package <code>math_engine</code> v0.2.0"));
    assert!(html_content.contains("href=\"math.html\""));
    assert!(html_content.contains("href=\"utils.html\""));
    assert!(html_content.contains("badge"));

    // Cleanup
    let _ = fs::remove_dir_all(&temp_pkg_dir);
}

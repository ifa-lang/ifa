//! End-to-end integration test validating the self-hosting compiler pipeline,
//! pure IFA AST analysis, colorless execution, testing framework, and canonical doc generation.

use std::path::PathBuf;
use std::process::Command;

fn get_ifa_binary() -> PathBuf {
    let mut path = std::env::current_exe().expect("current exe");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.push("ifa");
    path
}

#[test]
fn test_selfhost_compiler_full_pipeline() {
    let ifa_bin = get_ifa_binary();
    let sample_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("examples")
        .join("self_host_compiler.ifa");

    assert!(
        sample_file.exists(),
        "Sample compiler file missing at {:?}",
        sample_file
    );

    // 1. Static check
    let check_status = Command::new(&ifa_bin)
        .arg("check")
        .arg(&sample_file)
        .status()
        .expect("Failed to execute `ifa check`");
    assert!(
        check_status.success(),
        "ifa check failed on self_host_compiler.ifa"
    );

    // 2. Unit testing framework execution
    let test_output = Command::new(&ifa_bin)
        .arg("test")
        .arg(&sample_file)
        .output()
        .expect("Failed to execute `ifa test`");
    assert!(
        test_output.status.success(),
        "ifa test failed with exit code {:?}\nstdout: {}\nstderr: {}",
        test_output.status.code(),
        String::from_utf8_lossy(&test_output.stdout),
        String::from_utf8_lossy(&test_output.stderr)
    );
    let test_stdout = String::from_utf8_lossy(&test_output.stdout);
    assert!(test_stdout.contains("test test_selfhost_lexer ... ok"));
    assert!(test_stdout.contains("test test_selfhost_ast_building ... ok"));
    assert!(test_stdout.contains("test test_selfhost_eval ... ok"));
    assert!(test_stdout.contains("test test_selfhost_recursive_precedence ... ok"));
    assert!(test_stdout.contains("test test_selfhost_recursive_paren_precedence ... ok"));
    assert!(test_stdout.contains("test test_selfhost_function_parser_and_eval ... ok"));
    assert!(test_stdout.contains("test test_selfhost_fir_codegen_expression ... ok"));
    assert!(test_stdout.contains("test test_selfhost_fir_codegen_function ... ok"));
    assert!(test_stdout.contains("Test result: 8 passed; 0 failed"));

    // 3. Complete execution via SSA FIR interpreter
    let run_output = Command::new(&ifa_bin)
        .arg("run")
        .arg(&sample_file)
        .output()
        .expect("Failed to execute `ifa run`");
    let run_stdout = String::from_utf8_lossy(&run_output.stdout);
    assert!(
        run_output.status.success(),
        "ifa run failed with code {:?}\nstdout: {}\nstderr: {}",
        run_output.status.code(),
        run_stdout,
        String::from_utf8_lossy(&run_output.stderr)
    );
    assert!(
        run_stdout.contains("=== IFA Self-Hosting Compiler Testbench ==="),
        "stdout was: {}",
        run_stdout
    );
    assert!(
        run_stdout.contains("Total token count: 22"),
        "stdout was: {}",
        run_stdout
    );
    assert!(
        run_stdout.contains("Evaluated AST function compute(2): 42"),
        "stdout was: {}",
        run_stdout
    );
    assert!(
        run_stdout.contains("Evaluated AST function arithmetic(4): 28"),
        "stdout was: {}",
        run_stdout
    );
    assert!(
        run_stdout.contains("--- Generated FIR SSA for @compute ---"),
        "stdout was: {}",
        run_stdout
    );
    assert!(
        run_stdout.contains("fir.func @compute(%x: i64) -> i64 {"),
        "stdout was: {}",
        run_stdout
    );
    assert!(
        run_stdout.contains("%t1 = add %x, %t0"),
        "stdout was: {}",
        run_stdout
    );
    assert!(
        run_stdout.contains("--- Generated FIR SSA for @arithmetic ---"),
        "stdout was: {}",
        run_stdout
    );
    assert!(
        run_stdout.contains("fir.func @arithmetic(%x: i64) -> i64 {"),
        "stdout was: {}",
        run_stdout
    );
    assert!(run_stdout.contains("ret %t5"), "stdout was: {}", run_stdout);

    // 4. Canonical documentation generation
    let temp_doc_dir = std::env::temp_dir().join("ifa_selfhost_doc_test");
    let doc_output = Command::new(&ifa_bin)
        .arg("doc")
        .arg(&sample_file)
        .arg("-o")
        .arg(&temp_doc_dir)
        .output()
        .expect("Failed to execute `ifa doc`");
    assert!(
        doc_output.status.success(),
        "ifa doc failed: {:?}",
        doc_output
    );

    let md_file = temp_doc_dir.join("self_host_compiler.md");
    let html_file = temp_doc_dir.join("self_host_compiler.html");
    assert!(
        md_file.exists(),
        "Markdown docs not generated at {:?}",
        md_file
    );
    assert!(
        html_file.exists(),
        "HTML docs not generated at {:?}",
        html_file
    );

    let md_content = std::fs::read_to_string(&md_file).unwrap();
    assert!(md_content.contains("# Module `self_host_compiler`"));
    assert!(md_content.contains("fn tokenize_sample_program() -> List<Token>"));
    assert!(md_content.contains("struct AstExpr"));
    assert!(md_content.contains("inout stream: List<Token>"));

    let html_content = std::fs::read_to_string(&html_file).unwrap();
    assert!(html_content.contains("<!DOCTYPE html>"));
    assert!(html_content.contains("Module <code>self_host_compiler</code>"));
    assert!(html_content.contains("badge-pub"));

    // Cleanup
    let _ = std::fs::remove_dir_all(&temp_doc_dir);
}

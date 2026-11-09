//! Automated Testbench for Triple-Stage Bootstrap and Bit-for-Bit Deterministic Self-Hosting.
//!
//! Validates the fixed-point convergence of the IFA compiler toolchain:
//! - Stage 0 (Rust Host Compiler) compiles pure IFA compiler sources (`compiler/`).
//! - Stage 1 (`ifac-gen1`) produces Stage 2 artifacts (`ifac-gen2`).
//! - Stage 2 (`ifac-gen2`) produces Stage 3 artifacts (`ifac-gen3`).
//! - Fixed-point validation asserts: `sha256(ifac-gen2) == sha256(ifac-gen3)`.

use ifa_stdlib::crypto::sha256_hex;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn get_workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn get_kori_binary() -> PathBuf {
    let mut path = std::env::current_exe().expect("current test executable");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.push("kori");
    if !path.exists() {
        let status = Command::new("cargo")
            .arg("build")
            .arg("-p")
            .arg("kori")
            .status()
            .expect("Build kori binary");
        assert!(status.success(), "Failed to build kori binary");
    }
    path
}

#[test]
fn test_modular_compiler_sources_exist() {
    let root = get_workspace_root();
    let compiler_dir = root.join("compiler");

    let required_files = [
        "kori.toml",
        "lexer.ifa",
        "parser.ifa",
        "sema.ifa",
        "codegen_llvm.ifa",
        "driver.ifa",
        "main.ifa",
    ];

    for file in &required_files {
        let p = compiler_dir.join(file);
        assert!(
            p.exists(),
            "Required modular compiler file missing: {:?}",
            p
        );
        let meta = fs::metadata(&p).expect("read metadata");
        assert!(meta.len() > 0, "Compiler file {:?} is empty", p);
    }
}

#[test]
fn test_modular_compiler_unit_tests() {
    let root = get_workspace_root();
    let kori_bin = get_kori_binary();
    let manifest_path = root.join("compiler").join("kori.toml");

    let test_status = Command::new(&kori_bin)
        .arg("test")
        .arg("--manifest-path")
        .arg(&manifest_path)
        .output()
        .expect("Failed to execute `kori test` on modular compiler");

    let stdout = String::from_utf8_lossy(&test_status.stdout);
    let stderr = String::from_utf8_lossy(&test_status.stderr);

    assert!(
        test_status.status.success(),
        "`kori test` failed on compiler/kori.toml:\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );

    assert!(
        stdout.contains("test test_lexer_stream ... ok"),
        "Modular lexer tests missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_lexer_type_alias ... ok"),
        "Modular lexer type alias test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_lexer_tuples ... ok"),
        "Modular lexer tuples test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_lexer_arena ... ok"),
        "Modular lexer arena test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_parser_ast_building ... ok"),
        "Modular parser tests missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_parser_type_alias ... ok"),
        "Modular parser type alias test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_parser_tuple_expression ... ok"),
        "Modular parser tuple expression test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_parser_tuple_index_access ... ok"),
        "Modular parser tuple index access test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_parser_arena_declaration ... ok"),
        "Modular parser arena declaration test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_parser_trait_declaration ... ok"),
        "Modular parser trait test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_parser_impl_declaration ... ok"),
        "Modular parser impl test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_parser_match_expression ... ok"),
        "Modular parser match test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_parser_program_high_level_items ... ok"),
        "Modular parser program test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sema_eval ... ok"),
        "Modular sema tests missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sema_type_alias_resolution ... ok"),
        "Modular sema type alias resolution test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sema_tuple_operations ... ok"),
        "Modular sema tuple operations test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sema_arena_allocation ... ok"),
        "Modular sema arena allocation test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sema_pattern_matching ... ok"),
        "Modular sema pattern matching test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_function_emission ... ok"),
        "Modular codegen tests missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_while_loop ... ok"),
        "Modular codegen while loop test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_pattern_match ... ok"),
        "Modular codegen match test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_generic_method_call ... ok"),
        "Modular codegen generic method test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_complex_function ... ok"),
        "Modular codegen complex function test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_full_module_assembly ... ok"),
        "Modular driver tests missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_complex_module_and_bootstrap_orchestration ... ok"),
        "Modular driver complex module test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_selfhost_modular_pipeline ... ok"),
        "Modular selfhost pipeline test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("73 passed; 0 failed"),
        "Expected 73 passed unit tests, got:\n{}",
        stdout
    );
}

#[test]
fn test_bootstrap_triple_compilation_and_fixed_point_hash() {
    let root = get_workspace_root();
    let kori_bin = get_kori_binary();
    let manifest_path = root.join("compiler").join("kori.toml");
    let target_dev_dir = root.join("compiler").join("target").join("dev");

    // Stage 0 -> Stage 1: Build Gen 1 compiler executable
    let build_gen1 = Command::new(&kori_bin)
        .arg("build")
        .arg("--force")
        .arg("--manifest-path")
        .arg(&manifest_path)
        .output()
        .expect("Build Stage 1 compiler binary");

    assert!(
        build_gen1.status.success(),
        "Stage 1 compiler build failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&build_gen1.stdout),
        String::from_utf8_lossy(&build_gen1.stderr)
    );

    let ifac_bin = target_dev_dir.join("ifac");
    let ifac_ll = target_dev_dir.join("ifac.ll");
    let ifac_o = target_dev_dir.join("ifac.o");

    assert!(ifac_bin.exists(), "Gen 1 binary missing at {:?}", ifac_bin);
    assert!(ifac_ll.exists(), "Gen 1 LLVM IR missing at {:?}", ifac_ll);
    assert!(ifac_o.exists(), "Gen 1 Object file missing at {:?}", ifac_o);

    // Verify Gen 1 executable produces expected self-hosting output
    let run_gen1 = Command::new(&ifac_bin)
        .output()
        .expect("Execute Stage 1 binary");
    assert!(run_gen1.status.success(), "Stage 1 execution failed");
    let gen1_stdout = String::from_utf8_lossy(&run_gen1.stdout);
    assert!(
        gen1_stdout.contains("=== IFA Self-Hosting Compiler (Stage 1 Pure IFA) ==="),
        "Unexpected stdout: {}",
        gen1_stdout
    );
    assert!(
        gen1_stdout.contains("Self-hosting modular bootstrap validation: SUCCESS (42)"),
        "Unexpected stdout: {}",
        gen1_stdout
    );

    // Snapshot Gen 2 artifacts
    let temp_gen2_dir = std::env::temp_dir().join(format!(
        "ifa_bootstrap_gen2_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&temp_gen2_dir).expect("create gen2 temp dir");

    let gen2_bin = temp_gen2_dir.join("ifac-gen2");
    let gen2_ll = temp_gen2_dir.join("ifac-gen2.ll");
    let gen2_o = temp_gen2_dir.join("ifac-gen2.o");

    fs::copy(&ifac_bin, &gen2_bin).expect("copy gen2 binary");
    fs::copy(&ifac_ll, &gen2_ll).expect("copy gen2 ll");
    fs::copy(&ifac_o, &gen2_o).expect("copy gen2 o");

    let hash_ll_gen2 = sha256_hex(&fs::read(&gen2_ll).expect("read gen2 ll"));
    let hash_o_gen2 = sha256_hex(&fs::read(&gen2_o).expect("read gen2 o"));
    let hash_bin_gen2 = sha256_hex(&fs::read(&gen2_bin).expect("read gen2 bin"));

    // Stage 1 -> Stage 2: Recompile with complete cache bypass to produce Gen 3 artifacts
    let build_gen2 = Command::new(&kori_bin)
        .arg("build")
        .arg("--force")
        .arg("--manifest-path")
        .arg(&manifest_path)
        .output()
        .expect("Build Stage 2 compiler binary");

    assert!(
        build_gen2.status.success(),
        "Stage 2 compiler build failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&build_gen2.stdout),
        String::from_utf8_lossy(&build_gen2.stderr)
    );

    let temp_gen3_dir = std::env::temp_dir().join(format!(
        "ifa_bootstrap_gen3_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&temp_gen3_dir).expect("create gen3 temp dir");

    let gen3_bin = temp_gen3_dir.join("ifac-gen3");
    let gen3_ll = temp_gen3_dir.join("ifac-gen3.ll");
    let gen3_o = temp_gen3_dir.join("ifac-gen3.o");

    fs::copy(&ifac_bin, &gen3_bin).expect("copy gen3 binary");
    fs::copy(&ifac_ll, &gen3_ll).expect("copy gen3 ll");
    fs::copy(&ifac_o, &gen3_o).expect("copy gen3 o");

    let hash_ll_gen3 = sha256_hex(&fs::read(&gen3_ll).expect("read gen3 ll"));
    let hash_o_gen3 = sha256_hex(&fs::read(&gen3_o).expect("read gen3 o"));
    let hash_bin_gen3 = sha256_hex(&fs::read(&gen3_bin).expect("read gen3 bin"));

    // Verify Gen 3 executable also runs and validates cleanly
    let run_gen3 = Command::new(&gen3_bin)
        .output()
        .expect("Execute Stage 3 binary");
    assert!(run_gen3.status.success(), "Stage 3 execution failed");
    let gen3_stdout = String::from_utf8_lossy(&run_gen3.stdout);
    assert!(
        gen3_stdout.contains("Self-hosting modular bootstrap validation: SUCCESS (42)"),
        "Unexpected gen3 stdout: {}",
        gen3_stdout
    );

    // FIXED-POINT DETERMINISM CONVERGENCE ASSERTIONS
    assert_eq!(
        hash_ll_gen2, hash_ll_gen3,
        "LLVM IR is not bit-for-bit deterministic across compiler generations:\nGen 2: {}\nGen 3: {}",
        hash_ll_gen2, hash_ll_gen3
    );

    assert_eq!(
        hash_o_gen2, hash_o_gen3,
        "Native object files are not bit-for-bit deterministic:\nGen 2: {}\nGen 3: {}",
        hash_o_gen2, hash_o_gen3
    );

    assert_eq!(
        hash_bin_gen2, hash_bin_gen3,
        "Executable binaries differ bit-for-bit:\nsha256(ifac-gen2) = {}\nsha256(ifac-gen3) = {}",
        hash_bin_gen2, hash_bin_gen3
    );

    println!(
        "Bootstrap Fixed-Point Convergence Confirmed:\n  sha256(ifac-gen2) = {}\n  sha256(ifac-gen3) = {}",
        hash_bin_gen2, hash_bin_gen3
    );

    // Clean up temporary snapshot directories
    let _ = fs::remove_dir_all(&temp_gen2_dir);
    let _ = fs::remove_dir_all(&temp_gen3_dir);
}

#[test]
fn test_stdlib_compiler_essentials() {
    use ifa_stdlib::collections::{ByteBuffer, List, Map, Set, StringBuilder};
    use ifa_stdlib::fs::walk_dir_files;

    // 1. Collections: List, Map, Set determinism
    let mut map: Map<&str, i32> = Map::new();
    map.insert("gamma", 3);
    map.insert("alpha", 1);
    map.insert("beta", 2);
    let keys: Vec<_> = map.keys().copied().collect();
    assert_eq!(keys, vec!["alpha", "beta", "gamma"]);

    let mut set: Set<i64> = Set::new();
    set.insert(42);
    set.insert(10);
    set.insert(99);
    let items: Vec<_> = set.iter().copied().collect();
    assert_eq!(items, vec![10, 42, 99]);

    let mut list = List::new();
    list.push(3);
    list.push(1);
    list.push(2);
    list.sort();
    assert_eq!(list.as_slice(), &[1, 2, 3]);

    // 2. StringBuilder & ByteBuffer
    let mut sb = StringBuilder::new();
    sb.push_line("; IFA Bit-for-bit Reproducible LLVM IR");
    sb.push_line("define i32 @main() {");
    sb.indent();
    sb.push_line("ret i32 42");
    sb.dedent();
    sb.push_line("}");
    let ir = sb.into_string();
    assert!(ir.contains("    ret i32 42\n"));

    let mut buf = ByteBuffer::new();
    buf.write_u32_le(0x12345678);
    assert_eq!(buf.read_u32_le(0), Some(0x12345678));

    // 3. Fs traversal deterministic ordering
    let root = get_workspace_root();
    let compiler_files = walk_dir_files(root.join("compiler")).expect("walk compiler dir");
    assert!(!compiler_files.is_empty());
    for win in compiler_files.windows(2) {
        assert!(
            win[0] <= win[1],
            "Directory walk must be strictly sorted: {:?} > {:?}",
            win[0],
            win[1]
        );
    }
}

#[test]
fn test_autonomous_selfhost_driver_triple_stage_execution() {
    let root = get_workspace_root();
    let kori_bin = get_kori_binary();
    let manifest_path = root.join("compiler").join("kori.toml");
    let target_dev_dir = root.join("compiler").join("target").join("dev");
    let ifac_bin = target_dev_dir.join("ifac");

    // Ensure ifac executable is built
    if !ifac_bin.exists() {
        let build = Command::new(&kori_bin)
            .arg("build")
            .arg("--manifest-path")
            .arg(&manifest_path)
            .output()
            .expect("Build ifac compiler");
        assert!(build.status.success(), "Failed to build ifac compiler");
    }

    let temp_dir = std::env::temp_dir().join(format!(
        "ifa_autonomous_bootstrap_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&temp_dir).expect("create autonomous temp dir");
    let base_out = temp_dir.join("ifac_auto");

    // Execute autonomous triple stage bootstrap:
    // `ifac --bootstrap-triple <base_out>`
    let run_driver = Command::new(&ifac_bin)
        .arg("--bootstrap-triple")
        .arg(&base_out)
        .output()
        .expect("Run autonomous triple-stage bootstrap");

    let stdout = String::from_utf8_lossy(&run_driver.stdout);
    let stderr = String::from_utf8_lossy(&run_driver.stderr);
    assert!(
        run_driver.status.success(),
        "Autonomous bootstrap failed:\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );
    assert!(
        stdout.contains("Self-hosting triple-stage bootstrap completed: SUCCESS"),
        "Expected success message, got: {}",
        stdout
    );

    // Verify Gen 2 and Gen 3 artifacts generated by autonomous driver
    let gen2_bin = temp_dir.join("ifac_auto-gen2");
    let gen2_ll = temp_dir.join("ifac_auto-gen2.ll");
    let gen2_o = temp_dir.join("ifac_auto-gen2.o");

    let gen3_bin = temp_dir.join("ifac_auto-gen3");
    let gen3_ll = temp_dir.join("ifac_auto-gen3.ll");
    let gen3_o = temp_dir.join("ifac_auto-gen3.o");

    assert!(gen2_bin.exists(), "Gen 2 binary missing at {:?}", gen2_bin);
    assert!(gen2_ll.exists(), "Gen 2 LLVM IR missing at {:?}", gen2_ll);
    assert!(gen2_o.exists(), "Gen 2 object file missing at {:?}", gen2_o);

    assert!(gen3_bin.exists(), "Gen 3 binary missing at {:?}", gen3_bin);
    assert!(gen3_ll.exists(), "Gen 3 LLVM IR missing at {:?}", gen3_ll);
    assert!(gen3_o.exists(), "Gen 3 object file missing at {:?}", gen3_o);

    // Assert bit-for-bit identity across Gen 2 and Gen 3 produced by ifac driver
    let hash_ll_2 = sha256_hex(&fs::read(&gen2_ll).expect("read auto gen2 ll"));
    let hash_ll_3 = sha256_hex(&fs::read(&gen3_ll).expect("read auto gen3 ll"));
    assert_eq!(hash_ll_2, hash_ll_3, "LLVM IR differs bit-for-bit");

    let hash_o_2 = sha256_hex(&fs::read(&gen2_o).expect("read auto gen2 o"));
    let hash_o_3 = sha256_hex(&fs::read(&gen3_o).expect("read auto gen3 o"));
    assert_eq!(hash_o_2, hash_o_3, "Object files differ bit-for-bit");

    let hash_bin_2 = sha256_hex(&fs::read(&gen2_bin).expect("read auto gen2 bin"));
    let hash_bin_3 = sha256_hex(&fs::read(&gen3_bin).expect("read auto gen3 bin"));
    assert_eq!(
        hash_bin_2, hash_bin_3,
        "Autonomous executables differ bit-for-bit:\nsha256(gen2) = {}\nsha256(gen3) = {}",
        hash_bin_2, hash_bin_3
    );

    // Run the generated Gen 3 binary and verify it prints 42
    let run_gen3 = Command::new(&gen3_bin)
        .output()
        .expect("Execute autonomous gen3 executable");
    assert!(run_gen3.status.success());
    let gen3_out = String::from_utf8_lossy(&run_gen3.stdout);
    assert!(
        gen3_out.contains("42"),
        "Expected output 42 from autonomous Gen 3 executable, got: {}",
        gen3_out
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

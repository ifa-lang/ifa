use std::fs;
use std::process::Command;

fn get_ifa_binary() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // remove test binary name
    if path.ends_with("deps") {
        path.pop();
    }
    path.push("ifa");
    path
}

#[test]
fn test_cli_wasm_inspect_and_bundle() {
    let temp_dir = std::env::temp_dir().join(format!("ifa_cli_wasm_test_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    // Construct minimal valid WebAssembly binary with export section
    let mut wasm_bytes = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
    let export_payload = [
        0x01, // 1 export
        0x03, b'a', b'd', b'd', // name "add"
        0x00, // kind: func
        0x00, // func idx: 0
    ];
    wasm_bytes.push(0x07); // section id 7 (Export)
    wasm_bytes.push(export_payload.len() as u8);
    wasm_bytes.extend_from_slice(&export_payload);

    let wasm_file = temp_dir.join("test_math.wasm");
    fs::write(&wasm_file, &wasm_bytes).unwrap();

    let ifa_bin = get_ifa_binary();

    // 1. Test `ifa wasm inspect`
    let inspect_status = Command::new(&ifa_bin)
        .arg("wasm")
        .arg("inspect")
        .arg(&wasm_file)
        .status();

    if let Ok(status) = inspect_status {
        assert!(status.success(), "ifa wasm inspect failed");
    }

    // 2. Test `ifa wasm bundle`
    let dist_dir = temp_dir.join("dist");
    let bundle_status = Command::new(&ifa_bin)
        .arg("wasm")
        .arg("bundle")
        .arg("test_math")
        .arg(&wasm_file)
        .arg("--out-dir")
        .arg(&dist_dir)
        .status();

    if let Ok(status) = bundle_status {
        assert!(status.success(), "ifa wasm bundle failed");
        assert!(dist_dir.join("test_math.wasm").exists());
        assert!(dist_dir.join("index.js").exists());
        assert!(dist_dir.join("index.d.ts").exists());
        assert!(dist_dir.join("package.json").exists());
    }

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_lsp_stdio_handshake() {
    use std::io::{BufRead, BufReader, Write};
    use std::process::Stdio;

    let ifa_bin = get_ifa_binary();
    let mut child = Command::new(&ifa_bin)
        .arg("lsp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to spawn `ifa lsp` process");

    let init_payload = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
    let request = format!(
        "Content-Length: {}\r\n\r\n{}",
        init_payload.len(),
        init_payload
    );

    {
        let stdin = child.stdin.as_mut().expect("Failed to open child stdin");
        stdin
            .write_all(request.as_bytes())
            .expect("Failed to write to LSP stdin");
        stdin.flush().expect("Failed to flush LSP stdin");
    }

    let stdout = child.stdout.take().expect("Failed to open child stdout");
    let mut reader = BufReader::new(stdout);

    // Read Content-Length header
    let mut header_line = String::new();
    reader
        .read_line(&mut header_line)
        .expect("Failed to read LSP header");
    assert!(header_line.starts_with("Content-Length:"));

    let parts: Vec<&str> = header_line.trim().split(':').collect();
    let content_len: usize = parts[1].trim().parse().expect("Invalid Content-Length");

    // Read blank delimiter line
    let mut blank_line = String::new();
    reader
        .read_line(&mut blank_line)
        .expect("Failed to read header delimiter");

    // Read JSON-RPC response body
    let mut body_bytes = vec![0u8; content_len];
    std::io::Read::read_exact(&mut reader, &mut body_bytes).expect("Failed to read LSP body");
    let body_str = String::from_utf8(body_bytes).expect("Invalid UTF-8 in response");

    let resp_val: serde_json::Value =
        serde_json::from_str(&body_str).expect("Failed to parse JSON response");
    assert_eq!(resp_val["id"], 1);
    assert_eq!(resp_val["result"]["serverInfo"]["name"], "ifa-lsp");
    assert_eq!(resp_val["result"]["capabilities"]["textDocumentSync"], 1);

    // Terminate LSP child
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn test_cli_project_lifecycle_new_fmt_lint_test() {
    let ifa_bin = get_ifa_binary();
    let temp_dir = std::env::temp_dir().join(format!("ifa_cli_proj_test_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    // 1. Test `ifa new`
    let new_output = Command::new(&ifa_bin)
        .arg("new")
        .arg("sample_app")
        .current_dir(&temp_dir)
        .output()
        .expect("Failed to execute `ifa new`");
    assert!(new_output.status.success(), "ifa new failed");

    let app_dir = temp_dir.join("sample_app");
    assert!(app_dir.join("kori.toml").exists(), "kori.toml must exist");
    let main_file = app_dir.join("src/main.ifa");
    assert!(main_file.exists(), "src/main.ifa must exist");

    // 2. Test `ifa fmt` and `ifa fmt --check`
    let fmt_status = Command::new(&ifa_bin)
        .arg("fmt")
        .arg(&main_file)
        .status()
        .expect("Failed to execute `ifa fmt`");
    assert!(fmt_status.success(), "ifa fmt failed");

    let fmt_check_status = Command::new(&ifa_bin)
        .arg("fmt")
        .arg("--check")
        .arg(&main_file)
        .status()
        .expect("Failed to execute `ifa fmt --check`");
    assert!(fmt_check_status.success(), "ifa fmt --check failed");

    // 3. Test `ifa lint`
    let lint_output = Command::new(&ifa_bin)
        .arg("lint")
        .arg(&main_file)
        .output()
        .expect("Failed to execute `ifa lint`");
    assert!(lint_output.status.success(), "ifa lint failed");
    let lint_str = String::from_utf8_lossy(&lint_output.stdout);
    assert!(lint_str.contains("Lint passed"));

    // 4. Test `ifa test`
    let test_output = Command::new(&ifa_bin)
        .arg("test")
        .arg(&main_file)
        .output()
        .expect("Failed to execute `ifa test`");
    assert!(test_output.status.success(), "ifa test failed");
    let test_str = String::from_utf8_lossy(&test_output.stdout);
    assert!(test_str.contains("Test result:"));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_run_interp_and_native() {
    let ifa_bin = get_ifa_binary();
    let temp_dir = std::env::temp_dir().join(format!("ifa_cli_run_test_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let script_path = temp_dir.join("run_sample.ifa");
    let code = r#"
pub fn main() -> () {
    println("IFA_RUN_DETERMINISTIC_SUCCESS")
}
"#;
    fs::write(&script_path, code).unwrap();

    // 1. Run with internal FIR Interpreter
    let interp_output = Command::new(&ifa_bin)
        .arg("run")
        .arg(&script_path)
        .output()
        .expect("Failed to execute `ifa run`");
    assert!(interp_output.status.success());
    let interp_str = String::from_utf8_lossy(&interp_output.stdout);
    assert!(interp_str.contains("IFA_RUN_DETERMINISTIC_SUCCESS"));

    // 2. Run with Cranelift JIT engine
    let native_output = Command::new(&ifa_bin)
        .arg("run")
        .arg("--native")
        .arg(&script_path)
        .output()
        .expect("Failed to execute `ifa run --native`");
    assert!(native_output.status.success());
    let native_str = String::from_utf8_lossy(&native_output.stdout);
    assert!(native_str.contains("IFA_RUN_DETERMINISTIC_SUCCESS"));
    assert!(native_str.contains("Program finished with native exit code: 0"));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_build_binary_object_and_wasm() {
    let ifa_bin = get_ifa_binary();
    let temp_dir = std::env::temp_dir().join(format!("ifa_cli_build_test_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let src_file = temp_dir.join("build_target.ifa");
    let code = r#"
pub fn add(a: i64, b: i64) -> i64 {
    return a + b
}

pub fn main() -> () {
    let res = add(20, 22)
    println("IFA_BUILD_BIN_SUCCESS")
}
"#;
    fs::write(&src_file, code).unwrap();

    // 1. Build standalone executable
    let out_bin = temp_dir.join("test_exec");
    let build_bin_status = Command::new(&ifa_bin)
        .arg("build")
        .arg(&src_file)
        .arg("-o")
        .arg(&out_bin)
        .status()
        .expect("Failed to execute `ifa build`");
    assert!(build_bin_status.success(), "ifa build executable failed");
    assert!(out_bin.exists(), "Executable file must exist");

    let run_bin = Command::new(&out_bin)
        .output()
        .expect("Failed to run built binary");
    assert!(run_bin.status.success());
    let bin_str = String::from_utf8_lossy(&run_bin.stdout);
    assert!(bin_str.contains("IFA_BUILD_BIN_SUCCESS"));

    // 2. Build native object file
    let out_obj = temp_dir.join("test_obj.o");
    let build_obj_status = Command::new(&ifa_bin)
        .arg("build")
        .arg("--emit-obj")
        .arg(&src_file)
        .arg("-o")
        .arg(&out_obj)
        .status()
        .expect("Failed to execute `ifa build --emit-obj`");
    assert!(build_obj_status.success(), "ifa build --emit-obj failed");
    assert!(out_obj.exists(), "Object file must exist");

    // 3. Build WebAssembly WASI module
    let out_wasm = temp_dir.join("test_mod.wasm");
    let build_wasm_status = Command::new(&ifa_bin)
        .arg("build")
        .arg("--target")
        .arg("wasm32-wasi")
        .arg(&src_file)
        .arg("-o")
        .arg(&out_wasm)
        .status()
        .expect("Failed to execute `ifa build --target wasm32-wasi`");
    assert!(
        build_wasm_status.success(),
        "ifa build --target wasm32-wasi failed"
    );
    assert!(out_wasm.exists(), "Wasm module must exist");

    // Inspect compiled WebAssembly module
    let inspect_output = Command::new(&ifa_bin)
        .arg("wasm")
        .arg("inspect")
        .arg(&out_wasm)
        .output()
        .expect("Failed to execute `ifa wasm inspect`");
    assert!(inspect_output.status.success());
    let inspect_str = String::from_utf8_lossy(&inspect_output.stdout);
    assert!(inspect_str.contains("WebAssembly Module:"));
    assert!(inspect_str.contains("Exports"));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_benchmarks_and_contention() {
    let ifa_bin = get_ifa_binary();

    // 1. Generational safety microbenchmark
    let bench_output = Command::new(&ifa_bin)
        .arg("bench")
        .arg("--iterations")
        .arg("1000")
        .output()
        .expect("Failed to execute `ifa bench`");
    assert!(bench_output.status.success());
    let bench_str = String::from_utf8_lossy(&bench_output.stdout);
    assert!(bench_str.contains("IFA MEMORY MODEL BENCHMARK RESULTS"));
    assert!(bench_str.contains("Use-After-Free Interception Guarantee"));

    // 2. Multithread allocator contention benchmark
    let multithread_output = Command::new(&ifa_bin)
        .arg("bench")
        .arg("--multithread")
        .arg("--threads")
        .arg("2")
        .arg("--iterations")
        .arg("1000")
        .output()
        .expect("Failed to execute `ifa bench --multithread`");
    assert!(multithread_output.status.success());
    let multi_str = String::from_utf8_lossy(&multithread_output.stdout);
    assert!(multi_str.contains("IFA MULTITHREAD ALLOCATOR BENCHMARK"));
    assert!(multi_str.contains("Performance Comparison Ratios"));
}

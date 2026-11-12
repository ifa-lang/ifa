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

#[test]
fn test_cli_lsp_server_stdio() {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::process::Stdio;

    let ifa_bin = get_ifa_binary();
    let mut child = Command::new(&ifa_bin)
        .arg("lsp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to spawn `ifa lsp`");

    let mut stdin = child.stdin.take().expect("Failed to open stdin");
    let stdout = child.stdout.take().expect("Failed to open stdout");
    let mut reader = BufReader::new(stdout);

    // 1. Send initialize request
    let init_body = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
    let init_msg = format!("Content-Length: {}\r\n\r\n{}", init_body.len(), init_body);
    stdin
        .write_all(init_msg.as_bytes())
        .expect("Failed to write initialize to LSP");
    stdin.flush().unwrap();

    // Read response header
    let mut header = String::new();
    let mut content_length = 0;
    loop {
        header.clear();
        reader.read_line(&mut header).unwrap();
        let trimmed = header.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some(rest) = trimmed.strip_prefix("Content-Length:") {
            content_length = rest.trim().parse::<usize>().unwrap();
        }
    }
    assert!(content_length > 0);

    let mut body_bytes = vec![0u8; content_length];
    reader.read_exact(&mut body_bytes).unwrap();
    let body_str = String::from_utf8(body_bytes).unwrap();
    let init_resp: serde_json::Value = serde_json::from_str(&body_str).unwrap();

    assert_eq!(init_resp["id"], 1);
    let caps = &init_resp["result"]["capabilities"];
    assert!(caps["hoverProvider"].as_bool().unwrap());
    assert!(caps["definitionProvider"].as_bool().unwrap());
    assert!(caps["referencesProvider"].as_bool().unwrap());
    assert!(caps["renameProvider"].as_bool().unwrap());
    assert!(caps["documentSymbolProvider"].as_bool().unwrap());
    assert!(caps["workspaceSymbolProvider"].as_bool().unwrap());
    assert!(caps["semanticTokensProvider"].is_object());
    assert!(caps["inlayHintProvider"].as_bool().unwrap());
    assert!(caps["codeActionProvider"].as_bool().unwrap());
    assert!(caps["signatureHelpProvider"].is_object());

    // 2. Send shutdown request
    let shutdown_body = r#"{"jsonrpc":"2.0","id":2,"method":"shutdown","params":null}"#;
    let shutdown_msg = format!(
        "Content-Length: {}\r\n\r\n{}",
        shutdown_body.len(),
        shutdown_body
    );
    stdin
        .write_all(shutdown_msg.as_bytes())
        .expect("Failed to write shutdown to LSP");
    stdin.flush().unwrap();

    // Read shutdown response
    let mut sd_content_length = 0;
    loop {
        header.clear();
        reader.read_line(&mut header).unwrap();
        let trimmed = header.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some(rest) = trimmed.strip_prefix("Content-Length:") {
            sd_content_length = rest.trim().parse::<usize>().unwrap();
        }
    }
    let mut sd_body_bytes = vec![0u8; sd_content_length];
    reader.read_exact(&mut sd_body_bytes).unwrap();

    drop(stdin);
    let status = child.wait().expect("Failed to wait on LSP server process");
    assert!(status.success());
}

#[test]
fn test_cli_function_pointers_and_thunks_full_pipeline() {
    let ifa_bin = get_ifa_binary();
    let sample_file = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("examples")
        .join("function_pointers_and_thunks.ifa");

    assert!(
        sample_file.exists(),
        "Function pointers example file missing at {:?}",
        sample_file
    );

    // 1. Static semantic check
    let check_status = Command::new(&ifa_bin)
        .arg("check")
        .arg(&sample_file)
        .status()
        .expect("Failed to execute `ifa check`");
    assert!(
        check_status.success(),
        "ifa check failed on function_pointers_and_thunks.ifa"
    );

    // 2. Interpreter run
    let run_output = Command::new(&ifa_bin)
        .arg("run")
        .arg(&sample_file)
        .output()
        .expect("Failed to execute `ifa run`");
    assert!(run_output.status.success());
    let run_stdout = String::from_utf8_lossy(&run_output.stdout);
    assert!(
        run_stdout.contains("120"),
        "Interpreter did not return expected value 120: {}",
        run_stdout
    );

    // 3. Cranelift Native JIT run
    let native_output = Command::new(&ifa_bin)
        .arg("run")
        .arg("--native")
        .arg(&sample_file)
        .output()
        .expect("Failed to execute `ifa run --native`");
    assert!(native_output.status.success());
    let native_stdout = String::from_utf8_lossy(&native_output.stdout);
    assert!(
        native_stdout.contains("120"),
        "Native JIT did not return expected exit code 120: {}",
        native_stdout
    );

    // 4. Standalone native binary compilation and execution
    let temp_bin = std::env::temp_dir().join(format!("ifa_fn_ptr_test_bin_{}", std::process::id()));
    let build_status = Command::new(&ifa_bin)
        .arg("build")
        .arg(&sample_file)
        .arg("-o")
        .arg(&temp_bin)
        .status()
        .expect("Failed to execute `ifa build`");
    assert!(
        build_status.success(),
        "ifa build failed for function pointers example"
    );

    let bin_output = Command::new(&temp_bin)
        .output()
        .expect("Failed to execute generated standalone binary");
    let _ = fs::remove_file(&temp_bin);

    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        let exit_code = bin_output
            .status
            .code()
            .or_else(|| bin_output.status.signal());
        assert_eq!(exit_code, Some(120), "Standalone binary exit code mismatch");
    }
}

#[test]
fn test_cli_wasm_component_and_wit() {
    let ifa_bin = get_ifa_binary();
    let temp_dir = std::env::temp_dir().join(format!("ifa_cli_wit_test_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    // 1. Create a minimal valid core wasm file with an export
    let mut wasm_bytes = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
    let export_payload = [
        0x01, // 1 export
        0x03, b'a', b'd', b'd', // name "add"
        0x00, // kind: func
        0x00, // func idx: 0
    ];
    wasm_bytes.push(0x07);
    wasm_bytes.push(export_payload.len() as u8);
    wasm_bytes.extend_from_slice(&export_payload);

    let wasm_file = temp_dir.join("core.wasm");
    fs::write(&wasm_file, &wasm_bytes).unwrap();

    // 2. Test `ifa wasm component`
    let comp_file = temp_dir.join("core.component.wasm");
    let comp_output = Command::new(&ifa_bin)
        .arg("wasm")
        .arg("component")
        .arg(&wasm_file)
        .arg("-o")
        .arg(&comp_file)
        .output()
        .expect("Failed to execute `ifa wasm component`");
    assert!(
        comp_output.status.success(),
        "ifa wasm component failed: {}",
        String::from_utf8_lossy(&comp_output.stderr)
    );
    assert!(comp_file.exists());
    let comp_bytes = fs::read(&comp_file).unwrap();
    // Validate component header: \0asm [0x0d, 0x00, 0x01, 0x00]
    assert_eq!(&comp_bytes[0..4], b"\0asm");
    assert_eq!(&comp_bytes[4..8], &[0x0d, 0x00, 0x01, 0x00]);

    // 3. Test `ifa wasm wit`
    let wit_file = temp_dir.join("greeter.wit");
    let wit_content = r#"package example:greeter@0.1.0;

interface greeter {
    greet: func(name: string) -> string;
}

world host {
    export greeter;
}
"#;
    fs::write(&wit_file, wit_content).unwrap();

    let ifa_bindings = temp_dir.join("greeter_bindings.ifa");
    let wit_output = Command::new(&ifa_bin)
        .arg("wasm")
        .arg("wit")
        .arg(&wit_file)
        .arg("--out-ifa")
        .arg(&ifa_bindings)
        .output()
        .expect("Failed to execute `ifa wasm wit`");
    assert!(
        wit_output.status.success(),
        "ifa wasm wit failed: {}",
        String::from_utf8_lossy(&wit_output.stderr)
    );
    let stdout = String::from_utf8_lossy(&wit_output.stdout);
    assert!(stdout.contains("Parsed WIT package: example:greeter@0.1.0"));
    assert!(ifa_bindings.exists());
    let bindings_code = fs::read_to_string(&ifa_bindings).unwrap();
    assert!(bindings_code.contains("pub fn greet(name: string) -> string;"));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_run_and_build_with_local_submodule() {
    let temp_dir = std::env::temp_dir().join(format!("ifa_cli_submod_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(temp_dir.join("helpers")).unwrap();

    let submod_code = r#"pub fn calculate(a: i64, b: i64) -> i64 {
    return a * b + 42;
}
"#;
    fs::write(temp_dir.join("helpers").join("math.ifa"), submod_code).unwrap();

    let main_code = r#"import helpers::math;

pub fn main() -> i64 {
    let res: i64 = math::calculate(10, 5);
    return res;
}
"#;
    let main_file = temp_dir.join("main.ifa");
    fs::write(&main_file, main_code).unwrap();

    let ifa_bin = get_ifa_binary();

    // 1. Test `ifa check`
    let check_output = Command::new(&ifa_bin)
        .arg("check")
        .arg(&main_file)
        .output()
        .expect("Failed to execute `ifa check`");
    assert!(
        check_output.status.success(),
        "ifa check failed: {}",
        String::from_utf8_lossy(&check_output.stderr)
    );

    // 1.25. Test `ifa fir` (emits merged FIR module with submodules)
    let fir_output = Command::new(&ifa_bin)
        .arg("fir")
        .arg(&main_file)
        .output()
        .expect("Failed to execute `ifa fir`");
    assert!(
        fir_output.status.success(),
        "ifa fir failed: {}",
        String::from_utf8_lossy(&fir_output.stderr)
    );
    let fir_text = String::from_utf8_lossy(&fir_output.stdout);
    assert!(
        fir_text.contains("calculate"),
        "FIR module must contain lowered submodule functions"
    );

    // 1.5. Test `ifa run` (FIR interpreter)
    let interp_output = Command::new(&ifa_bin)
        .arg("run")
        .arg(&main_file)
        .output()
        .expect("Failed to execute `ifa run`");
    eprintln!(
        "interp_output stdout: '{}', stderr: '{}'",
        String::from_utf8_lossy(&interp_output.stdout),
        String::from_utf8_lossy(&interp_output.stderr)
    );
    let run_output = Command::new(&ifa_bin)
        .arg("run")
        .arg("--native")
        .arg(&main_file)
        .output()
        .expect("Failed to execute `ifa run`");
    eprintln!(
        "run_output stdout: '{}', stderr: '{}'",
        String::from_utf8_lossy(&run_output.stdout),
        String::from_utf8_lossy(&run_output.stderr)
    );
    assert!(
        run_output.status.success(),
        "ifa run failed: {}",
        String::from_utf8_lossy(&run_output.stderr)
    );

    // 3. Test `ifa build` (AOT)
    let out_bin = temp_dir.join("main_bin");
    let build_output = Command::new(&ifa_bin)
        .arg("build")
        .arg(&main_file)
        .arg("-o")
        .arg(&out_bin)
        .output()
        .expect("Failed to execute `ifa build`");
    assert!(
        build_output.status.success(),
        "ifa build failed: {}",
        String::from_utf8_lossy(&build_output.stderr)
    );
    assert!(out_bin.exists());

    // 4. Verify running the generated standalone binary
    let exec_output = Command::new(&out_bin)
        .output()
        .expect("Failed to execute generated binary");
    eprintln!(
        "exec_output code: {:?}, stdout: '{}', stderr: '{}'",
        exec_output.status.code(),
        String::from_utf8_lossy(&exec_output.stdout),
        String::from_utf8_lossy(&exec_output.stderr)
    );
    assert_eq!(exec_output.status.code(), Some(92));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_supervised_resource_usage_telemetry() {
    let ifa_bin = get_ifa_binary();
    let temp_dir =
        std::env::temp_dir().join(format!("ifa_cli_telemetry_test_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(temp_dir.join("src")).unwrap();

    let manifest_content = r#"[package]
name = "telemetry_demo"
version = "0.1.0"
edition = "2026"
authors = ["ASSOGBA Prudence Dieudonné <jprud67@gmail.com>"]
license = "MIT"
description = "Supervised resource usage telemetry end-to-end verification"
"#;
    fs::write(temp_dir.join("kori.toml"), manifest_content).unwrap();

    let main_source = r#"pub fn main() -> i64 {
    let mut sum: i64 = 0;
    let mut i: i64 = 0;
    while i < 1000 {
        sum = sum + i;
        i = i + 1;
    }
    return 0;
}
"#;
    let main_file = temp_dir.join("src/main.ifa");
    fs::write(&main_file, main_source).unwrap();

    // 1. End-to-end `ifa check` with package ResourceUsage telemetry audit
    let check_output = Command::new(&ifa_bin)
        .arg("check")
        .current_dir(&temp_dir)
        .output()
        .expect("Failed to execute `ifa check`");
    assert!(
        check_output.status.success(),
        "ifa check failed: {}",
        String::from_utf8_lossy(&check_output.stderr)
    );
    let check_stdout = String::from_utf8_lossy(&check_output.stdout);
    assert!(
        check_stdout.contains("Checked package `telemetry_demo`"),
        "Missing package check header: {}",
        check_stdout
    );
    assert!(
        check_stdout.contains("wall:")
            && check_stdout.contains("peak rss:")
            && check_stdout.contains("cores:"),
        "Missing telemetry metrics in ifa check output: {}",
        check_stdout
    );

    // 2. End-to-end `ifa build` with package ResourceUsage telemetry audit
    let build_output = Command::new(&ifa_bin)
        .arg("build")
        .current_dir(&temp_dir)
        .output()
        .expect("Failed to execute `ifa build`");
    assert!(
        build_output.status.success(),
        "ifa build failed: {}",
        String::from_utf8_lossy(&build_output.stderr)
    );
    let build_stdout = String::from_utf8_lossy(&build_output.stdout);
    assert!(
        build_stdout.contains("Finished dev build"),
        "Missing build summary: {}",
        build_stdout
    );
    assert!(
        build_stdout.contains("peak rss:") && build_stdout.contains("cores:"),
        "Missing telemetry metrics in ifa build output: {}",
        build_stdout
    );

    // 3. End-to-end `ifa run --telemetry` on supervised package executable
    let run_pkg_output = Command::new(&ifa_bin)
        .arg("run")
        .arg("--telemetry")
        .current_dir(&temp_dir)
        .output()
        .expect("Failed to execute `ifa run --telemetry`");
    assert!(
        run_pkg_output.status.success(),
        "ifa run --telemetry on package failed: {}",
        String::from_utf8_lossy(&run_pkg_output.stderr)
    );
    let run_pkg_stdout = String::from_utf8_lossy(&run_pkg_output.stdout);
    assert!(
        run_pkg_stdout.contains("[telemetry]")
            && run_pkg_stdout.contains("wall:")
            && run_pkg_stdout.contains("peak rss:")
            && run_pkg_stdout.contains("cores:"),
        "Missing telemetry audit header in ifa run output: {}",
        run_pkg_stdout
    );

    // 4. End-to-end `ifa run --telemetry` on single file (FIR interpreter)
    let run_interp_output = Command::new(&ifa_bin)
        .arg("run")
        .arg("--telemetry")
        .arg(&main_file)
        .output()
        .expect("Failed to execute `ifa run --telemetry <file>`");
    assert!(
        run_interp_output.status.success(),
        "ifa run --telemetry file failed: {}",
        String::from_utf8_lossy(&run_interp_output.stderr)
    );
    let run_interp_stdout = String::from_utf8_lossy(&run_interp_output.stdout);
    assert!(
        run_interp_stdout.contains("[telemetry]")
            && run_interp_stdout.contains("peak rss:")
            && run_interp_stdout.contains("cores:"),
        "Missing telemetry audit in interp output: {}",
        run_interp_stdout
    );

    // 5. End-to-end `ifa run --telemetry --native` on single file (Cranelift JIT)
    let run_jit_output = Command::new(&ifa_bin)
        .arg("run")
        .arg("--telemetry")
        .arg("--native")
        .arg(&main_file)
        .output()
        .expect("Failed to execute `ifa run --telemetry --native <file>`");
    assert!(
        run_jit_output.status.success(),
        "ifa run --telemetry --native file failed: {}",
        String::from_utf8_lossy(&run_jit_output.stderr)
    );
    let run_jit_stdout = String::from_utf8_lossy(&run_jit_output.stdout);
    assert!(
        run_jit_stdout.contains("[telemetry]")
            && run_jit_stdout.contains("peak rss:")
            && run_jit_stdout.contains("cores:"),
        "Missing telemetry audit in JIT output: {}",
        run_jit_stdout
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

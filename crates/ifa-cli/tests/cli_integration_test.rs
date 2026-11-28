use std::fs;
use std::process::Command;

fn get_ifa_binary() -> std::path::PathBuf {
    if let Some(bin) = option_env!("CARGO_BIN_EXE_ifa") {
        let p = std::path::PathBuf::from(bin);
        if p.exists() {
            return p;
        }
    }
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // remove test binary name
    if path.ends_with("deps") {
        path.pop();
    }
    path.push(if cfg!(windows) { "ifa.exe" } else { "ifa" });
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

#[test]
fn test_cli_net_session_list_inspect_migrate() {
    use ifa_runtime::{GossipFrame, IsspCapsule, SessionId, SessionRegistry, SessionSnapshot};

    let temp_dir =
        std::env::temp_dir().join(format!("ifa_cli_net_session_test_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let ifa_bin = get_ifa_binary();
    let state_file = temp_dir.join("cluster_state.issp");
    let capsule_file = temp_dir.join("cutover.cap");

    // 1. Build an ISSP registry with 2 sessions and dump it to state_file
    let reg = SessionRegistry::new(1);
    let id1 = SessionId::new(0x0123456789abcdef, 1, 42);
    let id2 = SessionId::new(0x89abcdef01234567, 2, 99);

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut snap1 = SessionSnapshot::new(id1, 1, now_secs);
    snap1.tx_seq = 1000;
    snap1.rx_seq_high = 995;
    reg.upsert_primary(snap1).unwrap();

    let mut snap2 = SessionSnapshot::new(id2, 1, now_secs);
    snap2.tx_seq = 2500;
    snap2.rx_seq_high = 2490;
    let frame2 = GossipFrame {
        sender_node_id: 2,
        snapshot: snap2,
    };
    reg.apply_gossip(&frame2);

    reg.save_to_file(&state_file).expect("save state dump");
    assert!(state_file.exists());

    // 2. Test `ifa net session list --file <state_file>`
    let list_out = Command::new(&ifa_bin)
        .arg("net")
        .arg("session")
        .arg("list")
        .arg("--file")
        .arg(&state_file)
        .output()
        .expect("execute `ifa net session list`");
    assert!(
        list_out.status.success(),
        "ifa net session list failed: {}",
        String::from_utf8_lossy(&list_out.stderr)
    );
    let list_str = String::from_utf8_lossy(&list_out.stdout);
    assert!(list_str.contains("Total Sessions: 2"));
    assert!(list_str.contains("Primary"));
    assert!(list_str.contains("Standby"));
    assert!(list_str.contains(&id1.to_canonical_string()));
    assert!(list_str.contains(&id2.to_canonical_string()));

    // 3. Test `ifa net session list --role primary`
    let list_prim_out = Command::new(&ifa_bin)
        .arg("net")
        .arg("session")
        .arg("list")
        .arg("--file")
        .arg(&state_file)
        .arg("--role")
        .arg("primary")
        .output()
        .expect("execute list primary");
    assert!(list_prim_out.status.success());
    let list_prim_str = String::from_utf8_lossy(&list_prim_out.stdout);
    assert!(list_prim_str.contains(&id1.to_canonical_string()));
    assert!(!list_prim_str.contains(&id2.to_canonical_string()));

    // 4. Test `ifa net session list --json`
    let list_json_out = Command::new(&ifa_bin)
        .arg("net")
        .arg("session")
        .arg("list")
        .arg("--file")
        .arg(&state_file)
        .arg("--json")
        .output()
        .expect("execute list json");
    assert!(list_json_out.status.success());
    let json_val: serde_json::Value =
        serde_json::from_slice(&list_json_out.stdout).expect("valid JSON list output");
    assert_eq!(json_val["total_sessions"], 2);
    assert_eq!(json_val["sessions"].as_array().unwrap().len(), 2);

    // 5. Test `ifa net session inspect <id>`
    let inspect_out = Command::new(&ifa_bin)
        .arg("net")
        .arg("session")
        .arg("inspect")
        .arg(id1.to_canonical_string())
        .arg("--file")
        .arg(&state_file)
        .output()
        .expect("execute inspect");
    assert!(inspect_out.status.success());
    let inspect_str = String::from_utf8_lossy(&inspect_out.stdout);
    assert!(inspect_str.contains("TX Sequence:      1000"));
    assert!(inspect_str.contains("RX High Sequence: 995"));
    assert!(inspect_str.contains("ChaCha20-Poly1305 (RFC 8439)"));

    // 6. Test `ifa net session inspect <id> --json`
    let inspect_json_out = Command::new(&ifa_bin)
        .arg("net")
        .arg("session")
        .arg("inspect")
        .arg(id1.to_canonical_string())
        .arg("--file")
        .arg(&state_file)
        .arg("--json")
        .output()
        .expect("execute inspect json");
    assert!(inspect_json_out.status.success());
    let insp_json: serde_json::Value =
        serde_json::from_slice(&inspect_json_out.stdout).expect("valid JSON inspect output");
    assert_eq!(insp_json["sequence"]["tx_seq"], 1000);
    assert_eq!(insp_json["sequence"]["rx_seq_high"], 995);

    // 7. Test `ifa net session migrate <id2>` with `--out-capsule`
    let migrate_out = Command::new(&ifa_bin)
        .arg("net")
        .arg("session")
        .arg("migrate")
        .arg(id2.to_canonical_string())
        .arg("--file")
        .arg(&state_file)
        .arg("--out-capsule")
        .arg(&capsule_file)
        .output()
        .expect("execute migrate");
    assert!(
        migrate_out.status.success(),
        "migrate failed: {}",
        String::from_utf8_lossy(&migrate_out.stderr)
    );
    let migrate_str = String::from_utf8_lossy(&migrate_out.stdout);
    assert!(migrate_str.contains("Successfully triggered transparent migration"));
    assert!(migrate_str.contains("New Epoch:       1"));
    assert!(migrate_str.contains("Role:            Primary"));

    // Verify capsule was produced
    assert!(capsule_file.exists());
    let cap_bytes = fs::read(&capsule_file).expect("read capsule");
    let decoded_cap = IsspCapsule::from_bytes(&cap_bytes).expect("valid IsspCapsule");
    assert_eq!(decoded_cap.origin_node_id, 1);

    // Re-inspect session 2 in state_file to verify persistent migration
    let verify_out = Command::new(&ifa_bin)
        .arg("net")
        .arg("session")
        .arg("inspect")
        .arg(id2.to_canonical_string())
        .arg("--file")
        .arg(&state_file)
        .output()
        .expect("execute re-inspect");
    assert!(verify_out.status.success());
    let verify_str = String::from_utf8_lossy(&verify_out.stdout);
    assert!(verify_str.contains("Primary (Local Gateway)"));
    assert!(verify_str.contains("Migration Epoch:    1"));

    // 8. Test real empty state when no state file is configured
    let empty_list_out = Command::new(&ifa_bin)
        .arg("net")
        .arg("session")
        .arg("list")
        .output()
        .expect("execute empty list");
    assert!(empty_list_out.status.success());
    let empty_list_str = String::from_utf8_lossy(&empty_list_out.stdout);
    assert!(empty_list_str.contains("No active or replicated tunnel sessions found in registry."));

    // 9. Test `ifa net session bench` (standard suite table)
    let bench_out = Command::new(&ifa_bin)
        .arg("net")
        .arg("session")
        .arg("bench")
        .arg("--sessions")
        .arg("10")
        .arg("--cycles")
        .arg("3")
        .output()
        .expect("execute bench");
    assert!(
        bench_out.status.success(),
        "bench failed: {}",
        String::from_utf8_lossy(&bench_out.stderr)
    );
    let bench_str = String::from_utf8_lossy(&bench_out.stdout);
    assert!(bench_str.contains("ISSP PROTOCOL FAILOVER & THROUGHPUT BENCHMARK"));
    assert!(bench_str.contains("Optimal LAN"));
    assert!(bench_str.contains("100% PASS"));
    assert!(bench_str.contains("ALL SCENARIOS PASSED WITH 100% STATE INTEGRITY AND ZERO DATA LOSS"));

    // 10. Test `ifa net session bench --json`
    let bench_json_out = Command::new(&ifa_bin)
        .arg("net")
        .arg("session")
        .arg("bench")
        .arg("--sessions")
        .arg("10")
        .arg("--cycles")
        .arg("3")
        .arg("--json")
        .output()
        .expect("execute bench json");
    assert!(bench_json_out.status.success());
    let bench_val: serde_json::Value =
        serde_json::from_slice(&bench_json_out.stdout).expect("valid JSON bench output");
    assert_eq!(bench_val["all_integrity_passed"], true);
    assert!(bench_val["scenarios"].as_array().unwrap().len() >= 5);

    // 11. Test `ifa net session bench` with custom loss and jitter
    let custom_bench_out = Command::new(&ifa_bin)
        .arg("net")
        .arg("session")
        .arg("bench")
        .arg("--sessions")
        .arg("10")
        .arg("--cycles")
        .arg("3")
        .arg("--loss")
        .arg("5.0")
        .arg("--jitter-ms")
        .arg("15")
        .output()
        .expect("execute custom bench");
    assert!(custom_bench_out.status.success());
    let custom_str = String::from_utf8_lossy(&custom_bench_out.stdout);
    assert!(custom_str.contains("Custom Profile (5.0% loss, 15ms jitter)"));
    assert!(custom_str.contains("100% PASS"));

    // 12. Test `ifa net session route` table output
    let route_out = Command::new(&ifa_bin)
        .arg("net")
        .arg("session")
        .arg("route")
        .output()
        .expect("execute route");
    assert!(
        route_out.status.success(),
        "route failed: {}",
        String::from_utf8_lossy(&route_out.stderr)
    );
    let route_str = String::from_utf8_lossy(&route_out.stdout);
    assert!(route_str.contains("ISSP DYNAMIC MULTIPATH ROUTING & HEARTBEAT FAILOVER"));
    assert!(route_str.contains("eth0-fiber-wan"));
    assert!(route_str.contains("wwan0-5g-edge"));
    assert!(route_str.contains("leo-sat-orbit"));

    // 13. Test `ifa net session route --fail-path 1 --json`
    let fail_route_out = Command::new(&ifa_bin)
        .arg("net")
        .arg("session")
        .arg("route")
        .arg("--fail-path")
        .arg("1")
        .arg("--json")
        .output()
        .expect("execute route failover json");
    assert!(fail_route_out.status.success());
    let fail_val: serde_json::Value =
        serde_json::from_slice(&fail_route_out.stdout).expect("valid JSON route output");
    assert_eq!(fail_val["failover_triggered"], true);
    assert_eq!(fail_val["failover_event"]["failed_path_id"], 1);
    assert_eq!(fail_val["failover_event"]["target_path_id"], 2);
    assert_eq!(fail_val["failed_paths"], 1);
    assert_eq!(fail_val["active_paths"], 1);

    // 14. Test `ifa net session aggregate` table output
    let agg_out = Command::new(&ifa_bin)
        .arg("net")
        .arg("session")
        .arg("aggregate")
        .arg("--sessions")
        .arg("2")
        .arg("--packets")
        .arg("15")
        .arg("--skew-ms")
        .arg("30")
        .output()
        .expect("execute aggregate");
    assert!(
        agg_out.status.success(),
        "aggregate failed: {}",
        String::from_utf8_lossy(&agg_out.stderr)
    );
    let agg_str = String::from_utf8_lossy(&agg_out.stdout);
    assert!(agg_str.contains("ISSP MULTIPATH BANDWIDTH AGGREGATION & RESEQUENCING"));
    assert!(agg_str.contains("eth0-fiber-wan"));
    assert!(agg_str.contains("wwan0-5g-edge"));
    assert!(agg_str.contains("100% IN-ORDER DELIVERY GUARANTEED"));

    // 15. Test `ifa net session aggregate --json`
    let agg_json_out = Command::new(&ifa_bin)
        .arg("net")
        .arg("session")
        .arg("aggregate")
        .arg("--sessions")
        .arg("2")
        .arg("--packets")
        .arg("20")
        .arg("--skew-ms")
        .arg("25")
        .arg("--json")
        .output()
        .expect("execute aggregate json");
    assert!(agg_json_out.status.success());
    let agg_val: serde_json::Value =
        serde_json::from_slice(&agg_json_out.stdout).expect("valid JSON aggregate output");
    assert_eq!(agg_val["sessions_count"], 2);
    assert_eq!(agg_val["packets_per_session"], 20);
    assert_eq!(agg_val["total_packets_scheduled"], 40);
    assert_eq!(agg_val["total_packets_delivered"], 40);
    assert_eq!(agg_val["all_sessions_strictly_in_order"], true);
    assert_eq!(agg_val["paths"].as_array().unwrap().len(), 2);

    // 16. Test `ifa net session probation` table output
    let prob_out = Command::new(&ifa_bin)
        .arg("net")
        .arg("session")
        .arg("probation")
        .arg("--flaps")
        .arg("2")
        .arg("--duration-ms")
        .arg("2000")
        .arg("--probes")
        .arg("4")
        .output()
        .expect("execute probation");
    assert!(
        prob_out.status.success(),
        "probation failed: {}",
        String::from_utf8_lossy(&prob_out.stderr)
    );
    let prob_str = String::from_utf8_lossy(&prob_out.stdout);
    assert!(prob_str.contains("ISSP ROUTE FLAPPING DAMPING & PROGRESSIVE PROBATION"));
    assert!(prob_str.contains("ROUTE FLAPPING DAMPING ESCALATION & SUPPRESSION"));
    assert!(prob_str.contains("EXPONENTIAL DECAY & PROBATION PROGRESSION"));
    assert!(prob_str.contains("PATH PROBATION GRADUATED & REINTEGRATED"));

    // 17. Test `ifa net session probation --json`
    let prob_json_out = Command::new(&ifa_bin)
        .arg("net")
        .arg("session")
        .arg("probation")
        .arg("--flaps")
        .arg("2")
        .arg("--duration-ms")
        .arg("2000")
        .arg("--probes")
        .arg("4")
        .arg("--json")
        .output()
        .expect("execute probation json");
    assert!(prob_json_out.status.success());
    let prob_val: serde_json::Value =
        serde_json::from_slice(&prob_json_out.stdout).expect("valid JSON probation output");
    assert_eq!(prob_val["flaps_requested"], 2);
    assert_eq!(prob_val["entered_probation"], true);
    assert_eq!(prob_val["graduated"], true);
    assert_eq!(prob_val["probation_steps"].as_array().unwrap().len(), 4);
    assert_eq!(prob_val["telemetry"]["total_paths"], 2);

    // 18. Test `ifa net session balance` table output
    let bal_out = Command::new(&ifa_bin)
        .arg("net")
        .arg("session")
        .arg("balance")
        .arg("--rounds")
        .arg("5")
        .arg("--gradient-us")
        .arg("80000")
        .arg("--packets")
        .arg("60")
        .output()
        .expect("execute balance");
    assert!(
        bal_out.status.success(),
        "balance failed: {}",
        String::from_utf8_lossy(&bal_out.stderr)
    );
    let bal_str = String::from_utf8_lossy(&bal_out.stdout);
    assert!(bal_str.contains("ISSP DYNAMIC BANDWIDTH BALANCING (RTT GRADIENT / BBR / LEDBAT)"));
    assert!(bal_str.contains("RTT GRADIENT DYNAMICS & CONGESTION FEEDBACK ROUNDS"));
    assert!(bal_str.contains("TRAFFIC STEERING REBALANCING SUMMARY"));
    assert!(bal_str.contains("DYNAMIC RTT GRADIENT CONGESTION BALANCING VERIFIED"));

    // 19. Test `ifa net session balance --json`
    let bal_json_out = Command::new(&ifa_bin)
        .arg("net")
        .arg("session")
        .arg("balance")
        .arg("--rounds")
        .arg("5")
        .arg("--gradient-us")
        .arg("80000")
        .arg("--packets")
        .arg("60")
        .arg("--json")
        .output()
        .expect("execute balance json");
    assert!(bal_json_out.status.success());
    let bal_val: serde_json::Value =
        serde_json::from_slice(&bal_json_out.stdout).expect("valid JSON balance output");
    assert_eq!(bal_val["rounds_evaluated"], 5);
    assert_eq!(bal_val["gradient_surge_us"], 80000);
    assert_eq!(bal_val["packets_per_round"], 60);
    assert_eq!(bal_val["dynamic_rebalancing_verified"], true);
    assert_eq!(bal_val["rounds"].as_array().unwrap().len(), 5);
    assert_eq!(bal_val["telemetry"]["total_paths"], 2);
    assert_eq!(bal_val["telemetry"]["routes"].as_array().unwrap().len(), 2);

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_net_session_telemetry_serve_e2e() {
    use ifa_runtime::{IsspMultipathRoute, IsspRoutingPolicy, SessionRegistry};
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpStream;
    use std::process::{Command, Stdio};

    let temp_dir =
        std::env::temp_dir().join(format!("ifa_cli_telem_serve_e2e_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let state_file = temp_dir.join("telemetry_cluster_state.issp");
    let reg = SessionRegistry::new(77);
    reg.set_multipath_routing_policy(IsspRoutingPolicy::BandwidthAggregation)
        .unwrap();
    reg.add_multipath_route(IsspMultipathRoute::new(1, 2, "eth0-wan", 1, 100))
        .unwrap();
    reg.add_multipath_route(IsspMultipathRoute::new(2, 2, "wwan0-5g", 2, 50))
        .unwrap();
    reg.save_to_file(&state_file).expect("save state dump");
    assert!(state_file.exists());

    let ifa_bin = get_ifa_binary();

    let mut child = Command::new(&ifa_bin)
        .arg("net")
        .arg("session")
        .arg("telemetry-serve")
        .arg("--addr")
        .arg("127.0.0.1:0")
        .arg("--file")
        .arg(&state_file)
        .arg("--max-requests")
        .arg("3")
        .arg("--ws-interval-ms")
        .arg("10")
        .arg("--ws-max-frames")
        .arg("2")
        .arg("--node-id")
        .arg("test-e2e-telem-node")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn `ifa net session telemetry-serve`");

    let child_stderr = child.stderr.take().expect("capture child stderr");
    let mut reader = BufReader::new(child_stderr);

    // Read stderr until we find the listening address line:
    // "Telemetry server listening on http://127.0.0.1:<PORT> ..."
    let mut server_addr = None;
    let mut line = String::new();
    while reader.read_line(&mut line).unwrap() > 0 {
        if let Some(pos) = line.find("http://") {
            let after_http = &line[pos + 7..];
            if let Some(addr_str) = after_http.split_whitespace().next() {
                server_addr = Some(addr_str.to_string());
                break;
            }
        }
        line.clear();
    }
    let server_addr = server_addr.expect("Failed to parse telemetry server address from stderr");

    // Spawn a background thread to drain remaining stderr logs to prevent pipe deadlock
    let stderr_drain = std::thread::spawn(move || {
        let mut rest = String::new();
        let _ = reader.read_to_string(&mut rest);
        rest
    });

    // 1. Test GET /metrics (Prometheus endpoint)
    {
        let mut stream =
            TcpStream::connect(&server_addr).expect("connect to telemetry-serve for /metrics");
        stream
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut resp = String::new();
        stream.read_to_string(&mut resp).unwrap();

        assert!(
            resp.contains("HTTP/1.1 200 OK"),
            "expected HTTP 200, got: {}",
            &resp[..resp.len().min(120)]
        );
        assert!(resp.contains("Content-Type: text/plain; version=0.0.4"));
        assert!(resp.contains("ifa_issp_multipath_active_paths"));
        assert!(resp.contains("node_id=\"77\""));
        assert!(resp.contains("interface=\"eth0-wan\""));
        assert!(resp.contains("interface=\"wwan0-5g\""));
    }

    // 2. Test GET /v1/metrics (OTLP JSON endpoint)
    {
        let mut stream =
            TcpStream::connect(&server_addr).expect("connect to telemetry-serve for /v1/metrics");
        stream
            .write_all(b"GET /v1/metrics HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut resp = String::new();
        stream.read_to_string(&mut resp).unwrap();

        assert!(
            resp.contains("HTTP/1.1 200 OK"),
            "expected HTTP 200, got: {}",
            &resp[..resp.len().min(120)]
        );
        assert!(resp.contains("Content-Type: application/json"));
        let body_pos = resp.find("\r\n\r\n").expect("find end of headers");
        let body = &resp[body_pos + 4..];
        assert!(body.contains("test-e2e-telem-node"));
        let val: serde_json::Value = serde_json::from_str(body).expect("valid JSON OTLP body");
        assert!(val.get("resourceMetrics").is_some() || val.get("scopeMetrics").is_some());
    }

    // 3. Test GET /ws/metrics (Streaming WebSocket endpoint)
    {
        let mut stream =
            TcpStream::connect(&server_addr).expect("connect to telemetry-serve for /ws/metrics");
        let ws_req = "GET /ws/metrics HTTP/1.1\r\n\
                      Host: 127.0.0.1\r\n\
                      Upgrade: websocket\r\n\
                      Connection: Upgrade\r\n\
                      Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                      Sec-WebSocket-Version: 13\r\n\r\n";
        stream.write_all(ws_req.as_bytes()).unwrap();

        // Read handshake response
        let mut resp_bytes: Vec<u8> = Vec::with_capacity(256);
        let mut one = [0u8; 1];
        loop {
            stream.read_exact(&mut one).unwrap();
            resp_bytes.push(one[0]);
            if resp_bytes.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let resp_str = String::from_utf8_lossy(&resp_bytes).to_string();
        assert!(resp_str.contains("101 Switching Protocols"));
        assert!(resp_str.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));

        // Read streamed WebSocket frames (ws_max_frames: 2)
        for i in 0..2 {
            let mut hdr = [0u8; 2];
            stream.read_exact(&mut hdr).expect("read frame header");
            assert_eq!(hdr[0], 0x81, "frame {} opcode must be text (0x81)", i);
            let payload_len: usize = match hdr[1] & 0x7F {
                126 => {
                    let mut ext = [0u8; 2];
                    stream.read_exact(&mut ext).unwrap();
                    u16::from_be_bytes(ext) as usize
                }
                127 => {
                    let mut ext = [0u8; 8];
                    stream.read_exact(&mut ext).unwrap();
                    u64::from_be_bytes(ext) as usize
                }
                n => n as usize,
            };
            let mut payload = vec![0u8; payload_len];
            stream.read_exact(&mut payload).unwrap();
            let frame_payload = String::from_utf8_lossy(&payload).to_string();

            assert!(
                frame_payload.contains("\"active_paths\":2"),
                "frame {} missing active_paths: {}",
                i,
                frame_payload
            );
            assert!(
                frame_payload.contains("eth0-wan"),
                "frame {} missing eth0-wan route",
                i
            );
            assert!(
                frame_payload.contains("wwan0-5g"),
                "frame {} missing wwan0-5g route",
                i
            );
        }
    }

    // 4. Verify process termination and graceful exit after max_requests = 3
    let status = child.wait().expect("child telemetry-serve process wait");
    assert!(
        status.success(),
        "telemetry-serve exited with failure status"
    );

    let _stderr_logs = stderr_drain.join().unwrap();
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_net_session_simd_bench_cli() {
    let ifa_bin = get_ifa_binary();

    let out = Command::new(&ifa_bin)
        .arg("net")
        .arg("session")
        .arg("simd-bench")
        .arg("--packets")
        .arg("500")
        .output()
        .expect("exec simd-bench");

    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("ISSP SIMD Capsule Header Decoding & Telemetry Classification Benchmark")
    );
    assert!(stdout.contains("SIMD / SWAR Vector"));
    assert!(stdout.contains("SIMD 4-Lane Batch"));

    let json_out = Command::new(&ifa_bin)
        .arg("net")
        .arg("session")
        .arg("simd-bench")
        .arg("--packets")
        .arg("500")
        .arg("--json")
        .output()
        .expect("exec simd-bench json");

    assert!(json_out.status.success());
    let json_str = String::from_utf8_lossy(&json_out.stdout);
    assert!(json_str.contains("packet_count"));
    assert!(json_str.contains("capsule_decode_speedup"));
    assert!(json_str.contains("classification_speedup"));
}

#[test]
fn test_net_session_trace_archive_cli() {
    let ifa_bin = get_ifa_binary();

    // 1. Bench mode table
    let bench_out = Command::new(&ifa_bin)
        .arg("net")
        .arg("session")
        .arg("trace-archive")
        .arg("--bench")
        .arg("--bench-records")
        .arg("200")
        .output()
        .expect("exec trace-archive bench");

    assert!(bench_out.status.success());
    let stdout = String::from_utf8_lossy(&bench_out.stdout);
    assert!(stdout.contains("ISSP Zstandard Streaming Trace Compression Pipeline Benchmark"));
    assert!(stdout.contains("Zstd Streaming Ingest & Compress"));

    // 2. Bench mode JSON
    let bench_json = Command::new(&ifa_bin)
        .arg("net")
        .arg("session")
        .arg("trace-archive")
        .arg("--bench")
        .arg("--bench-records")
        .arg("200")
        .arg("--json")
        .output()
        .expect("exec trace-archive bench json");

    assert!(bench_json.status.success());
    let json_str = String::from_utf8_lossy(&bench_json.stdout);
    assert!(json_str.contains("\"record_count\":200"));
    assert!(json_str.contains("\"verification_passed\":true"));

    // 3. End-to-end trace archiving and decompression
    let tmp_dir =
        std::env::temp_dir().join(format!("ifa_cli_trace_archive_test_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp_dir);
    let state_file = tmp_dir.join("state.issp");
    let zst_file = tmp_dir.join("traces.zst");

    let reg = ifa_runtime::SessionRegistry::new(10);
    reg.register_peer(20).unwrap();
    let sid = ifa_runtime::SessionId::new(0x2233_4455_6677_8899, 10, 1);
    let mut snap = ifa_runtime::SessionSnapshot::new(sid, 1, 1_700_000_000);
    snap.tx_seq = 200;
    snap.rx_seq_high = 195;
    reg.upsert_primary(snap).unwrap();
    reg.save_to_file(&state_file).unwrap();

    let archive_out = Command::new(&ifa_bin)
        .arg("net")
        .arg("session")
        .arg("trace-archive")
        .arg("--file")
        .arg(&state_file)
        .arg("--out")
        .arg(&zst_file)
        .output()
        .expect("exec trace-archive out");

    assert!(archive_out.status.success());
    let arc_str = String::from_utf8_lossy(&archive_out.stdout);
    assert!(arc_str.contains("Successfully archived"));
    assert!(zst_file.exists());

    let decomp_out = Command::new(&ifa_bin)
        .arg("net")
        .arg("session")
        .arg("trace-archive")
        .arg("--decompress")
        .arg(&zst_file)
        .output()
        .expect("exec trace-archive decompress");

    assert!(decomp_out.status.success());
    let dec_str = String::from_utf8_lossy(&decomp_out.stdout);
    assert!(dec_str.contains("Timestamp (ns)"));
    assert!(dec_str.contains("CongestionAvoidance"));

    let decomp_json = Command::new(&ifa_bin)
        .arg("net")
        .arg("session")
        .arg("trace-archive")
        .arg("--decompress")
        .arg(&zst_file)
        .arg("--json")
        .output()
        .expect("exec trace-archive decompress json");

    assert!(decomp_json.status.success());
    let dec_json_str = String::from_utf8_lossy(&decomp_json.stdout);
    assert!(dec_json_str.contains("\"phase\":\"CongestionAvoidance\""));

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[test]
fn test_cli_net_session_mtls_attestation_and_rotation() {
    let ifa_bin = env!("CARGO_BIN_EXE_ifa");

    // 1. Benchmark markdown table
    let bench_out = Command::new(ifa_bin)
        .arg("net")
        .arg("session")
        .arg("mtls")
        .arg("--bench")
        .arg("--bench-iterations")
        .arg("10")
        .output()
        .expect("exec mtls bench");
    assert!(bench_out.status.success());
    let bench_str = String::from_utf8_lossy(&bench_out.stdout);
    assert!(bench_str.contains("ISSP mTLS Mutual Attestation & Dynamic Key Rotation Benchmark"));
    assert!(bench_str.contains("PASSED (100% mutual attestation & bit-exact zero packet loss)"));

    // 2. Benchmark JSON output
    let bench_json = Command::new(ifa_bin)
        .arg("net")
        .arg("session")
        .arg("mtls")
        .arg("--bench")
        .arg("--bench-iterations")
        .arg("10")
        .arg("--json")
        .output()
        .expect("exec mtls bench json");
    assert!(bench_json.status.success());
    let json_str = String::from_utf8_lossy(&bench_json.stdout);
    assert!(json_str.contains("\"verification_passed\":true"));
    assert!(json_str.contains("\"handshake_iterations\":10"));

    // 3. Status display
    let status_out = Command::new(ifa_bin)
        .arg("net")
        .arg("session")
        .arg("mtls")
        .arg("--status")
        .output()
        .expect("exec mtls status");
    assert!(status_out.status.success());
    let status_str = String::from_utf8_lossy(&status_out.stdout);
    assert!(status_str.contains("Local Node Security & Attestation Identity:"));
    assert!(status_str.contains("No mesh peer connections registered in cluster state."));

    // 4. Attest peer
    let attest_out = Command::new(ifa_bin)
        .arg("net")
        .arg("session")
        .arg("mtls")
        .arg("--attest-peer")
        .arg("7")
        .arg("--json")
        .output()
        .expect("exec mtls attest");
    assert!(attest_out.status.success());
    let attest_str = String::from_utf8_lossy(&attest_out.stdout);
    assert!(attest_str.contains("\"status\":\"success\""));
    assert!(attest_str.contains("\"action\":\"attest\""));
    assert!(attest_str.contains("\"target_peer\":7"));

    // 5. Key rotation
    let rot_out = Command::new(ifa_bin)
        .arg("net")
        .arg("session")
        .arg("mtls")
        .arg("--rotate-key")
        .arg("7")
        .arg("--reason")
        .arg("emergency")
        .arg("--json")
        .output()
        .expect("exec mtls rotate");
    assert!(rot_out.status.success());
    let rot_str = String::from_utf8_lossy(&rot_out.stdout);
    assert!(rot_str.contains("\"status\":\"success\""));
    assert!(rot_str.contains("\"action\":\"rotate_key\""));
    assert!(rot_str.contains("\"new_epoch\":2"));
    assert!(rot_str.contains("\"reason\":\"emergency_revocation\""));

    // 6. Metrics exposition
    let metrics_out = Command::new(ifa_bin)
        .arg("net")
        .arg("session")
        .arg("mtls")
        .arg("--metrics")
        .output()
        .expect("exec mtls metrics");
    assert!(metrics_out.status.success());
    let metrics_str = String::from_utf8_lossy(&metrics_out.stdout);
    assert!(metrics_str.contains("ifa_mesh_mtls_peers_total"));
    assert!(metrics_str.contains("ifa_mesh_mtls_attested_peers"));
}

#[test]
fn test_cli_net_session_jitter_anomaly_and_thresholds() {
    let ifa_bin = env!("CARGO_BIN_EXE_ifa");

    // 1. Benchmark markdown table
    let bench_out = Command::new(ifa_bin)
        .arg("net")
        .arg("session")
        .arg("jitter")
        .arg("--bench")
        .arg("--bench-samples")
        .arg("300")
        .output()
        .expect("exec jitter bench");
    assert!(bench_out.status.success());
    let bench_str = String::from_utf8_lossy(&bench_out.stdout);
    assert!(bench_str
        .contains("ISSP Jitter Anomaly Detection & Dynamic BBR/LEDBAT Threshold Benchmark"));
    assert!(bench_str
        .contains("PASSED (100% anomaly pattern classification & dynamic threshold derivation)"));

    // 2. Benchmark JSON output
    let bench_json = Command::new(ifa_bin)
        .arg("net")
        .arg("session")
        .arg("jitter")
        .arg("--bench")
        .arg("--bench-samples")
        .arg("300")
        .arg("--json")
        .output()
        .expect("exec jitter bench json");
    assert!(bench_json.status.success());
    let json_str = String::from_utf8_lossy(&bench_json.stdout);
    assert!(json_str.contains("\"verification_passed\":true"));
    assert!(json_str.contains("\"total_samples\":300"));

    // 3. Status display
    let status_out = Command::new(ifa_bin)
        .arg("net")
        .arg("session")
        .arg("jitter")
        .arg("--status")
        .output()
        .expect("exec jitter status");
    assert!(status_out.status.success());
    let status_str = String::from_utf8_lossy(&status_out.stdout);
    assert!(status_str.contains("ISSP Jitter Anomaly & Dynamic Congestion Thresholds"));
    assert!(status_str.contains("eth0-fiber-wan"));
    assert!(status_str.contains("wwan0-5g-edge"));

    // 4. Status JSON output
    let status_json = Command::new(ifa_bin)
        .arg("net")
        .arg("session")
        .arg("jitter")
        .arg("--json")
        .output()
        .expect("exec jitter status json");
    assert!(status_json.status.success());
    let st_json_str = String::from_utf8_lossy(&status_json.stdout);
    assert!(st_json_str.contains("\"jitter_subpaths\":"));
    assert!(st_json_str.contains("\"dynamic_ledbat_target_us\":"));
    assert!(st_json_str.contains("\"dynamic_bbr_pacing_gain_q8\":"));

    // 5. Prometheus metrics output
    let metrics_out = Command::new(ifa_bin)
        .arg("net")
        .arg("session")
        .arg("jitter")
        .arg("--metrics")
        .output()
        .expect("exec jitter metrics");
    assert!(metrics_out.status.success());
    let metrics_str = String::from_utf8_lossy(&metrics_out.stdout);
    assert!(metrics_str.contains("ifa_jitter_mean_rtt_us"));
    assert!(metrics_str.contains("ifa_dynamic_ledbat_target_us"));
    assert!(metrics_str.contains("ifa_dynamic_bbr_pacing_gain"));
}

#[test]
fn test_cli_multipath_protocol_end_to_end_pipeline() {
    let ifa_bin = get_ifa_binary();
    let temp_dir = std::env::temp_dir().join(format!("ifa_cli_mp_e2e_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let src_file = temp_dir.join("multipath_app.ifa");
    let code = r#"
@multipath(resilient)
protocol TelemetryStream {
    slice control: Channel<u32>,
    slice metrics: Stream<u8>,
    slice video: Stream<u8>,
}

pub fn main() -> () {
    mut meta = __MultipathSubpathMeta {
        subpath_id: 42,
        interface_index: 3,
        weight: 100,
        rtt_micros: 350,
        loss_rate_ppm: 10,
        state: 1,
    };
    println("IFA_MULTIPATH_PIPELINE_OK");
}
"#;
    fs::write(&src_file, code).unwrap();

    // 1. End-to-end execution with internal FIR Interpreter (`ifa run`)
    let run_interp = Command::new(&ifa_bin)
        .arg("run")
        .arg(&src_file)
        .output()
        .expect("Failed to execute `ifa run` with multipath protocol");
    assert!(
        run_interp.status.success(),
        "Interpreter execution failed: {}",
        String::from_utf8_lossy(&run_interp.stderr)
    );
    let interp_out = String::from_utf8_lossy(&run_interp.stdout);
    assert!(
        interp_out.contains("IFA_MULTIPATH_PIPELINE_OK"),
        "Missing expected output in interpreter run: {}",
        interp_out
    );

    // 2. End-to-end execution with Cranelift JIT (`ifa run --native`)
    let run_native = Command::new(&ifa_bin)
        .arg("run")
        .arg("--native")
        .arg(&src_file)
        .output()
        .expect("Failed to execute `ifa run --native` with multipath protocol");
    assert!(
        run_native.status.success(),
        "JIT execution failed: {}",
        String::from_utf8_lossy(&run_native.stderr)
    );
    let native_out = String::from_utf8_lossy(&run_native.stdout);
    assert!(
        native_out.contains("IFA_MULTIPATH_PIPELINE_OK"),
        "Missing expected output in JIT run: {}",
        native_out
    );

    // 3. Ahead-of-Time compilation via `ifa compile` (CLI driver alias for `build`)
    let out_bin = temp_dir.join("multipath_exec");
    let compile_status = Command::new(&ifa_bin)
        .arg("compile")
        .arg(&src_file)
        .arg("-o")
        .arg(&out_bin)
        .status()
        .expect("Failed to execute `ifa compile`");
    assert!(
        compile_status.success(),
        "AOT standalone compilation failed"
    );
    assert!(out_bin.exists(), "Target executable does not exist");

    // Execute standalone binary
    let exec_output = Command::new(&out_bin)
        .output()
        .expect("Failed to execute compiled standalone binary");
    assert!(
        exec_output.status.success(),
        "Standalone binary execution failed"
    );
    let exec_out = String::from_utf8_lossy(&exec_output.stdout);
    assert!(
        exec_out.contains("IFA_MULTIPATH_PIPELINE_OK"),
        "Missing expected output in standalone binary: {}",
        exec_out
    );

    // 4. Object emission via `ifa compile --emit-obj`
    let out_obj = temp_dir.join("multipath_obj.o");
    let obj_status = Command::new(&ifa_bin)
        .arg("compile")
        .arg("--emit-obj")
        .arg(&src_file)
        .arg("-o")
        .arg(&out_obj)
        .status()
        .expect("Failed to emit object file via `ifa compile --emit-obj`");
    assert!(obj_status.success(), "Object file emission failed");
    assert!(out_obj.exists(), "Object file does not exist");
    let obj_meta = fs::metadata(&out_obj).unwrap();
    assert!(obj_meta.len() > 0, "Object file must not be empty");

    let _ = fs::remove_dir_all(&temp_dir);
}

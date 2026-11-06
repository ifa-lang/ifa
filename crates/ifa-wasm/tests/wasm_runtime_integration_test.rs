use ifa_codegen_llvm::{LlvmCompiler, LlvmTargetConfig};
use ifa_fir::compile_to_fir;
use ifa_lexer::tokenize;
use ifa_parser::parse;
use ifa_sema::analyze;
use ifa_span::SourceMap;
use ifa_wasm::{WasmEngine, WasmEngineRunner, WasmModuleInspector};
use std::fs;

#[test]
fn test_end_to_end_wasmtime_and_wasmer_execution() {
    let temp_dir = std::env::temp_dir().join(format!("ifa_wasm_e2e_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let src = r#"
pub extern "C" strict fn add(a: i64, b: i64) -> i64 {
    return a + b
}

pub extern "C" strict fn fib(n: i64) -> i64 {
    if n <= 1 {
        return n
    }
    mut prev = 0
    mut curr = 1
    mut i = 2
    while i <= n {
        let next = prev + curr
        prev = curr
        curr = next
        i = i + 1
    }
    return curr
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("wasm_test.ifa".to_string(), src);
    let tokens = tokenize(fid, src);
    let (prog, parse_diags) = parse(fid, tokens);
    assert!(parse_diags.is_empty(), "Parse error: {:?}", parse_diags);

    let analysis = analyze(&sm, &prog);
    assert!(!analysis.has_errors(), "Sema error");

    let fir_module =
        compile_to_fir(&prog, &analysis.symbols, true, true).expect("FIR lowering failed");

    let wasm_path = temp_dir.join("module.wasm");
    let compiler = LlvmCompiler::new(LlvmTargetConfig::wasm32_wasi());
    compiler
        .compile_to_wasm(&fir_module, &wasm_path)
        .expect("Compilation to WebAssembly failed");

    assert!(wasm_path.exists());
    let wasm_bytes = fs::read(&wasm_path).unwrap();

    // 1. Inspect and validate WebAssembly binary format
    let inspector = WasmModuleInspector::new(&wasm_bytes);
    let sections = inspector.inspect().expect("Wasm inspection failed");
    assert!(!sections.is_empty(), "No sections detected");

    let exports = inspector
        .extract_exports()
        .expect("Failed to extract exports");
    let export_names: Vec<String> = exports.into_iter().map(|e| e.name).collect();
    assert!(
        export_names.iter().any(|name| name == "add"),
        "Export `add` not found: {:?}",
        export_names
    );
    assert!(
        export_names.iter().any(|name| name == "fib"),
        "Export `fib` not found: {:?}",
        export_names
    );

    // 2. Execute within Wasmtime if available
    if WasmEngineRunner::is_available(WasmEngine::Wasmtime) {
        let res_add = WasmEngineRunner::run(
            WasmEngine::Wasmtime,
            &wasm_path,
            Some("add"),
            &["15".to_string(), "27".to_string()],
        )
        .expect("Wasmtime execution of `add` failed");
        assert_eq!(res_add.exit_code, 0);
        assert_eq!(res_add.return_value, Some(42));

        let res_fib = WasmEngineRunner::run(
            WasmEngine::Wasmtime,
            &wasm_path,
            Some("fib"),
            &["10".to_string()],
        )
        .expect("Wasmtime execution of `fib` failed");
        assert_eq!(res_fib.exit_code, 0);
        assert_eq!(res_fib.return_value, Some(55));
    }

    // 3. Execute within Wasmer if available
    if WasmEngineRunner::is_available(WasmEngine::Wasmer) {
        let res_add = WasmEngineRunner::run(
            WasmEngine::Wasmer,
            &wasm_path,
            Some("add"),
            &["15".to_string(), "27".to_string()],
        )
        .expect("Wasmer execution of `add` failed");
        assert_eq!(res_add.exit_code, 0);
        assert_eq!(res_add.return_value, Some(42));

        let res_fib = WasmEngineRunner::run(
            WasmEngine::Wasmer,
            &wasm_path,
            Some("fib"),
            &["10".to_string()],
        )
        .expect("Wasmer execution of `fib` failed");
        assert_eq!(res_fib.exit_code, 0);
        assert_eq!(res_fib.return_value, Some(55));
    }

    // 4. Test internal WASI validator
    let res_internal = WasmEngineRunner::run(WasmEngine::Internal, &wasm_path, None, &[])
        .expect("Internal WASI validator failed");
    assert_eq!(res_internal.exit_code, 0);

    let _ = fs::remove_dir_all(&temp_dir);
}

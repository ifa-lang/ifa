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

#[test]
fn test_end_to_end_higher_order_wasm_execution() {
    let temp_dir = std::env::temp_dir().join(format!("ifa_wasm_hof_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let src = r#"
pub extern "C" strict fn square(x: i64) -> i64 {
    return x * x
}

pub extern "C" strict fn double_val(x: i64) -> i64 {
    return x * 2
}

pub extern "C" strict fn apply(f: fn(i64) -> i64, val: i64) -> i64 {
    return f(val)
}

pub extern "C" strict fn run_square(n: i64) -> i64 {
    return apply(square, n)
}

pub extern "C" strict fn run_double(n: i64) -> i64 {
    return apply(double_val, n)
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("wasm_hof.ifa".to_string(), src);
    let tokens = tokenize(fid, src);
    let (prog, parse_diags) = parse(fid, tokens);
    assert!(parse_diags.is_empty(), "Parse error: {:?}", parse_diags);

    let analysis = analyze(&sm, &prog);
    assert!(!analysis.has_errors(), "Sema error");

    let fir_module =
        compile_to_fir(&prog, &analysis.symbols, true, true).expect("FIR lowering failed");

    let wasm_path = temp_dir.join("hof_module.wasm");
    let compiler = LlvmCompiler::new(LlvmTargetConfig::wasm32_wasi());
    compiler
        .compile_to_wasm(&fir_module, &wasm_path)
        .expect("Compilation of higher-order module to WebAssembly failed");

    assert!(wasm_path.exists());
    let wasm_bytes = fs::read(&wasm_path).unwrap();

    // 1. Inspect WebAssembly binary exports and sections
    let inspector = WasmModuleInspector::new(&wasm_bytes);
    let sections = inspector.inspect().expect("Wasm inspection failed");
    assert!(!sections.is_empty());

    let exports = inspector
        .extract_exports()
        .expect("Failed to extract exports");
    let export_names: Vec<String> = exports.into_iter().map(|e| e.name).collect();
    assert!(export_names.iter().any(|name| name == "run_square"));
    assert!(export_names.iter().any(|name| name == "run_double"));

    // 2. Execute within Wasmtime if available
    if WasmEngineRunner::is_available(WasmEngine::Wasmtime) {
        let res_sq = WasmEngineRunner::run(
            WasmEngine::Wasmtime,
            &wasm_path,
            Some("run_square"),
            &["9".to_string()],
        )
        .expect("Wasmtime execution of `run_square` failed");
        assert_eq!(res_sq.exit_code, 0);
        assert_eq!(res_sq.return_value, Some(81));

        let res_dbl = WasmEngineRunner::run(
            WasmEngine::Wasmtime,
            &wasm_path,
            Some("run_double"),
            &["21".to_string()],
        )
        .expect("Wasmtime execution of `run_double` failed");
        assert_eq!(res_dbl.exit_code, 0);
        assert_eq!(res_dbl.return_value, Some(42));
    }

    // 3. Execute within Wasmer if available
    if WasmEngineRunner::is_available(WasmEngine::Wasmer) {
        let res_sq = WasmEngineRunner::run(
            WasmEngine::Wasmer,
            &wasm_path,
            Some("run_square"),
            &["9".to_string()],
        )
        .expect("Wasmer execution of `run_square` failed");
        assert_eq!(res_sq.exit_code, 0);
        assert_eq!(res_sq.return_value, Some(81));

        let res_dbl = WasmEngineRunner::run(
            WasmEngine::Wasmer,
            &wasm_path,
            Some("run_double"),
            &["21".to_string()],
        )
        .expect("Wasmer execution of `run_double` failed");
        assert_eq!(res_dbl.exit_code, 0);
        assert_eq!(res_dbl.return_value, Some(42));
    }

    // 4. Test internal WASI emulator
    let res_internal = WasmEngineRunner::run(WasmEngine::Internal, &wasm_path, None, &[])
        .expect("Internal WASI validator failed");
    assert_eq!(res_internal.exit_code, 0);
    assert!(res_internal.stdout.contains("Internal WASI VM"));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_end_to_end_wasm_coroutine_inspection_and_validation() {
    use ifa_fir::{
        BasicBlock, BlockId, ConstantValue, FirFunction, FirModule, FirType, Instruction,
        Terminator, ValueExpr, ValueId,
    };
    use ifa_sema::types::IntType;
    use ifa_span::{Span, INTERNER};

    let temp_dir = std::env::temp_dir().join(format!("ifa_wasm_coro_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let fn_name = INTERNER.intern("wasm_stream_coro");
    let mut func = FirFunction::new(
        fn_name,
        vec![],
        FirType::Unit,
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );
    func.is_coroutine = true;

    let mut bb0 = BasicBlock::new(BlockId(0));
    let ch = ValueId(1);
    bb0.instructions.push(Instruction::new(
        Some(ch),
        ValueExpr::ChanCreate {
            elem_ty: FirType::Int(IntType::I64),
            capacity: None,
        },
        Span::DUMMY,
    ));

    let val = ValueId(2);
    bb0.instructions.push(Instruction::new(
        Some(val),
        ValueExpr::Constant(ConstantValue::Int(999, IntType::I64)),
        Span::DUMMY,
    ));

    bb0.instructions.push(Instruction::new(
        None,
        ValueExpr::ChanSend { chan: ch, val },
        Span::DUMMY,
    ));

    bb0.instructions
        .push(Instruction::new(None, ValueExpr::Yield, Span::DUMMY));

    bb0.terminator = Some(Terminator::Return(None));
    func.blocks.push(bb0);

    let module = FirModule {
        name: INTERNER.intern("wasm_coro_pkg"),
        functions: vec![func],
        structs: Vec::new(),
        enums: Vec::new(),
        constants: Vec::new(),
    };

    let wasm_path = temp_dir.join("coro_stream.wasm");
    let compiler = LlvmCompiler::new(LlvmTargetConfig::wasm32_wasi());
    compiler
        .compile_to_wasm(&module, &wasm_path)
        .expect("WebAssembly compilation of coroutine stream failed");

    assert!(wasm_path.exists());
    let wasm_bytes = fs::read(&wasm_path).unwrap();

    // 1. Inspect WebAssembly binary format
    let inspector = WasmModuleInspector::new(&wasm_bytes);
    let sections = inspector
        .inspect()
        .expect("Inspection of wasm coroutine module failed");
    assert!(!sections.is_empty());

    let exports = inspector
        .extract_exports()
        .expect("Extraction of exports failed");
    let export_names: Vec<String> = exports.into_iter().map(|e| e.name).collect();
    assert!(
        export_names.iter().any(|name| name == "wasm_stream_coro"),
        "Export `wasm_stream_coro` not found in WebAssembly binary: {:?}",
        export_names
    );

    // 2. Validate through internal WASI engine
    let res = WasmEngineRunner::run(WasmEngine::Internal, &wasm_path, None, &[])
        .expect("Internal WASI execution of coroutine module failed");
    assert_eq!(res.exit_code, 0);

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_wasm_stackless_iterator_generator_inspection_and_exports() {
    use ifa_codegen_llvm::compiler::LlvmCompiler;
    use ifa_codegen_llvm::target::LlvmTargetConfig;
    use ifa_fir::{
        BasicBlock, BlockId, ConstantValue, FirFunction, FirModule, FirType, Instruction,
        Terminator, ValueExpr, ValueId,
    };
    use ifa_sema::types::IntType;
    use ifa_span::{Span, INTERNER};
    use ifa_wasm::runner::{WasmEngine, WasmEngineRunner};
    use ifa_wasm::validator::WasmModuleInspector;
    use std::fs;

    let temp_dir = std::env::temp_dir().join(format!("ifa_wasm_gen_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);

    let fn_name = INTERNER.intern("wasm_prime_stream");
    let mut func = FirFunction::new(
        fn_name,
        vec![],
        FirType::Unit,
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );
    func.is_coroutine = true;

    let mut bb0 = BasicBlock::new(BlockId(0));
    let prime2 = ValueId(1);
    bb0.instructions.push(Instruction::new(
        Some(prime2),
        ValueExpr::Constant(ConstantValue::Int(2, IntType::I64)),
        Span::DUMMY,
    ));
    bb0.instructions.push(Instruction::new(
        None,
        ValueExpr::YieldValue { val: prime2 },
        Span::DUMMY,
    ));

    let prime3 = ValueId(2);
    bb0.instructions.push(Instruction::new(
        Some(prime3),
        ValueExpr::Constant(ConstantValue::Int(3, IntType::I64)),
        Span::DUMMY,
    ));
    bb0.instructions.push(Instruction::new(
        None,
        ValueExpr::YieldValue { val: prime3 },
        Span::DUMMY,
    ));

    let prime5 = ValueId(3);
    bb0.instructions.push(Instruction::new(
        Some(prime5),
        ValueExpr::Constant(ConstantValue::Int(5, IntType::I64)),
        Span::DUMMY,
    ));
    bb0.instructions.push(Instruction::new(
        None,
        ValueExpr::YieldValue { val: prime5 },
        Span::DUMMY,
    ));

    bb0.terminator = Some(Terminator::Return(None));
    func.blocks.push(bb0);

    let module = FirModule {
        name: INTERNER.intern("wasm_prime_pkg"),
        functions: vec![func],
        structs: Vec::new(),
        enums: Vec::new(),
        constants: Vec::new(),
    };

    let wasm_path = temp_dir.join("prime_stream.wasm");
    let compiler = LlvmCompiler::new(LlvmTargetConfig::wasm32_wasi());
    compiler
        .compile_to_wasm(&module, &wasm_path)
        .expect("WebAssembly compilation of prime stream generator failed");

    assert!(wasm_path.exists());
    let wasm_bytes = fs::read(&wasm_path).unwrap();

    // 1. Inspect WebAssembly binary sections
    let inspector = WasmModuleInspector::new(&wasm_bytes);
    let sections = inspector
        .inspect()
        .expect("Inspection of wasm generator module failed");
    assert!(!sections.is_empty());

    // 2. Validate exported generator and helpers
    let exports = inspector
        .extract_exports()
        .expect("Extraction of generator exports failed");
    let export_names: Vec<String> = exports.into_iter().map(|e| e.name).collect();
    assert!(
        export_names.iter().any(|name| name == "wasm_prime_stream"),
        "Export `wasm_prime_stream` not found in WebAssembly binary: {:?}",
        export_names
    );
    assert!(
        export_names
            .iter()
            .any(|name| name == "ifa_wasm_generator_next"),
        "Export `ifa_wasm_generator_next` not found in WebAssembly binary: {:?}",
        export_names
    );
    assert!(
        export_names.iter().any(|name| name == "ifa_wasm_coro_step"),
        "Export `ifa_wasm_coro_step` not found in WebAssembly binary: {:?}",
        export_names
    );

    // 3. Validate through internal WASI engine
    let res = WasmEngineRunner::run(WasmEngine::Internal, &wasm_path, None, &[])
        .expect("Internal WASI execution of prime generator module failed");
    assert_eq!(res.exit_code, 0);

    let _ = fs::remove_dir_all(&temp_dir);
}

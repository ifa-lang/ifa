use ifa_codegen_llvm::{LlvmIrEmitter, LlvmTargetConfig};
use ifa_fir::{compile_to_fir, FirInterpreter, FirValue};
use ifa_lexer::tokenize;
use ifa_parser::parse;
use ifa_sema::analyze;
use ifa_span::SourceMap;

#[test]
fn test_pure_closure_direct_lowering_without_thunk() {
    let src = r#"
        pub fn square(x: i64) -> i64 {
            return x * x;
        }

        pub fn apply(f: fn(i64) -> i64, v: i64) -> i64 {
            return f(v);
        }

        pub fn main() -> i64 {
            let pure_lambda = fn(n: i64) -> i64 {
                return n + 10;
            };
            let a = apply(square, 6);        // 36
            let b = apply(pure_lambda, 15);   // 25
            return a + b;                    // 61
        }
    "#;

    let mut sm = SourceMap::new();
    let file_id = sm.add_file("direct_closure.ifa".to_string(), src);
    let tokens = tokenize(file_id, src);
    let (prog, diags) = parse(file_id, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).expect("FIR failed");

    // 1. Verify zero thunk allocation across the entire module
    let has_thunk = fir_module
        .functions
        .iter()
        .any(|f| f.name.as_str().starts_with("__ifa_thunk_"));
    assert!(
        !has_thunk,
        "Module must have ZERO thunk allocations for native functions and pure closures"
    );

    // 2. Verify pure lambda does not possess dummy __env parameter
    for f in &fir_module.functions {
        if f.name.as_str().starts_with("__ifa_lambda_") {
            assert!(
                !f.params.iter().any(|p| p.name.as_str() == "__env"),
                "Pure lambda {} must not have a dummy __env parameter",
                f.name.as_str()
            );
        }
    }

    // 3. Verify execution via FIR interpreter produces expected mathematical result
    let mut interp = FirInterpreter::new(&fir_module);
    let result = interp.execute_function("main", vec![]).unwrap();
    assert_eq!(result, FirValue::Int(61));

    // 4. Verify LLVM IR emission includes proper declarations
    let target = LlvmTargetConfig::x86_64();
    let mut emitter = LlvmIrEmitter::new(&target);
    let llvm_ir = emitter
        .emit_module(&fir_module)
        .expect("LLVM emission failed");
    assert!(llvm_ir.contains("declare void @ifa_rt_bounds_check(i64, i64, ptr)"));
    assert!(llvm_ir.contains("declare i1 @ifa_rt_buffer_verify_bounds(ptr, i64, i64, i64)"));
}

#[test]
fn test_c_abi_ffi_bounds_check_intrinsics_emission() {
    let src = r#"
        pub extern "C" strict fn sum_two(a: i64, b: i64) -> i64 {
            return a + b;
        }

        pub fn main() -> i64 {
            return sum_two(18, 24);
        }
    "#;

    let mut sm = SourceMap::new();
    let file_id = sm.add_file("c_abi_export.ifa".to_string(), src);
    let tokens = tokenize(file_id, src);
    let (prog, diags) = parse(file_id, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).expect("FIR failed");

    let target = LlvmTargetConfig::x86_64();
    let mut emitter = LlvmIrEmitter::new(&target);
    let llvm_ir = emitter
        .emit_module(&fir_module)
        .expect("LLVM emission failed");

    // Verify C-ABI function is emitted with dso_local linkage and no mangling
    assert!(llvm_ir.contains("define dso_local i64 @sum_two(i64 %v0, i64 %v1)"));
    // Verify static bounds check and slice verification runtime declarations are present
    assert!(llvm_ir.contains("declare void @ifa_rt_bounds_check(i64, i64, ptr)"));
    assert!(llvm_ir.contains("declare void @ifa_rt_slice_bounds_check(i64, i64, i64, ptr)"));
    assert!(llvm_ir.contains("declare i1 @ifa_rt_buffer_verify_bounds(ptr, i64, i64, i64)"));
}

#[test]
fn test_runtime_c_abi_bounds_verification_unit() {
    use ifa_runtime::ffi::{
        ifa_rt_bounds_check, ifa_rt_buffer_verify_bounds, ifa_rt_c_abi_validate_slice,
        ifa_rt_slice_bounds_check, IfaSlice,
    };

    // Valid index check
    ifa_rt_bounds_check(0, 10, std::ptr::null());
    ifa_rt_bounds_check(9, 10, std::ptr::null());

    // Valid slice check
    ifa_rt_slice_bounds_check(0, 5, 10, std::ptr::null());
    ifa_rt_slice_bounds_check(2, 2, 10, std::ptr::null());
    ifa_rt_slice_bounds_check(0, 10, 10, std::ptr::null());

    // Buffer verification
    let buffer = [0u8; 64];
    assert!(ifa_rt_buffer_verify_bounds(buffer.as_ptr(), 64, 32, 8));
    assert!(!ifa_rt_buffer_verify_bounds(std::ptr::null(), 64, 32, 8));
    assert!(!ifa_rt_buffer_verify_bounds(buffer.as_ptr(), 16, 32, 8));

    // Slice validation
    let slice = IfaSlice {
        ptr: buffer.as_ptr(),
        len: 64,
    };
    assert!(ifa_rt_c_abi_validate_slice(slice, 8, 8)); // 8 elements of 8 bytes = 64 bytes
    assert!(!ifa_rt_c_abi_validate_slice(slice, 8, 9)); // 9 elements of 8 bytes = 72 bytes > 64
}

#[test]
fn test_llvm_array_and_slice_bounds_check_code_generation() {
    let src = r#"
        pub fn test_array_and_slice_access(s: Slice<i64>) -> i64 {
            let arr: [i64; 4] = [100, 200, 300, 400];
            let a = arr[2];
            let b = s[0];
            let sub = s[1..3];
            let c = sub[0];
            return a + b + c;
        }

        pub fn main() -> i64 {
            let data: [i64; 5] = [10, 20, 30, 40, 50];
            let win = data[0..4];
            return test_array_and_slice_access(win);
        }
    "#;

    let mut sm = SourceMap::new();
    let file_id = sm.add_file("bounds_codegen.ifa".to_string(), src);
    let tokens = tokenize(file_id, src);
    let (prog, diags) = parse(file_id, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).expect("FIR failed");

    let target = LlvmTargetConfig::x86_64();
    let mut emitter = LlvmIrEmitter::new(&target);
    let llvm_ir = emitter
        .emit_module(&fir_module)
        .expect("LLVM emission failed");

    // Verify bounds check calls are emitted for arrays and slices
    assert!(
        llvm_ir.contains("call void @ifa_rt_bounds_check"),
        "LLVM IR must emit bounds check calls for indexed accesses"
    );
    assert!(
        llvm_ir.contains("call void @ifa_rt_slice_bounds_check"),
        "LLVM IR must emit slice bounds check calls for sub-slicing"
    );

    // Verify native compilation and execution
    let temp_dir = std::env::temp_dir().join(format!("ifa_bounds_exec_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("bounds.o");
    let bin_path = temp_dir.join("bounds_exec");

    let compiler = ifa_codegen_llvm::LlvmCompiler::new(target);
    let compile_res = compiler.compile_to_object(&fir_module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Object compilation failed: {:?}",
        compile_res.err()
    );

    let link_res = ifa_codegen_llvm::LlvmCompiler::link_executable(&obj_path, &bin_path);
    assert!(link_res.is_ok(), "Native link failed: {:?}", link_res.err());

    let output = std::process::Command::new(&bin_path)
        .output()
        .expect("Failed to execute native binary");
    // a = arr[2] = 300
    // b = s[0] = win[0] = 10
    // sub = s[1..3] = [20, 30]
    // c = sub[0] = 20
    // total = 300 + 10 + 20 = 330 -> exit code (330 % 256) = 74
    assert_eq!(output.status.code(), Some((330i64 % 256) as i32));

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_array_out_of_bounds_aborts_safely() {
    let src = r#"
        pub fn main() -> i64 {
            let arr: [i64; 3] = [10, 20, 30];
            let out_of_bounds_val = arr[5];
            return out_of_bounds_val;
        }
    "#;

    let mut sm = SourceMap::new();
    let file_id = sm.add_file("oob_test.ifa".to_string(), src);
    let tokens = tokenize(file_id, src);
    let (prog, diags) = parse(file_id, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).expect("FIR failed");

    let target = LlvmTargetConfig::x86_64();
    let temp_dir = std::env::temp_dir().join(format!("ifa_oob_exec_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("oob.o");
    let bin_path = temp_dir.join("oob_exec");

    let compiler = ifa_codegen_llvm::LlvmCompiler::new(target);
    let compile_res = compiler.compile_to_object(&fir_module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Object compilation failed: {:?}",
        compile_res.err()
    );

    let link_res = ifa_codegen_llvm::LlvmCompiler::link_executable(&obj_path, &bin_path);
    assert!(link_res.is_ok(), "Native link failed: {:?}", link_res.err());

    let output = std::process::Command::new(&bin_path)
        .output()
        .expect("Failed to execute native binary");
    // Execution must fail / abort safely without memory corruption
    assert!(
        !output.status.success(),
        "Execution must abort on out-of-bounds access"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("BOUNDS CHECK")
            || stderr.contains("Out of bounds")
            || stderr.contains("out-of-bounds"),
        "Diagnostic must report bounds check violation: {}",
        stderr
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

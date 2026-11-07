use ifa_codegen_llvm::{
    fir_to_llvm_type, LlvmCompiler, LlvmIrEmitter, LlvmTargetConfig, TargetArch,
};
use ifa_fir::{compile_to_fir, FirType};
use ifa_lexer::tokenize;
use ifa_parser::parse;
use ifa_sema::analyze;
use ifa_sema::types::IntType;
use ifa_span::SourceMap;
use std::fs;

#[test]
fn test_llvm_target_configurations() {
    let x86 = LlvmTargetConfig::x86_64();
    assert_eq!(x86.arch, TargetArch::X86_64);
    assert_eq!(x86.triple, "x86_64-unknown-linux-gnu");
    assert!(x86.features.contains("+avx2"));

    let arm = LlvmTargetConfig::aarch64();
    assert_eq!(arm.arch, TargetArch::AArch64);
    assert_eq!(arm.triple, "aarch64-unknown-linux-gnu");
    assert!(arm.features.contains("+neon"));

    let wasm = LlvmTargetConfig::wasm32_wasi();
    assert_eq!(wasm.arch, TargetArch::Wasm32Wasi);
    assert_eq!(wasm.triple, "wasm32-unknown-wasi");
    assert!(wasm.features.contains("+simd128"));
}

#[test]
fn test_llvm_type_translation() {
    assert_eq!(fir_to_llvm_type(&FirType::Unit).unwrap(), "void");
    assert_eq!(fir_to_llvm_type(&FirType::Bool).unwrap(), "i1");
    assert_eq!(fir_to_llvm_type(&FirType::Str).unwrap(), "ptr");
    assert_eq!(fir_to_llvm_type(&FirType::String).unwrap(), "ptr");
    assert_eq!(
        fir_to_llvm_type(&FirType::GenerationalRef(Box::new(FirType::Int(
            IntType::I64
        ))))
        .unwrap(),
        "{ ptr, i32, i16, i16 }"
    );
}

#[test]
fn test_llvm_ir_emission_from_ifa_source() {
    let src = r#"
pub extern "C" strict fn add(a: i64, b: i64) -> i64 {
    return a + b
}

pub fn main() -> () {
    let x = 10
    let y = 20
    let sum = add(x, y)
    println("Calculations completed.")
}
"#;

    let mut sm = SourceMap::new();
    let file_id = sm.add_file("test_llvm.ifa".to_string(), src);
    let tokens = tokenize(file_id, src);
    let (prog, parse_diags) = parse(file_id, tokens);
    assert!(parse_diags.is_empty(), "Parse errors: {:?}", parse_diags);

    let analysis = analyze(&sm, &prog);
    assert!(!analysis.has_errors(), "Sema errors");

    let fir_module =
        compile_to_fir(&prog, &analysis.symbols, true, true).expect("FIR lowering failed");

    let target = LlvmTargetConfig::x86_64();
    let mut emitter = LlvmIrEmitter::new(&target);
    let llvm_ir = emitter
        .emit_module(&fir_module)
        .expect("LLVM IR emission failed");

    // Verify module header and target triple
    assert!(llvm_ir.contains("target triple = \"x86_64-unknown-linux-gnu\""));
    assert!(llvm_ir.contains("; IFA Runtime Intrinsic Declarations"));
    assert!(llvm_ir.contains("declare void @ifa_rt_println(ptr)"));

    // Verify strict pure function attributes
    assert!(llvm_ir.contains("define dso_local i64 @add("));
    assert!(llvm_ir.contains("add nsw i64"));

    // Verify string literal handling
    assert!(llvm_ir.contains("Calculations completed."));
}

#[test]
fn test_llvm_compiler_file_output() {
    let temp_dir = std::env::temp_dir().join(format!("llvm_test_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let src = r#"
pub fn main() -> () {
    let a = 100
    let b = 200
    let c = a + b
    println("Execution ok.")
}
"#;

    let mut sm = SourceMap::new();
    let file_id = sm.add_file("main.ifa".to_string(), src);
    let tokens = tokenize(file_id, src);
    let (prog, _) = parse(file_id, tokens);
    let analysis = analyze(&sm, &prog);
    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let target = LlvmTargetConfig::host();
    let compiler = LlvmCompiler::new(target);

    let ll_path = temp_dir.join("output.ll");
    let ir = compiler
        .emit_llvm_ir(&fir_module, &ll_path)
        .expect("Emit LLVM IR failed");
    assert!(ll_path.exists());
    assert!(!ir.is_empty());

    let obj_path = temp_dir.join("output.o");
    compiler
        .compile_to_object(&fir_module, &obj_path)
        .expect("Compile to object failed");
    assert!(obj_path.exists());

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_lto_cross_module_compilation() {
    let temp_dir = std::env::temp_dir().join(format!("llvm_lto_test_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let src1 = r#"
pub extern "C" fn calculate_tax(amount: i64) -> i64 {
    let tax = amount / 5
    return tax
}
"#;

    let src2 = r#"
pub fn main() -> () {
    let total = 1000
    println("LTO module execution completed.")
}
"#;

    let mut sm = SourceMap::new();
    let fid1 = sm.add_file("math_mod.ifa".to_string(), src1);
    let (prog1, _) = parse(fid1, tokenize(fid1, src1));
    let analysis1 = analyze(&sm, &prog1);
    let fir1 = compile_to_fir(&prog1, &analysis1.symbols, true, true).unwrap();

    let fid2 = sm.add_file("main_mod.ifa".to_string(), src2);
    let (prog2, _) = parse(fid2, tokenize(fid2, src2));
    let analysis2 = analyze(&sm, &prog2);
    let fir2 = compile_to_fir(&prog2, &analysis2.symbols, true, true).unwrap();

    let mut compiler = LlvmCompiler::new(LlvmTargetConfig::host());
    compiler.lto("thin").opt_level(3);

    let lto_obj = temp_dir.join("lto_combined.o");
    compiler
        .compile_modules_lto(&[&fir1, &fir2], &lto_obj)
        .expect("LTO compilation failed");

    assert!(lto_obj.exists());
    let metadata = fs::metadata(&lto_obj).unwrap();
    assert!(metadata.len() > 0);

    let bin_path = temp_dir.join("lto_exec");
    let link_res = LlvmCompiler::link_executable_with_lto(&lto_obj, &bin_path, "thin");
    if link_res.is_ok() && bin_path.exists() {
        let output = std::process::Command::new(&bin_path)
            .output()
            .expect("Failed to run LTO binary");
        assert!(output.status.success());
    }

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_codegen_monomorphized_generic_functions() {
    let src = r#"
        struct Box<T> {
            val: T,
        }

        fn unbox<T>(b: Box<T>) -> T {
            return b.val;
        }

        pub fn main() -> i64 {
            let b = Box(val: 42);
            let v = unbox(b);
            return v;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("llvm_generic.ifa".to_string(), src);
    let (prog, _) = parse(fid, tokenize(fid, src));
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );
    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let target = LlvmTargetConfig::host();
    let mut emitter = LlvmIrEmitter::new(&target);
    let llvm_ir = emitter.emit_module(&fir_module).unwrap();

    assert!(llvm_ir.contains("%struct.Box__i64 = type { i64 }"));
    assert!(llvm_ir.contains("@unbox__i64"));
    assert!(llvm_ir.contains("call i64 @unbox__i64"));
}

#[test]
fn test_llvm_for_loop_and_match_codegen() {
    let src = r#"
        fn score(v: i64) -> i64 {
            return match v {
                10 => 1,
                20 => 2,
                _ => 0,
            };
        }

        pub fn main() -> i64 {
            let nums = [10, 20];
            mut total = 0;
            for n in nums {
                total = total + score(n);
            }
            return total;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("llvm_for_match.ifa".to_string(), src);
    let (prog, _) = parse(fid, tokenize(fid, src));
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );
    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let target = LlvmTargetConfig::host();
    let mut emitter = LlvmIrEmitter::new(&target);
    let llvm_ir = emitter.emit_module(&fir_module).unwrap();

    assert!(llvm_ir.contains("define internal i64 @score(i64 %v0)"));
    assert!(llvm_ir.contains("define dso_local i64 @main()"));
    assert!(llvm_ir.contains("getelementptr inbounds [2 x i64]"));
    assert!(llvm_ir.contains("call i64 @score"));
}

#[test]
fn test_llvm_error_union_try_question_catch_codegen() {
    let src = r#"
        struct IoError {
            code: i64
        }

        fn step_success() -> IoError!i64 {
            return 10;
        }

        fn step_fail() -> IoError!i64 {
            fail IoError(code: 404);
        }

        fn chain_work() -> IoError!i64 {
            let a = try step_success();
            let b = step_fail()?;
            return a + b;
        }

        pub fn main() -> i64 {
            let res = chain_work() catch err {
                return 999;
            };
            return res;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("llvm_error.ifa".to_string(), src);
    let (prog, _) = parse(fid, tokenize(fid, src));
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );
    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let target = LlvmTargetConfig::host();
    let mut emitter = LlvmIrEmitter::new(&target);
    let llvm_ir = emitter.emit_module(&fir_module).unwrap();

    assert!(llvm_ir.contains("define internal ptr @step_success()"));
    assert!(llvm_ir.contains("define internal ptr @step_fail()"));
    assert!(llvm_ir.contains("define internal ptr @chain_work()"));
    assert!(llvm_ir.contains("define dso_local i64 @main()"));
    assert!(llvm_ir.contains("call ptr @chain_work()"));
}

#[test]
fn test_llvm_simd_slice_vectorization() {
    let target = LlvmTargetConfig::x86_64();
    let mut emitter = LlvmIrEmitter::new(&target);
    let module = ifa_fir::FirModule {
        name: ifa_span::INTERNER.intern("simd_test"),
        functions: Vec::new(),
        structs: Vec::new(),
        enums: Vec::new(),
        constants: Vec::new(),
    };
    let ir = emitter.emit_module(&module).unwrap();

    // Verify SIMD Vector Reduction Intrinsics and Vectorizers are generated
    assert!(ir.contains("declare float @llvm.vector.reduce.fadd.v8f32"));
    assert!(ir.contains("declare i32 @llvm.vector.reduce.add.v8i32"));
    assert!(ir.contains("@ifa_simd_slice_add_f32"));
    assert!(ir.contains("@ifa_simd_slice_mul_f32"));
    assert!(ir.contains("@ifa_simd_slice_dot_f32"));
    assert!(ir.contains("@ifa_simd_slice_sum_f32"));
    assert!(ir.contains("@ifa_simd_slice_add_i32"));
    assert!(ir.contains("@ifa_simd_slice_sum_i32"));
    assert!(ir.contains("<8 x float>"));
    assert!(ir.contains("<8 x i32>"));

    // Verify loop vectorization metadata
    assert!(ir.contains("!\"llvm.loop.vectorize.enable\", i1 1"));
    assert!(ir.contains("!\"llvm.loop.vectorize.width\", i32 8"));
    assert!(ir.contains("\"no-trapping-math\"=\"true\""));
}

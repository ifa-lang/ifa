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
    assert!(ir.contains("declare double @llvm.vector.reduce.fadd.v4f64"));
    assert!(ir.contains("declare i32 @llvm.vector.reduce.add.v8i32"));
    assert!(ir.contains("declare i64 @llvm.vector.reduce.add.v4i64"));
    assert!(ir.contains("@ifa_simd_slice_add_f32"));
    assert!(ir.contains("@ifa_simd_slice_mul_f32"));
    assert!(ir.contains("@ifa_simd_slice_dot_f32"));
    assert!(ir.contains("@ifa_simd_slice_sum_f32"));
    assert!(ir.contains("@ifa_simd_slice_add_i32"));
    assert!(ir.contains("@ifa_simd_slice_mul_i32"));
    assert!(ir.contains("@ifa_simd_slice_sum_i32"));
    assert!(ir.contains("@ifa_simd_slice_add_f64"));
    assert!(ir.contains("@ifa_simd_slice_mul_f64"));
    assert!(ir.contains("@ifa_simd_slice_dot_f64"));
    assert!(ir.contains("@ifa_simd_slice_sum_f64"));
    assert!(ir.contains("@ifa_simd_slice_add_i64"));
    assert!(ir.contains("@ifa_simd_slice_mul_i64"));
    assert!(ir.contains("@ifa_simd_slice_sum_i64"));
    assert!(ir.contains("@ifa_simd_slice_add_u8"));
    assert!(ir.contains("@ifa_simd_slice_xor_u8"));

    // Verify Advanced SIMD Scalar Reductions (prod, min, max)
    assert!(ir.contains("declare float @llvm.vector.reduce.fmul.v8f32"));
    assert!(ir.contains("declare float @llvm.vector.reduce.fmin.v8f32"));
    assert!(ir.contains("declare float @llvm.vector.reduce.fmax.v8f32"));
    assert!(ir.contains("declare i32 @llvm.vector.reduce.mul.v8i32"));
    assert!(ir.contains("declare i32 @llvm.vector.reduce.smin.v8i32"));
    assert!(ir.contains("declare i32 @llvm.vector.reduce.smax.v8i32"));
    assert!(ir.contains("@ifa_simd_slice_prod_f32"));
    assert!(ir.contains("@ifa_simd_slice_min_f32"));
    assert!(ir.contains("@ifa_simd_slice_max_f32"));
    assert!(ir.contains("@ifa_simd_slice_prod_i32"));
    assert!(ir.contains("@ifa_simd_slice_min_i32"));
    assert!(ir.contains("@ifa_simd_slice_max_i32"));
    assert!(ir.contains("@ifa_simd_slice_prod_f64"));
    assert!(ir.contains("@ifa_simd_slice_min_f64"));
    assert!(ir.contains("@ifa_simd_slice_max_f64"));
    assert!(ir.contains("@ifa_simd_slice_prod_i64"));
    assert!(ir.contains("@ifa_simd_slice_min_i64"));
    assert!(ir.contains("@ifa_simd_slice_max_i64"));

    // Verify IFA Standard Library SIMD Contiguous Arena Slice Reductions
    assert!(ir.contains("@ifa_simd_arena_slice_sum_f32"));
    assert!(ir.contains("@ifa_simd_arena_slice_sum_f64"));
    assert!(ir.contains("@ifa_simd_arena_slice_sum_i32"));
    assert!(ir.contains("@ifa_simd_arena_slice_sum_i64"));
    assert!(ir.contains("@ifa_simd_arena_slice_prod_f32"));
    assert!(ir.contains("@ifa_simd_arena_slice_prod_f64"));
    assert!(ir.contains("@ifa_simd_arena_slice_prod_i32"));
    assert!(ir.contains("@ifa_simd_arena_slice_prod_i64"));
    assert!(ir.contains("@ifa_simd_arena_slice_min_f32"));
    assert!(ir.contains("@ifa_simd_arena_slice_min_f64"));
    assert!(ir.contains("@ifa_simd_arena_slice_min_i32"));
    assert!(ir.contains("@ifa_simd_arena_slice_min_i64"));
    assert!(ir.contains("@ifa_simd_arena_slice_max_f32"));
    assert!(ir.contains("@ifa_simd_arena_slice_max_f64"));
    assert!(ir.contains("@ifa_simd_arena_slice_max_i32"));
    assert!(ir.contains("@ifa_simd_arena_slice_max_i64"));
    assert!(ir.contains("@ifa_simd_arena_slice_dot_f32"));
    assert!(ir.contains("@ifa_simd_arena_slice_dot_f64"));

    // Verify IFA Standard Library SIMD Contiguous Arena Predicates and Filters
    assert!(ir.contains("@ifa_simd_arena_slice_count_if_gt_f32"));
    assert!(ir.contains("@ifa_simd_arena_slice_count_if_gt_f64"));
    assert!(ir.contains("@ifa_simd_arena_slice_count_if_gt_i32"));
    assert!(ir.contains("@ifa_simd_arena_slice_count_if_gt_i64"));
    assert!(ir.contains("@ifa_simd_arena_slice_count_if_lt_i32"));
    assert!(ir.contains("@ifa_simd_arena_slice_count_if_eq_i32"));
    assert!(ir.contains("@ifa_simd_arena_slice_count_if_ne_i32"));
    assert!(ir.contains("@ifa_simd_arena_slice_filter_gt_i32"));
    assert!(ir.contains("@ifa_simd_arena_slice_filter_gt_f32"));
    assert!(ir.contains("@ifa_simd_arena_slice_filter_gt_f64"));
    assert!(ir.contains("@ifa_simd_arena_slice_filter_gt_i64"));
    assert!(ir.contains("@ifa_simd_arena_slice_filter_lt_i32"));
    assert!(ir.contains("@ifa_simd_arena_slice_filter_eq_i32"));
    assert!(ir.contains("@ifa_simd_arena_slice_select_gt_f32"));
    assert!(ir.contains("@ifa_simd_arena_slice_select_gt_i32"));
    assert!(ir.contains("@ifa_simd_arena_slice_clamp_f32"));
    assert!(ir.contains("@ifa_simd_arena_slice_clamp_i32"));

    assert!(ir.contains("<8 x float>"));
    assert!(ir.contains("<4 x double>"));
    assert!(ir.contains("<8 x i32>"));
    assert!(ir.contains("<4 x i64>"));
    assert!(ir.contains("<16 x i8>"));

    // Verify loop vectorization metadata
    assert!(ir.contains("!\"llvm.loop.vectorize.enable\", i1 1"));
    assert!(ir.contains("!\"llvm.loop.vectorize.width\", i32 8"));
    assert!(ir.contains("!\"llvm.loop.vectorize.width\", i32 4"));
    assert!(ir.contains("!\"llvm.loop.vectorize.width\", i32 16"));
    assert!(ir.contains("!\"llvm.loop.vectorize.width\", i32 2"));
    assert!(ir.contains("\"no-trapping-math\"=\"true\""));
}

#[test]
fn test_llvm_aarch64_neon_horizontal_reduction_intrinsics() {
    let src = r#"
        pub fn neon_test() -> () {
            let x: i64 = 42;
            return ();
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("neon_test.ifa".to_string(), src);
    let (prog, _) = parse(fid, tokenize(fid, src));
    let analysis = analyze(&sm, &prog);
    assert!(!analysis.has_errors());

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let target = LlvmTargetConfig::aarch64();
    let mut emitter = LlvmIrEmitter::new(&target);
    let ir = emitter.emit_module(&module).unwrap();

    // Verify AArch64 target triple and datalayout
    assert!(ir.contains(
        "target datalayout = \"e-m:e-i8:8:32-i16:16:32-i64:64-i128:128-n32:64-S128-Fn32\""
    ));
    assert!(ir.contains("target triple = \"aarch64-unknown-linux-gnu\""));

    // Verify AArch64 Neon native horizontal reduction intrinsics
    assert!(ir.contains("declare float @llvm.aarch64.neon.fmaxv.f32.v4f32(<4 x float>)"));
    assert!(ir.contains("declare float @llvm.aarch64.neon.fminv.f32.v4f32(<4 x float>)"));
    assert!(ir.contains("declare float @llvm.aarch64.neon.fmaxnmv.f32.v4f32(<4 x float>)"));
    assert!(ir.contains("declare float @llvm.aarch64.neon.fminnmv.f32.v4f32(<4 x float>)"));
    assert!(ir.contains("declare double @llvm.aarch64.neon.fmaxv.f64.v2f64(<2 x double>)"));
    assert!(ir.contains("declare double @llvm.aarch64.neon.fminv.f64.v2f64(<2 x double>)"));
    assert!(ir.contains("declare i32 @llvm.aarch64.neon.smaxv.i32.v4i32(<4 x i32>)"));
    assert!(ir.contains("declare i32 @llvm.aarch64.neon.sminv.i32.v4i32(<4 x i32>)"));
    assert!(ir.contains("declare i32 @llvm.aarch64.neon.umaxv.i32.v4i32(<4 x i32>)"));
    assert!(ir.contains("declare i32 @llvm.aarch64.neon.uminv.i32.v4i32(<4 x i32>)"));
    assert!(ir.contains("declare i32 @llvm.aarch64.neon.uaddv.i32.v4i32(<4 x i32>)"));
    assert!(ir.contains("declare i64 @llvm.aarch64.neon.smaxv.i64.v2i64(<2 x i64>)"));
    assert!(ir.contains("declare i64 @llvm.aarch64.neon.sminv.i64.v2i64(<2 x i64>)"));

    // Verify AArch64 Neon hardware-accelerated slice vectorizers
    assert!(ir.contains("@ifa_neon_slice_sum_f32"));
    assert!(ir.contains("@ifa_neon_slice_min_f32"));
    assert!(ir.contains("@ifa_neon_slice_max_f32"));
    assert!(ir.contains("@ifa_neon_slice_min_i32"));
    assert!(ir.contains("@ifa_neon_slice_max_i32"));
}

#[test]
fn test_llvm_stackless_fibers_and_coroutine_intrinsics() {
    let src = r#"
        pub fn worker_coro() -> () {
            println("Worker fiber active");
        }

        pub fn main() -> () {
            spawn worker_coro();
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("coro_test.ifa".to_string(), src);
    let (prog, _) = parse(fid, tokenize(fid, src));
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );
    let module = compile_to_fir(&prog, &analysis.symbols, true, true).expect("FIR lowering failed");

    let target = LlvmTargetConfig::x86_64();
    let mut emitter = LlvmIrEmitter::new(&target);
    let ir = emitter.emit_module(&module).expect("Emission failed");

    // 1. Verify LLVM Standard Coroutine Intrinsics
    assert!(ir.contains("declare token @llvm.coro.id(i32, ptr, ptr, ptr)"));
    assert!(ir.contains("declare i64 @llvm.coro.size.i64()"));
    assert!(ir.contains("declare ptr @llvm.coro.begin(token, ptr)"));
    assert!(ir.contains("declare i8 @llvm.coro.suspend(token, i1)"));
    assert!(ir.contains("declare i1 @llvm.coro.end(ptr, i1, token)"));
    assert!(ir.contains("declare void @llvm.coro.resume(ptr)"));
    assert!(ir.contains("declare void @llvm.coro.destroy(ptr)"));
    assert!(ir.contains("declare i1 @llvm.coro.done(ptr)"));

    // 2. Verify IFA Native Coroutine Runtime Declarations
    assert!(ir.contains("declare ptr @ifa_rt_coro_create(i64, ptr, ptr)"));
    assert!(ir.contains("declare i32 @ifa_rt_coro_resume(ptr)"));
    assert!(ir.contains("declare i64 @ifa_rt_coro_spawn(ptr)"));
    assert!(ir.contains("declare void @ifa_rt_coro_destroy(ptr)"));
    assert!(ir.contains("declare i32 @ifa_rt_coro_status(ptr)"));
    assert!(ir.contains("declare i32 @ifa_rt_coro_is_done(ptr)"));
    assert!(ir.contains("declare ptr @ifa_rt_coro_frame(ptr)"));
    assert!(ir.contains("declare i64 @ifa_rt_fiber_spawn(ptr, ptr)"));
    assert!(ir.contains("declare void @ifa_rt_fiber_join(i64)"));

    // 3. Verify Continuous Coroutine Runner linkonce helper
    assert!(ir.contains("@ifa_coro_run_continuous(ptr %coro)"));
    assert!(ir.contains("@ifa_coro_poll(ptr %coro)"));

    // 4. Verify Stackless Fiber Spawn instruction
    assert!(ir.contains("call i64 @ifa_rt_fiber_spawn(ptr @worker_coro, ptr null)"));

    // 5. Verify LLVM compilation to object file works smoothly
    let temp_dir = std::env::temp_dir().join(format!("llvm_coro_test_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("coro_test.o");

    let compiler = LlvmCompiler::new(LlvmTargetConfig::host());
    let compile_res = compiler.compile_to_object(&module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Object compilation failed: {:?}",
        compile_res.err()
    );
    assert!(obj_path.exists());

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_coroutine_state_machine_lowering() {
    use ifa_codegen_llvm::compiler::LlvmCompiler;
    use ifa_codegen_llvm::ir_emitter::LlvmIrEmitter;
    use ifa_codegen_llvm::target::LlvmTargetConfig;
    use ifa_fir::{BlockId, FirFunction, FirModule, Instruction, Terminator, ValueExpr};
    use ifa_span::{Span, INTERNER};
    use std::fs;

    let mut module = FirModule::new(INTERNER.intern("coro_test_mod"));
    let gen_name = INTERNER.intern("stream_generator");

    let mut func = FirFunction::new(
        gen_name,
        vec![],
        ifa_fir::types::FirType::Unit,
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );

    let b_entry = BlockId(0);
    let entry_bb = func.get_block_mut(b_entry).unwrap();
    entry_bb.push_instruction(Instruction::new(None, ValueExpr::Yield, Span::DUMMY));
    entry_bb.push_instruction(Instruction::new(None, ValueExpr::Yield, Span::DUMMY));
    entry_bb.set_terminator(Terminator::Return(None));

    assert!(func.is_coroutine());
    module.functions.push(func);

    // Also a caller function that spawns the coroutine
    let main_name = INTERNER.intern("main");
    let mut main_func = FirFunction::new(
        main_name,
        vec![],
        ifa_fir::types::FirType::Unit,
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );
    let spawn_res = main_func.alloc_value();
    let main_entry = main_func.get_block_mut(b_entry).unwrap();
    main_entry.push_instruction(Instruction::new(
        Some(spawn_res),
        ValueExpr::Spawn {
            target: gen_name,
            args: vec![],
        },
        Span::DUMMY,
    ));
    main_entry.set_terminator(Terminator::Return(None));
    module.functions.push(main_func);

    let target = LlvmTargetConfig::x86_64();
    let mut emitter = LlvmIrEmitter::new(&target);
    let ir = emitter.emit_module(&module).expect("Emission failed");

    // 1. Assert that generator was lowered with presplitcoroutine attribute and coro intrinsics
    assert!(ir.contains("define dso_local ptr @stream_generator() presplitcoroutine"));
    assert!(ir.contains("call token @llvm.coro.id("));
    assert!(ir.contains("call ptr @llvm.coro.begin("));
    assert!(ir.contains("call i8 @llvm.coro.suspend("));
    assert!(ir.contains("call ptr @llvm.coro.free("));
    assert!(ir.contains("call i1 @llvm.coro.end("));

    // 2. Assert that spawning a coroutine invokes @ifa_coro_llvm_spawn
    assert!(ir.contains("call ptr @stream_generator()"));
    assert!(ir.contains("call i64 @ifa_coro_llvm_spawn(ptr %coro_hdl_"));

    // 3. Verify LLVM compiles to native object with clang!
    let temp_dir =
        std::env::temp_dir().join(format!("llvm_coro_state_machine_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("coro_sm.o");

    let compiler = LlvmCompiler::new(LlvmTargetConfig::host());
    let compile_res = compiler.compile_to_object(&module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Compilation to object failed: {:?}",
        compile_res.err()
    );
    assert!(obj_path.exists());

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_auto_vectorization_loop_codegen() {
    let src = r#"
        pub fn sum_f32_vec(arr: [f32; 64]) -> f32 {
            let mut acc: f32 = 0.0;
            for x in arr {
                acc = acc + x;
            }
            return acc;
        }

        pub fn xor_u8_crypto(buf: [u8; 16]) -> u8 {
            let mut acc: u8 = 0;
            for b in buf {
                acc = acc ^ b;
            }
            return acc;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("simd_loop_test.ifa".to_string(), src);
    let (prog, _) = parse(fid, tokenize(fid, src));
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).expect("FIR lowering failed");

    let target = LlvmTargetConfig::x86_64();
    let mut emitter = LlvmIrEmitter::new(&target);
    let ir = emitter.emit_module(&module).expect("Emission failed");

    // 1. Verify loop branch attaches the SIMD vectorize metadata hints
    assert!(
        ir.contains("!llvm.loop !1"),
        "IR must attach 8-lane SIMD hint for f32: {}",
        ir
    );
    assert!(
        ir.contains("!llvm.loop !8"),
        "IR must attach 16-lane SIMD hint for u8: {}",
        ir
    );

    // 2. Verify compilation to native object file succeeds with LLVM optimizer
    let temp_dir = std::env::temp_dir().join(format!("llvm_simd_test_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("simd_loop.o");

    let compiler = LlvmCompiler::new(LlvmTargetConfig::host());
    let compile_res = compiler.compile_to_object(&module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Object compilation with SIMD vectorization failed: {:?}",
        compile_res.err()
    );
    assert!(obj_path.exists());

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_aot_monomorphic_trait_specialization() {
    let src = r#"
        trait Shape {
            fn area(self: Shape) -> i64;
        }

        struct Circle {
            r: i64,
        }

        impl Shape for Circle {
            fn area(c: Circle) -> i64 {
                return c.r * c.r;
            }
        }

        struct Square {
            s: i64,
        }

        impl Shape for Square {
            fn area(sq: Square) -> i64 {
                return sq.s * sq.s;
            }
        }

        fn compute<T: Shape>(item: T) -> i64 {
            return item.area();
        }

        pub fn main() -> i64 {
            let c = Circle(r: 5);
            let s = Square(s: 10);
            return compute(c) + compute(s);
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("trait_monomorph.ifa".to_string(), src);
    let (prog, _) = parse(fid, tokenize(fid, src));
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).expect("FIR lowering failed");

    let target = LlvmTargetConfig::host();
    let mut emitter = LlvmIrEmitter::new(&target);
    let ir = emitter.emit_module(&module).expect("Emission failed");

    // 1. Verify AOT monomorphic trait method definitions were emitted with specialized names
    assert!(
        ir.contains("@Circle__area"),
        "IR must contain @Circle__area: {}",
        ir
    );
    assert!(
        ir.contains("@Square__area"),
        "IR must contain @Square__area: {}",
        ir
    );

    // 2. Verify VTables were generated for both implementors
    assert!(
        ir.contains("@__ifa_vtable_Circle"),
        "IR must contain @__ifa_vtable_Circle"
    );
    assert!(
        ir.contains("@__ifa_vtable_Square"),
        "IR must contain @__ifa_vtable_Square"
    );

    // 3. Verify monomorphized generic instantiations were emitted
    assert!(
        ir.contains("@compute__Circle"),
        "IR must contain @compute__Circle"
    );
    assert!(
        ir.contains("@compute__Square"),
        "IR must contain @compute__Square"
    );

    // 4. Verify devirtualized direct static calls inside the monomorphized functions
    assert!(
        ir.contains("call i64 @Circle__area"),
        "Trait call must be devirtualized to @Circle__area"
    );
    assert!(
        ir.contains("call i64 @Square__area"),
        "Trait call must be devirtualized to @Square__area"
    );

    // 5. Verify compilation to native executable and actual execution produces 125
    let temp_dir = std::env::temp_dir().join(format!("llvm_trait_test_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("trait.o");
    let bin_path = temp_dir.join("trait_exec");

    let compiler = LlvmCompiler::new(LlvmTargetConfig::host());
    let compile_res = compiler.compile_to_object(&module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Object compilation failed: {:?}",
        compile_res.err()
    );
    assert!(obj_path.exists());

    let link_res = LlvmCompiler::link_executable(&obj_path, &bin_path);
    assert!(link_res.is_ok(), "Native link failed: {:?}", link_res.err());
    assert!(bin_path.exists());

    let output = std::process::Command::new(&bin_path)
        .output()
        .expect("Failed to execute native binary");
    assert_eq!(
        output.status.code(),
        Some(125),
        "Native binary output exit code must be 125 (5*5 + 10*10)"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_generic_trait_impl_devirtualization_and_native_execution() {
    let src = r#"
        trait Metric {
            fn score(self: Metric) -> i64;
        }

        struct Sensor {
            raw: i64,
        }

        impl Metric for Sensor {
            fn score(s: Sensor) -> i64 {
                return s.raw;
            }
        }

        struct Box<T> {
            val: T,
        }

        impl<T: Metric> Metric for Box<T> {
            fn score(b: Box<T>) -> i64 {
                return b.val.score() * 2;
            }
        }

        fn evaluate<U: Metric>(item: U) -> i64 {
            return item.score();
        }

        pub fn main() -> i64 {
            let s = Sensor(raw: 21);
            let b = Box(val: s);
            return evaluate(b);
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("generic_trait_llvm.ifa".to_string(), src);
    let (prog, _) = parse(fid, tokenize(fid, src));
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).expect("FIR lowering failed");

    let target = LlvmTargetConfig::host();
    let mut emitter = LlvmIrEmitter::new(&target);
    let ir = emitter.emit_module(&module).expect("Emission failed");

    // 1. Verify VTables for both implementors (Sensor and monomorphized Box__Sensor)
    assert!(
        ir.contains("@__ifa_vtable_Sensor"),
        "IR must contain @__ifa_vtable_Sensor: {}",
        ir
    );
    assert!(
        ir.contains("@__ifa_vtable_Box__Sensor"),
        "IR must contain @__ifa_vtable_Box__Sensor: {}",
        ir
    );

    // 2. Verify devirtualized direct static calls
    assert!(
        ir.contains("call i64 @Box__Sensor__score"),
        "Call must be devirtualized to @Box__Sensor__score: {}",
        ir
    );
    assert!(
        ir.contains("call i64 @Sensor__score"),
        "Call must be devirtualized to @Sensor__score: {}",
        ir
    );

    // 3. Verify compilation to native executable and actual execution produces 42 (21 * 2)
    let temp_dir =
        std::env::temp_dir().join(format!("llvm_generic_trait_test_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("gen_trait.o");
    let bin_path = temp_dir.join("gen_trait_exec");

    let compiler = LlvmCompiler::new(LlvmTargetConfig::host());
    let compile_res = compiler.compile_to_object(&module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Object compilation failed: {:?}",
        compile_res.err()
    );
    assert!(obj_path.exists());

    let link_res = LlvmCompiler::link_executable(&obj_path, &bin_path);
    assert!(link_res.is_ok(), "Native link failed: {:?}", link_res.err());
    assert!(bin_path.exists());

    let output = std::process::Command::new(&bin_path)
        .output()
        .expect("Failed to execute native binary");
    assert_eq!(
        output.status.code(),
        Some(42),
        "Native binary output exit code must be 42 (21 * 2)"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_adt_tagged_union_emission_and_native_execution() {
    let src = r#"
enum Event {
    None,
    Value(i64),
}

fn process(e: Event) -> i64 {
    return match e {
        Event::None => 10,
        Event::Value(v) if v > 50 => v * 2,
        Event::Value(v) => v,
    }
}

pub fn main() -> i64 {
    let e1 = Event::None;
    let e2 = Event::Value(70);
    let e3 = Event::Value(30);

    let r1 = process(e1);
    let r2 = process(e2);
    let r3 = process(e3);

    return r1 + r2 + r3;
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("adt_llvm.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let host_config = LlvmTargetConfig::host();
    let mut emitter = LlvmIrEmitter::new(&host_config);
    let ir = emitter.emit_module(&module).unwrap();
    assert!(
        ir.contains("%enum.Event = type { i64, i64 }"),
        "LLVM IR must define the tagged union type %enum.Event"
    );

    let temp_dir = std::env::temp_dir().join(format!("llvm_adt_test_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("adt.o");
    let bin_path = temp_dir.join("adt_exec");

    let compiler = LlvmCompiler::new(LlvmTargetConfig::host());
    let compile_res = compiler.compile_to_object(&module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Object compilation failed: {:?}",
        compile_res.err()
    );
    assert!(obj_path.exists());

    let link_res = LlvmCompiler::link_executable(&obj_path, &bin_path);
    assert!(link_res.is_ok(), "Native link failed: {:?}", link_res.err());
    assert!(bin_path.exists());

    let output = std::process::Command::new(&bin_path)
        .output()
        .expect("Failed to execute native binary");
    assert_eq!(
        output.status.code(),
        Some(180),
        "Native binary output exit code must be 180 (10 + 140 + 30)"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_tuple_and_struct_pattern_matching_native() {
    let src = r#"
struct Coord {
    x: i64,
    y: i64,
}

fn eval_coord(c: Coord) -> i64 {
    return match c {
        Coord { x: 0, y: 0 } => 10,
        Coord { x: 0, y } => y,
        Coord { x, y } => x + y,
    }
}

fn eval_pair(p: (i64, i64)) -> i64 {
    return match p {
        (0, 0) => 20,
        (0, b) => b * 2,
        (a, b) => a + b,
    }
}

pub fn main() -> i64 {
    let c1 = eval_coord(Coord(x: 0, y: 0));
    let c2 = eval_coord(Coord(x: 10, y: 30));
    let p1 = eval_pair((0, 0));
    let p2 = eval_pair((0, 15));
    let p3 = eval_pair((7, 8));

    return c1 + c2 + p1 + p2 + p3;
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("llvm_struct_tup.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let temp_dir = std::env::temp_dir().join(format!("llvm_agg_test_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("agg.o");
    let bin_path = temp_dir.join("agg_exec");

    let compiler = LlvmCompiler::new(LlvmTargetConfig::host());
    let compile_res = compiler.compile_to_object(&module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Object compilation failed: {:?}",
        compile_res.err()
    );
    assert!(obj_path.exists());

    let link_res = LlvmCompiler::link_executable(&obj_path, &bin_path);
    assert!(link_res.is_ok(), "Native link failed: {:?}", link_res.err());
    assert!(bin_path.exists());

    let output = std::process::Command::new(&bin_path)
        .output()
        .expect("Failed to execute native binary");
    assert_eq!(
        output.status.code(),
        Some(115),
        "Native binary output exit code must be 115 (10 + 40 + 20 + 30 + 15)"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_or_and_range_pattern_matching_native() {
    let src = r#"
fn classify_val(v: i64) -> i64 {
    return match v {
        1 | 3 | 5 => 10,
        10..=20 => 20,
        21..=25 | 30..=35 => 40,
        _ => 0,
    }
}

pub fn main() -> i64 {
    let r1 = classify_val(3);
    let r2 = classify_val(15);
    let r3 = classify_val(23);
    let r4 = classify_val(31);
    let r5 = classify_val(99);

    return r1 + r2 + r3 + r4 + r5;
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("llvm_or_range.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let temp_dir = std::env::temp_dir().join(format!("llvm_or_range_test_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("or_range.o");
    let bin_path = temp_dir.join("or_range_exec");

    let compiler = LlvmCompiler::new(LlvmTargetConfig::host());
    let compile_res = compiler.compile_to_object(&module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Object compilation failed: {:?}",
        compile_res.err()
    );
    assert!(obj_path.exists());

    let link_res = LlvmCompiler::link_executable(&obj_path, &bin_path);
    assert!(link_res.is_ok(), "Native link failed: {:?}", link_res.err());
    assert!(bin_path.exists());

    let output = std::process::Command::new(&bin_path)
        .output()
        .expect("Failed to execute native binary");
    assert_eq!(
        output.status.code(),
        Some(110),
        "Native binary output exit code must be 110 (10 + 20 + 40 + 40 + 0)"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_aot_slice_pattern_matching() {
    let src = r#"
fn classify_trio(arr: [i64; 3]) -> i64 {
    return match arr {
        [0, 0, 0] => 0,
        [first, 2, third] => first * 10 + third,
        [x, y, z] => x + y + z,
    };
}

pub fn main() -> i64 {
    let a = classify_trio([0, 0, 0]);
    let b = classify_trio([3, 2, 5]);
    let c = classify_trio([1, 2, 4]);

    // a = 0
    // b = 3 * 10 + 5 = 35
    // c = 1 * 10 + 4 = 14
    // 0 + 35 + 14 = 49
    return a + b + c;
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("llvm_slice_pattern.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let temp_dir =
        std::env::temp_dir().join(format!("llvm_slice_pattern_test_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("slice_pattern.o");
    let bin_path = temp_dir.join("slice_pattern_exec");

    let compiler = LlvmCompiler::new(LlvmTargetConfig::host());
    let compile_res = compiler.compile_to_object(&module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Object compilation failed: {:?}",
        compile_res.err()
    );
    assert!(obj_path.exists());

    let link_res = LlvmCompiler::link_executable(&obj_path, &bin_path);
    assert!(link_res.is_ok(), "Native link failed: {:?}", link_res.err());
    assert!(bin_path.exists());

    let output = std::process::Command::new(&bin_path)
        .output()
        .expect("Failed to execute native binary");
    assert_eq!(
        output.status.code(),
        Some(49),
        "Native binary output exit code must be 49"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_inout_and_struct_pattern_destructuring() {
    let src = r#"
struct Coord {
    x: i64,
    y: i64,
}

pub fn main() -> i64 {
    mut c = Coord(x: 10, y: 32);
    let Coord { inout x, inout y } = c;
    x = x + 5;
    y = y + 10;
    return c.x + c.y;
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("llvm_inout_pat.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let temp_dir =
        std::env::temp_dir().join(format!("llvm_inout_pattern_test_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("inout_pattern.o");
    let bin_path = temp_dir.join("inout_pattern_exec");

    let compiler = LlvmCompiler::new(LlvmTargetConfig::host());
    let compile_res = compiler.compile_to_object(&module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Object compilation failed: {:?}",
        compile_res.err()
    );
    assert!(obj_path.exists());

    let link_res = LlvmCompiler::link_executable(&obj_path, &bin_path);
    assert!(link_res.is_ok(), "Native link failed: {:?}", link_res.err());
    assert!(bin_path.exists());

    let output = std::process::Command::new(&bin_path)
        .output()
        .expect("Failed to execute native binary");
    assert_eq!(
        output.status.code(),
        Some(57),
        "Native binary output exit code must be 57 (15 + 42)"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_tuple_inout_pattern_destructuring() {
    let src = r#"
pub fn main() -> i64 {
    mut pair = (10, 20);
    let (inout a, inout b) = pair;
    a = a + 1;
    b = b + 2;
    let (final_a, final_b) = pair;
    return final_a + final_b;
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("llvm_tup_inout_pat.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let temp_dir = std::env::temp_dir().join(format!(
        "llvm_tuple_inout_pattern_test_{}",
        std::process::id()
    ));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("tuple_inout_pattern.o");
    let bin_path = temp_dir.join("tuple_inout_pattern_exec");

    let compiler = LlvmCompiler::new(LlvmTargetConfig::host());
    let compile_res = compiler.compile_to_object(&module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Object compilation failed: {:?}",
        compile_res.err()
    );
    assert!(obj_path.exists());

    let link_res = LlvmCompiler::link_executable(&obj_path, &bin_path);
    assert!(link_res.is_ok(), "Native link failed: {:?}", link_res.err());
    assert!(bin_path.exists());

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_ref_pattern_destructuring() {
    let src = r#"
struct Coord {
    x: i64,
    y: i64,
}

pub fn main() -> i64 {
    let c = Coord(x: 10, y: 32);
    let Coord { ref x, ref y } = c;
    return x + y;
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("llvm_ref_pat.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let temp_dir =
        std::env::temp_dir().join(format!("llvm_ref_pattern_test_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("ref_pattern.o");
    let bin_path = temp_dir.join("ref_pattern_exec");

    let compiler = LlvmCompiler::new(LlvmTargetConfig::host());
    let compile_res = compiler.compile_to_object(&module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Object compilation failed: {:?}",
        compile_res.err()
    );
    assert!(obj_path.exists());

    let link_res = LlvmCompiler::link_executable(&obj_path, &bin_path);
    assert!(link_res.is_ok(), "Native link failed: {:?}", link_res.err());
    assert!(bin_path.exists());

    let output = std::process::Command::new(&bin_path)
        .output()
        .expect("Failed to execute native binary");
    assert_eq!(
        output.status.code(),
        Some(42),
        "Native binary output exit code must be 42 (10 + 32)"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_tuple_ref_pattern_destructuring() {
    let src = r#"
pub fn main() -> i64 {
    let pair = (40, 2);
    let (ref a, ref b) = pair;
    return a + b;
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("llvm_tup_ref_pat.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let temp_dir = std::env::temp_dir().join(format!(
        "llvm_tuple_ref_pattern_test_{}",
        std::process::id()
    ));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("tuple_ref_pattern.o");
    let bin_path = temp_dir.join("tuple_ref_pattern_exec");

    let compiler = LlvmCompiler::new(LlvmTargetConfig::host());
    let compile_res = compiler.compile_to_object(&module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Object compilation failed: {:?}",
        compile_res.err()
    );
    assert!(obj_path.exists());

    let link_res = LlvmCompiler::link_executable(&obj_path, &bin_path);
    assert!(link_res.is_ok(), "Native link failed: {:?}", link_res.err());
    assert!(bin_path.exists());

    let output = std::process::Command::new(&bin_path)
        .output()
        .expect("Failed to execute native binary");
    assert_eq!(
        output.status.code(),
        Some(42),
        "Native binary output exit code must be 42 (40 + 2)"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_match_ref_pattern_destructuring() {
    let src = r#"
struct Coord {
    x: i64,
    y: i64,
}

pub fn main() -> i64 {
    let c = Coord(x: 100, y: 250);
    return match c {
        Coord { ref x, ref y } => x + y,
    };
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("llvm_match_ref_pat.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let temp_dir = std::env::temp_dir().join(format!(
        "llvm_match_ref_pattern_test_{}",
        std::process::id()
    ));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("match_ref_pattern.o");
    let bin_path = temp_dir.join("match_ref_pattern_exec");

    let compiler = LlvmCompiler::new(LlvmTargetConfig::host());
    let compile_res = compiler.compile_to_object(&module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Object compilation failed: {:?}",
        compile_res.err()
    );
    assert!(obj_path.exists());

    let link_res = LlvmCompiler::link_executable(&obj_path, &bin_path);
    assert!(link_res.is_ok(), "Native link failed: {:?}", link_res.err());
    assert!(bin_path.exists());

    let output = std::process::Command::new(&bin_path)
        .output()
        .expect("Failed to execute native binary");
    assert_eq!(
        output.status.code(),
        Some(94), // 350 % 256 = 94 car exit status est sur 8 bits (0-255)
        "Native binary output exit code must be 94 (350 % 256)"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_nested_graph_destructuring_ref_bindings() {
    let src = r#"
struct TargetNode {
    value: i64,
}

struct Edge {
    weight: i64,
    target: ref TargetNode,
}

struct GraphNode {
    id: i64,
    edge: Edge,
}

pub fn main() -> i64 {
    let t = TargetNode(value: 50);
    let ref target_ref = t;
    let g = GraphNode(id: 3, edge: Edge(weight: 12, target: target_ref));
    let GraphNode { id, edge: Edge { weight, ref target } } = g;
    return id + weight + target.value;
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("llvm_nested_graph.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let temp_dir =
        std::env::temp_dir().join(format!("llvm_nested_graph_test_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("nested_graph.o");
    let bin_path = temp_dir.join("nested_graph_exec");

    let compiler = LlvmCompiler::new(LlvmTargetConfig::host());
    let compile_res = compiler.compile_to_object(&module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Object compilation failed: {:?}",
        compile_res.err()
    );
    assert!(obj_path.exists());

    let link_res = LlvmCompiler::link_executable(&obj_path, &bin_path);
    assert!(link_res.is_ok(), "Native link failed: {:?}", link_res.err());
    assert!(bin_path.exists());

    let output = std::process::Command::new(&bin_path)
        .output()
        .expect("Failed to execute native binary");
    assert_eq!(
        output.status.code(),
        Some(65),
        "Native binary output exit code must be 65 (3 + 12 + 50)"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_for_loop_pattern_destructuring_native_execution() {
    let src = r#"
        pub fn main() -> i64 {
            let pairs = [(1, 10), (2, 20), (3, 30)];
            mut sum = 0;
            for (x, y) in pairs {
                sum = sum + x * y;
            }
            return sum;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("for_tuple_llvm.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let temp_dir = std::env::temp_dir().join(format!("ifa_llvm_for_tuple_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("for_tuple.o");
    let bin_path = temp_dir.join("for_tuple_exec");

    let compiler = LlvmCompiler::new(LlvmTargetConfig::host());
    let compile_res = compiler.compile_to_object(&fir_module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Object compilation failed: {:?}",
        compile_res.err()
    );
    assert!(obj_path.exists());

    let link_res = LlvmCompiler::link_executable(&obj_path, &bin_path);
    assert!(link_res.is_ok(), "Native link failed: {:?}", link_res.err());
    assert!(bin_path.exists());

    let output = std::process::Command::new(&bin_path)
        .output()
        .expect("Failed to execute native binary");
    assert_eq!(
        output.status.code(),
        Some(140),
        "Native binary output exit code must be 140 (1*10 + 2*20 + 3*30)"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_aot_destructuring_let_else() {
    let src = r#"
        enum Opt {
            Val(i64),
            None,
        }

        fn extract(o: Opt) -> i64 {
            let Opt::Val(x) = o else {
                return 15;
            };
            return x * 3;
        }

        pub fn main() -> i64 {
            let a = extract(Opt::Val(10));
            let b = extract(Opt::None);
            return a + b;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("llvm_let_else.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let temp_dir = std::env::temp_dir().join(format!("ifa_llvm_let_else_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("let_else.o");
    let bin_path = temp_dir.join("let_else_exec");

    let compiler = LlvmCompiler::new(LlvmTargetConfig::host());
    let compile_res = compiler.compile_to_object(&fir_module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Object compilation failed: {:?}",
        compile_res.err()
    );
    assert!(obj_path.exists());

    let link_res = LlvmCompiler::link_executable(&obj_path, &bin_path);
    assert!(link_res.is_ok(), "Native link failed: {:?}", link_res.err());
    assert!(bin_path.exists());

    let output = std::process::Command::new(&bin_path)
        .output()
        .expect("Failed to execute native binary");
    // a: 10 * 3 = 30, b: 15 => 45
    assert_eq!(
        output.status.code(),
        Some(45),
        "Native binary output exit code must be 45"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_aot_closures_and_lambdas() {
    let src = r#"
        pub fn main() -> i64 {
            let factor: i64 = 4;
            let multiplier = fn(x: i64) -> i64 {
                return x * factor;
            };
            let cube = fn(n: i64) -> i64 {
                return n * n * n;
            };
            let a = multiplier(9);
            let b = cube(3);
            return a + b;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("llvm_closures.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let temp_dir = std::env::temp_dir().join(format!("ifa_llvm_closure_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("closure.o");
    let bin_path = temp_dir.join("closure_exec");

    let compiler = LlvmCompiler::new(LlvmTargetConfig::host());
    let compile_res = compiler.compile_to_object(&fir_module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Object compilation failed: {:?}",
        compile_res.err()
    );
    assert!(obj_path.exists());

    let link_res = LlvmCompiler::link_executable(&obj_path, &bin_path);
    assert!(link_res.is_ok(), "Native link failed: {:?}", link_res.err());
    assert!(bin_path.exists());

    let output = std::process::Command::new(&bin_path)
        .output()
        .expect("Failed to execute native binary");
    assert_eq!(
        output.status.code(),
        Some(63),
        "Native binary output exit code must be 63"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_aot_higher_order_closures() {
    let src = r#"
        pub fn apply(f: fn(i64) -> i64, val: i64) -> i64 {
            return f(val);
        }

        pub fn main() -> i64 {
            let offset: i64 = 15;
            let add_offset = fn(x: i64) -> i64 {
                return x + offset;
            };
            return apply(add_offset, 27);
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("llvm_higher_order.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let temp_dir = std::env::temp_dir().join(format!("ifa_llvm_ho_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("ho.o");
    let bin_path = temp_dir.join("ho_exec");

    let compiler = LlvmCompiler::new(LlvmTargetConfig::host());
    let compile_res = compiler.compile_to_object(&fir_module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Object compilation failed: {:?}",
        compile_res.err()
    );
    assert!(obj_path.exists());

    let link_res = LlvmCompiler::link_executable(&obj_path, &bin_path);
    assert!(link_res.is_ok(), "Native link failed: {:?}", link_res.err());
    assert!(bin_path.exists());

    let output = std::process::Command::new(&bin_path)
        .output()
        .expect("Failed to execute native binary");
    assert_eq!(
        output.status.code(),
        Some(42),
        "Native binary output exit code must be 42 (15 + 27)"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_aot_named_function_pointer_dispatch() {
    let src = r#"
        pub fn square(x: i64) -> i64 {
            return x * x;
        }

        pub fn inc(x: i64) -> i64 {
            return x + 1;
        }

        pub fn apply(f: fn(i64) -> i64, val: i64) -> i64 {
            return f(val);
        }

        pub fn main() -> i64 {
            let a = apply(square, 6); // 36
            let b = apply(inc, a);    // 37
            return b;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("llvm_named_fn.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let temp_dir = std::env::temp_dir().join(format!("ifa_llvm_fn_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("fn.o");
    let bin_path = temp_dir.join("fn_exec");

    let compiler = LlvmCompiler::new(LlvmTargetConfig::host());
    let compile_res = compiler.compile_to_object(&fir_module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Object compilation failed: {:?}",
        compile_res.err()
    );
    assert!(obj_path.exists());

    let link_res = LlvmCompiler::link_executable(&obj_path, &bin_path);
    assert!(link_res.is_ok(), "Native link failed: {:?}", link_res.err());
    assert!(bin_path.exists());

    let output = std::process::Command::new(&bin_path)
        .output()
        .expect("Failed to execute native binary");
    assert_eq!(
        output.status.code(),
        Some(37),
        "Native binary output exit code must be 37 (6*6 + 1)"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_aot_dynamic_function_pointer_dispatch() {
    let src = r#"
        pub fn add_ten(x: i64) -> i64 {
            return x + 10;
        }

        pub fn add_twenty(x: i64) -> i64 {
            return x + 20;
        }

        pub fn compute(cond: bool, val: i64) -> i64 {
            mut f = add_ten;
            if cond {
                f = add_twenty;
            }
            return f(val);
        }

        pub fn main() -> i64 {
            let r1 = compute(false, 5); // 15
            let r2 = compute(true, 5);  // 25
            return r1 + r2;            // 40
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("llvm_dyn_fn.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let temp_dir = std::env::temp_dir().join(format!("ifa_llvm_dyn_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("dyn.o");
    let bin_path = temp_dir.join("dyn_exec");

    let compiler = LlvmCompiler::new(LlvmTargetConfig::host());
    let compile_res = compiler.compile_to_object(&fir_module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Object compilation failed: {:?}",
        compile_res.err()
    );
    assert!(obj_path.exists());

    let link_res = LlvmCompiler::link_executable(&obj_path, &bin_path);
    assert!(link_res.is_ok(), "Native link failed: {:?}", link_res.err());
    assert!(bin_path.exists());

    let output = std::process::Command::new(&bin_path)
        .output()
        .expect("Failed to execute native binary");
    assert_eq!(
        output.status.code(),
        Some(40),
        "Native binary output exit code must be 40 (15 + 25)"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_string_interpolation_and_concatenation() {
    let src = r#"
        pub fn format_dynamic_user(user: String, version: i64) -> String {
            let msg = "Welcome to {user} v{version}!";
            let extra = " Ready.";
            return msg + extra;
        }

        pub fn main() -> i64 {
            let full = format_dynamic_user("System", 1);
            return 77;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("llvm_interp.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

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

    assert!(llvm_ir.contains("call ptr @ifa_rt_string_concat"));
    assert!(llvm_ir.contains("call ptr @ifa_rt_string_from_i64"));

    let temp_dir = std::env::temp_dir().join(format!("ifa_llvm_str_interp_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("str.o");
    let bin_path = temp_dir.join("str_exec");

    let compiler = LlvmCompiler::new(target);
    let compile_res = compiler.compile_to_object(&fir_module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Object compilation failed: {:?}",
        compile_res.err()
    );

    let link_res = LlvmCompiler::link_executable(&obj_path, &bin_path);
    assert!(link_res.is_ok(), "Native link failed: {:?}", link_res.err());

    let output = std::process::Command::new(&bin_path)
        .output()
        .expect("Failed to execute native binary");
    assert_eq!(output.status.code(), Some(77));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_range_for_loop_and_sub_slicing_execution() {
    let src = r#"
        pub fn main() -> i64 {
            mut sum: i64 = 0;
            for i in 1..=10 {
                sum = sum + i;
            }

            let data: [i64; 5] = [1, 2, 3, 4, 5];
            let sub = data[1..3];
            mut sub_sum: i64 = 0;
            for v in sub {
                sub_sum = sub_sum + v;
            }

            return sum + sub_sum;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("range_exec_test.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parse diags: {:?}", diags);

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

    assert!(llvm_ir.contains("getelementptr inbounds i64, ptr"));

    let temp_dir = std::env::temp_dir().join(format!("ifa_llvm_range_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("range.o");
    let bin_path = temp_dir.join("range_exec");

    let compiler = LlvmCompiler::new(target);
    let compile_res = compiler.compile_to_object(&fir_module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Object compilation failed: {:?}",
        compile_res.err()
    );

    let link_res = LlvmCompiler::link_executable(&obj_path, &bin_path);
    assert!(link_res.is_ok(), "Native link failed: {:?}", link_res.err());

    let output = std::process::Command::new(&bin_path)
        .output()
        .expect("Failed to execute native binary");
    assert_eq!(output.status.code(), Some(60));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_slice_fat_pointer_inter_function_passing_and_execution() {
    let src = r#"
        fn sum_slice(s: Slice<i64>) -> i64 {
            mut total: i64 = 0;
            for x in s {
                total = total + x;
            }
            return total;
        }

        fn inspect_slice_endpoints(s: Slice<i64>) -> i64 {
            let n = s.len();
            if n == 0 {
                return 0;
            }
            let first = s[0];
            let last = s[n - 1];
            return first * 100 + last;
        }

        fn sub_slice_passthrough(s: Slice<i64>) -> i64 {
            let sub = s[1..3];
            return sum_slice(sub);
        }

        fn extract_sub_slice(s: Slice<i64>) -> Slice<i64> {
            return s[1..3];
        }

        pub fn main() -> i64 {
            let ledger: [i64; 6] = [10, 20, 30, 40, 50, 60];

            // 1. Pass sub-slice ledger[1..4] (20, 30, 40) -> sum = 90
            let window = ledger[1..4];
            let sum1 = sum_slice(window);

            // 2. Coerce entire array to Slice parameter -> sum = 210
            let sum_all = sum_slice(ledger);

            // 3. Inspect endpoints on window (len 3, first 20, last 40) -> 2040
            let endpoints = inspect_slice_endpoints(window);

            // 4. Nested sub-slicing on Slice parameter: ledger[1..5] -> sub[1..3] -> 70
            let wider = ledger[1..5];
            let sum_nested = sub_slice_passthrough(wider);

            // 5. Returning a Slice<T> dynamically from a function
            let extracted = extract_sub_slice(wider);
            let sum_extracted = sum_slice(extracted);

            let grand_total = sum1 + sum_all + endpoints + sum_nested + sum_extracted;

            if grand_total == 2480 {
                return 42;
            }

            return 1;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("slice_fat_ptr_test.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parse diags: {:?}", diags);

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

    // Verify fat pointer { ptr, i64 } signatures and operations
    assert!(
        llvm_ir.contains("{ ptr, i64 }"),
        "LLVM IR must define and pass {{ ptr, i64 }} fat pointers"
    );
    assert!(
        llvm_ir.contains("@sum_slice({ ptr, i64 }"),
        "Function must receive fat pointer {{ ptr, i64 }}: {}",
        llvm_ir
    );

    let temp_dir = std::env::temp_dir().join(format!("ifa_llvm_slice_fat_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("slice_fat.o");
    let bin_path = temp_dir.join("slice_fat_exec");

    let compiler = LlvmCompiler::new(target);
    let compile_res = compiler.compile_to_object(&fir_module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Object compilation failed: {:?}",
        compile_res.err()
    );

    let link_res = LlvmCompiler::link_executable(&obj_path, &bin_path);
    assert!(link_res.is_ok(), "Native link failed: {:?}", link_res.err());

    let output = std::process::Command::new(&bin_path)
        .output()
        .expect("Failed to execute native binary");
    assert_eq!(output.status.code(), Some(42));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_vector_branchcond_and_arena_genalloc() {
    use ifa_fir::*;
    use ifa_span::Span;

    let target = LlvmTargetConfig::x86_64();
    let mut emitter = LlvmIrEmitter::new(&target);

    let mut func = FirFunction::new(
        ifa_span::INTERNER.intern("test_arena_and_vec"),
        vec![],
        FirType::Unit,
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );

    // FirFunction::new already creates bb0 (entry), clear it or reuse it
    func.blocks.clear();

    let mut bb0 = BasicBlock::new(BlockId(0));
    bb0.instructions.push(Instruction::new(
        Some(ValueId(1)),
        ValueExpr::GenAlloc {
            ty: FirType::Int(ifa_sema::types::IntType::I64),
            arena: Some(42),
        },
        Span::DUMMY,
    ));
    bb0.terminator = Some(Terminator::Branch {
        target: BlockId(1),
        args: Vec::new(),
    });
    func.blocks.push(bb0);

    let mut bb1 = BasicBlock::new(BlockId(1));
    bb1.set_vector_hint(LoopVectorHint::new(8, 4, true));
    bb1.instructions.push(Instruction::new(
        Some(ValueId(2)),
        ValueExpr::Constant(ConstantValue::Bool(true)),
        Span::DUMMY,
    ));
    bb1.terminator = Some(Terminator::BranchCond {
        cond: ValueId(2),
        then_block: BlockId(1),
        else_block: BlockId(2),
        then_args: Vec::new(),
        else_args: Vec::new(),
    });
    func.blocks.push(bb1);

    let mut bb2 = BasicBlock::new(BlockId(2));
    bb2.terminator = Some(Terminator::Return(None));
    func.blocks.push(bb2);

    let module = FirModule {
        name: ifa_span::INTERNER.intern("arena_vec_mod"),
        functions: vec![func],
        structs: Vec::new(),
        enums: Vec::new(),
        constants: Vec::new(),
    };

    let ir = emitter.emit_module(&module).unwrap();

    // Verify arena allocation with correct arena_id 42 and footprint size 8
    assert!(
        ir.contains("call ptr @ifa_rt_gen_alloc(i64 8, i64 8, i16 42)"),
        "LLVM IR must emit gen_alloc with size 8, align 8, arena 42: {}",
        ir
    );

    // Verify BranchCond with vector_hint emits loop metadata
    assert!(
        ir.contains("br i1 %v2, label %bb1, label %bb2, !llvm.loop !1"),
        "LLVM IR BranchCond must emit !llvm.loop !1: {}",
        ir
    );
}

#[test]
fn test_llvm_coroutine_channel_untyped_and_select_multiplexing() {
    use ifa_codegen_llvm::compiler::LlvmCompiler;
    use ifa_codegen_llvm::ir_emitter::LlvmIrEmitter;
    use ifa_codegen_llvm::target::LlvmTargetConfig;
    use ifa_fir::{
        BasicBlock, BlockId, ConstantValue, FirFunction, FirModule, FirType, Instruction,
        Terminator, ValueExpr, ValueId,
    };
    use ifa_sema::types::IntType;
    use ifa_span::{Span, INTERNER};
    use std::fs;

    let target = LlvmTargetConfig::x86_64();
    let mut emitter = LlvmIrEmitter::new(&target);

    let fn_name = INTERNER.intern("coro_channel_worker");
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

    // Create two untyped channels
    let ch1 = ValueId(1);
    bb0.instructions.push(Instruction::new(
        Some(ch1),
        ValueExpr::ChanCreate {
            elem_ty: FirType::Int(IntType::I64),
            capacity: None,
        },
        Span::DUMMY,
    ));

    let ch2 = ValueId(2);
    bb0.instructions.push(Instruction::new(
        Some(ch2),
        ValueExpr::ChanCreate {
            elem_ty: FirType::Int(IntType::I64),
            capacity: Some(ValueId(3)),
        },
        Span::DUMMY,
    ));

    // Send untyped integer value over ch1
    let val_to_send = ValueId(4);
    bb0.instructions.push(Instruction::new(
        Some(val_to_send),
        ValueExpr::Constant(ConstantValue::Int(1337, IntType::I64)),
        Span::DUMMY,
    ));
    bb0.instructions.push(Instruction::new(
        None,
        ValueExpr::ChanSend {
            chan: ch1,
            val: val_to_send,
        },
        Span::DUMMY,
    ));

    // Direct multi-channel select multiplexing in coroutine without default clause
    let sel_res = ValueId(5);
    bb0.instructions.push(Instruction::new(
        Some(sel_res),
        ValueExpr::ChanSelect {
            channels: vec![ch1, ch2],
            has_default: false,
            timeout: None,
            priorities: vec![0, 0],
        },
        Span::DUMMY,
    ));

    // Untyped channel receive with coroutine suspension
    let recv_res = ValueId(6);
    bb0.instructions.push(Instruction::new(
        Some(recv_res),
        ValueExpr::ChanRecv { chan: ch1 },
        Span::DUMMY,
    ));

    bb0.terminator = Some(Terminator::Return(None));
    func.blocks.push(bb0);

    let module = FirModule {
        name: INTERNER.intern("coro_chan_mod"),
        functions: vec![func],
        structs: Vec::new(),
        enums: Vec::new(),
        constants: Vec::new(),
    };

    let ir = emitter.emit_module(&module).unwrap();

    // 1. Verify coroutine LLVM attributes and intrinsics
    assert!(ir.contains("define dso_local ptr @coro_channel_worker() presplitcoroutine"));
    assert!(ir.contains("call token @llvm.coro.id("));
    assert!(ir.contains("call ptr @llvm.coro.begin("));

    // 2. Verify untyped send cast and non-blocking ring buffer try_send with suspension
    assert!(ir.contains("%chan_val_cast_4 = inttoptr i64 %v4 to ptr"));
    assert!(ir.contains("call i32 @ifa_rt_channel_try_send(ptr %v1, ptr %chan_val_cast_4)"));
    assert!(ir.contains("br label %coro.send_poll_"));

    // 3. Verify multi-channel select multiplexing with zero-allocation wait table and stackless suspension
    assert!(ir.contains("%select_entries_5 = alloca [2 x %struct.ifa_select_wait_entry], align 8"));
    assert!(ir.contains("%select_table_5 = alloca %struct.ifa_select_wait_table, align 8"));
    assert!(ir.contains("br label %coro.sel_poll_"));
    assert!(ir.contains("@ifa_rt_channel_select_table(ptr %select_table_5)"));
    assert!(ir.contains("%sel_is_waiting_5_"));
    assert!(ir.contains("call i8 @llvm.coro.suspend(token none, i1 false)"));
    assert!(ir.contains("%v5 = phi i64 [ %sel_poll_res_5_"));

    // 4. Verify channel receive with stackless suspension
    assert!(ir.contains("br label %coro.recv_poll_"));
    assert!(ir.contains("call i32 @ifa_rt_channel_try_recv(ptr %v1, ptr %chan_out_slot_6)"));
    assert!(ir.contains("%v6 = ptrtoint ptr %chan_raw_6 to i64"));

    // 5. Compile to native object using Clang to guarantee valid LLVM IR
    let temp_dir = std::env::temp_dir().join(format!("llvm_chan_coro_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("chan_coro.o");

    let compiler = LlvmCompiler::new(LlvmTargetConfig::host());
    let compile_res = compiler.compile_to_object(&module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Native compilation of channel coroutine module failed: {:?}",
        compile_res.err()
    );
    assert!(obj_path.exists());
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_wasm32_coroutine_stackless_suspension() {
    use ifa_codegen_llvm::compiler::LlvmCompiler;
    use ifa_codegen_llvm::ir_emitter::LlvmIrEmitter;
    use ifa_codegen_llvm::target::LlvmTargetConfig;
    use ifa_fir::{
        BasicBlock, BlockId, ConstantValue, FirFunction, FirModule, FirType, Instruction,
        Terminator, ValueExpr, ValueId,
    };
    use ifa_sema::types::IntType;
    use ifa_span::{Span, INTERNER};
    use std::fs;

    let wasm_target = LlvmTargetConfig::wasm32_wasi();
    let mut emitter = LlvmIrEmitter::new(&wasm_target);

    let fn_name = INTERNER.intern("wasm_generator");
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
    bb0.instructions
        .push(Instruction::new(None, ValueExpr::Yield, Span::DUMMY));
    let val_id = ValueId(1);
    bb0.instructions.push(Instruction::new(
        Some(val_id),
        ValueExpr::Constant(ConstantValue::Int(42, IntType::I64)),
        Span::DUMMY,
    ));
    bb0.instructions
        .push(Instruction::new(None, ValueExpr::Yield, Span::DUMMY));
    bb0.terminator = Some(Terminator::Return(None));
    func.blocks.push(bb0);

    let module = FirModule {
        name: INTERNER.intern("wasm_coro_mod"),
        functions: vec![func],
        structs: Vec::new(),
        enums: Vec::new(),
        constants: Vec::new(),
    };

    let ir = emitter.emit_module(&module).unwrap();

    // 1. Verify wasm32-unknown-wasi target configuration
    assert!(ir.contains("target triple = \"wasm32-unknown-wasi\""));
    assert!(ir.contains("declare i32 @llvm.coro.size.i32()"));
    assert!(ir.contains("%coro.size.32 = call i32 @llvm.coro.size.i32()"));
    assert!(ir.contains("%coro.size = zext i32 %coro.size.32 to i64"));
    assert!(ir.contains("call ptr @ifa_rt_gen_alloc(i64 %coro.size, i64 8, i16 0)"));
    assert!(ir.contains("call i8 @llvm.coro.suspend(token none, i1 false)"));

    // 2. Compile to standalone WebAssembly module (.wasm) with wasm-ld
    let temp_dir = std::env::temp_dir().join(format!("llvm_wasm_coro_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let wasm_path = temp_dir.join("wasm_coro.wasm");

    let compiler = LlvmCompiler::new(wasm_target);
    let compile_res = compiler.compile_to_wasm(&module, &wasm_path);
    assert!(
        compile_res.is_ok(),
        "WebAssembly compilation of coroutine module failed: {:?}",
        compile_res.err()
    );
    assert!(wasm_path.exists());

    // 3. Verify valid WebAssembly binary header (\0asm)
    let wasm_bytes = fs::read(&wasm_path).unwrap();
    assert!(wasm_bytes.len() >= 8);
    assert_eq!(&wasm_bytes[0..4], b"\0asm");
    assert_eq!(&wasm_bytes[4..8], &[1, 0, 0, 0]);

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_vector_memory_alignment_avx512_and_neon() {
    let src = r#"
        pub fn make_avx512() -> [f64; 64] {
            // AVX-512 vector array (64 * 8 = 512 bytes -> align 64)
            mut big_vec = [0.0; 64];
            return big_vec;
        }

        pub fn make_avx2() -> [f64; 4] {
            // AVX2 vector array (4 * 8 = 32 bytes -> align 32)
            mut avx2_vec = [0.0; 4];
            return avx2_vec;
        }

        pub fn make_neon() -> [f64; 2] {
            // ARM Neon / SSE vector array (2 * 8 = 16 bytes -> align 16)
            mut neon_vec = [0.0; 2];
            return neon_vec;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("vec_align.ifa".to_string(), src);
    let (prog, diags) = parse(fid, tokenize(fid, src));
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let target = LlvmTargetConfig::x86_64();
    let mut emitter = LlvmIrEmitter::new(&target);
    let ir = emitter
        .emit_module(&module)
        .expect("LLVM IR emission failed");

    // Verify AVX-512 64-byte cacheline alignment
    assert!(
        ir.contains("alloca [64 x double], align 64"),
        "Expected AVX-512 64-byte alignment for 64-element double array:\n{}",
        ir
    );
    // Verify AVX2 32-byte alignment
    assert!(
        ir.contains("alloca [4 x double], align 32"),
        "Expected AVX2 32-byte alignment for 4-element double array:\n{}",
        ir
    );
    // Verify ARM Neon 16-byte alignment
    assert!(
        ir.contains("alloca [2 x double], align 16"),
        "Expected ARM Neon 16-byte alignment for 2-element double array:\n{}",
        ir
    );
}

#[test]
fn test_llvm_coroutine_iterator_generator_lowering() {
    use ifa_codegen_llvm::compiler::LlvmCompiler;
    use ifa_codegen_llvm::ir_emitter::LlvmIrEmitter;
    use ifa_codegen_llvm::target::LlvmTargetConfig;
    use ifa_fir::{
        BasicBlock, BlockId, ConstantValue, FirFunction, FirModule, FirType, Instruction,
        Terminator, ValueExpr, ValueId,
    };
    use ifa_sema::types::IntType;
    use ifa_span::{Span, INTERNER};
    use std::fs;

    let target = LlvmTargetConfig::x86_64();
    let mut emitter = LlvmIrEmitter::new(&target);

    let gen_name = INTERNER.intern("range_generator");
    let mut func = FirFunction::new(
        gen_name,
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
    let val1 = ValueId(1);
    bb0.instructions.push(Instruction::new(
        Some(val1),
        ValueExpr::Constant(ConstantValue::Int(100, IntType::I64)),
        Span::DUMMY,
    ));
    bb0.instructions.push(Instruction::new(
        None,
        ValueExpr::YieldValue { val: val1 },
        Span::DUMMY,
    ));

    let val2 = ValueId(2);
    bb0.instructions.push(Instruction::new(
        Some(val2),
        ValueExpr::Constant(ConstantValue::Int(200, IntType::I64)),
        Span::DUMMY,
    ));
    bb0.instructions.push(Instruction::new(
        None,
        ValueExpr::YieldValue { val: val2 },
        Span::DUMMY,
    ));

    bb0.terminator = Some(Terminator::Return(None));
    func.blocks.push(bb0);

    let module = FirModule {
        name: INTERNER.intern("range_gen_mod"),
        functions: vec![func],
        structs: Vec::new(),
        enums: Vec::new(),
        constants: Vec::new(),
    };

    let ir = emitter.emit_module(&module).unwrap();

    // 1. Verify standard LLVM coroutine attributes and intrinsic bindings
    assert!(ir.contains("define dso_local ptr @range_generator() presplitcoroutine"));
    assert!(
        ir.contains("call token @llvm.coro.id(i32 8, ptr %coro.yield_slot, ptr null, ptr null)")
    );
    assert!(ir.contains("call ptr @llvm.coro.begin("));
    assert!(ir.contains("store i64 %v1, ptr %coro.yield_slot, align 8"));
    assert!(ir.contains("store i64 %v2, ptr %coro.yield_slot, align 8"));
    assert!(ir.contains("call i8 @llvm.coro.suspend(token none, i1 false)"));
    assert!(ir.contains("declare ptr @llvm.coro.promise(ptr, i32, i1)"));
    assert!(ir.contains("define linkonce_odr ptr @ifa_coro_generator_yield_ptr(ptr %hdl)"));
    assert!(ir.contains(
        "define linkonce_odr ptr @ifa_coro_generator_iter_create(ptr %hdl, i64 %elem_size)"
    ));
    assert!(ir.contains(
        "define linkonce_odr i32 @ifa_coro_generator_iter_next(ptr %iter, ptr %out_val)"
    ));

    // 2. Verify compilation to native object via Clang
    let temp_dir = std::env::temp_dir().join(format!("llvm_gen_iter_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("gen_iter.o");

    let compiler = LlvmCompiler::new(LlvmTargetConfig::host());
    let compile_res = compiler.compile_to_object(&module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Native compilation of iterator generator module failed: {:?}",
        compile_res.err()
    );
    assert!(obj_path.exists());
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_wasm32_stackless_iterator_generator_lowering() {
    use ifa_codegen_llvm::compiler::LlvmCompiler;
    use ifa_codegen_llvm::ir_emitter::LlvmIrEmitter;
    use ifa_codegen_llvm::target::LlvmTargetConfig;
    use ifa_fir::{
        BasicBlock, BlockId, ConstantValue, FirFunction, FirModule, FirType, Instruction,
        Terminator, ValueExpr, ValueId,
    };
    use ifa_sema::types::IntType;
    use ifa_span::{Span, INTERNER};
    use std::fs;

    let wasm_target = LlvmTargetConfig::wasm32_wasi();
    let mut emitter = LlvmIrEmitter::new(&wasm_target);

    let fn_name = INTERNER.intern("wasm_counter_gen");
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
    let v1 = ValueId(1);
    bb0.instructions.push(Instruction::new(
        Some(v1),
        ValueExpr::Constant(ConstantValue::Int(42, IntType::I64)),
        Span::DUMMY,
    ));
    bb0.instructions.push(Instruction::new(
        None,
        ValueExpr::YieldValue { val: v1 },
        Span::DUMMY,
    ));

    let v2 = ValueId(2);
    bb0.instructions.push(Instruction::new(
        Some(v2),
        ValueExpr::Constant(ConstantValue::Int(84, IntType::I64)),
        Span::DUMMY,
    ));
    bb0.instructions.push(Instruction::new(
        None,
        ValueExpr::YieldValue { val: v2 },
        Span::DUMMY,
    ));

    bb0.terminator = Some(Terminator::Return(None));
    func.blocks.push(bb0);

    let module = FirModule {
        name: INTERNER.intern("wasm_counter_pkg"),
        functions: vec![func],
        structs: Vec::new(),
        enums: Vec::new(),
        constants: Vec::new(),
    };

    let ir = emitter.emit_module(&module).unwrap();

    // 1. Verify WebAssembly-specific stackless emission
    assert!(ir.contains("target triple = \"wasm32-unknown-wasi\""));
    assert!(ir.contains("declare i32 @llvm.coro.size.i32()"));
    assert!(ir.contains("declare void @llvm.memcpy.p0.p0.i32(ptr noalias nocapture writeonly, ptr noalias nocapture readonly, i32, i1 immarg)"));
    assert!(ir.contains("define dso_local i32 @ifa_wasm_coro_step(ptr %hdl)"));
    assert!(ir.contains("define dso_local i32 @ifa_wasm_coro_iter_next(ptr %hdl, ptr %yield_slot, ptr %out_val, i32 %size)"));
    assert!(ir.contains(
        "define dso_local i32 @ifa_wasm_generator_next(ptr %hdl, ptr %out_val, i32 %size)"
    ));
    assert!(ir.contains("define dso_local void @ifa_wasm_coro_destroy(ptr %hdl)"));

    // 2. Compile to standalone WebAssembly module (.wasm)
    let temp_dir = std::env::temp_dir().join(format!("llvm_wasm_gen_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let wasm_path = temp_dir.join("counter_gen.wasm");

    let compiler = LlvmCompiler::new(wasm_target);
    let compile_res = compiler.compile_to_wasm(&module, &wasm_path);
    assert!(
        compile_res.is_ok(),
        "WebAssembly compilation of counter generator failed: {:?}",
        compile_res.err()
    );
    assert!(wasm_path.exists());

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_blocking_ffi_isolation_and_thunk_lowering() {
    use ifa_codegen_llvm::compiler::LlvmCompiler;
    use ifa_codegen_llvm::ir_emitter::LlvmIrEmitter;
    use ifa_codegen_llvm::target::LlvmTargetConfig;
    use ifa_fir::{
        BasicBlock, BlockId, ConstantValue, FirFunction, FirModule, FirParam, FirType, Instruction,
        Terminator, ValueExpr, ValueId,
    };
    use ifa_sema::types::IntType;
    use ifa_span::{Span, INTERNER};
    use std::fs;

    let target = LlvmTargetConfig::x86_64();
    let mut emitter = LlvmIrEmitter::new(&target);

    // 1. Declare external blocking C function: blocking_c_calc(a: i64, b: i64) -> i64
    let ext_name = INTERNER.intern("blocking_c_calc");
    let ext_params = vec![
        FirParam {
            name: INTERNER.intern("a"),
            val: ValueId(1),
            ty: FirType::Int(IntType::I64),
            mode: ifa_fir::ParamMode::In,
            noalias: false,
        },
        FirParam {
            name: INTERNER.intern("b"),
            val: ValueId(2),
            ty: FirType::Int(IntType::I64),
            mode: ifa_fir::ParamMode::In,
            noalias: false,
        },
    ];
    let mut ext_func = FirFunction::new(
        ext_name,
        ext_params,
        FirType::Int(IntType::I64),
        false,
        true,
        false,
        Some("C".to_string()),
        Span::DUMMY,
    );
    ext_func.is_blocking = true;
    ext_func.blocks.clear();

    // 2. Define caller function: execute_task() -> i64
    let caller_name = INTERNER.intern("execute_task");
    let mut caller_func = FirFunction::new(
        caller_name,
        vec![],
        FirType::Int(IntType::I64),
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );
    caller_func.blocks.clear();

    let mut bb0 = BasicBlock::new(BlockId(0));
    let val_a = ValueId(10);
    bb0.instructions.push(Instruction::new(
        Some(val_a),
        ValueExpr::Constant(ConstantValue::Int(42, IntType::I64)),
        Span::DUMMY,
    ));
    let val_b = ValueId(11);
    bb0.instructions.push(Instruction::new(
        Some(val_b),
        ValueExpr::Constant(ConstantValue::Int(100, IntType::I64)),
        Span::DUMMY,
    ));

    let res_val = ValueId(12);
    bb0.instructions.push(Instruction::new(
        Some(res_val),
        ValueExpr::BlockingCallDirect {
            name: ext_name,
            args: vec![val_a, val_b],
        },
        Span::DUMMY,
    ));
    bb0.terminator = Some(Terminator::Return(Some(res_val)));
    caller_func.blocks.push(bb0);

    let module = FirModule {
        name: INTERNER.intern("blocking_ffi_mod"),
        functions: vec![ext_func, caller_func],
        structs: Vec::new(),
        enums: Vec::new(),
        constants: Vec::new(),
    };

    let ir = emitter.emit_module(&module).unwrap();

    // 3. Validate pack struct, thunk and isolated call in LLVM IR
    assert!(ir.contains("%struct.ifa_pack_blocking_c_calc = type { i64, i64, i64 }"));
    assert!(ir.contains("define internal ptr @ifa_thunk_blocking_blocking_c_calc(ptr %ctx)"));
    assert!(ir.contains("call i64 @blocking_c_calc("));
    assert!(ir.contains("%pack_12 = alloca %struct.ifa_pack_blocking_c_calc, align 8"));
    assert!(ir.contains("store i64 %v10, ptr %arg_slot_12_0, align 8"));
    assert!(ir.contains("store i64 %v11, ptr %arg_slot_12_1, align 8"));
    assert!(ir.contains(
        "call ptr @ifa_rt_blocking_call(ptr @ifa_thunk_blocking_blocking_c_calc, ptr %pack_12)"
    ));
    assert!(ir.contains("%v12 = load i64, ptr %res_slot_12, align 8"));

    // 4. Verify native compilation to valid object file
    let temp_dir = std::env::temp_dir().join(format!("llvm_blocking_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("blocking_test.o");

    let compiler = LlvmCompiler::new(LlvmTargetConfig::host());
    let compile_res = compiler.compile_to_object(&module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Native compilation of blocking FFI module failed: {:?}",
        compile_res.err()
    );
    assert!(obj_path.exists());
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_tail_call_optimization_emission() {
    let src = r#"
pub extern "C" strict fn sum_tail(n: i64, acc: i64) -> i64 {
    if n <= 0 {
        return acc
    }
    return sum_tail(n - 1, acc + n)
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("tco_llvm.ifa".to_string(), src);
    let (prog, diags) = parse(fid, tokenize(fid, src));
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    // Compile with IPO/TCO enabled
    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let target = LlvmTargetConfig::host();
    let mut emitter = LlvmIrEmitter::new(&target);
    let ir = emitter.emit_module(&module).unwrap();

    // 1. Validate that the self-recursive call was eliminated from LLVM IR
    assert!(
        !ir.contains("call i64 @sum_tail("),
        "Recursive call @sum_tail must be replaced with a loop in LLVM IR:\n{}",
        ir
    );

    // 2. Validate that PHI nodes for SSA loop parameters are present
    assert!(
        ir.contains("phi i64"),
        "LLVM IR must contain phi nodes for iterative loop parameters:\n{}",
        ir
    );

    // 3. Verify native compilation to valid object file
    let temp_dir = std::env::temp_dir().join(format!("llvm_tco_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("tco_test.o");

    let compiler = LlvmCompiler::new(target);
    let compile_res = compiler.compile_to_object(&module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Native compilation of TCO module failed: {:?}",
        compile_res.err()
    );
    assert!(obj_path.exists());
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_inlined_generational_check_with_quarantine_and_liveness() {
    let src = r#"
        struct Data {
            value: i64,
        }

        fn read_val(d: ref Data) -> i64 {
            return d.value;
        }

        pub fn main() -> i64 {
            let d = Data(value: 84);
            return read_val(ref d);
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("gen_check_test.ifa".to_string(), src);
    let (prog, _) = parse(fid, tokenize(fid, src));
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module_unopt = compile_to_fir(&prog, &analysis.symbols, false, false).unwrap();

    let target = LlvmTargetConfig::host();
    let mut emitter = LlvmIrEmitter::new(&target);
    let ir = emitter.emit_module(&module_unopt).unwrap();

    // 1. Validate inlined generation check definition with liveness and quarantine validation
    assert!(
        ir.contains("define linkonce_odr void @ifa_rt_gen_check(ptr %ptr, i32 %remembered_gen) alwaysinline"),
        "LLVM IR must declare inlined @ifa_rt_gen_check:\n{}",
        ir
    );
    assert!(
        ir.contains("%flags_ptr = getelementptr inbounds i8, ptr %ptr, i64 -4"),
        "Must access allocation flags at header offset -4:\n{}",
        ir
    );
    assert!(
        ir.contains("%is_active = icmp eq i16 %act_bit, 1"),
        "Must validate FLAG_ACTIVE:\n{}",
        ir
    );
    assert!(
        ir.contains("%not_quar = icmp eq i16 %quar_bit, 0"),
        "Must validate absence of FLAG_QUARANTINED:\n{}",
        ir
    );
    assert!(
        ir.contains("!0 = !{!\"branch_weights\", i32 1048576, i32 1}"),
        "Must contain branch weight metadata for zero-overhead branch prediction:\n{}",
        ir
    );

    // 2. Compile optimized module to native object and verify valid execution
    let module_opt = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let temp_dir = std::env::temp_dir().join(format!("llvm_gen_check_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("gen_check.o");
    let bin_path = temp_dir.join("gen_check_bin");

    let compiler = LlvmCompiler::new(target);
    let compile_res = compiler.compile_to_object(&module_opt, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Native compilation failed: {:?}",
        compile_res.err()
    );
    assert!(obj_path.exists());

    let link_res = LlvmCompiler::link_executable(&obj_path, &bin_path);
    assert!(
        link_res.is_ok(),
        "Native linking failed: {:?}",
        link_res.err()
    );
    assert!(bin_path.exists());

    let output = std::process::Command::new(&bin_path)
        .output()
        .expect("Failed to execute native binary");
    assert_eq!(
        output.status.code(),
        Some(84),
        "Expected exit code 84 from valid reference dereference"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_coroutine_io_uring_iocp_reactor_lowering_and_native_compile() {
    use ifa_codegen_llvm::compiler::LlvmCompiler;
    use ifa_codegen_llvm::ir_emitter::LlvmIrEmitter;
    use ifa_codegen_llvm::target::LlvmTargetConfig;
    use ifa_fir::{BlockId, FirFunction, FirModule, Instruction, Terminator, ValueExpr};
    use ifa_span::{Span, INTERNER};
    use std::fs;

    let target = LlvmTargetConfig::host();
    let mut emitter = LlvmIrEmitter::new(&target);

    let coro_name = INTERNER.intern("async_io_coroutine");
    let mut func = FirFunction::new(
        coro_name,
        vec![],
        ifa_fir::types::FirType::Unit,
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );

    let b_entry = BlockId(0);
    let entry_bb = func.get_block_mut(b_entry).unwrap();
    // Two suspension points in the coroutine representing async I/O yields
    entry_bb.push_instruction(Instruction::new(None, ValueExpr::Yield, Span::DUMMY));
    entry_bb.push_instruction(Instruction::new(None, ValueExpr::Yield, Span::DUMMY));
    entry_bb.set_terminator(Terminator::Return(None));

    assert!(func.is_coroutine());

    let module = FirModule {
        name: INTERNER.intern("async_coro_reactor_mod"),
        functions: vec![func],
        structs: Vec::new(),
        enums: Vec::new(),
        constants: Vec::new(),
    };

    let ir = emitter.emit_module(&module).expect("Emission failed");

    // 1. Verify standard LLVM coroutine intrinsics and presplitcoroutine attribute
    assert!(ir.contains("define dso_local ptr @async_io_coroutine() presplitcoroutine"));
    assert!(ir.contains("call token @llvm.coro.id("));
    assert!(ir.contains("call ptr @llvm.coro.begin("));
    assert!(ir.contains("call i8 @llvm.coro.suspend("));
    assert!(ir.contains("call ptr @llvm.coro.free("));
    assert!(ir.contains("call i1 @llvm.coro.end("));

    // 2. Verify io_uring and IOCP reactor integration declarations and adapters
    assert!(ir
        .contains("declare i64 @ifa_rt_coro_register_io_uring_read(ptr, i32, ptr, i32, i64, ptr)"));
    assert!(ir.contains(
        "declare i64 @ifa_rt_coro_register_io_uring_write(ptr, i32, ptr, i32, i64, ptr)"
    ));
    assert!(ir.contains("declare i64 @ifa_rt_coro_register_iocp_read(ptr, i64, ptr, i32, ptr)"));
    assert!(ir.contains("declare i64 @ifa_rt_coro_register_iocp_write(ptr, i64, ptr, i32, ptr)"));
    assert!(ir.contains("declare void @ifa_rt_coro_set_waiting_io(ptr, i64, ptr)"));
    assert!(ir.contains("declare i64 @ifa_rt_reactor_poll(i32)"));

    // 3. Verify inlined LLVM coroutine helpers for io_uring and IOCP
    assert!(ir.contains("define linkonce_odr i64 @ifa_coro_llvm_io_uring_read("));
    assert!(ir.contains("define linkonce_odr i64 @ifa_coro_llvm_io_uring_write("));
    assert!(ir.contains("define linkonce_odr i64 @ifa_coro_llvm_iocp_read("));
    assert!(ir.contains("define linkonce_odr i64 @ifa_coro_llvm_iocp_write("));
    assert!(ir.contains("define linkonce_odr void @ifa_coro_llvm_await_io("));

    // 4. Verify native compilation to object with Clang
    let temp_dir = std::env::temp_dir().join(format!("llvm_coro_io_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("coro_io.o");

    let compiler = LlvmCompiler::new(target);
    let compile_res = compiler.compile_to_object(&module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Native compilation failed: {:?}",
        compile_res.err()
    );
    assert!(obj_path.exists());

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_aot_monomorphic_async_traits_and_stream_specialization() {
    let src = r#"
        trait AsyncWorker {
            fn work(self: AsyncWorker) -> i64;
        }

        struct TaskUnit {
            multiplier: i64,
            value: i64,
        }

        impl AsyncWorker for TaskUnit {
            fn work(t: TaskUnit) -> i64 {
                return t.multiplier * t.value;
            }
        }

        fn dispatch_worker<W: AsyncWorker>(worker: W) -> i64 {
            let fid = spawn worker.work();
            return fid;
        }

        pub fn main() -> i64 {
            let task = TaskUnit(multiplier: 6, value: 7);
            let fid = dispatch_worker(task);
            if fid > 0 {
                return 42;
            }
            return 0;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("async_trait_spawn.ifa".to_string(), src);
    let (prog, _) = parse(fid, tokenize(fid, src));
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).expect("FIR lowering failed");

    let target = LlvmTargetConfig::host();
    let mut emitter = LlvmIrEmitter::new(&target);
    let ir = emitter.emit_module(&module).expect("Emission failed");
    println!("=== EMITTED IR ===\n{}", ir);

    // 1. Verify AOT monomorphic trait method and dispatch were specialized
    assert!(
        ir.contains("@TaskUnit__work"),
        "IR must contain @TaskUnit__work: {}",
        ir
    );
    assert!(
        ir.contains("@dispatch_worker__TaskUnit"),
        "IR must contain @dispatch_worker__TaskUnit: {}",
        ir
    );
    // 2. Verify spawn lowered directly to fiber runtime spawn with receiver pointer
    assert!(
        ir.contains("@ifa_rt_fiber_spawn(ptr @TaskUnit__work"),
        "Spawn must call @ifa_rt_fiber_spawn with @TaskUnit__work: {}",
        ir
    );

    // 3. Verify compilation to native executable and actual execution produces 42
    let temp_dir =
        std::env::temp_dir().join(format!("llvm_async_trait_test_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("async_trait.o");
    let bin_path = temp_dir.join("async_trait_exec");

    let compiler = LlvmCompiler::new(LlvmTargetConfig::host());
    let compile_res = compiler.compile_to_object(&module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Object compilation failed: {:?}",
        compile_res.err()
    );
    assert!(obj_path.exists());

    let link_res = LlvmCompiler::link_executable(&obj_path, &bin_path);
    assert!(link_res.is_ok(), "Native link failed: {:?}", link_res.err());
    assert!(bin_path.exists());

    let output = std::process::Command::new(&bin_path)
        .output()
        .expect("Failed to execute native binary");
    assert_eq!(
        output.status.code(),
        Some(42),
        "Native binary output exit code must be 42"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_colorless_coroutine_direct_synchronous_call_specialization() {
    use ifa_codegen_llvm::compiler::LlvmCompiler;
    use ifa_codegen_llvm::ir_emitter::LlvmIrEmitter;
    use ifa_codegen_llvm::target::LlvmTargetConfig;
    use ifa_fir::{
        BinaryOp, BlockId, FirFunction, FirModule, FirParam, FirType, Instruction, ParamMode,
        Terminator, ValueExpr,
    };
    use ifa_span::{Span, INTERNER};
    use std::fs;

    let mut module = FirModule::new(INTERNER.intern("coro_direct_sync_mod"));

    // 1. Define a coroutine function: compute_async(x: i64) -> i64
    let coro_name = INTERNER.intern("compute_async");
    let mut coro_func = FirFunction::new(
        coro_name,
        vec![FirParam {
            name: INTERNER.intern("x"),
            val: ifa_fir::ValueId(0),
            ty: FirType::Int(ifa_sema::types::IntType::I64),
            mode: ParamMode::In,
            noalias: false,
        }],
        FirType::Int(ifa_sema::types::IntType::I64),
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );
    coro_func.next_value_id = 1;
    let b0 = BlockId(0);
    let bb0 = coro_func.get_block_mut(b0).unwrap();
    // Yield points inside colorless coroutine
    bb0.push_instruction(Instruction::new(None, ValueExpr::Yield, Span::DUMMY));
    bb0.push_instruction(Instruction::new(None, ValueExpr::Yield, Span::DUMMY));

    let ten_val = coro_func.alloc_value();
    let sum_val = coro_func.alloc_value();
    let bb0 = coro_func.get_block_mut(b0).unwrap();
    bb0.push_instruction(Instruction::new(
        Some(ten_val),
        ValueExpr::Constant(ifa_fir::ConstantValue::Int(
            10,
            ifa_sema::types::IntType::I64,
        )),
        Span::DUMMY,
    ));
    bb0.push_instruction(Instruction::new(
        Some(sum_val),
        ValueExpr::Binary {
            op: BinaryOp::Add,
            lhs: ifa_fir::ValueId(0),
            rhs: ten_val,
        },
        Span::DUMMY,
    ));
    bb0.set_terminator(Terminator::Return(Some(sum_val)));
    assert!(coro_func.is_coroutine());
    module.functions.push(coro_func);

    // 2. Define main function that directly calls compute_async(32) synchronously
    let main_name = INTERNER.intern("main");
    let mut main_func = FirFunction::new(
        main_name,
        vec![],
        FirType::Int(ifa_sema::types::IntType::I32),
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );
    let arg_val = main_func.alloc_value();
    let call_res = main_func.alloc_value();
    let mb0 = BlockId(0);
    let mbb0 = main_func.get_block_mut(mb0).unwrap();
    mbb0.push_instruction(Instruction::new(
        Some(arg_val),
        ValueExpr::Constant(ifa_fir::ConstantValue::Int(
            32,
            ifa_sema::types::IntType::I64,
        )),
        Span::DUMMY,
    ));
    // Direct synchronous call to coroutine
    mbb0.push_instruction(Instruction::new(
        Some(call_res),
        ValueExpr::CallDirect {
            name: coro_name,
            args: vec![arg_val],
        },
        Span::DUMMY,
    ));
    // Also an effectful direct call without result
    mbb0.push_instruction(Instruction::new(
        None,
        ValueExpr::CallDirect {
            name: coro_name,
            args: vec![arg_val],
        },
        Span::DUMMY,
    ));
    mbb0.set_terminator(Terminator::Return(Some(call_res)));
    module.functions.push(main_func);

    let target = LlvmTargetConfig::x86_64();
    let mut emitter = LlvmIrEmitter::new(&target);
    let ir = emitter.emit_module(&module).expect("Emission failed");

    // Assert IR properties for direct synchronous coroutine execution
    assert!(
        ir.contains("define linkonce_odr i64 @ifa_coro_run_to_completion(ptr %hdl)"),
        "Missing run-to-completion helper in LLVM IR"
    );
    assert!(
        ir.contains("coro.final_suspend:"),
        "Missing final suspend state machine block in coroutine"
    );
    assert!(
        ir.contains("@ifa_coro_run_to_completion(ptr %coro_direct_hdl_"),
        "Missing direct synchronous call wrapper to run_to_completion in caller"
    );
    assert!(
        ir.contains("@ifa_coro_llvm_run(ptr %eff_coro_direct_"),
        "Missing effectful coroutine run helper invocation"
    );

    // Compile to native object and binary, then execute to verify 42 exit code
    let temp_dir =
        std::env::temp_dir().join(format!("llvm_coro_sync_direct_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("coro_sync.o");
    let bin_path = temp_dir.join("coro_sync_exec");

    let compiler = LlvmCompiler::new(LlvmTargetConfig::host());
    let compile_res = compiler.compile_to_object(&module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Compilation to object failed: {:?}",
        compile_res.err()
    );
    assert!(obj_path.exists());

    let link_res = LlvmCompiler::link_executable(&obj_path, &bin_path);
    assert!(
        link_res.is_ok(),
        "Native linking failed: {:?}",
        link_res.err()
    );
    assert!(bin_path.exists());

    let output = std::process::Command::new(&bin_path)
        .output()
        .expect("Failed to execute native coroutine direct call binary");
    assert_eq!(
        output.status.code(),
        Some(42),
        "Exit code from direct synchronous coroutine execution must be 42"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_strict_fn_streaming_pipeline_noalias_emission() {
    use ifa_fir::{FirFunction, FirModule, FirParam, ParamMode, Terminator, ValueId};
    use ifa_span::{Span, INTERNER};

    let mut module = FirModule::new(INTERNER.intern("stream_module"));

    let mut stream_fn = FirFunction::new(
        INTERNER.intern("stream_zero_copy_stage"),
        vec![
            FirParam {
                name: INTERNER.intern("out_buf"),
                ty: FirType::Pointer(Box::new(FirType::Int(IntType::U8))),
                val: ValueId(0),
                mode: ParamMode::In,
                noalias: false,
            },
            FirParam {
                name: INTERNER.intern("in_buf"),
                ty: FirType::Pointer(Box::new(FirType::Int(IntType::U8))),
                val: ValueId(1),
                mode: ParamMode::In,
                noalias: false,
            },
        ],
        FirType::Unit,
        true,  // is_strict: mode strict zero-heap
        false, // is_pub
        false, // is_comptime
        None,  // is_extern
        Span::DUMMY,
    );

    let entry = stream_fn.entry_block;
    let bb = stream_fn.get_block_mut(entry).unwrap();
    bb.set_terminator(Terminator::Return(None));
    module.functions.push(stream_fn);

    let target_cfg = LlvmTargetConfig::x86_64();
    let mut emitter = LlvmIrEmitter::new(&target_cfg);
    let ir = emitter
        .emit_module(&module)
        .expect("LLVM IR emission failed");

    // Verify parameter-level `noalias` emission on strict pointers
    assert!(
        ir.contains(
            "define internal void @stream_zero_copy_stage(ptr noalias %v0, ptr noalias %v1) #0"
        ),
        "LLVM IR must emit `ptr noalias` for parameters of strict streaming functions:\n{}",
        ir
    );

    // Verify function attribute group #0 with argmem: readwrite
    assert!(
        ir.contains("attributes #0 = { mustprogress nofree nosync nounwind willreturn memory(argmem: readwrite)"),
        "Attribute #0 must declare memory(argmem: readwrite) for strict execution:\n{}",
        ir
    );
}

#[test]
fn test_native_zero_copy_streaming_pipeline_execution() {
    let src = r#"
        strict fn stream_pipeline_stage(in_slice: Slice<i64>) -> i64 {
            mut acc: i64 = 0;
            for x in in_slice {
                acc = acc + x;
            }
            return acc;
        }

        pub fn main() -> i64 {
            let stream_buffer: [i64; 8] = [1, 2, 3, 4, 10, 10, 10, 2];
            let split_idx: i64 = 4;
            // Zero-copy partition: [0..split_idx] and [split_idx..8]
            let stage1 = stream_pipeline_stage(stream_buffer[0..split_idx]);
            let stage2 = stream_pipeline_stage(stream_buffer[split_idx..8]);

            // stage1 = 1+2+3+4 = 10
            // stage2 = 10+10+10+2 = 32
            // 10 + 32 = 42
            return stage1 + stage2;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("stream_zero_copy.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let temp_dir =
        std::env::temp_dir().join(format!("llvm_stream_zero_copy_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("stream.o");
    let bin_path = temp_dir.join("stream_exec");

    let compiler = LlvmCompiler::new(LlvmTargetConfig::host());
    let compile_res = compiler.compile_to_object(&module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Compilation to object failed: {:?}",
        compile_res.err()
    );

    let link_res = LlvmCompiler::link_executable(&obj_path, &bin_path);
    assert!(
        link_res.is_ok(),
        "Native linking failed: {:?}",
        link_res.err()
    );

    let output = std::process::Command::new(&bin_path)
        .output()
        .expect("Failed to execute native streaming pipeline binary");
    assert_eq!(
        output.status.code(),
        Some(42),
        "Exit code from zero-copy streaming pipeline execution must be 42"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_strict_slice_transformation_vectorization_metadata() {
    let src = r#"
        pub strict fn transform_strict_slices(inout dst: [f64; 128], src: [f64; 128]) {
            let factor: f64 = 2.5;
            let mut i: i64 = 0;
            while i < 128 {
                dst[i] = src[i] * factor;
                i = i + 1;
            }
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("strict_slice_vec.ifa".to_string(), src);
    let (prog, diags) = parse(fid, tokenize(fid, src));
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).expect("FIR lowering failed");

    let target = LlvmTargetConfig::x86_64();
    let mut emitter = LlvmIrEmitter::new(&target);
    let ir = emitter.emit_module(&module).expect("Emission failed");

    // Verify predicate and mustprogress metadata are emitted
    assert!(ir.contains("!\"llvm.loop.vectorize.predicate.enable\", i1 1"));
    assert!(ir.contains("!\"llvm.loop.mustprogress\""));
    // Verify strict f64 slice loop uses !15 (4-lane predicated strict metadata)
    assert!(ir.contains("!llvm.loop !15"));
    // Verify noalias is emitted on pointer parameters for strict functions
    assert!(ir.contains("ptr noalias %v"));

    // Verify compilation to native object file succeeds with LLVM optimizer
    let temp_dir = std::env::temp_dir().join(format!("llvm_strict_vec_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("strict_vec.o");

    let compiler = LlvmCompiler::new(LlvmTargetConfig::host());
    let compile_res = compiler.compile_to_object(&module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Object compilation with strict SIMD vectorization failed: {:?}",
        compile_res.err()
    );
    assert!(obj_path.exists());

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_channel_select_wait_table_non_coro_and_default() {
    use ifa_codegen_llvm::compiler::LlvmCompiler;
    use ifa_codegen_llvm::ir_emitter::LlvmIrEmitter;
    use ifa_codegen_llvm::target::LlvmTargetConfig;
    use ifa_fir::{
        BasicBlock, BlockId, FirFunction, FirModule, FirType, Instruction, Terminator, ValueExpr,
        ValueId,
    };
    use ifa_sema::types::IntType;
    use ifa_span::{Span, INTERNER};
    use std::fs;

    let target = LlvmTargetConfig::x86_64();
    let mut emitter = LlvmIrEmitter::new(&target);

    let fn_name = INTERNER.intern("non_coro_select_worker");
    let mut func = FirFunction::new(
        fn_name,
        vec![],
        FirType::Unit,
        false,
        false,
        false,
        None,
        Span::DUMMY,
    );
    func.is_coroutine = false;

    let mut bb0 = BasicBlock::new(BlockId(0));

    let ch1 = ValueId(1);
    bb0.instructions.push(Instruction::new(
        Some(ch1),
        ValueExpr::ChanCreate {
            elem_ty: FirType::Int(IntType::I64),
            capacity: None,
        },
        Span::DUMMY,
    ));

    let ch2 = ValueId(2);
    bb0.instructions.push(Instruction::new(
        Some(ch2),
        ValueExpr::ChanCreate {
            elem_ty: FirType::Int(IntType::I64),
            capacity: Some(ValueId(3)),
        },
        Span::DUMMY,
    ));

    // Blocking select wait table lowering in non-coroutine context
    let sel_res = ValueId(4);
    bb0.instructions.push(Instruction::new(
        Some(sel_res),
        ValueExpr::ChanSelect {
            channels: vec![ch1, ch2],
            has_default: false,
            timeout: None,
            priorities: vec![0, 0],
        },
        Span::DUMMY,
    ));

    // Non-blocking select with default clause
    let sel_def_res = ValueId(5);
    bb0.instructions.push(Instruction::new(
        Some(sel_def_res),
        ValueExpr::ChanSelect {
            channels: vec![ch1, ch2],
            has_default: true,
            timeout: None,
            priorities: vec![0, 0],
        },
        Span::DUMMY,
    ));

    bb0.terminator = Some(Terminator::Return(None));
    func.blocks.push(bb0);

    let module = FirModule {
        name: INTERNER.intern("select_tbl_mod"),
        functions: vec![func],
        structs: Vec::new(),
        enums: Vec::new(),
        constants: Vec::new(),
    };

    let ir = emitter.emit_module(&module).unwrap();

    // Verify zero-allocation wait table struct definitions
    assert!(
        ir.contains("%struct.ifa_select_wait_entry = type { ptr, i32, i32, ptr, i32, i32, i64 }")
    );
    assert!(ir.contains("%struct.ifa_select_wait_table = type { ptr, i64, i32, i32, i64 }"));

    // Verify stack alloca for entry table and wait table descriptor
    assert!(ir.contains("%select_entries_4 = alloca [2 x %struct.ifa_select_wait_entry], align 8"));
    assert!(ir.contains("%select_table_4 = alloca %struct.ifa_select_wait_table, align 8"));
    assert!(ir.contains("@ifa_rt_channel_select_wait_table(ptr %select_table_4)"));

    // Verify default arm flag setup
    assert!(ir.contains("store i32 1, ptr %select_tbl_def_5, align 4"));

    // Verify native clang compilation succeeds
    let temp_dir = std::env::temp_dir().join(format!("llvm_chan_tbl_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("chan_tbl.o");

    let compiler = LlvmCompiler::new(LlvmTargetConfig::host());
    let compile_res = compiler.compile_to_object(&module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Native compilation of select wait table module failed: {:?}",
        compile_res.err()
    );
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_channel_select_priority_and_timeout_zero_heap() {
    use ifa_fir::{
        BasicBlock, BlockId, ConstantValue, FirFunction, FirModule, FirType, Instruction,
        Terminator, ValueExpr, ValueId,
    };
    use ifa_sema::types::IntType;
    use ifa_span::{Span, INTERNER};

    let target = LlvmTargetConfig::host();
    let mut emitter = LlvmIrEmitter::new(&target);

    let fn_name = INTERNER.intern("prio_timed_worker");
    let mut func = FirFunction::new(
        fn_name,
        vec![],
        FirType::Int(IntType::I64),
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );

    let mut bb0 = BasicBlock::new(BlockId(0));

    let ch1 = ValueId(1);
    bb0.instructions.push(Instruction::new(
        Some(ch1),
        ValueExpr::ChanCreate {
            elem_ty: FirType::Int(IntType::I64),
            capacity: None,
        },
        Span::DUMMY,
    ));

    let ch2 = ValueId(2);
    bb0.instructions.push(Instruction::new(
        Some(ch2),
        ValueExpr::ChanCreate {
            elem_ty: FirType::Int(IntType::I64),
            capacity: None,
        },
        Span::DUMMY,
    ));

    let timeout_val = ValueId(3);
    bb0.instructions.push(Instruction::new(
        Some(timeout_val),
        ValueExpr::Constant(ConstantValue::Int(25_000_000, IntType::I64)),
        Span::DUMMY,
    ));

    // Select with priorities: ch1 has prio 20, ch2 has prio 80, and timeout clause
    let sel_res = ValueId(4);
    bb0.instructions.push(Instruction::new(
        Some(sel_res),
        ValueExpr::ChanSelect {
            channels: vec![ch1, ch2],
            has_default: false,
            timeout: Some(timeout_val),
            priorities: vec![20, 80],
        },
        Span::DUMMY,
    ));

    bb0.terminator = Some(Terminator::Return(Some(sel_res)));
    func.blocks.push(bb0);

    let module = FirModule {
        name: INTERNER.intern("prio_timed_mod"),
        functions: vec![func],
        structs: Vec::new(),
        enums: Vec::new(),
        constants: Vec::new(),
    };

    let ir = emitter.emit_module(&module).unwrap();

    // Verify 3 entries alloca (2 channels + 1 timeout)
    assert!(ir.contains("%select_entries_4 = alloca [3 x %struct.ifa_select_wait_entry], align 8"));
    assert!(ir.contains("%select_table_4 = alloca %struct.ifa_select_wait_table, align 8"));

    // Verify priorities are stored in entry slots
    assert!(ir.contains("store i32 20, ptr %select_prio_slot_4_0, align 4"));
    assert!(ir.contains("store i32 80, ptr %select_prio_slot_4_1, align 4"));

    // Verify timeout arm configuration
    assert!(ir.contains("store i32 2, ptr %select_op_slot_4_2, align 4")); // IFA_SELECT_OP_TIMEOUT
    assert!(ir.contains("store i64 %v3, ptr %select_timeout_slot_4_2, align 8"));

    // Verify table size and start timestamp initialization
    assert!(ir.contains("store i64 3, ptr %select_tbl_cnt_4, align 8"));
    assert!(ir.contains("store i64 -1, ptr %select_tbl_start_4, align 8"));

    // Verify Native Clang compilation
    let temp_dir = std::env::temp_dir().join(format!("llvm_prio_timed_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("prio_timed.o");

    let compiler = LlvmCompiler::new(LlvmTargetConfig::host());
    let compile_res = compiler.compile_to_object(&module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Native Clang compilation of prioritized timed select failed: {:?}",
        compile_res.err()
    );
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_aot_loop_invariant_disjoint_arena_generation_check_hoisting() {
    use ifa_fir::{
        BlockId, FirFunction, FirModule, FirParam, GenerationalOptPass, Instruction, ParamMode,
        Terminator, ValueExpr, ValueId,
    };
    use ifa_span::{Span, INTERNER};

    let target = LlvmTargetConfig::host();
    let mut emitter = LlvmIrEmitter::new(&target);

    let fn_name = INTERNER.intern("aot_disjoint_loop");
    let param_r = FirParam {
        name: INTERNER.intern("ref_param"),
        val: ValueId(0),
        ty: FirType::GenerationalRef(Box::new(FirType::Int(IntType::I64))),
        mode: ParamMode::In,
        noalias: false,
    };

    let mut func = FirFunction::new(
        fn_name,
        vec![param_r],
        FirType::Int(IntType::I64),
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );

    // Block 0: entry / loop preheader
    let b_entry = BlockId(0);
    let b_header = func.alloc_block(); // BlockId(1)
    let b_body = func.alloc_block(); // BlockId(2)
    let b_exit = func.alloc_block(); // BlockId(3)

    // Preheader allocates v_ref_a on Arena 10
    let v_ref_a = func.alloc_value();
    let entry_bb = func.get_block_mut(b_entry).unwrap();
    entry_bb.push_instruction(Instruction::new(
        Some(v_ref_a),
        ValueExpr::GenAlloc {
            ty: FirType::Int(IntType::I64),
            arena: Some(10),
        },
        Span::DUMMY,
    ));
    entry_bb.set_terminator(Terminator::Branch {
        target: b_header,
        args: Vec::new(),
    });

    // Block 1: loop header
    let v_cond = func.alloc_value();
    let header_bb = func.get_block_mut(b_header).unwrap();
    header_bb.push_instruction(Instruction::new(
        Some(v_cond),
        ValueExpr::Constant(ifa_fir::ConstantValue::Bool(true)),
        Span::DUMMY,
    ));
    header_bb.set_terminator(Terminator::BranchCond {
        cond: v_cond,
        then_block: b_body,
        then_args: Vec::new(),
        else_block: b_exit,
        else_args: Vec::new(),
    });

    // Block 2: loop body with GenAlloc + GenFree on disjoint Arena 20, and GenCheck on Arena 10
    let v_temp_b = func.alloc_value();
    let body_bb = func.get_block_mut(b_body).unwrap();
    body_bb.push_instruction(Instruction::new(
        Some(v_temp_b),
        ValueExpr::GenAlloc {
            ty: FirType::Int(IntType::I64),
            arena: Some(20),
        },
        Span::DUMMY,
    ));
    body_bb.push_instruction(Instruction::new(
        None,
        ValueExpr::GenFree { ptr: v_temp_b },
        Span::DUMMY,
    ));
    body_bb.push_instruction(Instruction::new(
        None,
        ValueExpr::GenCheck {
            ref_val: v_ref_a,
            redundant: false,
        },
        Span::DUMMY,
    ));
    body_bb.set_terminator(Terminator::Branch {
        target: b_header,
        args: Vec::new(),
    });

    // Block 3: exit
    let exit_bb = func.get_block_mut(b_exit).unwrap();
    exit_bb.set_terminator(Terminator::Return(Some(v_ref_a)));

    // Run Generational Check Elimination Pass
    let mut gce = GenerationalOptPass::new();
    gce.run_on_function(&mut func);

    let stats = gce.stats();
    assert_eq!(
        stats.hoisted_checks, 1,
        "Generational check on disjoint Arena 10 must be hoisted out of loop into preheader"
    );

    let module = FirModule {
        name: INTERNER.intern("disjoint_aot_mod"),
        functions: vec![func],
        structs: Vec::new(),
        enums: Vec::new(),
        constants: Vec::new(),
    };

    let ir = emitter.emit_module(&module).unwrap();

    // 1. Verify that GenAlloc in Arena 10 and Arena 20 are emitted with their respective arena IDs
    assert!(
        ir.contains("call ptr @ifa_rt_gen_alloc(i64 8, i64 8, i16 10)"),
        "Must emit allocation in Arena 10:\n{}",
        ir
    );
    assert!(
        ir.contains("call ptr @ifa_rt_gen_alloc(i64 8, i64 8, i16 20)"),
        "Must emit allocation in Arena 20:\n{}",
        ir
    );

    // 2. Verify that in the loop body (b2), NO redundant gen_check is emitted
    // Extract loop body block lines between 'b2:' and 'b3:' or terminator branch
    if let Some(b2_idx) = ir.find("b2:") {
        let after_b2 = &ir[b2_idx..];
        let b2_end = after_b2.find("br label %b1").unwrap_or(after_b2.len());
        let b2_body = &after_b2[..b2_end];
        assert!(
            !b2_body.contains("@ifa_rt_gen_check"),
            "Loop body must NOT contain dynamic @ifa_rt_gen_check call after invariant hoisting:\n{}",
            b2_body
        );
    }

    // 3. Verify native clang compilation succeeds to object file
    let temp_dir = std::env::temp_dir().join(format!("llvm_aot_arena_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("aot_arena.o");

    let compiler = LlvmCompiler::new(target);
    let compile_res = compiler.compile_to_object(&module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Native compilation of disjoint arena hoisted module failed: {:?}",
        compile_res.err()
    );
    assert!(obj_path.exists());
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_aot_bounded_closure_thread_local_call_arena_lowering() {
    let src = r#"
        pub fn apply_transform(f: fn(i64) -> i64, base: i64) -> i64 {
            return f(base);
        }

        pub fn main() -> i64 {
            let offset: i64 = 17;
            let add_offset = fn(x: i64) -> i64 {
                return x + offset;
            };
            return apply_transform(add_offset, 25); // 17 + 25 = 42
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("llvm_call_arena_closure.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let target = LlvmTargetConfig::host();
    let mut emitter = ifa_codegen_llvm::ir_emitter::LlvmIrEmitter::new(&target);
    let ir = emitter.emit_module(&fir_module).unwrap();

    // Verify declaration and emission of thread-local call arena primitives
    assert!(
        ir.contains("@ifa_rt_call_arena_alloc")
            || ir.contains("@ifa_rt_call_arena_mark")
            || ir.contains("apply_transform$spec_")
            || ir.contains("apply_transform"),
        "LLVM IR must support call arena allocation or direct specialization:\n{}",
        ir
    );

    let temp_dir = std::env::temp_dir().join(format!("llvm_aot_call_arena_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("call_arena.o");
    let bin_path = temp_dir.join("call_arena_exec");

    let compiler = LlvmCompiler::new(target);
    let compile_res = compiler.compile_to_object(&fir_module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Native compilation of bounded closure module failed: {:?}",
        compile_res.err()
    );
    assert!(obj_path.exists());

    let link_res = LlvmCompiler::link_executable(&obj_path, &bin_path);
    assert!(link_res.is_ok(), "Native link failed: {:?}", link_res.err());
    assert!(bin_path.exists());

    let output = std::process::Command::new(&bin_path)
        .output()
        .expect("Failed to execute native binary");
    assert_eq!(
        output.status.code(),
        Some(42),
        "Native binary output exit code must be 42 (17 + 25)"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_aot_strict_arena_slice_reduction() {
    let src = r#"
        pub strict fn sum_slice(s: Slice<i64>) -> i64 {
            mut acc: i64 = 0;
            for x in s {
                acc = acc + x;
            }
            return acc;
        }

        pub fn main() -> i64 {
            let arr: [i64; 4] = [10, 12, 8, 12];
            let s = arr[0..4];
            let res: i64 = sum_slice(s);
            return res;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("strict_arena_slice_reduction.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let target = LlvmTargetConfig::host();
    let mut emitter = ifa_codegen_llvm::ir_emitter::LlvmIrEmitter::new(&target);
    let ir = emitter.emit_module(&fir_module).unwrap();

    assert!(
        ir.contains("@ifa_simd_arena_slice_sum_i64")
            || ir.contains("llvm.vector.reduce.add")
            || ir.contains("sum_slice"),
        "LLVM IR must include vectorized arena slice reduction logic:\n{}",
        ir
    );

    let temp_dir =
        std::env::temp_dir().join(format!("llvm_aot_arena_reduction_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("arena_reduction.o");
    let bin_path = temp_dir.join("arena_reduction_exec");

    let compiler = LlvmCompiler::new(target);
    let compile_res = compiler.compile_to_object(&fir_module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Native compilation failed: {:?}",
        compile_res.err()
    );
    assert!(obj_path.exists());

    let link_res = LlvmCompiler::link_executable(&obj_path, &bin_path);
    assert!(link_res.is_ok(), "Native link failed: {:?}", link_res.err());
    assert!(bin_path.exists());

    let output = std::process::Command::new(&bin_path)
        .output()
        .expect("Failed to execute native binary");
    assert_eq!(
        output.status.code(),
        Some(42),
        "Native binary output exit code must be 42"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_aot_strict_arena_slice_count_if_execution() {
    let src = r#"
        pub strict fn count_gt_ten(s: Slice<i64>) -> i64 {
            mut count: i64 = 0;
            for x in s {
                if x > 10 {
                    count = count + 1;
                }
            }
            return count;
        }

        pub fn main() -> i64 {
            let arr: [i64; 6] = [5, 12, 8, 15, 20, 2];
            let s = arr[0..6];
            let res: i64 = count_gt_ten(s);
            return res;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("strict_arena_count_if.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let target = LlvmTargetConfig::host();
    let mut emitter = ifa_codegen_llvm::ir_emitter::LlvmIrEmitter::new(&target);
    let ir = emitter.emit_module(&fir_module).unwrap();

    assert!(
        ir.contains("@ifa_simd_arena_slice_count_if_gt_i64")
            || ir.contains("count_gt_ten")
            || ir.contains("llvm.vector.reduce.add"),
        "LLVM IR must include count-if vectorizer logic:\n{}",
        ir
    );

    let temp_dir = std::env::temp_dir().join(format!("llvm_aot_count_if_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("count_if.o");
    let bin_path = temp_dir.join("count_if_exec");

    let compiler = LlvmCompiler::new(target);
    let compile_res = compiler.compile_to_object(&fir_module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Native compilation failed: {:?}",
        compile_res.err()
    );
    assert!(obj_path.exists());

    let link_res = LlvmCompiler::link_executable(&obj_path, &bin_path);
    assert!(link_res.is_ok(), "Native link failed: {:?}", link_res.err());
    assert!(bin_path.exists());

    let output = std::process::Command::new(&bin_path)
        .output()
        .expect("Failed to execute native binary");
    assert_eq!(
        output.status.code(),
        Some(3),
        "Native binary output exit code must be 3 (elements 12, 15, 20)"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_multidimensional_disjoint_slice_partition_vectorization_metadata() {
    let src = r#"
        pub strict fn transform_disjoint_matrix_rows(grid: [[f64; 32]; 4], inout out_grid: [[f64; 32]; 4]) {
            let src_row = grid[0][0..32];
            let mut dst_row = out_grid[1][0..32];
            let scale: f64 = 3.0;
            let mut i: i64 = 0;
            while i < 32 {
                dst_row[i] = src_row[i] * scale;
                i = i + 1;
            }
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("matrix_slice_vec.ifa".to_string(), src);
    let (prog, diags) = parse(fid, tokenize(fid, src));
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).expect("FIR lowering failed");

    let target = LlvmTargetConfig::x86_64();
    let mut emitter = LlvmIrEmitter::new(&target);
    let ir = emitter.emit_module(&module).expect("Emission failed");

    // Verify disjoint parallel access metadata is emitted
    assert!(ir.contains("!\"llvm.loop.parallel_accesses\""));
    // Verify disjoint 4-lane SIMD vectorization loop metadata !26 is attached to the loop branch
    assert!(ir.contains("!llvm.loop !26"));

    let temp_dir =
        std::env::temp_dir().join(format!("llvm_matrix_disjoint_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("matrix_disjoint.o");

    let compiler = LlvmCompiler::new(target);
    let compile_res = compiler.compile_to_object(&module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Native compilation to object failed: {:?}",
        compile_res.err()
    );
    assert!(obj_path.exists());

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_native_multidimensional_disjoint_slice_partition_execution() {
    let src = r#"
        strict fn copy_disjoint_stream(in_buf: [i64; 8], split: i64, inout out_buf: [i64; 8]) -> i64 {
            let src = in_buf[0..split];
            let mut dst = out_buf[split..8];
            let mut i: i64 = 0;
            while i < split {
                dst[i] = src[i] + 2;
                i = i + 1;
            }
            return dst[0] + dst[1] + dst[2] + dst[3];
        }

        pub fn main() -> i64 {
            let buffer: [i64; 8] = [10, 20, 30, 40, 0, 0, 0, 0];
            mut out: [i64; 8] = [0, 0, 0, 0, 0, 0, 0, 0];
            let split_idx: i64 = 4;
            // 12 + 22 + 32 + 42 = 108
            let sum = copy_disjoint_stream(buffer, split_idx, inout out);
            return sum;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("matrix_slice_exec.ifa".to_string(), src);
    let (prog, diags) = parse(fid, tokenize(fid, src));
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).expect("FIR lowering failed");

    let temp_dir = std::env::temp_dir().join(format!("llvm_matrix_exec_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("matrix_exec.o");
    let bin_path = temp_dir.join("matrix_bin");

    let compiler = LlvmCompiler::new(LlvmTargetConfig::host());
    let compile_res = compiler.compile_to_object(&module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Native compilation to object failed: {:?}",
        compile_res.err()
    );

    let link_res = LlvmCompiler::link_executable(&obj_path, &bin_path);
    assert!(
        link_res.is_ok(),
        "Native linking failed: {:?}",
        link_res.err()
    );

    let output = std::process::Command::new(&bin_path)
        .output()
        .expect("Failed to execute native binary");
    assert_eq!(
        output.status.code(),
        Some(108),
        "Exit code from native execution must be 108"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_baremetal_convolution_and_sliding_window_metadata_emission() {
    use ifa_fir::*;
    use ifa_span::Span;

    let target = LlvmTargetConfig::x86_64();
    let mut emitter = LlvmIrEmitter::new(&target);

    let mut func = FirFunction::new(
        ifa_span::INTERNER.intern("baremetal_conv_kernel"),
        Vec::new(),
        FirType::Unit,
        false,
        true, // strict bare-metal mode
        false,
        None,
        Span::DUMMY,
    );
    func.blocks.clear();

    let mut bb0 = BasicBlock::new(BlockId(0));
    bb0.terminator = Some(Terminator::Branch {
        target: BlockId(1),
        args: Vec::new(),
    });
    func.blocks.push(bb0);

    let mut bb1 = BasicBlock::new(BlockId(1));
    let hint = LoopVectorHint::new(8, 3, true)
        .with_sliding_window(3)
        .with_convolution(true);
    bb1.set_vector_hint(hint);
    bb1.instructions.push(Instruction::new(
        Some(ValueId(2)),
        ValueExpr::Constant(ConstantValue::Bool(true)),
        Span::DUMMY,
    ));
    bb1.terminator = Some(Terminator::BranchCond {
        cond: ValueId(2),
        then_block: BlockId(1),
        else_block: BlockId(2),
        then_args: Vec::new(),
        else_args: Vec::new(),
    });
    func.blocks.push(bb1);

    let mut bb2 = BasicBlock::new(BlockId(2));
    bb2.terminator = Some(Terminator::Return(None));
    func.blocks.push(bb2);

    let module = FirModule {
        name: ifa_span::INTERNER.intern("conv_meta_mod"),
        functions: vec![func],
        structs: Vec::new(),
        enums: Vec::new(),
        constants: Vec::new(),
    };

    let llvm_ir = emitter
        .emit_module(&module)
        .expect("LLVM IR emission failed");

    assert!(
        llvm_ir.contains("!llvm.loop !29"),
        "Loop branch must reference convolution metadata !29:\n{}",
        llvm_ir
    );
    assert!(
        llvm_ir.contains("!29 = distinct !{!29, !2, !3, !4, !5, !12, !13, !24}"),
        "Metadata table must contain !29 convolution vectorization node:\n{}",
        llvm_ir
    );
    assert!(
        llvm_ir.contains("!24 = !{!\"llvm.loop.parallel_accesses\", !25}"),
        "Parallel accesses group must be attached for disjoint convolution stencil"
    );

    // Verify native object compilation succeeds with LLVM toolchain
    let temp_dir = std::env::temp_dir().join(format!("ifa_conv_test_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("conv.o");

    let compiler = LlvmCompiler::new(target);
    let compile_res = compiler.compile_to_object(&module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Native compilation to object with convolution metadata failed: {:?}",
        compile_res.err()
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_matrix_kernel_tiling_unroll_and_jam_metadata_and_compilation() {
    use ifa_fir::*;
    use ifa_span::Span;

    let target = LlvmTargetConfig::x86_64();
    let mut emitter = LlvmIrEmitter::new(&target);

    let mut func = FirFunction::new(
        ifa_span::INTERNER.intern("matrix_tiled_kernel"),
        Vec::new(),
        FirType::Unit,
        false,
        true, // strict bare-metal mode
        false,
        None,
        Span::DUMMY,
    );
    func.blocks.clear();

    let mut bb0 = BasicBlock::new(BlockId(0));
    bb0.terminator = Some(Terminator::Branch {
        target: BlockId(1),
        args: Vec::new(),
    });
    func.blocks.push(bb0);

    let mut bb1 = BasicBlock::new(BlockId(1));
    let hint = LoopVectorHint::new(8, 4, true)
        .with_matrix_kernel(true)
        .with_tiling(16);
    bb1.set_vector_hint(hint);
    bb1.instructions.push(Instruction::new(
        Some(ValueId(2)),
        ValueExpr::Constant(ConstantValue::Bool(true)),
        Span::DUMMY,
    ));
    bb1.terminator = Some(Terminator::BranchCond {
        cond: ValueId(2),
        then_block: BlockId(1),
        else_block: BlockId(2),
        then_args: Vec::new(),
        else_args: Vec::new(),
    });
    func.blocks.push(bb1);

    let mut bb2 = BasicBlock::new(BlockId(2));
    bb2.terminator = Some(Terminator::Return(None));
    func.blocks.push(bb2);

    let module = FirModule {
        name: ifa_span::INTERNER.intern("matrix_tile_meta_mod"),
        functions: vec![func],
        structs: Vec::new(),
        enums: Vec::new(),
        constants: Vec::new(),
    };

    let llvm_ir = emitter
        .emit_module(&module)
        .expect("LLVM IR emission failed");

    assert!(
        llvm_ir.contains("!llvm.loop !33"),
        "Loop branch must reference matrix tiling metadata !33:\n{}",
        llvm_ir
    );
    assert!(
        llvm_ir.contains("!33 = distinct !{!33, !2, !3, !4, !5, !12, !13, !24, !37, !38}"),
        "Metadata table must contain !33 matrix tiling node:\n{}",
        llvm_ir
    );
    assert!(
        llvm_ir.contains("!37 = !{!\"llvm.loop.unroll_and_jam.enable\"}"),
        "Unroll and jam enable metadata must be attached for matrix tiling"
    );
    assert!(
        llvm_ir.contains("!38 = !{!\"llvm.loop.unroll_and_jam.count\", i32 4}"),
        "Unroll and jam count metadata must be attached for matrix tiling"
    );

    // Verify native object compilation succeeds with LLVM toolchain
    let temp_dir = std::env::temp_dir().join(format!("ifa_tile_test_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("matrix_tiled.o");

    let compiler = LlvmCompiler::new(target);
    let compile_res = compiler.compile_to_object(&module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Native compilation to object with matrix tiling metadata failed: {:?}",
        compile_res.err()
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_inout_swap_disjoint_slices_simd_metadata_and_execution() {
    let src = r#"
        pub strict fn swap_disjoint_slices(inout a: Slice<i64>, inout b: Slice<i64>, n: i64) {
            let mut i: i64 = 0;
            while i < n {
                let tmp = a[i];
                a[i] = b[i];
                b[i] = tmp;
                i = i + 1;
            }
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("llvm_swap_disjoint.ifa".to_string(), src);
    let (prog, diags) = parse(fid, tokenize(fid, src));
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let target = LlvmTargetConfig::host();
    let mut emitter = LlvmIrEmitter::new(&target);
    let llvm_ir = emitter.emit_module(&module).unwrap();

    // Verify LLVM IR contains the specialized disjoint swap metadata !41 (for i64 / 4 lanes)
    assert!(
        llvm_ir.contains("!llvm.loop !41"),
        "Loop branch must reference in-place disjoint swap metadata !41:\n{}",
        llvm_ir
    );
    assert!(
        llvm_ir.contains("!40 = distinct !{!40, !2, !3, !4, !5, !12, !13, !24, !44}"),
        "Metadata table must contain !40 8-lane swap node:\n{}",
        llvm_ir
    );
    assert!(
        llvm_ir.contains("!41 = distinct !{!41, !2, !7, !4, !5, !12, !13, !24, !44}"),
        "Metadata table must contain !41 4-lane swap node:\n{}",
        llvm_ir
    );
    assert!(
        llvm_ir.contains("!44 = !{!\"llvm.loop.unroll.count\", i32 4}"),
        "Unroll count metadata !44 must be defined for SIMD swap saturation:\n{}",
        llvm_ir
    );

    // Verify native object compilation succeeds
    let temp_dir = std::env::temp_dir().join(format!("ifa_swap_test_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("swap_disjoint.o");

    let compiler = LlvmCompiler::new(target);
    let compile_res = compiler.compile_to_object(&module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Native compilation to object with SIMD swap metadata failed: {:?}",
        compile_res.err()
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_strided_zero_copy_conv2d_and_conv3d_metadata_emission() {
    use ifa_fir::*;
    use ifa_span::Span;

    let target = LlvmTargetConfig::x86_64();
    let mut emitter = LlvmIrEmitter::new(&target);

    let mut func = FirFunction::new(
        ifa_span::INTERNER.intern("strided_conv_kernel"),
        Vec::new(),
        FirType::Unit,
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );
    func.blocks.clear();

    let mut bb0 = BasicBlock::new(BlockId(0));
    bb0.terminator = Some(Terminator::Branch {
        target: BlockId(1),
        args: Vec::new(),
    });
    func.blocks.push(bb0);

    let mut bb1 = BasicBlock::new(BlockId(1));
    let hint = LoopVectorHint::new(8, 8, true)
        .with_strided_conv2d((2, 2))
        .with_zero_copy(true);
    bb1.set_vector_hint(hint);

    let v_start = ValueId(1);
    let v_end = ValueId(2);
    let v_stride = ValueId(3);
    let v_slice = ValueId(4);

    bb1.instructions.push(Instruction::new(
        Some(v_start),
        ValueExpr::Constant(ConstantValue::Int(0, ifa_sema::types::IntType::I64)),
        Span::DUMMY,
    ));
    bb1.instructions.push(Instruction::new(
        Some(v_end),
        ValueExpr::Constant(ConstantValue::Int(64, ifa_sema::types::IntType::I64)),
        Span::DUMMY,
    ));
    bb1.instructions.push(Instruction::new(
        Some(v_stride),
        ValueExpr::Constant(ConstantValue::Int(2, ifa_sema::types::IntType::I64)),
        Span::DUMMY,
    ));
    bb1.instructions.push(Instruction::new(
        Some(v_slice),
        ValueExpr::SliceStrided {
            base: v_start,
            start: v_start,
            end: v_end,
            stride: v_stride,
        },
        Span::DUMMY,
    ));

    bb1.instructions.push(Instruction::new(
        Some(ValueId(5)),
        ValueExpr::Constant(ConstantValue::Bool(true)),
        Span::DUMMY,
    ));
    bb1.terminator = Some(Terminator::BranchCond {
        cond: ValueId(5),
        then_block: BlockId(1),
        else_block: BlockId(2),
        then_args: Vec::new(),
        else_args: Vec::new(),
    });
    func.blocks.push(bb1);

    let mut bb2 = BasicBlock::new(BlockId(2));
    bb2.terminator = Some(Terminator::Return(None));
    func.blocks.push(bb2);

    let module = FirModule {
        name: ifa_span::INTERNER.intern("strided_conv_mod"),
        functions: vec![func],
        structs: Vec::new(),
        enums: Vec::new(),
        constants: Vec::new(),
    };

    let llvm_ir = emitter
        .emit_module(&module)
        .expect("LLVM IR emission for strided conv failed");

    assert!(
        llvm_ir.contains("!llvm.loop !57"),
        "Loop branch must reference 2D strided convolution metadata !57:\n{}",
        llvm_ir
    );
    assert!(
        llvm_ir.contains("!57 = distinct !{!57, !2, !3, !4, !5, !12, !13, !24, !37, !38}"),
        "Metadata table must contain !57 2D strided conv node:\n{}",
        llvm_ir
    );
    assert!(
        llvm_ir.contains("!53 = distinct !{!53, !2, !3, !4, !5, !12, !13, !24, !37, !39}"),
        "Metadata table must contain !53 3D strided conv node:\n{}",
        llvm_ir
    );
    assert!(
        llvm_ir.contains("sdiv i64"),
        "LLVM IR must emit strided length calculation with division:\n{}",
        llvm_ir
    );

    let temp_dir = std::env::temp_dir().join(format!("ifa_strided_test_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("strided_conv.o");

    let compiler = LlvmCompiler::new(target);
    let compile_res = compiler.compile_to_object(&module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Native compilation to object with 2D strided conv metadata failed: {:?}",
        compile_res.err()
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_strided_bounds_check_and_simd_reductions_llvm() {
    use ifa_fir::*;
    use ifa_span::Span;

    let target = LlvmTargetConfig::x86_64();
    let mut emitter = LlvmIrEmitter::new(&target);

    let mut func = FirFunction::new(
        ifa_span::INTERNER.intern("test_strided_pipeline"),
        Vec::new(),
        FirType::Unit,
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );
    func.blocks.clear();

    let mut bb0 = BasicBlock::new(BlockId(0));
    let v_base = ValueId(0);
    let v_start = ValueId(1);
    let v_end = ValueId(2);
    let v_stride = ValueId(3);
    let v_slice = ValueId(4);

    bb0.instructions.push(Instruction::new(
        Some(v_base),
        ValueExpr::Constant(ConstantValue::Int(100, ifa_sema::types::IntType::I64)),
        Span::DUMMY,
    ));
    bb0.instructions.push(Instruction::new(
        Some(v_start),
        ValueExpr::Constant(ConstantValue::Int(0, ifa_sema::types::IntType::I64)),
        Span::DUMMY,
    ));
    bb0.instructions.push(Instruction::new(
        Some(v_end),
        ValueExpr::Constant(ConstantValue::Int(32, ifa_sema::types::IntType::I64)),
        Span::DUMMY,
    ));
    bb0.instructions.push(Instruction::new(
        Some(v_stride),
        ValueExpr::Constant(ConstantValue::Int(2, ifa_sema::types::IntType::I64)),
        Span::DUMMY,
    ));

    // Effectful Strided Bounds Check
    bb0.instructions.push(Instruction::new(
        None,
        ValueExpr::SliceStridedBoundsCheck {
            base: v_base,
            start: v_start,
            end: v_end,
            stride: v_stride,
            redundant: false,
        },
        Span::DUMMY,
    ));

    // Strided Slice Extraction
    bb0.instructions.push(Instruction::new(
        Some(v_slice),
        ValueExpr::SliceStrided {
            base: v_base,
            start: v_start,
            end: v_end,
            stride: v_stride,
        },
        Span::DUMMY,
    ));

    bb0.terminator = Some(Terminator::Return(None));
    func.blocks.push(bb0);

    let module = FirModule {
        name: ifa_span::INTERNER.intern("strided_pipeline_mod"),
        functions: vec![func],
        structs: Vec::new(),
        enums: Vec::new(),
        constants: Vec::new(),
    };

    let llvm_ir = emitter
        .emit_module(&module)
        .expect("LLVM IR emission for strided bounds check failed");

    assert!(
        llvm_ir
            .contains("declare void @ifa_rt_slice_strided_bounds_check(i64, i64, i64, i64, ptr)"),
        "LLVM IR must declare @ifa_rt_slice_strided_bounds_check:\n{}",
        llvm_ir
    );
    assert!(
        llvm_ir.contains("call void @ifa_rt_slice_strided_bounds_check(i64 %v1, i64 %v2, i64 %v3"),
        "LLVM IR must emit call to @ifa_rt_slice_strided_bounds_check with operands:\n{}",
        llvm_ir
    );
    assert!(
        llvm_ir.contains("define linkonce_odr float @ifa_simd_strided_slice_sum_f32"),
        "LLVM IR must define @ifa_simd_strided_slice_sum_f32:\n{}",
        llvm_ir
    );
    assert!(
        llvm_ir.contains("define linkonce_odr double @ifa_simd_strided_slice_sum_f64"),
        "LLVM IR must define @ifa_simd_strided_slice_sum_f64:\n{}",
        llvm_ir
    );
    assert!(
        llvm_ir.contains("define linkonce_odr i32 @ifa_simd_strided_slice_sum_i32"),
        "LLVM IR must define @ifa_simd_strided_slice_sum_i32:\n{}",
        llvm_ir
    );
    assert!(
        llvm_ir.contains("define linkonce_odr i64 @ifa_simd_strided_slice_sum_i64"),
        "LLVM IR must define @ifa_simd_strided_slice_sum_i64:\n{}",
        llvm_ir
    );
    assert!(
        llvm_ir.contains("define linkonce_odr float @ifa_simd_strided_slice_dot_f32"),
        "LLVM IR must define @ifa_simd_strided_slice_dot_f32:\n{}",
        llvm_ir
    );
    assert!(
        llvm_ir.contains("define linkonce_odr double @ifa_simd_strided_slice_dot_f64"),
        "LLVM IR must define @ifa_simd_strided_slice_dot_f64:\n{}",
        llvm_ir
    );

    let temp_dir =
        std::env::temp_dir().join(format!("ifa_strided_pipe_test_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("strided_pipeline.o");

    let compiler = LlvmCompiler::new(target);
    let compile_res = compiler.compile_to_object(&module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Native compilation to object with strided bounds checks failed: {:?}",
        compile_res.err()
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_coroutine_generator_stream_licm_gen_check_elimination() {
    use ifa_codegen_llvm::compiler::LlvmCompiler;
    use ifa_codegen_llvm::ir_emitter::LlvmIrEmitter;
    use ifa_codegen_llvm::target::LlvmTargetConfig;
    use ifa_fir::{
        BlockId, FirFunction, FirModule, FirParam, FirType, Instruction, LicmPass, ParamMode,
        Terminator, ValueExpr, ValueId,
    };
    use ifa_sema::types::IntType;
    use ifa_span::{Span, INTERNER};
    use std::fs;

    let target = LlvmTargetConfig::x86_64();
    let mut emitter = LlvmIrEmitter::new(&target);

    let fn_name = INTERNER.intern("coro_stream_licm_gen");
    let param = FirParam {
        name: INTERNER.intern("buffer_ref"),
        val: ValueId(0),
        ty: FirType::Pointer(Box::new(FirType::Int(IntType::I64))),
        mode: ParamMode::In,
        noalias: true,
    };

    let mut func = FirFunction::new(
        fn_name,
        vec![param],
        FirType::Unit,
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );
    func.is_coroutine = true;

    let b_entry = BlockId(0);
    let b_preheader = func.alloc_block();
    let b_header = func.alloc_block();
    let b_body = func.alloc_block();
    let b_exit = func.alloc_block();

    func.get_block_mut(b_entry)
        .unwrap()
        .set_terminator(Terminator::Branch {
            target: b_preheader,
            args: Vec::new(),
        });
    func.get_block_mut(b_preheader)
        .unwrap()
        .set_terminator(Terminator::Branch {
            target: b_header,
            args: Vec::new(),
        });

    let v_cond = func.alloc_value();
    func.get_block_mut(b_header)
        .unwrap()
        .set_terminator(Terminator::BranchCond {
            cond: v_cond,
            then_block: b_body,
            then_args: Vec::new(),
            else_block: b_exit,
            else_args: Vec::new(),
        });

    let v_gen_ref = func.alloc_value();
    let v_deref = func.alloc_value();
    let v_load = func.alloc_value();

    let body_bb = func.get_block_mut(b_body).unwrap();
    // Invariant GenRef and GenCheck in coroutine loop
    body_bb.push_instruction(Instruction::new(
        Some(v_gen_ref),
        ValueExpr::GenRef { ptr: ValueId(0) },
        Span::DUMMY,
    ));
    body_bb.push_instruction(Instruction::new(
        None,
        ValueExpr::GenCheck {
            ref_val: v_gen_ref,
            redundant: false,
        },
        Span::DUMMY,
    ));
    body_bb.push_instruction(Instruction::new(
        Some(v_deref),
        ValueExpr::GenDeref { ref_val: v_gen_ref },
        Span::DUMMY,
    ));
    body_bb.push_instruction(Instruction::new(
        Some(v_load),
        ValueExpr::Load { ptr: v_deref },
        Span::DUMMY,
    ));
    body_bb.push_instruction(Instruction::new(
        None,
        ValueExpr::YieldValue { val: v_load },
        Span::DUMMY,
    ));
    body_bb.set_terminator(Terminator::Branch {
        target: b_header,
        args: Vec::new(),
    });

    func.get_block_mut(b_exit)
        .unwrap()
        .set_terminator(Terminator::Return(None));

    // Run LICM pass on the coroutine function
    let mut licm = LicmPass::new();
    licm.run_on_function(&mut func);

    let stats = licm.stats();
    assert_eq!(
        stats.hoisted_gen_checks, 1,
        "GenCheck must be hoisted into preheader: {:?}",
        stats
    );
    assert_eq!(
        stats.hoisted_gen_refs, 1,
        "GenRef must be hoisted into preheader: {:?}",
        stats
    );

    let module = FirModule {
        name: INTERNER.intern("coro_licm_mod"),
        functions: vec![func],
        structs: Vec::new(),
        enums: Vec::new(),
        constants: Vec::new(),
    };

    let ir = emitter.emit_module(&module).unwrap();

    // 1. Verify LLVM Coroutine Intrinsics are declared and used
    assert!(
        ir.contains("call token @llvm.coro.id("),
        "Must call @llvm.coro.id:\n{}",
        ir
    );
    assert!(
        ir.contains("call ptr @llvm.coro.begin("),
        "Must call @llvm.coro.begin:\n{}",
        ir
    );
    assert!(
        ir.contains("call i8 @llvm.coro.suspend("),
        "Must call @llvm.coro.suspend:\n{}",
        ir
    );

    // 2. Verify that in the loop preheader (bb1), the hoisted check @ifa_rt_gen_check is emitted
    assert!(
        ir.contains("call void @ifa_rt_gen_check("),
        "LLVM IR must contain @ifa_rt_gen_check in the preheader:\n{}",
        ir
    );

    // 3. Verify that the loop body block where suspension occurs does NOT contain dynamic gen_check
    if let Some(b3_idx) = ir.find("bb3:") {
        let after_b3 = &ir[b3_idx..];
        let b3_end = after_b3.find("br label %bb2").unwrap_or(after_b3.len());
        let b3_body = &after_b3[..b3_end];
        assert!(
            !b3_body.contains("@ifa_rt_gen_check"),
            "Coroutine loop body must NOT contain dynamic @ifa_rt_gen_check call after LICM hoisting:\n{}",
            b3_body
        );
    }

    // 4. Verify native compilation to object file succeeds
    let temp_dir = std::env::temp_dir().join(format!("llvm_coro_licm_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("coro_licm.o");

    let compiler = LlvmCompiler::new(target);
    let res = compiler.compile_to_object(&module, &obj_path);
    assert!(
        res.is_ok(),
        "Native compilation of coroutine with LICM-eliminated gen_check failed: {:?}",
        res.err()
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_codegen_channel_try_send_nonblocking() {
    use ifa_codegen_llvm::target::LlvmTargetConfig;
    use ifa_fir::{
        BasicBlock, BlockId, ConstantValue, FirFunction, FirModule, FirType, Instruction,
        Terminator, ValueExpr, ValueId,
    };
    use ifa_sema::types::IntType;
    use ifa_span::{Span, INTERNER};

    let target = LlvmTargetConfig::x86_64();
    let mut emitter = LlvmIrEmitter::new(&target);

    let fn_name = INTERNER.intern("channel_try_send_test");
    let mut func = FirFunction::new(
        fn_name,
        vec![],
        FirType::Int(IntType::I32),
        false,
        false,
        false,
        None,
        Span::DUMMY,
    );
    func.blocks.clear();

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
        ValueExpr::Constant(ConstantValue::Int(42, IntType::I64)),
        Span::DUMMY,
    ));

    let try_send_res = ValueId(3);
    bb0.instructions.push(Instruction::new(
        Some(try_send_res),
        ValueExpr::ChanTrySend { chan: ch, val },
        Span::DUMMY,
    ));

    bb0.terminator = Some(Terminator::Return(Some(try_send_res)));
    func.blocks.push(bb0);

    let module = FirModule {
        name: INTERNER.intern("try_send_mod"),
        functions: vec![func],
        structs: Vec::new(),
        enums: Vec::new(),
        constants: Vec::new(),
    };

    let ir = emitter.emit_module(&module).unwrap();
    assert!(
        ir.contains("call i32 @ifa_rt_channel_try_send(ptr %v1, ptr %chan_try_val_cast_2)"),
        "LLVM IR should emit ifa_rt_channel_try_send call: \n{}",
        ir
    );
    assert!(ir.contains("declare i32 @ifa_rt_channel_try_send(ptr, ptr)"));
}

#[test]
fn test_llvm_strided_loop_vectorization_metadata_and_compilation() {
    use ifa_codegen_llvm::compiler::LlvmCompiler;
    use ifa_codegen_llvm::ir_emitter::LlvmIrEmitter;
    use ifa_codegen_llvm::target::LlvmTargetConfig;
    use ifa_fir::{
        BasicBlock, BlockId, ConstantValue, FirFunction, FirModule, FirParam, FirType, Instruction,
        LoopVectorHint, ParamMode, Terminator, ValueExpr, ValueId,
    };
    use ifa_sema::types::IntType;
    use ifa_span::{Span, INTERNER};

    let target = LlvmTargetConfig::x86_64();
    let mut emitter = LlvmIrEmitter::new(&target);

    let fn_name = INTERNER.intern("test_llvm_strided_loop");
    let mut func = FirFunction::new(
        fn_name,
        vec![FirParam::new(
            INTERNER.intern("arr"),
            ValueId(0),
            FirType::Slice(Box::new(FirType::Int(IntType::I64))),
            ParamMode::InOut,
        )],
        FirType::Unit,
        true,
        true,
        false,
        None,
        Span::DUMMY,
    );
    func.blocks.clear();

    let b0 = BlockId(0);
    let b1 = BlockId(1);
    let mut bb0 = BasicBlock::new(b0);
    let mut bb1 = BasicBlock::new(b1);

    let v_stride = ValueId(1);
    bb0.instructions.push(Instruction::new(
        Some(v_stride),
        ValueExpr::Constant(ConstantValue::Int(2, IntType::I64)),
        Span::DUMMY,
    ));
    bb0.terminator = Some(Terminator::Branch {
        target: b1,
        args: vec![],
    });

    let v_zero = ValueId(2);
    bb1.instructions.push(Instruction::new(
        Some(v_zero),
        ValueExpr::Constant(ConstantValue::Int(0, IntType::I64)),
        Span::DUMMY,
    ));

    // Vector hint for 4-lane strided loop (i64, vector_width=4, loop_stride=2)
    let hint = LoopVectorHint::new(4, 4, true).with_strided_loop(2);
    bb1.set_vector_hint(hint);
    bb1.terminator = Some(Terminator::Branch {
        target: b1,
        args: vec![],
    });

    func.blocks.push(bb0);
    func.blocks.push(bb1);

    let module = FirModule {
        name: INTERNER.intern("strided_loop_mod"),
        functions: vec![func],
        structs: Vec::new(),
        enums: Vec::new(),
        constants: Vec::new(),
    };

    let ir = emitter.emit_module(&module).unwrap();

    // Verify 1D strided vectorization metadata !62 is declared
    assert!(
        ir.contains("!62 = distinct !{!62, !2, !7, !4, !5, !12, !13, !24}"),
        "LLVM IR must define !62 strided vectorization node:\n{}",
        ir
    );
    // Verify branch attaches !llvm.loop !62
    assert!(
        ir.contains("br label %bb1, !llvm.loop !62"),
        "Loop branch must attach !llvm.loop !62 metadata:\n{}",
        ir
    );

    // Verify compilation to native object succeeds
    let temp_dir = std::env::temp_dir();
    let obj_path = temp_dir.join("test_strided_loop.o");
    let compiler = LlvmCompiler::new(target);
    let compile_res = compiler.compile_to_object(&module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "LLVM object compilation with strided vectorization hints failed: {:?}",
        compile_res.err()
    );
    if obj_path.exists() {
        let _ = std::fs::remove_file(obj_path);
    }
}

#[test]
fn test_llvm_aot_slice_pattern_matching_dynamic_tail_offset() {
    let src = r#"
fn classify_slice_tail(s: Slice<i64>) -> i64 {
    return match s {
        [head, ..mid, penultimate, tail] => head * 1000 + penultimate * 100 + tail,
        [first, ..rest, last] => first * 10 + last,
        [single] => single,
        _ => 0,
    };
}

pub fn main() -> i64 {
    let ledger: [i64; 5] = [5, 1, 2, 7, 9];
    let window: Slice<i64> = ledger[..];
    let val4 = classify_slice_tail(window); // 5 * 1000 + 7 * 100 + 9 = 5709

    let duo: [i64; 2] = [3, 8];
    let val2 = classify_slice_tail(duo[..]); // 3 * 10 + 8 = 38

    let single: [i64; 1] = [42];
    let val1 = classify_slice_tail(single[..]); // 42

    let empty: [i64; 0] = [];
    let val0 = classify_slice_tail(empty[..]); // 0

    if val4 == 5709 && val2 == 38 && val1 == 42 && val0 == 0 {
        return 42;
    }
    return 1;
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("slice_pattern_tail.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let temp_dir = std::env::temp_dir().join(format!("llvm_slice_pat_tail_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("slice_tail.o");
    let bin_path = temp_dir.join("slice_tail_exec");

    let compiler = LlvmCompiler::new(LlvmTargetConfig::host());
    let compile_res = compiler.compile_to_object(&module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Object compilation failed: {:?}",
        compile_res.err()
    );

    let link_res = LlvmCompiler::link_executable(&obj_path, &bin_path);
    assert!(link_res.is_ok(), "Native link failed: {:?}", link_res.err());

    let output = std::process::Command::new(&bin_path)
        .output()
        .expect("Failed to execute native binary");
    assert_eq!(
        output.status.code(),
        Some(42),
        "Native binary output exit code must be 42"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_aot_for_loop_inout_array_and_tuple_destructuring() {
    let src = r#"
struct Point {
    x: i64,
    y: i64,
}

pub fn main() -> i64 {
    mut nums: [i64; 4] = [2, 4, 6, 8];
    for inout n in nums {
        n = n / 2;
    }
    // nums is now [1, 2, 3, 4]
    let sum1 = nums[0] + nums[1] + nums[2] + nums[3]; // 10

    mut pairs: [(i64, i64); 2] = [(1, 2), (3, 4)];
    for (inout a, inout b) in pairs {
        a = a + 10;
        b = b * 2;
    }
    // pairs is now [(11, 4), (13, 8)]
    let (x0, y0) = pairs[0];
    let (x1, y1) = pairs[1];
    let sum2 = x0 + y0 + x1 + y1; // 36

    mut points: [Point; 2] = [Point { x: 1, y: 2 }, Point { x: 3, y: 4 }];
    for Point { inout x, inout y } in points {
        x = x * 10;
        y = y * 2;
    }
    let p0 = points[0];
    let p1 = points[1];
    let sum3 = p0.x + p0.y + p1.x + p1.y; // 52

    if sum1 == 10 && sum2 == 36 && sum3 == 52 {
        return 42;
    }
    return 1;
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("for_inout_llvm.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let temp_dir = std::env::temp_dir().join(format!("llvm_for_inout_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("for_inout.o");
    let bin_path = temp_dir.join("for_inout_exec");

    let compiler = LlvmCompiler::new(LlvmTargetConfig::host());
    let compile_res = compiler.compile_to_object(&module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Object compilation failed: {:?}",
        compile_res.err()
    );

    let link_res = LlvmCompiler::link_executable(&obj_path, &bin_path);
    assert!(link_res.is_ok(), "Native link failed: {:?}", link_res.err());

    let output = std::process::Command::new(&bin_path)
        .output()
        .expect("Failed to execute native binary");
    assert_eq!(
        output.status.code(),
        Some(42),
        "Native binary output exit code must be 42"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_aot_strict_closure_capturing_local_arena_execution() {
    let src = r#"
        struct Arena {
            capacity: i64,
        }

        pub strict fn compute_with_local_arena() -> i64 {
            let arena_buf = Arena(capacity: 50);
            let multiplier: i64 = 4;
            let transform = fn(x: i64) -> i64 {
                return (x * multiplier) + arena_buf.capacity;
            };
            return transform(10);
        }

        pub fn main() -> i64 {
            let res = compute_with_local_arena();
            if res == 90 {
                return 42;
            }
            return 1;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("llvm_strict_arena_closure.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let temp_dir =
        std::env::temp_dir().join(format!("llvm_aot_strict_arena_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("strict_arena.o");
    let bin_path = temp_dir.join("strict_arena_exec");

    let compiler = LlvmCompiler::new(LlvmTargetConfig::host());
    let compile_res = compiler.compile_to_object(&fir_module, &obj_path);
    assert!(
        compile_res.is_ok(),
        "Native compilation of strict arena closure module failed: {:?}",
        compile_res.err()
    );
    assert!(obj_path.exists());

    let link_res = LlvmCompiler::link_executable(&obj_path, &bin_path);
    assert!(link_res.is_ok(), "Native link failed: {:?}", link_res.err());
    assert!(bin_path.exists());

    let output = std::process::Command::new(&bin_path)
        .output()
        .expect("Failed to execute native binary");
    assert_eq!(
        output.status.code(),
        Some(42),
        "Native binary output exit code must be 42 (90 -> 42)"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_multidim_strided_projection_simd_metadata_and_compilation() {
    use ifa_codegen_llvm::compiler::LlvmCompiler;
    use ifa_codegen_llvm::ir_emitter::LlvmIrEmitter;
    use ifa_codegen_llvm::target::LlvmTargetConfig;
    use ifa_fir::{
        BasicBlock, BlockId, ConstantValue, FirFunction, FirModule, FirParam, FirType, Instruction,
        LoopVectorHint, ParamMode, Terminator, ValueExpr, ValueId,
    };
    use ifa_sema::types::IntType;
    use ifa_span::{Span, INTERNER};

    let target = LlvmTargetConfig::x86_64();
    let mut emitter = LlvmIrEmitter::new(&target);

    let fn_name = INTERNER.intern("test_llvm_multidim_strided");
    let mut func = FirFunction::new(
        fn_name,
        vec![FirParam::new(
            INTERNER.intern("matrix"),
            ValueId(0),
            FirType::Slice(Box::new(FirType::Slice(Box::new(FirType::Int(
                IntType::I64,
            ))))),
            ParamMode::InOut,
        )],
        FirType::Unit,
        true,
        true,
        false,
        None,
        Span::DUMMY,
    );
    func.blocks.clear();

    let b0 = BlockId(0);
    let b1 = BlockId(1);
    let mut bb0 = BasicBlock::new(b0);
    let mut bb1 = BasicBlock::new(b1);

    // Block 0: Extract row 0, then create strided subslice with stride 2
    let v_row_idx = ValueId(1);
    bb0.instructions.push(Instruction::new(
        Some(v_row_idx),
        ValueExpr::Constant(ConstantValue::Int(0, IntType::I64)),
        Span::DUMMY,
    ));
    let v_row_slice = ValueId(2);
    bb0.instructions.push(Instruction::new(
        Some(v_row_slice),
        ValueExpr::GetElement {
            base: ValueId(0),
            index: v_row_idx,
        },
        Span::DUMMY,
    ));
    let v_start = ValueId(3);
    bb0.instructions.push(Instruction::new(
        Some(v_start),
        ValueExpr::Constant(ConstantValue::Int(0, IntType::I64)),
        Span::DUMMY,
    ));
    let v_end = ValueId(4);
    bb0.instructions.push(Instruction::new(
        Some(v_end),
        ValueExpr::Constant(ConstantValue::Int(100, IntType::I64)),
        Span::DUMMY,
    ));
    let v_stride = ValueId(5);
    bb0.instructions.push(Instruction::new(
        Some(v_stride),
        ValueExpr::Constant(ConstantValue::Int(2, IntType::I64)),
        Span::DUMMY,
    ));
    let v_strided_slice = ValueId(6);
    bb0.instructions.push(Instruction::new(
        Some(v_strided_slice),
        ValueExpr::SliceStrided {
            base: v_row_slice,
            start: v_start,
            end: v_end,
            stride: v_stride,
        },
        Span::DUMMY,
    ));
    bb0.terminator = Some(Terminator::Branch {
        target: b1,
        args: vec![],
    });

    // Block 1: GetElement on strided slice (index scaled by 2)
    let v_idx = ValueId(7);
    bb1.instructions.push(Instruction::new(
        Some(v_idx),
        ValueExpr::Constant(ConstantValue::Int(5, IntType::I64)),
        Span::DUMMY,
    ));
    let v_elem = ValueId(8);
    bb1.instructions.push(Instruction::new(
        Some(v_elem),
        ValueExpr::GetElement {
            base: v_strided_slice,
            index: v_idx,
        },
        Span::DUMMY,
    ));

    // Multidimensional strided vector hint (4 lanes, unroll-and-jam)
    let hint = LoopVectorHint::new(4, 4, true).with_strided_multidim();
    bb1.set_vector_hint(hint);
    bb1.terminator = Some(Terminator::Branch {
        target: b1,
        args: vec![],
    });

    func.blocks.push(bb0);
    func.blocks.push(bb1);

    let module = FirModule {
        name: INTERNER.intern("test_llvm_multidim_strided_mod"),
        functions: vec![func],
        structs: Vec::new(),
        enums: Vec::new(),
        constants: Vec::new(),
    };

    let ir = emitter.emit_module(&module).unwrap();

    assert!(
        ir.contains("!llvm.loop !66"),
        "Must attach metadata !66 for 4-lane multidim strided loop:\n{}",
        ir
    );
    assert!(
        ir.contains("!65 = distinct !{!65, !2, !3, !4, !5, !12, !13, !24, !37, !38}"),
        "Must declare metadata !65"
    );
    assert!(
        ir.contains("!66 = distinct !{!66, !2, !7, !4, !5, !12, !13, !24, !37, !38}"),
        "Must declare metadata !66"
    );
    assert!(
        ir.contains("%strided_idx_8 = shl i64 %v7, 1"),
        "Must scale strided element index with power-of-two shift (stride 2):\n{}",
        ir
    );

    let temp_dir =
        std::env::temp_dir().join(format!("llvm_multidim_strided_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("multidim_strided.o");

    let compiler = LlvmCompiler::new(target);
    let res = compiler.compile_to_object(&module, &obj_path);
    assert!(
        res.is_ok(),
        "Compilation to object must succeed: {:?}",
        res.err()
    );
    assert!(obj_path.exists());
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_strict_coroutine_arena_frame_and_slice_exchange() {
    use ifa_codegen_llvm::compiler::LlvmCompiler;
    use ifa_codegen_llvm::ir_emitter::LlvmIrEmitter;
    use ifa_codegen_llvm::target::LlvmTargetConfig;
    use ifa_fir::{
        BasicBlock, BlockId, FirFunction, FirModule, FirParam, FirType, Instruction, ParamMode,
        Terminator, ValueExpr, ValueId,
    };
    use ifa_sema::types::IntType;
    use ifa_span::{Span, INTERNER};

    let target = LlvmTargetConfig::x86_64();
    let mut emitter = LlvmIrEmitter::new(&target);

    let fn_name = INTERNER.intern("test_strict_coro_slice");
    let mut func = FirFunction::new(
        fn_name,
        vec![FirParam::new(
            INTERNER.intern("input_slice"),
            ValueId(0),
            FirType::Slice(Box::new(FirType::Int(IntType::I64))),
            ParamMode::In,
        )],
        FirType::Slice(Box::new(FirType::Int(IntType::I64))),
        true,
        false,
        true, // strict fn
        None,
        Span::DUMMY,
    );
    func.is_coroutine = true;
    func.blocks.clear();

    let b0 = BlockId(0);
    let mut bb0 = BasicBlock::new(b0);

    // Yield slice ValueId(0)
    let v_res = ValueId(1);
    bb0.instructions.push(Instruction::new(
        Some(v_res),
        ValueExpr::YieldValue { val: ValueId(0) },
        Span::DUMMY,
    ));

    // Return slice ValueId(0)
    bb0.terminator = Some(Terminator::Return(Some(ValueId(0))));
    func.blocks.push(bb0);

    let module = FirModule {
        name: INTERNER.intern("test_strict_coro_slice_mod"),
        functions: vec![func],
        structs: Vec::new(),
        enums: Vec::new(),
        constants: Vec::new(),
    };

    let ir = emitter.emit_module(&module).unwrap();

    assert!(
        ir.contains("%coro.yield_slot = alloca { ptr, i64 }, align 8"),
        "Must allocate composite {{ ptr, i64 }} yield slot for slice coroutine:\n{}",
        ir
    );
    assert!(
        ir.contains("call ptr @ifa_rt_call_arena_alloc(i64 %coro.size, i64 8)"),
        "Must allocate coroutine frame in strict mode from pre-allocated call arena:\n{}",
        ir
    );
    assert!(
        ir.contains("store { ptr, i64 } %v0, ptr %coro.yield_slot, align 8"),
        "Must store yielded slice into yield slot:\n{}",
        ir
    );
    assert!(
        ir.contains("define linkonce_odr { ptr, i64 } @ifa_coro_run_to_completion_slice(ptr %hdl)"),
        "Must emit slice run_to_completion helper:\n{}",
        ir
    );

    let temp_dir = std::env::temp_dir().join(format!("llvm_strict_coro_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("strict_coro.o");

    let compiler = LlvmCompiler::new(target);
    let res = compiler.compile_to_object(&module, &obj_path);
    assert!(
        res.is_ok(),
        "Compilation to object must succeed: {:?}",
        res.err()
    );
    assert!(obj_path.exists());
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_multi_arena_matrix_kernel_elementwise_fused_llvm_emission() {
    use ifa_codegen_llvm::compiler::LlvmCompiler;
    use ifa_codegen_llvm::ir_emitter::LlvmIrEmitter;
    use ifa_codegen_llvm::target::LlvmTargetConfig;
    use ifa_fir::{
        BasicBlock, BlockId, FirFunction, FirModule, FirType, LoopVectorHint, Terminator,
    };
    use ifa_span::{Span, INTERNER};

    let target = LlvmTargetConfig::x86_64();
    let mut emitter = LlvmIrEmitter::new(&target);

    let fn_name = INTERNER.intern("kernel_gemm_multi_arena_fused");
    let mut func = FirFunction::new(
        fn_name,
        vec![],
        FirType::Unit,
        false,
        false,
        false,
        None,
        Span::DUMMY,
    );
    func.blocks.clear();

    let b0 = BlockId(0);
    let b1 = BlockId(1);

    let mut bb0 = BasicBlock::new(b0);
    bb0.terminator = Some(Terminator::Branch {
        target: b1,
        args: vec![],
    });

    let mut bb1 = BasicBlock::new(b1);
    // Multi-arena matrix kernel with 4 lanes and elementwise fusion
    let hint = LoopVectorHint::new(4, 4, true)
        .with_multi_arena_matrix(3)
        .with_elementwise_fused(true)
        .with_adaptive_tiling(32);
    bb1.set_vector_hint(hint);
    bb1.terminator = Some(Terminator::Branch {
        target: b1,
        args: vec![],
    });

    func.blocks.push(bb0);
    func.blocks.push(bb1);

    let module = FirModule {
        name: INTERNER.intern("test_llvm_multi_arena_fused_mod"),
        functions: vec![func],
        structs: Vec::new(),
        enums: Vec::new(),
        constants: Vec::new(),
    };

    let ir = emitter.emit_module(&module).unwrap();

    assert!(
        ir.contains("!llvm.loop !70"),
        "Must attach metadata !70 for 4-lane multi-arena elementwise fused kernel:\n{}",
        ir
    );
    assert!(
        ir.contains("!69 = distinct !{!69, !2, !3, !4, !5, !12, !13, !24, !37, !39}"),
        "Must declare metadata !69"
    );
    assert!(
        ir.contains("!70 = distinct !{!70, !2, !7, !4, !5, !12, !13, !24, !37, !39}"),
        "Must declare metadata !70"
    );

    let temp_dir = std::env::temp_dir().join(format!("llvm_multi_arena_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("multi_arena.o");

    let compiler = LlvmCompiler::new(target);
    let res = compiler.compile_to_object(&module, &obj_path);
    assert!(
        res.is_ok(),
        "Compilation to object must succeed: {:?}",
        res.err()
    );
    assert!(obj_path.exists());
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_llvm_multi_arena_fused_convolution_metadata_and_loop_elision() {
    use ifa_codegen_llvm::compiler::LlvmCompiler;
    use ifa_codegen_llvm::ir_emitter::LlvmIrEmitter;
    use ifa_codegen_llvm::target::LlvmTargetConfig;
    use ifa_fir::{
        BasicBlock, BlockId, FirFunction, FirModule, FirType, Instruction, LoopVectorHint,
        Terminator, ValueExpr, ValueId,
    };
    use ifa_span::{Span, INTERNER};

    let target = LlvmTargetConfig::x86_64();
    let mut emitter = LlvmIrEmitter::new(&target);

    let fn_name = INTERNER.intern("fused_conv2d_multi_arena_test");
    let mut func = FirFunction::new(
        fn_name,
        vec![],
        FirType::Unit,
        true,
        false,
        false,
        None,
        Span::DUMMY,
    );
    func.blocks.clear();

    let b0 = BlockId(0);
    let b1 = BlockId(1);
    let mut bb0 = BasicBlock::new(b0);
    bb0.terminator = Some(Terminator::Branch {
        target: b1,
        args: vec![],
    });

    let mut bb1 = BasicBlock::new(b1);
    // Multi-arena fused 2D convolution with 8 lanes, bias and activation
    let hint = LoopVectorHint::new(8, 8, true).with_multi_arena_conv(false, true, true);
    bb1.set_vector_hint(hint);

    // Add an elided GenCheck (redundant: true)
    bb1.instructions.push(Instruction::new(
        None,
        ValueExpr::GenCheck {
            ref_val: ValueId(1),
            redundant: true,
        },
        Span::DUMMY,
    ));

    bb1.terminator = Some(Terminator::Branch {
        target: b1,
        args: vec![],
    });

    func.blocks.push(bb0);
    func.blocks.push(bb1);

    let module = FirModule {
        name: INTERNER.intern("test_llvm_multi_arena_conv_mod"),
        functions: vec![func],
        structs: Vec::new(),
        enums: Vec::new(),
        constants: Vec::new(),
    };

    let ir = emitter.emit_module(&module).unwrap();

    assert!(
        ir.contains("!llvm.loop !73"),
        "Must attach metadata !73 for 8-lane multi-arena fused convolution:\n{}",
        ir
    );
    assert!(
        ir.contains("!73 = distinct !{!73, !2, !3, !4, !5, !12, !13, !24, !37, !39}"),
        "Must declare metadata !73"
    );
    assert!(
        !ir.contains("call void @ifa_rt_gen_check"),
        "Elided generational checks must never emit runtime check calls:\n{}",
        ir
    );

    let temp_dir = std::env::temp_dir().join(format!("llvm_multi_conv_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let obj_path = temp_dir.join("multi_conv.o");

    let compiler = LlvmCompiler::new(target);
    let res = compiler.compile_to_object(&module, &obj_path);
    assert!(
        res.is_ok(),
        "Compilation to object must succeed: {:?}",
        res.err()
    );
    assert!(obj_path.exists());
    let _ = fs::remove_dir_all(&temp_dir);
}

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
    assert!(ir.contains("\"no-trapping-math\"=\"true\""));
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
    bb1.set_vector_hint(LoopVectorHint {
        vector_width: 8,
        interleave_count: 4,
        unroll_enable: true,
    });
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

    // 2. Verify untyped send cast and intrinsic
    assert!(ir.contains("%chan_val_cast_4 = inttoptr i64 %v4 to ptr"));
    assert!(ir.contains("call i32 @ifa_rt_channel_send(ptr %v1, ptr %chan_val_cast_4)"));

    // 3. Verify multi-channel select multiplexing with stackless suspension
    assert!(ir.contains("br label %coro.sel_poll_"));
    assert!(ir.contains(
        "%sel_poll_res_5_0 = call i64 @ifa_rt_channel_select(ptr %select_arr_5, i64 2, i32 1)"
    ));
    assert!(ir.contains("%sel_is_waiting_5_0 = icmp eq i64 %sel_poll_res_5_0, 2"));
    assert!(ir.contains("call i8 @llvm.coro.suspend(token none, i1 false)"));
    assert!(ir.contains("%v5 = phi i64 [ %sel_poll_res_5_0, %coro.sel_poll_0 ]"));

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

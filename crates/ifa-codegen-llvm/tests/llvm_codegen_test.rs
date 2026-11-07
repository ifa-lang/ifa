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

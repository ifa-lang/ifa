use ifa_codegen_cranelift::{AotCompiler, JitEngine};
use ifa_fir::compile_to_fir;
use ifa_lexer::tokenize;
use ifa_parser::parse;
use ifa_sema::analyze;
use ifa_span::SourceMap;
use std::env;
use std::fs;

#[test]
fn test_cranelift_jit_arithmetic_execution() {
    let src = r#"
        fn add(a: i64, b: i64) -> i64 {
            let res = a + b
            return res
        }

        pub fn main() -> i64 {
            let sum = add(35, 7)
            return sum
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("calc.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, _) = parse(fid, tokens);
    let analysis = analyze(&sm, &prog);
    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let mut jit = JitEngine::new().expect("Failed to initialize Cranelift JIT engine");
    jit.compile_module(&fir_module)
        .expect("Failed to compile FIR to Cranelift machine code");

    let result = jit.run_main().expect("Failed to execute native main");
    assert_eq!(result, 42);
}

#[test]
fn test_cranelift_jit_branching_and_comparisons() {
    let src = r#"
        fn max(a: i64, b: i64) -> i64 {
            if a > b {
                return a
            } else {
                return b
            }
        }

        pub fn main() -> i64 {
            let m1 = max(100, 42)
            let m2 = max(15, 99)
            return m1 + m2
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("branch.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, _) = parse(fid, tokens);
    let analysis = analyze(&sm, &prog);
    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let mut jit = JitEngine::new().expect("Failed to initialize Cranelift JIT engine");
    jit.compile_module(&fir_module)
        .expect("Failed to compile FIR to Cranelift machine code");

    let result = jit.run_main().expect("Failed to execute native main");
    assert_eq!(result, 199);
}

#[test]
fn test_cranelift_aot_object_emission() {
    let src = r#"
        pub fn main() -> i64 {
            let x = 10
            let y = 20
            return x * y
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("aot.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, _) = parse(fid, tokens);
    let analysis = analyze(&sm, &prog);
    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let aot = AotCompiler::new().expect("Failed to initialize AOT compiler");
    let out_dir = env::temp_dir().join("ifa_aot_test");
    let obj_path = out_dir.join("test_module.o");

    aot.compile_to_object(&fir_module, &obj_path)
        .expect("Failed to emit native object file");

    assert!(obj_path.exists());
    let metadata = fs::metadata(&obj_path).unwrap();
    assert!(metadata.len() > 0);

    let _ = fs::remove_dir_all(&out_dir);
}

#[test]
fn test_cranelift_jit_inout_mutation() {
    let src = r#"
        fn increment(inout val: i64, step: i64) {
            val = val + step;
        }

        pub fn main() -> i64 {
            mut counter: i64 = 50;
            increment(inout counter, 15);
            return counter;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("inout_test.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, _) = parse(fid, tokens);
    let analysis = analyze(&sm, &prog);
    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let mut jit = JitEngine::new().expect("Failed to initialize Cranelift JIT engine");
    jit.compile_module(&fir_module)
        .expect("Failed to compile FIR to Cranelift machine code");

    let result = jit.run_main().expect("Failed to execute native main");
    assert_eq!(result, 65);
}

#[test]
fn test_cranelift_aot_standalone_binary_execution() {
    let src = r#"
        fn multiply(a: i64, b: i64) -> i64 {
            return a * b;
        }

        pub fn main() -> i64 {
            let res = multiply(6, 7);
            return res;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("aot_exec.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, _) = parse(fid, tokens);
    let analysis = analyze(&sm, &prog);
    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let aot = AotCompiler::new().expect("Failed to initialize AOT compiler");
    let out_dir = env::temp_dir().join(format!("ifa_aot_exec_{}", std::process::id()));
    let obj_path = out_dir.join("test_mult.o");
    let bin_path = out_dir.join("test_mult");

    aot.compile_to_object(&fir_module, &obj_path)
        .expect("Failed to emit native object file");
    AotCompiler::link_executable(&obj_path, &bin_path).expect("Failed to link native executable");

    let output = std::process::Command::new(&bin_path)
        .output()
        .expect("Failed to execute native standalone binary");

    assert_eq!(output.status.code(), Some(42));

    let _ = fs::remove_dir_all(&out_dir);
}

#[test]
fn test_cranelift_generational_native_execution() {
    use ifa_fir::*;
    use ifa_span::{Span, INTERNER};

    let mod_name = INTERNER.intern("gen_test_mod");
    let mut fir_module = FirModule::new(mod_name);
    let fn_sym = INTERNER.intern("main");
    let mut func = FirFunction::new(
        fn_sym,
        Vec::new(),
        FirType::Int(ifa_sema::types::IntType::I64),
        true,
        false,
        false,
        None,
        Span::DUMMY,
    );

    let v_alloc = func.alloc_value();
    let v_99 = func.alloc_value();
    let v_load = func.alloc_value();

    let entry = func.get_block_mut(func.entry_block).unwrap();

    // 1. GenAlloc: allocate a generational 64-bit slot on arena 0
    entry.push_instruction(Instruction::new(
        Some(v_alloc),
        ValueExpr::GenAlloc {
            ty: FirType::Int(ifa_sema::types::IntType::I64),
            arena: Some(0),
        },
        Span::DUMMY,
    ));

    // 2. GenCheck: 1-cycle check
    entry.push_instruction(Instruction::new(
        None,
        ValueExpr::GenCheck {
            ref_val: v_alloc,
            redundant: false,
        },
        Span::DUMMY,
    ));

    // 3. SetField: write 99 into field 0
    entry.push_instruction(Instruction::new(
        Some(v_99),
        ValueExpr::Constant(ConstantValue::Int(99, ifa_sema::types::IntType::I64)),
        Span::DUMMY,
    ));
    entry.push_instruction(Instruction::new(
        None,
        ValueExpr::SetField {
            base: v_alloc,
            field_idx: 0,
            val: v_99,
        },
        Span::DUMMY,
    ));

    // 4. GetField: read from field 0
    let field_sym = INTERNER.intern("data");
    entry.push_instruction(Instruction::new(
        Some(v_load),
        ValueExpr::GetField {
            base: v_alloc,
            field_idx: 0,
            field_name: field_sym,
        },
        Span::DUMMY,
    ));

    // 5. Return loaded value
    entry.set_terminator(Terminator::Return(Some(v_load)));
    fir_module.functions.push(func);

    let mut jit = JitEngine::new().expect("Failed to initialize Cranelift JIT engine");
    jit.compile_module(&fir_module)
        .expect("Failed to compile generational FIR to Cranelift machine code");

    let result = jit.run_main().expect("Failed to execute native main");
    assert_eq!(result, 99);
}

#[test]
fn test_cranelift_jit_monomorphized_generic_functions() {
    let src = r#"
        fn identity<T>(x: T) -> T {
            return x;
        }

        fn add_vals<T>(a: T, b: T) -> T {
            return a + b;
        }

        pub fn main() -> i64 {
            let a = identity(100);
            let b = identity(23);
            let sum = add_vals(a, b);
            return sum;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("jit_generic.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, _) = ifa_parser::parse(fid, tokens);
    let analysis = ifa_sema::analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );
    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let mut jit = JitEngine::new().expect("Failed to initialize Cranelift JIT engine");
    jit.compile_module(&fir_module)
        .expect("Failed to compile monomorphized generic functions to Cranelift machine code");

    let result = jit.run_main().expect("Failed to execute native main");
    assert_eq!(result, 123);
}

#[test]
fn test_jit_for_loop_and_match_execution() {
    let src = r#"
        fn score(v: i64) -> i64 {
            return match v {
                10 => 1,
                20 => 2,
                30 => 3,
                _ => 0,
            };
        }

        pub fn main() -> i64 {
            let nums = [10, 20, 30];
            mut total = 0;
            for n in nums {
                total = total + score(n);
            }
            return total;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("jit_for_match.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, _) = ifa_parser::parse(fid, tokens);
    let analysis = ifa_sema::analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );
    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let mut jit = JitEngine::new().expect("Failed to initialize Cranelift JIT engine");
    jit.compile_module(&fir_module)
        .expect("Failed to compile for loop and match to Cranelift machine code");

    let result = jit.run_main().expect("Failed to execute native main");
    assert_eq!(result, 6); // 1 + 2 + 3 = 6
}

#[test]
fn test_jit_error_union_try_question_catch() {
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

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("jit_error.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, _) = ifa_parser::parse(fid, tokens);
    let analysis = ifa_sema::analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );
    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let mut jit = JitEngine::new().expect("Failed to initialize Cranelift JIT engine");
    jit.compile_module(&fir_module)
        .expect("Failed to compile error union propagation to Cranelift machine code");

    let result = jit.run_main().expect("Failed to execute native main");
    assert_eq!(result, 999);
}

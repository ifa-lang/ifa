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

#[test]
fn test_cranelift_jit_channel_operations() {
    use ifa_fir::{
        ConstantValue, FirFunction, FirModule, FirType, Instruction, Terminator, ValueExpr,
    };
    use ifa_sema::types::IntType;
    use ifa_span::{Span, INTERNER};

    let fn_name = INTERNER.intern("main");
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

    let v_chan = func.alloc_value();
    let v_send_val = func.alloc_value();
    let v_recv_val = func.alloc_value();

    let entry = func.get_block_mut(func.entry_block).unwrap();

    // 1. Create channel
    entry.push_instruction(Instruction::new(
        Some(v_chan),
        ValueExpr::ChanCreate {
            elem_ty: FirType::Int(IntType::I64),
            capacity: None,
        },
        Span::DUMMY,
    ));

    // 2. Prepare value 123
    entry.push_instruction(Instruction::new(
        Some(v_send_val),
        ValueExpr::Constant(ConstantValue::Int(123, IntType::I64)),
        Span::DUMMY,
    ));

    // 3. Send 123 into channel
    entry.push_instruction(Instruction::new(
        None,
        ValueExpr::ChanSend {
            chan: v_chan,
            val: v_send_val,
        },
        Span::DUMMY,
    ));

    // 4. Receive from channel
    entry.push_instruction(Instruction::new(
        Some(v_recv_val),
        ValueExpr::ChanRecv { chan: v_chan },
        Span::DUMMY,
    ));

    // 5. Close channel
    entry.push_instruction(Instruction::new(
        None,
        ValueExpr::ChanClose { chan: v_chan },
        Span::DUMMY,
    ));

    // 6. Return received value
    entry.set_terminator(Terminator::Return(Some(v_recv_val)));

    let mut module = FirModule::new(INTERNER.intern("test_chan_mod"));
    module.functions.push(func);

    let mut jit = JitEngine::new().expect("Failed to initialize Cranelift JIT engine");
    jit.compile_module(&module)
        .expect("Failed to compile channel operations to Cranelift");

    let result = jit.run_main().expect("Failed to run channel JIT");
    assert_eq!(result, 123);
}

#[test]
fn test_cranelift_jit_channel_select_operations() {
    use ifa_fir::{
        ConstantValue, FirFunction, FirModule, FirType, Instruction, Terminator, ValueExpr,
    };
    use ifa_sema::types::IntType;
    use ifa_span::{Span, INTERNER};

    let fn_name = INTERNER.intern("main");
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

    let v_chan1 = func.alloc_value();
    let v_chan2 = func.alloc_value();
    let v_val = func.alloc_value();
    let v_selected_idx = func.alloc_value();

    let entry = func.get_block_mut(func.entry_block).unwrap();

    // 1. Create chan1 and chan2
    entry.push_instruction(Instruction::new(
        Some(v_chan1),
        ValueExpr::ChanCreate {
            elem_ty: FirType::Int(IntType::I64),
            capacity: None,
        },
        Span::DUMMY,
    ));
    entry.push_instruction(Instruction::new(
        Some(v_chan2),
        ValueExpr::ChanCreate {
            elem_ty: FirType::Int(IntType::I64),
            capacity: None,
        },
        Span::DUMMY,
    ));

    // 2. Send data into chan2 (index 1)
    entry.push_instruction(Instruction::new(
        Some(v_val),
        ValueExpr::Constant(ConstantValue::Int(888, IntType::I64)),
        Span::DUMMY,
    ));
    entry.push_instruction(Instruction::new(
        None,
        ValueExpr::ChanSend {
            chan: v_chan2,
            val: v_val,
        },
        Span::DUMMY,
    ));

    // 3. Select over [chan1, chan2]
    entry.push_instruction(Instruction::new(
        Some(v_selected_idx),
        ValueExpr::ChanSelect {
            channels: vec![v_chan1, v_chan2],
            has_default: false,
        },
        Span::DUMMY,
    ));

    // 4. Return selected index (should be 1)
    entry.set_terminator(Terminator::Return(Some(v_selected_idx)));

    let mut module = FirModule::new(INTERNER.intern("test_select_mod"));
    module.functions.push(func);

    let mut jit = JitEngine::new().expect("Failed to initialize Cranelift JIT engine");
    jit.compile_module(&module)
        .expect("Failed to compile select operations to Cranelift");

    let result = jit.run_main().expect("Failed to run select JIT");
    assert_eq!(result, 1);
}

#[test]
fn test_cranelift_jit_monomorphized_trait_specialization() {
    let src = r#"
        trait Calculator {
            fn compute(self) -> i64;
        }

        struct Adder {
            a: i64,
            b: i64,
        }

        impl Calculator for Adder {
            fn compute(add: Adder) -> i64 {
                return add.a + add.b;
            }
        }

        struct Multiplier {
            x: i64,
            y: i64,
        }

        impl Calculator for Multiplier {
            fn compute(mul: Multiplier) -> i64 {
                return mul.x * mul.y;
            }
        }

        fn execute_calc<T: Calculator>(c: T) -> i64 {
            return c.compute();
        }

        pub fn main() -> i64 {
            let a = Adder(a: 20, b: 22);
            let m = Multiplier(x: 10, y: 5);
            return execute_calc(a) + execute_calc(m);
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("trait_jit.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, _) = parse(fid, tokens);
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );
    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let mut jit = JitEngine::new().expect("Failed to initialize Cranelift JIT engine");
    jit.compile_module(&fir_module)
        .expect("Failed to compile monomorphized trait FIR to Cranelift");

    let result = jit.run_main().expect("Failed to execute native main");
    assert_eq!(result, 92);
}

#[test]
fn test_cranelift_jit_adt_and_match_guards() {
    let src = r#"
        enum Message {
            Quit,
            Move(i64),
            Write(i64),
        }

        fn process(msg: Message) -> i64 {
            return match msg {
                Message::Quit => 0,
                Message::Move(dist) if dist > 100 => dist * 2,
                Message::Move(dist) => dist,
                Message::Write(len) => len + 10,
            }
        }

        pub fn main() -> i64 {
            let m1 = Message::Quit;
            let m2 = Message::Move(150);
            let m3 = Message::Move(40);
            let m4 = Message::Write(25);

            let r1 = process(m1);
            let r2 = process(m2);
            let r3 = process(m3);
            let r4 = process(m4);

            return r1 + r2 + r3 + r4;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("adt_jit.ifa", src);
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

    let mut jit = JitEngine::new().expect("Failed to initialize Cranelift JIT engine");
    jit.compile_module(&fir_module)
        .expect("Failed to compile ADT FIR to Cranelift");

    let result = jit.run_main().expect("Failed to execute native main");
    assert_eq!(result, 375);
}

#[test]
fn test_cranelift_jit_tuple_and_struct_match_destructuring() {
    let src = r#"
        struct Coord {
            x: i64,
            y: i64
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
    let fid = sm.add_file("cranelift_struct_tup.ifa", src);
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

    let mut jit = JitEngine::new().expect("Failed to initialize Cranelift JIT engine");
    jit.compile_module(&fir_module)
        .expect("Failed to compile FIR to Cranelift");

    let result = jit.run_main().expect("Failed to execute native main");
    // c1: 10, c2: 40, p1: 20, p2: 30, p3: 15 => 10 + 40 + 20 + 30 + 15 = 115
    assert_eq!(result, 115);
}

#[test]
fn test_cranelift_jit_or_and_range_pattern_matching() {
    let src = r#"
        fn classify_val(v: i64) -> i64 {
            return match v {
                1 | 3 | 5 => 10,
                10..=20 => 50,
                21..=25 | 30..=35 => 100,
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
    let fid = sm.add_file("cranelift_or_range.ifa", src);
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

    let mut jit = JitEngine::new().expect("Failed to initialize Cranelift JIT engine");
    jit.compile_module(&fir_module)
        .expect("Failed to compile FIR to Cranelift");

    let result = jit.run_main().expect("Failed to execute native main");
    // r1: 10, r2: 50, r3: 100, r4: 100, r5: 0 => 10 + 50 + 100 + 100 + 0 = 260
    assert_eq!(result, 260);
}

#[test]
fn test_cranelift_slice_pattern_matching_jit() {
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
            let b = classify_trio([5, 2, 7]);
            let c = classify_trio([10, 20, 30]);

            return a + b + c;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("cranelift_slice_pattern.ifa", src);
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

    let mut jit = JitEngine::new().expect("Failed to initialize Cranelift JIT engine");
    jit.compile_module(&fir_module)
        .expect("Failed to compile FIR to Cranelift");

    let result = jit.run_main().expect("Failed to execute native main");
    // a = 0, b = 57, c = 60 => 117
    assert_eq!(result, 117);
}

#[test]
fn test_cranelift_inout_pattern_destructuring() {
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
    let fid = sm.add_file("jit_inout_pat.ifa", src);
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

    let mut jit = JitEngine::new().expect("Failed to initialize Cranelift JIT engine");
    jit.compile_module(&fir_module)
        .expect("Failed to compile FIR to Cranelift");

    let result = jit.run_main().expect("Failed to execute native main");
    assert_eq!(result, 57);
}

#[test]
fn test_cranelift_ref_pattern_destructuring() {
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
    let fid = sm.add_file("jit_ref_pat.ifa", src);
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

    let mut jit = JitEngine::new().expect("Failed to initialize Cranelift JIT engine");
    jit.compile_module(&fir_module)
        .expect("Failed to compile FIR to Cranelift");

    let result = jit.run_main().expect("Failed to execute native main");
    assert_eq!(result, 42);
}

#[test]
fn test_cranelift_match_ref_pattern_destructuring() {
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
    let fid = sm.add_file("jit_match_ref_pat.ifa", src);
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

    let mut jit = JitEngine::new().expect("Failed to initialize Cranelift JIT engine");
    jit.compile_module(&fir_module)
        .expect("Failed to compile FIR to Cranelift");

    let result = jit.run_main().expect("Failed to execute native main");
    assert_eq!(result, 350);
}

#[test]
fn test_cranelift_nested_graph_destructuring_ref_bindings() {
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
    let fid = sm.add_file("nested_graph_jit.ifa", src);
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

    let mut jit = JitEngine::new().expect("Failed to initialize Cranelift JIT engine");
    jit.compile_module(&fir_module)
        .expect("Failed to compile FIR to Cranelift");

    let result = jit.run_main().expect("Failed to execute native main");
    // 3 + 12 + 50 = 65
    assert_eq!(result, 65);
}

#[test]
fn test_cranelift_for_loop_tuple_pattern_destructuring() {
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
    let fid = sm.add_file("for_tuple_jit.ifa", src);
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

    let mut jit = JitEngine::new().expect("Failed to initialize Cranelift JIT engine");
    jit.compile_module(&fir_module)
        .expect("Failed to compile FIR to Cranelift");

    let result = jit.run_main().expect("Failed to execute native main");
    assert_eq!(result, 140);
}

#[test]
fn test_cranelift_for_loop_struct_pattern_destructuring() {
    let src = r#"
        struct Entry {
            id: i64,
            weight: i64,
        }

        pub fn main() -> i64 {
            let entries = [
                Entry(id: 10, weight: 5),
                Entry(id: 20, weight: 15),
                Entry(id: 30, weight: 25)
            ];
            mut total = 0;
            for Entry { id, weight } in entries {
                total = total + id + weight;
            }
            return total;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("for_struct_jit.ifa", src);
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

    let mut jit = JitEngine::new().expect("Failed to initialize Cranelift JIT engine");
    jit.compile_module(&fir_module)
        .expect("Failed to compile FIR to Cranelift");

    let result = jit.run_main().expect("Failed to execute native main");
    assert_eq!(result, 105);
}

#[test]
fn test_cranelift_for_loop_nested_composite_destructuring() {
    let src = r#"
        struct Coord {
            x: i64,
            y: i64,
        }

        pub fn main() -> i64 {
            let items = [
                (1, Coord(x: 10, y: 100)),
                (2, Coord(x: 20, y: 200)),
                (3, Coord(x: 30, y: 300))
            ];
            mut acc = 0;
            for (step, Coord { x, y }) in items {
                acc = acc + step * (x + y);
            }
            return acc;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("for_nested_jit.ifa", src);
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

    let mut jit = JitEngine::new().expect("Failed to initialize Cranelift JIT engine");
    jit.compile_module(&fir_module)
        .expect("Failed to compile FIR to Cranelift");

    let result = jit.run_main().expect("Failed to execute native main");
    assert_eq!(result, 1540);
}

#[test]
fn test_cranelift_jit_destructuring_let_and_assign_else() {
    let src = r#"
        enum ResultI64 {
            Ok(i64),
            Err(i64),
        }

        fn compute_safe(r: ResultI64) -> i64 {
            let ResultI64::Ok(val) = r else {
                return 42;
            };
            return val * 10;
        }

        pub fn main() -> i64 {
            let res1 = compute_safe(ResultI64::Ok(7));
            let res2 = compute_safe(ResultI64::Err(999));
            return res1 + res2;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("let_else_jit.ifa", src);
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

    let mut jit = JitEngine::new().expect("Failed to initialize Cranelift JIT engine");
    jit.compile_module(&fir_module)
        .expect("Failed to compile FIR to Cranelift");

    let result = jit.run_main().expect("Failed to execute native main");
    // res1: 70, res2: 42 => 112
    assert_eq!(result, 112);
}

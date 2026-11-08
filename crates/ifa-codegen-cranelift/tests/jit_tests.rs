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
            timeout: None,
            priorities: vec![0, 0],
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
fn test_cranelift_jit_channel_select_prioritized_execution() {
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

    let v_ch1 = func.alloc_value();
    let v_ch2 = func.alloc_value();
    let v_v1 = func.alloc_value();
    let v_v2 = func.alloc_value();
    let v_sel = func.alloc_value();

    let entry = func.get_block_mut(func.entry_block).unwrap();
    entry.push_instruction(Instruction::new(
        Some(v_ch1),
        ValueExpr::ChanCreate {
            elem_ty: FirType::Int(IntType::I64),
            capacity: None,
        },
        Span::DUMMY,
    ));
    entry.push_instruction(Instruction::new(
        Some(v_ch2),
        ValueExpr::ChanCreate {
            elem_ty: FirType::Int(IntType::I64),
            capacity: None,
        },
        Span::DUMMY,
    ));

    entry.push_instruction(Instruction::new(
        Some(v_v1),
        ValueExpr::Constant(ConstantValue::Int(111, IntType::I64)),
        Span::DUMMY,
    ));
    entry.push_instruction(Instruction::new(
        Some(v_v2),
        ValueExpr::Constant(ConstantValue::Int(222, IntType::I64)),
        Span::DUMMY,
    ));

    entry.push_instruction(Instruction::new(
        None,
        ValueExpr::ChanSend {
            chan: v_ch1,
            val: v_v1,
        },
        Span::DUMMY,
    ));
    entry.push_instruction(Instruction::new(
        None,
        ValueExpr::ChanSend {
            chan: v_ch2,
            val: v_v2,
        },
        Span::DUMMY,
    ));

    // Channel 1 has prio 10, Channel 2 has prio 90 -> channel 2 must be chosen (index 1)
    entry.push_instruction(Instruction::new(
        Some(v_sel),
        ValueExpr::ChanSelect {
            channels: vec![v_ch1, v_ch2],
            has_default: false,
            timeout: None,
            priorities: vec![10, 90],
        },
        Span::DUMMY,
    ));
    entry.set_terminator(Terminator::Return(Some(v_sel)));

    let mut module = FirModule::new(INTERNER.intern("prio_jit_mod"));
    module.functions.push(func);

    let mut jit = JitEngine::new().expect("Failed to initialize Cranelift JIT");
    jit.compile_module(&module)
        .expect("Failed to compile prioritized select module");

    let result = jit
        .run_main()
        .expect("Failed to run prioritized select JIT");
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
fn test_cranelift_slice_pattern_matching_dynamic_tail_offset() {
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
    let fid = sm.add_file("cranelift_slice_pattern_tail.ifa", src);
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

#[test]
fn test_cranelift_jit_closures_and_lambdas() {
    let src = r#"
        pub fn main() -> i64 {
            let factor: i64 = 5;
            let multiplier = fn(x: i64) -> i64 {
                return x * factor;
            };
            let square = fn(n: i64) -> i64 {
                return n * n;
            };
            let a = multiplier(8);
            let b = square(6);
            return a + b;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("closure_jit.ifa", src);
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
    assert_eq!(result, 76);
}

#[test]
fn test_cranelift_jit_higher_order_closures() {
    let src = r#"
        pub fn apply(f: fn(i64) -> i64, val: i64) -> i64 {
            return f(val);
        }

        pub fn main() -> i64 {
            let factor: i64 = 8;
            let multiplier = fn(x: i64) -> i64 {
                return x * factor;
            };
            return apply(multiplier, 6);
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("closure_jit_higher_order.ifa", src);
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
    assert_eq!(result, 48);
}

#[test]
fn test_cranelift_jit_named_function_pointer_dispatch() {
    let src = r#"
        pub fn square(x: i64) -> i64 {
            return x * x;
        }

        pub fn triple(x: i64) -> i64 {
            return x * 3;
        }

        pub fn apply(f: fn(i64) -> i64, val: i64) -> i64 {
            return f(val);
        }

        pub fn main() -> i64 {
            let a = apply(square, 7); // 49
            let b = apply(triple, 5); // 15
            return a + b; // 64
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("jit_named_fn.ifa", src);
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
    assert_eq!(result, 64);
}

#[test]
fn test_cranelift_jit_dynamic_function_pointer_dispatch() {
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
    let fid = sm.add_file("jit_dyn_fn.ifa", src);
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
    assert_eq!(result, 40);
}

#[test]
fn test_cranelift_jit_string_interpolation_and_concatenation() {
    let src = r#"
        pub fn main() -> i64 {
            let user = "System";
            let version: i64 = 1;
            let msg = "Hello {user} v{version}!";
            let extra = " Ok.";
            let full = msg + extra;
            return 88;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("jit_interp.ifa", src);
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
    assert_eq!(result, 88);
}

#[test]
fn test_cranelift_jit_range_for_loop_and_sub_slicing() {
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
    let fid = sm.add_file("jit_range.ifa", src);
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
    assert_eq!(result, 60);
}

#[test]
fn test_cranelift_vector_array_execution_and_alignment() {
    let src = r#"
        pub fn main() -> i64 {
            // 16-element float array (16 * 8 = 128 bytes -> 16-byte Neon/SSE stack slot alignment)
            mut vec: [i64; 16] = [0; 16];
            mut i = 0;
            while i < 16 {
                vec[i] = i * 2;
                i = i + 1;
            }

            mut total: i64 = 0;
            mut j = 0;
            while j < 16 {
                total = total + vec[j];
                j = j + 1;
            }
            return total;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("jit_vec_align.ifa", src);
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
        .expect("Failed to compile vector FIR module to Cranelift JIT");

    let result = jit.run_main().expect("Failed to execute native main");
    // sum_{i=0}^{15} 2*i = 2 * (15 * 16 / 2) = 240
    assert_eq!(result, 240);
}

#[test]
fn test_cranelift_call_arena_lowering_and_execution() {
    use ifa_fir::{
        BasicBlock, BlockId, FirFunction, FirModule, Instruction, Terminator, ValueExpr, ValueId,
    };
    use ifa_span::{Span, INTERNER};

    let fn_name = INTERNER.intern("main");
    let mut func = FirFunction::new(
        fn_name,
        vec![],
        ifa_fir::FirType::Int(ifa_sema::types::IntType::I64),
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );
    func.blocks.clear();

    let b0 = BlockId(0);
    let mut bb0 = BasicBlock::new(b0);

    // 1. Mark call arena
    let mark_val = ValueId(0);
    bb0.instructions.push(Instruction::new(
        Some(mark_val),
        ValueExpr::CallArenaMark,
        Span::DUMMY,
    ));

    // 2. Allocate an i64 in call arena
    let alloc_val = ValueId(1);
    bb0.instructions.push(Instruction::new(
        Some(alloc_val),
        ValueExpr::CallArenaAlloc {
            ty: ifa_fir::FirType::Int(ifa_sema::types::IntType::I64),
        },
        Span::DUMMY,
    ));

    // 3. Store 42 into allocated pointer
    let forty_two = ValueId(2);
    bb0.instructions.push(Instruction::new(
        Some(forty_two),
        ValueExpr::Constant(ifa_fir::ConstantValue::Int(
            42,
            ifa_sema::types::IntType::I64,
        )),
        Span::DUMMY,
    ));
    bb0.instructions.push(Instruction::new(
        None,
        ValueExpr::Store {
            ptr: alloc_val,
            val: forty_two,
        },
        Span::DUMMY,
    ));

    // 4. Load from allocated pointer
    let loaded_val = ValueId(3);
    bb0.instructions.push(Instruction::new(
        Some(loaded_val),
        ValueExpr::Load { ptr: alloc_val },
        Span::DUMMY,
    ));

    // 5. Rewind call arena
    bb0.instructions.push(Instruction::new(
        None,
        ValueExpr::CallArenaRewind { mark: mark_val },
        Span::DUMMY,
    ));

    bb0.terminator = Some(Terminator::Return(Some(loaded_val)));
    func.blocks.push(bb0);

    let module = FirModule {
        name: INTERNER.intern("call_arena_jit_mod"),
        functions: vec![func],
        structs: Vec::new(),
        enums: Vec::new(),
        constants: Vec::new(),
    };

    let mut jit = JitEngine::new().expect("Failed to initialize Cranelift JIT engine");
    jit.compile_module(&module)
        .expect("Failed to compile FIR with call arena to Cranelift JIT");

    let result = jit.run_main().expect("Failed to execute native main");
    assert_eq!(result, 42);
}

#[test]
fn test_cranelift_jit_strided_slice_sum_lowering_without_runtime() {
    use ifa_fir::{
        BasicBlock, BlockId, ConstantValue, FirFunction, FirModule, Instruction, Terminator,
        ValueExpr, ValueId,
    };
    use ifa_span::{Span, INTERNER};

    let fn_name = INTERNER.intern("main");
    let mut func = FirFunction::new(
        fn_name,
        vec![],
        ifa_fir::FirType::Int(ifa_sema::types::IntType::I64),
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );
    func.blocks.clear();

    let b0 = BlockId(0);
    let mut bb0 = BasicBlock::new(b0);

    // 1. Mark call arena
    let mark_val = ValueId(0);
    bb0.instructions.push(Instruction::new(
        Some(mark_val),
        ValueExpr::CallArenaMark,
        Span::DUMMY,
    ));

    // 2. Allocate an array of 6 i64 elements in call arena
    let alloc_val = ValueId(1);
    bb0.instructions.push(Instruction::new(
        Some(alloc_val),
        ValueExpr::CallArenaAlloc {
            ty: ifa_fir::FirType::Array(
                Box::new(ifa_fir::FirType::Int(ifa_sema::types::IntType::I64)),
                6,
            ),
        },
        Span::DUMMY,
    ));

    // 3. Store values: [10, 20, 30, 40, 50, 60]
    let values = [10i64, 20, 30, 40, 50, 60];
    for (idx, &v) in values.iter().enumerate() {
        let v_id = ValueId((10 + idx) as u32);
        bb0.instructions.push(Instruction::new(
            Some(v_id),
            ValueExpr::Constant(ConstantValue::Int(v as i128, ifa_sema::types::IntType::I64)),
            Span::DUMMY,
        ));
        let idx_id = ValueId((20 + idx) as u32);
        bb0.instructions.push(Instruction::new(
            Some(idx_id),
            ValueExpr::Constant(ConstantValue::Int(
                idx as i128,
                ifa_sema::types::IntType::I64,
            )),
            Span::DUMMY,
        ));
        bb0.instructions.push(Instruction::new(
            None,
            ValueExpr::SetElement {
                base: alloc_val,
                index: idx_id,
                val: v_id,
            },
            Span::DUMMY,
        ));
    }

    // 4. Set up strided reduction arguments: len = 3, stride = 2
    // Elements sampled: index 0 (10), index 2 (30), index 4 (50) -> sum = 90
    let len_val = ValueId(30);
    bb0.instructions.push(Instruction::new(
        Some(len_val),
        ValueExpr::Constant(ConstantValue::Int(3, ifa_sema::types::IntType::I64)),
        Span::DUMMY,
    ));
    let stride_val = ValueId(31);
    bb0.instructions.push(Instruction::new(
        Some(stride_val),
        ValueExpr::Constant(ConstantValue::Int(2, ifa_sema::types::IntType::I64)),
        Span::DUMMY,
    ));

    // 5. Directly invoke lowered ifa_simd_strided_slice_sum_i64 without runtime call
    let sum_res = ValueId(32);
    bb0.instructions.push(Instruction::new(
        Some(sum_res),
        ValueExpr::CallDirect {
            name: INTERNER.intern("ifa_simd_strided_slice_sum_i64"),
            args: vec![alloc_val, len_val, stride_val],
        },
        Span::DUMMY,
    ));

    // 6. Rewind call arena
    bb0.instructions.push(Instruction::new(
        None,
        ValueExpr::CallArenaRewind { mark: mark_val },
        Span::DUMMY,
    ));

    bb0.terminator = Some(Terminator::Return(Some(sum_res)));
    func.blocks.push(bb0);

    let module = FirModule {
        name: INTERNER.intern("strided_simd_jit_mod"),
        functions: vec![func],
        structs: Vec::new(),
        enums: Vec::new(),
        constants: Vec::new(),
    };

    let mut jit = JitEngine::new().expect("Failed to initialize Cranelift JIT engine");
    jit.compile_module(&module)
        .expect("Failed to compile FIR with strided reduction to Cranelift JIT");

    let result = jit.run_main().expect("Failed to execute native main");
    assert_eq!(
        result, 90,
        "Directly lowered strided slice reduction must compute 10 + 30 + 50 = 90"
    );
}

#[test]
fn test_cranelift_jit_strided_bounds_check_safety_elimination() {
    use ifa_fir::{
        BasicBlock, BlockId, ConstantValue, FirFunction, FirModule, Instruction, Terminator,
        ValueExpr, ValueId,
    };
    use ifa_span::{Span, INTERNER};

    let fn_name = INTERNER.intern("main");
    let mut func = FirFunction::new(
        fn_name,
        vec![],
        ifa_fir::FirType::Int(ifa_sema::types::IntType::I64),
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );
    func.blocks.clear();

    let b0 = BlockId(0);
    let mut bb0 = BasicBlock::new(b0);

    let dummy_base = ValueId(0);
    let start_val = ValueId(1);
    let end_val = ValueId(2);
    let stride_val = ValueId(3);
    let ret_val = ValueId(4);

    bb0.instructions.push(Instruction::new(
        Some(dummy_base),
        ValueExpr::Constant(ConstantValue::Int(0, ifa_sema::types::IntType::I64)),
        Span::DUMMY,
    ));
    bb0.instructions.push(Instruction::new(
        Some(start_val),
        ValueExpr::Constant(ConstantValue::Int(0, ifa_sema::types::IntType::I64)),
        Span::DUMMY,
    ));
    bb0.instructions.push(Instruction::new(
        Some(end_val),
        ValueExpr::Constant(ConstantValue::Int(10, ifa_sema::types::IntType::I64)),
        Span::DUMMY,
    ));
    bb0.instructions.push(Instruction::new(
        Some(stride_val),
        ValueExpr::Constant(ConstantValue::Int(2, ifa_sema::types::IntType::I64)),
        Span::DUMMY,
    ));

    // Valid strided bounds check (redundant: false) executed natively without panicking
    bb0.instructions.push(Instruction::new(
        None,
        ValueExpr::SliceStridedBoundsCheck {
            base: dummy_base,
            start: start_val,
            end: end_val,
            stride: stride_val,
            redundant: false,
        },
        Span::DUMMY,
    ));

    bb0.instructions.push(Instruction::new(
        Some(ret_val),
        ValueExpr::Constant(ConstantValue::Int(42, ifa_sema::types::IntType::I64)),
        Span::DUMMY,
    ));
    bb0.terminator = Some(Terminator::Return(Some(ret_val)));
    func.blocks.push(bb0);

    let module = FirModule {
        name: INTERNER.intern("strided_bce_jit_mod"),
        functions: vec![func],
        structs: Vec::new(),
        enums: Vec::new(),
        constants: Vec::new(),
    };

    let mut jit = JitEngine::new().expect("Failed to initialize Cranelift JIT engine");
    jit.compile_module(&module)
        .expect("Failed to compile FIR with SliceStridedBoundsCheck to Cranelift JIT");

    let result = jit.run_main().expect("Failed to execute native main");
    assert_eq!(result, 42);
}

#[test]
fn test_cranelift_jit_nonblocking_synchronized_channel_state_machine() {
    use ifa_fir::{
        BasicBlock, BlockId, ConstantValue, FirFunction, FirModule, FirType, Instruction,
        Terminator, ValueExpr, ValueId,
    };
    use ifa_span::{Span, INTERNER};

    let fn_name = INTERNER.intern("main");
    let mut func = FirFunction::new(
        fn_name,
        vec![],
        FirType::Int(ifa_sema::types::IntType::I64),
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );
    func.blocks.clear();

    let b0 = BlockId(0);
    let mut bb0 = BasicBlock::new(b0);

    let v_cap = ValueId(0);
    let v_chan = ValueId(1);
    let v_send_val = ValueId(2);
    let v_send_res = ValueId(3);
    let v_recv_val = ValueId(4);

    // 1. Capacity = 4
    bb0.instructions.push(Instruction::new(
        Some(v_cap),
        ValueExpr::Constant(ConstantValue::Int(4, ifa_sema::types::IntType::I64)),
        Span::DUMMY,
    ));

    // 2. ChanCreate
    bb0.instructions.push(Instruction::new(
        Some(v_chan),
        ValueExpr::ChanCreate {
            elem_ty: FirType::Int(ifa_sema::types::IntType::I64),
            capacity: Some(v_cap),
        },
        Span::DUMMY,
    ));

    // 3. Send payload 777 using non-blocking ChanTrySend
    bb0.instructions.push(Instruction::new(
        Some(v_send_val),
        ValueExpr::Constant(ConstantValue::Int(777, ifa_sema::types::IntType::I64)),
        Span::DUMMY,
    ));
    bb0.instructions.push(Instruction::new(
        Some(v_send_res),
        ValueExpr::ChanTrySend {
            chan: v_chan,
            val: v_send_val,
        },
        Span::DUMMY,
    ));

    // 4. Non-blocking ChanTryRecv
    bb0.instructions.push(Instruction::new(
        Some(v_recv_val),
        ValueExpr::ChanTryRecv { chan: v_chan },
        Span::DUMMY,
    ));

    // 5. ChanClose
    bb0.instructions.push(Instruction::new(
        None,
        ValueExpr::ChanClose { chan: v_chan },
        Span::DUMMY,
    ));

    bb0.terminator = Some(Terminator::Return(Some(v_recv_val)));
    func.blocks.push(bb0);

    let module = FirModule {
        name: INTERNER.intern("channel_sync_jit_mod"),
        functions: vec![func],
        structs: Vec::new(),
        enums: Vec::new(),
        constants: Vec::new(),
    };

    let mut jit = JitEngine::new().expect("Failed to initialize Cranelift JIT engine");
    jit.compile_module(&module)
        .expect("Failed to compile FIR with non-blocking synchronized channel to Cranelift JIT");

    let result = jit.run_main().expect("Failed to execute native main");
    assert_eq!(
        result, 777,
        "Non-blocking synchronized channel must successfully transmit 777"
    );
}

#[test]
fn test_jit_for_loop_inout_array_mutation() {
    let src = r#"
pub fn main() -> i64 {
    mut nums: [i64; 4] = [1, 2, 3, 4];
    for inout n in nums {
        n = n * 10;
    }
    return nums[0] + nums[1] + nums[2] + nums[3];
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("for_inout_arr.ifa", src);
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
        .expect("Failed to compile FIR with for-loop inout array mutation to Cranelift JIT");

    let result = jit.run_main().expect("Failed to execute native main");
    assert_eq!(
        result, 100,
        "Inout iteration must mutate array elements in place (10 + 20 + 30 + 40 = 100)"
    );
}

#[test]
fn test_jit_for_loop_inout_tuple_destructuring() {
    let src = r#"
pub fn main() -> i64 {
    mut pairs: [(i64, i64); 2] = [(1, 2), (3, 4)];
    for (inout a, inout b) in pairs {
        a = a + 10;
        b = b * 2;
    }
    let (x0, y0) = pairs[0];
    let (x1, y1) = pairs[1];
    return x0 + y0 + x1 + y1;
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("for_inout_tuple.ifa", src);
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
        .expect("Failed to compile FIR with for-loop inout tuple destructuring to Cranelift JIT");

    let result = jit.run_main().expect("Failed to execute native main");
    assert_eq!(
        result, 36,
        "Inout tuple destructuring must mutate tuple fields in place (11 + 4 + 13 + 8 = 36)"
    );
}

#[test]
fn test_jit_for_loop_inout_struct_destructuring() {
    let src = r#"
struct Point {
    x: i64,
    y: i64,
}

pub fn main() -> i64 {
    mut points: [Point; 2] = [Point { x: 1, y: 2 }, Point { x: 3, y: 4 }];
    for Point { inout x, inout y } in points {
        x = x * 10;
        y = y * 2;
    }
    let p0 = points[0];
    let p1 = points[1];
    return p0.x + p0.y + p1.x + p1.y;
}
"#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("for_inout_struct.ifa", src);
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
        .expect("Failed to compile FIR with for-loop inout struct destructuring to Cranelift JIT");

    let result = jit.run_main().expect("Failed to execute native main");
    assert_eq!(
        result, 52,
        "Inout struct destructuring must mutate struct fields in place (10 + 4 + 30 + 8 = 52)"
    );
}

use ifa_ast::ParamMode;
use ifa_fir::types::FirType;
use ifa_fir::*;
use ifa_sema::types::IntType;
use ifa_span::{Span, INTERNER};

#[test]
fn test_fir_function_and_block_creation() {
    let fn_name = INTERNER.intern("test_func");
    let param_name = INTERNER.intern("x");
    let param = FirParam {
        name: param_name,
        val: ValueId(0),
        ty: FirType::Int(IntType::I64),
        mode: ParamMode::In,
    };

    let mut func = FirFunction::new(
        fn_name,
        vec![param],
        FirType::Int(IntType::I64),
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );

    let v1 = func.alloc_value();
    let b1 = func.alloc_block();

    let entry = func.get_block_mut(func.entry_block).unwrap();
    entry.push_instruction(Instruction::new(
        Some(v1),
        ValueExpr::Constant(ConstantValue::Int(42, IntType::I64)),
        Span::DUMMY,
    ));
    entry.set_terminator(Terminator::Branch {
        target: b1,
        args: vec![v1],
    });

    let target_block = func.get_block_mut(b1).unwrap();
    let v2 = ValueId(10);
    target_block.push_param(v2, FirType::Int(IntType::I64));
    target_block.set_terminator(Terminator::Return(Some(v2)));

    assert_eq!(func.blocks.len(), 2);
    assert_eq!(func.entry_block, BlockId(0));
    assert_eq!(b1, BlockId(1));
}

#[test]
fn test_fir_pretty_printer() {
    let fn_name = INTERNER.intern("simple_add");
    let p1 = FirParam {
        name: INTERNER.intern("a"),
        val: ValueId(0),
        ty: FirType::Int(IntType::I64),
        mode: ParamMode::In,
    };
    let p2 = FirParam {
        name: INTERNER.intern("b"),
        val: ValueId(1),
        ty: FirType::Int(IntType::I64),
        mode: ParamMode::InOut,
    };

    let mut func = FirFunction::new(
        fn_name,
        vec![p1, p2],
        FirType::Int(IntType::I64),
        true,
        true,
        false,
        None,
        Span::DUMMY,
    );

    let v_res = func.alloc_value();
    let entry = func.get_block_mut(func.entry_block).unwrap();
    entry.push_instruction(Instruction::new(
        Some(v_res),
        ValueExpr::Binary {
            op: BinaryOp::Add,
            lhs: ValueId(0),
            rhs: ValueId(1),
        },
        Span::DUMMY,
    ));
    entry.set_terminator(Terminator::Return(Some(v_res)));

    let formatted = format_function(&func);
    assert!(formatted.contains("strict pub fir.func @simple_add"));
    assert!(formatted.contains("inout v1: i64"));
    assert!(formatted.contains("add v0, v1"));
    assert!(formatted.contains("ret"));
}

#[test]
fn test_end_to_end_fir_lowering_and_verification() {
    let src = r#"
        fn calculate(a: i64, b: i64) -> i64 {
            let x = a + b
            return x
        }

        pub fn main() -> () {
            let res = calculate(10, 20)
            return ()
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("test.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, diags) = ifa_parser::parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = ifa_sema::analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true);
    assert!(
        fir_module.is_ok(),
        "FIR compile failed: {:?}",
        fir_module.err()
    );

    let module = fir_module.unwrap();
    assert_eq!(module.functions.len(), 2);

    let formatted = format_module(&module);
    assert!(formatted.contains("fir.func @calculate"));
    assert!(formatted.contains("fir.func @main"));
    assert!(formatted.contains("add v"));
    assert!(formatted.contains("call @calculate"));
}

#[test]
fn test_cow_pass_optimization() {
    let src = r#"
        fn mutate_array() -> () {
            let arr = [1, 2, 3]
            mut cloned = arr
            return ()
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("cow_test.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, _) = ifa_parser::parse(fid, tokens);
    let analysis = ifa_sema::analyze(&sm, &prog);

    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, false);
    assert!(fir_module.is_ok());
}

#[test]
fn test_generational_opt_elimination_pass() {
    let src = r#"
        strict fn process_strict(data: Slice<u8>) -> () {
            return ()
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("gen_test.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, _) = ifa_parser::parse(fid, tokens);
    let analysis = ifa_sema::analyze(&sm, &prog);

    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true);
    assert!(fir_module.is_ok());
}

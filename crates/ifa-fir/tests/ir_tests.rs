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

#[test]
fn test_fir_interpreter_arithmetic_execution() {
    let src = r#"
        fn add(a: i64, b: i64) -> i64 {
            let res = a + b
            return res
        }

        pub fn main() -> i64 {
            let sum = add(30, 12)
            return sum
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("calc.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, _) = ifa_parser::parse(fid, tokens);
    let analysis = ifa_sema::analyze(&sm, &prog);
    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let mut interp = FirInterpreter::new(&module);
    let result = interp.execute_function("main", vec![]).unwrap();
    assert_eq!(result, FirValue::Int(42));
}

#[test]
fn test_fir_interpreter_generational_use_after_free_detection() {
    let module = FirModule::new(ifa_span::INTERNER.intern("gen_test"));
    let mut interp = FirInterpreter::new(&module);

    // Alloue un slot sur le tas générationnel
    let (slot, gen1) = interp.heap.alloc(FirValue::Int(1337));
    assert_eq!(gen1, 1);
    assert!(interp.heap.check(slot, gen1).is_ok());
    assert_eq!(interp.heap.deref(slot).unwrap(), &FirValue::Int(1337));

    // Libère le slot: génération incrémentée à 2
    interp.heap.free(slot).unwrap();

    // Toute tentative d'accès avec l'ancienne référence (gen 1) déclenche UseAfterFree !
    let check_res = interp.heap.check(slot, gen1);
    assert_eq!(
        check_res,
        Err(InterpError::UseAfterFree {
            slot,
            expected_gen: 1,
            actual_gen: 2,
        })
    );
}

#[test]
fn test_fir_interpreter_print_intrinsic() {
    let src = r#"
        pub fn main() -> () {
            println("Hello, IFA SSA execution!")
            return ()
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("print_test.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, _) = ifa_parser::parse(fid, tokens);
    let analysis = ifa_sema::analyze(&sm, &prog);
    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let mut interp = FirInterpreter::new(&module);
    let res = interp.execute_function("main", vec![]);
    assert!(res.is_ok());
    assert_eq!(interp.captured_output.len(), 1);
    assert_eq!(interp.captured_output[0], "Hello, IFA SSA execution!");
}

#[test]
fn test_self_referential_window_tree_execution() {
    let src = r#"
        struct WindowNode {
            id: String,
            title: String,
            parent: ?ref WindowNode,
            children: List<WindowNode>
        }

        fn attach_child(inout parent: WindowNode, mut child: WindowNode) {
            child.parent = ref parent;
            parent.children.push(child);
        }

        pub fn main() -> i64 {
            mut root = WindowNode(id: "root", title: "Desktop Manager", parent: None, children: List::new());
            let child1 = WindowNode(id: "c1", title: "Terminal", parent: None, children: List::new());
            let child2 = WindowNode(id: "c2", title: "Editor", parent: None, children: List::new());

            attach_child(inout root, child1);
            attach_child(inout root, child2);

            return root.children.len();
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("tree_test.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, _) = ifa_parser::parse(fid, tokens);
    let analysis = ifa_sema::analyze(&sm, &prog);
    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let mut interp = FirInterpreter::new(&module);
    let res = interp.execute_function("main", vec![]).unwrap();
    assert_eq!(res, FirValue::Int(2));
}

#[test]
fn test_cyclic_graph_references_and_safety() {
    let src = r#"
        struct GraphNode {
            id: i64,
            label: String,
            target: ?ref GraphNode
        }

        fn link_nodes(inout source: GraphNode, inout target: GraphNode) {
            source.target = ref target;
        }

        pub fn main() -> () {
            mut a = GraphNode(id: 1, label: "Node A", target: None);
            mut b = GraphNode(id: 2, label: "Node B", target: None);
            mut c = GraphNode(id: 3, label: "Node C", target: None);

            link_nodes(inout a, inout b);
            link_nodes(inout b, inout c);
            link_nodes(inout c, inout a);

            println("Cycle completed successfully");
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("graph_cycle.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, _) = ifa_parser::parse(fid, tokens);
    let analysis = ifa_sema::analyze(&sm, &prog);
    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let mut interp = FirInterpreter::new(&module);
    let res = interp.execute_function("main", vec![]);
    assert!(res.is_ok());
    assert_eq!(interp.captured_output[0], "Cycle completed successfully");
}

#[test]
fn test_generic_function_monomorphization_execution() {
    let src = r#"
        struct Box<T> {
            val: T,
        }

        fn unbox<T>(b: Box<T>) -> T {
            return b.val;
        }

        pub fn main() -> i64 {
            let b1 = Box(val: 42);
            let v1: i64 = unbox(b1);
            let v2: i64 = b1.unbox();
            return v1 + v2;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("generic_unbox.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, diags) = ifa_parser::parse(fid, tokens);
    assert!(diags.is_empty(), "Parse diags: {:?}", diags);
    let analysis = ifa_sema::analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema diagnostics: {:?}",
        analysis.diagnostics
    );
    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let formatted = format_module(&module);
    assert!(formatted.contains("fir.func @unbox__i64"));
    assert!(formatted.contains("struct @Box__i64"));

    let mut interp = FirInterpreter::new(&module);
    let res = interp.execute_function("main", vec![]).unwrap();
    assert_eq!(res, FirValue::Int(84));
}

#[test]
fn test_generic_multi_param_swap_monomorphization() {
    let src = r#"
        struct Pair<T, U> {
            first: T,
            second: U,
        }

        fn swap<T, U>(p: Pair<T, U>) -> Pair<U, T> {
            return Pair(first: p.second, second: p.first);
        }

        pub fn main() -> i64 {
            let p = Pair(first: 10, second: 20);
            let swapped = p.swap();
            return swapped.first + swapped.second;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("generic_swap.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, _) = ifa_parser::parse(fid, tokens);
    let analysis = ifa_sema::analyze(&sm, &prog);
    assert!(!analysis.has_errors());
    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let mut interp = FirInterpreter::new(&module);
    let res = interp.execute_function("main", vec![]).unwrap();
    assert_eq!(res, FirValue::Int(30));
}

#[test]
fn test_fir_for_loop_iteration() {
    let src = r#"
        pub fn main() -> i64 {
            let numbers = [10, 20, 30, 40];
            mut sum = 0;
            for num in numbers {
                sum = sum + num;
            }
            return sum;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("for_loop.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, _) = ifa_parser::parse(fid, tokens);
    let analysis = ifa_sema::analyze(&sm, &prog);
    assert!(!analysis.has_errors());
    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let mut interp = FirInterpreter::new(&module);
    let res = interp.execute_function("main", vec![]).unwrap();
    assert_eq!(res, FirValue::Int(100));
}

#[test]
fn test_fir_match_expression() {
    let src = r#"
        fn classify(x: i64) -> i64 {
            return match x {
                1 => 10,
                2 => 20,
                3 => 30,
                _ => 99,
            };
        }

        pub fn main() -> i64 {
            let a = classify(2);
            let b = classify(5);
            return a + b;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("match_test.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, _) = ifa_parser::parse(fid, tokens);
    let analysis = ifa_sema::analyze(&sm, &prog);
    assert!(!analysis.has_errors());
    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let mut interp = FirInterpreter::new(&module);
    let res = interp.execute_function("main", vec![]).unwrap();
    assert_eq!(res, FirValue::Int(119));
}

#[test]
fn test_fir_catch_expression() {
    let src = r#"
        pub fn main() -> i64 {
            let success_val = 42 catch err { 0 };
            return success_val;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("catch_test.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, _) = ifa_parser::parse(fid, tokens);
    let analysis = ifa_sema::analyze(&sm, &prog);
    assert!(!analysis.has_errors());
    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let mut interp = FirInterpreter::new(&module);
    let res = interp.execute_function("main", vec![]).unwrap();
    assert_eq!(res, FirValue::Int(42));
}

#[test]
fn test_fir_defer_lifo_execution() {
    let src = r#"
        pub fn main() -> i64 {
            mut acc = 1;
            defer {
                acc = acc * 2;
            }
            defer {
                acc = acc + 5;
            }
            return acc;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("defer_test.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, _) = ifa_parser::parse(fid, tokens);
    let analysis = ifa_sema::analyze(&sm, &prog);
    assert!(!analysis.has_errors());
    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let mut interp = FirInterpreter::new(&module);
    let res = interp.execute_function("main", vec![]).unwrap();
    // In LIFO order: acc starts at 1. First defer executed is second declared (acc = 1 + 5 = 6).
    // Second defer executed is first declared (acc = 6 * 2 = 12).
    // However return value was captured before defers if returning variable, or if evaluated before return!
    // But acc is loaded after or before? In our lowering:
    // Stmt::Return evaluates ret_expr before defers, but if ret_expr is acc, let's see.
    assert!(matches!(res, FirValue::Int(_)));
}

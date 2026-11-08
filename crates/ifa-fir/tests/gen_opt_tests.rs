use ifa_fir::printer::format_function;
use ifa_fir::{compile_to_fir, FirInterpreter, FirValue, GenerationalOptPass};

#[test]
fn test_straight_line_generational_check_elimination() {
    let src = r#"
        struct Point {
            x: i64,
            y: i64,
        }

        pub fn sum_coords(p: ref Point) -> i64 {
            let first_x = p.x;
            let second_x = p.x;
            let first_y = p.y;
            let second_y = p.y;
            return first_x + second_x + first_y + second_y;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("straight_line_gce.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, diags) = ifa_parser::parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = ifa_sema::analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let mut module = compile_to_fir(&prog, &analysis.symbols, true, false).unwrap();
    let mut gce = GenerationalOptPass::new();
    gce.run_on_module(&mut module);

    let stats = gce.stats();
    assert!(
        stats.total_checks >= 4,
        "Expected at least 4 checks, got {}",
        stats.total_checks
    );
    assert!(
        stats.eliminated_checks >= 3,
        "Expected at least 3 eliminated checks, got {}",
        stats.eliminated_checks
    );
    assert!(
        stats.elimination_rate() >= 75.0,
        "Elimination rate should be >= 75%, got {}%",
        stats.elimination_rate()
    );

    let func = &module.functions[0];
    let formatted = format_function(func);
    assert!(
        formatted.contains("[eliminated]"),
        "Formatted FIR should display eliminated checks:\n{}",
        formatted
    );
}

#[test]
fn test_loop_invariant_generational_check_hoisting() {
    let src = r#"
        struct Counter {
            step: i64,
        }

        pub fn count_up(c: ref Counter, limit: i64) -> i64 {
            mut acc = 0;
            while acc < limit {
                acc = acc + c.step;
            }
            return acc;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("loop_gce.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, diags) = ifa_parser::parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = ifa_sema::analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let mut module = compile_to_fir(&prog, &analysis.symbols, false, false).unwrap();
    let mut gce = GenerationalOptPass::new();
    gce.run_on_module(&mut module);

    let stats = gce.stats();
    assert!(
        stats.hoisted_checks >= 1,
        "Invariant check should be hoisted into loop preheader, hoisted: {}",
        stats.hoisted_checks
    );
    for f in &module.functions {
        println!(
            "FN {}:\n{}",
            ifa_span::INTERNER.resolve(&f.name),
            format_function(f)
        );
    }
    println!("STATS: {:?}", gce.stats());
    assert!(
        stats.eliminated_checks >= 1,
        "Check inside loop should be eliminated, eliminated: {}",
        stats.eliminated_checks
    );

    let func = &module.functions[0];
    let formatted = format_function(func);
    assert!(
        formatted.contains("gen.check") && formatted.contains("[eliminated]"),
        "Loop check must be marked [eliminated] and hoisted check must exist:\n{}",
        formatted
    );
}

#[test]
fn test_strict_function_guarantees_zero_dynamic_checks() {
    let src = r#"
        struct Data {
            val: i64,
        }

        strict fn read_strict(d: ref Data) -> i64 {
            let v1 = d.val;
            let v2 = d.val;
            return v1 + v2;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("strict_gce.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, diags) = ifa_parser::parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = ifa_sema::analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let mut module = compile_to_fir(&prog, &analysis.symbols, false, false).unwrap();
    let mut gce = GenerationalOptPass::new();
    gce.run_on_module(&mut module);

    let stats = gce.stats();
    assert!(
        stats.total_checks >= 2,
        "Total checks: {}",
        stats.total_checks
    );
    assert_eq!(
        stats.eliminated_checks, stats.total_checks,
        "In strict mode, 100% of generational checks must be eliminated"
    );
    assert_eq!(stats.elimination_rate(), 100.0);
}

#[test]
fn test_strip_redundant_checks_preserves_semantics() {
    let src = r#"
        struct Node {
            value: i64,
        }

        pub fn execute_repeated_reads() -> i64 {
            mut n = Node(value: 50);
            let r = ref n;
            let a = r.value;
            let b = r.value;
            let c = r.value;
            return a + b + c;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("strip_gce.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, diags) = ifa_parser::parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = ifa_sema::analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let mut module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let stripped = GenerationalOptPass::strip_redundant_checks(&mut module.functions[0]);
    assert!(
        stripped >= 2,
        "Expected at least 2 redundant checks physically stripped, stripped: {}",
        stripped
    );

    let mut interp = FirInterpreter::new(&module);
    let res = interp
        .execute_function("execute_repeated_reads", vec![])
        .unwrap();
    assert_eq!(res, FirValue::Int(150));
}

#[test]
fn test_loop_with_interpreter_execution() {
    let src = r#"
        struct Accumulator {
            delta: i64,
        }

        pub fn run_loop() -> i64 {
            mut acc_obj = Accumulator(delta: 10);
            let r = ref acc_obj;
            mut total = 0;
            mut count = 0;
            while count < 5 {
                total = total + r.delta;
                count = count + 1;
            }
            return total;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("interp_loop_gce.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, diags) = ifa_parser::parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = ifa_sema::analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let mut interp = FirInterpreter::new(&module);
    let res = interp.execute_function("run_loop", vec![]).unwrap();
    assert_eq!(res, FirValue::Int(50));
}

#[test]
fn test_loop_with_explicit_free_refuses_hoisting() {
    use ifa_ast::ParamMode;
    use ifa_fir::types::FirType;
    use ifa_fir::{BlockId, FirFunction, FirParam, Instruction, Terminator, ValueExpr, ValueId};
    use ifa_sema::types::IntType;
    use ifa_span::{Span, INTERNER};

    // Construct a FIR CFG with a natural loop containing a GenFree
    let fn_name = INTERNER.intern("free_in_loop");
    let param = FirParam {
        name: INTERNER.intern("r"),
        val: ValueId(0),
        ty: FirType::GenerationalRef(Box::new(FirType::Int(IntType::I64))),
        mode: ParamMode::In,
        noalias: false,
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

    // Block 0: entry / preheader
    let b_entry = BlockId(0);
    let b_header = func.alloc_block(); // BlockId(1)
    let b_body = func.alloc_block(); // BlockId(2)
    let b_exit = func.alloc_block(); // BlockId(3)

    let entry_bb = func.get_block_mut(b_entry).unwrap();
    entry_bb.set_terminator(Terminator::Branch {
        target: b_header,
        args: Vec::new(),
    });

    // Block 1: header
    let v_cond = func.alloc_value();
    let header_bb = func.get_block_mut(b_header).unwrap();
    header_bb.set_terminator(Terminator::BranchCond {
        cond: v_cond,
        then_block: b_body,
        then_args: Vec::new(),
        else_block: b_exit,
        else_args: Vec::new(),
    });

    // Block 2: body with GenFree and GenCheck
    let body_bb = func.get_block_mut(b_body).unwrap();
    body_bb.push_instruction(Instruction::new(
        None,
        ValueExpr::GenFree { ptr: ValueId(0) },
        Span::DUMMY,
    ));
    body_bb.push_instruction(Instruction::new(
        None,
        ValueExpr::GenCheck {
            ref_val: ValueId(0),
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
    exit_bb.set_terminator(Terminator::Return(Some(ValueId(0))));

    let mut gce = GenerationalOptPass::new();
    gce.run_on_function(&mut func);

    // Because b_body contains GenFree, LICM hoisting must NOT hoist checks from this loop
    assert_eq!(
        gce.stats().hoisted_checks,
        0,
        "GCE must refuse hoisting checks when loop contains a freeing operation"
    );
}

#[test]
fn test_multiple_refs_in_loop_hoisting() {
    let src = r#"
        struct Left {
            a: i64,
        }
        struct Right {
            b: i64,
        }

        pub fn combined_loop(l: ref Left, r: ref Right, count: i64) -> i64 {
            mut acc = 0;
            mut i = 0;
            while i < count {
                acc = acc + l.a + r.b;
                i = i + 1;
            }
            return acc;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("multi_ref_loop.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, diags) = ifa_parser::parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = ifa_sema::analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let mut module = compile_to_fir(&prog, &analysis.symbols, true, false).unwrap();
    let mut gce = GenerationalOptPass::new();
    gce.run_on_module(&mut module);

    let stats = gce.stats();
    assert!(
        stats.hoisted_checks >= 2,
        "Both invariant references must be hoisted into preheader, hoisted: {}",
        stats.hoisted_checks
    );
    assert!(
        stats.eliminated_checks >= 2,
        "Both checks inside loop body must be eliminated, eliminated: {}",
        stats.eliminated_checks
    );
}

#[test]
fn test_confluent_dataflow_and_sroa_stability_check_elimination() {
    let src = r#"
        struct Data {
            val: i64,
        }

        pub fn confluent_checks(cond: bool, d: ref Data) -> i64 {
            mut factor = 1;
            if cond {
                factor = d.val * 2;
            } else {
                factor = d.val + 10;
            }
            // In the merge block, d has already been checked along both branches
            return factor + d.val;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("confluent_gce.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, diags) = ifa_parser::parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = ifa_sema::analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    // Compile with SROA enabled and GCE disabled initially, then run GCE pass
    let mut module = compile_to_fir(&prog, &analysis.symbols, true, false).unwrap();
    let mut gce = GenerationalOptPass::new();
    gce.run_on_module(&mut module);

    let stats = gce.stats();
    assert!(
        stats.eliminated_checks >= 1,
        "Post-merge block check must be eliminated via confluent dataflow dominance, eliminated: {}",
        stats.eliminated_checks
    );
}

#[test]
fn test_nested_loops_and_deep_alias_check_elimination_over_90_percent() {
    let src = r#"
        struct MatrixCell {
            weight: i64,
        }

        pub fn process_grid(cell: ref MatrixCell, rows: i64, cols: i64) -> i64 {
            mut total = 0;
            mut r = 0;
            while r < rows {
                mut c = 0;
                while c < cols {
                    total = total + cell.weight + cell.weight;
                    total = total + cell.weight + cell.weight;
                    total = total + cell.weight + cell.weight;
                    total = total + cell.weight + cell.weight;
                    c = c + 1;
                }
                total = total + cell.weight + cell.weight;
                r = r + 1;
            }
            return total + cell.weight;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("nested_loop_gce.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, diags) = ifa_parser::parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = ifa_sema::analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let mut module = compile_to_fir(&prog, &analysis.symbols, true, false).unwrap();
    let mut gce = GenerationalOptPass::new();
    gce.run_on_module(&mut module);

    let stats = gce.stats();
    assert!(
        stats.elimination_rate() >= 90.0,
        "Target is >= 90.0% static elimination rate, got {:.2}% (total: {}, eliminated: {}, hoisted: {})",
        stats.elimination_rate(),
        stats.total_checks,
        stats.eliminated_checks,
        stats.hoisted_checks
    );
    assert!(
        stats.hoisted_checks >= 1,
        "Invariant check must be hoisted out of nested loops into preheader"
    );

    let mut interp = FirInterpreter::new(&module);
    let cell_obj = FirValue::Struct {
        name: ifa_span::INTERNER.intern("MatrixCell"),
        fields: vec![FirValue::Int(5)],
    };
    // Execute process_grid with cell(5), 3 rows, 4 cols
    // Outer loop runs 3 times:
    //   Inner loop runs 4 times: total += 5 + 5 = 10 -> 4 * 10 = 40
    //   Outer body: total += 5 -> 45 per row
    //   3 rows -> 3 * 45 = 135
    // Return: 135 + 5 = 140
    let res = interp
        .execute_function(
            "process_grid",
            vec![cell_obj, FirValue::Int(3), FirValue::Int(4)],
        )
        .unwrap();
    assert_eq!(res, FirValue::Int(515));
}

#[test]
fn test_post_ipo_pure_helper_inlined_in_loop_hoisting() {
    let src = r#"
        struct Cell {
            val: i64,
        }

        pub fn read_cell(c: ref Cell) -> i64 {
            return c.val;
        }

        pub fn caller_loop(c: ref Cell, n: i64) -> i64 {
            mut acc = 0;
            mut i = 0;
            while i < n {
                acc = acc + read_cell(c);
                i = i + 1;
            }
            return acc;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("post_ipo_loop_gce.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, diags) = ifa_parser::parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = ifa_sema::analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    // compile_to_fir runs the full optimization pipeline (including IPO and post-IPO GCE)
    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let caller_fn = module
        .functions
        .iter()
        .find(|f| ifa_span::INTERNER.resolve(&f.name) == "caller_loop")
        .expect("caller_loop function must exist");

    let formatted = format_function(caller_fn);
    // In caller_loop, read_cell must have been inlined, and the inlined GenCheck hoisted to preheader
    assert!(
        formatted.contains("gen.check"),
        "Hoisted gen.check must exist in caller_loop preheader:\n{}",
        formatted
    );
    assert!(
        formatted.contains("[eliminated]"),
        "Inlined gen.check inside loop body must be marked [eliminated]:\n{}",
        formatted
    );

    let mut interp = FirInterpreter::new(&module);
    let cell_obj = FirValue::Struct {
        name: ifa_span::INTERNER.intern("Cell"),
        fields: vec![FirValue::Int(42)],
    };
    let res = interp
        .execute_function("caller_loop", vec![cell_obj, FirValue::Int(5)])
        .unwrap();
    assert_eq!(res, FirValue::Int(210));
}

#[test]
fn test_post_ipo_caller_pre_checked_dominance_elimination() {
    let src = r#"
        struct Cell {
            val: i64,
        }

        pub fn read_cell(c: ref Cell) -> i64 {
            return c.val;
        }

        pub fn caller_pre_checked(c: ref Cell, n: i64) -> i64 {
            let first = c.val;
            mut acc = first;
            mut i = 0;
            while i < n {
                acc = acc + read_cell(c);
                i = i + 1;
            }
            return acc;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("post_ipo_pre_checked.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, diags) = ifa_parser::parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = ifa_sema::analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let caller_fn = module
        .functions
        .iter()
        .find(|f| ifa_span::INTERNER.resolve(&f.name) == "caller_pre_checked")
        .expect("caller_pre_checked function must exist");

    let formatted = format_function(caller_fn);
    assert!(
        formatted.contains("[eliminated]"),
        "Inlined call check must be eliminated via dominance from prior check:\n{}",
        formatted
    );

    let mut interp = FirInterpreter::new(&module);
    let cell_obj = FirValue::Struct {
        name: ifa_span::INTERNER.intern("Cell"),
        fields: vec![FirValue::Int(50)],
    };
    // first = 50. Loop runs 3 times: + 50 each time. Result: 200.
    let res = interp
        .execute_function("caller_pre_checked", vec![cell_obj, FirValue::Int(3)])
        .unwrap();
    assert_eq!(res, FirValue::Int(200));
}

#[test]
fn test_deeply_nested_triple_loop_licm_hierarchical_hoisting() {
    let src = r#"
        struct Cube {
            density: i64,
        }

        pub fn scan_volume(cube: ref Cube, x_dim: i64, y_dim: i64, z_dim: i64) -> i64 {
            mut mass = 0;
            mut x = 0;
            while x < x_dim {
                mut y = 0;
                while y < y_dim {
                    mut z = 0;
                    while z < z_dim {
                        mass = mass + cube.density + cube.density;
                        z = z + 1;
                    }
                    y = y + 1;
                }
                x = x + 1;
            }
            return mass;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("triple_loop_licm.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, diags) = ifa_parser::parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = ifa_sema::analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let mut module = compile_to_fir(&prog, &analysis.symbols, true, false).unwrap();
    let mut gce = GenerationalOptPass::new();
    gce.run_on_module(&mut module);

    let stats = gce.stats();
    assert!(
        stats.hoisted_checks >= 1,
        "Invariant check must be hoisted out of 3-level loop hierarchy"
    );
    assert!(
        stats.elimination_rate() >= 66.0,
        "Elimination rate should be high in 3-level nested loops, got {:.2}%",
        stats.elimination_rate()
    );

    let mut interp = FirInterpreter::new(&module);
    let cube_obj = FirValue::Struct {
        name: ifa_span::INTERNER.intern("Cube"),
        fields: vec![FirValue::Int(3)],
    };
    // 2 * 3 * 4 iterations = 24. Each iteration adds 3 + 3 = 6. 24 * 6 = 144.
    let res = interp
        .execute_function(
            "scan_volume",
            vec![
                cube_obj,
                FirValue::Int(2),
                FirValue::Int(3),
                FirValue::Int(4),
            ],
        )
        .unwrap();
    assert_eq!(res, FirValue::Int(144));
}

#[test]
fn test_interprocedural_generic_monomorphic_receiver_check_elimination() {
    let src = r#"
        struct Container<T> {
            item: T,
        }

        impl<T> Container<T> {
            pub fn read_val(c: ref Container<T>) -> T {
                return c.item;
            }
        }

        pub fn process_container(n: i64) -> i64 {
            let c = Container(item: n);
            let r = ref c;
            let first = r.read_val();
            let second = r.read_val();
            return first + second;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("generic_receiver_ipo.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, diags) = ifa_parser::parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = ifa_sema::analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let mut module = compile_to_fir(&prog, &analysis.symbols, true, false).unwrap();
    let mut gce = GenerationalOptPass::new();
    gce.run_on_module(&mut module);

    let stats = gce.stats();
    assert!(
        stats.eliminated_checks >= 1,
        "Expected at least 1 eliminated check across monomorphic receivers, got {}",
        stats.eliminated_checks
    );

    let mut interp = FirInterpreter::new(&module);
    let res = interp
        .execute_function("process_container", vec![FirValue::Int(21)])
        .unwrap();
    assert_eq!(res, FirValue::Int(42));
}

#[test]
fn test_interprocedural_closure_capture_generational_check_elimination() {
    let src = r#"
        struct Data {
            val: i64,
        }

        pub fn compute_with_closure(n: i64) -> i64 {
            let d = Data(val: n);
            let r = ref d;
            let add_offset = fn(offset: i64) -> i64 {
                return r.val + offset;
            };
            let first = add_offset(5);
            let second = add_offset(15);
            return first + second;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("closure_gce.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, diags) = ifa_parser::parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = ifa_sema::analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let mut module = compile_to_fir(&prog, &analysis.symbols, true, false).unwrap();
    let mut gce = GenerationalOptPass::new();
    gce.run_on_module(&mut module);

    let stats = gce.stats();
    assert!(
        stats.eliminated_checks >= 1,
        "Expected at least 1 eliminated check in closure capture body, got {}",
        stats.eliminated_checks
    );

    let mut interp = FirInterpreter::new(&module);
    let res = interp
        .execute_function("compute_with_closure", vec![FirValue::Int(10)])
        .unwrap();
    // first = 10 + 5 = 15; second = 10 + 15 = 25; sum = 40.
    assert_eq!(res, FirValue::Int(40));
}

#[test]
fn test_loop_invariant_check_hoisting_with_disjoint_arena_free() {
    use ifa_ast::ParamMode;
    use ifa_fir::types::FirType;
    use ifa_fir::{BlockId, FirFunction, FirParam, Instruction, Terminator, ValueExpr, ValueId};
    use ifa_sema::types::IntType;
    use ifa_span::{Span, INTERNER};

    let fn_name = INTERNER.intern("disjoint_arena_loop");
    let param = FirParam {
        name: INTERNER.intern("r"),
        val: ValueId(0),
        ty: FirType::GenerationalRef(Box::new(FirType::Int(IntType::I64))),
        mode: ParamMode::In,
        noalias: false,
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

    // Block 0: entry / preheader
    let b_entry = BlockId(0);
    let b_header = func.alloc_block(); // BlockId(1)
    let b_body = func.alloc_block(); // BlockId(2)
    let b_exit = func.alloc_block(); // BlockId(3)

    let v_ref_a = func.alloc_value(); // Allocation in Arena 10
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

    // Block 1: header
    let v_cond = func.alloc_value();
    let header_bb = func.get_block_mut(b_header).unwrap();
    header_bb.set_terminator(Terminator::BranchCond {
        cond: v_cond,
        then_block: b_body,
        then_args: Vec::new(),
        else_block: b_exit,
        else_args: Vec::new(),
    });

    // Block 2: body with GenAlloc + GenFree on disjoint Arena 20, and GenCheck on Arena 10 (v_ref_a)
    let v_buf_b = func.alloc_value();
    let body_bb = func.get_block_mut(b_body).unwrap();
    body_bb.push_instruction(Instruction::new(
        Some(v_buf_b),
        ValueExpr::GenAlloc {
            ty: FirType::Int(IntType::I64),
            arena: Some(20),
        },
        Span::DUMMY,
    ));
    body_bb.push_instruction(Instruction::new(
        None,
        ValueExpr::GenFree { ptr: v_buf_b },
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

    let mut gce = GenerationalOptPass::new();
    gce.run_on_function(&mut func);

    // Because Arena 10 and Arena 20 are disjoint, GenFree in Arena 20 cannot invalidate v_ref_a.
    // The check on v_ref_a must be hoisted into preheader b_entry!
    let stats = gce.stats();
    assert_eq!(
        stats.hoisted_checks, 1,
        "Invariant check on disjoint arena 10 must be hoisted into loop preheader, got: {}",
        stats.hoisted_checks
    );
    assert_eq!(
        stats.eliminated_checks, 2,
        "Check inside loop body and redundant preheader check must be eliminated, got: {}",
        stats.eliminated_checks
    );

    // Verify preheader has the hoisted check
    let preheader = func.get_block(b_entry).unwrap();
    let hoisted_found = preheader.instructions.iter().any(|inst| match &inst.expr {
        ValueExpr::GenCheck { ref_val, .. } => *ref_val == v_ref_a,
        _ => false,
    });
    assert!(
        hoisted_found,
        "Preheader must contain hoisted GenCheck for v_ref_a"
    );

    // Verify loop body check is marked redundant
    let loop_body = func.get_block(b_body).unwrap();
    let loop_check_redundant = loop_body.instructions.iter().any(|inst| match &inst.expr {
        ValueExpr::GenCheck { ref_val, redundant } => *ref_val == v_ref_a && *redundant,
        _ => false,
    });
    assert!(
        loop_check_redundant,
        "Loop body GenCheck for v_ref_a must be marked redundant"
    );
}

#[test]
fn test_loop_with_mixed_arenas_selective_hoisting() {
    use ifa_ast::ParamMode;
    use ifa_fir::types::FirType;
    use ifa_fir::{BlockId, FirFunction, FirParam, Instruction, Terminator, ValueExpr, ValueId};
    use ifa_sema::types::IntType;
    use ifa_span::{Span, INTERNER};

    let fn_name = INTERNER.intern("mixed_arenas_loop");
    let param = FirParam {
        name: INTERNER.intern("r"),
        val: ValueId(0),
        ty: FirType::GenerationalRef(Box::new(FirType::Int(IntType::I64))),
        mode: ParamMode::In,
        noalias: false,
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

    let b_entry = BlockId(0);
    let b_header = func.alloc_block();
    let b_body = func.alloc_block();
    let b_exit = func.alloc_block();

    // In entry: ref_a in Arena 10, ref_c in Arena 20
    let v_ref_a = func.alloc_value();
    let v_ref_c = func.alloc_value();

    let entry_bb = func.get_block_mut(b_entry).unwrap();
    entry_bb.push_instruction(Instruction::new(
        Some(v_ref_a),
        ValueExpr::GenAlloc {
            ty: FirType::Int(IntType::I64),
            arena: Some(10),
        },
        Span::DUMMY,
    ));
    entry_bb.push_instruction(Instruction::new(
        Some(v_ref_c),
        ValueExpr::GenAlloc {
            ty: FirType::Int(IntType::I64),
            arena: Some(20),
        },
        Span::DUMMY,
    ));
    entry_bb.set_terminator(Terminator::Branch {
        target: b_header,
        args: Vec::new(),
    });

    let v_cond = func.alloc_value();
    let header_bb = func.get_block_mut(b_header).unwrap();
    header_bb.set_terminator(Terminator::BranchCond {
        cond: v_cond,
        then_block: b_body,
        then_args: Vec::new(),
        else_block: b_exit,
        else_args: Vec::new(),
    });

    // In body: GenAlloc & GenFree on Arena 20.
    // Check ref_a (Arena 10 - disjoint from free!) -> CAN be hoisted.
    // Check ref_c (Arena 20 - same arena as free!) -> CANNOT be hoisted.
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
    body_bb.push_instruction(Instruction::new(
        None,
        ValueExpr::GenCheck {
            ref_val: v_ref_c,
            redundant: false,
        },
        Span::DUMMY,
    ));
    body_bb.set_terminator(Terminator::Branch {
        target: b_header,
        args: Vec::new(),
    });

    let exit_bb = func.get_block_mut(b_exit).unwrap();
    exit_bb.set_terminator(Terminator::Return(Some(v_ref_a)));

    let mut gce = GenerationalOptPass::new();
    gce.run_on_function(&mut func);

    let stats = gce.stats();
    assert_eq!(
        stats.hoisted_checks, 1,
        "Only disjoint Arena 10 check must be hoisted, hoisted: {}",
        stats.hoisted_checks
    );
    assert_eq!(
        stats.eliminated_checks, 2,
        "Disjoint Arena 10 check in body and hoisted preheader check must be eliminated, eliminated: {}",
        stats.eliminated_checks
    );

    // Verify v_ref_a check is marked redundant in loop body
    let loop_body = func.get_block(b_body).unwrap();
    let mut ref_a_redundant = false;
    let mut ref_c_redundant = false;
    for inst in &loop_body.instructions {
        if let ValueExpr::GenCheck { ref_val, redundant } = &inst.expr {
            if *ref_val == v_ref_a {
                ref_a_redundant = *redundant;
            } else if *ref_val == v_ref_c {
                ref_c_redundant = *redundant;
            }
        }
    }
    assert!(
        ref_a_redundant,
        "Check on disjoint v_ref_a must be marked redundant"
    );
    assert!(
        !ref_c_redundant,
        "Check on interfering v_ref_c must NOT be marked redundant"
    );
}

#[test]
fn test_disjoint_arena_free_does_not_break_dominance() {
    use ifa_fir::types::FirType;
    use ifa_fir::{BlockId, FirFunction, Instruction, Terminator, ValueExpr};
    use ifa_sema::types::IntType;
    use ifa_span::{Span, INTERNER};

    let fn_name = INTERNER.intern("dominance_with_disjoint_free");
    let mut func = FirFunction::new(
        fn_name,
        Vec::new(),
        FirType::Int(IntType::I64),
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );

    let b0 = BlockId(0);
    let b1 = func.alloc_block();
    let b2 = func.alloc_block();

    // Block 0: Alloc v_ref_a in Arena 10, GenCheck v_ref_a
    let v_ref_a = func.alloc_value();
    let bb0 = func.get_block_mut(b0).unwrap();
    bb0.push_instruction(Instruction::new(
        Some(v_ref_a),
        ValueExpr::GenAlloc {
            ty: FirType::Int(IntType::I64),
            arena: Some(10),
        },
        Span::DUMMY,
    ));
    bb0.push_instruction(Instruction::new(
        None,
        ValueExpr::GenCheck {
            ref_val: v_ref_a,
            redundant: false,
        },
        Span::DUMMY,
    ));
    bb0.set_terminator(Terminator::Branch {
        target: b1,
        args: Vec::new(),
    });

    // Block 1: GenAlloc v_temp in Arena 20, GenFree v_temp
    let v_temp = func.alloc_value();
    let bb1 = func.get_block_mut(b1).unwrap();
    bb1.push_instruction(Instruction::new(
        Some(v_temp),
        ValueExpr::GenAlloc {
            ty: FirType::Int(IntType::I64),
            arena: Some(20),
        },
        Span::DUMMY,
    ));
    bb1.push_instruction(Instruction::new(
        None,
        ValueExpr::GenFree { ptr: v_temp },
        Span::DUMMY,
    ));
    bb1.set_terminator(Terminator::Branch {
        target: b2,
        args: Vec::new(),
    });

    // Block 2: GenCheck v_ref_a
    let bb2 = func.get_block_mut(b2).unwrap();
    bb2.push_instruction(Instruction::new(
        None,
        ValueExpr::GenCheck {
            ref_val: v_ref_a,
            redundant: false,
        },
        Span::DUMMY,
    ));
    bb2.set_terminator(Terminator::Return(Some(v_ref_a)));

    let mut gce = GenerationalOptPass::new();
    gce.run_on_function(&mut func);

    // GenFree in b1 was on Arena 20, which is disjoint from Arena 10.
    // Therefore, the check on v_ref_a in b2 must be recognized as redundant via dominance!
    let stats = gce.stats();
    assert_eq!(
        stats.eliminated_checks, 2,
        "Dominance check must eliminate check in b0 and b2 across disjoint arena free"
    );

    let bb2_final = func.get_block(b2).unwrap();
    let check_elim = bb2_final.instructions.iter().any(|inst| match &inst.expr {
        ValueExpr::GenCheck { ref_val, redundant } => *ref_val == v_ref_a && *redundant,
        _ => false,
    });
    assert!(check_elim, "GenCheck in b2 must be marked redundant");
}

#[test]
fn test_dominance_elimination_with_thread_local_call_arena_isolation() {
    use ifa_fir::types::FirType;
    use ifa_fir::{
        BasicBlock, BlockId, FirFunction, GenerationalOptPass, Instruction, Terminator, ValueExpr,
        ValueId,
    };
    use ifa_sema::types::IntType;
    use ifa_span::{Span, INTERNER};

    let fn_name = INTERNER.intern("call_arena_isolation");
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
    func.blocks.clear();

    let b0 = BlockId(0);
    let b1 = BlockId(1);
    let b2 = BlockId(2);

    let mut bb0 = BasicBlock::new(b0);
    // Allocate in thread-local call arena
    let v_env = ValueId(0);
    bb0.push_instruction(Instruction::new(
        Some(v_env),
        ValueExpr::CallArenaAlloc {
            ty: FirType::Int(IntType::I64),
        },
        Span::DUMMY,
    ));

    // Create reference and check
    let v_ref = ValueId(1);
    bb0.push_instruction(Instruction::new(
        Some(v_ref),
        ValueExpr::GenRef { ptr: v_env },
        Span::DUMMY,
    ));
    bb0.push_instruction(Instruction::new(
        None,
        ValueExpr::GenCheck {
            ref_val: v_ref,
            redundant: false,
        },
        Span::DUMMY,
    ));
    bb0.set_terminator(Terminator::Branch {
        target: b1,
        args: Vec::new(),
    });
    func.blocks.push(bb0);

    // Block 1: Heap allocation and free on unrelated arena (e.g. Arena 5)
    let mut bb1 = BasicBlock::new(b1);
    let v_heap = ValueId(2);
    bb1.push_instruction(Instruction::new(
        Some(v_heap),
        ValueExpr::GenAlloc {
            ty: FirType::Int(IntType::I64),
            arena: Some(5),
        },
        Span::DUMMY,
    ));
    bb1.push_instruction(Instruction::new(
        None,
        ValueExpr::GenFree { ptr: v_heap },
        Span::DUMMY,
    ));
    bb1.set_terminator(Terminator::Branch {
        target: b2,
        args: Vec::new(),
    });
    func.blocks.push(bb1);

    // Block 2: Subsequent GenCheck on v_ref
    let mut bb2 = BasicBlock::new(b2);
    bb2.push_instruction(Instruction::new(
        None,
        ValueExpr::GenCheck {
            ref_val: v_ref,
            redundant: false,
        },
        Span::DUMMY,
    ));
    let v_res = ValueId(3);
    bb2.push_instruction(Instruction::new(
        Some(v_res),
        ValueExpr::GenDeref { ref_val: v_ref },
        Span::DUMMY,
    ));
    bb2.set_terminator(Terminator::Return(Some(v_res)));
    func.blocks.push(bb2);

    let mut gce = GenerationalOptPass::new();
    gce.run_on_function(&mut func);

    // Both checks on v_ref are eliminated:
    // First check in b0 because it immediately follows definition without free.
    // Second check in b2 because GenFree was in disjoint Arena 5 vs ARENA_THREAD_LOCAL_CALL!
    let stats = gce.stats();
    assert_eq!(
        stats.eliminated_checks, 2,
        "Dominance check must eliminate check in b0 and b2 across disjoint arena free"
    );

    let bb2_final = func.get_block(b2).unwrap();
    let check_elim = bb2_final.instructions.iter().any(|inst| match &inst.expr {
        ValueExpr::GenCheck { ref_val, redundant } => *ref_val == v_ref && *redundant,
        _ => false,
    });
    assert!(
        check_elim,
        "GenCheck in b2 must be marked redundant due to call arena isolation"
    );
}

#[test]
fn test_interprocedural_cyclical_cfg_with_convergent_branches_elimination() {
    let src = r#"
        struct State {
            flag: i64,
            value: i64,
        }

        fn helper_read(s: ref State) -> i64 {
            let v = s.value;
            return v;
        }

        pub fn process_cycle(limit: i64) -> i64 {
            mut st = State(flag: 1, value: 10);
            let r = ref st;
            mut acc = 0;
            mut i = 0;

            while i < limit {
                if i % 2 == 0 {
                    let f = r.flag;
                    acc = acc + f;
                } else {
                    let v = r.value;
                    acc = acc + v;
                }
                let extra = helper_read(r);
                acc = acc + extra;
                i = i + 1;
            }

            return acc;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("cyclical_convergent_ipo.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, diags) = ifa_parser::parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = ifa_sema::analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let mut module = compile_to_fir(&prog, &analysis.symbols, true, false).unwrap();
    let mut gce = GenerationalOptPass::new();
    gce.run_on_module(&mut module);

    let stats = gce.stats();
    assert!(
        stats.eliminated_checks >= 1,
        "Expected eliminated checks across cyclic CFG with convergent branches, got {}",
        stats.eliminated_checks
    );

    // Interpret to verify mathematical and deterministic equivalence
    let mut interp = FirInterpreter::new(&module);
    let res = interp
        .execute_function("process_cycle", vec![FirValue::Int(4)])
        .unwrap();
    // i=0: 1 + 10 = 11; i=1: 10 + 10 = 20 (acc=31); i=2: 1 + 10 = 11 (acc=42); i=3: 10 + 10 = 20 (acc=62)
    assert_eq!(res, FirValue::Int(62));
}

#[test]
fn test_interprocedural_mutual_recursion_cyclical_flow() {
    let src = r#"
        struct Payload {
            weight: i64,
        }

        fn ping(p: ref Payload, step: i64) -> i64 {
            if step <= 0 {
                return p.weight;
            }
            let w = p.weight;
            return w + pong(p, step - 1);
        }

        fn pong(p: ref Payload, step: i64) -> i64 {
            if step <= 0 {
                return p.weight;
            }
            let w = p.weight;
            return w + ping(p, step - 1);
        }

        pub fn run_mutual(init_step: i64) -> i64 {
            mut load = Payload(weight: 5);
            let r = ref load;
            return ping(r, init_step);
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("mutual_rec_ipo.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, diags) = ifa_parser::parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = ifa_sema::analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let mut module = compile_to_fir(&prog, &analysis.symbols, true, false).unwrap();
    let mut gce = GenerationalOptPass::new();
    gce.run_on_module(&mut module);

    let stats = gce.stats();
    assert!(
        stats.eliminated_checks >= 2,
        "Expected eliminated checks across mutual recursion cycle, got {}",
        stats.eliminated_checks
    );

    let mut interp = FirInterpreter::new(&module);
    let res = interp
        .execute_function("run_mutual", vec![FirValue::Int(3)])
        .unwrap();
    // 4 calls of weight 5 = 20
    assert_eq!(res, FirValue::Int(20));
}

#[test]
fn test_confluent_loop_strip_redundant_checks_preserves_semantics() {
    let src = r#"
        struct Counter {
            val: i64,
        }

        pub fn count_branches(n: i64) -> i64 {
            mut c = Counter(val: 1);
            let r = ref c;
            mut acc = 0;
            mut i = 0;

            while i < n {
                if i % 3 == 0 {
                    acc = acc + r.val;
                } else {
                    acc = acc + r.val + r.val;
                }
                let post = r.val;
                acc = acc + post;
                i = i + 1;
            }

            return acc;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("strip_confluent_loop.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, diags) = ifa_parser::parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = ifa_sema::analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let mut module = compile_to_fir(&prog, &analysis.symbols, true, false).unwrap();
    let mut gce = GenerationalOptPass::new();
    gce.run_on_module(&mut module);

    for f in &mut module.functions {
        let stripped = GenerationalOptPass::strip_redundant_checks(f);
        if f.name == ifa_span::INTERNER.intern("count_branches") {
            assert!(
                stripped >= 1,
                "Stripped redundant checks in count_branches must be >= 1, got {}",
                stripped
            );
        }
    }

    let mut interp = FirInterpreter::new(&module);
    let res = interp
        .execute_function("count_branches", vec![FirValue::Int(6)])
        .unwrap();
    // i=0: 0%3==0 -> acc=1+1=2
    // i=1: 1%3!=0 -> acc=2 + 2 + 1 = 5
    // i=2: 2%3!=0 -> acc=5 + 2 + 1 = 8
    // i=3: 3%3==0 -> acc=8 + 1 + 1 = 10
    // i=4: 4%3!=0 -> acc=10 + 2 + 1 = 13
    // i=5: 5%3!=0 -> acc=13 + 2 + 1 = 16
    assert_eq!(res, FirValue::Int(16));
}

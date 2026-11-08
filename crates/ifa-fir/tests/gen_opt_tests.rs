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

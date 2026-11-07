use ifa_fir::{
    compile_to_fir, compile_to_fir_with_opts, format_function, FirInterpreter, FirValue, SroaPass,
};

#[test]
fn test_scalar_variable_mem2reg_promotion() {
    let src = r#"
        pub fn add_numbers(a: i64, b: i64) -> i64 {
            let x = a + 10;
            let y = b + 20;
            let res = x + y;
            return res;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("scalar_test.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, diags) = ifa_parser::parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = ifa_sema::analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    // 1. Without SROA: contains alloca, store, load
    let unopt_module =
        compile_to_fir_with_opts(&prog, &analysis.symbols, false, false, false, false).unwrap();
    let unopt_func = &unopt_module.functions[0];
    let unopt_formatted = format_function(unopt_func);
    assert!(unopt_formatted.contains("alloca"));
    assert!(unopt_formatted.contains("store"));
    assert!(unopt_formatted.contains("load"));

    // 2. With SROA / Mem2Reg: non-escaping allocas, stores, loads promoted into pure SSA
    let opt_module =
        compile_to_fir_with_opts(&prog, &analysis.symbols, false, false, true, false).unwrap();
    let opt_func = &opt_module.functions[0];
    let opt_formatted = format_function(opt_func);

    // Verify all non-escaping allocas are eliminated
    assert!(
        !opt_formatted.contains("alloca"),
        "Expected 0 allocas after Mem2Reg promotion:\n{}",
        opt_formatted
    );
    assert!(
        !opt_formatted.contains("store"),
        "Expected 0 stores after Mem2Reg promotion:\n{}",
        opt_formatted
    );
    assert!(
        !opt_formatted.contains("load"),
        "Expected 0 loads after Mem2Reg promotion:\n{}",
        opt_formatted
    );
    assert!(opt_formatted.contains("add"));

    // 3. Execution in FIR interpreter produces identical correct result
    let mut interp = FirInterpreter::new(&opt_module);
    let result = interp
        .execute_function("add_numbers", vec![FirValue::Int(5), FirValue::Int(7)])
        .unwrap();
    assert_eq!(result, FirValue::Int(42));
}

#[test]
fn test_sroa_aggregate_decomposition_and_promotion() {
    let src = r#"
        struct Vector2D {
            x: i64,
            y: i64,
        }

        pub fn compute_vector() -> i64 {
            mut v = Vector2D(x: 10, y: 20);
            v.x = 42;
            let final_x = v.x;
            return final_x;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("sroa_struct.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, diags) = ifa_parser::parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = ifa_sema::analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let mut module =
        compile_to_fir_with_opts(&prog, &analysis.symbols, false, false, false, false).unwrap();
    let mut sroa = SroaPass::new();
    sroa.run_on_module(&mut module);

    let stats = sroa.stats();
    assert!(
        stats.decomposed_aggregates >= 1,
        "Expected aggregate decomposition, got {:?}",
        stats
    );
    assert!(
        stats.promoted_loads >= 1,
        "Expected promoted loads, got {:?}",
        stats
    );

    // Execute in FIR Interpreter
    let mut interp = FirInterpreter::new(&module);
    let result = interp.execute_function("compute_vector", vec![]).unwrap();
    assert_eq!(result, FirValue::Int(42));
}

#[test]
fn test_escaping_alloca_with_generational_ref_preserved() {
    let src = r#"
        struct Node {
            value: i64,
            parent: ?ref Node,
        }

        pub fn link_nodes() -> i64 {
            mut parent_node = Node(value: 100, parent: None);
            let r = ref parent_node;
            return parent_node.value;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("escape_test.ifa", src);
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
    let func = &module.functions[0];
    let formatted = format_function(func);

    // parent_node escapes via `ref parent_node` (GenRef), so it MUST retain alloca
    assert!(
        formatted.contains("alloca"),
        "Escaped alloca must be preserved:\n{}",
        formatted
    );
    assert!(formatted.contains("gen.ref"));

    let mut interp = FirInterpreter::new(&module);
    let result = interp.execute_function("link_nodes", vec![]).unwrap();
    assert_eq!(result, FirValue::Int(100));
}

#[test]
fn test_multiple_field_reads_and_straight_line_optimizations() {
    let src = r#"
        struct Triangle {
            a: i64,
            b: i64,
            c: i64,
        }

        pub fn perimeter() -> i64 {
            mut t = Triangle(a: 3, b: 4, c: 5);
            let p = t.a + t.b + t.c;
            return p;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("perimeter.ifa", src);
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
    let func = &module.functions[0];
    let formatted = format_function(func);

    // Non-escaping Triangle struct fields should be completely scalarized
    assert!(
        !formatted.contains("alloca"),
        "Expected 0 allocas for pure scalar triangle calculation:\n{}",
        formatted
    );

    let mut interp = FirInterpreter::new(&module);
    let res = interp.execute_function("perimeter", vec![]).unwrap();
    assert_eq!(res, FirValue::Int(12));
}

#[test]
fn test_sroa_mutated_struct_full_pipeline() {
    let src = r#"
        struct Vector2D {
            x: i64,
            y: i64,
        }

        pub fn compute() -> i64 {
            mut v = Vector2D(x: 10, y: 20);
            v.x = 42;
            let final_x = v.x;
            return final_x;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("vec.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, diags) = ifa_parser::parse(fid, tokens);
    assert!(diags.is_empty());

    let analysis = ifa_sema::analyze(&sm, &prog);
    assert!(!analysis.has_errors());

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let func = &module.functions[0];
    let formatted = format_function(func);
    assert!(
        !formatted.contains("alloca"),
        "Expected 0 allocas:\n{}",
        formatted
    );

    let mut interp = FirInterpreter::new(&module);
    let res = interp.execute_function("compute", vec![]).unwrap();
    assert_eq!(res, FirValue::Int(42));
}

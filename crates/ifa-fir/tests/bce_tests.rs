use ifa_fir::printer::format_function;
use ifa_fir::{compile_to_fir, BcePass, FirInterpreter, FirValue};
use ifa_lexer::tokenize;
use ifa_parser::parse;
use ifa_sema::analyze;
use ifa_span::SourceMap;

#[test]
fn test_constant_index_bounds_check_elimination() {
    let src = r#"
        pub fn test_fixed_array_access() -> i64 {
            let arr: [i64; 4] = [10, 20, 30, 40];
            let a = arr[0];
            let b = arr[1];
            let c = arr[2];
            let d = arr[3];
            return a + b + c + d;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("const_bce.ifa".to_string(), src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let mut module = ifa_fir::lower_program(&prog, &analysis.symbols);
    println!("LOWERED FIR:\n{}", ifa_fir::printer::format_module(&module));
    let mut bce = BcePass::new();
    bce.run_on_module(&mut module);
    println!(
        "OPTIMIZED FIR:\n{}",
        ifa_fir::printer::format_module(&module)
    );

    let stats = bce.stats();
    assert!(
        stats.total_checks >= 4,
        "Expected at least 4 bounds checks, got {}",
        stats.total_checks
    );
    assert!(
        stats.eliminated_checks >= 4,
        "All 4 constant in-bounds accesses should be statically eliminated, got {}",
        stats.eliminated_checks
    );
    assert_eq!(
        stats.elimination_rate(),
        100.0,
        "Elimination rate for constant in-bounds accesses should be 100%"
    );

    let func = &module.functions[0];
    let formatted = format_function(func);
    assert!(
        formatted.contains("[eliminated]"),
        "Formatted FIR should display eliminated checks:\n{}",
        formatted
    );

    // Verify execution in FIR interpreter
    let mut interp = FirInterpreter::new(&module);
    let result = interp
        .execute_function("test_fixed_array_access", vec![])
        .unwrap();
    assert_eq!(result, FirValue::Int(100));
}

#[test]
fn test_loop_induction_bounds_check_elimination() {
    let src = r#"
        pub fn sum_array() -> i64 {
            let arr: [i64; 5] = [2, 4, 6, 8, 10];
            let mut sum: i64 = 0;
            for x in arr {
                sum = sum + x;
            }
            return sum;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("loop_bce.ifa".to_string(), src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let mut module = ifa_fir::lower_program(&prog, &analysis.symbols);
    println!("LOWERED FIR:\n{}", ifa_fir::printer::format_module(&module));
    let mut bce = BcePass::new();
    bce.run_on_module(&mut module);
    println!(
        "OPTIMIZED FIR:\n{}",
        ifa_fir::printer::format_module(&module)
    );

    let stats = bce.stats();
    assert!(
        stats.eliminated_checks >= 1,
        "Loop bounds check must be eliminated by induction variable analysis, got {}",
        stats.eliminated_checks
    );

    let mut interp = FirInterpreter::new(&module);
    let result = interp.execute_function("sum_array", vec![]).unwrap();
    assert_eq!(result, FirValue::Int(30));
}

#[test]
fn test_dominance_bounds_check_elimination() {
    let src = r#"
        pub fn double_access(s: Slice<i64>, idx: i64) -> i64 {
            let a = s[idx];
            let b = s[idx];
            return a + b;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("dom_bce.ifa".to_string(), src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let mut module = ifa_fir::lower_program(&prog, &analysis.symbols);
    println!("LOWERED FIR:\n{}", ifa_fir::printer::format_module(&module));
    let mut bce = BcePass::new();
    bce.run_on_module(&mut module);
    println!(
        "OPTIMIZED FIR:\n{}",
        ifa_fir::printer::format_module(&module)
    );

    let stats = bce.stats();
    assert!(
        stats.total_checks >= 2,
        "Expected at least 2 checks, got {}",
        stats.total_checks
    );
    assert!(
        stats.dominance_checks_eliminated >= 1,
        "Second access must be eliminated by dominance analysis, got {}",
        stats.dominance_checks_eliminated
    );
}

#[test]
fn test_purge_redundant_checks_removes_instructions() {
    let src = r#"
        pub fn clean_indices() -> i64 {
            let arr: [i64; 3] = [100, 200, 300];
            return arr[0] + arr[1];
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("purge_bce.ifa".to_string(), src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty());

    let analysis = analyze(&sm, &prog);
    assert!(!analysis.has_errors());

    let mut module = compile_to_fir(&prog, &analysis.symbols, true, true).expect("FIR failed");
    let bce = BcePass::new();
    bce.purge_redundant_checks(&mut module.functions[0]);

    // Format and verify no bounds_check instructions remain in the purged function
    let formatted = format_function(&module.functions[0]);
    assert!(
        !formatted.contains("bounds.check"),
        "Purged function must not contain redundant bounds.check instructions:\n{}",
        formatted
    );
}

use ifa_fir::{
    compile_to_fir, compile_to_fir_with_opts, format_function, FirInterpreter, FirValue,
    FirVerifier, IpoPass, TcoPass,
};
use ifa_lexer::tokenize;
use ifa_parser::parse;
use ifa_sema::analyze;
use ifa_span::{SourceMap, INTERNER};

#[test]
fn test_tco_direct_tail_recursion_sum() {
    let src = r#"
        pub fn sum_tail(n: i64, acc: i64) -> i64 {
            if n <= 0 {
                return acc;
            }
            return sum_tail(n - 1, acc + n);
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("sum_tail.ifa".to_string(), src);
    let (prog, diags) = parse(fid, tokenize(fid, src));
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    // 1. Lower to FIR without full vectorize/IPO
    let mut module =
        compile_to_fir_with_opts(&prog, &analysis.symbols, true, true, true, false).unwrap();

    // 2. Run TCO Pass directly
    let mut tco = TcoPass::new();
    tco.run_on_module(&mut module);

    let stats = tco.stats();
    assert_eq!(
        stats.functions_transformed, 1,
        "sum_tail must be transformed to a loop: {:?}",
        stats
    );
    assert_eq!(
        stats.tail_calls_eliminated, 1,
        "1 tail call site must be eliminated: {:?}",
        stats
    );

    // 3. Verify SSA invariants
    FirVerifier::verify_module(&module).expect("FIR module must verify after TCO");

    let sum_fn = module
        .functions
        .iter()
        .find(|f| INTERNER.resolve(&f.name) == "sum_tail")
        .expect("sum_tail function exists");

    let formatted = format_function(sum_fn);
    assert!(
        !formatted.contains("call_direct sum_tail"),
        "Recursive call must be eliminated from FIR:\n{}",
        formatted
    );

    // 4. Test execution via FIR Interpreter for small and large N
    let mut interp = FirInterpreter::new(&module);

    let res_small = interp
        .execute_function("sum_tail", vec![FirValue::Int(10), FirValue::Int(0)])
        .expect("Interpretation failed");
    assert_eq!(res_small, FirValue::Int(55));

    // Deep recursion that would overflow stack if not transformed into a loop
    let res_large = interp
        .execute_function("sum_tail", vec![FirValue::Int(2000), FirValue::Int(0)])
        .expect("Interpretation failed");
    assert_eq!(res_large, FirValue::Int(2001000));
}

#[test]
fn test_tco_collatz_multiple_tail_branches() {
    let src = r#"
        pub fn collatz_steps(n: i64, steps: i64) -> i64 {
            if n <= 1 {
                return steps;
            }
            if n % 2 == 0 {
                return collatz_steps(n / 2, steps + 1);
            } else {
                return collatz_steps(3 * n + 1, steps + 1);
            }
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("collatz.ifa".to_string(), src);
    let (prog, diags) = parse(fid, tokenize(fid, src));
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let mut module =
        compile_to_fir_with_opts(&prog, &analysis.symbols, true, true, true, false).unwrap();

    let mut tco = TcoPass::new();
    tco.run_on_module(&mut module);

    let stats = tco.stats();
    assert_eq!(stats.functions_transformed, 1);
    assert_eq!(
        stats.tail_calls_eliminated, 2,
        "Both even and odd recursive branches must be eliminated: {:?}",
        stats
    );

    FirVerifier::verify_module(&module).expect("FIR module must verify after TCO");

    let collatz_fn = module
        .functions
        .iter()
        .find(|f| INTERNER.resolve(&f.name) == "collatz_steps")
        .expect("collatz_steps function exists");

    let formatted = format_function(collatz_fn);
    assert!(
        !formatted.contains("call_direct collatz_steps"),
        "Both recursive calls must be eliminated:\n{}",
        formatted
    );

    let mut interp = FirInterpreter::new(&module);

    // collatz_steps(6, 0): 6 -> 3 -> 10 -> 5 -> 16 -> 8 -> 4 -> 2 -> 1 (8 steps)
    let res = interp
        .execute_function("collatz_steps", vec![FirValue::Int(6), FirValue::Int(0)])
        .expect("Interpretation failed");
    assert_eq!(res, FirValue::Int(8));
}

#[test]
fn test_tco_gcd_euclidean() {
    let src = r#"
        pub fn gcd(a: i64, b: i64) -> i64 {
            if b == 0 {
                return a;
            }
            return gcd(b, a % b);
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("gcd.ifa".to_string(), src);
    let (prog, diags) = parse(fid, tokenize(fid, src));
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let mut module =
        compile_to_fir_with_opts(&prog, &analysis.symbols, true, true, true, false).unwrap();

    let mut tco = TcoPass::new();
    tco.run_on_module(&mut module);

    assert_eq!(tco.stats().functions_transformed, 1);
    assert_eq!(tco.stats().tail_calls_eliminated, 1);

    FirVerifier::verify_module(&module).expect("FIR module must verify after TCO");

    let mut interp = FirInterpreter::new(&module);

    let res = interp
        .execute_function("gcd", vec![FirValue::Int(48), FirValue::Int(18)])
        .expect("Interpretation failed");
    assert_eq!(res, FirValue::Int(6));

    let res2 = interp
        .execute_function("gcd", vec![FirValue::Int(1071), FirValue::Int(462)])
        .expect("Interpretation failed");
    assert_eq!(res2, FirValue::Int(21));
}

#[test]
fn test_tco_non_tail_recursion_preserved() {
    let src = r#"
        pub fn fib(n: i64) -> i64 {
            if n <= 1 {
                return n;
            }
            return fib(n - 1) + fib(n - 2);
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("fib.ifa".to_string(), src);
    let (prog, diags) = parse(fid, tokenize(fid, src));
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let mut module =
        compile_to_fir_with_opts(&prog, &analysis.symbols, true, true, true, false).unwrap();

    let mut tco = TcoPass::new();
    tco.run_on_module(&mut module);

    assert_eq!(
        tco.stats().tail_calls_eliminated,
        0,
        "Non-tail recursive fib calls must NOT be eliminated by TCO"
    );
    assert_eq!(tco.stats().functions_transformed, 0);

    FirVerifier::verify_module(&module).expect("FIR module must verify");
}

#[test]
fn test_tco_integrated_ipo_whole_module() {
    let src = r#"
        pub fn fact_tail(n: i64, acc: i64) -> i64 {
            if n <= 1 {
                return acc;
            }
            return fact_tail(n - 1, acc * n);
        }

        pub fn compute_total(limit: i64) -> i64 {
            return fact_tail(limit, 1);
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("fact_ipo.ifa".to_string(), src);
    let (prog, diags) = parse(fid, tokenize(fid, src));
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    // Full compilation to FIR with IPO enabled
    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let fact_fn = module
        .functions
        .iter()
        .find(|f| INTERNER.resolve(&f.name) == "fact_tail")
        .expect("fact_tail function exists");

    let formatted = format_function(fact_fn);
    assert!(
        !formatted.contains("call_direct fact_tail"),
        "fact_tail must be converted to loop by IPO/TCO pass:\n{}",
        formatted
    );

    let mut interp = FirInterpreter::new(&module);

    let res = interp
        .execute_function("compute_total", vec![FirValue::Int(5)])
        .expect("Interpretation failed");
    assert_eq!(res, FirValue::Int(120));
}

#[test]
fn test_tco_mutually_recursive_pure_functions() {
    let src = r#"
        pub fn is_even(n: i64) -> bool {
            if n == 0 {
                return true;
            }
            return is_odd(n - 1);
        }

        pub fn is_odd(n: i64) -> bool {
            if n == 0 {
                return false;
            }
            return is_even(n - 1);
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("mutual_rec_tco.ifa".to_string(), src);
    let (prog, diags) = parse(fid, tokenize(fid, src));
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let mut module =
        compile_to_fir_with_opts(&prog, &analysis.symbols, true, true, true, false).unwrap();

    let mut ipo_pass = IpoPass::new();
    ipo_pass.run_on_module(&mut module);

    let stats = ipo_pass.stats();
    assert!(
        stats.mutual_tail_calls_inlined >= 1 || stats.tail_calls_eliminated >= 1,
        "Expected mutual tail recursion to be inlined and transformed into loop: {:?}",
        stats
    );

    FirVerifier::verify_module(&module).expect("FIR module must verify after mutual TCO");

    let mut interp = FirInterpreter::new(&module);

    let res_even = interp
        .execute_function("is_even", vec![FirValue::Int(10)])
        .expect("Interpretation failed");
    assert_eq!(res_even, FirValue::Bool(true));

    let res_odd = interp
        .execute_function("is_even", vec![FirValue::Int(11)])
        .expect("Interpretation failed");
    assert_eq!(res_odd, FirValue::Bool(false));
}

#[test]
fn test_tco_deep_recursion_no_stack_overflow() {
    let src = r#"
        pub fn count_down(n: i64, acc: i64) -> i64 {
            if n <= 0 {
                return acc;
            }
            return count_down(n - 1, acc + 1);
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("deep_tco.ifa".to_string(), src);
    let (prog, diags) = parse(fid, tokenize(fid, src));
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let mut module =
        compile_to_fir_with_opts(&prog, &analysis.symbols, true, true, true, false).unwrap();

    let mut tco = TcoPass::new();
    tco.run_on_module(&mut module);

    assert_eq!(tco.stats().functions_transformed, 1);
    assert_eq!(tco.stats().tail_calls_eliminated, 1);

    FirVerifier::verify_module(&module).expect("FIR module must verify after TCO");

    let mut interp = FirInterpreter::new(&module);
    // 50,000 iterations in standard recursion would blow the interpreter stack (call depth > 50,000).
    // In TCO loop, it runs in O(1) space on a single frame.
    let res = interp
        .execute_function("count_down", vec![FirValue::Int(50000), FirValue::Int(0)])
        .expect("Interpretation of 50,000 iterations failed");
    assert_eq!(res, FirValue::Int(50000));
}

#[test]
fn test_tco_unit_returning_tail_call() {
    let src = r#"
        pub fn recurse_unit(mut n: i64) {
            if n <= 0 {
                return;
            }
            recurse_unit(n - 1);
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("unit_tco.ifa".to_string(), src);
    let (prog, diags) = parse(fid, tokenize(fid, src));
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let mut module =
        compile_to_fir_with_opts(&prog, &analysis.symbols, true, true, true, false).unwrap();

    let mut tco = TcoPass::new();
    tco.run_on_module(&mut module);

    assert_eq!(tco.stats().functions_transformed, 1);
    assert_eq!(tco.stats().tail_calls_eliminated, 1);

    FirVerifier::verify_module(&module).expect("FIR module must verify after TCO");

    let mut interp = FirInterpreter::new(&module);
    let res = interp
        .execute_function("recurse_unit", vec![FirValue::Int(50)])
        .expect("Interpretation failed");
    assert_eq!(res, FirValue::Unit);
}

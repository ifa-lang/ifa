use ifa_fir::{compile_to_fir, FirInterpreter, FirValue};
use ifa_lexer::tokenize;
use ifa_parser::parse;
use ifa_sema::analyze;
use ifa_span::SourceMap;

#[test]
fn test_fir_pure_lambda_execution() {
    let src = r#"
        pub fn main() -> i64 {
            let square = fn(x: i64) -> i64 {
                return x * x;
            };
            return square(9);
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("pure_lambda.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let mut interp = FirInterpreter::new(&module);
    let result = interp.execute_function("main", vec![]).unwrap();
    assert_eq!(result, FirValue::Int(81));
}

#[test]
fn test_fir_closure_environment_capture() {
    let src = r#"
        pub fn main() -> i64 {
            let factor: i64 = 7;
            let multiplier = fn(x: i64) -> i64 {
                return x * factor;
            };
            return multiplier(6);
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("closure_capture.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let mut interp = FirInterpreter::new(&module);
    let result = interp.execute_function("main", vec![]).unwrap();
    assert_eq!(result, FirValue::Int(42));
}

#[test]
fn test_fir_closure_multiple_captures() {
    let src = r#"
        pub fn main() -> i64 {
            let base: i64 = 100;
            let offset: i64 = 25;
            let compute = fn(factor: i64) -> i64 {
                return base + offset * factor;
            };
            return compute(3);
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("closure_multi_capture.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let mut interp = FirInterpreter::new(&module);
    let result = interp.execute_function("main", vec![]).unwrap();
    assert_eq!(result, FirValue::Int(175));
}

#[test]
fn test_fir_closure_bidirectional_inference_and_inline_call() {
    let src = r#"
        pub fn main() -> i64 {
            let add_ten: fn(i64) -> i64 = fn(x) {
                return x + 10;
            };
            let a = add_ten(32);
            let b = (fn(y: i64) -> i64 { return y * 2; })(5);
            return a + b;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("closure_inference.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let mut interp = FirInterpreter::new(&module);
    let result = interp.execute_function("main", vec![]).unwrap();
    assert_eq!(result, FirValue::Int(52));
}

#[test]
fn test_fir_higher_order_function_apply() {
    let src = r#"
        pub fn apply(f: fn(i64) -> i64, val: i64) -> i64 {
            return f(val);
        }

        pub fn main() -> i64 {
            let factor: i64 = 6;
            let multiplier = fn(x: i64) -> i64 {
                return x * factor;
            };
            return apply(multiplier, 7);
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("closure_apply.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let mut interp = FirInterpreter::new(&module);
    let result = interp.execute_function("main", vec![]).unwrap();
    assert_eq!(result, FirValue::Int(42));
}

#[test]
fn test_fir_closure_escape_analysis_and_devirtualization() {
    let src = r#"
        pub fn apply(f: fn(i64) -> i64, val: i64) -> i64 {
            return f(val);
        }

        pub fn main() -> i64 {
            let offset: i64 = 100;
            let add_offset = fn(x: i64) -> i64 {
                return x + offset;
            };
            return apply(add_offset, 25);
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("closure_opt_test.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let mut fir_module = ifa_fir::lower_program(&prog, &analysis.symbols);
    let mut sroa = ifa_fir::SroaPass::new();
    sroa.run_on_module(&mut fir_module);

    let mut closure_pass = ifa_fir::ClosureOptPass::new();
    closure_pass.run_on_module(&mut fir_module);

    let stats = closure_pass.stats();
    assert_eq!(stats.total_closures, 1);
    assert_eq!(stats.stack_allocated_closures, 1);
    assert_eq!(stats.heap_allocated_closures, 0);
    assert!(stats.inlined_higher_order_calls >= 1);

    let mut interp = FirInterpreter::new(&fir_module);
    let result = interp.execute_function("main", vec![]).unwrap();
    assert_eq!(result, FirValue::Int(125));
}

#[test]
fn test_fir_higher_order_iterators_example() {
    let src = include_str!("../../../examples/higher_order_iterators.ifa");

    let mut sm = SourceMap::new();
    let fid = sm.add_file("higher_order_iterators.ifa", src);
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
    let mut interp = FirInterpreter::new(&fir_module);
    let result = interp.execute_function("main", vec![]).unwrap();
    assert_eq!(result, FirValue::Int(82));
}

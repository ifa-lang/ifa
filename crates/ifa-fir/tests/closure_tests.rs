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

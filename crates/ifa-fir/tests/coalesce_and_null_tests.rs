use ifa_fir::{compile_to_fir, FirInterpreter, FirValue, InterpError};
use ifa_lexer::tokenize;
use ifa_parser::parse;
use ifa_sema::analyze;
use ifa_span::SourceMap;

#[test]
fn test_null_literal_and_coalesce_fallback() {
    let src = r#"
        fn main() -> i64 {
            let x: ?i64 = null;
            let y = x ?? 42;
            return y;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("coalesce_null.ifa", src);
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
    let res = interp.execute_function("main", vec![]).unwrap();
    assert_eq!(res, FirValue::Int(42));
}

#[test]
fn test_coalesce_non_null_value() {
    let src = r#"
        fn main() -> i64 {
            let x: ?i64 = 100;
            let y = x ?? 42;
            return y;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("coalesce_val.ifa", src);
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
    let res = interp.execute_function("main", vec![]).unwrap();
    assert_eq!(res, FirValue::Int(100));
}

#[test]
fn test_null_equality_and_assert_eq() {
    let src = r#"
        fn main() -> () {
            let a: ?i64 = null;
            let b: ?i64 = null;
            assert(a == null);
            assert(a == b);
            assert_eq(null, null);

            let c: ?i64 = 77;
            assert(c != null);
            assert_ne(c, null);
            assert_eq(c, 77);
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("null_eq.ifa", src);
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
    let res = interp.execute_function("main", vec![]).unwrap();
    assert_eq!(res, FirValue::Unit);
}

#[test]
fn test_assert_eq_failure_diagnostics() {
    let src = r#"
        fn fail_eq() -> () {
            assert_eq(42, 99, "value mismatch");
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("assert_fail.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, _) = parse(fid, tokens);
    let analysis = analyze(&sm, &prog);
    assert!(!analysis.has_errors());

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let mut interp = FirInterpreter::new(&module);
    let err = interp.execute_function("fail_eq", vec![]).unwrap_err();

    match err {
        InterpError::Panic(msg) => {
            assert!(msg.contains("assertion failed: `(left == right)`"));
            assert!(msg.contains("left: `42`"));
            assert!(msg.contains("right: `99`"));
            assert!(msg.contains("value mismatch"));
        }
        other => panic!("Expected Panic error, got: {:?}", other),
    }
}

#[test]
fn test_assert_ne_failure_diagnostics() {
    let src = r#"
        fn fail_ne() -> () {
            assert_ne(100, 100);
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("assert_ne_fail.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, _) = parse(fid, tokens);
    let analysis = analyze(&sm, &prog);
    assert!(!analysis.has_errors());

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let mut interp = FirInterpreter::new(&module);
    let err = interp.execute_function("fail_ne", vec![]).unwrap_err();

    match err {
        InterpError::Panic(msg) => {
            assert!(msg.contains("assertion failed: `(left != right)`"));
            assert!(msg.contains("both equal to `100`"));
        }
        other => panic!("Expected Panic error, got: {:?}", other),
    }
}

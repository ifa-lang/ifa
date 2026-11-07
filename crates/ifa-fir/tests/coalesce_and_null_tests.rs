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

#[test]
fn test_safe_navigation_operator_null_and_non_null() {
    let src = r#"
        struct Node {
            val: i64,
            next: ?ref Node,
        }

        fn get_val(n: ref Node) -> i64 {
            return n.val;
        }

        fn main() -> () {
            let empty: ?ref Node = null;
            let v1 = empty?.val;
            assert_eq(v1, null);

            let v_coalesced = empty?.val ?? 999;
            assert_eq(v_coalesced, 999);

            let m_call = empty?.get_val();
            assert_eq(m_call, null);

            let n = Node(val: 123, next: null);
            let r: ref Node = ref n;
            let opt_r: ?ref Node = r;
            let v2 = opt_r?.val;
            assert_eq(v2, 123);
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("safe_nav.ifa", src);
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
fn test_safe_navigation_chained() {
    let src = r#"
        struct BoxNode {
            inner: ?ref BoxNode,
            data: i64,
        }

        fn main() -> i64 {
            let root: ?ref BoxNode = null;
            let d1 = root?.inner?.data ?? 888;
            return d1;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("safe_nav_chain.ifa", src);
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
    assert_eq!(res, FirValue::Int(888));
}

#[test]
fn test_constant_folding_and_dead_branch_elimination() {
    let src = r#"
        fn main() -> i64 {
            let x: ?i64 = null;
            let val = if (x == null) {
                111
            } else {
                222
            };
            return val;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("dead_branch.ifa", src);
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
    let main_fn = module
        .functions
        .iter()
        .find(|f| ifa_span::INTERNER.resolve(&f.name) == "main")
        .unwrap();

    let has_cond_branch = main_fn
        .blocks
        .iter()
        .any(|b| matches!(b.terminator, Some(ifa_fir::Terminator::BranchCond { .. })));
    assert!(
        !has_cond_branch,
        "Statically known condition must eliminate BranchCond"
    );

    let mut interp = FirInterpreter::new(&module);
    let res = interp.execute_function("main", vec![]).unwrap();
    assert_eq!(res, FirValue::Int(111));
}

use ifa_fir::{compile_to_fir, FirInterpreter, FirValue};
use ifa_lexer::tokenize;
use ifa_parser::parse;
use ifa_sema::analyze;
use ifa_span::SourceMap;

#[test]
fn test_adt_enum_payload_and_match_destructuring() {
    let src = r#"
        enum WebEvent {
            PageLoad,
            KeyPress(i64),
            Click(i64),
        }

        fn evaluate_event(e: WebEvent) -> i64 {
            return match e {
                WebEvent::PageLoad => 10,
                WebEvent::KeyPress(key) => key + 1,
                WebEvent::Click(pos) => pos * 2,
            }
        }

        fn main() -> i64 {
            let e1 = WebEvent::PageLoad;
            let e2 = WebEvent::KeyPress(41);
            let e3 = WebEvent::Click(25);

            let r1 = evaluate_event(e1);
            let r2 = evaluate_event(e2);
            let r3 = evaluate_event(e3);

            return r1 + r2 + r3;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("adt_match.ifa", src);
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
    // r1: 10, r2: 42, r3: 50 => 10 + 42 + 50 = 102
    assert_eq!(res, FirValue::Int(102));
}

#[test]
fn test_match_guards_with_adt_payloads() {
    let src = r#"
        enum Status {
            Pending,
            Active(i64),
            Completed(i64),
        }

        fn classify_status(s: Status) -> i64 {
            return match s {
                Status::Pending => 0,
                Status::Active(priority) if priority > 100 => 200,
                Status::Active(priority) => priority,
                Status::Completed(code) => code * 10,
            }
        }

        fn main() -> i64 {
            let s_low = Status::Active(50);
            let s_high = Status::Active(150);
            let s_done = Status::Completed(7);
            let s_wait = Status::Pending;

            let c1 = classify_status(s_low);
            let c2 = classify_status(s_high);
            let c3 = classify_status(s_done);
            let c4 = classify_status(s_wait);

            return c1 + c2 + c3 + c4;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("match_guard.ifa", src);
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
    // c1: 50, c2: 200 (guard prioritised), c3: 70, c4: 0 => 50 + 200 + 70 + 0 = 320
    assert_eq!(res, FirValue::Int(320));
}

#[test]
fn test_adt_semantic_validation_errors() {
    // 1. Variant expects payload but none provided
    let src_missing_payload = r#"
        enum ResultPayload {
            Ok(i64),
            Err,
        }

        fn test() -> () {
            let _ = ResultPayload::Ok();
        }
    "#;
    let mut sm = SourceMap::new();
    let fid = sm.add_file("err1.ifa", src_missing_payload);
    let tokens = tokenize(fid, src_missing_payload);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty());
    let analysis = analyze(&sm, &prog);
    assert!(analysis.has_errors());
    assert!(analysis
        .diagnostics
        .iter()
        .any(|d| d.code.as_deref() == Some("E0040")));

    // 2. Variant does not expect payload but argument provided
    let src_unexpected_payload = r#"
        enum ResultPayload {
            Ok(i64),
            Err,
        }

        fn test() -> () {
            let _ = ResultPayload::Err(42);
        }
    "#;
    let mut sm = SourceMap::new();
    let fid = sm.add_file("err2.ifa", src_unexpected_payload);
    let tokens = tokenize(fid, src_unexpected_payload);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty());
    let analysis = analyze(&sm, &prog);
    assert!(analysis.has_errors());
    assert!(analysis
        .diagnostics
        .iter()
        .any(|d| d.code.as_deref() == Some("E0042")));
}

#[test]
fn test_nested_variant_and_literal_pattern_matching() {
    let src = r#"
        enum TreeVal {
            Leaf(i64),
            Empty,
        }

        fn eval_tree(t: TreeVal) -> i64 {
            return match t {
                TreeVal::Leaf(0) => 1000,
                TreeVal::Leaf(val) => val * 10,
                TreeVal::Empty => 0,
            }
        }

        fn main() -> i64 {
            let t1 = TreeVal::Leaf(0);
            let t2 = TreeVal::Leaf(5);
            let t3 = TreeVal::Empty;

            let r1 = eval_tree(t1);
            let r2 = eval_tree(t2);
            let r3 = eval_tree(t3);

            return r1 + r2 + r3;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("nested_match.ifa", src);
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
    // r1: 1000 (Leaf(0) matched), r2: 50 (Leaf(val)), r3: 0 (Empty) => 1050
    assert_eq!(res, FirValue::Int(1050));
}

#[test]
fn test_sroa_tagged_union_folding() {
    use ifa_fir::{lower_program, SroaPass};

    let src = r#"
        enum Choice {
            First(i64),
            Second,
        }

        fn compute() -> i64 {
            let c = Choice::First(99);
            return match c {
                Choice::First(x) => x,
                Choice::Second => 0,
            }
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("sroa_tagged.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty());

    let analysis = analyze(&sm, &prog);
    assert!(!analysis.has_errors());

    let mut fir_module = lower_program(&prog, &analysis.symbols);
    let mut sroa = SroaPass::new();
    sroa.run_on_module(&mut fir_module);

    assert!(
        sroa.stats().folded_discriminants > 0,
        "Expected at least one tagged union discriminant to be folded, stats: {:?}",
        sroa.stats()
    );
    assert!(
        sroa.stats().forwarded_payloads > 0,
        "Expected at least one tagged union payload to be forwarded, stats: {:?}",
        sroa.stats()
    );

    let mut interp = FirInterpreter::new(&fir_module);
    let res = interp.execute_function("compute", vec![]).unwrap();
    assert_eq!(res, FirValue::Int(99));
}

#[test]
fn test_tuple_pattern_matching_execution() {
    let src = r#"
        fn match_tuple(p: (i64, i64)) -> i64 {
            return match p {
                (0, 0) => 100,
                (0, y) => y,
                (x, 0) => x,
                (x, y) => x + y,
            }
        }

        fn main() -> i64 {
            let p1 = match_tuple((0, 0));
            let p2 = match_tuple((0, 42));
            let p3 = match_tuple((55, 0));
            let p4 = match_tuple((10, 20));
            return p1 + p2 + p3 + p4;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("tup_match.ifa", src);
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
    // p1: 100, p2: 42, p3: 55, p4: 30 => 100 + 42 + 55 + 30 = 227
    assert_eq!(res, FirValue::Int(227));
}

#[test]
fn test_struct_pattern_matching_execution() {
    let src = r#"
        struct Point {
            x: i64,
            y: i64
        }

        fn process_point(pt: Point) -> i64 {
            return match pt {
                Point { x: 0, y: 0 } => 500,
                Point { x: 0, y } => y * 10,
                Point { x, y: 0 } => x * 100,
                Point { x, y } => x + y,
            }
        }

        fn main() -> i64 {
            let p1 = process_point(Point(x: 0, y: 0));
            let p2 = process_point(Point(x: 0, y: 7));
            let p3 = process_point(Point(x: 3, y: 0));
            let p4 = process_point(Point(x: 15, y: 25));
            return p1 + p2 + p3 + p4;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("struct_match.ifa", src);
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
    // p1: 500, p2: 70, p3: 300, p4: 40 => 500 + 70 + 300 + 40 = 910
    assert_eq!(res, FirValue::Int(910));
}

#[test]
fn test_nested_struct_and_tuple_pattern_execution() {
    let src = r#"
        struct Container {
            pair: (i64, i64),
            factor: i64
        }

        fn evaluate_container(c: Container) -> i64 {
            return match c {
                Container { pair: (0, 0), factor } => factor,
                Container { pair: (x, y), factor } => (x + y) * factor,
            }
        }

        fn main() -> i64 {
            let c1 = evaluate_container(Container(pair: (0, 0), factor: 42));
            let c2 = evaluate_container(Container(pair: (3, 4), factor: 10));
            return c1 + c2;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("nested_match.ifa", src);
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
    // c1: 42, c2: (3 + 4) * 10 = 70 => 112
    assert_eq!(res, FirValue::Int(112));
}

#[test]
fn test_sroa_aggregate_projection_folding() {
    use ifa_fir::{lower_program, SroaPass};

    let src = r#"
        struct Coord {
            a: i64,
            b: i64
        }

        fn compute_proj() -> i64 {
            let pt = Coord(a: 11, b: 22);
            return match pt {
                Coord { a, b } => a + b,
            }
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("sroa_proj.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty());

    let analysis = analyze(&sm, &prog);
    assert!(!analysis.has_errors());

    let mut fir_module = lower_program(&prog, &analysis.symbols);
    let mut sroa = SroaPass::new();
    sroa.run_on_module(&mut fir_module);

    assert!(
        sroa.stats().decomposed_aggregates > 0 || sroa.stats().forwarded_payloads > 0,
        "Expected at least one field projection or aggregate to be optimized by SROA, stats: {:?}",
        sroa.stats()
    );

    let mut interp = FirInterpreter::new(&fir_module);
    let res = interp.execute_function("compute_proj", vec![]).unwrap();
    assert_eq!(res, FirValue::Int(33));
}

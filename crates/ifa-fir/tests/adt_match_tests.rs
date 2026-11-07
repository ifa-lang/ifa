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

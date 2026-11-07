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

#[test]
fn test_or_pattern_execution() {
    let src = r#"
        enum Coin {
            Heads,
            Tails,
            Edge
        }

        fn eval_coin(c: Coin) -> i64 {
            return match c {
                Coin::Heads | Coin::Tails => 1,
                Coin::Edge => 2,
            }
        }

        fn classify_int(n: i64) -> i64 {
            return match n {
                1 | 3 | 5 | 7 | 9 => 11,
                2 | 4 | 6 | 8 => 22,
                _ => 99,
            }
        }

        pub fn main() -> i64 {
            let r1 = eval_coin(Coin::Heads);
            let r2 = eval_coin(Coin::Tails);
            let r3 = eval_coin(Coin::Edge);
            let r4 = classify_int(5);
            let r5 = classify_int(4);
            let r6 = classify_int(100);
            return r1 + r2 + r3 + r4 + r5 + r6;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("or_pattern.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parsing errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Analysis errors: {:?}",
        analysis.diagnostics
    );

    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let mut interp = FirInterpreter::new(&fir_module);
    let res = interp.execute_function("main", vec![]).unwrap();
    // r1: 1, r2: 1, r3: 2, r4: 11, r5: 22, r6: 99 => sum = 136
    assert_eq!(res, FirValue::Int(136));
}

#[test]
fn test_range_pattern_execution() {
    let src = r#"
        fn classify_grade(score: i64) -> i64 {
            return match score {
                90..=100 => 4,
                80..=89 => 3,
                70..=79 => 2,
                0..=69 => 1,
                _ => 0,
            }
        }

        fn combined_match(val: i64) -> i64 {
            return match val {
                1..=5 | 10..=15 => 100,
                20..=25 | 30..=35 => 200,
                _ => -1,
            }
        }

        pub fn main() -> i64 {
            let g1 = classify_grade(95);
            let g2 = classify_grade(85);
            let g3 = classify_grade(60);
            let c1 = combined_match(3);
            let c2 = combined_match(12);
            let c3 = combined_match(33);
            let c4 = combined_match(50);
            return g1 + g2 + g3 + c1 + c2 + c3 + c4;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("range_pattern.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parsing errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Analysis errors: {:?}",
        analysis.diagnostics
    );

    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let mut interp = FirInterpreter::new(&fir_module);
    let res = interp.execute_function("main", vec![]).unwrap();
    // g1: 4, g2: 3, g3: 1, c1: 100, c2: 100, c3: 200, c4: -1 => sum = 407
    assert_eq!(res, FirValue::Int(407));
}

#[test]
fn test_or_pattern_with_shared_bindings_execution() {
    let src = r#"
        enum ResultVal {
            Success(i64),
            Cached(i64),
            Failure
        }

        fn extract_val(res: ResultVal) -> i64 {
            return match res {
                ResultVal::Success(v) | ResultVal::Cached(v) => v * 2,
                ResultVal::Failure => 0,
            }
        }

        pub fn main() -> i64 {
            let r1 = extract_val(ResultVal::Success(21));
            let r2 = extract_val(ResultVal::Cached(50));
            let r3 = extract_val(ResultVal::Failure);
            return r1 + r2 + r3;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("or_pattern_bindings.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parsing errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Analysis errors: {:?}",
        analysis.diagnostics
    );

    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let mut interp = FirInterpreter::new(&fir_module);
    let res = interp.execute_function("main", vec![]).unwrap();
    // r1: 42, r2: 100, r3: 0 => sum = 142
    assert_eq!(res, FirValue::Int(142));
}

#[test]
fn test_slice_pattern_matching_fixed_array_interp() {
    let src = r#"
        fn classify_trio(arr: [i64; 3]) -> i64 {
            return match arr {
                [0, 0, 0] => 0,
                [first, 2, third] => first * 10 + third,
                [x, y, z] => x + y + z,
            };
        }

        pub fn main() -> i64 {
            let a = classify_trio([0, 0, 0]);
            let b = classify_trio([5, 2, 7]);
            let c = classify_trio([10, 20, 30]);
            return a + b + c;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("slice_pattern_fixed.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parsing errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Analysis errors: {:?}",
        analysis.diagnostics
    );

    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let mut interp = FirInterpreter::new(&fir_module);
    let res = interp.execute_function("main", vec![]).unwrap();
    // a = 0
    // b = 5 * 10 + 7 = 57
    // c = 10 + 20 + 30 = 60
    // sum = 117
    assert_eq!(res, FirValue::Int(117));
}

#[test]
fn test_slice_pattern_with_rest_and_subslice_interp() {
    let src = r#"
        fn classify_with_rest(arr: [i64; 4]) -> i64 {
            return match arr {
                [0, ..mid, 0] => 1000,
                [first, ..mid, last] => first * 100 + last,
            };
        }

        pub fn main() -> i64 {
            let r1 = classify_with_rest([0, 5, 8, 0]);
            let r2 = classify_with_rest([3, 7, 11, 9]);
            return r1 + r2;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("slice_pattern_rest.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parsing errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Analysis errors: {:?}",
        analysis.diagnostics
    );

    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let mut interp = FirInterpreter::new(&fir_module);
    let res = interp.execute_function("main", vec![]).unwrap();
    // r1: 1000
    // r2: 3 * 100 + 9 = 309
    // sum = 1309
    assert_eq!(res, FirValue::Int(1309));
}

#[test]
fn test_nested_slice_pattern_matching_interp() {
    let src = r#"
        fn sum_matrix_2x2(m: [[i64; 2]; 2]) -> i64 {
            return match m {
                [[a, b], [c, d]] => a + b + c + d,
            };
        }

        pub fn main() -> i64 {
            let m: [[i64; 2]; 2] = [[10, 20], [30, 40]];
            return sum_matrix_2x2(m);
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("nested_slice_pattern.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parsing errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Analysis errors: {:?}",
        analysis.diagnostics
    );

    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let mut interp = FirInterpreter::new(&fir_module);
    let res = interp.execute_function("main", vec![]).unwrap();
    // 10 + 20 + 30 + 40 = 100
    assert_eq!(res, FirValue::Int(100));
}

#[test]
fn test_destructuring_let_and_mut_interp() {
    let src = r#"
        struct Coordinate {
            x: i64,
            y: i64,
        }

        pub fn main() -> i64 {
            // 1. Tuple destructuring
            let (a, b) = (10, 20);

            // 2. Mutable tuple destructuring with mutation
            mut (u, v) = (5, 15);
            u += 10; // u = 15
            v += 20; // v = 35

            // 3. Struct destructuring
            let c = Coordinate(x: 100, y: 200);
            let Coordinate { x: cx, y: cy } = c;

            // 4. Fixed array slice destructuring
            let arr: [i64; 3] = [30, 40, 50];
            let [first, ..rest] = arr;

            return a + b + u + v + cx + cy + first + rest[0] + rest[1];
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("destructuring_let.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parsing errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Analysis errors: {:?}",
        analysis.diagnostics
    );

    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let mut interp = FirInterpreter::new(&fir_module);
    let res = interp.execute_function("main", vec![]).unwrap();
    assert_eq!(res, FirValue::Int(500));
}

#[test]
fn test_if_let_execution_then_and_else() {
    let src = r#"
        enum OptionVal {
            Some(i64),
            None,
        }

        fn compute(opt: OptionVal) -> i64 {
            if let OptionVal::Some(x) = opt {
                return x * 2;
            } else {
                return -1;
            }
        }

        fn main() -> i64 {
            let s = OptionVal::Some(21);
            let n = OptionVal::None;

            let r1 = compute(s);
            let r2 = compute(n);

            return r1 + r2; // 42 + (-1) = 41
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("if_let_exec.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parsing errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Analysis errors: {:?}",
        analysis.diagnostics
    );

    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let mut interp = FirInterpreter::new(&fir_module);
    let res = interp.execute_function("main", vec![]).unwrap();
    assert_eq!(res, FirValue::Int(41));
}

#[test]
fn test_while_let_execution_accumulator() {
    let src = r#"
        enum Stream {
            Value(i64),
            End,
        }

        fn step(current: i64) -> Stream {
            if current > 0 {
                return Stream::Value(current - 1);
            } else {
                return Stream::End;
            }
        }

        fn main() -> i64 {
            mut s = Stream::Value(4);
            mut sum = 0;

            while let Stream::Value(n) = s {
                sum += n;
                s = step(n);
            }

            return sum; // 4 + 3 + 2 + 1 + 0 = 10
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("while_let_exec.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parsing errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Analysis errors: {:?}",
        analysis.diagnostics
    );

    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let mut interp = FirInterpreter::new(&fir_module);
    let res = interp.execute_function("main", vec![]).unwrap();
    assert_eq!(res, FirValue::Int(10));
}

#[test]
fn test_if_let_expression_phi_value() {
    let src = r#"
        enum Flag {
            Enabled(i64),
            Disabled,
        }

        fn main() -> i64 {
            let f1 = Flag::Enabled(100);
            let f2 = Flag::Disabled;

            let v1 = if let Flag::Enabled(x) = f1 { x + 10 } else { 0 };
            let v2 = if let Flag::Enabled(y) = f2 { y + 10 } else { 5 };

            return v1 + v2; // 110 + 5 = 115
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("if_let_expr.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parsing errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Analysis errors: {:?}",
        analysis.diagnostics
    );

    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let mut interp = FirInterpreter::new(&fir_module);
    let res = interp.execute_function("main", vec![]).unwrap();
    assert_eq!(res, FirValue::Int(115));
}

#[test]
fn test_example_if_let_while_let_execution() {
    let src = include_str!("../../../examples/if_let_while_let.ifa");

    let mut sm = SourceMap::new();
    let fid = sm.add_file("if_let_while_let.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parsing errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Analysis errors: {:?}",
        analysis.diagnostics
    );

    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let mut interp = FirInterpreter::new(&fir_module);
    let res = interp.execute_function("main", vec![]).unwrap();
    assert_eq!(res, FirValue::Int(3659));
}

#[test]
fn test_if_let_with_guard_execution() {
    let src = r#"
        enum NumOpt {
            Some(i64),
            None,
        }

        fn classify(opt: NumOpt) -> i64 {
            if let NumOpt::Some(x) = opt if x > 100 {
                return x * 2;
            } else if let NumOpt::Some(y) = opt if y > 0 {
                return y + 10;
            } else if let NumOpt::Some(z) = opt {
                return z - 1;
            } else {
                return -999;
            }
        }

        fn main() -> i64 {
            let a = classify(NumOpt::Some(150)); // 300
            let b = classify(NumOpt::Some(50));  // 60
            let c = classify(NumOpt::Some(-5));  // -6
            let d = classify(NumOpt::None);      // -999

            return a + b + c + d; // 300 + 60 - 6 - 999 = -645
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("if_let_guard_exec.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parsing errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Analysis errors: {:?}",
        analysis.diagnostics
    );

    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let mut interp = FirInterpreter::new(&fir_module);
    let res = interp.execute_function("main", vec![]).unwrap();
    assert_eq!(res, FirValue::Int(-645));
}

#[test]
fn test_while_let_with_guard_execution() {
    let src = r#"
        enum Stream {
            Next(i64),
            End,
        }

        fn step(x: i64) -> Stream {
            return Stream::Next(x + 1);
        }

        fn main() -> i64 {
            mut s = Stream::Next(1);
            mut sum = 0;

            // Loop continues while s is Stream::Next(n) AND n is less than or equal to 5
            while let Stream::Next(n) = s if n <= 5 {
                sum += n;
                s = step(n);
            }

            return sum; // 1 + 2 + 3 + 4 + 5 = 15
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("while_let_guard_exec.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parsing errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Analysis errors: {:?}",
        analysis.diagnostics
    );

    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let mut interp = FirInterpreter::new(&fir_module);
    let res = interp.execute_function("main", vec![]).unwrap();
    assert_eq!(res, FirValue::Int(15));
}

#[test]
fn test_if_let_nested_patterns_and_guard_execution() {
    let src = r#"
        struct Coord {
            x: i64,
            y: i64,
        }

        enum Position {
            Point(Coord),
            Origin,
        }

        fn evaluate(pos: Position) -> i64 {
            if let Position::Point(Coord { x, y }) = pos if x > 0 && y > 0 {
                return x * y;
            } else if let Position::Point(Coord { x, y }) = pos if x < 0 || y < 0 {
                return -(x * y);
            } else {
                return 0;
            }
        }

        fn main() -> i64 {
            let p1 = Position::Point(Coord(x: 4, y: 5));   // 20
            let p2 = Position::Point(Coord(x: -3, y: 7));  // -(-21) = 21
            let p3 = Position::Point(Coord(x: 0, y: 10));  // 0
            let p4 = Position::Origin;                     // 0

            return evaluate(p1) + evaluate(p2) + evaluate(p3) + evaluate(p4); // 20 + 21 + 0 + 0 = 41
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("if_let_nested_guard_exec.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parsing errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Analysis errors: {:?}",
        analysis.diagnostics
    );

    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let mut interp = FirInterpreter::new(&fir_module);
    let res = interp.execute_function("main", vec![]).unwrap();
    assert_eq!(res, FirValue::Int(41));
}

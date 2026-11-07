use ifa_fir::{compile_to_fir, FirInterpreter, FirValue};
use ifa_lexer::tokenize;
use ifa_parser::parse;
use ifa_sema::analyze;
use ifa_span::SourceMap;

#[test]
fn test_string_interpolation_basic() {
    let src = r#"
        pub fn main() -> String {
            let name = "World";
            let msg = "Hello, {name}!";
            return msg;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("interp_basic.ifa", src);
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
    assert_eq!(result, FirValue::String("Hello, World!".to_string()));
}

#[test]
fn test_string_interpolation_with_integers_and_arithmetic() {
    let src = r#"
        pub fn main() -> String {
            let a: i64 = 10;
            let b: i64 = 32;
            let msg = "Result: {a + b} (double is {(a + b) * 2})";
            return msg;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("interp_arith.ifa", src);
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
    assert_eq!(
        result,
        FirValue::String("Result: 42 (double is 84)".to_string())
    );
}

#[test]
fn test_string_interpolation_with_escaped_braces() {
    let src = r#"
        pub fn main() -> String {
            let count: i64 = 5;
            let payload = "JSON: {{'count': {count}}}";
            return payload;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("interp_escape.ifa", src);
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
    assert_eq!(result, FirValue::String("JSON: {'count': 5}".to_string()));
}

#[test]
fn test_string_interpolation_with_floats_and_booleans() {
    let src = r#"
        pub fn main() -> String {
            let available: bool = true;
            let score: f64 = 98.5;
            let msg = "Status: {available}, Score: {score}";
            return msg;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("interp_types.ifa", src);
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
    assert_eq!(
        result,
        FirValue::String("Status: true, Score: 98.5".to_string())
    );
}

#[test]
fn test_string_interpolation_with_struct_fields_spec_section_4_3() {
    let src = r#"
        struct PaymentPayload {
            merchant_id: String,
            amount_xof: i64,
            currency: String
        }

        pub fn main() -> String {
            let payload = PaymentPayload(
                merchant_id: "MERCH-99482",
                amount_xof: 75000,
                currency: "XOF"
            );
            return "Traitement transaction pour {payload.merchant_id} : {payload.amount_xof} {payload.currency}";
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("interp_spec_4_3.ifa", src);
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
    assert_eq!(
        result,
        FirValue::String("Traitement transaction pour MERCH-99482 : 75000 XOF".to_string())
    );
}

#[test]
fn test_string_interpolation_with_higher_order_closures() {
    let src = r#"
        pub fn main() -> String {
            let factor: i64 = 3;
            let triple = fn(x: i64) -> i64 {
                return x * factor;
            };
            return "Computed value: {triple(14)}";
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("interp_closure.ifa", src);
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
    assert_eq!(result, FirValue::String("Computed value: 42".to_string()));
}

#[test]
fn test_string_concatenation_with_add_operator() {
    let src = r#"
        pub fn main() -> String {
            let prefix = "IFA Systems ";
            let suffix = "Language";
            return prefix + suffix;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("str_concat.ifa", src);
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
    assert_eq!(result, FirValue::String("IFA Systems Language".to_string()));
}

#[test]
fn test_string_interpolation_in_comptime() {
    let src = r#"
        comptime fn format_metric(label: String, val: i64) -> String {
            return "{label}: {val} ms";
        }

        pub fn main() -> String {
            return comptime format_metric("Latency", 42);
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("comptime_interp.ifa", src);
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
    assert_eq!(result, FirValue::String("Latency: 42 ms".to_string()));
}

#[test]
fn test_string_constant_folding_pure_literals() {
    let src = r#"
        pub fn main() -> String {
            let combined = "Part1: " + "Part2: " + "Part3";
            return combined;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("fold_pure.ifa", src);
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
    assert_eq!(result, FirValue::String("Part1: Part2: Part3".to_string()));

    // Verify that the main function contains folded constant strings
    let main_fn = module
        .functions
        .iter()
        .find(|f| f.name.as_str() == "main")
        .unwrap();
    let format_count = main_fn
        .blocks
        .iter()
        .flat_map(|b| &b.instructions)
        .filter(|inst| matches!(inst.expr, ifa_fir::ValueExpr::FormatString(_)))
        .count();
    assert_eq!(
        format_count, 0,
        "All pure string concatenations must be folded away into constants"
    );
}

#[test]
fn test_string_constant_folding_mixed_contiguous_segments() {
    let src = r#"
        pub fn main() -> String {
            let dyn_label = "DYNAMIC";
            let msg = "Start " + " middle: " + dyn_label + " end1 " + "end2";
            return msg;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("fold_mixed.ifa", src);
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
    assert_eq!(
        result,
        FirValue::String("Start  middle: DYNAMIC end1 end2".to_string())
    );
}

#[test]
fn test_string_interpolation_struct_to_string_method() {
    let src = r#"
        struct Currency {
            code: String,
            symbol: String,
        }

        impl Currency {
            pub fn to_string(c: Currency) -> String {
                return c.code + " (" + c.symbol + ")";
            }
        }

        pub fn main() -> String {
            let eur = Currency(code: "EUR", symbol: "€");
            let msg = "Selected currency: {eur}";
            return msg;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("interp_struct_method.ifa", src);
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
    assert_eq!(
        result,
        FirValue::String("Selected currency: EUR (€)".to_string())
    );
}

#[test]
fn test_string_interpolation_trait_display_implementation() {
    let src = r#"
        trait Display {
            fn to_string(p: Point) -> String;
        }

        struct Point {
            x: i64,
            y: i64,
        }

        impl Display for Point {
            pub fn to_string(p: Point) -> String {
                return "({p.x}, {p.y})";
            }
        }

        pub fn main() -> String {
            let pt = Point(x: 12, y: 34);
            let display = "Coordinate is {pt}";
            return display;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("interp_trait_display.ifa", src);
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
    assert_eq!(
        result,
        FirValue::String("Coordinate is (12, 34)".to_string())
    );
}

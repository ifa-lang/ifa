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

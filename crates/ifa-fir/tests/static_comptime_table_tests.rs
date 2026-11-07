use ifa_fir::{compile_to_fir, format_function};
use ifa_lexer::tokenize;
use ifa_parser::parse;
use ifa_sema::analyze;
use ifa_span::{SourceMap, INTERNER};

#[test]
fn test_static_comptime_table_generation_and_lowering() {
    let src = r#"
        comptime fn generate_coefficients() -> [i64; 4] {
            mut arr = [0; 4];
            mut i = 0;
            while i < 4 {
                arr[i] = (i + 1) * 10;
                i = i + 1;
            }
            return arr;
        }

        const COEFFS: [i64; 4] = comptime generate_coefficients();

        pub fn get_coeff(idx: i64) -> i64 {
            return COEFFS[idx];
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("comptime_table.ifa".to_string(), src);
    let (prog, _) = parse(fid, tokenize(fid, src));
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    // Verify comptime value evaluated in sema
    let coeffs_sym = INTERNER.intern("COEFFS");
    let val = analysis
        .symbols
        .comptime_values
        .get(&coeffs_sym)
        .expect("COEFFS must be evaluated");
    if let ifa_comptime::Value::Array(elems) = val {
        assert_eq!(elems.len(), 4);
        assert_eq!(elems[0], ifa_comptime::Value::Int(10));
        assert_eq!(elems[1], ifa_comptime::Value::Int(20));
        assert_eq!(elems[2], ifa_comptime::Value::Int(30));
        assert_eq!(elems[3], ifa_comptime::Value::Int(40));
    } else {
        panic!("Expected array value for COEFFS, got: {:?}", val);
    }

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let get_coeff_fn = module
        .functions
        .iter()
        .find(|f| INTERNER.resolve(&f.name) == "get_coeff")
        .expect("get_coeff must exist in FIR module");

    let formatted = format_function(get_coeff_fn);
    assert!(
        formatted.contains("array(") || formatted.contains("getelem"),
        "FIR function must lower comptime array table into FIR SSA aggregate:\n{}",
        formatted
    );
}

#[test]
fn test_static_comptime_table_constant_indexing_folded_by_sroa() {
    let src = r#"
        comptime fn make_powers() -> [i64; 4] {
            mut p = [1; 4];
            p[1] = 2;
            p[2] = 4;
            p[3] = 8;
            return p;
        }

        const POWERS: [i64; 4] = comptime make_powers();

        pub fn get_third_power() -> i64 {
            return POWERS[3];
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("comptime_sroa.ifa".to_string(), src);
    let (prog, _) = parse(fid, tokenize(fid, src));
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let fn_fir = module
        .functions
        .iter()
        .find(|f| INTERNER.resolve(&f.name) == "get_third_power")
        .expect("get_third_power must exist");

    let formatted = format_function(fn_fir);
    // SROA forwards constant indexing from ArrayInit(1, 2, 4, 8) at index 3 directly to v3 = const 8_i64
    assert!(
        formatted.contains("ret v3") && formatted.contains("const 8_i64"),
        "Expected SROA to forward constant index 3 to constant 8:\n{}",
        formatted
    );
}

#[test]
fn test_static_comptime_table_in_vectorized_loop() {
    let src = r#"
        const FACTORS: [f32; 4] = comptime [1.5, 2.0, 2.5, 3.0];

        pub fn apply_factors(mut data: [f32; 64]) {
            mut i = 0;
            while i < 64 {
                data[i] = data[i] * FACTORS[0];
                i = i + 1;
            }
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("table_vec.ifa".to_string(), src);
    let (prog, _) = parse(fid, tokenize(fid, src));
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let apply_fn = module
        .functions
        .iter()
        .find(|f| INTERNER.resolve(&f.name) == "apply_factors")
        .expect("apply_factors must exist");

    let formatted = format_function(apply_fn);
    assert!(
        formatted.contains("// [vector_hint: width="),
        "Loop accessing static comptime table must be auto-vectorized:\n{}",
        formatted
    );
}

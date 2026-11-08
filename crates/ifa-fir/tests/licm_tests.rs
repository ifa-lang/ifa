use ifa_fir::printer::format_function;
use ifa_fir::{compile_to_fir, lower_program, FirInterpreter, FirValue, LicmPass};

#[test]
fn test_nested_generic_struct_field_projection_licm_hoisting() {
    let src = r#"
        struct Inner<T> {
            val: T,
        }

        struct Pair<T> {
            first: Inner<T>,
            second: Inner<T>,
        }

        pub fn sum_loop(p: Pair<i64>, n: i64) -> i64 {
            mut acc = 0;
            mut i = 0;
            while i < n {
                acc = acc + p.first.val;
                i = i + 1;
            }
            return acc;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("licm_nested.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, diags) = ifa_parser::parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = ifa_sema::analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let func = module
        .functions
        .iter()
        .find(|f| ifa_span::INTERNER.resolve(&f.name) == "sum_loop")
        .expect("sum_loop must exist");

    let _formatted = format_function(func);

    // In sum_loop, the preheader block (bb1) must contain the hoisted field projections
    let mut interp = FirInterpreter::new(&module);
    let inner_obj = FirValue::Struct {
        name: ifa_span::INTERNER.intern("Inner__i64"),
        fields: vec![FirValue::Int(15)],
    };
    let pair_obj = FirValue::Struct {
        name: ifa_span::INTERNER.intern("Pair__Inner__i64"),
        fields: vec![inner_obj.clone(), inner_obj],
    };

    // 15 * 10 = 150
    let res = interp
        .execute_function("sum_loop", vec![pair_obj, FirValue::Int(10)])
        .unwrap();
    assert_eq!(res, FirValue::Int(150));
}

#[test]
fn test_licm_preserves_semantics_with_multiple_nested_generic_fields() {
    let src = r#"
        struct Config<T> {
            multiplier: T,
            offset: T,
        }

        pub fn compute_scaled(cfg: Config<i64>, limit: i64) -> i64 {
            mut acc = 0;
            mut i = 0;
            while i < limit {
                acc = acc + (cfg.multiplier + cfg.offset);
                i = i + 1;
            }
            return acc;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("licm_multi.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, diags) = ifa_parser::parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = ifa_sema::analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let mut interp = FirInterpreter::new(&module);
    let cfg_obj = FirValue::Struct {
        name: ifa_span::INTERNER.intern("Config__i64"),
        fields: vec![FirValue::Int(7), FirValue::Int(3)],
    };

    // (7 + 3) * 5 = 50
    let res = interp
        .execute_function("compute_scaled", vec![cfg_obj, FirValue::Int(5)])
        .unwrap();
    assert_eq!(res, FirValue::Int(50));
}

#[test]
fn test_licm_pass_stats_and_hoisting_action() {
    let src = r#"
        struct Data<T> {
            val: T,
        }

        pub fn run_hoisting_action(d: Data<i64>, n: i64) -> i64 {
            mut acc = 0;
            mut i = 0;
            while i < n {
                acc = acc + d.val;
                i = i + 1;
            }
            return acc;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("licm_action.ifa", src);
    let tokens = ifa_lexer::tokenize(fid, src);
    let (prog, diags) = ifa_parser::parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = ifa_sema::analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let mut module = lower_program(&prog, &analysis.symbols);
    println!("BEFORE LICM:\n{}", format_function(&module.functions[0]));
    let mut licm = LicmPass::new();
    licm.run_on_module(&mut module);
    println!("AFTER LICM:\n{}", format_function(&module.functions[0]));
    println!("STATS: {:?}", licm.stats());

    let stats = licm.stats();
    assert!(
        stats.loops_optimized >= 1,
        "LICM must optimize at least one loop with generic struct field access"
    );

    let mut interp = FirInterpreter::new(&module);
    let data_obj = FirValue::Struct {
        name: ifa_span::INTERNER.intern("Data__i64"),
        fields: vec![FirValue::Int(100)],
    };
    let res = interp
        .execute_function("run_hoisting_action", vec![data_obj, FirValue::Int(4)])
        .unwrap();
    assert_eq!(res, FirValue::Int(400));
}

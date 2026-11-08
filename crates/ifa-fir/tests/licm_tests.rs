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

#[test]
fn test_licm_bounds_check_hoisting_out_of_loop() {
    let src = r#"
        pub fn sum_array_licm(arr: [i64; 4], idx: i64, n: i64) -> i64 {
            mut acc = 0;
            mut i = 0;
            while i < n {
                acc = acc + arr[idx];
                i = i + 1;
            }
            return acc;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("licm_bce.ifa", src);
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
    let mut licm = LicmPass::new();
    licm.run_on_module(&mut module);

    let stats = licm.stats();
    assert!(
        stats.hoisted_bounds_checks >= 1,
        "Expected at least 1 hoisted bounds check, got {:?}",
        stats
    );

    let mut interp = FirInterpreter::new(&module);
    let arr_val = FirValue::Array(vec![
        FirValue::Int(10),
        FirValue::Int(25),
        FirValue::Int(30),
        FirValue::Int(45),
    ]);

    // arr[1] = 25; 25 * 4 = 100
    let res = interp
        .execute_function(
            "sum_array_licm",
            vec![arr_val, FirValue::Int(1), FirValue::Int(4)],
        )
        .unwrap();
    assert_eq!(res, FirValue::Int(100));
}

#[test]
fn test_licm_nested_struct_disjoint_field_write_fusion() {
    let src = r#"
        struct ValueHolder {
            num: i64,
        }

        struct DualContext {
            read_side: ValueHolder,
            write_side: ValueHolder,
        }

        pub fn process_context(ctx: DualContext, n: i64) -> i64 {
            mut acc = 0;
            mut i = 0;
            mut written = ctx.write_side.num;
            while i < n {
                acc = acc + ctx.read_side.num;
                written = written + 1;
                i = i + 1;
            }
            return acc + written;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("licm_disjoint.ifa", src);
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
    let mut licm = LicmPass::new();
    licm.run_on_module(&mut module);

    let stats = licm.stats();
    assert!(
        stats.loops_optimized >= 1,
        "Expected loop to be optimized by LICM with disjoint field analysis"
    );

    let mut interp = FirInterpreter::new(&module);
    let read_holder = FirValue::Struct {
        name: ifa_span::INTERNER.intern("ValueHolder"),
        fields: vec![FirValue::Int(50)],
    };
    let write_holder = FirValue::Struct {
        name: ifa_span::INTERNER.intern("ValueHolder"),
        fields: vec![FirValue::Int(5)],
    };
    let dual_ctx = FirValue::Struct {
        name: ifa_span::INTERNER.intern("DualContext"),
        fields: vec![read_holder, write_holder],
    };

    // acc = 50 * 3 = 150; written = 5 + 3 = 8; total = 158
    let res = interp
        .execute_function("process_context", vec![dual_ctx, FirValue::Int(3)])
        .unwrap();
    assert_eq!(res, FirValue::Int(158));
}

#[test]
fn test_licm_nested_struct_array_bounds_check_hoisting() {
    let src = r#"
        struct BufferWrapper {
            items: [i64; 4],
        }

        struct SystemState {
            buf: BufferWrapper,
            step: i64,
        }

        pub fn run_state_loop(s: SystemState, idx: i64, n: i64) -> i64 {
            mut acc = 0;
            mut i = 0;
            while i < n {
                acc = acc + s.buf.items[idx];
                i = i + 1;
            }
            return acc;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("licm_nested_bce.ifa", src);
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
    let mut licm = LicmPass::new();
    licm.run_on_module(&mut module);

    let stats = licm.stats();
    assert!(
        stats.hoisted_bounds_checks >= 1,
        "Expected nested struct array bounds check to be hoisted, got {:?}",
        stats
    );

    let mut interp = FirInterpreter::new(&module);
    let buf_obj = FirValue::Struct {
        name: ifa_span::INTERNER.intern("BufferWrapper"),
        fields: vec![FirValue::Array(vec![
            FirValue::Int(11),
            FirValue::Int(22),
            FirValue::Int(33),
            FirValue::Int(44),
        ])],
    };
    let state_obj = FirValue::Struct {
        name: ifa_span::INTERNER.intern("SystemState"),
        fields: vec![buf_obj, FirValue::Int(1)],
    };

    // items[2] = 33; 33 * 5 = 165
    let res = interp
        .execute_function(
            "run_state_loop",
            vec![state_obj, FirValue::Int(2), FirValue::Int(5)],
        )
        .unwrap();
    assert_eq!(res, FirValue::Int(165));
}

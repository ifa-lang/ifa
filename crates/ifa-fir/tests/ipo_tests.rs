use ifa_fir::{compile_to_fir, compile_to_fir_with_opts, format_function, IpoPass, VectorizePass};
use ifa_lexer::tokenize;
use ifa_parser::parse;
use ifa_sema::analyze;
use ifa_span::{SourceMap, INTERNER};

#[test]
fn test_ipo_purity_analysis_computation() {
    let src = r#"
        pub fn square(x: f32) -> f32 {
            return x * x;
        }

        pub fn pure_caller(x: f32) -> f32 {
            return square(x) + 1.0;
        }

        pub fn side_effecting_log(val: i64) {
            println("trace");
        }

        pub fn impure_caller(val: i64) {
            side_effecting_log(val);
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("purity_test.ifa".to_string(), src);
    let (prog, diags) = parse(fid, tokenize(fid, src));
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let pure_funcs = IpoPass::compute_pure_functions(&module);

    let square_sym = INTERNER.intern("square");
    let pure_caller_sym = INTERNER.intern("pure_caller");
    let side_effect_sym = INTERNER.intern("side_effecting_log");
    let impure_caller_sym = INTERNER.intern("impure_caller");

    assert!(
        pure_funcs.contains(&square_sym),
        "square must be proven pure"
    );
    assert!(
        pure_funcs.contains(&pure_caller_sym),
        "pure_caller must be proven pure"
    );
    assert!(
        !pure_funcs.contains(&side_effect_sym),
        "side_effecting_log is impure"
    );
    assert!(
        !pure_funcs.contains(&impure_caller_sym),
        "impure_caller transitively calls impure"
    );
}

#[test]
fn test_ipo_pure_helper_inlining_in_vectorizable_loop() {
    let src = r#"
        pub fn scale_f32(x: f32) -> f32 {
            return x * 2.5;
        }

        pub fn process_array(mut data: [f32; 128]) {
            mut i = 0;
            while i < 128 {
                data[i] = scale_f32(data[i]);
                i = i + 1;
            }
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("ipo_inline.ifa".to_string(), src);
    let (prog, diags) = parse(fid, tokenize(fid, src));
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    // 1. Compile with opt_vectorize = false to test isolated IpoPass transformation
    let mut module =
        compile_to_fir_with_opts(&prog, &analysis.symbols, true, true, true, false).unwrap();

    let mut ipo_pass = IpoPass::new();
    ipo_pass.run_on_module(&mut module);

    let ipo_stats = ipo_pass.stats();
    assert!(
        ipo_stats.pure_calls_inlined_in_loops >= 1,
        "Expected pure helper call to be inlined in loop, got stats: {:?}",
        ipo_stats
    );
    assert!(
        ipo_stats.loops_transformed >= 1,
        "Expected loop to be transformed by IPO inlining"
    );

    // 2. Now run VectorizePass on the inlined module
    let mut vec_pass = VectorizePass::new();
    vec_pass.run_on_module(&mut module);
    let vec_stats = vec_pass.stats();
    assert!(
        vec_stats.loops_vectorized >= 1,
        "Loop must be auto-vectorized after IPO inlining: {:?}",
        vec_stats
    );

    let process_fn = module
        .functions
        .iter()
        .find(|f| INTERNER.resolve(&f.name) == "process_array")
        .expect("process_array must exist");

    let formatted = format_function(process_fn);
    assert!(
        formatted.contains("// [vector_hint: width="),
        "Expected vector hint after pure function inlining:\n{}",
        formatted
    );
}

#[test]
fn test_ipo_impure_call_prevents_loop_vectorization() {
    let src = r#"
        pub fn notify_step(i: i64) {
            println("step");
        }

        pub fn loop_with_io(mut data: [f32; 64]) {
            mut i = 0;
            while i < 64 {
                notify_step(i);
                data[i] = data[i] + 1.0;
                i = i + 1;
            }
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("impure_loop.ifa".to_string(), src);
    let (prog, diags) = parse(fid, tokenize(fid, src));
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let mut module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let mut ipo_pass = IpoPass::new();
    ipo_pass.run_on_module(&mut module);

    assert_eq!(
        ipo_pass.stats().pure_calls_inlined_in_loops,
        0,
        "Impure call must not be inlined by IPO"
    );

    let loop_fn = module
        .functions
        .iter()
        .find(|f| INTERNER.resolve(&f.name) == "loop_with_io")
        .expect("loop_with_io must exist");

    let formatted = format_function(loop_fn);
    assert!(
        !formatted.contains("[vector_hint:"),
        "Loop with I/O call must NOT be vectorized:\n{}",
        formatted
    );
}

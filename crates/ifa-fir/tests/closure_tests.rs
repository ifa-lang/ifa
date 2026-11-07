use ifa_fir::{compile_to_fir, FirInterpreter, FirValue};
use ifa_lexer::tokenize;
use ifa_parser::parse;
use ifa_sema::analyze;
use ifa_span::SourceMap;

#[test]
fn test_fir_pure_lambda_execution() {
    let src = r#"
        pub fn main() -> i64 {
            let square = fn(x: i64) -> i64 {
                return x * x;
            };
            return square(9);
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("pure_lambda.ifa", src);
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
    assert_eq!(result, FirValue::Int(81));
}

#[test]
fn test_fir_closure_environment_capture() {
    let src = r#"
        pub fn main() -> i64 {
            let factor: i64 = 7;
            let multiplier = fn(x: i64) -> i64 {
                return x * factor;
            };
            return multiplier(6);
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("closure_capture.ifa", src);
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
    assert_eq!(result, FirValue::Int(42));
}

#[test]
fn test_fir_closure_multiple_captures() {
    let src = r#"
        pub fn main() -> i64 {
            let base: i64 = 100;
            let offset: i64 = 25;
            let compute = fn(factor: i64) -> i64 {
                return base + offset * factor;
            };
            return compute(3);
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("closure_multi_capture.ifa", src);
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
    assert_eq!(result, FirValue::Int(175));
}

#[test]
fn test_fir_closure_bidirectional_inference_and_inline_call() {
    let src = r#"
        pub fn main() -> i64 {
            let add_ten: fn(i64) -> i64 = fn(x) {
                return x + 10;
            };
            let a = add_ten(32);
            let b = (fn(y: i64) -> i64 { return y * 2; })(5);
            return a + b;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("closure_inference.ifa", src);
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
    assert_eq!(result, FirValue::Int(52));
}

#[test]
fn test_fir_higher_order_function_apply() {
    let src = r#"
        pub fn apply(f: fn(i64) -> i64, val: i64) -> i64 {
            return f(val);
        }

        pub fn main() -> i64 {
            let factor: i64 = 6;
            let multiplier = fn(x: i64) -> i64 {
                return x * factor;
            };
            return apply(multiplier, 7);
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("closure_apply.ifa", src);
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
    assert_eq!(result, FirValue::Int(42));
}

#[test]
fn test_fir_closure_escape_analysis_and_devirtualization() {
    let src = r#"
        pub fn apply(f: fn(i64) -> i64, val: i64) -> i64 {
            return f(val);
        }

        pub fn main() -> i64 {
            let offset: i64 = 100;
            let add_offset = fn(x: i64) -> i64 {
                return x + offset;
            };
            return apply(add_offset, 25);
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("closure_opt_test.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let mut fir_module = ifa_fir::lower_program(&prog, &analysis.symbols);
    let mut sroa = ifa_fir::SroaPass::new();
    sroa.run_on_module(&mut fir_module);

    let mut closure_pass = ifa_fir::ClosureOptPass::new();
    closure_pass.run_on_module(&mut fir_module);

    let stats = closure_pass.stats();
    assert_eq!(stats.total_closures, 1);
    assert_eq!(stats.stack_allocated_closures, 1);
    assert_eq!(stats.heap_allocated_closures, 0);
    assert!(stats.inlined_higher_order_calls >= 1);

    let mut interp = FirInterpreter::new(&fir_module);
    let result = interp.execute_function("main", vec![]).unwrap();
    assert_eq!(result, FirValue::Int(125));
}

#[test]
fn test_fir_higher_order_iterators_example() {
    let src = include_str!("../../../examples/higher_order_iterators.ifa");

    let mut sm = SourceMap::new();
    let fid = sm.add_file("higher_order_iterators.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let mut interp = FirInterpreter::new(&fir_module);
    let result = interp.execute_function("main", vec![]).unwrap();
    assert_eq!(result, FirValue::Int(82));
}

#[test]
fn test_fir_first_class_named_function_items() {
    let src = r#"
        pub fn square(x: i64) -> i64 {
            return x * x;
        }

        pub fn double_val(x: i64) -> i64 {
            return x * 2;
        }

        pub fn apply(f: fn(i64) -> i64, val: i64) -> i64 {
            return f(val);
        }

        pub fn main() -> i64 {
            let res1 = apply(square, 8); // 64
            let res2 = apply(double_val, 13); // 26
            return res1 + res2; // 90
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("named_fn_items.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let mut interp = FirInterpreter::new(&fir_module);
    let result = interp.execute_function("main", vec![]).unwrap();
    assert_eq!(result, FirValue::Int(90));
}

#[test]
fn test_fir_dynamic_function_pointer_reassignment() {
    let src = r#"
        pub fn add_ten(x: i64) -> i64 {
            return x + 10;
        }

        pub fn add_twenty(x: i64) -> i64 {
            return x + 20;
        }

        pub fn compute(cond: bool, val: i64) -> i64 {
            mut f = add_ten;
            if cond {
                f = add_twenty;
            }
            return f(val);
        }

        pub fn main() -> i64 {
            let r1 = compute(false, 5); // 15
            let r2 = compute(true, 5);  // 25
            return r1 + r2;            // 40
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("dyn_fn_reassign.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let mut interp = FirInterpreter::new(&fir_module);
    let result = interp.execute_function("main", vec![]).unwrap();
    assert_eq!(result, FirValue::Int(40));
}

#[test]
fn test_fir_monomorphic_loop_specialization_and_thunk_inlining() {
    let src = r#"
        pub fn square(x: i64) -> i64 {
            return x * x;
        }

        pub fn apply_sum(f: fn(i64) -> i64, n: i64) -> i64 {
            mut sum = 0;
            mut i = 1;
            while i <= n {
                sum = sum + f(i);
                i = i + 1;
            }
            return sum;
        }

        pub fn main() -> i64 {
            return apply_sum(square, 4); // 1 + 4 + 9 + 16 = 30
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("mono_spec.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    // Verify specialized function was generated
    let has_spec = fir_module
        .functions
        .iter()
        .any(|f| f.name.as_str().contains("apply_sum$spec_square"));
    assert!(
        has_spec,
        "Expected specialized function apply_sum$spec_square to exist in FIR module"
    );

    // Verify main calls the specialized function directly
    let main_fn = fir_module
        .functions
        .iter()
        .find(|f| f.name.as_str() == "main")
        .expect("main function must exist");
    let calls_spec = main_fn
        .blocks
        .iter()
        .flat_map(|b| &b.instructions)
        .any(|inst| {
            if let ifa_fir::ValueExpr::CallDirect { name, .. } = &inst.expr {
                name.as_str().contains("apply_sum$spec_square")
            } else {
                false
            }
        });
    assert!(calls_spec, "main must call apply_sum$spec_square directly");

    // Execute via FIR interpreter
    let mut interp = FirInterpreter::new(&fir_module);
    let result = interp.execute_function("main", vec![]).unwrap();
    assert_eq!(result, FirValue::Int(30));
}

#[test]
fn test_fir_closure_opt_stats_and_thunk_elimination() {
    let src = r#"
        pub fn cube(x: i64) -> i64 {
            return x * x * x;
        }

        pub fn transform(f: fn(i64) -> i64, val: i64) -> i64 {
            return f(val);
        }

        pub fn main() -> i64 {
            return transform(cube, 5); // 125
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("stats_test.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, diags) = parse(fid, tokens);
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);

    let analysis = analyze(&sm, &prog);
    assert!(!analysis.has_errors());

    let mut module = ifa_fir::lower_program(&prog, &analysis.symbols);
    let mut closure_pass = ifa_fir::ClosureOptPass::new();
    closure_pass.run_on_module(&mut module);

    let stats = closure_pass.stats();
    assert!(
        stats.inlined_thunk_adapters > 0,
        "Expected inlined_thunk_adapters > 0, got {}",
        stats.inlined_thunk_adapters
    );

    let mut interp = FirInterpreter::new(&module);
    let result = interp.execute_function("main", vec![]).unwrap();
    assert_eq!(result, FirValue::Int(125));
}

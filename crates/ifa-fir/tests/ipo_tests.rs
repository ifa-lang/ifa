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

#[test]
fn test_ipo_recursive_pure_graph_fibonacci() {
    let src = r#"
        pub fn fib(n: i64) -> i64 {
            if n <= 1 {
                return n;
            }
            return fib(n - 1) + fib(n - 2);
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("fib_test.ifa".to_string(), src);
    let (prog, diags) = parse(fid, tokenize(fid, src));
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let mut module =
        compile_to_fir_with_opts(&prog, &analysis.symbols, true, true, true, false).unwrap();
    let mut ipo_pass = IpoPass::new();
    ipo_pass.run_on_module(&mut module);

    let stats = ipo_pass.stats();
    assert_eq!(
        stats.pure_functions, 1,
        "fib must be proven pure inter-procedurally"
    );
    assert_eq!(
        stats.recursive_functions_detected, 1,
        "fib must be identified as self-recursive"
    );
    assert_eq!(
        stats.pure_calls_inlined_in_loops, 0,
        "Recursive function must not be inlined into loops"
    );
}

#[test]
fn test_ipo_mutually_recursive_functions_purity() {
    let src = r#"
        pub fn is_even(n: i64) -> bool {
            if n == 0 {
                return true;
            }
            return is_odd(n - 1);
        }

        pub fn is_odd(n: i64) -> bool {
            if n == 0 {
                return false;
            }
            return is_even(n - 1);
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("mutual_rec.ifa".to_string(), src);
    let (prog, diags) = parse(fid, tokenize(fid, src));
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let mut module =
        compile_to_fir_with_opts(&prog, &analysis.symbols, true, true, true, false).unwrap();
    let mut ipo_pass = IpoPass::new();
    ipo_pass.run_on_module(&mut module);

    let stats = ipo_pass.stats();
    assert_eq!(
        stats.pure_functions, 2,
        "Both mutually recursive functions must be proven pure"
    );
    assert_eq!(
        stats.recursive_functions_detected, 2,
        "Both must be detected in recursive SCC cycle"
    );
}

#[test]
fn test_ipo_recursive_with_io_marked_impure() {
    let src = r#"
        pub fn rec_with_log(n: i64) -> i64 {
            if n <= 0 {
                println("base");
                return 0;
            }
            return rec_with_log(n - 1) + 1;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("impure_rec.ifa".to_string(), src);
    let (prog, diags) = parse(fid, tokenize(fid, src));
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let mut module =
        compile_to_fir_with_opts(&prog, &analysis.symbols, true, true, true, false).unwrap();
    let mut ipo_pass = IpoPass::new();
    ipo_pass.run_on_module(&mut module);

    let stats = ipo_pass.stats();
    assert_eq!(
        stats.pure_functions, 0,
        "Recursive function with I/O in any branch must be marked impure"
    );
    assert_eq!(
        stats.recursive_functions_detected, 1,
        "Must still detect recursive structure"
    );
}

#[test]
fn test_ipo_pure_call_cse_elimination() {
    let src = r#"
        pub fn compute_hash(val: i64) -> i64 {
            return val * 31 + 7;
        }

        pub fn caller_with_redundant_calls(x: i64) -> i64 {
            let a = compute_hash(x);
            let b = compute_hash(x);
            return a + b;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("cse_test.ifa".to_string(), src);
    let (prog, diags) = parse(fid, tokenize(fid, src));
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let mut module =
        compile_to_fir_with_opts(&prog, &analysis.symbols, true, true, true, false).unwrap();
    let mut ipo_pass = IpoPass::new();
    ipo_pass.run_on_module(&mut module);

    let stats = ipo_pass.stats();
    assert!(stats.pure_functions >= 2, "Both functions are pure");
    assert!(
        stats.pure_calls_cse_eliminated >= 1,
        "Redundant pure call compute_hash(x) must be eliminated via CSE: {:?}",
        stats
    );
}

#[test]
fn test_ipo_local_stack_alloca_mutation_is_pure() {
    let src = r#"
        struct LocalPoint {
            x: f32,
            y: f32,
        }

        pub fn build_and_sum(a: f32, b: f32) -> f32 {
            mut pt = LocalPoint { x: a, y: b };
            pt.x = pt.x * 2.0;
            return pt.x + pt.y;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("local_stack.ifa".to_string(), src);
    let (prog, diags) = parse(fid, tokenize(fid, src));
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let mut module =
        compile_to_fir_with_opts(&prog, &analysis.symbols, true, true, true, false).unwrap();
    let mut ipo_pass = IpoPass::new();
    ipo_pass.run_on_module(&mut module);

    let stats = ipo_pass.stats();
    let pt_fn_sym = INTERNER.intern("build_and_sum");
    let pure_funcs = IpoPass::compute_pure_functions(&module);
    assert!(
        pure_funcs.contains(&pt_fn_sym),
        "build_and_sum mutates only local stack alloca fields and must be proven pure! Stats: {:?}",
        stats
    );
}

#[test]
fn test_ipo_strict_ffi_elevation_and_cse() {
    let src = r#"
        extern "C" strict fn c_hypot(x: f64, y: f64) -> f64;

        pub fn compute_double_dist(x: f64, y: f64) -> f64 {
            let d1 = c_hypot(x, y);
            let d2 = c_hypot(x, y);
            return d1 + d2;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("strict_ffi_cse.ifa".to_string(), src);
    let (prog, diags) = parse(fid, tokenize(fid, src));
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let mut module =
        compile_to_fir_with_opts(&prog, &analysis.symbols, true, true, true, false).unwrap();
    let call_graph = ifa_fir::IpoCallGraph::build(&module);
    let mem_map = ifa_fir::InterproceduralMemoryMap::compute(&module, &call_graph);

    let c_hypot_sym = INTERNER.intern("c_hypot");
    let caller_sym = INTERNER.intern("compute_double_dist");

    assert!(
        mem_map.is_pure(&c_hypot_sym),
        "extern 'C' strict fn c_hypot must be elevated to Pure"
    );
    assert!(
        mem_map.is_pure(&caller_sym),
        "compute_double_dist calling c_hypot must be proven Pure"
    );

    let mut ipo_pass = IpoPass::new();
    ipo_pass.run_on_module(&mut module);

    let stats = ipo_pass.stats();
    assert!(
        stats.strict_ffi_pure_functions >= 1,
        "strict_ffi_pure_functions should be >= 1, got {:?}",
        stats
    );
    assert_eq!(
        stats.pure_calls_cse_eliminated, 1,
        "Second pure call to c_hypot(x, y) must be eliminated by pure call CSE: {:?}",
        stats
    );
}

#[test]
fn test_ipo_strict_ffi_loop_vectorization_allowed() {
    let src = r#"
        extern "C" strict fn c_cos_f32(x: f32) -> f32;

        pub fn compute_cosine_table(mut data: [f32; 64]) {
            mut i = 0;
            while i < 64 {
                data[i] = c_cos_f32(data[i]);
                i = i + 1;
            }
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("strict_ffi_loop.ifa".to_string(), src);
    let (prog, diags) = parse(fid, tokenize(fid, src));
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    // Full optimization with vectorization enabled
    let module =
        compile_to_fir_with_opts(&prog, &analysis.symbols, true, true, true, true).unwrap();
    let c_cos_sym = INTERNER.intern("c_cos_f32");
    let pure_funcs = IpoPass::compute_pure_functions(&module);
    assert!(
        pure_funcs.contains(&c_cos_sym),
        "c_cos_f32 must be in pure_funcs set"
    );

    // Find the caller function in FIR
    let caller_func = module
        .functions
        .iter()
        .find(|f| INTERNER.resolve(&f.name) == "compute_cosine_table")
        .expect("compute_cosine_table must exist in FIR module");

    // Verify it contains Vectorize hints and preserved calls
    let formatted = format_function(caller_func);
    assert!(
        formatted.contains("c_cos_f32"),
        "Function must preserve strict pure FFI call: {}",
        formatted
    );
}

#[test]
fn test_ipo_non_strict_ffi_remains_impure() {
    let src = r#"
        extern "C" fn c_impure_log(val: i64);

        pub fn my_logger(x: i64) {
            c_impure_log(x);
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("impure_ffi.ifa".to_string(), src);
    let (prog, diags) = parse(fid, tokenize(fid, src));
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module =
        compile_to_fir_with_opts(&prog, &analysis.symbols, true, true, true, false).unwrap();
    let call_graph = ifa_fir::IpoCallGraph::build(&module);
    let mem_map = ifa_fir::InterproceduralMemoryMap::compute(&module, &call_graph);

    let log_sym = INTERNER.intern("c_impure_log");
    let caller_sym = INTERNER.intern("my_logger");

    assert_eq!(
        mem_map.get_summary(&log_sym).map(|s| s.effect),
        Some(ifa_fir::MemoryEffect::Arbitrary),
        "Non-strict extern C must have Arbitrary memory effect"
    );
    assert_eq!(
        mem_map.get_summary(&caller_sym).map(|s| s.effect),
        Some(ifa_fir::MemoryEffect::Arbitrary),
        "Caller of non-strict extern C must inherit Arbitrary effect"
    );
}

#[test]
fn test_ipo_colorless_coroutine_in_place_specialization() {
    use ifa_fir::{BlockId, FirFunction, FirModule, FirType, Instruction, Terminator, ValueExpr};
    use ifa_span::Span;

    let mut module = FirModule::new(INTERNER.intern("test_coro_spec_mod"));

    // 1. Define a coroutine function that performs cooperative yields
    let coro_name = INTERNER.intern("stream_worker");
    let mut coro_func = FirFunction::new(
        coro_name,
        vec![],
        FirType::Int(ifa_sema::types::IntType::I64),
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );
    let ret_val = coro_func.alloc_value();
    let b0 = BlockId(0);
    let bb0 = coro_func.get_block_mut(b0).unwrap();
    bb0.push_instruction(Instruction::new(None, ValueExpr::Yield, Span::DUMMY));
    bb0.push_instruction(Instruction::new(
        Some(ret_val),
        ValueExpr::Constant(ifa_fir::ConstantValue::Int(
            42,
            ifa_sema::types::IntType::I64,
        )),
        Span::DUMMY,
    ));
    bb0.set_terminator(Terminator::Return(Some(ret_val)));
    assert!(coro_func.is_coroutine());
    module.functions.push(coro_func);

    // 2. Define a caller that directly invokes the coroutine synchronously via CallDirect
    let caller_name = INTERNER.intern("sync_caller");
    let mut caller_func = FirFunction::new(
        caller_name,
        vec![],
        FirType::Int(ifa_sema::types::IntType::I64),
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );
    let call_res = caller_func.alloc_value();
    let cb0 = BlockId(0);
    let cbb0 = caller_func.get_block_mut(cb0).unwrap();
    cbb0.push_instruction(Instruction::new(
        Some(call_res),
        ValueExpr::CallDirect {
            name: coro_name,
            args: vec![],
        },
        Span::DUMMY,
    ));
    cbb0.set_terminator(Terminator::Return(Some(call_res)));
    module.functions.push(caller_func);

    // Run IPO pass
    let mut ipo_pass = IpoPass::new();
    ipo_pass.run_on_module(&mut module);

    assert_eq!(ipo_pass.stats().coroutines_specialized_sync, 1);
    assert_eq!(ipo_pass.stats().direct_coroutine_calls_specialized, 1);

    // The coroutine must have been specialized in place into a synchronous function
    let target = module
        .functions
        .iter()
        .find(|f| f.name == coro_name)
        .unwrap();
    assert!(!target.is_coroutine());
    let has_yield = target.blocks.iter().any(|b| {
        b.instructions
            .iter()
            .any(|i| matches!(i.expr, ValueExpr::Yield | ValueExpr::YieldValue { .. }))
    });
    assert!(
        !has_yield,
        "Yield instructions must be replaced with ifa_rt_fiber_yield"
    );
}

#[test]
fn test_ipo_colorless_coroutine_cloned_variant_specialization() {
    use ifa_fir::{BlockId, FirFunction, FirModule, FirType, Instruction, Terminator, ValueExpr};
    use ifa_span::Span;

    let mut module = FirModule::new(INTERNER.intern("test_coro_dual_mod"));

    // 1. Define a coroutine function
    let coro_name = INTERNER.intern("hybrid_task");
    let mut coro_func = FirFunction::new(
        coro_name,
        vec![],
        FirType::Int(ifa_sema::types::IntType::I64),
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );
    let ret_val = coro_func.alloc_value();
    let b0 = BlockId(0);
    let bb0 = coro_func.get_block_mut(b0).unwrap();
    bb0.push_instruction(Instruction::new(None, ValueExpr::Yield, Span::DUMMY));
    bb0.push_instruction(Instruction::new(
        Some(ret_val),
        ValueExpr::Constant(ifa_fir::ConstantValue::Int(
            100,
            ifa_sema::types::IntType::I64,
        )),
        Span::DUMMY,
    ));
    bb0.set_terminator(Terminator::Return(Some(ret_val)));
    assert!(coro_func.is_coroutine());
    module.functions.push(coro_func);

    // 2. Caller A spawns the coroutine asynchronously
    let async_caller_name = INTERNER.intern("async_launcher");
    let mut async_caller = FirFunction::new(
        async_caller_name,
        vec![],
        FirType::Unit,
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );
    let spawn_res = async_caller.alloc_value();
    let ab0 = async_caller.get_block_mut(BlockId(0)).unwrap();
    ab0.push_instruction(Instruction::new(
        Some(spawn_res),
        ValueExpr::Spawn {
            target: coro_name,
            args: vec![],
        },
        Span::DUMMY,
    ));
    ab0.set_terminator(Terminator::Return(None));
    module.functions.push(async_caller);

    // 3. Caller B directly calls the coroutine synchronously
    let sync_caller_name = INTERNER.intern("direct_caller");
    let mut sync_caller = FirFunction::new(
        sync_caller_name,
        vec![],
        FirType::Int(ifa_sema::types::IntType::I64),
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );
    let direct_call_res = sync_caller.alloc_value();
    let sb0 = sync_caller.get_block_mut(BlockId(0)).unwrap();
    sb0.push_instruction(Instruction::new(
        Some(direct_call_res),
        ValueExpr::CallDirect {
            name: coro_name,
            args: vec![],
        },
        Span::DUMMY,
    ));
    sb0.set_terminator(Terminator::Return(Some(direct_call_res)));
    module.functions.push(sync_caller);

    // Run IPO pass
    let mut ipo_pass = IpoPass::new();
    ipo_pass.run_on_module(&mut module);

    assert_eq!(ipo_pass.stats().coroutines_specialized_sync, 1);
    assert_eq!(ipo_pass.stats().direct_coroutine_calls_specialized, 1);

    // The original function must remain a coroutine for async spawn
    let orig = module
        .functions
        .iter()
        .find(|f| f.name == coro_name)
        .unwrap();
    assert!(orig.is_coroutine());

    // A specialized sync clone must have been created
    let sync_clone_name = INTERNER.intern("hybrid_task_direct_sync");
    let clone_opt = module.functions.iter().find(|f| f.name == sync_clone_name);
    assert!(clone_opt.is_some(), "Specialized sync clone must exist");
    let clone = clone_opt.unwrap();
    assert!(!clone.is_coroutine());

    // The direct caller must have been retargeted to the specialized sync clone
    let updated_sync_caller = module
        .functions
        .iter()
        .find(|f| f.name == sync_caller_name)
        .unwrap();
    let called_target = updated_sync_caller.blocks[0]
        .instructions
        .iter()
        .find_map(|i| {
            if let ValueExpr::CallDirect { name, .. } = &i.expr {
                Some(*name)
            } else {
                None
            }
        });
    assert_eq!(called_target, Some(sync_clone_name));
}

#[test]
fn test_interprocedural_symbolic_constant_propagation_sliding_window() {
    use ifa_fir::types::FirType;
    use ifa_fir::{
        BasicBlock, BinaryOp, BlockId, ConstantValue, FirFunction, FirModule, FirParam,
        Instruction, Terminator, ValueExpr,
    };
    use ifa_sema::types::IntType;
    use ifa_span::Span;

    let callee_name = INTERNER.intern("convolve_1d_baremetal");
    let caller_name = INTERNER.intern("caller_pipeline");

    let f32_slice = FirType::Slice(Box::new(FirType::Float(ifa_sema::types::FloatType::F32)));
    let i64_ty = FirType::Int(IntType::I64);

    // callee: convolve_1d_baremetal(sig: [f32], kern: [f32], window_size: i64) -> f32
    let mut f_callee = FirFunction::new(
        callee_name,
        Vec::new(),
        FirType::Float(ifa_sema::types::FloatType::F32),
        false,
        true, // strict bare-metal mode
        false,
        None,
        Span::DUMMY,
    );

    let p_sig = f_callee.alloc_value();
    let p_kern = f_callee.alloc_value();
    let p_w = f_callee.alloc_value();

    f_callee.params.push(FirParam {
        name: INTERNER.intern("sig"),
        ty: f32_slice.clone(),
        val: p_sig,
        mode: ifa_ast::ParamMode::In,
    });
    f_callee.params.push(FirParam {
        name: INTERNER.intern("kern"),
        ty: f32_slice.clone(),
        val: p_kern,
        mode: ifa_ast::ParamMode::In,
    });
    f_callee.params.push(FirParam {
        name: INTERNER.intern("window_size"),
        ty: i64_ty.clone(),
        val: p_w,
        mode: ifa_ast::ParamMode::In,
    });

    let bb_entry = f_callee.entry_block;
    let bb_header = BlockId(1);
    let bb_body = BlockId(2);
    let bb_exit = BlockId(3);

    f_callee.blocks.push(BasicBlock::new(bb_header));
    f_callee.blocks.push(BasicBlock::new(bb_body));
    f_callee.blocks.push(BasicBlock::new(bb_exit));

    // Entry jumps to loop header
    let v_k_init = f_callee.alloc_value();
    let v_acc_init = f_callee.alloc_value();
    let entry_mut = f_callee.get_block_mut(bb_entry).unwrap();
    entry_mut.push_instruction(Instruction::new(
        Some(v_k_init),
        ValueExpr::Constant(ConstantValue::Int(0, IntType::I64)),
        Span::DUMMY,
    ));
    entry_mut.push_instruction(Instruction::new(
        Some(v_acc_init),
        ValueExpr::Constant(ConstantValue::Float(0.0, ifa_sema::types::FloatType::F32)),
        Span::DUMMY,
    ));
    entry_mut.set_terminator(Terminator::Branch {
        target: bb_header,
        args: vec![],
    });

    // Header: check k < window_size
    let v_cond = f_callee.alloc_value();
    let header_mut = f_callee.get_block_mut(bb_header).unwrap();
    header_mut.push_instruction(Instruction::new(
        Some(v_cond),
        ValueExpr::Binary {
            op: BinaryOp::Lt,
            lhs: v_k_init,
            rhs: p_w,
        },
        Span::DUMMY,
    ));
    header_mut.set_terminator(Terminator::BranchCond {
        cond: v_cond,
        then_block: bb_body,
        then_args: vec![],
        else_block: bb_exit,
        else_args: vec![],
    });

    // Body: index = i + k, bounds_check on index, read sig[index] and kern[k], multiply and add
    let v_idx = f_callee.alloc_value();
    let v_sig_val = f_callee.alloc_value();
    let v_kern_val = f_callee.alloc_value();
    let v_prod = f_callee.alloc_value();
    let v_acc_next = f_callee.alloc_value();
    let body_mut = f_callee.get_block_mut(bb_body).unwrap();
    body_mut.push_instruction(Instruction::new(
        Some(v_idx),
        ValueExpr::Binary {
            op: BinaryOp::Add,
            lhs: v_k_init,
            rhs: v_k_init,
        },
        Span::DUMMY,
    ));
    body_mut.push_instruction(Instruction::new(
        None,
        ValueExpr::BoundsCheck {
            base: p_sig,
            index: v_idx,
            redundant: false,
        },
        Span::DUMMY,
    ));
    body_mut.push_instruction(Instruction::new(
        Some(v_sig_val),
        ValueExpr::GetElement {
            base: p_sig,
            index: v_idx,
        },
        Span::DUMMY,
    ));
    body_mut.push_instruction(Instruction::new(
        Some(v_kern_val),
        ValueExpr::GetElement {
            base: p_kern,
            index: v_k_init,
        },
        Span::DUMMY,
    ));
    body_mut.push_instruction(Instruction::new(
        Some(v_prod),
        ValueExpr::Binary {
            op: BinaryOp::Mul,
            lhs: v_sig_val,
            rhs: v_kern_val,
        },
        Span::DUMMY,
    ));
    body_mut.push_instruction(Instruction::new(
        Some(v_acc_next),
        ValueExpr::Binary {
            op: BinaryOp::Add,
            lhs: v_acc_init,
            rhs: v_prod,
        },
        Span::DUMMY,
    ));
    // Latch jumps back to header
    body_mut.set_terminator(Terminator::Branch {
        target: bb_header,
        args: vec![],
    });

    // Exit returns acc
    let exit_mut = f_callee.get_block_mut(bb_exit).unwrap();
    exit_mut.set_terminator(Terminator::Return(Some(v_acc_init)));

    // Caller: calls convolve_1d_baremetal(sig, kern, 3)
    let mut f_caller = FirFunction::new(
        caller_name,
        Vec::new(),
        FirType::Float(ifa_sema::types::FloatType::F32),
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );
    let c_e = f_caller.entry_block;
    let v_c_sig = f_caller.alloc_value();
    let v_c_kern = f_caller.alloc_value();
    let v_c_w = f_caller.alloc_value();
    let v_res = f_caller.alloc_value();
    let c_entry = f_caller.get_block_mut(c_e).unwrap();
    c_entry.push_instruction(Instruction::new(
        Some(v_c_w),
        ValueExpr::Constant(ConstantValue::Int(3, IntType::I64)),
        Span::DUMMY,
    ));
    c_entry.push_instruction(Instruction::new(
        Some(v_res),
        ValueExpr::CallDirect {
            name: callee_name,
            args: vec![v_c_sig, v_c_kern, v_c_w],
        },
        Span::DUMMY,
    ));
    c_entry.set_terminator(Terminator::Return(Some(v_res)));

    let mut module = FirModule {
        name: INTERNER.intern("test_conv_mod"),
        structs: Vec::new(),
        enums: Vec::new(),
        constants: Vec::new(),
        functions: vec![f_callee, f_caller],
    };

    let mut ipo_pass = IpoPass::new();
    ipo_pass.run_on_module(&mut module);

    let stats = ipo_pass.stats();
    assert!(
        stats.interprocedural_constants_propagated >= 1,
        "window_size = 3 must be propagated inter-procedurally: {:?}",
        stats
    );
    assert!(
        stats.sliding_windows_specialized >= 1,
        "Sliding window must be specialized: {:?}",
        stats
    );
    assert!(
        stats.convolutions_vectorized >= 1,
        "Convolution loop must be vectorized: {:?}",
        stats
    );
    assert!(
        stats.sliding_window_bounds_eliminated >= 1,
        "Redundant BoundsCheck in convolution stencil must be eliminated: {:?}",
        stats
    );

    // Verify optimized callee function
    let opt_callee = module
        .functions
        .iter()
        .find(|f| f.name == callee_name)
        .unwrap();

    // Check that entry block has a Constant instruction with value 3
    let has_const_3 = opt_callee.blocks[0].instructions.iter().any(|i| {
        matches!(
            i.expr,
            ValueExpr::Constant(ConstantValue::Int(3, IntType::I64))
        )
    });
    assert!(
        has_const_3,
        "Entry block must contain propagated constant 3"
    );

    // Check that body has redundant = true on BoundsCheck
    let bounds_check_redundant = opt_callee.blocks.iter().any(|b| {
        b.instructions.iter().any(|i| {
            matches!(
                i.expr,
                ValueExpr::BoundsCheck {
                    redundant: true,
                    ..
                }
            )
        })
    });
    assert!(
        bounds_check_redundant,
        "BoundsCheck in convolution loop must be redundant"
    );

    // Check that loop header has LoopVectorHint with sliding_window_size: Some(3)
    let header_hint = opt_callee
        .blocks
        .iter()
        .find_map(|b| b.vector_hint)
        .expect("LoopVectorHint must be present");

    assert_eq!(header_hint.sliding_window_size, Some(3));
    assert!(header_hint.is_convolution);
    assert!(header_hint.unroll_enable);
    assert!(header_hint.contiguous_reduction);
    assert!(header_hint.disjoint_slices);
}

#[test]
fn test_polymorphic_sliding_window_specialization() {
    use ifa_fir::types::FirType;
    use ifa_fir::{
        BasicBlock, BinaryOp, BlockId, ConstantValue, FirFunction, FirModule, FirParam,
        Instruction, Terminator, ValueExpr,
    };
    use ifa_sema::types::IntType;
    use ifa_span::Span;

    let callee_name = INTERNER.intern("sliding_filter");
    let caller1_name = INTERNER.intern("pipeline_fast");
    let caller2_name = INTERNER.intern("pipeline_deep");

    let f32_slice = FirType::Slice(Box::new(FirType::Float(ifa_sema::types::FloatType::F32)));
    let i64_ty = FirType::Int(IntType::I64);

    let mut f_callee = FirFunction::new(
        callee_name,
        Vec::new(),
        FirType::Float(ifa_sema::types::FloatType::F32),
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );
    let p_sig = f_callee.alloc_value();
    let p_w = f_callee.alloc_value();
    f_callee.params.push(FirParam {
        name: INTERNER.intern("sig"),
        ty: f32_slice.clone(),
        val: p_sig,
        mode: ifa_ast::ParamMode::In,
    });
    f_callee.params.push(FirParam {
        name: INTERNER.intern("window_size"),
        ty: i64_ty.clone(),
        val: p_w,
        mode: ifa_ast::ParamMode::In,
    });

    let bb_entry = f_callee.entry_block;
    let bb_loop = BlockId(1);
    let bb_exit = BlockId(2);
    f_callee.blocks.push(BasicBlock::new(bb_loop));
    f_callee.blocks.push(BasicBlock::new(bb_exit));

    let entry_mut = f_callee.get_block_mut(bb_entry).unwrap();
    entry_mut.set_terminator(Terminator::Branch {
        target: bb_loop,
        args: vec![],
    });

    let v_k = f_callee.alloc_value();
    let v_cond = f_callee.alloc_value();
    let loop_mut = f_callee.get_block_mut(bb_loop).unwrap();
    loop_mut.push_instruction(Instruction::new(
        Some(v_k),
        ValueExpr::Constant(ConstantValue::Int(0, IntType::I64)),
        Span::DUMMY,
    ));
    loop_mut.push_instruction(Instruction::new(
        Some(v_cond),
        ValueExpr::Binary {
            op: BinaryOp::Lt,
            lhs: v_k,
            rhs: p_w,
        },
        Span::DUMMY,
    ));
    loop_mut.set_terminator(Terminator::BranchCond {
        cond: v_cond,
        then_block: bb_loop,
        then_args: vec![],
        else_block: bb_exit,
        else_args: vec![],
    });

    let exit_mut = f_callee.get_block_mut(bb_exit).unwrap();
    exit_mut.set_terminator(Terminator::Return(None));

    // Caller 1 calls with window_size = 3
    let mut f_caller1 = FirFunction::new(
        caller1_name,
        Vec::new(),
        FirType::Unit,
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );
    let c1_e = f_caller1.entry_block;
    let v_w3 = f_caller1.alloc_value();
    let c1_bb = f_caller1.get_block_mut(c1_e).unwrap();
    c1_bb.push_instruction(Instruction::new(
        Some(v_w3),
        ValueExpr::Constant(ConstantValue::Int(3, IntType::I64)),
        Span::DUMMY,
    ));
    c1_bb.push_instruction(Instruction::new(
        None,
        ValueExpr::CallDirect {
            name: callee_name,
            args: vec![v_w3, v_w3],
        },
        Span::DUMMY,
    ));
    c1_bb.set_terminator(Terminator::Return(None));

    // Caller 2 calls with window_size = 5
    let mut f_caller2 = FirFunction::new(
        caller2_name,
        Vec::new(),
        FirType::Unit,
        false,
        true,
        false,
        None,
        Span::DUMMY,
    );
    let c2_e = f_caller2.entry_block;
    let v_w5 = f_caller2.alloc_value();
    let c2_bb = f_caller2.get_block_mut(c2_e).unwrap();
    c2_bb.push_instruction(Instruction::new(
        Some(v_w5),
        ValueExpr::Constant(ConstantValue::Int(5, IntType::I64)),
        Span::DUMMY,
    ));
    c2_bb.push_instruction(Instruction::new(
        None,
        ValueExpr::CallDirect {
            name: callee_name,
            args: vec![v_w5, v_w5],
        },
        Span::DUMMY,
    ));
    c2_bb.set_terminator(Terminator::Return(None));

    let mut module = FirModule {
        name: INTERNER.intern("test_poly_window_mod"),
        structs: Vec::new(),
        enums: Vec::new(),
        constants: Vec::new(),
        functions: vec![f_callee, f_caller1, f_caller2],
    };

    let mut ipo_pass = IpoPass::new();
    ipo_pass.run_on_module(&mut module);

    // Verify that specialized clones sliding_filter_w3 and sliding_filter_w5 were created
    let w3_sym = INTERNER.intern("sliding_filter_w3");
    let w5_sym = INTERNER.intern("sliding_filter_w5");

    assert!(
        module.functions.iter().any(|f| f.name == w3_sym),
        "Specialized clone sliding_filter_w3 must exist"
    );
    assert!(
        module.functions.iter().any(|f| f.name == w5_sym),
        "Specialized clone sliding_filter_w5 must exist"
    );

    // Verify retargeting in caller 1
    let c1 = module
        .functions
        .iter()
        .find(|f| f.name == caller1_name)
        .unwrap();
    let c1_target = c1.blocks[0].instructions.iter().find_map(|i| {
        if let ValueExpr::CallDirect { name, .. } = &i.expr {
            Some(*name)
        } else {
            None
        }
    });
    assert_eq!(
        c1_target,
        Some(w3_sym),
        "Caller 1 must be retargeted to sliding_filter_w3"
    );

    // Verify retargeting in caller 2
    let c2 = module
        .functions
        .iter()
        .find(|f| f.name == caller2_name)
        .unwrap();
    let c2_target = c2.blocks[0].instructions.iter().find_map(|i| {
        if let ValueExpr::CallDirect { name, .. } = &i.expr {
            Some(*name)
        } else {
            None
        }
    });
    assert_eq!(
        c2_target,
        Some(w5_sym),
        "Caller 2 must be retargeted to sliding_filter_w5"
    );
}

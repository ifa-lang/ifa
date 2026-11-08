use ifa_fir::printer::format_function;
use ifa_fir::{compile_to_fir, lower_program, FirInterpreter, FirValue, LicmPass, LoopOptPass};

#[test]
fn test_nested_matrix_inter_loop_hoisting_and_tiling() {
    let src = r#"
        pub fn matrix_scale_2d(n: i64, factor: i64) -> i64 {
            mut acc = 0;
            mut i = 0;
            while i < n {
                mut j = 0;
                while j < n {
                    acc = acc + factor * 2;
                    j = j + 1;
                }
                i = i + 1;
            }
            return acc;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("matrix_scale.ifa", src);
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

    let mut loop_opt = LoopOptPass::new();
    loop_opt.run_on_module(&mut module);

    let licm_stats = licm.stats();
    assert!(
        licm_stats.total_hoisted() >= 1,
        "Invariant factor computation must be hoisted: {:?}",
        licm_stats
    );
    assert!(
        licm_stats.inter_loop_hoisted >= 1,
        "Multi-level inter-loop hoisting must occur: {:?}",
        licm_stats
    );

    let func = module
        .functions
        .iter()
        .find(|f| ifa_span::INTERNER.resolve(&f.name) == "matrix_scale_2d")
        .expect("matrix_scale_2d must exist");

    let formatted = format_function(func);
    assert!(
        !formatted.is_empty(),
        "Formatted function must not be empty"
    );

    // Verify execution fidelity in interpreter: (4 * 4) * (5 * 2) = 16 * 10 = 160
    let mut interp = FirInterpreter::new(&module);
    let res = interp
        .execute_function("matrix_scale_2d", vec![FirValue::Int(4), FirValue::Int(5)])
        .unwrap();
    assert_eq!(res, FirValue::Int(160));
}

#[test]
fn test_3d_tensor_contraction_inter_loop_hoisting_and_kernel_tiling() {
    let src = r#"
        struct TensorBuffer {
            multiplier: i64,
        }

        pub fn tensor_contract_3d(buf: ref TensorBuffer, dim_m: i64, dim_n: i64, dim_k: i64) -> i64 {
            mut total = 0;
            mut i = 0;
            while i < dim_m {
                mut j = 0;
                while j < dim_n {
                    mut k = 0;
                    while k < dim_k {
                        total = total + buf.multiplier;
                        k = k + 1;
                    }
                    j = j + 1;
                }
                i = i + 1;
            }
            return total;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("tensor_contract.ifa", src);
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
        stats.inter_loop_hoisted >= 1,
        "Tensor projection must be hoisted across 3 loop levels: {:?}",
        stats
    );
    assert!(
        stats.matrix_kernels_hoisted >= 1,
        "Matrix / tensor kernel projection must be identified: {:?}",
        stats
    );

    // Verify execution in interpreter: 2 * 3 * 4 * 7 = 168
    let mut interp = FirInterpreter::new(&module);
    let buf_obj = FirValue::Struct {
        name: ifa_span::INTERNER.intern("TensorBuffer"),
        fields: vec![FirValue::Int(7)],
    };

    let res = interp
        .execute_function(
            "tensor_contract_3d",
            vec![
                buf_obj,
                FirValue::Int(2),
                FirValue::Int(3),
                FirValue::Int(4),
            ],
        )
        .unwrap();
    assert_eq!(res, FirValue::Int(168));
}

#[test]
fn test_adjacent_loop_fusion_with_intermediate_buffer_elimination() {
    let src = r#"
        pub fn pipeline_transform(n: i64) -> [i64; 4] {
            mut temp: [i64; 4] = [0, 0, 0, 0];
            mut out_val: [i64; 4] = [0, 0, 0, 0];

            mut i = 0;
            while i < 4 {
                temp[i] = i * 3;
                i = i + 1;
            }

            mut j = 0;
            while j < 4 {
                out_val[j] = temp[j] + 7;
                j = j + 1;
            }

            return out_val;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("pipeline_fusion.ifa", src);
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

    let mut loop_opt = LoopOptPass::new();
    loop_opt.run_on_module(&mut module);

    let stats = loop_opt.stats();
    assert!(
        stats.loops_fused >= 1,
        "Adjacent streaming loops must be fused: {:?}",
        stats
    );
    assert!(
        stats.intermediate_arena_buffers_eliminated >= 1,
        "Intermediate array element writes must be eliminated: {:?}",
        stats
    );

    // Verify SSA invariants after fusion
    ifa_fir::FirVerifier::verify_module(&module).expect("Module must verify after loop fusion");

    // Verify execution in interpreter
    let mut interp = FirInterpreter::new(&module);
    let res = interp
        .execute_function("pipeline_transform", vec![FirValue::Int(4)])
        .unwrap();

    // Expected: out_val[k] = (k * 3) + 7:
    // k=0: 7, k=1: 10, k=2: 13, k=3: 16
    let expected = FirValue::Array(vec![
        FirValue::Int(7),
        FirValue::Int(10),
        FirValue::Int(13),
        FirValue::Int(16),
    ]);
    assert_eq!(res, expected);
}

#[test]
fn test_strict_zero_heap_matrix_kernel_tiling_and_compilation() {
    let src = r#"
        pub strict fn matrix_tile_dot(scale: i64, n: i64) -> i64 {
            mut acc = 0;
            mut i = 0;
            while i < n {
                mut j = 0;
                while j < n {
                    acc = acc + scale;
                    j = j + 1;
                }
                i = i + 1;
            }
            return acc;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("matrix_strict_tile.ifa", src);
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
        .find(|f| ifa_span::INTERNER.resolve(&f.name) == "matrix_tile_dot")
        .expect("matrix_tile_dot must exist");

    assert!(func.is_strict, "Function must preserve strict determinism");

    let mut interp = FirInterpreter::new(&module);
    let res = interp
        .execute_function("matrix_tile_dot", vec![FirValue::Int(3), FirValue::Int(6)])
        .unwrap();
    // 3 * (6 * 6) = 3 * 36 = 108
    assert_eq!(res, FirValue::Int(108));
}

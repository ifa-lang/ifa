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

#[test]
fn test_multi_arena_matrix_kernel_adaptive_cache_tiling_and_elementwise_fusion() {
    let src = r#"
        pub strict fn tensor_gemm_bias_scale(dim: i64, factor: i64) -> i64 {
            mut acc = 0;
            mut i = 0;
            while i < dim {
                mut j = 0;
                while j < dim {
                    acc = acc + factor * 3;
                    j = j + 1;
                }
                i = i + 1;
            }
            return acc;
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("gemm_bias_scale.ifa", src);
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
    let mut sroa = ifa_fir::SroaPass::new();
    sroa.run_on_module(&mut module);

    let mut loop_opt = LoopOptPass::new();
    loop_opt.run_on_module(&mut module);

    let stats = loop_opt.stats();
    assert!(
        stats.matrix_kernels_tiled >= 1,
        "Matrix kernels must be tiled: {:?}",
        stats
    );
    assert!(
        stats.tensor_loops_optimized >= 1,
        "Tensor loops must be optimized: {:?}",
        stats
    );
    assert!(
        stats.adaptive_tiles_computed >= 1,
        "Adaptive cache tile sizes must be computed: {:?}",
        stats
    );
    assert!(
        stats.multi_arena_kernels_specialized >= 1,
        "Multi-arena kernel specialization must be identified: {:?}",
        stats
    );
    assert!(
        stats.elementwise_fusions >= 1,
        "Elementary operations (bias/scale) must be fused: {:?}",
        stats
    );

    let func = module
        .functions
        .iter()
        .find(|f| ifa_span::INTERNER.resolve(&f.name) == "tensor_gemm_bias_scale")
        .expect("tensor_gemm_bias_scale must exist");

    // Verify outer loop header vector hint
    let mut found_hint = false;
    for block in &func.blocks {
        if let Some(hint) = &block.vector_hint {
            if hint.is_matrix_kernel && hint.is_tiled {
                assert!(hint.is_multi_arena_matrix, "Must be tagged multi-arena");
                assert!(
                    hint.is_elementwise_fused,
                    "Must be tagged elementwise fused"
                );
                assert!(
                    hint.adaptive_tile_size.is_some(),
                    "Adaptive tile size must be attached"
                );
                found_hint = true;
                break;
            }
        }
    }
    assert!(
        found_hint,
        "Tiled vector hint with adaptive tiling must be attached to loop header"
    );

    let mut interp = FirInterpreter::new(&module);
    let res = interp
        .execute_function(
            "tensor_gemm_bias_scale",
            vec![FirValue::Int(4), FirValue::Int(2)],
        )
        .unwrap();
    // (4 * 4) * (2 * 3) = 16 * 6 = 96
    assert_eq!(res, FirValue::Int(96));
}

#[test]
fn test_multi_arena_convolution_nest_specialization_and_hints() {
    let src = r#"
        pub strict fn conv2d_pipeline_nest(
            inout out: Slice<f32>,
            img: Slice<f32>,
            weights: Slice<f32>,
            h_out: i64,
            w_out: i64,
            stride: i64
        ) {
            mut y = 0;
            while y < h_out {
                mut x = 0;
                while x < w_out {
                    let in_idx = (y * stride) * w_out + (x * stride);
                    let out_idx = y * w_out + x;
                    out[out_idx] = out[out_idx] + img[in_idx] * weights[0] + 1.0;
                    x = x + 1;
                }
                y = y + 1;
            }
        }
    "#;

    let mut sm = ifa_span::SourceMap::new();
    let fid = sm.add_file("conv2d_nest.ifa", src);
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
        stats.multi_arena_conv_nests_optimized >= 1,
        "Multi-arena convolution nest must be optimized: {:?}",
        stats
    );

    let func = module
        .functions
        .iter()
        .find(|f| ifa_span::INTERNER.resolve(&f.name) == "conv2d_pipeline_nest")
        .expect("conv2d_pipeline_nest must exist");

    let header_hint = func
        .blocks
        .iter()
        .find_map(|b| b.vector_hint.filter(|h| h.is_multi_arena_conv));
    assert!(
        header_hint.is_some(),
        "Loop nest must have multi-arena conv vector hint"
    );
    let h = header_hint.unwrap();
    assert!(h.is_strided_conv2d, "Must be tagged strided 2D convolution");
    assert!(h.conv_has_bias, "Must detect bias addition");
    assert!(h.disjoint_slices, "Must have disjoint slices enabled");
}

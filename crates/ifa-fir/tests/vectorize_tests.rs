use ifa_fir::{
    compile_to_fir, format_function, BasicBlock, BinaryOp, BlockId, ConstantValue, FirFunction,
    FirParam, FirType, Instruction, ParamMode, Terminator, ValueExpr, ValueId, VectorizePass,
};
use ifa_lexer::tokenize;
use ifa_parser::parse;
use ifa_sema::analyze;
use ifa_sema::types::IntType;
use ifa_span::{SourceMap, Span, INTERNER};

#[test]
fn test_vectorize_pass_array_sum_f32() {
    let src = r#"
        pub fn sum_f32(arr: [f32; 64]) -> f32 {
            let mut acc: f32 = 0.0;
            for x in arr {
                acc = acc + x;
            }
            return acc;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("vec_f32.ifa".to_string(), src);
    let (prog, _) = parse(fid, tokenize(fid, src));
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let func = &module.functions[0];

    // Verify vectorization hint is attached in printer representation
    let formatted = format_function(func);
    assert!(
        formatted.contains("// [vector_hint: width=8, interleave=4]"),
        "Formatted FIR:\n{}",
        formatted
    );

    let mut pass = VectorizePass::new();
    let mut mod_clone = module.clone();
    pass.run_on_module(&mut mod_clone);

    let stats = pass.stats();
    assert_eq!(stats.loops_analyzed, 1);
    assert_eq!(stats.loops_vectorized, 1);
    assert!(stats.arrays_vectorized >= 1);
}

#[test]
fn test_vectorize_pass_slice_f64() {
    let src = r#"
        pub fn dot_f64(arr: [f64; 128]) -> f64 {
            let mut sum: f64 = 0.0;
            for x in arr {
                sum = sum + x;
            }
            return sum;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("vec_f64.ifa".to_string(), src);
    let (prog, _) = parse(fid, tokenize(fid, src));
    let analysis = analyze(&sm, &prog);
    assert!(!analysis.has_errors());

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let func = &module.functions[0];
    let formatted = format_function(func);
    assert!(formatted.contains("// [vector_hint: width=4, interleave=4]"));
}

#[test]
fn test_vectorize_pass_u8_crypto_bytes() {
    let src = r#"
        pub fn xor_bytes(buf: [u8; 32]) -> u8 {
            let mut acc: u8 = 0;
            for b in buf {
                acc = acc ^ b;
            }
            return acc;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("vec_u8.ifa".to_string(), src);
    let (prog, _) = parse(fid, tokenize(fid, src));
    let analysis = analyze(&sm, &prog);
    assert!(!analysis.has_errors());

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let func = &module.functions[0];
    let formatted = format_function(func);
    assert!(formatted.contains("// [vector_hint: width=16, interleave=4]"));
}

#[test]
fn test_vectorize_pass_impure_loop_rejected() {
    let src = r#"
        pub fn impure_loop(arr: [f32; 10]) -> () {
            for x in arr {
                println("side effect");
            }
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("impure.ifa".to_string(), src);
    let (prog, _) = parse(fid, tokenize(fid, src));
    let analysis = analyze(&sm, &prog);
    assert!(!analysis.has_errors());

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let func = &module.functions[0];
    let formatted = format_function(func);
    // Impure loops must not receive SIMD vector hints
    assert!(!formatted.contains("[vector_hint:"));
}

#[test]
fn test_vectorize_pass_array_map_transform_f32() {
    let src = r#"
        pub fn map_scale(mut arr: [f32; 64], factor: f32) -> [f32; 64] {
            let mut i: i64 = 0;
            while i < 64 {
                arr[i] = arr[i] * factor;
                i = i + 1;
            }
            return arr;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("map_scale.ifa".to_string(), src);
    let (prog, _) = parse(fid, tokenize(fid, src));
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let func = &module.functions[0];
    let formatted = format_function(func);
    assert!(
        formatted.contains("// [vector_hint: width=8, interleave=4]"),
        "Formatted FIR:\n{}",
        formatted
    );

    let mut pass = VectorizePass::new();
    let mut mod_clone = module.clone();
    pass.run_on_module(&mut mod_clone);

    let stats = pass.stats();
    assert_eq!(stats.loops_analyzed, 1);
    assert_eq!(stats.loops_vectorized, 1);
    assert!(stats.maps_vectorized >= 1);
}

#[test]
fn test_vectorize_pass_array_copy_map_i32() {
    let src = r#"
        pub fn copy_offset(src_arr: [i32; 32], mut dst_arr: [i32; 32], offset: i32) -> [i32; 32] {
            let mut i: i64 = 0;
            while i < 32 {
                dst_arr[i] = src_arr[i] + offset;
                i = i + 1;
            }
            return dst_arr;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("copy_offset.ifa".to_string(), src);
    let (prog, _) = parse(fid, tokenize(fid, src));
    let analysis = analyze(&sm, &prog);
    assert!(!analysis.has_errors());

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let func = &module.functions[0];
    let formatted = format_function(func);
    assert!(
        formatted.contains("// [vector_hint: width=8, interleave=4]"),
        "Formatted FIR:\n{}",
        formatted
    );

    let mut pass = VectorizePass::new();
    let mut mod_clone = module.clone();
    pass.run_on_module(&mut mod_clone);

    let stats = pass.stats();
    assert_eq!(stats.loops_analyzed, 1);
    assert_eq!(stats.loops_vectorized, 1);
    assert!(stats.maps_vectorized >= 1);
}

#[test]
fn test_vectorize_pass_slice_sum_f32() {
    let src = r#"
        pub fn sum_slice_f32(s: Slice<f32>) -> f32 {
            let mut acc: f32 = 0.0;
            for x in s {
                acc = acc + x;
            }
            return acc;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("slice_vec_f32.ifa".to_string(), src);
    let (prog, _) = parse(fid, tokenize(fid, src));
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let func = &module.functions[0];
    let formatted = format_function(func);
    assert!(
        formatted.contains("// [vector_hint: width=8, interleave=4]"),
        "Formatted FIR:\n{}",
        formatted
    );

    let mut pass = VectorizePass::new();
    let mut mod_clone = module.clone();
    pass.run_on_module(&mut mod_clone);

    let stats = pass.stats();
    assert_eq!(stats.loops_analyzed, 1);
    assert_eq!(stats.loops_vectorized, 1);
    assert!(stats.slices_vectorized >= 1);
    assert!(stats.eliminated_bounds_loops >= 1);
}

#[test]
fn test_vectorize_pass_subslice_induction_f64() {
    let src = r#"
        pub fn subslice_vec(arr: [f64; 64]) -> f64 {
            let s = arr[0..32];
            let mut acc: f64 = 0.0;
            for x in s {
                acc = acc + x;
            }
            return acc;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("subslice_vec.ifa".to_string(), src);
    let (prog, _) = parse(fid, tokenize(fid, src));
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let func = &module.functions[0];
    let formatted = format_function(func);
    assert!(
        formatted.contains("// [vector_hint: width=4, interleave=4]"),
        "Formatted FIR:\n{}",
        formatted
    );

    let mut pass = VectorizePass::new();
    let mut mod_clone = module.clone();
    pass.run_on_module(&mut mod_clone);

    let stats = pass.stats();
    assert_eq!(stats.loops_analyzed, 1);
    assert_eq!(stats.loops_vectorized, 1);
    assert!(stats.slices_vectorized >= 1);
    assert!(stats.eliminated_bounds_loops >= 1);
}

#[test]
fn test_vectorize_pass_slice_mutation_map_i32() {
    let src = r#"
        pub fn scale_slice(mut s: [i32], factor: i32) -> [i32] {
            let mut i: i64 = 0;
            let len: i64 = s.len();
            while i < len {
                s[i] = s[i] * factor;
                i = i + 1;
            }
            return s;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("scale_slice.ifa".to_string(), src);
    let (prog, _) = parse(fid, tokenize(fid, src));
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let func = &module.functions[0];
    let formatted = format_function(func);
    assert!(
        formatted.contains("// [vector_hint: width=8, interleave=4]"),
        "Formatted FIR:\n{}",
        formatted
    );

    let mut pass = VectorizePass::new();
    let mut mod_clone = module.clone();
    pass.run_on_module(&mut mod_clone);

    let stats = pass.stats();
    assert_eq!(stats.loops_analyzed, 1);
    assert_eq!(stats.loops_vectorized, 1);
    assert!(stats.slices_vectorized >= 1);
    assert!(stats.maps_vectorized >= 1);
}

#[test]
fn test_vectorize_pass_slice_product_f32() {
    let src = r#"
        pub fn prod_slice_f32(s: Slice<f32>) -> f32 {
            let mut acc: f32 = 1.0;
            for x in s {
                acc = acc * x;
            }
            return acc;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("prod_f32.ifa".to_string(), src);
    let (prog, _) = parse(fid, tokenize(fid, src));
    let analysis = analyze(&sm, &prog);
    assert!(!analysis.has_errors());

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let func = &module.functions[0];
    let formatted = format_function(func);
    assert!(
        formatted.contains("// [vector_hint: width=8, interleave=4]"),
        "Formatted FIR:\n{}",
        formatted
    );
    assert!(formatted.contains("// [reduction: product]"));

    let mut pass = VectorizePass::new();
    let mut mod_clone = module.clone();
    pass.run_on_module(&mut mod_clone);

    let stats = pass.stats();
    assert_eq!(stats.loops_analyzed, 1);
    assert_eq!(stats.loops_vectorized, 1);
    assert_eq!(stats.product_reductions_vectorized, 1);
}

#[test]
fn test_vectorize_pass_array_product_i64() {
    let src = r#"
        pub fn prod_arr_i64(arr: [i64; 32]) -> i64 {
            let mut acc: i64 = 1;
            for x in arr {
                acc = acc * x;
            }
            return acc;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("prod_i64.ifa".to_string(), src);
    let (prog, _) = parse(fid, tokenize(fid, src));
    let analysis = analyze(&sm, &prog);
    assert!(!analysis.has_errors());

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let func = &module.functions[0];
    let formatted = format_function(func);
    assert!(formatted.contains("// [vector_hint: width=4, interleave=4]"));
    assert!(formatted.contains("// [reduction: product]"));

    let mut pass = VectorizePass::new();
    let mut mod_clone = module.clone();
    pass.run_on_module(&mut mod_clone);

    let stats = pass.stats();
    assert_eq!(stats.loops_vectorized, 1);
    assert_eq!(stats.product_reductions_vectorized, 1);
}

#[test]
fn test_vectorize_pass_slice_min_reduction_f32() {
    let src = r#"
        pub fn min_slice_f32(s: Slice<f32>) -> f32 {
            let mut m: f32 = 1000.0;
            for x in s {
                if x < m {
                    m = x;
                }
            }
            return m;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("min_f32.ifa".to_string(), src);
    let (prog, _) = parse(fid, tokenize(fid, src));
    let analysis = analyze(&sm, &prog);
    assert!(!analysis.has_errors());

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let func = &module.functions[0];
    let formatted = format_function(func);
    assert!(
        formatted.contains("// [vector_hint: width=8, interleave=4]"),
        "Formatted FIR:\n{}",
        formatted
    );
    assert!(formatted.contains("// [reduction: min]"));

    let mut pass = VectorizePass::new();
    let mut mod_clone = module.clone();
    pass.run_on_module(&mut mod_clone);

    let stats = pass.stats();
    assert_eq!(stats.loops_vectorized, 1);
    assert_eq!(stats.min_reductions_vectorized, 1);
}

#[test]
fn test_vectorize_pass_intrinsic_min_reduction() {
    let src = r#"
        pub fn intrinsic_min(arr: [f32; 64]) -> f32 {
            let mut m: f32 = arr[0];
            for x in arr {
                m = min(m, x);
            }
            return m;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("intrinsic_min.ifa".to_string(), src);
    let (prog, _) = parse(fid, tokenize(fid, src));
    let analysis = analyze(&sm, &prog);
    assert!(!analysis.has_errors());

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let func = &module.functions[0];
    let formatted = format_function(func);
    assert!(
        formatted.contains("// [vector_hint: width=8, interleave=4]"),
        "Formatted FIR:\n{}",
        formatted
    );
    assert!(formatted.contains("// [reduction: min]"));

    let mut pass = VectorizePass::new();
    let mut mod_clone = module.clone();
    pass.run_on_module(&mut mod_clone);

    let stats = pass.stats();
    assert_eq!(stats.loops_vectorized, 1);
    assert_eq!(stats.min_reductions_vectorized, 1);
}

#[test]
fn test_vectorize_pass_slice_max_reduction_i32() {
    let src = r#"
        pub fn max_slice_i32(s: Slice<i32>) -> i32 {
            let mut m: i32 = -1000;
            for x in s {
                if x > m {
                    m = x;
                }
            }
            return m;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("max_i32.ifa".to_string(), src);
    let (prog, _) = parse(fid, tokenize(fid, src));
    let analysis = analyze(&sm, &prog);
    assert!(!analysis.has_errors());

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let func = &module.functions[0];
    let formatted = format_function(func);
    assert!(
        formatted.contains("// [vector_hint: width=8, interleave=4]"),
        "Formatted FIR:\n{}",
        formatted
    );
    assert!(formatted.contains("// [reduction: max]"));

    let mut pass = VectorizePass::new();
    let mut mod_clone = module.clone();
    pass.run_on_module(&mut mod_clone);

    let stats = pass.stats();
    assert_eq!(stats.loops_vectorized, 1);
    assert_eq!(stats.max_reductions_vectorized, 1);
}

#[test]
fn test_vectorize_pass_while_min_reduction_f64() {
    let src = r#"
        pub fn while_min_f64(arr: [f64; 64]) -> f64 {
            let mut m: f64 = 99999.0;
            let mut i: i64 = 0;
            while i < 64 {
                if arr[i] < m {
                    m = arr[i];
                }
                i = i + 1;
            }
            return m;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("while_min.ifa".to_string(), src);
    let (prog, _) = parse(fid, tokenize(fid, src));
    let analysis = analyze(&sm, &prog);
    assert!(!analysis.has_errors());

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let func = &module.functions[0];
    let formatted = format_function(func);
    assert!(formatted.contains("// [vector_hint: width=4, interleave=4]"));
    assert!(formatted.contains("// [reduction: min]"));

    let mut pass = VectorizePass::new();
    let mut mod_clone = module.clone();
    pass.run_on_module(&mut mod_clone);

    let stats = pass.stats();
    assert_eq!(stats.loops_vectorized, 1);
    assert_eq!(stats.min_reductions_vectorized, 1);
}

#[test]
fn test_vectorize_pass_intrinsic_max_reduction() {
    let src = r#"
        pub fn intrinsic_max(arr: [f32; 64]) -> f32 {
            let mut m: f32 = arr[0];
            for x in arr {
                m = max(m, x);
            }
            return m;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("intrinsic_max.ifa".to_string(), src);
    let (prog, _) = parse(fid, tokenize(fid, src));
    let analysis = analyze(&sm, &prog);
    assert!(!analysis.has_errors());

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let func = &module.functions[0];
    let formatted = format_function(func);
    assert!(
        formatted.contains("// [vector_hint: width=8, interleave=4]"),
        "Formatted FIR:\n{}",
        formatted
    );
    assert!(formatted.contains("// [reduction: max]"));

    let mut pass = VectorizePass::new();
    let mut mod_clone = module.clone();
    pass.run_on_module(&mut mod_clone);

    let stats = pass.stats();
    assert_eq!(stats.loops_vectorized, 1);
    assert_eq!(stats.max_reductions_vectorized, 1);
}

#[test]
fn test_vectorize_pass_disjoint_slices_parallel_iteration() {
    let src = r#"
        pub fn slice_scale_map(src_arr: [f32; 64], inout dst_arr: [f32; 64]) {
            let src = src_arr[0..64];
            let mut dst = dst_arr[0..64];
            let factor: f32 = 3.5;
            let mut i: i64 = 0;
            while i < 64 {
                dst[i] = src[i] * factor;
                i = i + 1;
            }
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("disjoint_slice_map.ifa".to_string(), src);
    let (prog, diags) = parse(fid, tokenize(fid, src));
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    assert!(!module.functions.is_empty());
    let func = &module.functions[0];
    let formatted = format_function(func);
    assert!(
        formatted.contains("// [vector_hint: width=8, interleave=4]"),
        "Formatted FIR:\n{}",
        formatted
    );
    assert!(formatted.contains("// [disjoint_slices: true]"));

    let mut pass = VectorizePass::new();
    let mut mod_clone = module.clone();
    pass.run_on_module(&mut mod_clone);

    let stats = pass.stats();
    assert_eq!(stats.loops_vectorized, 1);
    assert_eq!(stats.disjoint_slice_loops, 1);
    assert!(stats.disjoint_slices_vectorized >= 2);
}

#[test]
fn test_vectorize_pass_strict_slice_transformation() {
    let src = r#"
        pub strict fn strict_slice_scale(mut s: [f32], factor: f32) -> [f32] {
            let mut i: i64 = 0;
            let len: i64 = s.len();
            while i < len {
                s[i] = s[i] * factor;
                i = i + 1;
            }
            return s;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("strict_scale.ifa".to_string(), src);
    let (prog, diags) = parse(fid, tokenize(fid, src));
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let func = &module.functions[0];
    let formatted = format_function(func);
    assert!(
        formatted.contains("// [vector_hint: width=8, interleave=4]"),
        "Formatted FIR:\n{}",
        formatted
    );
    assert!(formatted.contains("// [predicate_enable: true]"));
    assert!(formatted.contains("// [strict_vectorize: true]"));

    let mut pass = VectorizePass::new();
    let mut mod_clone = module.clone();
    pass.run_on_module(&mut mod_clone);

    let stats = pass.stats();
    assert_eq!(stats.loops_vectorized, 1);
    assert_eq!(stats.strict_slice_loops_vectorized, 1);
    assert_eq!(stats.predicated_loops_vectorized, 1);
    assert!(stats.slices_vectorized >= 1);
}

#[test]
fn test_vectorize_pass_strict_partitioned_subslice_disjoint() {
    let src = r#"
        pub strict fn strict_partition_copy(buf: [f32; 64], inout out_buf: [f32; 64]) {
            let src = buf[0..32];
            let mut dst = out_buf[32..64];
            let factor: f32 = 2.0;
            let mut i: i64 = 0;
            while i < 32 {
                dst[i] = src[i] * factor;
                i = i + 1;
            }
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("strict_partition.ifa".to_string(), src);
    let (prog, diags) = parse(fid, tokenize(fid, src));
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let func = &module.functions[0];
    let formatted = format_function(func);
    assert!(
        formatted.contains("// [vector_hint: width=8, interleave=4]"),
        "Formatted FIR:\n{}",
        formatted
    );
    assert!(formatted.contains("// [disjoint_slices: true]"));
    assert!(formatted.contains("// [predicate_enable: true]"));
    assert!(formatted.contains("// [strict_vectorize: true]"));

    let mut pass = VectorizePass::new();
    let mut mod_clone = module.clone();
    pass.run_on_module(&mut mod_clone);

    let stats = pass.stats();
    assert_eq!(stats.loops_vectorized, 1);
    assert_eq!(stats.disjoint_slice_loops, 1);
    assert_eq!(stats.strict_slice_loops_vectorized, 1);
    assert_eq!(stats.predicated_loops_vectorized, 1);
}

#[test]
fn test_vectorize_pass_strict_arena_slice_sum_f32() {
    let src = r#"
        pub strict fn sum_strict_arena_slice(s: Slice<f32>) -> f32 {
            let mut acc: f32 = 0.0;
            for x in s {
                acc = acc + x;
            }
            return acc;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("strict_arena_sum.ifa".to_string(), src);
    let (prog, diags) = parse(fid, tokenize(fid, src));
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let func = &module.functions[0];
    let formatted = format_function(func);
    assert!(
        formatted.contains("// [vector_hint: width=8, interleave=8]"),
        "Formatted FIR must contain width 8, interleave 8:\n{}",
        formatted
    );
    assert!(formatted.contains("// [reduction: sum]"));
    assert!(formatted.contains("// [contiguous_reduction: true]"));
    assert!(formatted.contains("// [local_arena: true]"));
    assert!(formatted.contains("// [strict_vectorize: true]"));

    let mut pass = VectorizePass::new();
    let mut mod_clone = module.clone();
    pass.run_on_module(&mut mod_clone);

    let stats = pass.stats();
    assert_eq!(stats.loops_vectorized, 1);
    assert!(stats.slices_vectorized >= 1);
    assert_eq!(stats.contiguous_slice_reductions, 1);
    assert_eq!(stats.arena_slice_reductions_specialized, 1);
    assert_eq!(stats.strict_zero_heap_reductions, 1);
}

#[test]
fn test_vectorize_pass_strict_arena_slice_dot_product_f64() {
    let src = r#"
        pub strict fn dot_strict_arena_slices(buf1: [f64; 64], buf2: [f64; 64]) -> f64 {
            let a = buf1[0..64];
            let b = buf2[0..64];
            let mut acc: f64 = 0.0;
            let mut i: i64 = 0;
            while i < 64 {
                acc = acc + a[i] * b[i];
                i = i + 1;
            }
            return acc;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("strict_arena_dot.ifa".to_string(), src);
    let (prog, diags) = parse(fid, tokenize(fid, src));
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let func = &module.functions[0];
    let formatted = format_function(func);
    assert!(
        formatted.contains("// [vector_hint: width=4, interleave=4]"),
        "Formatted FIR:\n{}",
        formatted
    );
    assert!(formatted.contains("// [reduction: dot]"));
    assert!(formatted.contains("// [contiguous_reduction: true]"));
    assert!(formatted.contains("// [local_arena: true]"));
    assert!(formatted.contains("// [strict_vectorize: true]"));

    let mut pass = VectorizePass::new();
    let mut mod_clone = module.clone();
    pass.run_on_module(&mut mod_clone);

    let stats = pass.stats();
    assert_eq!(stats.loops_vectorized, 1);
    assert_eq!(stats.dot_reductions_vectorized, 1);
    assert_eq!(stats.contiguous_slice_reductions, 1);
    assert_eq!(stats.arena_slice_reductions_specialized, 1);
    assert_eq!(stats.strict_zero_heap_reductions, 1);
}

#[test]
fn test_vectorize_pass_strict_arena_slice_min_max_i32() {
    let src = r#"
        pub strict fn min_strict_arena(s: Slice<i32>) -> i32 {
            let mut m: i32 = 2147483647;
            for x in s {
                if x < m {
                    m = x;
                }
            }
            return m;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("strict_arena_min.ifa".to_string(), src);
    let (prog, diags) = parse(fid, tokenize(fid, src));
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);
    let analysis = analyze(&sm, &prog);
    assert!(!analysis.has_errors());

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let func = &module.functions[0];
    let formatted = format_function(func);
    assert!(
        formatted.contains("// [vector_hint: width=8, interleave=8]"),
        "Formatted FIR:\n{}",
        formatted
    );
    assert!(formatted.contains("// [reduction: min]"));
    assert!(formatted.contains("// [contiguous_reduction: true]"));
    assert!(formatted.contains("// [local_arena: true]"));
    assert!(formatted.contains("// [strict_vectorize: true]"));

    let mut pass = VectorizePass::new();
    let mut mod_clone = module.clone();
    pass.run_on_module(&mut mod_clone);

    let stats = pass.stats();
    assert_eq!(stats.loops_vectorized, 1);
    assert_eq!(stats.min_reductions_vectorized, 1);
    assert_eq!(stats.contiguous_slice_reductions, 1);
    assert_eq!(stats.arena_slice_reductions_specialized, 1);
    assert_eq!(stats.strict_zero_heap_reductions, 1);
}

#[test]
fn test_vectorize_pass_direct_reduction_call_specialization() {
    use ifa_fir::{
        BasicBlock, BlockId, FirFunction, FirModule, FirParam, FirType, Instruction, ParamMode,
        Terminator, ValueExpr, ValueId,
    };
    use ifa_sema::types::FloatType;
    use ifa_span::{Span, INTERNER};

    let fn_sym = INTERNER.intern("call_arena_slice_reduce");
    let param = FirParam {
        name: INTERNER.intern("s"),
        ty: FirType::Slice(Box::new(FirType::Float(FloatType::F32))),
        val: ValueId(0),
        mode: ParamMode::In,
        noalias: false,
    };
    let mut func = FirFunction::new(
        fn_sym,
        vec![param],
        FirType::Float(FloatType::F32),
        true,
        true,
        false,
        None,
        Span::DUMMY,
    );

    let mut bb0 = BasicBlock::new(BlockId(0));
    // Call generic slice_sum with local slice argument
    let sum_sym = INTERNER.intern("slice_sum_f32");
    bb0.instructions.push(Instruction::new(
        Some(ValueId(1)),
        ValueExpr::CallDirect {
            name: sum_sym,
            args: vec![ValueId(0)],
        },
        Span::DUMMY,
    ));
    bb0.terminator = Some(Terminator::Return(Some(ValueId(1))));
    func.blocks[0] = bb0;

    let mut module = FirModule {
        name: INTERNER.intern("arena_spec_mod"),
        functions: vec![func],
        structs: Vec::new(),
        enums: Vec::new(),
        constants: Vec::new(),
    };

    let mut pass = VectorizePass::new();
    pass.run_on_module(&mut module);

    let stats = pass.stats();
    assert_eq!(stats.arena_slice_reductions_specialized, 1);
    assert_eq!(stats.contiguous_slice_reductions, 1);
    assert_eq!(stats.strict_zero_heap_reductions, 1);

    // Verify the function call was specialized to ifa_simd_arena_slice_sum_f32
    let updated_func = &module.functions[0];
    let inst = &updated_func.blocks[0].instructions[0];
    if let ValueExpr::CallDirect { name, .. } = inst.expr {
        let specialized_callee = INTERNER.resolve(&name);
        assert_eq!(
            specialized_callee, "ifa_simd_arena_slice_sum_f32",
            "Call must be specialized to contiguous arena SIMD vectorizer"
        );
    } else {
        panic!("Instruction must remain a CallDirect");
    }
}

#[test]
fn test_vectorize_pass_strict_arena_slice_count_if_i32() {
    let src = r#"
        pub strict fn count_positives(s: Slice<i32>) -> i64 {
            let mut count: i64 = 0;
            for x in s {
                if x > 0 {
                    count = count + 1;
                }
            }
            return count;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("strict_count_if.ifa".to_string(), src);
    let (prog, diags) = parse(fid, tokenize(fid, src));
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let func = &module.functions[0];
    let formatted = format_function(func);
    assert!(
        formatted.contains("// [vector_hint: width=8, interleave=8]"),
        "Formatted FIR:\n{}",
        formatted
    );
    assert!(formatted.contains("// [reduction: count_if]"));
    assert!(formatted.contains("// [predicate_enable: true]"));
    assert!(formatted.contains("// [contiguous_reduction: true]"));
    assert!(formatted.contains("// [local_arena: true]"));
    assert!(formatted.contains("// [strict_vectorize: true]"));

    let mut pass = VectorizePass::new();
    let mut mod_clone = module.clone();
    pass.run_on_module(&mut mod_clone);

    let stats = pass.stats();
    assert_eq!(stats.loops_vectorized, 1);
    assert_eq!(stats.count_if_reductions_vectorized, 1);
    assert_eq!(stats.contiguous_slice_reductions, 1);
    assert_eq!(stats.arena_slice_reductions_specialized, 1);
    assert_eq!(stats.strict_zero_heap_reductions, 1);
}

#[test]
fn test_vectorize_pass_predicated_filter_and_scatter() {
    let src = r#"
        pub strict fn filter_threshold(src: Slice<i32>, mut dst: Slice<i32>) -> () {
            let mut i: i64 = 0;
            for x in src {
                if x > 10 {
                    dst[i] = x;
                    i = i + 1;
                }
            }
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("predicated_filter.ifa".to_string(), src);
    let (prog, diags) = parse(fid, tokenize(fid, src));
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let func = &module.functions[0];
    let formatted = format_function(func);
    assert!(
        formatted.contains("// [predicated_scatter_gather: true]")
            || formatted.contains("// [predicate_enable: true]"),
        "Formatted FIR:\n{}",
        formatted
    );

    let mut pass = VectorizePass::new();
    let mut mod_clone = module.clone();
    pass.run_on_module(&mut mod_clone);

    let stats = pass.stats();
    assert_eq!(stats.loops_vectorized, 1);
    assert!(stats.predicated_scatter_gather_loops >= 1);
}

#[test]
fn test_vectorize_pass_direct_count_if_and_filter_specialization() {
    use ifa_fir::{
        BasicBlock, BlockId, FirFunction, FirModule, FirParam, FirType, Instruction, ParamMode,
        Terminator, ValueExpr, ValueId,
    };
    use ifa_sema::types::IntType;
    use ifa_span::{Span, INTERNER};

    let fn_sym = INTERNER.intern("call_predicated_arena_primitives");
    let param = FirParam {
        name: INTERNER.intern("s"),
        ty: FirType::Slice(Box::new(FirType::Int(IntType::I32))),
        val: ValueId(0),
        mode: ParamMode::In,
        noalias: false,
    };
    let mut func = FirFunction::new(
        fn_sym,
        vec![param],
        FirType::Int(IntType::I64),
        true,
        true,
        false,
        None,
        Span::DUMMY,
    );

    let mut bb0 = BasicBlock::new(BlockId(0));
    // 1. Call slice_count_gt_i32
    let count_sym = INTERNER.intern("slice_count_gt_i32");
    bb0.instructions.push(Instruction::new(
        Some(ValueId(1)),
        ValueExpr::CallDirect {
            name: count_sym,
            args: vec![ValueId(0), ValueId(10)],
        },
        Span::DUMMY,
    ));
    // 2. Call slice_filter_gt_i32
    let filter_sym = INTERNER.intern("slice_filter_gt_i32");
    bb0.instructions.push(Instruction::new(
        Some(ValueId(2)),
        ValueExpr::CallDirect {
            name: filter_sym,
            args: vec![ValueId(0), ValueId(0), ValueId(10)],
        },
        Span::DUMMY,
    ));
    // 3. Call slice_clamp_f32 on f32 slice
    let clamp_sym = INTERNER.intern("slice_clamp_f32");
    bb0.instructions.push(Instruction::new(
        Some(ValueId(3)),
        ValueExpr::CallDirect {
            name: clamp_sym,
            args: vec![ValueId(0), ValueId(0), ValueId(10), ValueId(20)],
        },
        Span::DUMMY,
    ));
    bb0.terminator = Some(Terminator::Return(Some(ValueId(1))));
    func.blocks[0] = bb0;

    let mut module = FirModule {
        name: INTERNER.intern("arena_pred_spec_mod"),
        functions: vec![func],
        structs: Vec::new(),
        enums: Vec::new(),
        constants: Vec::new(),
    };

    let mut pass = VectorizePass::new();
    pass.run_on_module(&mut module);

    let stats = pass.stats();
    assert_eq!(stats.count_if_reductions_vectorized, 1);
    assert_eq!(stats.arena_slice_filters_specialized, 2);
    assert!(stats.predicated_scatter_gather_loops >= 2);
    assert!(stats.arena_slice_reductions_specialized >= 1);

    // Verify rewritten function names
    let updated_func = &module.functions[0];
    if let ValueExpr::CallDirect { name, .. } = &updated_func.blocks[0].instructions[0].expr {
        assert_eq!(
            INTERNER.resolve(name),
            "ifa_simd_arena_slice_count_if_gt_i32"
        );
    } else {
        panic!("Inst 0 must remain CallDirect");
    }

    if let ValueExpr::CallDirect { name, .. } = &updated_func.blocks[0].instructions[1].expr {
        assert_eq!(INTERNER.resolve(name), "ifa_simd_arena_slice_filter_gt_i32");
    } else {
        panic!("Inst 1 must remain CallDirect");
    }

    if let ValueExpr::CallDirect { name, .. } = &updated_func.blocks[0].instructions[2].expr {
        assert_eq!(INTERNER.resolve(name), "ifa_simd_arena_slice_clamp_f32");
    } else {
        panic!("Inst 2 must remain CallDirect");
    }
}

#[test]
fn test_vectorize_pass_symbolic_partition_split_point_disjoint() {
    let src = r#"
        pub strict fn symbolic_partition_stream(buf: [f32; 64], split: i64, inout out_buf: [f32; 64]) {
            let src = buf[0..split];
            let mut dst = out_buf[split..64];
            let factor: f32 = 1.5;
            let mut i: i64 = 0;
            while i < split {
                dst[i] = src[i] * factor;
                i = i + 1;
            }
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("symbolic_partition.ifa".to_string(), src);
    let (prog, diags) = parse(fid, tokenize(fid, src));
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let func = &module.functions[0];
    let formatted = format_function(func);
    assert!(
        formatted.contains("// [vector_hint: width=8, interleave=4]"),
        "Formatted FIR:\n{}",
        formatted
    );
    assert!(formatted.contains("// [disjoint_slices: true]"));

    let mut pass = VectorizePass::new();
    let mut mod_clone = module.clone();
    pass.run_on_module(&mut mod_clone);

    let stats = pass.stats();
    assert_eq!(stats.loops_vectorized, 1);
    assert_eq!(stats.disjoint_slice_loops, 1);
    assert!(stats.symbolic_partitions_vectorized >= 1);
}

#[test]
fn test_vectorize_pass_multidimensional_projection_disjoint() {
    let src = r#"
        pub strict fn matrix_row_transform(grid: [[f32; 32]; 8], inout out_grid: [[f32; 32]; 8]) {
            let src_row = grid[0][0..32];
            let mut dst_row = out_grid[1][0..32];
            let scale: f32 = 4.0;
            let mut c: i64 = 0;
            while c < 32 {
                dst_row[c] = src_row[c] * scale;
                c = c + 1;
            }
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("matrix_disjoint.ifa".to_string(), src);
    let (prog, diags) = parse(fid, tokenize(fid, src));
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let func = &module.functions[0];
    let formatted = format_function(func);
    assert!(
        formatted.contains("// [vector_hint: width=8, interleave=4]"),
        "Formatted FIR:\n{}",
        formatted
    );
    assert!(formatted.contains("// [disjoint_slices: true]"));

    let mut pass = VectorizePass::new();
    let mut mod_clone = module.clone();
    pass.run_on_module(&mut mod_clone);

    let stats = pass.stats();
    assert_eq!(stats.loops_vectorized, 1);
    assert_eq!(stats.disjoint_slice_loops, 1);
    assert!(stats.multidim_projections_vectorized >= 1);
}

#[test]
fn test_vectorize_pass_inout_swap_disjoint_slices() {
    let src = r#"
        pub strict fn swap_disjoint_slices(inout a: Slice<i64>, inout b: Slice<i64>, n: i64) {
            let mut i: i64 = 0;
            while i < n {
                let tmp = a[i];
                a[i] = b[i];
                b[i] = tmp;
                i = i + 1;
            }
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("swap_disjoint.ifa".to_string(), src);
    let (prog, diags) = parse(fid, tokenize(fid, src));
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let func = &module.functions[0];
    let formatted = format_function(func);
    assert!(
        formatted.contains("// [is_swap: true]"),
        "Formatted FIR must contain is_swap hint:\n{}",
        formatted
    );
    assert!(
        formatted.contains("// [disjoint_slices: true]"),
        "Formatted FIR must contain disjoint_slices hint:\n{}",
        formatted
    );

    let mut pass = VectorizePass::new();
    let mut mod_clone = module.clone();
    pass.run_on_module(&mut mod_clone);

    let stats = pass.stats();
    assert_eq!(stats.loops_vectorized, 1);
    assert_eq!(stats.disjoint_swap_loops_vectorized, 1);
    assert!(stats.disjoint_slices_vectorized >= 2);
}

#[test]
fn test_vectorize_pass_bipartite_matrix_reduction_disjoint_windows() {
    let src = r#"
        pub strict fn matrix_bipartite_reduction(row_a: Slice<f32>, row_b: Slice<f32>, n: i64) -> f32 {
            let mut sum: f32 = 0.0;
            let mut i: i64 = 0;
            while i < n {
                sum = sum + row_a[i] * row_b[i];
                i = i + 1;
            }
            return sum;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("bipartite_reduction.ifa".to_string(), src);
    let (prog, diags) = parse(fid, tokenize(fid, src));
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let func = &module.functions[0];
    let formatted = format_function(func);
    assert!(
        formatted.contains("// [bipartite_matrix_reduction: true]"),
        "Formatted FIR must contain bipartite_matrix_reduction hint:\n{}",
        formatted
    );
    assert!(
        formatted.contains("// [disjoint_slices: true]"),
        "Formatted FIR must contain disjoint_slices hint:\n{}",
        formatted
    );

    let mut pass = VectorizePass::new();
    let mut mod_clone = module.clone();
    pass.run_on_module(&mut mod_clone);

    let stats = pass.stats();
    assert_eq!(stats.loops_vectorized, 1);
    assert_eq!(stats.bipartite_matrix_reductions_vectorized, 1);
    assert_eq!(stats.multidim_matrix_reductions_vectorized, 1);
}

#[test]
fn test_vectorize_pass_tripartite_matrix_reduction_disjoint_windows() {
    let src = r#"
        pub strict fn matrix_tripartite_reduction(inout acc: Slice<f32>, row_a: Slice<f32>, col_b: Slice<f32>, n: i64) {
            let mut i: i64 = 0;
            while i < n {
                acc[i] = acc[i] + row_a[i] * col_b[i];
                i = i + 1;
            }
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("tripartite_reduction.ifa".to_string(), src);
    let (prog, diags) = parse(fid, tokenize(fid, src));
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let func = &module.functions[0];
    let formatted = format_function(func);
    assert!(
        formatted.contains("// [tripartite_matrix_reduction: true]"),
        "Formatted FIR must contain tripartite_matrix_reduction hint:\n{}",
        formatted
    );
    assert!(
        formatted.contains("// [disjoint_slices: true]"),
        "Formatted FIR must contain disjoint_slices hint:\n{}",
        formatted
    );

    let mut pass = VectorizePass::new();
    let mut mod_clone = module.clone();
    pass.run_on_module(&mut mod_clone);

    let stats = pass.stats();
    assert_eq!(stats.loops_vectorized, 1);
    assert_eq!(stats.tripartite_matrix_reductions_vectorized, 1);
    assert_eq!(stats.multidim_matrix_reductions_vectorized, 1);
}

#[test]
fn test_vectorize_pass_strided_conv2d_zero_copy() {
    let src = r#"
        pub strict fn conv2d_strided_zero_copy(
            inout out: Slice<f32>,
            img: Slice<f32>,
            kernel: Slice<f32>,
            h_out: i64,
            w_out: i64,
            stride_y: i64,
            stride_x: i64,
            img_width: i64
        ) {
            let mut y: i64 = 0;
            while y < h_out {
                let mut x: i64 = 0;
                while x < w_out {
                    let in_idx = (y * stride_y) * img_width + (x * stride_x);
                    let out_idx = y * w_out + x;
                    out[out_idx] = out[out_idx] + img[in_idx] * kernel[0];
                    x = x + 1;
                }
                y = y + 1;
            }
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("conv2d_strided.ifa".to_string(), src);
    let (prog, diags) = parse(fid, tokenize(fid, src));
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let func = &module.functions[0];
    let formatted = format_function(func);
    assert!(
        formatted.contains("// [zero_copy: true]")
            || formatted.contains("// [strided_conv2d: true]"),
        "Formatted FIR must contain zero_copy or strided_conv2d hint:\n{}",
        formatted
    );

    let mut pass = VectorizePass::new();
    let mut mod_clone = module.clone();
    pass.run_on_module(&mut mod_clone);

    let stats = pass.stats();
    assert!(
        stats.loops_vectorized >= 1,
        "Loops should be vectorized: {:?}",
        stats
    );
    assert!(
        stats.strided_conv2d_vectorized >= 1,
        "2D strided convolution must be recognized: {:?}",
        stats
    );
    assert!(
        stats.zero_copy_convolutions_specialized >= 1,
        "Zero-copy convolution must be specialized: {:?}",
        stats
    );
}

#[test]
fn test_vectorize_pass_strided_conv3d_zero_copy() {
    let src = r#"
        pub strict fn conv3d_strided_zero_copy(
            inout out: Slice<f32>,
            volume: Slice<f32>,
            kernel: Slice<f32>,
            d_out: i64,
            h_out: i64,
            w_out: i64,
            stride_z: i64,
            stride_y: i64,
            stride_x: i64,
            plane_pitch: i64,
            row_pitch: i64
        ) {
            let mut z: i64 = 0;
            while z < d_out {
                let mut y: i64 = 0;
                while y < h_out {
                    let mut x: i64 = 0;
                    while x < w_out {
                        let in_idx = (z * stride_z) * plane_pitch + (y * stride_y) * row_pitch + (x * stride_x);
                        let out_idx = (z * h_out + y) * w_out + x;
                        out[out_idx] = out[out_idx] + volume[in_idx] * kernel[0];
                        x = x + 1;
                    }
                    y = y + 1;
                }
                z = z + 1;
            }
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("conv3d_strided.ifa".to_string(), src);
    let (prog, diags) = parse(fid, tokenize(fid, src));
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let mut pass = VectorizePass::new();
    let mut mod_clone = module.clone();
    pass.run_on_module(&mut mod_clone);

    let stats = pass.stats();
    assert!(
        stats.loops_vectorized >= 1,
        "Loops should be vectorized: {:?}",
        stats
    );
    assert!(
        stats.strided_conv3d_vectorized >= 1,
        "3D strided convolution must be recognized: {:?}",
        stats
    );
    assert!(
        stats.zero_copy_convolutions_specialized >= 1,
        "Zero-copy 3D convolution must be specialized: {:?}",
        stats
    );
}

#[test]
fn test_vectorize_strided_slices_non_aliasing_interleaved() {
    let mut func = FirFunction::new(
        INTERNER.intern("test_interleaved_strided"),
        vec![FirParam::new(
            INTERNER.intern("base"),
            ValueId(0),
            FirType::Slice(Box::new(FirType::Float(ifa_sema::types::FloatType::F32))),
            ParamMode::InOut,
        )],
        FirType::Unit,
        true,
        false,
        false,
        None,
        Span::DUMMY,
    );

    let entry = func.entry_block;
    let b = func.get_block_mut(entry).unwrap();
    let v_even_start = ValueId(1);
    let v_odd_start = ValueId(2);
    let v_end = ValueId(3);
    let v_stride = ValueId(4);
    let v_even_slice = ValueId(5);
    let v_odd_slice = ValueId(6);

    b.push_instruction(Instruction::new(
        Some(v_even_start),
        ValueExpr::Constant(ConstantValue::Int(0, IntType::I64)),
        Span::DUMMY,
    ));
    b.push_instruction(Instruction::new(
        Some(v_odd_start),
        ValueExpr::Constant(ConstantValue::Int(1, IntType::I64)),
        Span::DUMMY,
    ));
    b.push_instruction(Instruction::new(
        Some(v_end),
        ValueExpr::Constant(ConstantValue::Int(100, IntType::I64)),
        Span::DUMMY,
    ));
    b.push_instruction(Instruction::new(
        Some(v_stride),
        ValueExpr::Constant(ConstantValue::Int(2, IntType::I64)),
        Span::DUMMY,
    ));
    b.push_instruction(Instruction::new(
        Some(v_even_slice),
        ValueExpr::SliceStrided {
            base: ValueId(0),
            start: v_even_start,
            end: v_end,
            stride: v_stride,
        },
        Span::DUMMY,
    ));
    b.push_instruction(Instruction::new(
        Some(v_odd_slice),
        ValueExpr::SliceStrided {
            base: ValueId(0),
            start: v_odd_start,
            end: v_end,
            stride: v_stride,
        },
        Span::DUMMY,
    ));
    b.set_terminator(Terminator::Return(None));

    assert!(
        VectorizePass::are_slice_bases_disjoint(&func, v_even_slice, v_odd_slice),
        "Even and odd strided slices on the same base must be provably disjoint"
    );
}

#[test]
fn test_strided_loop_vectorization_directive_and_bounds_elimination() {
    use ifa_fir::{BasicBlock, BinaryOp, BlockId};

    let mut func = FirFunction::new(
        INTERNER.intern("test_strided_loop"),
        vec![FirParam::new(
            INTERNER.intern("arr"),
            ValueId(0),
            FirType::Slice(Box::new(FirType::Int(IntType::I64))),
            ParamMode::InOut,
        )],
        FirType::Unit,
        true,
        false,
        false,
        None,
        Span::DUMMY,
    );

    // Block 0: Entry
    let b0 = BlockId(0);
    let b1 = BlockId(1); // Loop header / body
    let b2 = BlockId(2); // Loop latch
    let b3 = BlockId(3); // Exit

    func.blocks.clear();
    let mut bb0 = BasicBlock::new(b0);
    let mut bb1 = BasicBlock::new(b1);
    let mut bb2 = BasicBlock::new(b2);
    let mut bb3 = BasicBlock::new(b3);

    let v_start = ValueId(1);
    let v_end = ValueId(2);
    let v_stride = ValueId(3);
    let v_strided_slice = ValueId(4);

    bb0.push_instruction(Instruction::new(
        Some(v_start),
        ValueExpr::Constant(ConstantValue::Int(0, IntType::I64)),
        Span::DUMMY,
    ));
    bb0.push_instruction(Instruction::new(
        Some(v_end),
        ValueExpr::Constant(ConstantValue::Int(100, IntType::I64)),
        Span::DUMMY,
    ));
    bb0.push_instruction(Instruction::new(
        Some(v_stride),
        ValueExpr::Constant(ConstantValue::Int(2, IntType::I64)),
        Span::DUMMY,
    ));
    bb0.push_instruction(Instruction::new(
        Some(v_strided_slice),
        ValueExpr::SliceStrided {
            base: ValueId(0),
            start: v_start,
            end: v_end,
            stride: v_stride,
        },
        Span::DUMMY,
    ));
    bb0.set_terminator(Terminator::Branch {
        target: b1,
        args: vec![v_start],
    });

    // Block 1: Header / Body
    let v_i = ValueId(5);
    bb1.push_param(v_i, FirType::Int(IntType::I64));
    let v_cond = ValueId(6);
    bb1.push_instruction(Instruction::new(
        Some(v_cond),
        ValueExpr::Binary {
            op: BinaryOp::Lt,
            lhs: v_i,
            rhs: v_end,
        },
        Span::DUMMY,
    ));
    bb1.set_terminator(Terminator::BranchCond {
        cond: v_cond,
        then_block: b2,
        then_args: vec![],
        else_block: b3,
        else_args: vec![],
    });

    // Block 2: Latch
    let v_bounds_tok = ValueId(7);
    bb2.push_instruction(Instruction::new(
        Some(v_bounds_tok),
        ValueExpr::SliceStridedBoundsCheck {
            base: v_strided_slice,
            start: v_start,
            end: v_end,
            stride: v_stride,
            redundant: false,
        },
        Span::DUMMY,
    ));
    let v_elem = ValueId(8);
    bb2.push_instruction(Instruction::new(
        Some(v_elem),
        ValueExpr::GetElement {
            base: v_strided_slice,
            index: v_i,
        },
        Span::DUMMY,
    ));
    let v_c1 = ValueId(9);
    bb2.push_instruction(Instruction::new(
        Some(v_c1),
        ValueExpr::Constant(ConstantValue::Int(1, IntType::I64)),
        Span::DUMMY,
    ));
    let v_next_i = ValueId(10);
    bb2.push_instruction(Instruction::new(
        Some(v_next_i),
        ValueExpr::Binary {
            op: BinaryOp::Add,
            lhs: v_i,
            rhs: v_c1,
        },
        Span::DUMMY,
    ));
    bb2.set_terminator(Terminator::Branch {
        target: b1,
        args: vec![v_next_i],
    });

    // Block 3: Exit
    bb3.set_terminator(Terminator::Return(None));

    func.blocks.push(bb0);
    func.blocks.push(bb1);
    func.blocks.push(bb2);
    func.blocks.push(bb3);

    let mut pass = VectorizePass::new();
    pass.run_on_function(&mut func);
    let stats = pass.stats();

    assert!(
        stats.strided_loops_vectorized >= 1,
        "Strided loop must be vectorized: {:?}",
        stats
    );
    assert!(
        stats.strided_bounds_eliminated >= 1,
        "Strided bounds check must be statically eliminated: {:?}",
        stats
    );

    let latch_b = func.get_block(b2).unwrap();
    let hint = latch_b.vector_hint.expect("Latch must have vector hint");
    assert!(hint.is_strided_loop, "Vector hint must mark strided loop");
    assert_eq!(hint.loop_stride, Some(2), "Stride must be detected as 2");
}

#[test]
fn test_vectorize_multidim_strided_projections_vectorized_and_bce() {
    let mut func = FirFunction::new(
        INTERNER.intern("test_multidim_strided_proj"),
        vec![FirParam::new(
            INTERNER.intern("matrix"),
            ValueId(0),
            FirType::Slice(Box::new(FirType::Slice(Box::new(FirType::Float(
                ifa_sema::types::FloatType::F32,
            ))))),
            ParamMode::InOut,
        )],
        FirType::Unit,
        true,
        false,
        false,
        None,
        Span::DUMMY,
    );

    let b0 = BlockId(0);
    let b1 = BlockId(1);
    let b2 = BlockId(2);
    let b3 = BlockId(3);

    let mut bb0 = BasicBlock::new(b0);
    let mut bb1 = BasicBlock::new(b1);
    let mut bb2 = BasicBlock::new(b2);
    let mut bb3 = BasicBlock::new(b3);

    // Block 0: Entry -> Project row 0 of 2D matrix, then extract strided slice [0..100:2]
    let v_row_idx = ValueId(1);
    bb0.push_instruction(Instruction::new(
        Some(v_row_idx),
        ValueExpr::Constant(ConstantValue::Int(0, IntType::I64)),
        Span::DUMMY,
    ));
    let v_row_slice = ValueId(2);
    bb0.push_instruction(Instruction::new(
        Some(v_row_slice),
        ValueExpr::GetElement {
            base: ValueId(0),
            index: v_row_idx,
        },
        Span::DUMMY,
    ));

    let v_start = ValueId(3);
    bb0.push_instruction(Instruction::new(
        Some(v_start),
        ValueExpr::Constant(ConstantValue::Int(0, IntType::I64)),
        Span::DUMMY,
    ));
    let v_end = ValueId(4);
    bb0.push_instruction(Instruction::new(
        Some(v_end),
        ValueExpr::Constant(ConstantValue::Int(100, IntType::I64)),
        Span::DUMMY,
    ));
    let v_stride = ValueId(5);
    bb0.push_instruction(Instruction::new(
        Some(v_stride),
        ValueExpr::Constant(ConstantValue::Int(2, IntType::I64)),
        Span::DUMMY,
    ));
    let v_strided_proj = ValueId(6);
    bb0.push_instruction(Instruction::new(
        Some(v_strided_proj),
        ValueExpr::SliceStrided {
            base: v_row_slice,
            start: v_start,
            end: v_end,
            stride: v_stride,
        },
        Span::DUMMY,
    ));
    let v_init_i = ValueId(7);
    bb0.push_instruction(Instruction::new(
        Some(v_init_i),
        ValueExpr::Constant(ConstantValue::Int(0, IntType::I64)),
        Span::DUMMY,
    ));
    bb0.set_terminator(Terminator::Branch {
        target: b1,
        args: vec![v_init_i],
    });

    // Block 1: Header (Loop over strided projection)
    let v_i = ValueId(8);
    bb1.params.push((v_i, FirType::Int(IntType::I64)));
    let v_cond = ValueId(9);
    bb1.push_instruction(Instruction::new(
        Some(v_cond),
        ValueExpr::Binary {
            op: BinaryOp::Lt,
            lhs: v_i,
            rhs: v_end,
        },
        Span::DUMMY,
    ));
    bb1.set_terminator(Terminator::BranchCond {
        cond: v_cond,
        then_block: b2,
        then_args: Vec::new(),
        else_block: b3,
        else_args: Vec::new(),
    });

    // Block 2: Body with SliceStridedBoundsCheck and GetElement
    bb2.push_instruction(Instruction::new(
        None,
        ValueExpr::SliceStridedBoundsCheck {
            base: v_strided_proj,
            start: v_start,
            end: v_end,
            stride: v_stride,
            redundant: false,
        },
        Span::DUMMY,
    ));
    let v_elem = ValueId(10);
    bb2.push_instruction(Instruction::new(
        Some(v_elem),
        ValueExpr::GetElement {
            base: v_strided_proj,
            index: v_i,
        },
        Span::DUMMY,
    ));
    let v_c1 = ValueId(11);
    bb2.push_instruction(Instruction::new(
        Some(v_c1),
        ValueExpr::Constant(ConstantValue::Int(1, IntType::I64)),
        Span::DUMMY,
    ));
    let v_next_i = ValueId(12);
    bb2.push_instruction(Instruction::new(
        Some(v_next_i),
        ValueExpr::Binary {
            op: BinaryOp::Add,
            lhs: v_i,
            rhs: v_c1,
        },
        Span::DUMMY,
    ));
    bb2.set_terminator(Terminator::Branch {
        target: b1,
        args: vec![v_next_i],
    });

    // Block 3: Exit
    bb3.set_terminator(Terminator::Return(None));

    func.blocks.push(bb0);
    func.blocks.push(bb1);
    func.blocks.push(bb2);
    func.blocks.push(bb3);

    let mut pass = VectorizePass::new();
    pass.run_on_function(&mut func);
    let stats = pass.stats();

    assert!(
        stats.multidim_strided_projections_vectorized >= 1,
        "Multidimensional strided projection must be vectorized: {:?}",
        stats
    );
    assert!(
        stats.multidim_projections_vectorized >= 1,
        "Multidimensional projection count must increase: {:?}",
        stats
    );
    assert!(
        stats.strided_bounds_eliminated >= 1,
        "Strided bounds check must be eliminated: {:?}",
        stats
    );

    let latch_b = func.get_block(b2).unwrap();
    let hint = latch_b.vector_hint.expect("Latch must have vector hint");
    assert!(
        hint.is_strided_multidim,
        "Hint must mark is_strided_multidim"
    );
    assert!(hint.unroll_and_jam, "Hint must enable unroll_and_jam");
    assert!(hint.disjoint_slices, "Hint must mark disjoint_slices");
}

#[test]
fn test_vectorize_pass_multi_arena_fused_conv2d_bias_activation() {
    let src = r#"
        pub strict fn conv2d_fused_bias_kernel(
            inout out: Slice<f32>,
            img: Slice<f32>,
            weights: Slice<f32>,
            bias: Slice<f32>,
            h_out: i64,
            w_out: i64,
            stride_y: i64,
            stride_x: i64,
            img_width: i64
        ) {
            let mut y: i64 = 0;
            while y < h_out {
                let mut x: i64 = 0;
                while x < w_out {
                    let in_idx = (y * stride_y) * img_width + (x * stride_x);
                    let out_idx = y * w_out + x;
                    let conv_val = img[in_idx] * weights[0] + bias[0];
                    out[out_idx] = out[out_idx] + conv_val;
                    x = x + 1;
                }
                y = y + 1;
            }
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("conv2d_fused.ifa".to_string(), src);
    let (prog, diags) = parse(fid, tokenize(fid, src));
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let mut func = module.functions[0].clone();

    // Insert generational checks within the loop body to verify nested gen_check elision
    let inner_header_block = func
        .blocks
        .iter()
        .find(|b| {
            b.instructions.iter().any(|i| {
                matches!(
                    i.expr,
                    ValueExpr::Binary {
                        op: BinaryOp::Mul,
                        ..
                    }
                )
            })
        })
        .map(|b| b.id)
        .unwrap();

    let p_img = func.params[1].val;
    let p_weights = func.params[2].val;

    if let Some(b) = func.get_block_mut(inner_header_block) {
        b.instructions.insert(
            0,
            Instruction::new(
                None,
                ValueExpr::GenCheck {
                    ref_val: p_img,
                    redundant: false,
                },
                Span::DUMMY,
            ),
        );
        b.instructions.insert(
            1,
            Instruction::new(
                None,
                ValueExpr::GenCheck {
                    ref_val: p_weights,
                    redundant: false,
                },
                Span::DUMMY,
            ),
        );
    }

    let mut pass = VectorizePass::new();
    pass.run_on_function(&mut func);
    let stats = pass.stats();

    assert!(
        stats.multi_arena_conv2d_vectorized >= 1,
        "Multi-arena 2D convolution must be recognized: {:?}",
        stats
    );
    assert!(
        stats.fused_convolutions_vectorized >= 1,
        "Fused convolution with bias addition must be recognized: {:?}",
        stats
    );
    assert!(
        stats.nested_gen_checks_eliminated >= 2,
        "Generational checks in nested convolution loops must be eliminated: {:?}",
        stats
    );

    // Verify all GenChecks in the loop body have been marked redundant
    let blk = func.get_block(inner_header_block).unwrap();
    for inst in &blk.instructions {
        if let ValueExpr::GenCheck { redundant, .. } = &inst.expr {
            assert!(
                *redundant,
                "GenCheck in convolution body must be marked redundant"
            );
        }
    }
}

#[test]
fn test_vectorize_pass_multi_arena_fused_conv3d_volumetric_gen_elision() {
    let src = r#"
        pub strict fn conv3d_fused_volumetric(
            inout out: Slice<f32>,
            volume: Slice<f32>,
            filter: Slice<f32>,
            bias: Slice<f32>,
            d_out: i64,
            h_out: i64,
            w_out: i64,
            stride_z: i64,
            stride_y: i64,
            stride_x: i64,
            plane_pitch: i64,
            row_pitch: i64
        ) {
            let mut z: i64 = 0;
            while z < d_out {
                let mut y: i64 = 0;
                while y < h_out {
                    let mut x: i64 = 0;
                    while x < w_out {
                        let in_idx = (z * stride_z) * plane_pitch + (y * stride_y) * row_pitch + (x * stride_x);
                        let out_idx = (z * h_out + y) * w_out + x;
                        let product = volume[in_idx] * filter[0];
                        out[out_idx] = out[out_idx] + product + bias[0];
                        x = x + 1;
                    }
                    y = y + 1;
                }
                z = z + 1;
            }
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("conv3d_fused.ifa".to_string(), src);
    let (prog, diags) = parse(fid, tokenize(fid, src));
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let mut func = module.functions[0].clone();

    // Insert generation checks in volumetric loop
    let inner_block_id = func
        .blocks
        .iter()
        .find(|b| {
            b.instructions.iter().any(|i| {
                matches!(
                    i.expr,
                    ValueExpr::Binary {
                        op: BinaryOp::Mul,
                        ..
                    }
                )
            })
        })
        .map(|b| b.id)
        .unwrap();

    let p_vol = func.params[1].val;

    if let Some(b) = func.get_block_mut(inner_block_id) {
        b.instructions.insert(
            0,
            Instruction::new(
                None,
                ValueExpr::GenCheck {
                    ref_val: p_vol,
                    redundant: false,
                },
                Span::DUMMY,
            ),
        );
    }

    let mut pass = VectorizePass::new();
    pass.run_on_function(&mut func);
    let stats = pass.stats();

    assert!(
        stats.multi_arena_conv3d_vectorized >= 1,
        "Multi-arena 3D convolution must be recognized: {:?}",
        stats
    );
    assert!(
        stats.fused_convolutions_vectorized >= 1,
        "Fused 3D convolution must be recognized: {:?}",
        stats
    );
    assert!(
        stats.nested_gen_checks_eliminated >= 1,
        "Generational checks in nested 3D loops must be eliminated: {:?}",
        stats
    );
}

#[test]
fn test_dilated_convolution_vectorization_and_gen_check_elision() {
    use ifa_fir::LoopVectorHint;
    let src = r#"
        pub strict fn dilated_conv2d_kernel(
            inout dst: Slice<f32>,
            img: Slice<f32>,
            weights: Slice<f32>,
            bias: Slice<f32>
        ) {
            let mut y: i64 = 0;
            while y < 3 {
                let mut x: i64 = 0;
                while x < 3 {
                    let mut ky: i64 = 0;
                    while ky < 2 {
                        let mut kx: i64 = 0;
                        while kx < 2 {
                            let in_idx = (y * 1 + ky * 2) * 5 + (x * 1 + kx * 2);
                            let w_idx = ky * 2 + kx;
                            let out_idx = y * 3 + x;
                            dst[out_idx] = dst[out_idx] + img[in_idx] * weights[w_idx];
                            kx = kx + 1;
                        }
                        ky = ky + 1;
                    }
                    x = x + 1;
                }
                y = y + 1;
            }
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("dilated_conv.ifa".to_string(), src);
    let (prog, diags) = parse(fid, tokenize(fid, src));
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let mut func = module.functions[0].clone();

    // Attach dilated convolution vector hint to loop blocks
    for b in &mut func.blocks {
        b.set_vector_hint(LoopVectorHint::new(8, 8, true).with_dilated_conv(
            false,
            (1, 2, 2),
            true,
            true,
        ));
    }

    // Insert generation check into the inner loop body
    let inner_block = func
        .blocks
        .iter_mut()
        .find(|b| {
            b.instructions.iter().any(|i| {
                matches!(
                    i.expr,
                    ValueExpr::Binary {
                        op: BinaryOp::Mul,
                        ..
                    }
                )
            })
        })
        .unwrap();

    let p_img = func.params[1].val;
    inner_block.instructions.insert(
        0,
        Instruction::new(
            None,
            ValueExpr::GenCheck {
                ref_val: p_img,
                redundant: false,
            },
            Span::DUMMY,
        ),
    );

    let mut pass = VectorizePass::new();
    pass.run_on_function(&mut func);
    let stats = pass.stats();

    assert!(
        stats.dilated_conv_vectorized >= 1,
        "Dilated convolution must be recognized: {:?}",
        stats
    );
    assert!(
        stats.nested_gen_checks_eliminated >= 1,
        "Generational checks in dilated conv loops must be statically eliminated: {:?}",
        stats
    );
}

#[test]
fn test_spatial_max_and_avg_pooling_vectorization_and_gen_check_elision() {
    use ifa_fir::{LoopVectorHint, PoolingKind};
    let src = r#"
        pub strict fn spatial_pool_kernel(
            inout dst: Slice<f32>,
            img: Slice<f32>
        ) {
            let mut y: i64 = 0;
            while y < 2 {
                let mut x: i64 = 0;
                while x < 2 {
                    let mut py: i64 = 0;
                    while py < 2 {
                        let mut px: i64 = 0;
                        while px < 2 {
                            let in_idx = (y * 2 + py) * 4 + (x * 2 + px);
                            let out_idx = y * 2 + x;
                            dst[out_idx] = dst[out_idx] + img[in_idx];
                            px = px + 1;
                        }
                        py = py + 1;
                    }
                    x = x + 1;
                }
                y = y + 1;
            }
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("spatial_pool.ifa".to_string(), src);
    let (prog, diags) = parse(fid, tokenize(fid, src));
    assert!(diags.is_empty(), "Parse errors: {:?}", diags);
    let analysis = analyze(&sm, &prog);
    assert!(
        !analysis.has_errors(),
        "Sema errors: {:?}",
        analysis.diagnostics
    );

    let module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();
    let mut func = module.functions[0].clone();

    // Attach spatial max pooling hint to loop blocks
    for b in &mut func.blocks {
        b.set_vector_hint(LoopVectorHint::new(8, 8, true).with_pooling(
            PoolingKind::Max,
            (2, 2),
            (2, 2),
        ));
    }

    let inner_block = func
        .blocks
        .iter_mut()
        .find(|b| {
            b.instructions.iter().any(|i| {
                matches!(
                    i.expr,
                    ValueExpr::Binary {
                        op: BinaryOp::Add,
                        ..
                    }
                )
            })
        })
        .unwrap();

    let p_img = func.params[1].val;
    inner_block.instructions.insert(
        0,
        Instruction::new(
            None,
            ValueExpr::GenCheck {
                ref_val: p_img,
                redundant: false,
            },
            Span::DUMMY,
        ),
    );

    let mut pass = VectorizePass::new();
    pass.run_on_function(&mut func);
    let stats = pass.stats();

    assert!(
        stats.total_pooling_vectorized >= 1,
        "Total pooling must be recognized: {:?}",
        stats
    );
    assert!(
        stats.max_pooling_vectorized >= 1,
        "Max pooling must be recognized: {:?}",
        stats
    );
    assert!(
        stats.nested_gen_checks_eliminated >= 1,
        "Generational checks in spatial pooling loops must be eliminated: {:?}",
        stats
    );
}

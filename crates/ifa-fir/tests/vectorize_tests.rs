use ifa_fir::{compile_to_fir, format_function, VectorizePass};
use ifa_lexer::tokenize;
use ifa_parser::parse;
use ifa_sema::analyze;
use ifa_span::SourceMap;

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

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
    assert!(formatted.contains("// [vector_hint: width=8, interleave=4]"));

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
    assert!(formatted.contains("// [vector_hint: width=8, interleave=4]"));

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
    assert!(formatted.contains("// [vector_hint: width=8, interleave=4]"));

    let mut pass = VectorizePass::new();
    let mut mod_clone = module.clone();
    pass.run_on_module(&mut mod_clone);

    let stats = pass.stats();
    assert_eq!(stats.loops_analyzed, 1);
    assert_eq!(stats.loops_vectorized, 1);
    assert!(stats.maps_vectorized >= 1);
}

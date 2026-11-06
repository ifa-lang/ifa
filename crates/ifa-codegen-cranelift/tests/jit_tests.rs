use ifa_codegen_cranelift::{AotCompiler, JitEngine};
use ifa_fir::compile_to_fir;
use ifa_lexer::tokenize;
use ifa_parser::parse;
use ifa_sema::analyze;
use ifa_span::SourceMap;
use std::env;
use std::fs;

#[test]
fn test_cranelift_jit_arithmetic_execution() {
    let src = r#"
        fn add(a: i64, b: i64) -> i64 {
            let res = a + b
            return res
        }

        pub fn main() -> i64 {
            let sum = add(35, 7)
            return sum
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("calc.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, _) = parse(fid, tokens);
    let analysis = analyze(&sm, &prog);
    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let mut jit = JitEngine::new().expect("Failed to initialize Cranelift JIT engine");
    jit.compile_module(&fir_module)
        .expect("Failed to compile FIR to Cranelift machine code");

    let result = jit.run_main().expect("Failed to execute native main");
    assert_eq!(result, 42);
}

#[test]
fn test_cranelift_jit_branching_and_comparisons() {
    let src = r#"
        fn max(a: i64, b: i64) -> i64 {
            if a > b {
                return a
            } else {
                return b
            }
        }

        pub fn main() -> i64 {
            let m1 = max(100, 42)
            let m2 = max(15, 99)
            return m1 + m2
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("branch.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, _) = parse(fid, tokens);
    let analysis = analyze(&sm, &prog);
    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let mut jit = JitEngine::new().expect("Failed to initialize Cranelift JIT engine");
    jit.compile_module(&fir_module)
        .expect("Failed to compile FIR to Cranelift machine code");

    let result = jit.run_main().expect("Failed to execute native main");
    assert_eq!(result, 199);
}

#[test]
fn test_cranelift_aot_object_emission() {
    let src = r#"
        pub fn main() -> i64 {
            let x = 10
            let y = 20
            return x * y
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("aot.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, _) = parse(fid, tokens);
    let analysis = analyze(&sm, &prog);
    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let aot = AotCompiler::new().expect("Failed to initialize AOT compiler");
    let out_dir = env::temp_dir().join("ifa_aot_test");
    let obj_path = out_dir.join("test_module.o");

    aot.compile_to_object(&fir_module, &obj_path)
        .expect("Failed to emit native object file");

    assert!(obj_path.exists());
    let metadata = fs::metadata(&obj_path).unwrap();
    assert!(metadata.len() > 0);

    let _ = fs::remove_dir_all(&out_dir);
}

#[test]
fn test_cranelift_jit_inout_mutation() {
    let src = r#"
        fn increment(inout val: i64, step: i64) {
            val = val + step;
        }

        pub fn main() -> i64 {
            mut counter: i64 = 50;
            increment(inout counter, 15);
            return counter;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("inout_test.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, _) = parse(fid, tokens);
    let analysis = analyze(&sm, &prog);
    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let mut jit = JitEngine::new().expect("Failed to initialize Cranelift JIT engine");
    jit.compile_module(&fir_module)
        .expect("Failed to compile FIR to Cranelift machine code");

    let result = jit.run_main().expect("Failed to execute native main");
    assert_eq!(result, 65);
}

#[test]
fn test_cranelift_aot_standalone_binary_execution() {
    let src = r#"
        fn multiply(a: i64, b: i64) -> i64 {
            return a * b;
        }

        pub fn main() -> i64 {
            let res = multiply(6, 7);
            return res;
        }
    "#;

    let mut sm = SourceMap::new();
    let fid = sm.add_file("aot_exec.ifa", src);
    let tokens = tokenize(fid, src);
    let (prog, _) = parse(fid, tokens);
    let analysis = analyze(&sm, &prog);
    let fir_module = compile_to_fir(&prog, &analysis.symbols, true, true).unwrap();

    let aot = AotCompiler::new().expect("Failed to initialize AOT compiler");
    let out_dir = env::temp_dir().join(format!("ifa_aot_exec_{}", std::process::id()));
    let obj_path = out_dir.join("test_mult.o");
    let bin_path = out_dir.join("test_mult");

    aot.compile_to_object(&fir_module, &obj_path)
        .expect("Failed to emit native object file");
    AotCompiler::link_executable(&obj_path, &bin_path).expect("Failed to link native executable");

    let output = std::process::Command::new(&bin_path)
        .output()
        .expect("Failed to execute native standalone binary");

    assert_eq!(output.status.code(), Some(42));

    let _ = fs::remove_dir_all(&out_dir);
}

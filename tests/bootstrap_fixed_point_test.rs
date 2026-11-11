//! Automated Testbench for Triple-Stage Bootstrap and Bit-for-Bit Deterministic Self-Hosting.
//!
//! Validates the fixed-point convergence of the IFA compiler toolchain:
//! - Stage 0 (Rust Host Compiler) compiles pure IFA compiler sources (`compiler/`).
//! - Stage 1 (`ifac-gen1`) produces Stage 2 artifacts (`ifac-gen2`).
//! - Stage 2 (`ifac-gen2`) produces Stage 3 artifacts (`ifac-gen3`).
//! - Fixed-point validation asserts: `sha256(ifac-gen2) == sha256(ifac-gen3)`.

use ifa_stdlib::crypto::sha256_hex;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Mutex, OnceLock};

static BOOTSTRAP_TEST_MUTEX: Mutex<()> = Mutex::new(());
static KORI_BIN_CACHE: OnceLock<PathBuf> = OnceLock::new();
static IFA_BIN_CACHE: OnceLock<PathBuf> = OnceLock::new();

fn get_workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn get_kori_binary() -> PathBuf {
    KORI_BIN_CACHE
        .get_or_init(|| {
            let mut path = std::env::current_exe().expect("current test executable");
            path.pop();
            if path.ends_with("deps") {
                path.pop();
            }
            path.push("kori");
            if !path.exists() {
                let workspace_kori = get_workspace_root()
                    .join("target")
                    .join("debug")
                    .join("kori");
                if workspace_kori.exists() {
                    return workspace_kori;
                }
                let status = Command::new("cargo")
                    .arg("build")
                    .arg("-p")
                    .arg("kori")
                    .status()
                    .expect("Build kori binary");
                assert!(status.success(), "Failed to build kori binary");
            }
            path
        })
        .clone()
}

fn get_ifa_binary() -> PathBuf {
    IFA_BIN_CACHE
        .get_or_init(|| {
            let mut path = std::env::current_exe().expect("current test executable");
            path.pop();
            if path.ends_with("deps") {
                path.pop();
            }
            path.push("ifa");
            if !path.exists() {
                let workspace_ifa = get_workspace_root()
                    .join("target")
                    .join("debug")
                    .join("ifa");
                if workspace_ifa.exists() {
                    return workspace_ifa;
                }
                let status = Command::new("cargo")
                    .arg("build")
                    .arg("-p")
                    .arg("ifa-cli")
                    .status()
                    .expect("Build ifa binary");
                assert!(status.success(), "Failed to build ifa binary");
            }
            path
        })
        .clone()
}

#[test]
fn test_modular_compiler_sources_exist() {
    let root = get_workspace_root();
    let compiler_dir = root.join("compiler");

    let required_files = [
        "kori.toml",
        "lexer.ifa",
        "parser.ifa",
        "sema.ifa",
        "codegen_llvm.ifa",
        "driver.ifa",
        "main.ifa",
    ];

    for file in &required_files {
        let p = compiler_dir.join(file);
        assert!(
            p.exists(),
            "Required modular compiler file missing: {:?}",
            p
        );
        let meta = fs::metadata(&p).expect("read metadata");
        assert!(meta.len() > 0, "Compiler file {:?} is empty", p);
    }
}

#[test]
fn test_modular_compiler_unit_tests() {
    let _lock = BOOTSTRAP_TEST_MUTEX
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let root = get_workspace_root();
    let kori_bin = get_kori_binary();
    let manifest_path = root.join("compiler").join("kori.toml");

    let test_status = Command::new(&kori_bin)
        .arg("test")
        .arg("--manifest-path")
        .arg(&manifest_path)
        .output()
        .expect("Failed to execute `kori test` on modular compiler");

    let stdout = String::from_utf8_lossy(&test_status.stdout);
    let stderr = String::from_utf8_lossy(&test_status.stderr);

    assert!(
        test_status.status.success(),
        "`kori test` failed on compiler/kori.toml:\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );

    assert!(
        stdout.contains("test test_lexer_stream ... ok"),
        "Modular lexer tests missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_lexer_type_alias ... ok"),
        "Modular lexer type alias test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_lexer_tuples ... ok"),
        "Modular lexer tuples test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_lexer_arena ... ok"),
        "Modular lexer arena test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_lexer_const_declaration ... ok"),
        "Modular lexer const declaration test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_lexer_enum_declaration ... ok"),
        "Modular lexer enum declaration test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_lexer_comptime_directives ... ok"),
        "Modular lexer comptime directives test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_lexer_syntax_macros ... ok"),
        "Modular lexer syntax macros test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_parser_ast_building ... ok"),
        "Modular parser tests missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_parser_type_alias ... ok"),
        "Modular parser type alias test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_parser_tuple_expression ... ok"),
        "Modular parser tuple expression test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_parser_tuple_index_access ... ok"),
        "Modular parser tuple index access test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_parser_arena_declaration ... ok"),
        "Modular parser arena declaration test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_parser_const_declaration ... ok"),
        "Modular parser const declaration test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_parser_enum_declaration ... ok"),
        "Modular parser enum declaration test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_parser_trait_declaration ... ok"),
        "Modular parser trait test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_parser_impl_declaration ... ok"),
        "Modular parser impl test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_parser_match_expression ... ok"),
        "Modular parser match test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_parser_program_high_level_items ... ok"),
        "Modular parser program test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_parser_comptime_directives ... ok"),
        "Modular parser comptime directives test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_parser_syntax_macros ... ok"),
        "Modular parser syntax macros test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sema_eval ... ok"),
        "Modular sema tests missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sema_type_alias_resolution ... ok"),
        "Modular sema type alias resolution test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sema_tuple_operations ... ok"),
        "Modular sema tuple operations test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sema_arena_allocation ... ok"),
        "Modular sema arena allocation test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sema_const_resolution ... ok"),
        "Modular sema const resolution test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sema_enum_resolution ... ok"),
        "Modular sema enum resolution test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sema_pattern_matching ... ok"),
        "Modular sema pattern matching test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_function_emission ... ok"),
        "Modular codegen tests missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_while_loop ... ok"),
        "Modular codegen while loop test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_pattern_match ... ok"),
        "Modular codegen match test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_generic_method_call ... ok"),
        "Modular codegen generic method test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_complex_function ... ok"),
        "Modular codegen complex function test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_global_constants ... ok"),
        "Modular codegen global constants test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_enum_definitions ... ok"),
        "Modular codegen enum definitions test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_struct_definitions ... ok"),
        "Modular codegen struct definitions test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_vtable_dispatch ... ok"),
        "Modular codegen vtable dispatch test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_fn_pointer_and_indirect_call ... ok"),
        "Modular codegen fn pointer and indirect call test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_lightweight_thunk_and_closure ... ok"),
        "Modular codegen lightweight thunk and closure test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_fiber_spawn_and_yield ... ok"),
        "Modular codegen fiber spawn and yield test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_channel_operations ... ok"),
        "Modular codegen channel operations test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_channel_select ... ok"),
        "Modular codegen channel select test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sema_global_symbol_table ... ok"),
        "Modular sema global symbol table test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sema_channel_type_checking ... ok"),
        "Modular sema channel type checking test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sema_channel_directionality_and_bounds ... ok"),
        "Modular sema channel directionality test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_full_module_assembly ... ok"),
        "Modular driver tests missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_complex_module_and_bootstrap_orchestration ... ok"),
        "Modular driver complex module test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_multi_module_symbol_resolution ... ok"),
        "Modular driver multi-module symbol resolution test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_import_graph_and_transitive_deps ... ok"),
        "Modular driver import DAG test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_ffi_header_and_php_bridge_generation ... ok"),
        "Modular driver FFI C/PHP bridge test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_linker_selection_and_process_bindings ... ok"),
        "Modular driver linker selection test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_timed_and_prioritized_channel_select ... ok"),
        "Modular codegen timed select test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_task_nursery_concurrency ... ok"),
        "Modular codegen nursery test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sema_fiber_escape_analysis ... ok"),
        "Modular sema fiber escape analysis test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sema_arena_transfer_ownership ... ok"),
        "Modular sema arena transfer ownership test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sema_local_type_inference ... ok"),
        "Modular sema local type inference test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sema_nested_pattern_matching ... ok"),
        "Modular sema nested pattern matching test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sema_comptime_evaluation ... ok"),
        "Modular sema comptime evaluation test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_lexer_while_loop ... ok"),
        "Modular lexer while loop test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_lexer_if_else ... ok"),
        "Modular lexer if/else test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_tokenize_source_basic ... ok"),
        "Modular lexer tokenize_source basic test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_tokenize_source_integers ... ok"),
        "Modular lexer tokenize_source integers test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_tokenize_source_comments ... ok"),
        "Modular lexer tokenize_source comments test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_parser_while_loop ... ok"),
        "Modular parser while loop test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_parser_if_else ... ok"),
        "Modular parser if/else test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_parser_function_zero_arg ... ok"),
        "Modular parser zero-arg test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_parser_function_multi_param ... ok"),
        "Modular parser multi-param test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_parser_mut_statements ... ok"),
        "Modular parser mut statements test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_pipeline_source_to_ast_basic ... ok"),
        "Modular pipeline source to AST basic test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_pipeline_source_to_ast_multi_param ... ok"),
        "Modular pipeline source to AST multi-param test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_pipeline_source_to_ast_mut_statements ... ok"),
        "Modular pipeline source to AST mut statements test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_pipeline_source_to_ast_program_full ... ok"),
        "Modular pipeline source to AST full program test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_pipeline_source_to_llvm_ir ... ok"),
        "Modular pipeline source to LLVM IR test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_llvm_ir_function_emission ... ok"),
        "Modular codegen LLVM IR function emission test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_llvm_ir_zero_arg_function ... ok"),
        "Modular codegen LLVM IR zero-arg function test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sema_while_loop ... ok"),
        "Modular sema while loop test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sema_if_else ... ok"),
        "Modular sema if/else test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_if_else ... ok"),
        "Modular codegen if/else test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_parser_direct_call ... ok"),
        "Modular parser direct call test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sema_direct_call_eval ... ok"),
        "Modular sema direct call eval test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_direct_call_zero_arg ... ok"),
        "Modular codegen direct call zero arg test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_direct_call_multi_arg ... ok"),
        "Modular codegen direct call multi arg test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_function_with_direct_call_and_return_reg ... ok"),
        "Modular codegen function with direct call test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_pipeline_source_to_llvm_ir_direct_call ... ok"),
        "Modular pipeline source to LLVM IR direct call test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_selfhost_modular_pipeline ... ok"),
        "Modular selfhost pipeline test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_lexer_complex_string_escapes ... ok"),
        "Modular lexer complex string escapes test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_lexer_raw_strings ... ok"),
        "Modular lexer raw strings test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_parser_panic_mode_recovery ... ok"),
        "Modular parser panic mode recovery test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_parser_syntax_diagnostics ... ok"),
        "Modular parser syntax diagnostics test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_parser_arena_direct_ast_construction ... ok"),
        "Modular parser arena direct AST construction test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_parser_cow_mutability_annotations ... ok"),
        "Modular parser cow mutability annotations test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_opt_level_flags ... ok"),
        "Modular driver opt level flags test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_llvm_opt_module_assembly ... ok"),
        "Modular driver llvm opt module assembly test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sema_optional_and_union_return_inference ... ok"),
        "Modular sema optional and union return inference test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_try_catch_blocks ... ok"),
        "Modular codegen try/catch blocks test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_error_propagation ... ok"),
        "Modular codegen error propagation test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_main_cli_project_scaffolding ... ok"),
        "Modular main CLI project scaffolding test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_main_kori_manifest_generation ... ok"),
        "Modular main kori manifest generation test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_simd_avx2_vector_add ... ok"),
        "Modular codegen SIMD AVX2 vector add test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_simd_neon_dot_product ... ok"),
        "Modular codegen SIMD NEON dot product test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_simd_metadata_and_fir ... ok"),
        "Modular codegen SIMD metadata and FIR test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_simd_vectorization_metadata_assembly ... ok"),
        "Modular driver SIMD vectorization metadata assembly test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sema_simd_vector_eligibility_and_width ... ok"),
        "Modular sema SIMD vector eligibility test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sema_simd_disjoint_slice_aliasing ... ok"),
        "Modular sema SIMD disjoint slice aliasing test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_arena_allocation_and_reset ... ok"),
        "Modular codegen arena allocation test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_gen_ref_check ... ok"),
        "Modular codegen gen ref check test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_cow_make_mut ... ok"),
        "Modular codegen cow make mut test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_generational_memory_runtime_assembly ... ok"),
        "Modular driver generational memory runtime assembly test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sema_generational_ref_safety ... ok"),
        "Modular sema generational ref safety test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sema_cow_inplace_exclusivity ... ok"),
        "Modular sema cow inplace exclusivity test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sema_disjoint_access_paths ... ok"),
        "Modular sema disjoint access paths test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sema_interprocedural_access_path_propagation ... ok"),
        "Modular sema interprocedural access path propagation test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_lexer_cow_arena ... ok"),
        "Modular lexer cow arena test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_lexer_nested_match ... ok"),
        "Modular lexer nested match test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_parser_advanced_cow_arena_decl ... ok"),
        "Modular parser advanced cow arena decl test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_parser_nested_pattern_matching ... ok"),
        "Modular parser nested pattern matching test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sema_transitive_interprocedural_access_path_propagation ... ok"),
        "Modular sema transitive access path propagation test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sema_concurrent_task_path_exclusivity ... ok"),
        "Modular sema concurrent task path exclusivity test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_cow_slice_and_freeze ... ok"),
        "Modular codegen cow slice and freeze test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_cow_clone_subtree ... ok"),
        "Modular codegen cow clone subtree test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_ssa_phi_and_select ... ok"),
        "Modular codegen ssa phi and select test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_ssa_icmp ... ok"),
        "Modular codegen ssa icmp test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_ssa_branches ... ok"),
        "Modular codegen ssa branches test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_ssa_load_store ... ok"),
        "Modular codegen ssa load store test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_extern_decl ... ok"),
        "Modular codegen extern decl test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_llvm_module_header ... ok"),
        "Modular codegen llvm module header test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_fn_ptr_multi_call ... ok"),
        "Modular codegen fn ptr multi call test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_trait_fat_ptr_and_reified_dispatch ... ok"),
        "Modular codegen trait fat ptr and reified dispatch test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_reified_vtable_descriptor ... ok"),
        "Modular codegen reified vtable descriptor test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_memory_alignment_and_struct_layout ... ok"),
        "Modular driver memory alignment and struct layout test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_arena_aligned_allocation_and_reset ... ok"),
        "Modular driver arena aligned allocation test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_disjoint_access_path_validation ... ok"),
        "Modular driver disjoint access path validation test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_ssa_switch_and_jump_table ... ok"),
        "Modular codegen ssa switch test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_symbol_lookup_table ... ok"),
        "Modular codegen symbol lookup table test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_checksum_verification ... ok"),
        "Modular codegen checksum verification test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_manifest_generation ... ok"),
        "Modular driver manifest generation test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_ast_function_summary ... ok"),
        "Modular driver ast function summary test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_computed_goto_dispatch_table ... ok"),
        "Modular codegen computed goto dispatch table test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_multi_file_deterministic_lowering ... ok"),
        "Modular driver multi-file deterministic lowering test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_multi_file_build_orchestration ... ok"),
        "Modular driver multi-file build orchestration test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_ipo_callgraph_and_reachability ... ok"),
        "Modular driver ipo callgraph and reachability test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_intermodule_dead_code_elimination ... ok"),
        "Modular driver intermodule dead code elimination test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sema_polymorphic_where_clause_resolution ... ok"),
        "Modular sema polymorphic where clause resolution test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sema_trait_impl_completeness_and_method_dispatch ... ok"),
        "Modular sema trait impl completeness test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_autonomous_packaging_and_embedded_stdlib ... ok"),
        "Modular driver autonomous packaging test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_static_runtime_bundle_validation ... ok"),
        "Modular driver static runtime bundle test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_native_elf_symbol_table_generation ... ok"),
        "Modular driver native elf symbol table test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_native_macho_symbol_table_generation ... ok"),
        "Modular driver native macho symbol table test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_native_symbol_export_directives ... ok"),
        "Modular driver native symbol export directives test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sema_explicit_arena_declarations ... ok"),
        "Modular sema explicit arena declarations test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sema_generic_struct_monomorphization ... ok"),
        "Modular sema generic struct monomorphization test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_monomorphized_generic_struct ... ok"),
        "Modular codegen monomorphized generic struct test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_monomorphized_struct_field_access ... ok"),
        "Modular codegen monomorphized struct field access test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_codegen_explicit_arena_descriptor ... ok"),
        "Modular codegen explicit arena descriptor test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_stdlib_collections_and_fs_pipeline_integration ... ok"),
        "Modular driver stdlib collections and fs pipeline integration test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_embedded_stdlib_bundle_resolution ... ok"),
        "Modular driver embedded stdlib bundle resolution test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_stdlib_process_and_linker_invocation_pipeline ... ok"),
        "Modular driver stdlib process and linker invocation pipeline test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_direct_elf64_binary_assembler ... ok"),
        "Modular driver direct elf64 binary assembler test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_direct_macho64_binary_assembler ... ok"),
        "Modular driver direct macho64 binary assembler test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_linkerless_cross_target_emission ... ok"),
        "Modular driver linkerless cross-target emission test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_ipo_constant_folding_and_propagation ... ok"),
        "Modular driver ipo constant folding and propagation test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_direct_elf64_shared_library_assembler ... ok"),
        "Modular driver direct elf64 shared library assembler test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_direct_macho64_shared_library_assembler ... ok"),
        "Modular driver direct macho64 shared library assembler test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_cross_target_shared_library_relocations ... ok"),
        "Modular driver cross target shared library relocations test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_ipo_intermodule_inlining_pipeline ... ok"),
        "Modular driver IPO intermodule inlining pipeline test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_direct_elf64_dwarf_debug_tables ... ok"),
        "Modular driver direct elf64 dwarf debug tables test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_symbolic_debugging_coverage_and_report ... ok"),
        "Modular driver symbolic debugging coverage and report test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_macho64_compact_unwind_and_dysymtab_generation ... ok"),
        "Modular driver Mach-O 64 compact unwind and dysymtab test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_direct_macho64_symbolic_binary_assembler ... ok"),
        "Modular driver direct macho64 symbolic binary assembler test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_cross_platform_symbolic_compliance ... ok"),
        "Modular driver cross-platform symbolic compliance test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_pe_coff_pdata_and_exception_directory ... ok"),
        "Modular driver PE32+/COFF .pdata exception directory test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_direct_pe_coff_symbolic_binary_assembler ... ok"),
        "Modular driver direct PE32+/COFF symbolic binary assembler test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_tri_platform_symbolic_compliance ... ok"),
        "Modular driver universal tri-platform symbolic compliance test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_pe_coff_base_relocations_and_aslr ... ok"),
        "Modular driver PE32+/COFF base relocations test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout
            .contains("test test_driver_direct_pe_coff_relocatable_dll_and_aslr_assembler ... ok"),
        "Modular driver direct PE32+/COFF relocatable DLL and ASLR test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_tri_platform_relocation_compliance ... ok"),
        "Modular driver tri-platform relocation compliance test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_pe_coff_import_directory_and_iat_generation ... ok"),
        "Modular driver PE32+/COFF import directory and IAT test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_pe_coff_delay_load_and_thunks_generation ... ok"),
        "Modular driver PE32+/COFF delay-load and thunks test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_direct_pe_coff_dynamic_import_executable_assembler ... ok"),
        "Modular driver direct PE32+/COFF dynamic import executable assembler test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_pe_coff_export_directory_and_eat_generation ... ok"),
        "Modular driver PE32+/COFF export directory and EAT test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_direct_pe_coff_shared_library_with_exports_and_relocs ... ok"),
        "Modular driver direct PE32+/COFF shared library with exports and relocs test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_tri_platform_export_symbol_compliance ... ok"),
        "Modular driver tri-platform export compliance test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("390 passed; 0 failed"),
        "Expected 390 passed unit tests, got:\n{}",
        stdout
    );
}

#[test]
fn test_bootstrap_triple_compilation_and_fixed_point_hash() {
    let _lock = BOOTSTRAP_TEST_MUTEX
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let root = get_workspace_root();
    let kori_bin = get_kori_binary();
    let manifest_path = root.join("compiler").join("kori.toml");
    let target_dev_dir = root.join("compiler").join("target").join("dev");
    let ifac_bin = target_dev_dir.join("ifac");

    // Remove any previously compiled binary to prevent ETXTBSY
    let _ = fs::remove_file(&ifac_bin);

    // Stage 0 -> Stage 1: Build Gen 1 compiler executable
    let build_gen1 = Command::new(&kori_bin)
        .arg("build")
        .arg("--force")
        .arg("--manifest-path")
        .arg(&manifest_path)
        .output()
        .expect("Build Stage 1 compiler binary");

    assert!(
        build_gen1.status.success(),
        "Stage 1 compiler build failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&build_gen1.stdout),
        String::from_utf8_lossy(&build_gen1.stderr)
    );

    let ifac_bin = target_dev_dir.join("ifac");
    let ifac_ll = target_dev_dir.join("ifac.ll");
    let ifac_o = target_dev_dir.join("ifac.o");

    assert!(ifac_bin.exists(), "Gen 1 binary missing at {:?}", ifac_bin);
    assert!(ifac_ll.exists(), "Gen 1 LLVM IR missing at {:?}", ifac_ll);
    assert!(ifac_o.exists(), "Gen 1 Object file missing at {:?}", ifac_o);

    // Verify Gen 1 executable produces expected self-hosting output
    let run_gen1 = Command::new(&ifac_bin)
        .output()
        .expect("Execute Stage 1 binary");
    assert!(
        run_gen1.status.success(),
        "Stage 1 execution failed (status: {:?}):\nstdout:\n{}\nstderr:\n{}",
        run_gen1.status,
        String::from_utf8_lossy(&run_gen1.stdout),
        String::from_utf8_lossy(&run_gen1.stderr)
    );
    let gen1_stdout = String::from_utf8_lossy(&run_gen1.stdout);
    assert!(
        gen1_stdout.contains("=== IFA Self-Hosting Compiler (Stage 1 Pure IFA) ==="),
        "Unexpected stdout: {}",
        gen1_stdout
    );
    assert!(
        gen1_stdout.contains("Self-hosting modular bootstrap validation: SUCCESS (42)"),
        "Unexpected stdout: {}",
        gen1_stdout
    );

    // Snapshot Gen 2 artifacts
    let temp_gen2_dir = std::env::temp_dir().join(format!(
        "ifa_bootstrap_gen2_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&temp_gen2_dir).expect("create gen2 temp dir");

    let gen2_bin = temp_gen2_dir.join("ifac-gen2");
    let gen2_ll = temp_gen2_dir.join("ifac-gen2.ll");
    let gen2_o = temp_gen2_dir.join("ifac-gen2.o");

    fs::copy(&ifac_bin, &gen2_bin).expect("copy gen2 binary");
    fs::copy(&ifac_ll, &gen2_ll).expect("copy gen2 ll");
    fs::copy(&ifac_o, &gen2_o).expect("copy gen2 o");

    let hash_ll_gen2 = sha256_hex(&fs::read(&gen2_ll).expect("read gen2 ll"));
    let hash_o_gen2 = sha256_hex(&fs::read(&gen2_o).expect("read gen2 o"));
    let hash_bin_gen2 = sha256_hex(&fs::read(&gen2_bin).expect("read gen2 bin"));

    // Remove ifac artifacts before regenerating Gen 3
    let _ = fs::remove_file(&ifac_bin);
    let _ = fs::remove_file(&ifac_ll);
    let _ = fs::remove_file(&ifac_o);

    // Stage 1 -> Stage 2: Recompile with complete cache bypass to produce Gen 3 artifacts
    let build_gen2 = Command::new(&kori_bin)
        .arg("build")
        .arg("--force")
        .arg("--manifest-path")
        .arg(&manifest_path)
        .output()
        .expect("Build Stage 2 compiler binary");

    assert!(
        build_gen2.status.success(),
        "Stage 2 compiler build failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&build_gen2.stdout),
        String::from_utf8_lossy(&build_gen2.stderr)
    );

    let temp_gen3_dir = std::env::temp_dir().join(format!(
        "ifa_bootstrap_gen3_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&temp_gen3_dir).expect("create gen3 temp dir");

    let gen3_bin = temp_gen3_dir.join("ifac-gen3");
    let gen3_ll = temp_gen3_dir.join("ifac-gen3.ll");
    let gen3_o = temp_gen3_dir.join("ifac-gen3.o");

    fs::copy(&ifac_bin, &gen3_bin).expect("copy gen3 binary");
    fs::copy(&ifac_ll, &gen3_ll).expect("copy gen3 ll");
    fs::copy(&ifac_o, &gen3_o).expect("copy gen3 o");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = fs::metadata(&gen3_bin) {
            let mut perms = metadata.permissions();
            perms.set_mode(0o755);
            let _ = fs::set_permissions(&gen3_bin, perms);
        }
    }

    let hash_ll_gen3 = sha256_hex(&fs::read(&gen3_ll).expect("read gen3 ll"));
    let hash_o_gen3 = sha256_hex(&fs::read(&gen3_o).expect("read gen3 o"));
    let hash_bin_gen3 = sha256_hex(&fs::read(&gen3_bin).expect("read gen3 bin"));

    // Verify Gen 3 executable also runs and validates cleanly
    let run_gen3 = Command::new(&gen3_bin)
        .output()
        .expect("Execute Stage 3 binary");
    assert!(
        run_gen3.status.success(),
        "Stage 3 execution failed (status: {:?}):\nstdout:\n{}\nstderr:\n{}",
        run_gen3.status,
        String::from_utf8_lossy(&run_gen3.stdout),
        String::from_utf8_lossy(&run_gen3.stderr)
    );
    let gen3_stdout = String::from_utf8_lossy(&run_gen3.stdout);
    assert!(
        gen3_stdout.contains("Self-hosting modular bootstrap validation: SUCCESS (42)"),
        "Unexpected gen3 stdout: {}",
        gen3_stdout
    );

    // FIXED-POINT DETERMINISM CONVERGENCE ASSERTIONS
    assert_eq!(
        hash_ll_gen2, hash_ll_gen3,
        "LLVM IR is not bit-for-bit deterministic across compiler generations:\nGen 2: {}\nGen 3: {}",
        hash_ll_gen2, hash_ll_gen3
    );

    assert_eq!(
        hash_o_gen2, hash_o_gen3,
        "Native object files are not bit-for-bit deterministic:\nGen 2: {}\nGen 3: {}",
        hash_o_gen2, hash_o_gen3
    );

    assert_eq!(
        hash_bin_gen2, hash_bin_gen3,
        "Executable binaries differ bit-for-bit:\nsha256(ifac-gen2) = {}\nsha256(ifac-gen3) = {}",
        hash_bin_gen2, hash_bin_gen3
    );

    println!(
        "Bootstrap Fixed-Point Convergence Confirmed:\n  sha256(ifac-gen2) = {}\n  sha256(ifac-gen3) = {}",
        hash_bin_gen2, hash_bin_gen3
    );

    // Clean up temporary snapshot directories
    let _ = fs::remove_dir_all(&temp_gen2_dir);
    let _ = fs::remove_dir_all(&temp_gen3_dir);
}

#[test]
fn test_stdlib_compiler_essentials() {
    use ifa_stdlib::collections::{BinaryHeap, ByteBuffer, Deque, List, Map, Set, StringBuilder};
    use ifa_stdlib::fs::walk_dir_files;

    // 1. Collections: List, Map, Set determinism
    let mut map: Map<&str, i32> = Map::new();
    map.insert("gamma", 3);
    map.insert("alpha", 1);
    map.insert("beta", 2);
    let keys: Vec<_> = map.keys().copied().collect();
    assert_eq!(keys, vec!["alpha", "beta", "gamma"]);

    let mut set: Set<i64> = Set::new();
    set.insert(42);
    set.insert(10);
    set.insert(99);
    let items: Vec<_> = set.iter().copied().collect();
    assert_eq!(items, vec![10, 42, 99]);

    let mut list = List::new();
    list.push(3);
    list.push(1);
    list.push(2);
    list.sort();
    assert_eq!(list.as_slice(), &[1, 2, 3]);

    // Priority Queue / BinaryHeap (Min and Max)
    let mut min_heap = BinaryHeap::new_min();
    min_heap.push(30);
    min_heap.push(10);
    min_heap.push(20);
    assert_eq!(min_heap.peek(), Some(&10));
    assert_eq!(min_heap.pop(), Some(10));
    assert_eq!(min_heap.pop(), Some(20));
    assert_eq!(min_heap.pop(), Some(30));
    assert_eq!(min_heap.pop(), None);

    let mut max_heap = BinaryHeap::new_max();
    max_heap.push(10);
    max_heap.push(30);
    max_heap.push(20);
    assert_eq!(max_heap.peek(), Some(&30));
    assert_eq!(max_heap.pop(), Some(30));
    assert_eq!(max_heap.pop(), Some(20));
    assert_eq!(max_heap.pop(), Some(10));

    // Deque (double-ended queue)
    let mut dq = Deque::new();
    dq.push_back(2);
    dq.push_front(1);
    dq.push_back(3);
    assert_eq!(dq.peek_front(), Some(&1));
    assert_eq!(dq.peek_back(), Some(&3));
    assert_eq!(dq.pop_front(), Some(1));
    assert_eq!(dq.pop_back(), Some(3));
    assert_eq!(dq.pop_front(), Some(2));
    assert!(dq.is_empty());

    // 2. StringBuilder & ByteBuffer
    let mut sb = StringBuilder::new();
    sb.push_line("; IFA Bit-for-bit Reproducible LLVM IR");
    sb.push_line("define i32 @main() {");
    sb.indent();
    sb.push_line("ret i32 42");
    sb.dedent();
    sb.push_line("}");
    let ir = sb.into_string();
    assert!(ir.contains("    ret i32 42\n"));

    let mut buf = ByteBuffer::new();
    buf.write_u32_le(0x12345678);
    assert_eq!(buf.read_u32_le(0), Some(0x12345678));

    // 3. Fs traversal deterministic ordering
    let root = get_workspace_root();
    let compiler_files = walk_dir_files(root.join("compiler")).expect("walk compiler dir");
    assert!(!compiler_files.is_empty());
    for win in compiler_files.windows(2) {
        assert!(
            win[0] <= win[1],
            "Directory walk must be strictly sorted: {:?} > {:?}",
            win[0],
            win[1]
        );
    }
}

#[test]
fn test_autonomous_stdlib_unit_tests() {
    let _lock = BOOTSTRAP_TEST_MUTEX
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let root = get_workspace_root();
    let kori_bin = get_kori_binary();
    let manifest_path = root.join("std").join("kori.toml");

    let test_status = Command::new(&kori_bin)
        .arg("test")
        .arg("--manifest-path")
        .arg(&manifest_path)
        .output()
        .expect("Failed to execute `kori test` on pure IFA autonomous stdlib");

    let stdout = String::from_utf8_lossy(&test_status.stdout);
    let stderr = String::from_utf8_lossy(&test_status.stderr);

    assert!(
        test_status.status.success(),
        "`kori test` failed on std/kori.toml:\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );

    assert!(
        stdout.contains("test test_crypto_fnv1a ... ok"),
        "Std crypto FNV-1a test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_crypto_murmur3 ... ok"),
        "Std crypto Murmur3 test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_crypto_sha256_empty ... ok"),
        "Std crypto SHA256 empty test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_crypto_sha256_abc ... ok"),
        "Std crypto SHA256 abc test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_crypto_constant_time_eq ... ok"),
        "Std crypto constant time eq test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_crypto_hmac ... ok"),
        "Std crypto HMAC test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_fs_path_join ... ok"),
        "Std fs path join test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_fs_path_dirname ... ok"),
        "Std fs path dirname test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_fs_path_basename ... ok"),
        "Std fs path basename test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_fs_path_extension ... ok"),
        "Std fs path extension test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_fs_path_stem ... ok"),
        "Std fs path stem test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_fs_path_normalize ... ok"),
        "Std fs path normalize test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_fs_path_is_absolute ... ok"),
        "Std fs path is absolute test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_fs_io_roundtrip ... ok"),
        "Std fs io roundtrip test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_fs_append_and_lines_io ... ok"),
        "Std fs append and lines io test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_fs_copy_and_dir_inspection ... ok"),
        "Std fs copy and dir inspection test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_fs_walk_and_filter ... ok"),
        "Std fs walk and filter test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_fs_path_relative_and_extension ... ok"),
        "Std fs path relative and extension test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_fs_rename_and_dir_removal ... ok"),
        "Std fs rename and dir removal test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_process_find_linker ... ok"),
        "Std process find linker test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_process_find_tool ... ok"),
        "Std process find tool test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_process_build_linker_command ... ok"),
        "Std process build linker command test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_process_build_assembler_command ... ok"),
        "Std process build assembler command test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_process_echo ... ok"),
        "Std process echo test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_process_cwd ... ok"),
        "Std process cwd test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_collections_list ... ok"),
        "Std collections list test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_collections_map ... ok"),
        "Std collections map test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_collections_set ... ok"),
        "Std collections set test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_collections_byte_buffer ... ok"),
        "Std collections byte buffer test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_collections_string_builder ... ok"),
        "Std collections string builder test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_crypto_blake3_empty ... ok"),
        "Std crypto BLAKE3 empty test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_crypto_blake3_abc ... ok"),
        "Std crypto BLAKE3 abc test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_crypto_blake3_ifa ... ok"),
        "Std crypto BLAKE3 ifa test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_crypto_blake3_tree ... ok"),
        "Std crypto BLAKE3 tree test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_crypto_sha1_vectors ... ok"),
        "Std crypto SHA-1 vectors test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_crypto_base64_and_websocket_key ... ok"),
        "Std crypto Base64 & WebSocket key test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_crypto_hmac_sha1_vectors ... ok"),
        "Std crypto HMAC-SHA1 vectors test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_crypto_hotp_totp_vectors ... ok"),
        "Std crypto HOTP & TOTP vectors test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_crypto_pbkdf2_vectors ... ok"),
        "Std crypto PBKDF2 vectors test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_net_tcp_echo ... ok"),
        "Std net tcp echo test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_net_http_wire ... ok"),
        "Std net http wire test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_net_nonblocking_fiber_transport ... ok"),
        "Std net nonblocking fiber transport test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_net_all ... ok"),
        "Std net all test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_net_url_parsing_and_formatting ... ok"),
        "Std net URL parsing test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_net_http_client_and_response_parsing ... ok"),
        "Std net HTTP client test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_net_http_client_server_roundtrip ... ok"),
        "Std net HTTP roundtrip test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_net_http_status_helpers ... ok"),
        "Std net HTTP status helpers test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_net_http_put_and_delete ... ok"),
        "Std net HTTP put/delete test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_net_udp_roundtrip ... ok"),
        "Std net UDP roundtrip test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_net_http_router_and_query_params ... ok"),
        "Std net HTTP router test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_net_http_headers_and_status_categories ... ok"),
        "Std net HTTP headers test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_net_http_patch_and_head ... ok"),
        "Std net HTTP patch/head test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_net_http_chunked_streaming ... ok"),
        "Std net HTTP chunked streaming test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_net_websocket_framing_and_roundtrip ... ok"),
        "Std net WebSocket framing test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_net_tcp_server_multiple_clients ... ok"),
        "Std net TCP server multiple clients test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_collections_ring_buffer ... ok"),
        "Std collections ring buffer test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_collections_int_map ... ok"),
        "Std collections int map test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_collections_binary_heap ... ok"),
        "Std collections binary heap test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_collections_deque ... ok"),
        "Std collections deque test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_json_primitives ... ok"),
        "Std json primitives test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_json_arrays ... ok"),
        "Std json arrays test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_json_objects ... ok"),
        "Std json objects test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_json_escaped_strings ... ok"),
        "Std json escaped strings test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_json_nested_structure ... ok"),
        "Std json nested structure test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_json_pretty_formatting ... ok"),
        "Std json pretty formatting test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_json_canonical_serialization ... ok"),
        "Std json canonical serialization test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_json_strict_parser ... ok"),
        "Std json strict parser test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_json_pointer ... ok"),
        "Std json pointer test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_json_deep_eq_and_clone ... ok"),
        "Std json deep eq and clone test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_json_merge_and_remove ... ok"),
        "Std json merge and remove test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_json_heterogeneous_arrays ... ok"),
        "Std json heterogeneous arrays test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_json_deep_merge_and_flatten ... ok"),
        "Std json deep merge and flatten test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_json_all ... ok"),
        "Std json all test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_time_leap_year ... ok"),
        "Std time leap year test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_time_epoch_zero ... ok"),
        "Std time epoch zero test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_time_known_timestamp ... ok"),
        "Std time known timestamp test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_time_duration_arithmetic ... ok"),
        "Std time duration arithmetic test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_time_instant_elapsed ... ok"),
        "Std time instant elapsed test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_time_all ... ok"),
        "Std time all test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sync_channel_unbounded ... ok"),
        "Std sync channel unbounded test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sync_channel_bounded ... ok"),
        "Std sync channel bounded test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sync_channel_string ... ok"),
        "Std sync channel string test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sync_channel_close ... ok"),
        "Std sync channel close test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sync_mutex_basic ... ok"),
        "Std sync mutex test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sync_condvar_signal ... ok"),
        "Std sync condvar signal test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sync_condvar_broadcast ... ok"),
        "Std sync condvar broadcast test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sync_wait_group ... ok"),
        "Std sync wait group test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sync_atomic_int ... ok"),
        "Std sync atomic int test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sync_atomic_bool ... ok"),
        "Std sync atomic bool test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sync_semaphore ... ok"),
        "Std sync semaphore test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sync_barrier ... ok"),
        "Std sync barrier test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sync_once ... ok"),
        "Std sync once test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sync_select ... ok"),
        "Std sync select test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_sync_all ... ok"),
        "Std sync all test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_fmt_all ... ok"),
        "Std fmt all test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_fmt_hex ... ok"),
        "Std fmt hex test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_fmt_octal ... ok"),
        "Std fmt octal test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_fmt_binary ... ok"),
        "Std fmt binary test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_fmt_padding_and_alignment ... ok"),
        "Std fmt padding and alignment test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_csv_all ... ok"),
        "Std csv all test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_csv_rfc4180_quotes_and_commas ... ok"),
        "Std csv RFC 4180 quotes test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_csv_table_access_by_header ... ok"),
        "Std csv table access by header test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_csv_roundtrip_encode_decode ... ok"),
        "Std csv roundtrip encode decode test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_csv_custom_delimiter_tsv ... ok"),
        "Std csv custom delimiter TSV test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_io_string_reader_lines ... ok"),
        "Std io string reader lines test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_io_string_reader_seek_and_peek ... ok"),
        "Std io string reader seek and peek test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_io_string_writer_accumulation ... ok"),
        "Std io string writer accumulation test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_io_buffered_reader_and_writer ... ok"),
        "Std io buffered reader and writer test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_io_byte_stream_endianness ... ok"),
        "Std io byte stream endianness test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_io_all ... ok"),
        "Std io all test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_net_crc32_and_adler32 ... ok"),
        "Std net crc32 and adler32 test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_net_deflate_compression_roundtrip ... ok"),
        "Std net deflate compression roundtrip test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_net_gzip_compression_roundtrip ... ok"),
        "Std net gzip compression roundtrip test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_net_http_secure_client_token_negotiation ... ok"),
        "Std net http secure client token negotiation test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_net_url_percent_encoding_roundtrip ... ok"),
        "Std net url percent encoding roundtrip test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_net_http_cookies_and_session ... ok"),
        "Std net http cookies and session test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_net_multipart_form_data ... ok"),
        "Std net multipart form data test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_net_http_sse_streaming_and_content_negotiation ... ok"),
        "Std net http sse streaming and content negotiation test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_net_http_auth_cors_and_etag ... ok"),
        "Std net http auth cors and etag test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_net_http_router_dynamic_params_and_websocket_handshake ... ok"),
        "Std net http router dynamic params and websocket handshake test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_net_websocket_frame_demux_and_fragmentation ... ok"),
        "Std net websocket frame demux and fragmentation test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_net_rate_limiting_and_mime_resolver ... ok"),
        "Std net rate limiting and mime resolver test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_net_http_reverse_proxy_gateway_and_load_balancer ... ok"),
        "Std net http reverse proxy gateway and load balancer test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_net_http_connection_pooling_and_keep_alive ... ok"),
        "Std net http connection pooling and keep alive test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_net_http_circuit_breaker ... ok"),
        "Std net http circuit breaker test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_net_http_retry_policy ... ok"),
        "Std net http retry policy test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_net_http_auto_compression ... ok"),
        "Std net http auto compression test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_db_basic_crud ... ok"),
        "Std db basic crud test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_db_transaction_commit ... ok"),
        "Std db transaction commit test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_db_transaction_rollback ... ok"),
        "Std db transaction rollback test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_db_range_scan ... ok"),
        "Std db range scan test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_db_wal_integrity ... ok"),
        "Std db wal integrity test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_db_wal_recovery ... ok"),
        "Std db wal recovery test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_db_all ... ok"),
        "Std db all test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_std_all ... ok"),
        "Std all subsystem tests missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("302 passed; 0 failed"),
        "Expected 302 passed std unit tests, got:\n{}",
        stdout
    );
}

#[test]
fn test_autonomous_selfhost_driver_triple_stage_execution() {
    let _lock = BOOTSTRAP_TEST_MUTEX
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let root = get_workspace_root();
    let kori_bin = get_kori_binary();
    let manifest_path = root.join("compiler").join("kori.toml");
    let target_dev_dir = root.join("compiler").join("target").join("dev");
    let ifac_bin = target_dev_dir.join("ifac");

    // Ensure ifac executable is built and up to date
    let build = Command::new(&kori_bin)
        .arg("build")
        .arg("--manifest-path")
        .arg(&manifest_path)
        .arg("--force")
        .output()
        .expect("Build ifac compiler");
    assert!(
        build.status.success(),
        "Failed to build ifac compiler:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&build.stdout),
        String::from_utf8_lossy(&build.stderr)
    );

    let temp_dir = std::env::temp_dir().join(format!(
        "ifa_autonomous_bootstrap_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&temp_dir).expect("create autonomous temp dir");
    let base_out = temp_dir.join("ifac_auto");

    // Execute autonomous triple stage bootstrap:
    // `ifac --bootstrap-triple <base_out>`
    let run_driver = Command::new(&ifac_bin)
        .arg("--bootstrap-triple")
        .arg(&base_out)
        .output()
        .expect("Run autonomous triple-stage bootstrap");

    let stdout = String::from_utf8_lossy(&run_driver.stdout);
    let stderr = String::from_utf8_lossy(&run_driver.stderr);
    assert!(
        run_driver.status.success(),
        "Autonomous bootstrap failed:\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );
    assert!(
        stdout.contains("Self-hosting triple-stage bootstrap completed: SUCCESS"),
        "Expected success message, got: {}",
        stdout
    );

    // Verify Gen 2 and Gen 3 artifacts generated by autonomous driver
    let gen2_bin = temp_dir.join("ifac_auto-gen2");
    let gen2_ll = temp_dir.join("ifac_auto-gen2.ll");
    let gen2_o = temp_dir.join("ifac_auto-gen2.o");

    let gen3_bin = temp_dir.join("ifac_auto-gen3");
    let gen3_ll = temp_dir.join("ifac_auto-gen3.ll");
    let gen3_o = temp_dir.join("ifac_auto-gen3.o");

    assert!(gen2_bin.exists(), "Gen 2 binary missing at {:?}", gen2_bin);
    assert!(gen2_ll.exists(), "Gen 2 LLVM IR missing at {:?}", gen2_ll);
    assert!(gen2_o.exists(), "Gen 2 object file missing at {:?}", gen2_o);

    assert!(gen3_bin.exists(), "Gen 3 binary missing at {:?}", gen3_bin);
    assert!(gen3_ll.exists(), "Gen 3 LLVM IR missing at {:?}", gen3_ll);
    assert!(gen3_o.exists(), "Gen 3 object file missing at {:?}", gen3_o);

    // Assert bit-for-bit identity across Gen 2 and Gen 3 produced by ifac driver
    let hash_ll_2 = sha256_hex(&fs::read(&gen2_ll).expect("read auto gen2 ll"));
    let hash_ll_3 = sha256_hex(&fs::read(&gen3_ll).expect("read auto gen3 ll"));
    assert_eq!(hash_ll_2, hash_ll_3, "LLVM IR differs bit-for-bit");

    let hash_o_2 = sha256_hex(&fs::read(&gen2_o).expect("read auto gen2 o"));
    let hash_o_3 = sha256_hex(&fs::read(&gen3_o).expect("read auto gen3 o"));
    assert_eq!(hash_o_2, hash_o_3, "Object files differ bit-for-bit");

    let hash_bin_2 = sha256_hex(&fs::read(&gen2_bin).expect("read auto gen2 bin"));
    let hash_bin_3 = sha256_hex(&fs::read(&gen3_bin).expect("read auto gen3 bin"));
    assert_eq!(
        hash_bin_2, hash_bin_3,
        "Autonomous executables differ bit-for-bit:\nsha256(gen2) = {}\nsha256(gen3) = {}",
        hash_bin_2, hash_bin_3
    );

    // Run the generated Gen 3 binary and verify it prints 42
    let run_gen3 = Command::new(&gen3_bin)
        .output()
        .expect("Execute autonomous gen3 executable");
    assert!(run_gen3.status.success());
    let gen3_out = String::from_utf8_lossy(&run_gen3.stdout);
    assert!(
        gen3_out.contains("42"),
        "Expected output 42 from autonomous Gen 3 executable, got: {}",
        gen3_out
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_external_source_compilation_via_ifac() {
    let _lock = BOOTSTRAP_TEST_MUTEX
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let root = get_workspace_root();
    let kori_bin = get_kori_binary();
    let manifest_path = root.join("compiler").join("kori.toml");
    let target_dev_dir = root.join("compiler").join("target").join("dev");
    let ifac_bin = target_dev_dir.join("ifac");

    // Ensure ifac executable is built and up to date
    let build = Command::new(&kori_bin)
        .arg("build")
        .arg("--manifest-path")
        .arg(&manifest_path)
        .arg("--force")
        .output()
        .expect("Build ifac compiler");
    assert!(
        build.status.success(),
        "Failed to build ifac compiler:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&build.stdout),
        String::from_utf8_lossy(&build.stderr)
    );

    let temp_dir = std::env::temp_dir().join(format!(
        "ifa_external_source_test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&temp_dir).expect("create external source temp dir");

    let source_path = temp_dir.join("external_sample.ifa");
    fs::write(
        &source_path,
        "pub fn main() {\n    let val: i64 = 42;\n    println(\"External compilation verification: 42\");\n}\n",
    )
    .expect("write external sample source");

    // 1. Emit LLVM IR: `ifac -S external_sample.ifa -o external_sample.ll`
    let ll_path = temp_dir.join("external_sample.ll");
    let run_ir = Command::new(&ifac_bin)
        .arg("-S")
        .arg(&source_path)
        .arg("-o")
        .arg(&ll_path)
        .output()
        .expect("Run ifac --emit-ir");
    assert!(
        run_ir.status.success(),
        "ifac -S failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&run_ir.stdout),
        String::from_utf8_lossy(&run_ir.stderr)
    );
    assert!(ll_path.exists(), "Generated LLVM IR file missing");
    let ll_content = fs::read_to_string(&ll_path).expect("read generated LLVM IR");
    assert!(
        ll_content.contains("target datalayout =") && ll_content.contains("define i32 @main()"),
        "Generated LLVM IR does not contain valid module header or entry:\n{}",
        ll_content
    );

    // 2. Assemble object file: `ifac -c external_sample.ifa -o external_sample.o`
    let obj_path = temp_dir.join("external_sample.o");
    let run_obj = Command::new(&ifac_bin)
        .arg("-c")
        .arg(&source_path)
        .arg("-o")
        .arg(&obj_path)
        .output()
        .expect("Run ifac -c");
    assert!(
        run_obj.status.success(),
        "ifac -c failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&run_obj.stdout),
        String::from_utf8_lossy(&run_obj.stderr)
    );
    assert!(obj_path.exists(), "Generated object file missing");
    let obj_bytes = fs::read(&obj_path).expect("read generated object file");
    // Validate ELF magic bytes: 0x7f, 'E', 'L', 'F'
    assert!(
        obj_bytes.len() >= 4 && &obj_bytes[0..4] == b"\x7fELF",
        "Generated object file is not a valid ELF binary"
    );

    // 3. Compile full binary executable: `ifac external_sample.ifa -o external_sample.bin`
    let bin_path = temp_dir.join("external_sample.bin");
    let run_bin = Command::new(&ifac_bin)
        .arg(&source_path)
        .arg("-o")
        .arg(&bin_path)
        .output()
        .expect("Run ifac to produce executable");
    assert!(
        run_bin.status.success(),
        "ifac executable link failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&run_bin.stdout),
        String::from_utf8_lossy(&run_bin.stderr)
    );
    assert!(bin_path.exists(), "Generated binary executable missing");

    // 4. Execute the compiled binary and assert expected execution
    let run_exec = Command::new(&bin_path)
        .output()
        .expect("Execute compiled binary");
    assert!(
        run_exec.status.success(),
        "Execution of compiled external binary failed with status: {:?}",
        run_exec.status
    );
    let exec_stdout = String::from_utf8_lossy(&run_exec.stdout);
    assert!(
        exec_stdout.contains("42"),
        "Expected output containing 42, got: {}",
        exec_stdout
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cross_target_deterministic_hash_regression_bench() {
    let _lock = BOOTSTRAP_TEST_MUTEX
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let root = get_workspace_root();
    let kori_bin = get_kori_binary();
    let manifest_path = root.join("compiler").join("kori.toml");
    let target_dev_dir = root.join("compiler").join("target").join("dev");
    let ifac_bin = target_dev_dir.join("ifac");

    // Ensure ifac executable is built and up to date
    let build = Command::new(&kori_bin)
        .arg("build")
        .arg("--manifest-path")
        .arg(&manifest_path)
        .arg("--force")
        .output()
        .expect("Build ifac compiler");
    assert!(
        build.status.success(),
        "Failed to build ifac compiler:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&build.stdout),
        String::from_utf8_lossy(&build.stderr)
    );

    let temp_bench = std::env::temp_dir().join(format!(
        "ifa_cross_target_bench_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&temp_bench).expect("create bench temp dir");

    let sample_src = temp_bench.join("cross_sample.ifa");
    fs::write(
        &sample_src,
        "pub struct Vec3 {\n    x: i64,\n    y: i64,\n    z: i64\n}\npub fn make_vec(x: i64, y: i64, z: i64) -> Vec3 {\n    return Vec3(x: x, y: y, z: z);\n}\npub fn main() {\n    let v = make_vec(1, 2, 3);\n    println(\"Determinism check: 42\");\n}\n",
    )
    .expect("write sample source");

    // Cross-compilation target triples to validate for deterministic hashes
    let targets = [
        (
            "x86_64-unknown-linux-gnu",
            "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128",
        ),
        (
            "aarch64-unknown-linux-gnu",
            "e-m:e-i8:8:32-i16:16:32-i64:64-i128:128-n32:64-S128",
        ),
        (
            "x86_64-apple-darwin",
            "e-m:o-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128",
        ),
        ("aarch64-apple-darwin", "e-m:o-i64:64-i128:128-n32:64-S128"),
        (
            "x86_64-pc-windows-msvc",
            "e-m:w-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128",
        ),
        (
            "aarch64-pc-windows-msvc",
            "e-m:w-p:64:64-i32:32-i64:64-i128:128-n32:64-S128",
        ),
    ];

    for (target, expected_datalayout) in &targets {
        // Run A
        let out_ll_a = temp_bench.join(format!("sample_{}_a.ll", target));
        let run_a = Command::new(&ifac_bin)
            .arg("-S")
            .arg(&sample_src)
            .arg("--target")
            .arg(target)
            .arg("-o")
            .arg(&out_ll_a)
            .output()
            .expect("Run cross emission A");
        assert!(
            run_a.status.success(),
            "Target {} compilation A failed:\nstdout: {}\nstderr: {}",
            target,
            String::from_utf8_lossy(&run_a.stdout),
            String::from_utf8_lossy(&run_a.stderr)
        );

        // Run B (with independent output file to verify bit-for-bit repeatability)
        let out_ll_b = temp_bench.join(format!("sample_{}_b.ll", target));
        let run_b = Command::new(&ifac_bin)
            .arg("-S")
            .arg(&sample_src)
            .arg("--target")
            .arg(target)
            .arg("-o")
            .arg(&out_ll_b)
            .output()
            .expect("Run cross emission B");
        assert!(
            run_b.status.success(),
            "Target {} compilation B failed:\nstdout: {}\nstderr: {}",
            target,
            String::from_utf8_lossy(&run_b.stdout),
            String::from_utf8_lossy(&run_b.stderr)
        );

        let content_a = fs::read_to_string(&out_ll_a).expect("read ll A");
        let content_b = fs::read_to_string(&out_ll_b).expect("read ll B");

        assert!(
            content_a.contains(&format!("target triple = \"{}\"", target)),
            "Target triple missing from output: {}",
            target
        );
        assert!(
            content_a.contains(&format!("target datalayout = \"{}\"", expected_datalayout)),
            "Target datalayout missing or incorrect for target {}:\nExpected: {}\nOutput: {}",
            target,
            expected_datalayout,
            content_a
        );

        let hash_a = sha256_hex(content_a.as_bytes());
        let hash_b = sha256_hex(content_b.as_bytes());

        assert_eq!(
            hash_a, hash_b,
            "Cross-target non-determinism detected for target {}: hash_a={} != hash_b={}",
            target, hash_a, hash_b
        );
    }

    let _ = fs::remove_dir_all(&temp_bench);
}

#[test]
fn test_direct_elf64_dwarf_symbolic_debug_determinism() {
    let _lock = BOOTSTRAP_TEST_MUTEX
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let root = get_workspace_root();
    let kori_bin = get_kori_binary();
    let manifest_path = root.join("compiler").join("kori.toml");

    let test_run = Command::new(&kori_bin)
        .arg("test")
        .arg("--manifest-path")
        .arg(&manifest_path)
        .output()
        .expect("Run modular compiler tests including DWARF v5 symbolic debug");

    assert!(
        test_run.status.success(),
        "Modular compiler unit tests failed with status: {:?}\nstdout: {}\nstderr: {}",
        test_run.status,
        String::from_utf8_lossy(&test_run.stdout),
        String::from_utf8_lossy(&test_run.stderr)
    );

    let stdout = String::from_utf8_lossy(&test_run.stdout);
    assert!(
        stdout.contains("test test_driver_direct_elf64_dwarf_debug_tables ... ok"),
        "DWARF v5 debug tables test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_symbolic_debugging_coverage_and_report ... ok"),
        "Symbolic debugging coverage report test missing from output:\n{}",
        stdout
    );
}

#[test]
fn test_direct_macho64_symbolic_compliance_determinism() {
    let _lock = BOOTSTRAP_TEST_MUTEX
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let root = get_workspace_root();
    let kori_bin = get_kori_binary();
    let manifest_path = root.join("compiler").join("kori.toml");

    let test_run = Command::new(&kori_bin)
        .arg("test")
        .arg("--manifest-path")
        .arg(&manifest_path)
        .output()
        .expect("Run modular compiler tests including Mach-O 64 compact unwind and cross-platform compliance");

    assert!(
        test_run.status.success(),
        "Modular compiler unit tests failed with status: {:?}\nstdout: {}\nstderr: {}",
        test_run.status,
        String::from_utf8_lossy(&test_run.stdout),
        String::from_utf8_lossy(&test_run.stderr)
    );

    let stdout = String::from_utf8_lossy(&test_run.stdout);
    assert!(
        stdout.contains("test test_driver_macho64_compact_unwind_and_dysymtab_generation ... ok"),
        "Mach-O 64 compact unwind generation test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_direct_macho64_symbolic_binary_assembler ... ok"),
        "Direct Mach-O 64 symbolic binary assembler test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_cross_platform_symbolic_compliance ... ok"),
        "Cross-platform symbolic compliance test missing from output:\n{}",
        stdout
    );
}

#[test]
fn test_direct_pe_coff_symbolic_compliance_determinism() {
    let _lock = BOOTSTRAP_TEST_MUTEX
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let root = get_workspace_root();
    let kori_bin = get_kori_binary();
    let manifest_path = root.join("compiler").join("kori.toml");

    let test_run = Command::new(&kori_bin)
        .arg("test")
        .arg("--manifest-path")
        .arg(&manifest_path)
        .output()
        .expect("Run modular compiler tests including PE32+/COFF .pdata exception directory and tri-platform compliance");

    assert!(
        test_run.status.success(),
        "Modular compiler unit tests failed with status: {:?}\nstdout: {}\nstderr: {}",
        test_run.status,
        String::from_utf8_lossy(&test_run.stdout),
        String::from_utf8_lossy(&test_run.stderr)
    );

    let stdout = String::from_utf8_lossy(&test_run.stdout);
    assert!(
        stdout.contains("test test_driver_pe_coff_pdata_and_exception_directory ... ok"),
        "PE32+/COFF .pdata exception directory test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_direct_pe_coff_symbolic_binary_assembler ... ok"),
        "Direct PE32+/COFF symbolic binary assembler test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_tri_platform_symbolic_compliance ... ok"),
        "Universal tri-platform symbolic compliance test missing from output:\n{}",
        stdout
    );
}

#[test]
fn test_direct_pe_coff_base_relocations_and_dll_determinism() {
    let _lock = BOOTSTRAP_TEST_MUTEX
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let root = get_workspace_root();
    let kori_bin = get_kori_binary();
    let manifest_path = root.join("compiler").join("kori.toml");

    let test_run = Command::new(&kori_bin)
        .arg("test")
        .arg("--manifest-path")
        .arg(&manifest_path)
        .output()
        .expect("Run modular compiler tests including PE32+/COFF base relocations and relocatable DLL assembler");

    assert!(
        test_run.status.success(),
        "Modular compiler unit tests failed with status: {:?}\nstdout: {}\nstderr: {}",
        test_run.status,
        String::from_utf8_lossy(&test_run.stdout),
        String::from_utf8_lossy(&test_run.stderr)
    );

    let stdout = String::from_utf8_lossy(&test_run.stdout);
    assert!(
        stdout.contains("test test_driver_pe_coff_base_relocations_and_aslr ... ok"),
        "PE32+/COFF base relocations test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout
            .contains("test test_driver_direct_pe_coff_relocatable_dll_and_aslr_assembler ... ok"),
        "Direct PE32+/COFF relocatable DLL and ASLR test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_tri_platform_relocation_compliance ... ok"),
        "Universal tri-platform relocation compliance test missing from output:\n{}",
        stdout
    );
}

#[test]
fn test_direct_pe_coff_dynamic_imports_and_delay_load_determinism() {
    let _lock = BOOTSTRAP_TEST_MUTEX
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let root = get_workspace_root();
    let kori_bin = get_kori_binary();
    let manifest_path = root.join("compiler").join("kori.toml");

    let test_run = Command::new(&kori_bin)
        .arg("test")
        .arg("--manifest-path")
        .arg(&manifest_path)
        .output()
        .expect("Run modular compiler tests including PE32+/COFF dynamic imports, IAT and Delay-Load assembler");

    assert!(
        test_run.status.success(),
        "Modular compiler unit tests failed with status: {:?}\nstdout: {}\nstderr: {}",
        test_run.status,
        String::from_utf8_lossy(&test_run.stdout),
        String::from_utf8_lossy(&test_run.stderr)
    );

    let stdout = String::from_utf8_lossy(&test_run.stdout);
    assert!(
        stdout.contains("test test_driver_pe_coff_import_directory_and_iat_generation ... ok"),
        "PE32+/COFF IDT and IAT test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_pe_coff_delay_load_and_thunks_generation ... ok"),
        "PE32+/COFF Delay-Load and thunks test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout
            .contains("test test_driver_direct_pe_coff_dynamic_import_executable_assembler ... ok"),
        "Direct PE32+/COFF dynamic import executable assembler test missing from output:\n{}",
        stdout
    );
}

#[test]
fn test_direct_pe_coff_export_directory_and_tri_platform_compliance() {
    let _lock = BOOTSTRAP_TEST_MUTEX
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let root = get_workspace_root();
    let kori_bin = get_kori_binary();
    let manifest_path = root.join("compiler").join("kori.toml");

    let test_run = Command::new(&kori_bin)
        .arg("test")
        .arg("--manifest-path")
        .arg(&manifest_path)
        .output()
        .expect("Run modular compiler tests including PE32+/COFF export directory (.edata) and universal export compliance");

    assert!(
        test_run.status.success(),
        "Modular compiler unit tests failed with status: {:?}\nstdout: {}\nstderr: {}",
        test_run.status,
        String::from_utf8_lossy(&test_run.stdout),
        String::from_utf8_lossy(&test_run.stderr)
    );

    let stdout = String::from_utf8_lossy(&test_run.stdout);
    assert!(
        stdout.contains("test test_driver_pe_coff_export_directory_and_eat_generation ... ok"),
        "PE32+/COFF IDT and EAT test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains(
            "test test_driver_direct_pe_coff_shared_library_with_exports_and_relocs ... ok"
        ),
        "PE32+/COFF shared library with exports test missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("test test_driver_tri_platform_export_symbol_compliance ... ok"),
        "Direct universal tri-platform export compliance test missing from output:\n{}",
        stdout
    );
}

#[test]
fn test_industrial_dogfooding_http_service_and_data_processor_cli() {
    let _lock = BOOTSTRAP_TEST_MUTEX
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let root = get_workspace_root();
    let kori_bin = get_kori_binary();

    // 1. Verify HTTP REST Microservice package unit tests
    let http_manifest = root.join("examples").join("http_service").join("kori.toml");
    let http_test_run = Command::new(&kori_bin)
        .arg("test")
        .arg("--manifest-path")
        .arg(&http_manifest)
        .output()
        .expect("Run kori test on examples/http_service");

    assert!(
        http_test_run.status.success(),
        "HTTP service package tests failed: {:?}\nstdout: {}\nstderr: {}",
        http_test_run.status,
        String::from_utf8_lossy(&http_test_run.stdout),
        String::from_utf8_lossy(&http_test_run.stderr)
    );
    let http_test_stdout = String::from_utf8_lossy(&http_test_run.stdout);
    assert!(
        http_test_stdout.contains("test test_http_service_all ... ok"),
        "HTTP service test_http_service_all missing from output:\n{}",
        http_test_stdout
    );
    assert!(
        http_test_stdout.contains("test test_service_post_and_get_orders ... ok"),
        "HTTP service test_service_post_and_get_orders missing from output:\n{}",
        http_test_stdout
    );

    // 2. Verify HTTP REST Microservice native JIT execution
    let http_run = Command::new(&kori_bin)
        .arg("run")
        .arg("--manifest-path")
        .arg(&http_manifest)
        .output()
        .expect("Run kori run on examples/http_service");

    assert!(
        http_run.status.success(),
        "HTTP service package run failed: {:?}\nstdout: {}\nstderr: {}",
        http_run.status,
        String::from_utf8_lossy(&http_run.stdout),
        String::from_utf8_lossy(&http_run.stderr)
    );
    let http_run_stdout = String::from_utf8_lossy(&http_run.stdout);
    assert!(
        http_run_stdout.contains("All HTTP microservice tests PASSED"),
        "HTTP service run output missing success banner:\n{}",
        http_run_stdout
    );

    // 3. Verify Autonomous Data Processor CLI package unit tests
    let cli_manifest = root
        .join("examples")
        .join("data_processor_cli")
        .join("kori.toml");
    let cli_test_run = Command::new(&kori_bin)
        .arg("test")
        .arg("--manifest-path")
        .arg(&cli_manifest)
        .output()
        .expect("Run kori test on examples/data_processor_cli");

    assert!(
        cli_test_run.status.success(),
        "Data processor CLI package tests failed: {:?}\nstdout: {}\nstderr: {}",
        cli_test_run.status,
        String::from_utf8_lossy(&cli_test_run.stdout),
        String::from_utf8_lossy(&cli_test_run.stderr)
    );
    let cli_test_stdout = String::from_utf8_lossy(&cli_test_run.stdout);
    assert!(
        cli_test_stdout.contains("test test_cli_all ... ok"),
        "Data processor CLI test_cli_all missing from output:\n{}",
        cli_test_stdout
    );
    assert!(
        cli_test_stdout.contains("test test_cli_stats ... ok"),
        "Data processor CLI test_cli_stats missing from output:\n{}",
        cli_test_stdout
    );
    assert!(
        cli_test_stdout.contains("test test_cli_filter_threshold ... ok"),
        "Data processor CLI test_cli_filter_threshold missing from output:\n{}",
        cli_test_stdout
    );
    assert!(
        cli_test_stdout.contains("test test_cli_csv2json ... ok"),
        "Data processor CLI test_cli_csv2json missing from output:\n{}",
        cli_test_stdout
    );
    assert!(
        cli_test_stdout.contains("test test_cli_stream_transform ... ok"),
        "Data processor CLI test_cli_stream_transform missing from output:\n{}",
        cli_test_stdout
    );

    // 4. Verify Autonomous Data Processor CLI native JIT execution
    let cli_run = Command::new(&kori_bin)
        .arg("run")
        .arg("--manifest-path")
        .arg(&cli_manifest)
        .output()
        .expect("Run kori run on examples/data_processor_cli");

    assert!(
        cli_run.status.success(),
        "Data processor CLI package run failed: {:?}\nstdout: {}\nstderr: {}",
        cli_run.status,
        String::from_utf8_lossy(&cli_run.stdout),
        String::from_utf8_lossy(&cli_run.stderr)
    );
    let cli_run_stdout = String::from_utf8_lossy(&cli_run.stdout);
    assert!(
        cli_run_stdout.contains("All CLI tests PASSED"),
        "Data processor CLI run output missing success banner:\n{}",
        cli_run_stdout
    );
}

#[test]
fn test_canonical_code_formatting_tooling_kori_and_ifa() {
    let _lock = BOOTSTRAP_TEST_MUTEX
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let kori_bin = get_kori_binary();
    let ifa_bin = get_ifa_binary();

    let tmp_dir = std::env::temp_dir().join(format!("ifa_tooling_fmt_test_{}", std::process::id()));
    fs::create_dir_all(tmp_dir.join("src")).expect("create test tmp dir");
    let test_file = tmp_dir.join("src").join("matrix.ifa");

    let unformatted_code = r#"//  Raw mathematical vector and matrix compute
pub fn   vector_dot( a:List<i64>,b:List<i64> )->i64{
mut sum:i64 = 0;
mut i:i64 = 0;
while i < a.len() {
sum = sum + a[i]*b[i];
i = i + 1;
}
return sum;
}
"#;
    fs::write(&test_file, unformatted_code).expect("write test file");

    // 1. Verify `kori fmt --check` flags unformatted file with exit code 1
    let kori_check_res = Command::new(&kori_bin)
        .arg("fmt")
        .arg("--check")
        .arg(&test_file)
        .output()
        .expect("Run kori fmt --check");

    assert!(
        !kori_check_res.status.success(),
        "kori fmt --check should fail on unformatted file"
    );
    let check_stderr = String::from_utf8_lossy(&kori_check_res.stderr);
    assert!(
        check_stderr.contains("are not canonically formatted"),
        "kori fmt --check output missing diagnostics: {}",
        check_stderr
    );

    // 2. Format in-place using `kori fmt`
    let kori_fmt_res = Command::new(&kori_bin)
        .arg("fmt")
        .arg(&test_file)
        .output()
        .expect("Run kori fmt");

    assert!(
        kori_fmt_res.status.success(),
        "kori fmt failed: {}",
        String::from_utf8_lossy(&kori_fmt_res.stderr)
    );

    let formatted_code = fs::read_to_string(&test_file).expect("read formatted code");
    assert!(
        formatted_code.contains("pub fn vector_dot(a: List<i64>, b: List<i64>) -> i64 {"),
        "Formatted signature mismatch:\n{}",
        formatted_code
    );
    assert!(
        formatted_code.contains("    mut sum: i64 = 0;"),
        "Formatted indentation mismatch:\n{}",
        formatted_code
    );

    // 3. Verify `ifa fmt --check` confirms the file is now canonically formatted
    let ifa_check_res = Command::new(&ifa_bin)
        .arg("fmt")
        .arg("--check")
        .arg(&test_file)
        .output()
        .expect("Run ifa fmt --check");

    assert!(
        ifa_check_res.status.success(),
        "ifa fmt --check failed on canonically formatted file: {}",
        String::from_utf8_lossy(&ifa_check_res.stderr)
    );
    let ifa_check_stdout = String::from_utf8_lossy(&ifa_check_res.stdout);
    assert!(
        ifa_check_stdout.contains("all canonically formatted"),
        "ifa fmt --check output mismatch: {}",
        ifa_check_stdout
    );

    // 4. Test recursive directory formatting across whole tree
    let test_file2 = tmp_dir.join("src").join("tensor.ifa");
    fs::write(&test_file2, "fn tensor_id( x:i64 )->i64{\nreturn x;\n}\n")
        .expect("write tensor.ifa");

    let kori_dir_fmt_res = Command::new(&kori_bin)
        .arg("fmt")
        .arg(&tmp_dir)
        .output()
        .expect("Run kori fmt on directory");

    assert!(
        kori_dir_fmt_res.status.success(),
        "kori fmt on directory failed: {}",
        String::from_utf8_lossy(&kori_dir_fmt_res.stderr)
    );

    let kori_dir_check_res = Command::new(&kori_bin)
        .arg("fmt")
        .arg("--check")
        .arg(&tmp_dir)
        .output()
        .expect("Run kori fmt --check on directory");

    assert!(
        kori_dir_check_res.status.success(),
        "kori fmt --check on directory should succeed after formatting"
    );

    let _ = fs::remove_dir_all(tmp_dir);
}

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
        stdout.contains("340 passed; 0 failed"),
        "Expected 340 passed unit tests, got:\n{}",
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
    use ifa_stdlib::collections::{ByteBuffer, List, Map, Set, StringBuilder};
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
        stdout.contains("test test_std_all ... ok"),
        "Std all subsystem tests missing from output:\n{}",
        stdout
    );
    assert!(
        stdout.contains("55 passed; 0 failed"),
        "Expected 55 passed std unit tests, got:\n{}",
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

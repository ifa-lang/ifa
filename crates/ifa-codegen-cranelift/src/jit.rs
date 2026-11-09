use crate::error::CodegenError;
use crate::translator::FunctionTranslator;
use crate::types::fir_signature_to_cranelift;
use cranelift_codegen::ir::{types, AbiParam, Signature};
use cranelift_codegen::Context;
use cranelift_frontend::FunctionBuilderContext;
use cranelift_jit::{JITBuilder, JITModule};
use cranelift_module::{FuncId, Linkage, Module};
use ifa_fir::FirModule;
use ifa_runtime::*;
use ifa_span::INTERNER;
use std::collections::HashMap;

/// JIT Execution engine compiling FIR SSA into native machine code in-memory.
pub struct JitEngine {
    builder_context: FunctionBuilderContext,
    ctx: Context,
    module: JITModule,
    func_ids: HashMap<String, FuncId>,
}

impl JitEngine {
    /// Create a new JIT engine initialized with the host machine's native ISA.
    pub fn new() -> Result<Self, CodegenError> {
        let flag_builder = cranelift_codegen::settings::builder();
        let isa_builder = cranelift_native::builder()
            .map_err(|e| CodegenError::Codegen(format!("Failed to build native ISA: {}", e)))?;
        let isa = isa_builder
            .finish(cranelift_codegen::settings::Flags::new(flag_builder))
            .map_err(|e| CodegenError::Codegen(format!("Failed to finish ISA: {}", e)))?;

        let mut builder = JITBuilder::with_isa(isa, cranelift_module::default_libcall_names());
        builder.symbol("println", ifa_rt_println as *const u8);
        builder.symbol("ifa_rt_println", ifa_rt_println as *const u8);
        builder.symbol("ifa_rt_print", ifa_rt_print as *const u8);
        builder.symbol("ifa_rt_println_i64", ifa_rt_println_i64 as *const u8);
        builder.symbol("ifa_rt_print_i64", ifa_rt_print_i64 as *const u8);
        builder.symbol("ifa_rt_gen_alloc", ifa_rt_gen_alloc as *const u8);
        builder.symbol("ifa_rt_gen_free", ifa_rt_gen_free as *const u8);
        builder.symbol("ifa_rt_gen_check", ifa_rt_gen_check as *const u8);
        builder.symbol(
            "ifa_rt_call_arena_alloc",
            ifa_rt_call_arena_alloc as *const u8,
        );
        builder.symbol(
            "ifa_rt_call_arena_mark",
            ifa_rt_call_arena_mark as *const u8,
        );
        builder.symbol(
            "ifa_rt_call_arena_rewind",
            ifa_rt_call_arena_rewind as *const u8,
        );
        builder.symbol(
            "ifa_rt_call_arena_reset",
            ifa_rt_call_arena_reset as *const u8,
        );
        builder.symbol(
            "ifa_rt_call_arena_capacity",
            ifa_rt_call_arena_capacity as *const u8,
        );
        builder.symbol(
            "ifa_rt_call_arena_high_water_mark",
            ifa_rt_call_arena_high_water_mark as *const u8,
        );
        builder.symbol(
            "ifa_rt_call_arena_shrink_to_fit",
            ifa_rt_call_arena_shrink_to_fit as *const u8,
        );
        builder.symbol("ifa_rt_fiber_yield", ifa_rt_fiber_yield as *const u8);
        builder.symbol("ifa_rt_channel_create", ifa_rt_channel_create as *const u8);
        builder.symbol(
            "ifa_rt_channel_destroy",
            ifa_rt_channel_destroy as *const u8,
        );
        builder.symbol("ifa_rt_channel_send", ifa_rt_channel_send as *const u8);
        builder.symbol(
            "ifa_rt_channel_try_send",
            ifa_rt_channel_try_send as *const u8,
        );
        builder.symbol("ifa_rt_channel_recv", ifa_rt_channel_recv as *const u8);
        builder.symbol(
            "ifa_rt_channel_try_recv",
            ifa_rt_channel_try_recv as *const u8,
        );
        builder.symbol("ifa_rt_channel_close", ifa_rt_channel_close as *const u8);
        builder.symbol(
            "ifa_rt_channel_is_closed",
            ifa_rt_channel_is_closed as *const u8,
        );
        builder.symbol("ifa_rt_channel_len", ifa_rt_channel_len as *const u8);
        builder.symbol(
            "ifa_rt_channel_capacity",
            ifa_rt_channel_capacity as *const u8,
        );
        builder.symbol("ifa_rt_channel_select", ifa_rt_channel_select as *const u8);
        builder.symbol(
            "ifa_rt_channel_select_prioritized",
            ifa_rt_channel_select_prioritized as *const u8,
        );
        builder.symbol(
            "ifa_rt_channel_select_timed",
            ifa_rt_channel_select_timed as *const u8,
        );
        builder.symbol("ifa_rt_now_ns", ifa_rt_now_ns as *const u8);
        builder.symbol("ifa_rt_string_concat", ifa_rt_string_concat as *const u8);
        builder.symbol(
            "ifa_rt_string_eq",
            ifa_runtime::ffi::ifa_rt_string_eq as *const u8,
        );
        builder.symbol(
            "ifa_rt_string_from_i64",
            ifa_rt_string_from_i64 as *const u8,
        );
        builder.symbol(
            "ifa_rt_string_from_f64",
            ifa_rt_string_from_f64 as *const u8,
        );
        builder.symbol(
            "ifa_rt_string_from_bool",
            ifa_rt_string_from_bool as *const u8,
        );
        builder.symbol(
            "ifa_rt_args_count",
            ifa_runtime::ffi::ifa_rt_args_count as *const u8,
        );
        builder.symbol(
            "ifa_rt_args_get",
            ifa_runtime::ffi::ifa_rt_args_get as *const u8,
        );
        builder.symbol(
            "ifa_rt_process_exec",
            ifa_runtime::ffi::ifa_rt_process_exec as *const u8,
        );
        builder.symbol(
            "ifa_rt_process_exec_output",
            ifa_runtime::ffi::ifa_rt_process_exec_output as *const u8,
        );
        builder.symbol(
            "ifa_rt_process_exec_stderr",
            ifa_runtime::ffi::ifa_rt_process_exec_stderr as *const u8,
        );
        builder.symbol(
            "ifa_rt_process_exec_with_stdin",
            ifa_runtime::ffi::ifa_rt_process_exec_with_stdin as *const u8,
        );
        builder.symbol(
            "ifa_rt_process_find_linker",
            ifa_runtime::ffi::ifa_rt_process_find_linker as *const u8,
        );
        builder.symbol(
            "ifa_rt_process_find_tool",
            ifa_runtime::ffi::ifa_rt_process_find_tool as *const u8,
        );
        builder.symbol("ifa_rt_coro_create", ifa_rt_coro_create as *const u8);
        builder.symbol(
            "ifa_rt_coro_create_custom",
            ifa_rt_coro_create_custom as *const u8,
        );
        builder.symbol("ifa_rt_coro_resume", ifa_rt_coro_resume as *const u8);
        builder.symbol("ifa_rt_coro_spawn", ifa_rt_coro_spawn as *const u8);
        builder.symbol("ifa_rt_coro_is_done", ifa_rt_coro_is_done as *const u8);
        builder.symbol("ifa_rt_coro_status", ifa_rt_coro_status as *const u8);
        builder.symbol("ifa_rt_coro_frame", ifa_rt_coro_frame as *const u8);
        builder.symbol("ifa_rt_coro_destroy", ifa_rt_coro_destroy as *const u8);

        // Multi-arena SIMD convolution & tensor stencil primitives
        builder.symbol(
            "ifa_simd_multi_arena_conv2d_f32",
            ifa_simd_multi_arena_conv2d_f32 as *const u8,
        );
        builder.symbol(
            "ifa_simd_multi_arena_conv2d_f64",
            ifa_simd_multi_arena_conv2d_f64 as *const u8,
        );
        builder.symbol(
            "ifa_simd_multi_arena_conv2d_i64",
            ifa_simd_multi_arena_conv2d_i64 as *const u8,
        );
        builder.symbol(
            "ifa_simd_multi_arena_conv3d_f32",
            ifa_simd_multi_arena_conv3d_f32 as *const u8,
        );
        builder.symbol(
            "ifa_simd_multi_arena_conv3d_f64",
            ifa_simd_multi_arena_conv3d_f64 as *const u8,
        );
        builder.symbol(
            "ifa_simd_multi_arena_conv3d_i64",
            ifa_simd_multi_arena_conv3d_i64 as *const u8,
        );
        builder.symbol(
            "ifa_simd_multi_arena_dilated_conv2d_f32",
            ifa_simd_multi_arena_dilated_conv2d_f32 as *const u8,
        );
        builder.symbol(
            "ifa_simd_multi_arena_dilated_conv2d_f64",
            ifa_simd_multi_arena_dilated_conv2d_f64 as *const u8,
        );
        builder.symbol(
            "ifa_simd_multi_arena_dilated_conv2d_i64",
            ifa_simd_multi_arena_dilated_conv2d_i64 as *const u8,
        );
        builder.symbol(
            "ifa_simd_multi_arena_maxpool2d_f32",
            ifa_simd_multi_arena_maxpool2d_f32 as *const u8,
        );
        builder.symbol(
            "ifa_simd_multi_arena_maxpool2d_f64",
            ifa_simd_multi_arena_maxpool2d_f64 as *const u8,
        );
        builder.symbol(
            "ifa_simd_multi_arena_maxpool2d_i64",
            ifa_simd_multi_arena_maxpool2d_i64 as *const u8,
        );
        builder.symbol(
            "ifa_simd_multi_arena_avgpool2d_f32",
            ifa_simd_multi_arena_avgpool2d_f32 as *const u8,
        );
        builder.symbol(
            "ifa_simd_multi_arena_avgpool2d_f64",
            ifa_simd_multi_arena_avgpool2d_f64 as *const u8,
        );
        builder.symbol(
            "ifa_simd_multi_arena_avgpool2d_i64",
            ifa_simd_multi_arena_avgpool2d_i64 as *const u8,
        );
        builder.symbol(
            "ifa_simd_multi_arena_depthwise_conv2d_f32",
            ifa_simd_multi_arena_depthwise_conv2d_f32 as *const u8,
        );
        builder.symbol(
            "ifa_simd_multi_arena_depthwise_conv2d_f64",
            ifa_simd_multi_arena_depthwise_conv2d_f64 as *const u8,
        );
        builder.symbol(
            "ifa_simd_multi_arena_depthwise_conv2d_i64",
            ifa_simd_multi_arena_depthwise_conv2d_i64 as *const u8,
        );
        builder.symbol(
            "ifa_simd_multi_arena_pointwise_conv2d_f32",
            ifa_simd_multi_arena_pointwise_conv2d_f32 as *const u8,
        );
        builder.symbol(
            "ifa_simd_multi_arena_pointwise_conv2d_f64",
            ifa_simd_multi_arena_pointwise_conv2d_f64 as *const u8,
        );
        builder.symbol(
            "ifa_simd_multi_arena_pointwise_conv2d_i64",
            ifa_simd_multi_arena_pointwise_conv2d_i64 as *const u8,
        );
        builder.symbol(
            "ifa_simd_multi_arena_batch_norm2d_f32",
            ifa_simd_multi_arena_batch_norm2d_f32 as *const u8,
        );
        builder.symbol(
            "ifa_simd_multi_arena_batch_norm2d_f64",
            ifa_simd_multi_arena_batch_norm2d_f64 as *const u8,
        );
        builder.symbol(
            "ifa_simd_multi_arena_slice_dot_f32",
            ifa_simd_multi_arena_slice_dot_f32 as *const u8,
        );
        builder.symbol(
            "ifa_simd_multi_arena_slice_dot_f64",
            ifa_simd_multi_arena_slice_dot_f64 as *const u8,
        );
        builder.symbol(
            "ifa_simd_multi_arena_slice_dot_i32",
            ifa_simd_multi_arena_slice_dot_i32 as *const u8,
        );
        builder.symbol(
            "ifa_simd_multi_arena_slice_dot_i64",
            ifa_simd_multi_arena_slice_dot_i64 as *const u8,
        );
        builder.symbol(
            "ifa_simd_multi_arena_tripartite_f32",
            ifa_simd_multi_arena_tripartite_f32 as *const u8,
        );
        builder.symbol(
            "ifa_simd_multi_arena_tripartite_f64",
            ifa_simd_multi_arena_tripartite_f64 as *const u8,
        );
        builder.symbol(
            "ifa_simd_arena_slice_count_if_gt_f32",
            ifa_simd_arena_slice_count_if_gt_f32 as *const u8,
        );
        builder.symbol(
            "ifa_simd_arena_slice_count_if_gt_f64",
            ifa_simd_arena_slice_count_if_gt_f64 as *const u8,
        );
        builder.symbol(
            "ifa_simd_arena_slice_count_if_gt_i32",
            ifa_simd_arena_slice_count_if_gt_i32 as *const u8,
        );
        builder.symbol(
            "ifa_simd_arena_slice_count_if_gt_i64",
            ifa_simd_arena_slice_count_if_gt_i64 as *const u8,
        );

        let module = JITModule::new(builder);

        Ok(Self {
            builder_context: FunctionBuilderContext::new(),
            ctx: module.make_context(),
            module,
            func_ids: HashMap::new(),
        })
    }

    /// Compile all functions in a FIR module into machine code.
    pub fn compile_module(&mut self, fir_module: &FirModule) -> Result<(), CodegenError> {
        let ptr_type = self.module.target_config().pointer_type();
        let call_conv = self.module.target_config().default_call_conv;

        // Register runtime intrinsic signatures
        let mut println_sig = Signature::new(call_conv);
        println_sig.params.push(AbiParam::new(ptr_type));
        let println_id = self
            .module
            .declare_function("println", Linkage::Import, &println_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids.insert("println".into(), println_id);

        let mut print_i64_sig = Signature::new(call_conv);
        print_i64_sig.params.push(AbiParam::new(types::I64));
        let print_i64_id = self
            .module
            .declare_function("ifa_rt_println_i64", Linkage::Import, &print_i64_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_println_i64".into(), print_i64_id);

        let mut gen_alloc_sig = Signature::new(call_conv);
        gen_alloc_sig.params.push(AbiParam::new(ptr_type));
        gen_alloc_sig.params.push(AbiParam::new(ptr_type));
        gen_alloc_sig.params.push(AbiParam::new(types::I32));
        gen_alloc_sig.returns.push(AbiParam::new(ptr_type));
        let gen_alloc_id = self
            .module
            .declare_function("ifa_rt_gen_alloc", Linkage::Import, &gen_alloc_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_gen_alloc".into(), gen_alloc_id);

        let mut gen_free_sig = Signature::new(call_conv);
        gen_free_sig.params.push(AbiParam::new(ptr_type));
        let gen_free_id = self
            .module
            .declare_function("ifa_rt_gen_free", Linkage::Import, &gen_free_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids.insert("ifa_rt_gen_free".into(), gen_free_id);

        let mut gen_check_sig = Signature::new(call_conv);
        gen_check_sig.params.push(AbiParam::new(ptr_type));
        gen_check_sig.params.push(AbiParam::new(types::I32));
        let gen_check_id = self
            .module
            .declare_function("ifa_rt_gen_check", Linkage::Import, &gen_check_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_gen_check".into(), gen_check_id);

        let mut call_alloc_sig = Signature::new(call_conv);
        call_alloc_sig.params.push(AbiParam::new(ptr_type));
        call_alloc_sig.params.push(AbiParam::new(ptr_type));
        call_alloc_sig.returns.push(AbiParam::new(ptr_type));
        let call_alloc_id = self
            .module
            .declare_function("ifa_rt_call_arena_alloc", Linkage::Import, &call_alloc_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_call_arena_alloc".into(), call_alloc_id);

        let mut call_mark_sig = Signature::new(call_conv);
        call_mark_sig.returns.push(AbiParam::new(types::I64));
        let call_mark_id = self
            .module
            .declare_function("ifa_rt_call_arena_mark", Linkage::Import, &call_mark_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_call_arena_mark".into(), call_mark_id);

        let mut call_rewind_sig = Signature::new(call_conv);
        call_rewind_sig.params.push(AbiParam::new(types::I64));
        let call_rewind_id = self
            .module
            .declare_function(
                "ifa_rt_call_arena_rewind",
                Linkage::Import,
                &call_rewind_sig,
            )
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_call_arena_rewind".into(), call_rewind_id);

        let call_reset_sig = Signature::new(call_conv);
        let call_reset_id = self
            .module
            .declare_function("ifa_rt_call_arena_reset", Linkage::Import, &call_reset_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_call_arena_reset".into(), call_reset_id);

        let yield_sig = Signature::new(call_conv);
        let yield_id = self
            .module
            .declare_function("ifa_rt_fiber_yield", Linkage::Import, &yield_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids.insert("ifa_rt_fiber_yield".into(), yield_id);

        let mut chan_create_sig = Signature::new(call_conv);
        chan_create_sig.params.push(AbiParam::new(ptr_type));
        chan_create_sig.returns.push(AbiParam::new(ptr_type));
        let chan_create_id = self
            .module
            .declare_function("ifa_rt_channel_create", Linkage::Import, &chan_create_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_channel_create".into(), chan_create_id);

        let mut chan_send_sig = Signature::new(call_conv);
        chan_send_sig.params.push(AbiParam::new(ptr_type));
        chan_send_sig.params.push(AbiParam::new(ptr_type));
        chan_send_sig.returns.push(AbiParam::new(types::I32));
        let chan_send_id = self
            .module
            .declare_function("ifa_rt_channel_send", Linkage::Import, &chan_send_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_channel_send".into(), chan_send_id);

        let mut chan_recv_sig = Signature::new(call_conv);
        chan_recv_sig.params.push(AbiParam::new(ptr_type));
        chan_recv_sig.params.push(AbiParam::new(ptr_type));
        chan_recv_sig.returns.push(AbiParam::new(types::I32));
        let chan_recv_id = self
            .module
            .declare_function("ifa_rt_channel_recv", Linkage::Import, &chan_recv_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_channel_recv".into(), chan_recv_id);

        let mut chan_try_recv_sig = Signature::new(call_conv);
        chan_try_recv_sig.params.push(AbiParam::new(ptr_type));
        chan_try_recv_sig.params.push(AbiParam::new(ptr_type));
        chan_try_recv_sig.returns.push(AbiParam::new(types::I32));
        let chan_try_recv_id = self
            .module
            .declare_function(
                "ifa_rt_channel_try_recv",
                Linkage::Import,
                &chan_try_recv_sig,
            )
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_channel_try_recv".into(), chan_try_recv_id);

        let mut chan_try_send_sig = Signature::new(call_conv);
        chan_try_send_sig.params.push(AbiParam::new(ptr_type));
        chan_try_send_sig.params.push(AbiParam::new(ptr_type));
        chan_try_send_sig.returns.push(AbiParam::new(types::I32));
        let chan_try_send_id = self
            .module
            .declare_function(
                "ifa_rt_channel_try_send",
                Linkage::Import,
                &chan_try_send_sig,
            )
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_channel_try_send".into(), chan_try_send_id);

        let mut chan_is_closed_sig = Signature::new(call_conv);
        chan_is_closed_sig.params.push(AbiParam::new(ptr_type));
        chan_is_closed_sig.returns.push(AbiParam::new(types::I32));
        let chan_is_closed_id = self
            .module
            .declare_function(
                "ifa_rt_channel_is_closed",
                Linkage::Import,
                &chan_is_closed_sig,
            )
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_channel_is_closed".into(), chan_is_closed_id);

        let mut chan_len_sig = Signature::new(call_conv);
        chan_len_sig.params.push(AbiParam::new(ptr_type));
        chan_len_sig.returns.push(AbiParam::new(types::I64));
        let chan_len_id = self
            .module
            .declare_function("ifa_rt_channel_len", Linkage::Import, &chan_len_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_channel_len".into(), chan_len_id);

        let mut chan_cap_sig = Signature::new(call_conv);
        chan_cap_sig.params.push(AbiParam::new(ptr_type));
        chan_cap_sig.returns.push(AbiParam::new(types::I64));
        let chan_cap_id = self
            .module
            .declare_function("ifa_rt_channel_capacity", Linkage::Import, &chan_cap_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_channel_capacity".into(), chan_cap_id);

        let mut chan_close_sig = Signature::new(call_conv);
        chan_close_sig.params.push(AbiParam::new(ptr_type));
        let chan_close_id = self
            .module
            .declare_function("ifa_rt_channel_close", Linkage::Import, &chan_close_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_channel_close".into(), chan_close_id);

        let mut chan_select_sig = Signature::new(call_conv);
        chan_select_sig.params.push(AbiParam::new(ptr_type));
        chan_select_sig.params.push(AbiParam::new(ptr_type));
        chan_select_sig.params.push(AbiParam::new(types::I32));
        chan_select_sig.returns.push(AbiParam::new(types::I64));
        let chan_select_id = self
            .module
            .declare_function("ifa_rt_channel_select", Linkage::Import, &chan_select_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_channel_select".into(), chan_select_id);

        let mut chan_select_timed_sig = Signature::new(call_conv);
        chan_select_timed_sig.params.push(AbiParam::new(ptr_type));
        chan_select_timed_sig.params.push(AbiParam::new(ptr_type));
        chan_select_timed_sig.params.push(AbiParam::new(ptr_type));
        chan_select_timed_sig.params.push(AbiParam::new(types::I64));
        chan_select_timed_sig.params.push(AbiParam::new(types::I32));
        chan_select_timed_sig
            .returns
            .push(AbiParam::new(types::I64));
        let chan_select_timed_id = self
            .module
            .declare_function(
                "ifa_rt_channel_select_timed",
                Linkage::Import,
                &chan_select_timed_sig,
            )
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_channel_select_timed".into(), chan_select_timed_id);

        let mut str_concat_sig = Signature::new(call_conv);
        str_concat_sig.params.push(AbiParam::new(ptr_type));
        str_concat_sig.params.push(AbiParam::new(ptr_type));
        str_concat_sig.returns.push(AbiParam::new(ptr_type));
        let str_concat_id = self
            .module
            .declare_function("ifa_rt_string_concat", Linkage::Import, &str_concat_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_string_concat".into(), str_concat_id);

        let mut str_eq_sig = Signature::new(call_conv);
        str_eq_sig.params.push(AbiParam::new(ptr_type));
        str_eq_sig.params.push(AbiParam::new(ptr_type));
        str_eq_sig.returns.push(AbiParam::new(types::I8));
        let str_eq_id = self
            .module
            .declare_function("ifa_rt_string_eq", Linkage::Import, &str_eq_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids.insert("ifa_rt_string_eq".into(), str_eq_id);

        let mut str_i64_sig = Signature::new(call_conv);
        str_i64_sig.params.push(AbiParam::new(types::I64));
        str_i64_sig.returns.push(AbiParam::new(ptr_type));
        let str_i64_id = self
            .module
            .declare_function("ifa_rt_string_from_i64", Linkage::Import, &str_i64_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_string_from_i64".into(), str_i64_id);

        let mut str_f64_sig = Signature::new(call_conv);
        str_f64_sig.params.push(AbiParam::new(types::F64));
        str_f64_sig.returns.push(AbiParam::new(ptr_type));
        let str_f64_id = self
            .module
            .declare_function("ifa_rt_string_from_f64", Linkage::Import, &str_f64_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_string_from_f64".into(), str_f64_id);

        let mut str_bool_sig = Signature::new(call_conv);
        str_bool_sig.params.push(AbiParam::new(types::I8));
        str_bool_sig.returns.push(AbiParam::new(ptr_type));
        let str_bool_id = self
            .module
            .declare_function("ifa_rt_string_from_bool", Linkage::Import, &str_bool_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_string_from_bool".into(), str_bool_id);

        let mut args_count_sig = Signature::new(call_conv);
        args_count_sig.returns.push(AbiParam::new(types::I64));
        let args_count_id = self
            .module
            .declare_function("ifa_rt_args_count", Linkage::Import, &args_count_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_args_count".into(), args_count_id);
        self.func_ids
            .insert("process::args_count".into(), args_count_id);
        self.func_ids.insert("args_count".into(), args_count_id);

        let mut args_get_sig = Signature::new(call_conv);
        args_get_sig.params.push(AbiParam::new(types::I64));
        args_get_sig.returns.push(AbiParam::new(ptr_type));
        let args_get_id = self
            .module
            .declare_function("ifa_rt_args_get", Linkage::Import, &args_get_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids.insert("ifa_rt_args_get".into(), args_get_id);
        self.func_ids
            .insert("process::args_get".into(), args_get_id);
        self.func_ids.insert("args_get".into(), args_get_id);

        // Process intrinsics
        let mut proc_exec_sig = Signature::new(call_conv);
        proc_exec_sig.params.push(AbiParam::new(ptr_type));
        proc_exec_sig.params.push(AbiParam::new(ptr_type));
        proc_exec_sig.returns.push(AbiParam::new(types::I64));
        let proc_exec_id = self
            .module
            .declare_function("ifa_rt_process_exec", Linkage::Import, &proc_exec_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_process_exec".into(), proc_exec_id);
        self.func_ids.insert("process::exec".into(), proc_exec_id);

        let mut proc_out_sig = Signature::new(call_conv);
        proc_out_sig.params.push(AbiParam::new(ptr_type));
        proc_out_sig.params.push(AbiParam::new(ptr_type));
        proc_out_sig.returns.push(AbiParam::new(ptr_type));
        let proc_out_id = self
            .module
            .declare_function("ifa_rt_process_exec_output", Linkage::Import, &proc_out_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_process_exec_output".into(), proc_out_id);
        self.func_ids
            .insert("process::exec_output".into(), proc_out_id);

        let proc_err_id = self
            .module
            .declare_function("ifa_rt_process_exec_stderr", Linkage::Import, &proc_out_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_process_exec_stderr".into(), proc_err_id);
        self.func_ids
            .insert("process::exec_stderr".into(), proc_err_id);

        let mut proc_stdin_sig = Signature::new(call_conv);
        proc_stdin_sig.params.push(AbiParam::new(ptr_type));
        proc_stdin_sig.params.push(AbiParam::new(ptr_type));
        proc_stdin_sig.params.push(AbiParam::new(ptr_type));
        proc_stdin_sig.returns.push(AbiParam::new(types::I64));
        let proc_stdin_id = self
            .module
            .declare_function(
                "ifa_rt_process_exec_with_stdin",
                Linkage::Import,
                &proc_stdin_sig,
            )
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_process_exec_with_stdin".into(), proc_stdin_id);
        self.func_ids
            .insert("process::exec_with_stdin".into(), proc_stdin_id);

        let mut proc_find_linker_sig = Signature::new(call_conv);
        proc_find_linker_sig.returns.push(AbiParam::new(ptr_type));
        let proc_find_linker_id = self
            .module
            .declare_function(
                "ifa_rt_process_find_linker",
                Linkage::Import,
                &proc_find_linker_sig,
            )
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_process_find_linker".into(), proc_find_linker_id);
        self.func_ids
            .insert("process::find_linker".into(), proc_find_linker_id);

        let mut proc_find_tool_sig = Signature::new(call_conv);
        proc_find_tool_sig.params.push(AbiParam::new(ptr_type));
        proc_find_tool_sig.returns.push(AbiParam::new(ptr_type));
        let proc_find_tool_id = self
            .module
            .declare_function(
                "ifa_rt_process_find_tool",
                Linkage::Import,
                &proc_find_tool_sig,
            )
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_process_find_tool".into(), proc_find_tool_id);
        self.func_ids
            .insert("process::find_tool".into(), proc_find_tool_id);

        // Register stackless coroutine intrinsics
        let mut coro_create_sig = Signature::new(call_conv);
        coro_create_sig.params.push(AbiParam::new(ptr_type));
        coro_create_sig.params.push(AbiParam::new(ptr_type));
        coro_create_sig.params.push(AbiParam::new(ptr_type));
        coro_create_sig.returns.push(AbiParam::new(ptr_type));
        let coro_create_id = self
            .module
            .declare_function("ifa_rt_coro_create", Linkage::Import, &coro_create_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_coro_create".into(), coro_create_id);

        let mut coro_frame_sig = Signature::new(call_conv);
        coro_frame_sig.params.push(AbiParam::new(ptr_type));
        coro_frame_sig.returns.push(AbiParam::new(ptr_type));
        let coro_frame_id = self
            .module
            .declare_function("ifa_rt_coro_frame", Linkage::Import, &coro_frame_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_coro_frame".into(), coro_frame_id);

        let mut coro_resume_sig = Signature::new(call_conv);
        coro_resume_sig.params.push(AbiParam::new(ptr_type));
        coro_resume_sig.returns.push(AbiParam::new(types::I32));
        let coro_resume_id = self
            .module
            .declare_function("ifa_rt_coro_resume", Linkage::Import, &coro_resume_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_coro_resume".into(), coro_resume_id);

        let mut coro_spawn_sig = Signature::new(call_conv);
        coro_spawn_sig.params.push(AbiParam::new(ptr_type));
        coro_spawn_sig.returns.push(AbiParam::new(types::I64));
        let coro_spawn_id = self
            .module
            .declare_function("ifa_rt_coro_spawn", Linkage::Import, &coro_spawn_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_coro_spawn".into(), coro_spawn_id);

        let mut coro_is_done_sig = Signature::new(call_conv);
        coro_is_done_sig.params.push(AbiParam::new(ptr_type));
        coro_is_done_sig.returns.push(AbiParam::new(types::I32));
        let coro_is_done_id = self
            .module
            .declare_function("ifa_rt_coro_is_done", Linkage::Import, &coro_is_done_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_coro_is_done".into(), coro_is_done_id);

        let mut coro_destroy_sig = Signature::new(call_conv);
        coro_destroy_sig.params.push(AbiParam::new(ptr_type));
        let coro_destroy_id = self
            .module
            .declare_function("ifa_rt_coro_destroy", Linkage::Import, &coro_destroy_sig)
            .map_err(|e| CodegenError::Module(e.to_string()))?;
        self.func_ids
            .insert("ifa_rt_coro_destroy".into(), coro_destroy_id);

        let coro_funcs: std::collections::HashSet<ifa_span::Symbol> = fir_module
            .functions
            .iter()
            .filter(|f| f.is_coroutine())
            .map(|f| f.name)
            .collect();

        // 1. Declare all functions first to enable mutual recursion and forward calls
        for fir_func in &fir_module.functions {
            let fn_name = INTERNER.resolve(&fir_func.name);
            let sig = fir_signature_to_cranelift(fir_func, call_conv, ptr_type)?;
            let linkage = if fir_func.blocks.is_empty() {
                Linkage::Import
            } else if fir_func.is_pub {
                Linkage::Export
            } else {
                Linkage::Local
            };
            let func_id = self
                .module
                .declare_function(&fn_name, linkage, &sig)
                .map_err(|e| CodegenError::Module(e.to_string()))?;
            self.func_ids.insert(fn_name.clone(), func_id);

            if fir_func.is_coroutine() && !fir_func.blocks.is_empty() {
                let resume_name = format!("{}$resume", fn_name);
                let mut resume_sig = Signature::new(call_conv);
                resume_sig.params.push(AbiParam::new(ptr_type));
                resume_sig.returns.push(AbiParam::new(types::I32));
                let resume_func_id = self
                    .module
                    .declare_function(&resume_name, Linkage::Local, &resume_sig)
                    .map_err(|e| CodegenError::Module(e.to_string()))?;
                self.func_ids.insert(resume_name, resume_func_id);
            }
        }

        let struct_defs: HashMap<ifa_span::Symbol, Vec<(ifa_span::Symbol, ifa_fir::FirType)>> =
            fir_module
                .structs
                .iter()
                .map(|s| (s.name, s.fields.clone()))
                .collect();

        let fn_param_types: HashMap<String, Vec<ifa_fir::FirType>> = fir_module
            .functions
            .iter()
            .map(|f| {
                (
                    INTERNER.resolve(&f.name).to_string(),
                    f.params.iter().map(|p| p.ty.clone()).collect(),
                )
            })
            .collect();

        // 2. Translate and define each function
        for fir_func in &fir_module.functions {
            if fir_func.blocks.is_empty() {
                continue;
            }
            let fn_name = INTERNER.resolve(&fir_func.name);

            if fir_func.is_coroutine() {
                // A) Define coroutine resume function
                let resume_name = format!("{}$resume", fn_name);
                let resume_id = self.func_ids[&resume_name];
                let mut resume_sig = Signature::new(call_conv);
                resume_sig.params.push(AbiParam::new(ptr_type));
                resume_sig.returns.push(AbiParam::new(types::I32));
                self.ctx.func.signature = resume_sig;

                {
                    let builder = cranelift_frontend::FunctionBuilder::new(
                        &mut self.ctx.func,
                        &mut self.builder_context,
                    );
                    let translator = FunctionTranslator::new(
                        builder,
                        &mut self.module,
                        &self.func_ids,
                        ptr_type,
                        &struct_defs,
                        &coro_funcs,
                        &fn_param_types,
                    );
                    translator.translate_coroutine_resume(fir_func)?;
                }

                self.module
                    .define_function(resume_id, &mut self.ctx)
                    .map_err(|e| {
                        CodegenError::Module(format!(
                            "Failed to define coroutine resume `{}`: {}\nFunction IR:\n{}",
                            resume_name, e, self.ctx.func
                        ))
                    })?;

                self.module.clear_context(&mut self.ctx);

                // B) Define coroutine factory instantiator function
                let func_id = self.func_ids[&fn_name];
                let sig = fir_signature_to_cranelift(fir_func, call_conv, ptr_type)?;
                self.ctx.func.signature = sig;

                {
                    let builder = cranelift_frontend::FunctionBuilder::new(
                        &mut self.ctx.func,
                        &mut self.builder_context,
                    );
                    let translator = FunctionTranslator::new(
                        builder,
                        &mut self.module,
                        &self.func_ids,
                        ptr_type,
                        &struct_defs,
                        &coro_funcs,
                        &fn_param_types,
                    );
                    translator.translate_coroutine_factory(fir_func, &resume_name)?;
                }

                self.module
                    .define_function(func_id, &mut self.ctx)
                    .map_err(|e| {
                        CodegenError::Module(format!(
                            "Failed to define coroutine factory `{}`: {}\nFunction IR:\n{}",
                            fn_name, e, self.ctx.func
                        ))
                    })?;

                self.module.clear_context(&mut self.ctx);
            } else {
                let func_id = self.func_ids[&fn_name];
                let sig = fir_signature_to_cranelift(fir_func, call_conv, ptr_type)?;
                self.ctx.func.signature = sig;

                {
                    let builder = cranelift_frontend::FunctionBuilder::new(
                        &mut self.ctx.func,
                        &mut self.builder_context,
                    );
                    let translator = FunctionTranslator::new(
                        builder,
                        &mut self.module,
                        &self.func_ids,
                        ptr_type,
                        &struct_defs,
                        &coro_funcs,
                        &fn_param_types,
                    );
                    translator.translate(fir_func)?;
                }

                self.module
                    .define_function(func_id, &mut self.ctx)
                    .map_err(|e| {
                        CodegenError::Module(format!(
                            "Failed to define function `{}`: {}\nFunction IR:\n{}",
                            fn_name, e, self.ctx.func
                        ))
                    })?;

                self.module.clear_context(&mut self.ctx);
            }
        }

        self.module
            .finalize_definitions()
            .map_err(|e| CodegenError::Module(e.to_string()))?;

        Ok(())
    }

    /// Execute the compiled `main` function and return its integer result.
    pub fn run_main(&self) -> Result<i64, CodegenError> {
        self.run_function("main")
    }

    /// Execute any compiled parameterless function by name and return its integer result.
    pub fn run_function(&self, name: &str) -> Result<i64, CodegenError> {
        let func_id = self
            .func_ids
            .get(name)
            .copied()
            .ok_or_else(|| CodegenError::FunctionNotFound(name.into()))?;

        let code_ptr = self.module.get_finalized_function(func_id);
        let target_fn: fn() -> i64 = unsafe { std::mem::transmute(code_ptr) };
        let result = target_fn();
        Ok(result)
    }
}

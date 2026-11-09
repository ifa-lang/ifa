use crate::error::LlvmCodegenError;
use crate::target::{LlvmTargetConfig, TargetArch};
use crate::types::fir_to_llvm_type;
use ifa_fir::{
    BinaryOp, BlockId, ConstantValue, FirFunction, FirModule, Terminator, UnaryOp, ValueExpr,
    ValueId,
};
use ifa_span::INTERNER;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// Emits canonical textual LLVM IR (.ll) from FIR SSA modules.
pub struct LlvmIrEmitter<'a> {
    target: &'a LlvmTargetConfig,
    string_literals: BTreeMap<String, String>,
    next_str_id: usize,
}

impl<'a> LlvmIrEmitter<'a> {
    /// Create a new LLVM IR emitter configured for the specified target architecture.
    pub fn new(target: &'a LlvmTargetConfig) -> Self {
        Self {
            target,
            string_literals: BTreeMap::new(),
            next_str_id: 0,
        }
    }

    /// Emit complete, valid, optimizable textual LLVM IR for a FIR module.
    pub fn emit_module(&mut self, module: &FirModule) -> Result<String, LlvmCodegenError> {
        let mut out = String::new();

        // 1. Module Header
        out.push_str("; ModuleID = 'ifa_module'\n");
        out.push_str("source_filename = \"ifa_module.ifa\"\n");
        out.push_str(&format!(
            "target datalayout = \"{}\"\n",
            self.target.datalayout
        ));
        out.push_str(&format!("target triple = \"{}\"\n\n", self.target.triple));

        // 2. Scan and prepare global string literals
        let mut str_declarations = String::new();
        for func in &module.functions {
            for block in &func.blocks {
                for inst in &block.instructions {
                    if let ValueExpr::Constant(ConstantValue::String(sym)) = &inst.expr {
                        let text = INTERNER.resolve(sym);
                        if !self.string_literals.contains_key(&text) {
                            let str_id = format!("@.str.{}", self.next_str_id);
                            self.next_str_id += 1;
                            let escaped = escape_llvm_string(&text);
                            let len = text.len() + 1; // +1 for null terminator
                            str_declarations.push_str(&format!(
                                "{} = private unnamed_addr constant [{} x i8] c\"{}\\00\", align 1\n",
                                str_id, len, escaped
                            ));
                            self.string_literals.insert(text, str_id);
                        }
                    }
                }
            }
        }

        if !str_declarations.is_empty() {
            out.push_str("; String Literals\n");
            out.push_str(&str_declarations);
            out.push('\n');
        }

        // 3. Declare standard runtime intrinsic functions
        if self.target.arch == TargetArch::Wasm32Wasi {
            out.push_str("; WASI Preview 1 standard intrinsics & I/O\n");
            out.push_str("declare i32 @__wasi_fd_write(i32, ptr, i32, ptr) #2\n\n");
            out.push_str(
                "@__ifa_nl = private unnamed_addr constant [1 x i8] c\"\\0A\", align 1\n\n",
            );
            out.push_str("define linkonce_odr void @ifa_rt_println(ptr %str) {\n");
            out.push_str("entry:\n");
            out.push_str("  br label %len_loop\n");
            out.push_str("len_loop:\n");
            out.push_str("  %idx = phi i32 [ 0, %entry ], [ %next_idx, %len_next ]\n");
            out.push_str("  %p = getelementptr inbounds i8, ptr %str, i32 %idx\n");
            out.push_str("  %ch = load i8, ptr %p, align 1\n");
            out.push_str("  %is_zero = icmp eq i8 %ch, 0\n");
            out.push_str("  br i1 %is_zero, label %write_out, label %len_next\n");
            out.push_str("len_next:\n");
            out.push_str("  %next_idx = add i32 %idx, 1\n");
            out.push_str("  br label %len_loop\n");
            out.push_str("write_out:\n");
            out.push_str("  %iov = alloca [4 x i32], align 4\n");
            out.push_str("  %nwritten = alloca i32, align 4\n");
            out.push_str("  %p0 = getelementptr inbounds i32, ptr %iov, i32 0\n");
            out.push_str("  %str_int = ptrtoint ptr %str to i32\n");
            out.push_str("  store i32 %str_int, ptr %p0, align 4\n");
            out.push_str("  %p1 = getelementptr inbounds i32, ptr %iov, i32 1\n");
            out.push_str("  store i32 %idx, ptr %p1, align 4\n");
            out.push_str("  %p2 = getelementptr inbounds i32, ptr %iov, i32 2\n");
            out.push_str("  %nl_int = ptrtoint ptr @__ifa_nl to i32\n");
            out.push_str("  store i32 %nl_int, ptr %p2, align 4\n");
            out.push_str("  %p3 = getelementptr inbounds i32, ptr %iov, i32 3\n");
            out.push_str("  store i32 1, ptr %p3, align 4\n");
            out.push_str(
                "  %call_res = call i32 @__wasi_fd_write(i32 1, ptr %iov, i32 2, ptr %nwritten)\n",
            );
            out.push_str("  ret void\n");
            out.push_str("}\n\n");
            out.push_str("declare void @ifa_rt_print(ptr)\n");
            out.push_str("declare void @ifa_rt_println_i64(i64)\n");
            out.push_str("declare void @ifa_rt_print_i64(i64)\n");
            out.push_str("declare ptr @ifa_rt_gen_alloc(i64, i64, i16)\n");
            out.push_str("declare void @ifa_rt_gen_free(ptr)\n");
            out.push_str("declare ptr @ifa_rt_call_arena_alloc(i64, i64)\n");
            out.push_str("declare i64 @ifa_rt_call_arena_mark()\n");
            out.push_str("declare void @ifa_rt_call_arena_rewind(i64)\n");
            out.push_str("declare void @ifa_rt_call_arena_reset()\n");
            out.push_str("declare void @ifa_rt_fiber_yield()\n");
            out.push_str("declare i64 @ifa_rt_fiber_spawn(ptr, ptr)\n");
            out.push_str("declare void @ifa_rt_fiber_join(i64)\n");
            out.push_str("declare ptr @ifa_rt_coro_create(i64, ptr, ptr)\n");
            out.push_str("declare ptr @ifa_rt_coro_create_custom(ptr, ptr, ptr)\n");
            out.push_str("declare i32 @ifa_rt_coro_resume(ptr)\n");
            out.push_str("declare i64 @ifa_rt_coro_spawn(ptr)\n");
            out.push_str("declare void @ifa_rt_coro_destroy(ptr)\n");
            out.push_str("declare i32 @ifa_rt_coro_status(ptr)\n");
            out.push_str("declare i32 @ifa_rt_coro_is_done(ptr)\n");
            out.push_str("declare ptr @ifa_rt_coro_frame(ptr)\n");
            out.push_str("declare ptr @ifa_rt_coro_iter_create(ptr, ptr, i64)\n");
            out.push_str("declare i32 @ifa_rt_coro_iter_next(ptr, ptr)\n");
            out.push_str("declare i32 @ifa_rt_coro_iter_is_done(ptr)\n");
            out.push_str("declare void @ifa_rt_coro_iter_destroy(ptr)\n");
            out.push_str("declare ptr @ifa_rt_channel_create(i64)\n");
            out.push_str("declare void @ifa_rt_channel_destroy(ptr)\n");
            out.push_str("declare i32 @ifa_rt_channel_send(ptr, ptr)\n");
            out.push_str("declare i32 @ifa_rt_channel_recv(ptr, ptr)\n");
            out.push_str("declare i32 @ifa_rt_channel_try_send(ptr, ptr)\n");
            out.push_str("declare i32 @ifa_rt_channel_try_recv(ptr, ptr)\n");
            out.push_str("declare void @ifa_rt_channel_close(ptr)\n");
            out.push_str("declare i32 @ifa_rt_channel_is_closed(ptr)\n");
            out.push_str("declare i64 @ifa_rt_channel_len(ptr)\n");
            out.push_str("declare i64 @ifa_rt_channel_capacity(ptr)\n");
            out.push_str("declare i64 @ifa_rt_channel_select(ptr, i64, i32)\n");
            out.push_str("declare i64 @ifa_rt_channel_select_prioritized(ptr, ptr, i64, i32)\n");
            out.push_str("declare i64 @ifa_rt_channel_select_timed(ptr, ptr, i64, i64, i32)\n");
            out.push_str("declare i64 @ifa_rt_channel_select_table(ptr)\n");
            out.push_str("declare i64 @ifa_rt_channel_select_wait_table(ptr)\n");
            out.push_str("declare i64 @ifa_rt_now_ns()\n");
            out.push_str("declare void @ifa_rt_panic_uaf(ptr, i32, i32)\n");
            out.push_str("declare ptr @ifa_rt_string_concat(ptr, ptr)\n");
            out.push_str("declare ptr @ifa_rt_string_from_i64(i64)\n");
            out.push_str("declare ptr @ifa_rt_string_from_f64(double)\n");
            out.push_str("declare ptr @ifa_rt_string_from_bool(i1)\n");
            out.push_str("declare i64 @ifa_rt_blocking_spawn(ptr, ptr, ptr, ptr)\n");
            out.push_str("declare void @ifa_rt_bounds_check(i64, i64, ptr)\n");
            out.push_str("declare void @ifa_rt_slice_bounds_check(i64, i64, i64, ptr)\n");
            out.push_str(
                "declare void @ifa_rt_slice_strided_bounds_check(i64, i64, i64, i64, ptr)\n",
            );
            out.push_str("declare i1 @ifa_rt_buffer_verify_bounds(ptr, i64, i64, i64)\n");
            out.push_str("declare void @ifa_rt_panic_out_of_bounds(i64, i64)\n");
            out.push_str(
                "declare i64 @ifa_rt_coro_register_io_uring_read(ptr, i32, ptr, i32, i64, ptr)\n",
            );
            out.push_str(
                "declare i64 @ifa_rt_coro_register_io_uring_write(ptr, i32, ptr, i32, i64, ptr)\n",
            );
            out.push_str("declare i64 @ifa_rt_coro_register_iocp_read(ptr, i64, ptr, i32, ptr)\n");
            out.push_str("declare i64 @ifa_rt_coro_register_iocp_write(ptr, i64, ptr, i32, ptr)\n");
            out.push_str("declare void @ifa_rt_coro_set_waiting_io(ptr, i64, ptr)\n");
            out.push_str("declare i32 @ifa_rt_coro_wake_io(i64, i64)\n");
            out.push_str("declare i64 @ifa_rt_reactor_poll(i32)\n");
            out.push_str("declare i64 @ifa_rt_coro_pending_io_count()\n");
            out.push_str("declare ptr @ifa_rt_fs_read_to_string(ptr)\n");
            out.push_str("declare i1 @ifa_rt_fs_write_string(ptr, ptr)\n");
            out.push_str("declare i1 @ifa_rt_fs_exists(ptr)\n");
            out.push_str("declare i64 @ifa_rt_fs_file_size(ptr)\n");
            out.push_str("declare i64 @ifa_rt_process_exec(ptr, ptr)\n");
            out.push_str("declare ptr @ifa_rt_process_exec_output(ptr, ptr)\n");
            out.push_str("declare ptr @ifa_rt_process_exec_stderr(ptr, ptr)\n");
            out.push_str("declare i64 @ifa_rt_process_exec_with_stdin(ptr, ptr, ptr)\n");
            out.push_str("declare ptr @ifa_rt_process_find_linker()\n");
            out.push_str("declare ptr @ifa_rt_process_find_tool(ptr)\n");
            out.push_str("declare ptr @ifa_rt_env_var(ptr)\n");
            out.push_str("declare i64 @ifa_rt_args_count()\n");
            out.push_str("declare ptr @ifa_rt_args_get(i64)\n");
            out.push_str("declare i1 @ifa_rt_string_eq(ptr, ptr)\n");
            out.push_str("declare i64 @ifa_rt_string_len(ptr)\n");
            out.push_str("declare i64 @ifa_rt_string_char_at(ptr, i64)\n\n");
        } else {
            out.push_str("; IFA Runtime Intrinsic Declarations\n");
            out.push_str("declare void @ifa_rt_println(ptr)\n");
            out.push_str("declare void @ifa_rt_print(ptr)\n");
            out.push_str("declare void @ifa_rt_println_i64(i64)\n");
            out.push_str("declare void @ifa_rt_print_i64(i64)\n");
            out.push_str("declare ptr @ifa_rt_gen_alloc(i64, i64, i16)\n");
            out.push_str("declare void @ifa_rt_gen_free(ptr)\n");
            out.push_str("declare ptr @ifa_rt_call_arena_alloc(i64, i64)\n");
            out.push_str("declare i64 @ifa_rt_call_arena_mark()\n");
            out.push_str("declare void @ifa_rt_call_arena_rewind(i64)\n");
            out.push_str("declare void @ifa_rt_call_arena_reset()\n");
            out.push_str("declare void @ifa_rt_fiber_yield()\n");
            out.push_str("declare i64 @ifa_rt_fiber_spawn(ptr, ptr)\n");
            out.push_str("declare void @ifa_rt_fiber_join(i64)\n");
            out.push_str("declare ptr @ifa_rt_coro_create(i64, ptr, ptr)\n");
            out.push_str("declare ptr @ifa_rt_coro_create_custom(ptr, ptr, ptr)\n");
            out.push_str("declare i32 @ifa_rt_coro_resume(ptr)\n");
            out.push_str("declare i64 @ifa_rt_coro_spawn(ptr)\n");
            out.push_str("declare void @ifa_rt_coro_destroy(ptr)\n");
            out.push_str("declare i32 @ifa_rt_coro_status(ptr)\n");
            out.push_str("declare i32 @ifa_rt_coro_is_done(ptr)\n");
            out.push_str("declare ptr @ifa_rt_coro_frame(ptr)\n");
            out.push_str("declare ptr @ifa_rt_coro_iter_create(ptr, ptr, i64)\n");
            out.push_str("declare i32 @ifa_rt_coro_iter_next(ptr, ptr)\n");
            out.push_str("declare i32 @ifa_rt_coro_iter_is_done(ptr)\n");
            out.push_str("declare void @ifa_rt_coro_iter_destroy(ptr)\n");
            out.push_str("declare ptr @ifa_rt_channel_create(i64)\n");
            out.push_str("declare void @ifa_rt_channel_destroy(ptr)\n");
            out.push_str("declare i32 @ifa_rt_channel_send(ptr, ptr)\n");
            out.push_str("declare i32 @ifa_rt_channel_recv(ptr, ptr)\n");
            out.push_str("declare i32 @ifa_rt_channel_try_send(ptr, ptr)\n");
            out.push_str("declare i32 @ifa_rt_channel_try_recv(ptr, ptr)\n");
            out.push_str("declare void @ifa_rt_channel_close(ptr)\n");
            out.push_str("declare i32 @ifa_rt_channel_is_closed(ptr)\n");
            out.push_str("declare i64 @ifa_rt_channel_len(ptr)\n");
            out.push_str("declare i64 @ifa_rt_channel_capacity(ptr)\n");
            out.push_str("declare i64 @ifa_rt_channel_select(ptr, i64, i32)\n");
            out.push_str("declare i64 @ifa_rt_channel_select_prioritized(ptr, ptr, i64, i32)\n");
            out.push_str("declare i64 @ifa_rt_channel_select_timed(ptr, ptr, i64, i64, i32)\n");
            out.push_str("declare i64 @ifa_rt_channel_select_table(ptr)\n");
            out.push_str("declare i64 @ifa_rt_channel_select_wait_table(ptr)\n");
            out.push_str("declare i64 @ifa_rt_now_ns()\n");
            out.push_str("declare void @ifa_rt_panic_uaf(ptr, i32, i32)\n");
            out.push_str("declare ptr @ifa_rt_string_concat(ptr, ptr)\n");
            out.push_str("declare ptr @ifa_rt_string_from_i64(i64)\n");
            out.push_str("declare ptr @ifa_rt_string_from_f64(double)\n");
            out.push_str("declare ptr @ifa_rt_string_from_bool(i1)\n");
            out.push_str("declare i64 @ifa_rt_blocking_spawn(ptr, ptr, ptr, ptr)\n");
            out.push_str("declare void @ifa_rt_bounds_check(i64, i64, ptr)\n");
            out.push_str("declare void @ifa_rt_slice_bounds_check(i64, i64, i64, ptr)\n");
            out.push_str(
                "declare void @ifa_rt_slice_strided_bounds_check(i64, i64, i64, i64, ptr)\n",
            );
            out.push_str("declare i1 @ifa_rt_buffer_verify_bounds(ptr, i64, i64, i64)\n");
            out.push_str("declare void @ifa_rt_panic_out_of_bounds(i64, i64)\n");
            out.push_str(
                "declare i64 @ifa_rt_coro_register_io_uring_read(ptr, i32, ptr, i32, i64, ptr)\n",
            );
            out.push_str(
                "declare i64 @ifa_rt_coro_register_io_uring_write(ptr, i32, ptr, i32, i64, ptr)\n",
            );
            out.push_str("declare i64 @ifa_rt_coro_register_iocp_read(ptr, i64, ptr, i32, ptr)\n");
            out.push_str("declare i64 @ifa_rt_coro_register_iocp_write(ptr, i64, ptr, i32, ptr)\n");
            out.push_str("declare void @ifa_rt_coro_set_waiting_io(ptr, i64, ptr)\n");
            out.push_str("declare i32 @ifa_rt_coro_wake_io(i64, i64)\n");
            out.push_str("declare i64 @ifa_rt_reactor_poll(i32)\n");
            out.push_str("declare i64 @ifa_rt_coro_pending_io_count()\n");
            out.push_str("declare ptr @ifa_rt_fs_read_to_string(ptr)\n");
            out.push_str("declare i1 @ifa_rt_fs_write_string(ptr, ptr)\n");
            out.push_str("declare i1 @ifa_rt_fs_exists(ptr)\n");
            out.push_str("declare i64 @ifa_rt_fs_file_size(ptr)\n");
            out.push_str("declare i64 @ifa_rt_process_exec(ptr, ptr)\n");
            out.push_str("declare ptr @ifa_rt_process_exec_output(ptr, ptr)\n");
            out.push_str("declare ptr @ifa_rt_process_exec_stderr(ptr, ptr)\n");
            out.push_str("declare i64 @ifa_rt_process_exec_with_stdin(ptr, ptr, ptr)\n");
            out.push_str("declare ptr @ifa_rt_process_find_linker()\n");
            out.push_str("declare ptr @ifa_rt_process_find_tool(ptr)\n");
            out.push_str("declare ptr @ifa_rt_env_var(ptr)\n");
            out.push_str("declare i64 @ifa_rt_args_count()\n");
            out.push_str("declare ptr @ifa_rt_args_get(i64)\n");
            out.push_str("declare i1 @ifa_rt_string_eq(ptr, ptr)\n");
            out.push_str("declare i64 @ifa_rt_string_len(ptr)\n");
            out.push_str("declare i64 @ifa_rt_string_char_at(ptr, i64)\n\n");
        }

        // LLVM Standard Coroutine Intrinsics
        out.push_str("; LLVM Standard Coroutine Intrinsics\n");
        out.push_str("declare token @llvm.coro.id(i32, ptr, ptr, ptr)\n");
        if self.target.arch == TargetArch::Wasm32Wasi {
            out.push_str("declare i32 @llvm.coro.size.i32()\n");
            out.push_str("declare void @llvm.memcpy.p0.p0.i32(ptr noalias nocapture writeonly, ptr noalias nocapture readonly, i32, i1 immarg)\n");
        } else {
            out.push_str("declare i64 @llvm.coro.size.i64()\n");
            out.push_str("declare void @llvm.memcpy.p0.p0.i64(ptr noalias nocapture writeonly, ptr noalias nocapture readonly, i64, i1 immarg)\n");
        }
        out.push_str("declare ptr @llvm.coro.begin(token, ptr)\n");
        out.push_str("declare i8 @llvm.coro.suspend(token, i1)\n");
        out.push_str("declare i1 @llvm.coro.end(ptr, i1, token)\n");
        out.push_str("declare void @llvm.coro.resume(ptr)\n");
        out.push_str("declare void @llvm.coro.destroy(ptr)\n");
        out.push_str("declare i1 @llvm.coro.done(ptr)\n");
        out.push_str("declare ptr @llvm.coro.free(token, ptr)\n");
        out.push_str("declare ptr @llvm.coro.promise(ptr, i32, i1)\n");
        out.push_str("declare ptr @llvm.coro.frame()\n\n");

        // Zero-Allocation Channel Multiplexing Select Wait Table Descriptors
        out.push_str(
            "%struct.ifa_select_wait_entry = type { ptr, i32, i32, ptr, i32, i32, i64 }\n",
        );
        out.push_str("%struct.ifa_select_wait_table = type { ptr, i64, i32, i32, i64 }\n\n");

        // IFA Stackless Fiber Continuous Execution Helpers
        out.push_str("; IFA Stackless Fiber Continuous Execution Helpers\n");
        out.push_str(
            "define linkonce_odr void @ifa_coro_run_continuous(ptr %coro) alwaysinline {\n",
        );
        out.push_str("entry:\n  br label %step_loop\n");
        out.push_str("step_loop:\n  %status = call i32 @ifa_rt_coro_resume(ptr %coro)\n  %is_done = icmp eq i32 %status, 1\n  br i1 %is_done, label %done, label %suspend_step\n");
        out.push_str("suspend_step:\n  call void @ifa_rt_fiber_yield()\n  br label %step_loop\n");
        out.push_str("done:\n  call void @ifa_rt_coro_destroy(ptr %coro)\n  ret void\n}\n\n");

        out.push_str("define linkonce_odr i32 @ifa_coro_poll(ptr %coro) alwaysinline {\n");
        out.push_str(
            "entry:\n  %res = call i32 @ifa_rt_coro_resume(ptr %coro)\n  ret i32 %res\n}\n\n",
        );

        out.push_str(
            "define linkonce_odr i32 @ifa_coro_llvm_resume_adapter(ptr %hdl) alwaysinline {\n",
        );
        out.push_str("entry:\n  %is_done = call i1 @llvm.coro.done(ptr %hdl)\n  br i1 %is_done, label %done, label %do_resume\n");
        out.push_str("do_resume:\n  call void @llvm.coro.resume(ptr %hdl)\n  %after_done = call i1 @llvm.coro.done(ptr %hdl)\n  %res = select i1 %after_done, i32 1, i32 0\n  ret i32 %res\n");
        out.push_str("done:\n  ret i32 1\n}\n\n");

        out.push_str(
            "define linkonce_odr void @ifa_coro_llvm_destroy_adapter(ptr %hdl) alwaysinline {\n",
        );
        out.push_str("entry:\n  call void @llvm.coro.destroy(ptr %hdl)\n  ret void\n}\n\n");

        out.push_str("define linkonce_odr i64 @ifa_coro_llvm_spawn(ptr %hdl) alwaysinline {\n");
        out.push_str("entry:\n  %coro = call ptr @ifa_rt_coro_create_custom(ptr %hdl, ptr @ifa_coro_llvm_resume_adapter, ptr @ifa_coro_llvm_destroy_adapter)\n");
        out.push_str("  %fid = call i64 @ifa_rt_coro_spawn(ptr %coro)\n  ret i64 %fid\n}\n\n");

        out.push_str("define linkonce_odr void @ifa_coro_llvm_run(ptr %hdl) alwaysinline {\n");
        out.push_str("entry:\n  br label %step_loop\n");
        out.push_str("step_loop:\n  %done = call i1 @llvm.coro.done(ptr %hdl)\n  br i1 %done, label %cleanup, label %resume_step\n");
        out.push_str("resume_step:\n  call void @llvm.coro.resume(ptr %hdl)\n  %done_after = call i1 @llvm.coro.done(ptr %hdl)\n  br i1 %done_after, label %cleanup, label %yield_step\n");
        out.push_str("yield_step:\n  call void @ifa_rt_fiber_yield()\n  br label %step_loop\n");
        out.push_str("cleanup:\n  call void @llvm.coro.destroy(ptr %hdl)\n  ret void\n}\n\n");

        out.push_str(
            "define linkonce_odr i64 @ifa_coro_run_to_completion(ptr %hdl) alwaysinline {\n",
        );
        out.push_str("entry:\n  br label %step_loop\n");
        out.push_str("step_loop:\n  %done = call i1 @llvm.coro.done(ptr %hdl)\n  br i1 %done, label %extract, label %resume_step\n");
        out.push_str("resume_step:\n  call void @llvm.coro.resume(ptr %hdl)\n  %done_after = call i1 @llvm.coro.done(ptr %hdl)\n  br i1 %done_after, label %extract, label %yield_step\n");
        out.push_str("yield_step:\n  call void @ifa_rt_fiber_yield()\n  br label %step_loop\n");
        out.push_str("extract:\n  %slot = call ptr @llvm.coro.promise(ptr %hdl, i32 8, i1 false)\n  %val = load i64, ptr %slot, align 8\n  call void @llvm.coro.destroy(ptr %hdl)\n  ret i64 %val\n}\n\n");

        out.push_str(
            "define linkonce_odr { ptr, i64 } @ifa_coro_run_to_completion_slice(ptr %hdl) alwaysinline {\n",
        );
        out.push_str("entry:\n  br label %step_loop\n");
        out.push_str("step_loop:\n  %done = call i1 @llvm.coro.done(ptr %hdl)\n  br i1 %done, label %extract, label %resume_step\n");
        out.push_str("resume_step:\n  call void @llvm.coro.resume(ptr %hdl)\n  %done_after = call i1 @llvm.coro.done(ptr %hdl)\n  br i1 %done_after, label %extract, label %yield_step\n");
        out.push_str("yield_step:\n  call void @ifa_rt_fiber_yield()\n  br label %step_loop\n");
        out.push_str("extract:\n  %slot = call ptr @llvm.coro.promise(ptr %hdl, i32 8, i1 false)\n  %val = load { ptr, i64 }, ptr %slot, align 8\n  call void @llvm.coro.destroy(ptr %hdl)\n  ret { ptr, i64 } %val\n}\n\n");

        // IFA Stackless Generator Iterator Helpers
        out.push_str("; IFA Stackless Generator Iterator Helpers\n");
        out.push_str(
            "define linkonce_odr ptr @ifa_coro_generator_yield_ptr(ptr %hdl) alwaysinline {\n",
        );
        out.push_str("entry:\n  %p = call ptr @llvm.coro.promise(ptr %hdl, i32 8, i1 false)\n  ret ptr %p\n}\n\n");

        out.push_str("define linkonce_odr ptr @ifa_coro_generator_iter_create(ptr %hdl, i64 %elem_size) alwaysinline {\n");
        out.push_str("entry:\n");
        out.push_str("  %slot = call ptr @llvm.coro.promise(ptr %hdl, i32 8, i1 false)\n");
        out.push_str("  %coro = call ptr @ifa_rt_coro_create_custom(ptr %hdl, ptr @ifa_coro_llvm_resume_adapter, ptr @ifa_coro_llvm_destroy_adapter)\n");
        out.push_str(
            "  %iter = call ptr @ifa_rt_coro_iter_create(ptr %coro, ptr %slot, i64 %elem_size)\n",
        );
        out.push_str("  ret ptr %iter\n}\n\n");

        out.push_str("define linkonce_odr i32 @ifa_coro_generator_iter_next(ptr %iter, ptr %out_val) alwaysinline {\n");
        out.push_str("entry:\n  %res = call i32 @ifa_rt_coro_iter_next(ptr %iter, ptr %out_val)\n  ret i32 %res\n}\n\n");

        out.push_str(
            "define linkonce_odr void @ifa_coro_generator_iter_destroy(ptr %iter) alwaysinline {\n",
        );
        out.push_str("entry:\n  call void @ifa_rt_coro_iter_destroy(ptr %iter)\n  ret void\n}\n\n");

        // IFA Asynchronous Reactor & io_uring / IOCP Coroutine Integration Helpers
        out.push_str(
            "; IFA Asynchronous Reactor & io_uring / IOCP Coroutine Integration Helpers\n",
        );
        out.push_str("define linkonce_odr i64 @ifa_coro_llvm_io_uring_read(ptr %coro, i32 %fd, ptr %buf, i32 %len, i64 %off, ptr %res_slot) alwaysinline {\n");
        out.push_str("entry:\n  %tok = call i64 @ifa_rt_coro_register_io_uring_read(ptr %coro, i32 %fd, ptr %buf, i32 %len, i64 %off, ptr %res_slot)\n  ret i64 %tok\n}\n\n");

        out.push_str("define linkonce_odr i64 @ifa_coro_llvm_io_uring_write(ptr %coro, i32 %fd, ptr %buf, i32 %len, i64 %off, ptr %res_slot) alwaysinline {\n");
        out.push_str("entry:\n  %tok = call i64 @ifa_rt_coro_register_io_uring_write(ptr %coro, i32 %fd, ptr %buf, i32 %len, i64 %off, ptr %res_slot)\n  ret i64 %tok\n}\n\n");

        out.push_str("define linkonce_odr i64 @ifa_coro_llvm_iocp_read(ptr %coro, i64 %key, ptr %buf, i32 %len, ptr %res_slot) alwaysinline {\n");
        out.push_str("entry:\n  %tok = call i64 @ifa_rt_coro_register_iocp_read(ptr %coro, i64 %key, ptr %buf, i32 %len, ptr %res_slot)\n  ret i64 %tok\n}\n\n");

        out.push_str("define linkonce_odr i64 @ifa_coro_llvm_iocp_write(ptr %coro, i64 %key, ptr %buf, i32 %len, ptr %res_slot) alwaysinline {\n");
        out.push_str("entry:\n  %tok = call i64 @ifa_rt_coro_register_iocp_write(ptr %coro, i64 %key, ptr %buf, i32 %len, ptr %res_slot)\n  ret i64 %tok\n}\n\n");

        out.push_str("define linkonce_odr void @ifa_coro_llvm_await_io(ptr %coro, i64 %token, ptr %res_slot) alwaysinline {\n");
        out.push_str("entry:\n  call void @ifa_rt_coro_set_waiting_io(ptr %coro, i64 %token, ptr %res_slot)\n  ret void\n}\n\n");

        // WebAssembly Standalone Stackless Coroutine & Generator Helpers
        if self.target.arch == TargetArch::Wasm32Wasi {
            out.push_str("; WebAssembly Standalone Stackless Coroutine & Generator Helpers\n");
            out.push_str("define dso_local i32 @ifa_wasm_coro_step(ptr %hdl) {\n");
            out.push_str("entry:\n  %is_done = call i1 @llvm.coro.done(ptr %hdl)\n  br i1 %is_done, label %done, label %resume\n");
            out.push_str("resume:\n  call void @llvm.coro.resume(ptr %hdl)\n  %after = call i1 @llvm.coro.done(ptr %hdl)\n  %res = select i1 %after, i32 1, i32 0\n  ret i32 %res\n");
            out.push_str("done:\n  ret i32 1\n}\n\n");

            out.push_str("define dso_local i32 @ifa_wasm_coro_iter_next(ptr %hdl, ptr %yield_slot, ptr %out_val, i32 %size) {\n");
            out.push_str("entry:\n  %done = call i1 @llvm.coro.done(ptr %hdl)\n  br i1 %done, label %finished, label %resume_step\n");
            out.push_str("resume_step:\n  call void @llvm.coro.resume(ptr %hdl)\n  %after_done = call i1 @llvm.coro.done(ptr %hdl)\n  br i1 %after_done, label %finished, label %copy_val\n");
            out.push_str("copy_val:\n  %has_out = icmp ne ptr %out_val, null\n  %has_slot = icmp ne ptr %yield_slot, null\n  %do_copy = and i1 %has_out, %has_slot\n  br i1 %do_copy, label %exec_copy, label %yield_ok\n");
            out.push_str("exec_copy:\n  call void @llvm.memcpy.p0.p0.i32(ptr %out_val, ptr %yield_slot, i32 %size, i1 false)\n  br label %yield_ok\n");
            out.push_str("yield_ok:\n  ret i32 1\n");
            out.push_str("finished:\n  ret i32 0\n}\n\n");

            out.push_str("define dso_local i32 @ifa_wasm_generator_next(ptr %hdl, ptr %out_val, i32 %size) {\n");
            out.push_str("entry:\n  %slot = call ptr @llvm.coro.promise(ptr %hdl, i32 8, i1 false)\n  %res = call i32 @ifa_wasm_coro_iter_next(ptr %hdl, ptr %slot, ptr %out_val, i32 %size)\n  ret i32 %res\n}\n\n");

            out.push_str("define dso_local void @ifa_wasm_coro_destroy(ptr %hdl) {\n");
            out.push_str("entry:\n  call void @llvm.coro.destroy(ptr %hdl)\n  ret void\n}\n\n");

            out.push_str("define linkonce_odr ptr @ifa_rt_blocking_call(ptr %thunk, ptr %ctx) alwaysinline {\n");
            out.push_str("entry:\n  %res = call ptr %thunk(ptr %ctx)\n  ret ptr %res\n}\n\n");
        }

        // SIMD Vector Reduction Intrinsics
        out.push_str("; LLVM Vector Reduction Intrinsics\n");
        out.push_str("declare float @llvm.vector.reduce.fadd.v4f32(float, <4 x float>)\n");
        out.push_str("declare float @llvm.vector.reduce.fadd.v8f32(float, <8 x float>)\n");
        out.push_str("declare double @llvm.vector.reduce.fadd.v4f64(double, <4 x double>)\n");
        out.push_str("declare i32 @llvm.vector.reduce.add.v4i32(<4 x i32>)\n");
        out.push_str("declare i32 @llvm.vector.reduce.add.v8i32(<8 x i32>)\n");
        out.push_str("declare i64 @llvm.vector.reduce.add.v4i64(<4 x i64>)\n");
        out.push_str("declare float @llvm.vector.reduce.fmul.v4f32(float, <4 x float>)\n");
        out.push_str("declare float @llvm.vector.reduce.fmul.v8f32(float, <8 x float>)\n");
        out.push_str("declare double @llvm.vector.reduce.fmul.v4f64(double, <4 x double>)\n");
        out.push_str("declare i32 @llvm.vector.reduce.mul.v4i32(<4 x i32>)\n");
        out.push_str("declare i32 @llvm.vector.reduce.mul.v8i32(<8 x i32>)\n");
        out.push_str("declare i64 @llvm.vector.reduce.mul.v4i64(<4 x i64>)\n");
        out.push_str("declare float @llvm.vector.reduce.fmin.v4f32(<4 x float>)\n");
        out.push_str("declare float @llvm.vector.reduce.fmin.v8f32(<8 x float>)\n");
        out.push_str("declare double @llvm.vector.reduce.fmin.v4f64(<4 x double>)\n");
        out.push_str("declare i32 @llvm.vector.reduce.smin.v4i32(<4 x i32>)\n");
        out.push_str("declare i32 @llvm.vector.reduce.smin.v8i32(<8 x i32>)\n");
        out.push_str("declare i64 @llvm.vector.reduce.smin.v4i64(<4 x i64>)\n");
        out.push_str("declare float @llvm.vector.reduce.fmax.v4f32(<4 x float>)\n");
        out.push_str("declare float @llvm.vector.reduce.fmax.v8f32(<8 x float>)\n");
        out.push_str("declare double @llvm.vector.reduce.fmax.v4f64(<4 x double>)\n");
        out.push_str("declare i32 @llvm.vector.reduce.smax.v4i32(<4 x i32>)\n");
        out.push_str("declare i32 @llvm.vector.reduce.smax.v8i32(<8 x i32>)\n");
        out.push_str("declare i64 @llvm.vector.reduce.smax.v4i64(<4 x i64>)\n");
        out.push_str("declare float @llvm.sqrt.f32(float)\n");
        out.push_str("declare double @llvm.sqrt.f64(double)\n\n");

        if self.target.arch == TargetArch::AArch64 {
            out.push_str("; AArch64 Advanced SIMD (NEON) Horizontal Reduction Intrinsics\n");
            out.push_str("declare float @llvm.aarch64.neon.fmaxv.f32.v4f32(<4 x float>)\n");
            out.push_str("declare float @llvm.aarch64.neon.fminv.f32.v4f32(<4 x float>)\n");
            out.push_str("declare float @llvm.aarch64.neon.fmaxnmv.f32.v4f32(<4 x float>)\n");
            out.push_str("declare float @llvm.aarch64.neon.fminnmv.f32.v4f32(<4 x float>)\n");
            out.push_str("declare double @llvm.aarch64.neon.fmaxv.f64.v2f64(<2 x double>)\n");
            out.push_str("declare double @llvm.aarch64.neon.fminv.f64.v2f64(<2 x double>)\n");
            out.push_str("declare i32 @llvm.aarch64.neon.smaxv.i32.v4i32(<4 x i32>)\n");
            out.push_str("declare i32 @llvm.aarch64.neon.sminv.i32.v4i32(<4 x i32>)\n");
            out.push_str("declare i32 @llvm.aarch64.neon.umaxv.i32.v4i32(<4 x i32>)\n");
            out.push_str("declare i32 @llvm.aarch64.neon.uminv.i32.v4i32(<4 x i32>)\n");
            out.push_str("declare i32 @llvm.aarch64.neon.uaddv.i32.v4i32(<4 x i32>)\n");
            out.push_str("declare i32 @llvm.aarch64.neon.saddv.i32.v4i32(<4 x i32>)\n");
            out.push_str("declare i64 @llvm.aarch64.neon.smaxv.i64.v2i64(<2 x i64>)\n");
            out.push_str("declare i64 @llvm.aarch64.neon.sminv.i64.v2i64(<2 x i64>)\n\n");
        }

        // Linkonce SIMD Vectorized Slice Operations
        out.push_str("; IFA Standard Library SIMD Slice Vectorizers\n");
        out.push_str("define linkonce_odr void @ifa_simd_slice_add_f32(ptr %dst, ptr %src1, ptr %src2, i64 %len) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -8\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %tail_entry\n");
        out.push_str("vec_step:\n  %p1 = getelementptr inbounds float, ptr %src1, i64 %i\n  %p2 = getelementptr inbounds float, ptr %src2, i64 %i\n  %pd = getelementptr inbounds float, ptr %dst, i64 %i\n");
        out.push_str("  %v1 = load <8 x float>, ptr %p1, align 4\n  %v2 = load <8 x float>, ptr %p2, align 4\n  %vr = fadd <8 x float> %v1, %v2\n  store <8 x float> %vr, ptr %pd, align 4\n");
        out.push_str("  %next_i = add i64 %i, 8\n  br label %vec_loop, !llvm.loop !1\n");
        out.push_str("tail_entry:\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %tail_entry ], [ %next_ti, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp1 = getelementptr inbounds float, ptr %src1, i64 %ti\n  %tp2 = getelementptr inbounds float, ptr %src2, i64 %ti\n  %tpd = getelementptr inbounds float, ptr %dst, i64 %ti\n");
        out.push_str("  %tv1 = load float, ptr %tp1, align 4\n  %tv2 = load float, ptr %tp2, align 4\n  %tvr = fadd float %tv1, %tv2\n  store float %tvr, ptr %tpd, align 4\n");
        out.push_str("  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret void\n}\n\n");

        out.push_str("define linkonce_odr void @ifa_simd_slice_mul_f32(ptr %dst, ptr %src1, ptr %src2, i64 %len) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -8\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %tail_entry\n");
        out.push_str("vec_step:\n  %p1 = getelementptr inbounds float, ptr %src1, i64 %i\n  %p2 = getelementptr inbounds float, ptr %src2, i64 %i\n  %pd = getelementptr inbounds float, ptr %dst, i64 %i\n");
        out.push_str("  %v1 = load <8 x float>, ptr %p1, align 4\n  %v2 = load <8 x float>, ptr %p2, align 4\n  %vr = fmul <8 x float> %v1, %v2\n  store <8 x float> %vr, ptr %pd, align 4\n");
        out.push_str("  %next_i = add i64 %i, 8\n  br label %vec_loop, !llvm.loop !1\n");
        out.push_str("tail_entry:\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %tail_entry ], [ %next_ti, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp1 = getelementptr inbounds float, ptr %src1, i64 %ti\n  %tp2 = getelementptr inbounds float, ptr %src2, i64 %ti\n  %tpd = getelementptr inbounds float, ptr %dst, i64 %ti\n");
        out.push_str("  %tv1 = load float, ptr %tp1, align 4\n  %tv2 = load float, ptr %tp2, align 4\n  %tvr = fmul float %tv1, %tv2\n  store float %tvr, ptr %tpd, align 4\n");
        out.push_str("  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret void\n}\n\n");

        out.push_str("define linkonce_odr float @ifa_simd_slice_dot_f32(ptr %src1, ptr %src2, i64 %len) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -8\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <8 x float> [ zeroinitializer, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
        out.push_str("vec_step:\n  %p1 = getelementptr inbounds float, ptr %src1, i64 %i\n  %p2 = getelementptr inbounds float, ptr %src2, i64 %i\n  %v1 = load <8 x float>, ptr %p1, align 4\n  %v2 = load <8 x float>, ptr %p2, align 4\n");
        out.push_str("  %prod = fmul <8 x float> %v1, %v2\n  %next_acc = fadd <8 x float> %acc, %prod\n  %next_i = add i64 %i, 8\n  br label %vec_loop, !llvm.loop !1\n");
        out.push_str("reduce:\n  %vec_sum = call float @llvm.vector.reduce.fadd.v8f32(float 0.0, <8 x float> %acc)\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi float [ %vec_sum, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp1 = getelementptr inbounds float, ptr %src1, i64 %ti\n  %tp2 = getelementptr inbounds float, ptr %src2, i64 %ti\n  %tv1 = load float, ptr %tp1, align 4\n  %tv2 = load float, ptr %tp2, align 4\n");
        out.push_str("  %tprod = fmul float %tv1, %tv2\n  %next_s_acc = fadd float %s_acc, %tprod\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret float %s_acc\n}\n\n");

        out.push_str("define linkonce_odr float @ifa_simd_slice_sum_f32(ptr %src, i64 %len) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -8\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <8 x float> [ zeroinitializer, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
        out.push_str("vec_step:\n  %p = getelementptr inbounds float, ptr %src, i64 %i\n  %v = load <8 x float>, ptr %p, align 4\n  %next_acc = fadd <8 x float> %acc, %v\n  %next_i = add i64 %i, 8\n  br label %vec_loop, !llvm.loop !1\n");
        out.push_str("reduce:\n  %vec_sum = call float @llvm.vector.reduce.fadd.v8f32(float 0.0, <8 x float> %acc)\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi float [ %vec_sum, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp = getelementptr inbounds float, ptr %src, i64 %ti\n  %tv = load float, ptr %tp, align 4\n  %next_s_acc = fadd float %s_acc, %tv\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret float %s_acc\n}\n\n");

        out.push_str("define linkonce_odr void @ifa_simd_slice_add_i32(ptr %dst, ptr %src1, ptr %src2, i64 %len) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -8\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %tail_entry\n");
        out.push_str("vec_step:\n  %p1 = getelementptr inbounds i32, ptr %src1, i64 %i\n  %p2 = getelementptr inbounds i32, ptr %src2, i64 %i\n  %pd = getelementptr inbounds i32, ptr %dst, i64 %i\n");
        out.push_str("  %v1 = load <8 x i32>, ptr %p1, align 4\n  %v2 = load <8 x i32>, ptr %p2, align 4\n  %vr = add <8 x i32> %v1, %v2\n  store <8 x i32> %vr, ptr %pd, align 4\n");
        out.push_str("  %next_i = add i64 %i, 8\n  br label %vec_loop, !llvm.loop !1\n");
        out.push_str("tail_entry:\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %tail_entry ], [ %next_ti, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp1 = getelementptr inbounds i32, ptr %src1, i64 %ti\n  %tp2 = getelementptr inbounds i32, ptr %src2, i64 %ti\n  %tpd = getelementptr inbounds i32, ptr %dst, i64 %ti\n");
        out.push_str("  %tv1 = load i32, ptr %tp1, align 4\n  %tv2 = load i32, ptr %tp2, align 4\n  %tvr = add i32 %tv1, %tv2\n  store i32 %tvr, ptr %tpd, align 4\n");
        out.push_str("  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret void\n}\n\n");

        out.push_str("define linkonce_odr void @ifa_simd_slice_mul_i32(ptr %dst, ptr %src1, ptr %src2, i64 %len) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -8\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %tail_entry\n");
        out.push_str("vec_step:\n  %p1 = getelementptr inbounds i32, ptr %src1, i64 %i\n  %p2 = getelementptr inbounds i32, ptr %src2, i64 %i\n  %pd = getelementptr inbounds i32, ptr %dst, i64 %i\n");
        out.push_str("  %v1 = load <8 x i32>, ptr %p1, align 4\n  %v2 = load <8 x i32>, ptr %p2, align 4\n  %vr = mul <8 x i32> %v1, %v2\n  store <8 x i32> %vr, ptr %pd, align 4\n");
        out.push_str("  %next_i = add i64 %i, 8\n  br label %vec_loop, !llvm.loop !1\n");
        out.push_str("tail_entry:\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %tail_entry ], [ %next_ti, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp1 = getelementptr inbounds i32, ptr %src1, i64 %ti\n  %tp2 = getelementptr inbounds i32, ptr %src2, i64 %ti\n  %tpd = getelementptr inbounds i32, ptr %dst, i64 %ti\n");
        out.push_str("  %tv1 = load i32, ptr %tp1, align 4\n  %tv2 = load i32, ptr %tp2, align 4\n  %tvr = mul i32 %tv1, %tv2\n  store i32 %tvr, ptr %tpd, align 4\n");
        out.push_str("  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret void\n}\n\n");

        out.push_str(
            "define linkonce_odr i32 @ifa_simd_slice_sum_i32(ptr %src, i64 %len) alwaysinline {\n",
        );
        out.push_str("entry:\n  %vec_len = and i64 %len, -8\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <8 x i32> [ zeroinitializer, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
        out.push_str("vec_step:\n  %p = getelementptr inbounds i32, ptr %src, i64 %i\n  %v = load <8 x i32>, ptr %p, align 4\n  %next_acc = add <8 x i32> %acc, %v\n  %next_i = add i64 %i, 8\n  br label %vec_loop, !llvm.loop !1\n");
        out.push_str("reduce:\n  %vec_sum = call i32 @llvm.vector.reduce.add.v8i32(<8 x i32> %acc)\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi i32 [ %vec_sum, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp = getelementptr inbounds i32, ptr %src, i64 %ti\n  %tv = load i32, ptr %tp, align 4\n  %next_s_acc = add i32 %s_acc, %tv\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret i32 %s_acc\n}\n\n");

        // 64-bit Floating-Point SIMD Operations (AVX/NEON 4-lane)
        out.push_str("define linkonce_odr void @ifa_simd_slice_add_f64(ptr %dst, ptr %src1, ptr %src2, i64 %len) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -4\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %tail_entry\n");
        out.push_str("vec_step:\n  %p1 = getelementptr inbounds double, ptr %src1, i64 %i\n  %p2 = getelementptr inbounds double, ptr %src2, i64 %i\n  %pd = getelementptr inbounds double, ptr %dst, i64 %i\n");
        out.push_str("  %v1 = load <4 x double>, ptr %p1, align 8\n  %v2 = load <4 x double>, ptr %p2, align 8\n  %vr = fadd <4 x double> %v1, %v2\n  store <4 x double> %vr, ptr %pd, align 8\n");
        out.push_str("  %next_i = add i64 %i, 4\n  br label %vec_loop, !llvm.loop !6\n");
        out.push_str("tail_entry:\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %tail_entry ], [ %next_ti, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp1 = getelementptr inbounds double, ptr %src1, i64 %ti\n  %tp2 = getelementptr inbounds double, ptr %src2, i64 %ti\n  %tpd = getelementptr inbounds double, ptr %dst, i64 %ti\n");
        out.push_str("  %tv1 = load double, ptr %tp1, align 8\n  %tv2 = load double, ptr %tp2, align 8\n  %tvr = fadd double %tv1, %tv2\n  store double %tvr, ptr %tpd, align 8\n");
        out.push_str("  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret void\n}\n\n");

        out.push_str("define linkonce_odr void @ifa_simd_slice_mul_f64(ptr %dst, ptr %src1, ptr %src2, i64 %len) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -4\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %tail_entry\n");
        out.push_str("vec_step:\n  %p1 = getelementptr inbounds double, ptr %src1, i64 %i\n  %p2 = getelementptr inbounds double, ptr %src2, i64 %i\n  %pd = getelementptr inbounds double, ptr %dst, i64 %i\n");
        out.push_str("  %v1 = load <4 x double>, ptr %p1, align 8\n  %v2 = load <4 x double>, ptr %p2, align 8\n  %vr = fmul <4 x double> %v1, %v2\n  store <4 x double> %vr, ptr %pd, align 8\n");
        out.push_str("  %next_i = add i64 %i, 4\n  br label %vec_loop, !llvm.loop !6\n");
        out.push_str("tail_entry:\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %tail_entry ], [ %next_ti, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp1 = getelementptr inbounds double, ptr %src1, i64 %ti\n  %tp2 = getelementptr inbounds double, ptr %src2, i64 %ti\n  %tpd = getelementptr inbounds double, ptr %dst, i64 %ti\n");
        out.push_str("  %tv1 = load double, ptr %tp1, align 8\n  %tv2 = load double, ptr %tp2, align 8\n  %tvr = fmul double %tv1, %tv2\n  store double %tvr, ptr %tpd, align 8\n");
        out.push_str("  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret void\n}\n\n");

        out.push_str("define linkonce_odr double @ifa_simd_slice_dot_f64(ptr %src1, ptr %src2, i64 %len) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -4\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <4 x double> [ zeroinitializer, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
        out.push_str("vec_step:\n  %p1 = getelementptr inbounds double, ptr %src1, i64 %i\n  %p2 = getelementptr inbounds double, ptr %src2, i64 %i\n  %v1 = load <4 x double>, ptr %p1, align 8\n  %v2 = load <4 x double>, ptr %p2, align 8\n");
        out.push_str("  %prod = fmul <4 x double> %v1, %v2\n  %next_acc = fadd <4 x double> %acc, %prod\n  %next_i = add i64 %i, 4\n  br label %vec_loop, !llvm.loop !6\n");
        out.push_str("reduce:\n  %vec_sum = call double @llvm.vector.reduce.fadd.v4f64(double 0.0, <4 x double> %acc)\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi double [ %vec_sum, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp1 = getelementptr inbounds double, ptr %src1, i64 %ti\n  %tp2 = getelementptr inbounds double, ptr %src2, i64 %ti\n  %tv1 = load double, ptr %tp1, align 8\n  %tv2 = load double, ptr %tp2, align 8\n");
        out.push_str("  %tprod = fmul double %tv1, %tv2\n  %next_s_acc = fadd double %s_acc, %tprod\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret double %s_acc\n}\n\n");

        out.push_str("define linkonce_odr double @ifa_simd_slice_sum_f64(ptr %src, i64 %len) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -4\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <4 x double> [ zeroinitializer, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
        out.push_str("vec_step:\n  %p = getelementptr inbounds double, ptr %src, i64 %i\n  %v = load <4 x double>, ptr %p, align 8\n  %next_acc = fadd <4 x double> %acc, %v\n  %next_i = add i64 %i, 4\n  br label %vec_loop, !llvm.loop !6\n");
        out.push_str("reduce:\n  %vec_sum = call double @llvm.vector.reduce.fadd.v4f64(double 0.0, <4 x double> %acc)\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi double [ %vec_sum, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp = getelementptr inbounds double, ptr %src, i64 %ti\n  %tv = load double, ptr %tp, align 8\n  %next_s_acc = fadd double %s_acc, %tv\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret double %s_acc\n}\n\n");

        // 64-bit Integer SIMD Operations
        out.push_str("define linkonce_odr void @ifa_simd_slice_add_i64(ptr %dst, ptr %src1, ptr %src2, i64 %len) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -4\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %tail_entry\n");
        out.push_str("vec_step:\n  %p1 = getelementptr inbounds i64, ptr %src1, i64 %i\n  %p2 = getelementptr inbounds i64, ptr %src2, i64 %i\n  %pd = getelementptr inbounds i64, ptr %dst, i64 %i\n");
        out.push_str("  %v1 = load <4 x i64>, ptr %p1, align 8\n  %v2 = load <4 x i64>, ptr %p2, align 8\n  %vr = add <4 x i64> %v1, %v2\n  store <4 x i64> %vr, ptr %pd, align 8\n");
        out.push_str("  %next_i = add i64 %i, 4\n  br label %vec_loop, !llvm.loop !6\n");
        out.push_str("tail_entry:\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %tail_entry ], [ %next_ti, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp1 = getelementptr inbounds i64, ptr %src1, i64 %ti\n  %tp2 = getelementptr inbounds i64, ptr %src2, i64 %ti\n  %tpd = getelementptr inbounds i64, ptr %dst, i64 %ti\n");
        out.push_str("  %tv1 = load i64, ptr %tp1, align 8\n  %tv2 = load i64, ptr %tp2, align 8\n  %tvr = add i64 %tv1, %tv2\n  store i64 %tvr, ptr %tpd, align 8\n");
        out.push_str("  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret void\n}\n\n");

        out.push_str("define linkonce_odr void @ifa_simd_slice_mul_i64(ptr %dst, ptr %src1, ptr %src2, i64 %len) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -4\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %tail_entry\n");
        out.push_str("vec_step:\n  %p1 = getelementptr inbounds i64, ptr %src1, i64 %i\n  %p2 = getelementptr inbounds i64, ptr %src2, i64 %i\n  %pd = getelementptr inbounds i64, ptr %dst, i64 %i\n");
        out.push_str("  %v1 = load <4 x i64>, ptr %p1, align 8\n  %v2 = load <4 x i64>, ptr %p2, align 8\n  %vr = mul <4 x i64> %v1, %v2\n  store <4 x i64> %vr, ptr %pd, align 8\n");
        out.push_str("  %next_i = add i64 %i, 4\n  br label %vec_loop, !llvm.loop !6\n");
        out.push_str("tail_entry:\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %tail_entry ], [ %next_ti, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp1 = getelementptr inbounds i64, ptr %src1, i64 %ti\n  %tp2 = getelementptr inbounds i64, ptr %src2, i64 %ti\n  %tpd = getelementptr inbounds i64, ptr %dst, i64 %ti\n");
        out.push_str("  %tv1 = load i64, ptr %tp1, align 8\n  %tv2 = load i64, ptr %tp2, align 8\n  %tvr = mul i64 %tv1, %tv2\n  store i64 %tvr, ptr %tpd, align 8\n");
        out.push_str("  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret void\n}\n\n");

        out.push_str(
            "define linkonce_odr i64 @ifa_simd_slice_sum_i64(ptr %src, i64 %len) alwaysinline {\n",
        );
        out.push_str("entry:\n  %vec_len = and i64 %len, -4\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <4 x i64> [ zeroinitializer, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
        out.push_str("vec_step:\n  %p = getelementptr inbounds i64, ptr %src, i64 %i\n  %v = load <4 x i64>, ptr %p, align 8\n  %next_acc = add <4 x i64> %acc, %v\n  %next_i = add i64 %i, 4\n  br label %vec_loop, !llvm.loop !6\n");
        out.push_str("reduce:\n  %vec_sum = call i64 @llvm.vector.reduce.add.v4i64(<4 x i64> %acc)\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi i64 [ %vec_sum, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp = getelementptr inbounds i64, ptr %src, i64 %ti\n  %tv = load i64, ptr %tp, align 8\n  %next_s_acc = add i64 %s_acc, %tv\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret i64 %s_acc\n}\n\n");

        // 8-bit Byte SIMD Operations (16-lane SSE/AVX/NEON/WASM - for cryptographic hashes and memory blocks)
        out.push_str("define linkonce_odr void @ifa_simd_slice_add_u8(ptr %dst, ptr %src1, ptr %src2, i64 %len) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -16\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %tail_entry\n");
        out.push_str("vec_step:\n  %p1 = getelementptr inbounds i8, ptr %src1, i64 %i\n  %p2 = getelementptr inbounds i8, ptr %src2, i64 %i\n  %pd = getelementptr inbounds i8, ptr %dst, i64 %i\n");
        out.push_str("  %v1 = load <16 x i8>, ptr %p1, align 1\n  %v2 = load <16 x i8>, ptr %p2, align 1\n  %vr = add <16 x i8> %v1, %v2\n  store <16 x i8> %vr, ptr %pd, align 1\n");
        out.push_str("  %next_i = add i64 %i, 16\n  br label %vec_loop, !llvm.loop !8\n");
        out.push_str("tail_entry:\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %tail_entry ], [ %next_ti, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp1 = getelementptr inbounds i8, ptr %src1, i64 %ti\n  %tp2 = getelementptr inbounds i8, ptr %src2, i64 %ti\n  %tpd = getelementptr inbounds i8, ptr %dst, i64 %ti\n");
        out.push_str("  %tv1 = load i8, ptr %tp1, align 1\n  %tv2 = load i8, ptr %tp2, align 1\n  %tvr = add i8 %tv1, %tv2\n  store i8 %tvr, ptr %tpd, align 1\n");
        out.push_str("  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret void\n}\n\n");

        out.push_str("define linkonce_odr void @ifa_simd_slice_xor_u8(ptr %dst, ptr %src1, ptr %src2, i64 %len) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -16\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %tail_entry\n");
        out.push_str("vec_step:\n  %p1 = getelementptr inbounds i8, ptr %src1, i64 %i\n  %p2 = getelementptr inbounds i8, ptr %src2, i64 %i\n  %pd = getelementptr inbounds i8, ptr %dst, i64 %i\n");
        out.push_str("  %v1 = load <16 x i8>, ptr %p1, align 1\n  %v2 = load <16 x i8>, ptr %p2, align 1\n  %vr = xor <16 x i8> %v1, %v2\n  store <16 x i8> %vr, ptr %pd, align 1\n");
        out.push_str("  %next_i = add i64 %i, 16\n  br label %vec_loop, !llvm.loop !8\n");
        out.push_str("tail_entry:\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %tail_entry ], [ %next_ti, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp1 = getelementptr inbounds i8, ptr %src1, i64 %ti\n  %tp2 = getelementptr inbounds i8, ptr %src2, i64 %ti\n  %tpd = getelementptr inbounds i8, ptr %dst, i64 %ti\n");
        out.push_str("  %tv1 = load i8, ptr %tp1, align 1\n  %tv2 = load i8, ptr %tp2, align 1\n  %tvr = xor i8 %tv1, %tv2\n  store i8 %tvr, ptr %tpd, align 1\n");
        out.push_str("  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret void\n}\n\n");

        // Advanced SIMD Scalar Reductions: Product, Min, Max (32-bit & 64-bit)
        out.push_str("; IFA Standard Library SIMD Advanced Scalar Reductions\n");
        out.push_str("define linkonce_odr float @ifa_simd_slice_prod_f32(ptr %src, i64 %len) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -8\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <8 x float> [ <float 1.0, float 1.0, float 1.0, float 1.0, float 1.0, float 1.0, float 1.0, float 1.0>, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
        out.push_str("vec_step:\n  %p = getelementptr inbounds float, ptr %src, i64 %i\n  %v = load <8 x float>, ptr %p, align 4\n  %next_acc = fmul <8 x float> %acc, %v\n  %next_i = add i64 %i, 8\n  br label %vec_loop, !llvm.loop !1\n");
        out.push_str("reduce:\n  %vec_prod = call float @llvm.vector.reduce.fmul.v8f32(float 1.0, <8 x float> %acc)\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi float [ %vec_prod, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp = getelementptr inbounds float, ptr %src, i64 %ti\n  %tv = load float, ptr %tp, align 4\n  %next_s_acc = fmul float %s_acc, %tv\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret float %s_acc\n}\n\n");

        out.push_str("define linkonce_odr float @ifa_simd_slice_min_f32(ptr %src, i64 %len) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -8\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <8 x float> [ <float 0x7FF0000000000000, float 0x7FF0000000000000, float 0x7FF0000000000000, float 0x7FF0000000000000, float 0x7FF0000000000000, float 0x7FF0000000000000, float 0x7FF0000000000000, float 0x7FF0000000000000>, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
        out.push_str("vec_step:\n  %p = getelementptr inbounds float, ptr %src, i64 %i\n  %v = load <8 x float>, ptr %p, align 4\n  %cmp = fcmp olt <8 x float> %v, %acc\n  %next_acc = select <8 x i1> %cmp, <8 x float> %v, <8 x float> %acc\n  %next_i = add i64 %i, 8\n  br label %vec_loop, !llvm.loop !1\n");
        out.push_str("reduce:\n  %vec_min = call float @llvm.vector.reduce.fmin.v8f32(<8 x float> %acc)\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi float [ %vec_min, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp = getelementptr inbounds float, ptr %src, i64 %ti\n  %tv = load float, ptr %tp, align 4\n  %tcmp = fcmp olt float %tv, %s_acc\n  %next_s_acc = select i1 %tcmp, float %tv, float %s_acc\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret float %s_acc\n}\n\n");

        out.push_str("define linkonce_odr float @ifa_simd_slice_max_f32(ptr %src, i64 %len) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -8\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <8 x float> [ <float 0xFFF0000000000000, float 0xFFF0000000000000, float 0xFFF0000000000000, float 0xFFF0000000000000, float 0xFFF0000000000000, float 0xFFF0000000000000, float 0xFFF0000000000000, float 0xFFF0000000000000>, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
        out.push_str("vec_step:\n  %p = getelementptr inbounds float, ptr %src, i64 %i\n  %v = load <8 x float>, ptr %p, align 4\n  %cmp = fcmp ogt <8 x float> %v, %acc\n  %next_acc = select <8 x i1> %cmp, <8 x float> %v, <8 x float> %acc\n  %next_i = add i64 %i, 8\n  br label %vec_loop, !llvm.loop !1\n");
        out.push_str("reduce:\n  %vec_max = call float @llvm.vector.reduce.fmax.v8f32(<8 x float> %acc)\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi float [ %vec_max, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp = getelementptr inbounds float, ptr %src, i64 %ti\n  %tv = load float, ptr %tp, align 4\n  %tcmp = fcmp ogt float %tv, %s_acc\n  %next_s_acc = select i1 %tcmp, float %tv, float %s_acc\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret float %s_acc\n}\n\n");

        out.push_str(
            "define linkonce_odr i32 @ifa_simd_slice_prod_i32(ptr %src, i64 %len) alwaysinline {\n",
        );
        out.push_str("entry:\n  %vec_len = and i64 %len, -8\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <8 x i32> [ <i32 1, i32 1, i32 1, i32 1, i32 1, i32 1, i32 1, i32 1>, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
        out.push_str("vec_step:\n  %p = getelementptr inbounds i32, ptr %src, i64 %i\n  %v = load <8 x i32>, ptr %p, align 4\n  %next_acc = mul <8 x i32> %acc, %v\n  %next_i = add i64 %i, 8\n  br label %vec_loop, !llvm.loop !1\n");
        out.push_str("reduce:\n  %vec_prod = call i32 @llvm.vector.reduce.mul.v8i32(<8 x i32> %acc)\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi i32 [ %vec_prod, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp = getelementptr inbounds i32, ptr %src, i64 %ti\n  %tv = load i32, ptr %tp, align 4\n  %next_s_acc = mul i32 %s_acc, %tv\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret i32 %s_acc\n}\n\n");

        out.push_str(
            "define linkonce_odr i32 @ifa_simd_slice_min_i32(ptr %src, i64 %len) alwaysinline {\n",
        );
        out.push_str("entry:\n  %vec_len = and i64 %len, -8\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <8 x i32> [ <i32 2147483647, i32 2147483647, i32 2147483647, i32 2147483647, i32 2147483647, i32 2147483647, i32 2147483647, i32 2147483647>, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
        out.push_str("vec_step:\n  %p = getelementptr inbounds i32, ptr %src, i64 %i\n  %v = load <8 x i32>, ptr %p, align 4\n  %cmp = icmp slt <8 x i32> %v, %acc\n  %next_acc = select <8 x i1> %cmp, <8 x i32> %v, <8 x i32> %acc\n  %next_i = add i64 %i, 8\n  br label %vec_loop, !llvm.loop !1\n");
        out.push_str("reduce:\n  %vec_min = call i32 @llvm.vector.reduce.smin.v8i32(<8 x i32> %acc)\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi i32 [ %vec_min, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp = getelementptr inbounds i32, ptr %src, i64 %ti\n  %tv = load i32, ptr %tp, align 4\n  %tcmp = icmp slt i32 %tv, %s_acc\n  %next_s_acc = select i1 %tcmp, i32 %tv, i32 %s_acc\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret i32 %s_acc\n}\n\n");

        out.push_str(
            "define linkonce_odr i32 @ifa_simd_slice_max_i32(ptr %src, i64 %len) alwaysinline {\n",
        );
        out.push_str("entry:\n  %vec_len = and i64 %len, -8\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <8 x i32> [ <i32 -2147483648, i32 -2147483648, i32 -2147483648, i32 -2147483648, i32 -2147483648, i32 -2147483648, i32 -2147483648, i32 -2147483648>, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
        out.push_str("vec_step:\n  %p = getelementptr inbounds i32, ptr %src, i64 %i\n  %v = load <8 x i32>, ptr %p, align 4\n  %cmp = icmp sgt <8 x i32> %v, %acc\n  %next_acc = select <8 x i1> %cmp, <8 x i32> %v, <8 x i32> %acc\n  %next_i = add i64 %i, 8\n  br label %vec_loop, !llvm.loop !1\n");
        out.push_str("reduce:\n  %vec_max = call i32 @llvm.vector.reduce.smax.v8i32(<8 x i32> %acc)\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi i32 [ %vec_max, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp = getelementptr inbounds i32, ptr %src, i64 %ti\n  %tv = load i32, ptr %tp, align 4\n  %tcmp = icmp sgt i32 %tv, %s_acc\n  %next_s_acc = select i1 %tcmp, i32 %tv, i32 %s_acc\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret i32 %s_acc\n}\n\n");

        out.push_str("define linkonce_odr double @ifa_simd_slice_prod_f64(ptr %src, i64 %len) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -4\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <4 x double> [ <double 1.0, double 1.0, double 1.0, double 1.0>, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
        out.push_str("vec_step:\n  %p = getelementptr inbounds double, ptr %src, i64 %i\n  %v = load <4 x double>, ptr %p, align 8\n  %next_acc = fmul <4 x double> %acc, %v\n  %next_i = add i64 %i, 4\n  br label %vec_loop, !llvm.loop !6\n");
        out.push_str("reduce:\n  %vec_prod = call double @llvm.vector.reduce.fmul.v4f64(double 1.0, <4 x double> %acc)\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi double [ %vec_prod, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp = getelementptr inbounds double, ptr %src, i64 %ti\n  %tv = load double, ptr %tp, align 8\n  %next_s_acc = fmul double %s_acc, %tv\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret double %s_acc\n}\n\n");

        out.push_str("define linkonce_odr double @ifa_simd_slice_min_f64(ptr %src, i64 %len) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -4\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <4 x double> [ <double 0x7FF0000000000000, double 0x7FF0000000000000, double 0x7FF0000000000000, double 0x7FF0000000000000>, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
        out.push_str("vec_step:\n  %p = getelementptr inbounds double, ptr %src, i64 %i\n  %v = load <4 x double>, ptr %p, align 8\n  %cmp = fcmp olt <4 x double> %v, %acc\n  %next_acc = select <4 x i1> %cmp, <4 x double> %v, <4 x double> %acc\n  %next_i = add i64 %i, 4\n  br label %vec_loop, !llvm.loop !6\n");
        out.push_str("reduce:\n  %vec_min = call double @llvm.vector.reduce.fmin.v4f64(<4 x double> %acc)\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi double [ %vec_min, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp = getelementptr inbounds double, ptr %src, i64 %ti\n  %tv = load double, ptr %tp, align 8\n  %tcmp = fcmp olt double %tv, %s_acc\n  %next_s_acc = select i1 %tcmp, double %tv, double %s_acc\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret double %s_acc\n}\n\n");

        out.push_str("define linkonce_odr double @ifa_simd_slice_max_f64(ptr %src, i64 %len) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -4\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <4 x double> [ <double 0xFFF0000000000000, double 0xFFF0000000000000, double 0xFFF0000000000000, double 0xFFF0000000000000>, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
        out.push_str("vec_step:\n  %p = getelementptr inbounds double, ptr %src, i64 %i\n  %v = load <4 x double>, ptr %p, align 8\n  %cmp = fcmp ogt <4 x double> %v, %acc\n  %next_acc = select <4 x i1> %cmp, <4 x double> %v, <4 x double> %acc\n  %next_i = add i64 %i, 4\n  br label %vec_loop, !llvm.loop !6\n");
        out.push_str("reduce:\n  %vec_max = call double @llvm.vector.reduce.fmax.v4f64(<4 x double> %acc)\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi double [ %vec_max, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp = getelementptr inbounds double, ptr %src, i64 %ti\n  %tv = load double, ptr %tp, align 8\n  %tcmp = fcmp ogt double %tv, %s_acc\n  %next_s_acc = select i1 %tcmp, double %tv, double %s_acc\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret double %s_acc\n}\n\n");

        out.push_str(
            "define linkonce_odr i64 @ifa_simd_slice_prod_i64(ptr %src, i64 %len) alwaysinline {\n",
        );
        out.push_str("entry:\n  %vec_len = and i64 %len, -4\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <4 x i64> [ <i64 1, i64 1, i64 1, i64 1>, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
        out.push_str("vec_step:\n  %p = getelementptr inbounds i64, ptr %src, i64 %i\n  %v = load <4 x i64>, ptr %p, align 8\n  %next_acc = mul <4 x i64> %acc, %v\n  %next_i = add i64 %i, 4\n  br label %vec_loop, !llvm.loop !6\n");
        out.push_str("reduce:\n  %vec_prod = call i64 @llvm.vector.reduce.mul.v4i64(<4 x i64> %acc)\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi i64 [ %vec_prod, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp = getelementptr inbounds i64, ptr %src, i64 %ti\n  %tv = load i64, ptr %tp, align 8\n  %next_s_acc = mul i64 %s_acc, %tv\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret i64 %s_acc\n}\n\n");

        out.push_str(
            "define linkonce_odr i64 @ifa_simd_slice_min_i64(ptr %src, i64 %len) alwaysinline {\n",
        );
        out.push_str("entry:\n  %vec_len = and i64 %len, -4\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <4 x i64> [ <i64 9223372036854775807, i64 9223372036854775807, i64 9223372036854775807, i64 9223372036854775807>, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
        out.push_str("vec_step:\n  %p = getelementptr inbounds i64, ptr %src, i64 %i\n  %v = load <4 x i64>, ptr %p, align 8\n  %cmp = icmp slt <4 x i64> %v, %acc\n  %next_acc = select <4 x i1> %cmp, <4 x i64> %v, <4 x i64> %acc\n  %next_i = add i64 %i, 4\n  br label %vec_loop, !llvm.loop !6\n");
        out.push_str("reduce:\n  %vec_min = call i64 @llvm.vector.reduce.smin.v4i64(<4 x i64> %acc)\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi i64 [ %vec_min, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp = getelementptr inbounds i64, ptr %src, i64 %ti\n  %tv = load i64, ptr %tp, align 8\n  %tcmp = icmp slt i64 %tv, %s_acc\n  %next_s_acc = select i1 %tcmp, i64 %tv, i64 %s_acc\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret i64 %s_acc\n}\n\n");

        out.push_str(
            "define linkonce_odr i64 @ifa_simd_slice_max_i64(ptr %src, i64 %len) alwaysinline {\n",
        );
        out.push_str("entry:\n  %vec_len = and i64 %len, -4\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <4 x i64> [ <i64 -9223372036854775808, i64 -9223372036854775808, i64 -9223372036854775808, i64 -9223372036854775808>, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
        out.push_str("vec_step:\n  %p = getelementptr inbounds i64, ptr %src, i64 %i\n  %v = load <4 x i64>, ptr %p, align 8\n  %cmp = icmp sgt <4 x i64> %v, %acc\n  %next_acc = select <4 x i1> %cmp, <4 x i64> %v, <4 x i64> %acc\n  %next_i = add i64 %i, 4\n  br label %vec_loop, !llvm.loop !6\n");
        out.push_str("reduce:\n  %vec_max = call i64 @llvm.vector.reduce.smax.v4i64(<4 x i64> %acc)\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi i64 [ %vec_max, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp = getelementptr inbounds i64, ptr %src, i64 %ti\n  %tv = load i64, ptr %tp, align 8\n  %tcmp = icmp sgt i64 %tv, %s_acc\n  %next_s_acc = select i1 %tcmp, i64 %tv, i64 %s_acc\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret i64 %s_acc\n}\n\n");

        // IFA Standard Library SIMD Contiguous Arena Slice Reductions (Zero-Heap Strict Determinism)
        out.push_str("; IFA Standard Library SIMD Contiguous Arena Slice Reductions\n");

        // 1. Arena Slice Sum (f32, f64, i32, i64)
        out.push_str("define linkonce_odr float @ifa_simd_arena_slice_sum_f32(ptr %src, i64 %len) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -8\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <8 x float> [ zeroinitializer, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
        out.push_str("vec_step:\n  %p = getelementptr inbounds float, ptr %src, i64 %i\n  %v = load <8 x float>, ptr %p, align 32\n  %next_acc = fadd <8 x float> %acc, %v\n  %next_i = add i64 %i, 8\n  br label %vec_loop, !llvm.loop !18\n");
        out.push_str("reduce:\n  %vec_sum = call float @llvm.vector.reduce.fadd.v8f32(float 0.0, <8 x float> %acc)\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi float [ %vec_sum, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp = getelementptr inbounds float, ptr %src, i64 %ti\n  %tv = load float, ptr %tp, align 4\n  %next_s_acc = fadd float %s_acc, %tv\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret float %s_acc\n}\n\n");

        out.push_str("define linkonce_odr double @ifa_simd_arena_slice_sum_f64(ptr %src, i64 %len) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -4\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <4 x double> [ zeroinitializer, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
        out.push_str("vec_step:\n  %p = getelementptr inbounds double, ptr %src, i64 %i\n  %v = load <4 x double>, ptr %p, align 32\n  %next_acc = fadd <4 x double> %acc, %v\n  %next_i = add i64 %i, 4\n  br label %vec_loop, !llvm.loop !19\n");
        out.push_str("reduce:\n  %vec_sum = call double @llvm.vector.reduce.fadd.v4f64(double 0.0, <4 x double> %acc)\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi double [ %vec_sum, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp = getelementptr inbounds double, ptr %src, i64 %ti\n  %tv = load double, ptr %tp, align 8\n  %next_s_acc = fadd double %s_acc, %tv\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret double %s_acc\n}\n\n");

        out.push_str("define linkonce_odr i32 @ifa_simd_arena_slice_sum_i32(ptr %src, i64 %len) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -8\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <8 x i32> [ zeroinitializer, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
        out.push_str("vec_step:\n  %p = getelementptr inbounds i32, ptr %src, i64 %i\n  %v = load <8 x i32>, ptr %p, align 32\n  %next_acc = add <8 x i32> %acc, %v\n  %next_i = add i64 %i, 8\n  br label %vec_loop, !llvm.loop !18\n");
        out.push_str("reduce:\n  %vec_sum = call i32 @llvm.vector.reduce.add.v8i32(<8 x i32> %acc)\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi i32 [ %vec_sum, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp = getelementptr inbounds i32, ptr %src, i64 %ti\n  %tv = load i32, ptr %tp, align 4\n  %next_s_acc = add i32 %s_acc, %tv\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret i32 %s_acc\n}\n\n");

        out.push_str("define linkonce_odr i64 @ifa_simd_arena_slice_sum_i64(ptr %src, i64 %len) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -4\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <4 x i64> [ zeroinitializer, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
        out.push_str("vec_step:\n  %p = getelementptr inbounds i64, ptr %src, i64 %i\n  %v = load <4 x i64>, ptr %p, align 32\n  %next_acc = add <4 x i64> %acc, %v\n  %next_i = add i64 %i, 4\n  br label %vec_loop, !llvm.loop !19\n");
        out.push_str("reduce:\n  %vec_sum = call i64 @llvm.vector.reduce.add.v4i64(<4 x i64> %acc)\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi i64 [ %vec_sum, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp = getelementptr inbounds i64, ptr %src, i64 %ti\n  %tv = load i64, ptr %tp, align 8\n  %next_s_acc = add i64 %s_acc, %tv\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret i64 %s_acc\n}\n\n");

        // 2. Arena Slice Product (f32, f64, i32, i64)
        out.push_str("define linkonce_odr float @ifa_simd_arena_slice_prod_f32(ptr %src, i64 %len) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -8\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <8 x float> [ <float 1.0, float 1.0, float 1.0, float 1.0, float 1.0, float 1.0, float 1.0, float 1.0>, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
        out.push_str("vec_step:\n  %p = getelementptr inbounds float, ptr %src, i64 %i\n  %v = load <8 x float>, ptr %p, align 32\n  %next_acc = fmul <8 x float> %acc, %v\n  %next_i = add i64 %i, 8\n  br label %vec_loop, !llvm.loop !18\n");
        out.push_str("reduce:\n  %vec_prod = call float @llvm.vector.reduce.fmul.v8f32(float 1.0, <8 x float> %acc)\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi float [ %vec_prod, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp = getelementptr inbounds float, ptr %src, i64 %ti\n  %tv = load float, ptr %tp, align 4\n  %next_s_acc = fmul float %s_acc, %tv\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret float %s_acc\n}\n\n");

        out.push_str("define linkonce_odr double @ifa_simd_arena_slice_prod_f64(ptr %src, i64 %len) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -4\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <4 x double> [ <double 1.0, double 1.0, double 1.0, double 1.0>, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
        out.push_str("vec_step:\n  %p = getelementptr inbounds double, ptr %src, i64 %i\n  %v = load <4 x double>, ptr %p, align 32\n  %next_acc = fmul <4 x double> %acc, %v\n  %next_i = add i64 %i, 4\n  br label %vec_loop, !llvm.loop !19\n");
        out.push_str("reduce:\n  %vec_prod = call double @llvm.vector.reduce.fmul.v4f64(double 1.0, <4 x double> %acc)\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi double [ %vec_prod, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp = getelementptr inbounds double, ptr %src, i64 %ti\n  %tv = load double, ptr %tp, align 8\n  %next_s_acc = fmul double %s_acc, %tv\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret double %s_acc\n}\n\n");

        out.push_str("define linkonce_odr i32 @ifa_simd_arena_slice_prod_i32(ptr %src, i64 %len) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -8\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <8 x i32> [ <i32 1, i32 1, i32 1, i32 1, i32 1, i32 1, i32 1, i32 1>, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
        out.push_str("vec_step:\n  %p = getelementptr inbounds i32, ptr %src, i64 %i\n  %v = load <8 x i32>, ptr %p, align 32\n  %next_acc = mul <8 x i32> %acc, %v\n  %next_i = add i64 %i, 8\n  br label %vec_loop, !llvm.loop !18\n");
        out.push_str("reduce:\n  %vec_prod = call i32 @llvm.vector.reduce.mul.v8i32(<8 x i32> %acc)\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi i32 [ %vec_prod, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp = getelementptr inbounds i32, ptr %src, i64 %ti\n  %tv = load i32, ptr %tp, align 4\n  %next_s_acc = mul i32 %s_acc, %tv\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret i32 %s_acc\n}\n\n");

        out.push_str("define linkonce_odr i64 @ifa_simd_arena_slice_prod_i64(ptr %src, i64 %len) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -4\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <4 x i64> [ <i64 1, i64 1, i64 1, i64 1>, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
        out.push_str("vec_step:\n  %p = getelementptr inbounds i64, ptr %src, i64 %i\n  %v = load <4 x i64>, ptr %p, align 32\n  %next_acc = mul <4 x i64> %acc, %v\n  %next_i = add i64 %i, 4\n  br label %vec_loop, !llvm.loop !19\n");
        out.push_str("reduce:\n  %vec_prod = call i64 @llvm.vector.reduce.mul.v4i64(<4 x i64> %acc)\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi i64 [ %vec_prod, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp = getelementptr inbounds i64, ptr %src, i64 %ti\n  %tv = load i64, ptr %tp, align 8\n  %next_s_acc = mul i64 %s_acc, %tv\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret i64 %s_acc\n}\n\n");

        // 3. Arena Slice Min (f32, f64, i32, i64)
        out.push_str("define linkonce_odr float @ifa_simd_arena_slice_min_f32(ptr %src, i64 %len) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -8\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <8 x float> [ <float 0x7FF0000000000000, float 0x7FF0000000000000, float 0x7FF0000000000000, float 0x7FF0000000000000, float 0x7FF0000000000000, float 0x7FF0000000000000, float 0x7FF0000000000000, float 0x7FF0000000000000>, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
        out.push_str("vec_step:\n  %p = getelementptr inbounds float, ptr %src, i64 %i\n  %v = load <8 x float>, ptr %p, align 32\n  %cmp = fcmp olt <8 x float> %v, %acc\n  %next_acc = select <8 x i1> %cmp, <8 x float> %v, <8 x float> %acc\n  %next_i = add i64 %i, 8\n  br label %vec_loop, !llvm.loop !18\n");
        out.push_str("reduce:\n  %vec_min = call float @llvm.vector.reduce.fmin.v8f32(<8 x float> %acc)\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi float [ %vec_min, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp = getelementptr inbounds float, ptr %src, i64 %ti\n  %tv = load float, ptr %tp, align 4\n  %tcmp = fcmp olt float %tv, %s_acc\n  %next_s_acc = select i1 %tcmp, float %tv, float %s_acc\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret float %s_acc\n}\n\n");

        out.push_str("define linkonce_odr double @ifa_simd_arena_slice_min_f64(ptr %src, i64 %len) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -4\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <4 x double> [ <double 0x7FF0000000000000, double 0x7FF0000000000000, double 0x7FF0000000000000, double 0x7FF0000000000000>, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
        out.push_str("vec_step:\n  %p = getelementptr inbounds double, ptr %src, i64 %i\n  %v = load <4 x double>, ptr %p, align 32\n  %cmp = fcmp olt <4 x double> %v, %acc\n  %next_acc = select <4 x i1> %cmp, <4 x double> %v, <4 x double> %acc\n  %next_i = add i64 %i, 4\n  br label %vec_loop, !llvm.loop !19\n");
        out.push_str("reduce:\n  %vec_min = call double @llvm.vector.reduce.fmin.v4f64(<4 x double> %acc)\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi double [ %vec_min, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp = getelementptr inbounds double, ptr %src, i64 %ti\n  %tv = load double, ptr %tp, align 8\n  %tcmp = fcmp olt double %tv, %s_acc\n  %next_s_acc = select i1 %tcmp, double %tv, double %s_acc\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret double %s_acc\n}\n\n");

        out.push_str("define linkonce_odr i32 @ifa_simd_arena_slice_min_i32(ptr %src, i64 %len) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -8\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <8 x i32> [ <i32 2147483647, i32 2147483647, i32 2147483647, i32 2147483647, i32 2147483647, i32 2147483647, i32 2147483647, i32 2147483647>, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
        out.push_str("vec_step:\n  %p = getelementptr inbounds i32, ptr %src, i64 %i\n  %v = load <8 x i32>, ptr %p, align 32\n  %cmp = icmp slt <8 x i32> %v, %acc\n  %next_acc = select <8 x i1> %cmp, <8 x i32> %v, <8 x i32> %acc\n  %next_i = add i64 %i, 8\n  br label %vec_loop, !llvm.loop !18\n");
        out.push_str("reduce:\n  %vec_min = call i32 @llvm.vector.reduce.smin.v8i32(<8 x i32> %acc)\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi i32 [ %vec_min, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp = getelementptr inbounds i32, ptr %src, i64 %ti\n  %tv = load i32, ptr %tp, align 4\n  %tcmp = icmp slt i32 %tv, %s_acc\n  %next_s_acc = select i1 %tcmp, i32 %tv, i32 %s_acc\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret i32 %s_acc\n}\n\n");

        out.push_str("define linkonce_odr i64 @ifa_simd_arena_slice_min_i64(ptr %src, i64 %len) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -4\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <4 x i64> [ <i64 9223372036854775807, i64 9223372036854775807, i64 9223372036854775807, i64 9223372036854775807>, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
        out.push_str("vec_step:\n  %p = getelementptr inbounds i64, ptr %src, i64 %i\n  %v = load <4 x i64>, ptr %p, align 32\n  %cmp = icmp slt <4 x i64> %v, %acc\n  %next_acc = select <4 x i1> %cmp, <4 x i64> %v, <4 x i64> %acc\n  %next_i = add i64 %i, 4\n  br label %vec_loop, !llvm.loop !19\n");
        out.push_str("reduce:\n  %vec_min = call i64 @llvm.vector.reduce.smin.v4i64(<4 x i64> %acc)\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi i64 [ %vec_min, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp = getelementptr inbounds i64, ptr %src, i64 %ti\n  %tv = load i64, ptr %tp, align 8\n  %tcmp = icmp slt i64 %tv, %s_acc\n  %next_s_acc = select i1 %tcmp, i64 %tv, i64 %s_acc\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret i64 %s_acc\n}\n\n");

        // 4. Arena Slice Max (f32, f64, i32, i64)
        out.push_str("define linkonce_odr float @ifa_simd_arena_slice_max_f32(ptr %src, i64 %len) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -8\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <8 x float> [ <float 0xFFF0000000000000, float 0xFFF0000000000000, float 0xFFF0000000000000, float 0xFFF0000000000000, float 0xFFF0000000000000, float 0xFFF0000000000000, float 0xFFF0000000000000, float 0xFFF0000000000000>, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
        out.push_str("vec_step:\n  %p = getelementptr inbounds float, ptr %src, i64 %i\n  %v = load <8 x float>, ptr %p, align 32\n  %cmp = fcmp ogt <8 x float> %v, %acc\n  %next_acc = select <8 x i1> %cmp, <8 x float> %v, <8 x float> %acc\n  %next_i = add i64 %i, 8\n  br label %vec_loop, !llvm.loop !18\n");
        out.push_str("reduce:\n  %vec_max = call float @llvm.vector.reduce.fmax.v8f32(<8 x float> %acc)\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi float [ %vec_max, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp = getelementptr inbounds float, ptr %src, i64 %ti\n  %tv = load float, ptr %tp, align 4\n  %tcmp = fcmp ogt float %tv, %s_acc\n  %next_s_acc = select i1 %tcmp, float %tv, float %s_acc\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret float %s_acc\n}\n\n");

        out.push_str("define linkonce_odr double @ifa_simd_arena_slice_max_f64(ptr %src, i64 %len) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -4\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <4 x double> [ <double 0xFFF0000000000000, double 0xFFF0000000000000, double 0xFFF0000000000000, double 0xFFF0000000000000>, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
        out.push_str("vec_step:\n  %p = getelementptr inbounds double, ptr %src, i64 %i\n  %v = load <4 x double>, ptr %p, align 32\n  %cmp = fcmp ogt <4 x double> %v, %acc\n  %next_acc = select <4 x i1> %cmp, <4 x double> %v, <4 x double> %acc\n  %next_i = add i64 %i, 4\n  br label %vec_loop, !llvm.loop !19\n");
        out.push_str("reduce:\n  %vec_max = call double @llvm.vector.reduce.fmax.v4f64(<4 x double> %acc)\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi double [ %vec_max, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp = getelementptr inbounds double, ptr %src, i64 %ti\n  %tv = load double, ptr %tp, align 8\n  %tcmp = fcmp ogt double %tv, %s_acc\n  %next_s_acc = select i1 %tcmp, double %tv, double %s_acc\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret double %s_acc\n}\n\n");

        out.push_str("define linkonce_odr i32 @ifa_simd_arena_slice_max_i32(ptr %src, i64 %len) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -8\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <8 x i32> [ <i32 -2147483648, i32 -2147483648, i32 -2147483648, i32 -2147483648, i32 -2147483648, i32 -2147483648, i32 -2147483648, i32 -2147483648>, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
        out.push_str("vec_step:\n  %p = getelementptr inbounds i32, ptr %src, i64 %i\n  %v = load <8 x i32>, ptr %p, align 32\n  %cmp = icmp sgt <8 x i32> %v, %acc\n  %next_acc = select <8 x i1> %cmp, <8 x i32> %v, <8 x i32> %acc\n  %next_i = add i64 %i, 8\n  br label %vec_loop, !llvm.loop !18\n");
        out.push_str("reduce:\n  %vec_max = call i32 @llvm.vector.reduce.smax.v8i32(<8 x i32> %acc)\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi i32 [ %vec_max, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp = getelementptr inbounds i32, ptr %src, i64 %ti\n  %tv = load i32, ptr %tp, align 4\n  %tcmp = icmp sgt i32 %tv, %s_acc\n  %next_s_acc = select i1 %tcmp, i32 %tv, i32 %s_acc\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret i32 %s_acc\n}\n\n");

        out.push_str("define linkonce_odr i64 @ifa_simd_arena_slice_max_i64(ptr %src, i64 %len) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -4\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <4 x i64> [ <i64 -9223372036854775808, i64 -9223372036854775808, i64 -9223372036854775808, i64 -9223372036854775808>, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
        out.push_str("vec_step:\n  %p = getelementptr inbounds i64, ptr %src, i64 %i\n  %v = load <4 x i64>, ptr %p, align 32\n  %cmp = icmp sgt <4 x i64> %v, %acc\n  %next_acc = select <4 x i1> %cmp, <4 x i64> %v, <4 x i64> %acc\n  %next_i = add i64 %i, 4\n  br label %vec_loop, !llvm.loop !19\n");
        out.push_str("reduce:\n  %vec_max = call i64 @llvm.vector.reduce.smax.v4i64(<4 x i64> %acc)\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi i64 [ %vec_max, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp = getelementptr inbounds i64, ptr %src, i64 %ti\n  %tv = load i64, ptr %tp, align 8\n  %tcmp = icmp sgt i64 %tv, %s_acc\n  %next_s_acc = select i1 %tcmp, i64 %tv, i64 %s_acc\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret i64 %s_acc\n}\n\n");

        // 5. Arena Slice Dot Product (f32, f64)
        out.push_str("define linkonce_odr float @ifa_simd_arena_slice_dot_f32(ptr %src1, ptr %src2, i64 %len) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -8\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <8 x float> [ zeroinitializer, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
        out.push_str("vec_step:\n  %p1 = getelementptr inbounds float, ptr %src1, i64 %i\n  %p2 = getelementptr inbounds float, ptr %src2, i64 %i\n  %v1 = load <8 x float>, ptr %p1, align 32\n  %v2 = load <8 x float>, ptr %p2, align 32\n  %prod = fmul <8 x float> %v1, %v2\n  %next_acc = fadd <8 x float> %acc, %prod\n  %next_i = add i64 %i, 8\n  br label %vec_loop, !llvm.loop !18\n");
        out.push_str("reduce:\n  %vec_sum = call float @llvm.vector.reduce.fadd.v8f32(float 0.0, <8 x float> %acc)\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi float [ %vec_sum, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp1 = getelementptr inbounds float, ptr %src1, i64 %ti\n  %tp2 = getelementptr inbounds float, ptr %src2, i64 %ti\n  %tv1 = load float, ptr %tp1, align 4\n  %tv2 = load float, ptr %tp2, align 4\n  %tprod = fmul float %tv1, %tv2\n  %next_s_acc = fadd float %s_acc, %tprod\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret float %s_acc\n}\n\n");

        out.push_str("define linkonce_odr double @ifa_simd_arena_slice_dot_f64(ptr %src1, ptr %src2, i64 %len) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -4\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <4 x double> [ zeroinitializer, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
        out.push_str("vec_step:\n  %p1 = getelementptr inbounds double, ptr %src1, i64 %i\n  %p2 = getelementptr inbounds double, ptr %src2, i64 %i\n  %v1 = load <4 x double>, ptr %p1, align 32\n  %v2 = load <4 x double>, ptr %p2, align 32\n  %prod = fmul <4 x double> %v1, %v2\n  %next_acc = fadd <4 x double> %acc, %prod\n  %next_i = add i64 %i, 4\n  br label %vec_loop, !llvm.loop !19\n");
        out.push_str("reduce:\n  %vec_sum = call double @llvm.vector.reduce.fadd.v4f64(double 0.0, <4 x double> %acc)\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi double [ %vec_sum, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp1 = getelementptr inbounds double, ptr %src1, i64 %ti\n  %tp2 = getelementptr inbounds double, ptr %src2, i64 %ti\n  %tv1 = load double, ptr %tp1, align 8\n  %tv2 = load double, ptr %tp2, align 8\n  %tprod = fmul double %tv1, %tv2\n  %next_s_acc = fadd double %s_acc, %tprod\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret double %s_acc\n}\n\n");

        // 5b. Strided Slice Reductions & Dot Products (Downsampling, Channel Projections, Zero-Heap)
        out.push_str("; IFA Standard Library SIMD Strided Slice Reductions\n");

        out.push_str("define linkonce_odr float @ifa_simd_strided_slice_sum_f32(ptr %src, i64 %len, i64 %stride) alwaysinline {\n");
        out.push_str("entry:\n  %is_contig = icmp eq i64 %stride, 1\n  br i1 %is_contig, label %contig_fast, label %strided_init\n");
        out.push_str("contig_fast:\n  %c_res = call float @ifa_simd_arena_slice_sum_f32(ptr %src, i64 %len)\n  ret float %c_res\n");
        out.push_str("strided_init:\n  %unroll_len = and i64 %len, -4\n  br label %unroll_loop\n");
        out.push_str("unroll_loop:\n  %i = phi i64 [ 0, %strided_init ], [ %next_i, %unroll_step ]\n  %acc = phi float [ 0.0, %strided_init ], [ %next_acc, %unroll_step ]\n  %has_unroll = icmp ult i64 %i, %unroll_len\n  br i1 %has_unroll, label %unroll_step, label %tail_loop\n");
        out.push_str("unroll_step:\n  %idx0 = mul i64 %i, %stride\n  %i1 = add i64 %i, 1\n  %idx1 = mul i64 %i1, %stride\n  %i2 = add i64 %i, 2\n  %idx2 = mul i64 %i2, %stride\n  %i3 = add i64 %i, 3\n  %idx3 = mul i64 %i3, %stride\n  %p0 = getelementptr inbounds float, ptr %src, i64 %idx0\n  %p1 = getelementptr inbounds float, ptr %src, i64 %idx1\n  %p2 = getelementptr inbounds float, ptr %src, i64 %idx2\n  %p3 = getelementptr inbounds float, ptr %src, i64 %idx3\n  %v0 = load float, ptr %p0, align 4\n  %v1 = load float, ptr %p1, align 4\n  %v2 = load float, ptr %p2, align 4\n  %v3 = load float, ptr %p3, align 4\n  %s01 = fadd float %v0, %v1\n  %s23 = fadd float %v2, %v3\n  %s03 = fadd float %s01, %s23\n  %next_acc = fadd float %acc, %s03\n  %next_i = add i64 %i, 4\n  br label %unroll_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %unroll_len, %unroll_loop ], [ %next_ti, %tail_step ]\n  %t_acc = phi float [ %acc, %unroll_loop ], [ %next_t_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %t_idx = mul i64 %ti, %stride\n  %tp = getelementptr inbounds float, ptr %src, i64 %t_idx\n  %tv = load float, ptr %tp, align 4\n  %next_t_acc = fadd float %t_acc, %tv\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret float %t_acc\n}\n\n");

        out.push_str("define linkonce_odr double @ifa_simd_strided_slice_sum_f64(ptr %src, i64 %len, i64 %stride) alwaysinline {\n");
        out.push_str("entry:\n  %is_contig = icmp eq i64 %stride, 1\n  br i1 %is_contig, label %contig_fast, label %strided_init\n");
        out.push_str("contig_fast:\n  %c_res = call double @ifa_simd_arena_slice_sum_f64(ptr %src, i64 %len)\n  ret double %c_res\n");
        out.push_str("strided_init:\n  %unroll_len = and i64 %len, -4\n  br label %unroll_loop\n");
        out.push_str("unroll_loop:\n  %i = phi i64 [ 0, %strided_init ], [ %next_i, %unroll_step ]\n  %acc = phi double [ 0.0, %strided_init ], [ %next_acc, %unroll_step ]\n  %has_unroll = icmp ult i64 %i, %unroll_len\n  br i1 %has_unroll, label %unroll_step, label %tail_loop\n");
        out.push_str("unroll_step:\n  %idx0 = mul i64 %i, %stride\n  %i1 = add i64 %i, 1\n  %idx1 = mul i64 %i1, %stride\n  %i2 = add i64 %i, 2\n  %idx2 = mul i64 %i2, %stride\n  %i3 = add i64 %i, 3\n  %idx3 = mul i64 %i3, %stride\n  %p0 = getelementptr inbounds double, ptr %src, i64 %idx0\n  %p1 = getelementptr inbounds double, ptr %src, i64 %idx1\n  %p2 = getelementptr inbounds double, ptr %src, i64 %idx2\n  %p3 = getelementptr inbounds double, ptr %src, i64 %idx3\n  %v0 = load double, ptr %p0, align 8\n  %v1 = load double, ptr %p1, align 8\n  %v2 = load double, ptr %p2, align 8\n  %v3 = load double, ptr %p3, align 8\n  %s01 = fadd double %v0, %v1\n  %s23 = fadd double %v2, %v3\n  %s03 = fadd double %s01, %s23\n  %next_acc = fadd double %acc, %s03\n  %next_i = add i64 %i, 4\n  br label %unroll_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %unroll_len, %unroll_loop ], [ %next_ti, %tail_step ]\n  %t_acc = phi double [ %acc, %unroll_loop ], [ %next_t_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %t_idx = mul i64 %ti, %stride\n  %tp = getelementptr inbounds double, ptr %src, i64 %t_idx\n  %tv = load double, ptr %tp, align 8\n  %next_t_acc = fadd double %t_acc, %tv\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret double %t_acc\n}\n\n");

        out.push_str("define linkonce_odr i32 @ifa_simd_strided_slice_sum_i32(ptr %src, i64 %len, i64 %stride) alwaysinline {\n");
        out.push_str("entry:\n  %is_contig = icmp eq i64 %stride, 1\n  br i1 %is_contig, label %contig_fast, label %strided_init\n");
        out.push_str("contig_fast:\n  %c_res = call i32 @ifa_simd_arena_slice_sum_i32(ptr %src, i64 %len)\n  ret i32 %c_res\n");
        out.push_str("strided_init:\n  %unroll_len = and i64 %len, -4\n  br label %unroll_loop\n");
        out.push_str("unroll_loop:\n  %i = phi i64 [ 0, %strided_init ], [ %next_i, %unroll_step ]\n  %acc = phi i32 [ 0, %strided_init ], [ %next_acc, %unroll_step ]\n  %has_unroll = icmp ult i64 %i, %unroll_len\n  br i1 %has_unroll, label %unroll_step, label %tail_loop\n");
        out.push_str("unroll_step:\n  %idx0 = mul i64 %i, %stride\n  %i1 = add i64 %i, 1\n  %idx1 = mul i64 %i1, %stride\n  %i2 = add i64 %i, 2\n  %idx2 = mul i64 %i2, %stride\n  %i3 = add i64 %i, 3\n  %idx3 = mul i64 %i3, %stride\n  %p0 = getelementptr inbounds i32, ptr %src, i64 %idx0\n  %p1 = getelementptr inbounds i32, ptr %src, i64 %idx1\n  %p2 = getelementptr inbounds i32, ptr %src, i64 %idx2\n  %p3 = getelementptr inbounds i32, ptr %src, i64 %idx3\n  %v0 = load i32, ptr %p0, align 4\n  %v1 = load i32, ptr %p1, align 4\n  %v2 = load i32, ptr %p2, align 4\n  %v3 = load i32, ptr %p3, align 4\n  %s01 = add i32 %v0, %v1\n  %s23 = add i32 %v2, %v3\n  %s03 = add i32 %s01, %s23\n  %next_acc = add i32 %acc, %s03\n  %next_i = add i64 %i, 4\n  br label %unroll_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %unroll_len, %unroll_loop ], [ %next_ti, %tail_step ]\n  %t_acc = phi i32 [ %acc, %unroll_loop ], [ %next_t_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %t_idx = mul i64 %ti, %stride\n  %tp = getelementptr inbounds i32, ptr %src, i64 %t_idx\n  %tv = load i32, ptr %tp, align 4\n  %next_t_acc = add i32 %t_acc, %tv\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret i32 %t_acc\n}\n\n");

        out.push_str("define linkonce_odr i64 @ifa_simd_strided_slice_sum_i64(ptr %src, i64 %len, i64 %stride) alwaysinline {\n");
        out.push_str("entry:\n  %is_contig = icmp eq i64 %stride, 1\n  br i1 %is_contig, label %contig_fast, label %strided_init\n");
        out.push_str("contig_fast:\n  %c_res = call i64 @ifa_simd_arena_slice_sum_i64(ptr %src, i64 %len)\n  ret i64 %c_res\n");
        out.push_str("strided_init:\n  %unroll_len = and i64 %len, -4\n  br label %unroll_loop\n");
        out.push_str("unroll_loop:\n  %i = phi i64 [ 0, %strided_init ], [ %next_i, %unroll_step ]\n  %acc = phi i64 [ 0, %strided_init ], [ %next_acc, %unroll_step ]\n  %has_unroll = icmp ult i64 %i, %unroll_len\n  br i1 %has_unroll, label %unroll_step, label %tail_loop\n");
        out.push_str("unroll_step:\n  %idx0 = mul i64 %i, %stride\n  %i1 = add i64 %i, 1\n  %idx1 = mul i64 %i1, %stride\n  %i2 = add i64 %i, 2\n  %idx2 = mul i64 %i2, %stride\n  %i3 = add i64 %i, 3\n  %idx3 = mul i64 %i3, %stride\n  %p0 = getelementptr inbounds i64, ptr %src, i64 %idx0\n  %p1 = getelementptr inbounds i64, ptr %src, i64 %idx1\n  %p2 = getelementptr inbounds i64, ptr %src, i64 %idx2\n  %p3 = getelementptr inbounds i64, ptr %src, i64 %idx3\n  %v0 = load i64, ptr %p0, align 8\n  %v1 = load i64, ptr %p1, align 8\n  %v2 = load i64, ptr %p2, align 8\n  %v3 = load i64, ptr %p3, align 8\n  %s01 = add i64 %v0, %v1\n  %s23 = add i64 %v2, %v3\n  %s03 = add i64 %s01, %s23\n  %next_acc = add i64 %acc, %s03\n  %next_i = add i64 %i, 4\n  br label %unroll_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %unroll_len, %unroll_loop ], [ %next_ti, %tail_step ]\n  %t_acc = phi i64 [ %acc, %unroll_loop ], [ %next_t_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %t_idx = mul i64 %ti, %stride\n  %tp = getelementptr inbounds i64, ptr %src, i64 %t_idx\n  %tv = load i64, ptr %tp, align 8\n  %next_t_acc = add i64 %t_acc, %tv\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret i64 %t_acc\n}\n\n");

        out.push_str("define linkonce_odr float @ifa_simd_strided_slice_dot_f32(ptr %src1, ptr %src2, i64 %len, i64 %stride) alwaysinline {\n");
        out.push_str("entry:\n  %is_contig = icmp eq i64 %stride, 1\n  br i1 %is_contig, label %contig_fast, label %strided_init\n");
        out.push_str("contig_fast:\n  %c_res = call float @ifa_simd_arena_slice_dot_f32(ptr %src1, ptr %src2, i64 %len)\n  ret float %c_res\n");
        out.push_str("strided_init:\n  %unroll_len = and i64 %len, -4\n  br label %unroll_loop\n");
        out.push_str("unroll_loop:\n  %i = phi i64 [ 0, %strided_init ], [ %next_i, %unroll_step ]\n  %acc = phi float [ 0.0, %strided_init ], [ %next_acc, %unroll_step ]\n  %has_unroll = icmp ult i64 %i, %unroll_len\n  br i1 %has_unroll, label %unroll_step, label %tail_loop\n");
        out.push_str("unroll_step:\n  %idx0 = mul i64 %i, %stride\n  %i1 = add i64 %i, 1\n  %idx1 = mul i64 %i1, %stride\n  %i2 = add i64 %i, 2\n  %idx2 = mul i64 %i2, %stride\n  %i3 = add i64 %i, 3\n  %idx3 = mul i64 %i3, %stride\n  %p1_0 = getelementptr inbounds float, ptr %src1, i64 %idx0\n  %p2_0 = getelementptr inbounds float, ptr %src2, i64 %idx0\n  %p1_1 = getelementptr inbounds float, ptr %src1, i64 %idx1\n  %p2_1 = getelementptr inbounds float, ptr %src2, i64 %idx1\n  %p1_2 = getelementptr inbounds float, ptr %src1, i64 %idx2\n  %p2_2 = getelementptr inbounds float, ptr %src2, i64 %idx2\n  %p1_3 = getelementptr inbounds float, ptr %src1, i64 %idx3\n  %p2_3 = getelementptr inbounds float, ptr %src2, i64 %idx3\n  %v1_0 = load float, ptr %p1_0, align 4\n  %v2_0 = load float, ptr %p2_0, align 4\n  %v1_1 = load float, ptr %p1_1, align 4\n  %v2_1 = load float, ptr %p2_1, align 4\n  %v1_2 = load float, ptr %p1_2, align 4\n  %v2_2 = load float, ptr %p2_2, align 4\n  %v1_3 = load float, ptr %p1_3, align 4\n  %v2_3 = load float, ptr %p2_3, align 4\n  %prod0 = fmul float %v1_0, %v2_0\n  %prod1 = fmul float %v1_1, %v2_1\n  %prod2 = fmul float %v1_2, %v2_2\n  %prod3 = fmul float %v1_3, %v2_3\n  %s01 = fadd float %prod0, %prod1\n  %s23 = fadd float %prod2, %prod3\n  %s03 = fadd float %s01, %s23\n  %next_acc = fadd float %acc, %s03\n  %next_i = add i64 %i, 4\n  br label %unroll_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %unroll_len, %unroll_loop ], [ %next_ti, %tail_step ]\n  %t_acc = phi float [ %acc, %unroll_loop ], [ %next_t_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %t_idx = mul i64 %ti, %stride\n  %tp1 = getelementptr inbounds float, ptr %src1, i64 %t_idx\n  %tp2 = getelementptr inbounds float, ptr %src2, i64 %t_idx\n  %tv1 = load float, ptr %tp1, align 4\n  %tv2 = load float, ptr %tp2, align 4\n  %tprod = fmul float %tv1, %tv2\n  %next_t_acc = fadd float %t_acc, %tprod\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret float %t_acc\n}\n\n");

        out.push_str("define linkonce_odr double @ifa_simd_strided_slice_dot_f64(ptr %src1, ptr %src2, i64 %len, i64 %stride) alwaysinline {\n");
        out.push_str("entry:\n  %is_contig = icmp eq i64 %stride, 1\n  br i1 %is_contig, label %contig_fast, label %strided_init\n");
        out.push_str("contig_fast:\n  %c_res = call double @ifa_simd_arena_slice_dot_f64(ptr %src1, ptr %src2, i64 %len)\n  ret double %c_res\n");
        out.push_str("strided_init:\n  %unroll_len = and i64 %len, -4\n  br label %unroll_loop\n");
        out.push_str("unroll_loop:\n  %i = phi i64 [ 0, %strided_init ], [ %next_i, %unroll_step ]\n  %acc = phi double [ 0.0, %strided_init ], [ %next_acc, %unroll_step ]\n  %has_unroll = icmp ult i64 %i, %unroll_len\n  br i1 %has_unroll, label %unroll_step, label %tail_loop\n");
        out.push_str("unroll_step:\n  %idx0 = mul i64 %i, %stride\n  %i1 = add i64 %i, 1\n  %idx1 = mul i64 %i1, %stride\n  %i2 = add i64 %i, 2\n  %idx2 = mul i64 %i2, %stride\n  %i3 = add i64 %i, 3\n  %idx3 = mul i64 %i3, %stride\n  %p1_0 = getelementptr inbounds double, ptr %src1, i64 %idx0\n  %p2_0 = getelementptr inbounds double, ptr %src2, i64 %idx0\n  %p1_1 = getelementptr inbounds double, ptr %src1, i64 %idx1\n  %p2_1 = getelementptr inbounds double, ptr %src2, i64 %idx1\n  %p1_2 = getelementptr inbounds double, ptr %src1, i64 %idx2\n  %p2_2 = getelementptr inbounds double, ptr %src2, i64 %idx2\n  %p1_3 = getelementptr inbounds double, ptr %src1, i64 %idx3\n  %p2_3 = getelementptr inbounds double, ptr %src2, i64 %idx3\n  %v1_0 = load double, ptr %p1_0, align 8\n  %v2_0 = load double, ptr %p2_0, align 8\n  %v1_1 = load double, ptr %p1_1, align 8\n  %v2_1 = load double, ptr %p2_1, align 8\n  %v1_2 = load double, ptr %p1_2, align 8\n  %v2_2 = load double, ptr %p2_2, align 8\n  %v1_3 = load double, ptr %p1_3, align 8\n  %v2_3 = load double, ptr %p2_3, align 8\n  %prod0 = fmul double %v1_0, %v2_0\n  %prod1 = fmul double %v1_1, %v2_1\n  %prod2 = fmul double %v1_2, %v2_2\n  %prod3 = fmul double %v1_3, %v2_3\n  %s01 = fadd double %prod0, %prod1\n  %s23 = fadd double %prod2, %prod3\n  %s03 = fadd double %s01, %s23\n  %next_acc = fadd double %acc, %s03\n  %next_i = add i64 %i, 4\n  br label %unroll_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %unroll_len, %unroll_loop ], [ %next_ti, %tail_step ]\n  %t_acc = phi double [ %acc, %unroll_loop ], [ %next_t_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %t_idx = mul i64 %ti, %stride\n  %tp1 = getelementptr inbounds double, ptr %src1, i64 %t_idx\n  %tp2 = getelementptr inbounds double, ptr %src2, i64 %t_idx\n  %tv1 = load double, ptr %tp1, align 8\n  %tv2 = load double, ptr %tp2, align 8\n  %tprod = fmul double %tv1, %tv2\n  %next_t_acc = fadd double %t_acc, %tprod\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret double %t_acc\n}\n\n");

        out.push_str("define linkonce_odr float @ifa_simd_multi_arena_slice_dot_f32(ptr %src1, ptr %src2, i64 %len, i64 %stride1, i64 %stride2) alwaysinline {\n");
        out.push_str("entry:\n  %both_contig = and i1 1, 1\n  %is_c1 = icmp eq i64 %stride1, 1\n  %is_c2 = icmp eq i64 %stride2, 1\n  %is_all_c = and i1 %is_c1, %is_c2\n  br i1 %is_all_c, label %c_fast, label %s_init\n");
        out.push_str("c_fast:\n  %cr = call float @ifa_simd_arena_slice_dot_f32(ptr %src1, ptr %src2, i64 %len)\n  ret float %cr\n");
        out.push_str("s_init:\n  %unroll_len = and i64 %len, -4\n  br label %u_loop\n");
        out.push_str("u_loop:\n  %i = phi i64 [ 0, %s_init ], [ %next_i, %u_step ]\n  %acc = phi float [ 0.0, %s_init ], [ %next_acc, %u_step ]\n  %has_u = icmp ult i64 %i, %unroll_len\n  br i1 %has_u, label %u_step, label %t_loop\n");
        out.push_str("u_step:\n  %idx1_0 = mul i64 %i, %stride1\n  %idx2_0 = mul i64 %i, %stride2\n  %i1 = add i64 %i, 1\n  %idx1_1 = mul i64 %i1, %stride1\n  %idx2_1 = mul i64 %i1, %stride2\n  %i2 = add i64 %i, 2\n  %idx1_2 = mul i64 %i2, %stride1\n  %idx2_2 = mul i64 %i2, %stride2\n  %i3 = add i64 %i, 3\n  %idx1_3 = mul i64 %i3, %stride1\n  %idx2_3 = mul i64 %i3, %stride2\n  %p1_0 = getelementptr inbounds float, ptr %src1, i64 %idx1_0\n  %p2_0 = getelementptr inbounds float, ptr %src2, i64 %idx2_0\n  %p1_1 = getelementptr inbounds float, ptr %src1, i64 %idx1_1\n  %p2_1 = getelementptr inbounds float, ptr %src2, i64 %idx2_1\n  %p1_2 = getelementptr inbounds float, ptr %src1, i64 %idx1_2\n  %p2_2 = getelementptr inbounds float, ptr %src2, i64 %idx2_2\n  %p1_3 = getelementptr inbounds float, ptr %src1, i64 %idx1_3\n  %p2_3 = getelementptr inbounds float, ptr %src2, i64 %idx2_3\n  %v1_0 = load float, ptr %p1_0, align 4\n  %v2_0 = load float, ptr %p2_0, align 4\n  %v1_1 = load float, ptr %p1_1, align 4\n  %v2_1 = load float, ptr %p2_1, align 4\n  %v1_2 = load float, ptr %p1_2, align 4\n  %v2_2 = load float, ptr %p2_2, align 4\n  %v1_3 = load float, ptr %p1_3, align 4\n  %v2_3 = load float, ptr %p2_3, align 4\n  %prod0 = fmul float %v1_0, %v2_0\n  %prod1 = fmul float %v1_1, %v2_1\n  %prod2 = fmul float %v1_2, %v2_2\n  %prod3 = fmul float %v1_3, %v2_3\n  %s01 = fadd float %prod0, %prod1\n  %s23 = fadd float %prod2, %prod3\n  %s03 = fadd float %s01, %s23\n  %next_acc = fadd float %acc, %s03\n  %next_i = add i64 %i, 4\n  br label %u_loop\n");
        out.push_str("t_loop:\n  %ti = phi i64 [ %unroll_len, %u_loop ], [ %next_ti, %t_step ]\n  %t_acc = phi float [ %acc, %u_loop ], [ %next_t_acc, %t_step ]\n  %has_t = icmp ult i64 %ti, %len\n  br i1 %has_t, label %t_step, label %done\n");
        out.push_str("t_step:\n  %t_idx1 = mul i64 %ti, %stride1\n  %t_idx2 = mul i64 %ti, %stride2\n  %tp1 = getelementptr inbounds float, ptr %src1, i64 %t_idx1\n  %tp2 = getelementptr inbounds float, ptr %src2, i64 %t_idx2\n  %tv1 = load float, ptr %tp1, align 4\n  %tv2 = load float, ptr %tp2, align 4\n  %tprod = fmul float %tv1, %tv2\n  %next_t_acc = fadd float %t_acc, %tprod\n  %next_ti = add i64 %ti, 1\n  br label %t_loop\n");
        out.push_str("done:\n  ret float %t_acc\n}\n\n");

        out.push_str("define linkonce_odr double @ifa_simd_multi_arena_slice_dot_f64(ptr %src1, ptr %src2, i64 %len, i64 %stride1, i64 %stride2) alwaysinline {\n");
        out.push_str("entry:\n  %is_c1 = icmp eq i64 %stride1, 1\n  %is_c2 = icmp eq i64 %stride2, 1\n  %is_all_c = and i1 %is_c1, %is_c2\n  br i1 %is_all_c, label %c_fast, label %s_init\n");
        out.push_str("c_fast:\n  %cr = call double @ifa_simd_arena_slice_dot_f64(ptr %src1, ptr %src2, i64 %len)\n  ret double %cr\n");
        out.push_str("s_init:\n  %unroll_len = and i64 %len, -4\n  br label %u_loop\n");
        out.push_str("u_loop:\n  %i = phi i64 [ 0, %s_init ], [ %next_i, %u_step ]\n  %acc = phi double [ 0.0, %s_init ], [ %next_acc, %u_step ]\n  %has_u = icmp ult i64 %i, %unroll_len\n  br i1 %has_u, label %u_step, label %t_loop\n");
        out.push_str("u_step:\n  %idx1_0 = mul i64 %i, %stride1\n  %idx2_0 = mul i64 %i, %stride2\n  %i1 = add i64 %i, 1\n  %idx1_1 = mul i64 %i1, %stride1\n  %idx2_1 = mul i64 %i1, %stride2\n  %i2 = add i64 %i, 2\n  %idx1_2 = mul i64 %i2, %stride1\n  %idx2_2 = mul i64 %i2, %stride2\n  %i3 = add i64 %i, 3\n  %idx1_3 = mul i64 %i3, %stride1\n  %idx2_3 = mul i64 %i3, %stride2\n  %p1_0 = getelementptr inbounds double, ptr %src1, i64 %idx1_0\n  %p2_0 = getelementptr inbounds double, ptr %src2, i64 %idx2_0\n  %p1_1 = getelementptr inbounds double, ptr %src1, i64 %idx1_1\n  %p2_1 = getelementptr inbounds double, ptr %src2, i64 %idx2_1\n  %p1_2 = getelementptr inbounds double, ptr %src1, i64 %idx1_2\n  %p2_2 = getelementptr inbounds double, ptr %src2, i64 %idx2_2\n  %p1_3 = getelementptr inbounds double, ptr %src1, i64 %idx1_3\n  %p2_3 = getelementptr inbounds double, ptr %src2, i64 %idx2_3\n  %v1_0 = load double, ptr %p1_0, align 8\n  %v2_0 = load double, ptr %p2_0, align 8\n  %v1_1 = load double, ptr %p1_1, align 8\n  %v2_1 = load double, ptr %p2_1, align 8\n  %v1_2 = load double, ptr %p1_2, align 8\n  %v2_2 = load double, ptr %p2_2, align 8\n  %v1_3 = load double, ptr %p1_3, align 8\n  %v2_3 = load double, ptr %p2_3, align 8\n  %prod0 = fmul double %v1_0, %v2_0\n  %prod1 = fmul double %v1_1, %v2_1\n  %prod2 = fmul double %v1_2, %v2_2\n  %prod3 = fmul double %v1_3, %v2_3\n  %s01 = fadd double %prod0, %prod1\n  %s23 = fadd double %prod2, %prod3\n  %s03 = fadd double %s01, %s23\n  %next_acc = fadd double %acc, %s03\n  %next_i = add i64 %i, 4\n  br label %u_loop\n");
        out.push_str("t_loop:\n  %ti = phi i64 [ %unroll_len, %u_loop ], [ %next_ti, %t_step ]\n  %t_acc = phi double [ %acc, %u_loop ], [ %next_t_acc, %t_step ]\n  %has_t = icmp ult i64 %ti, %len\n  br i1 %has_t, label %t_step, label %done\n");
        out.push_str("t_step:\n  %t_idx1 = mul i64 %ti, %stride1\n  %t_idx2 = mul i64 %ti, %stride2\n  %tp1 = getelementptr inbounds double, ptr %src1, i64 %t_idx1\n  %tp2 = getelementptr inbounds double, ptr %src2, i64 %t_idx2\n  %tv1 = load double, ptr %tp1, align 8\n  %tv2 = load double, ptr %tp2, align 8\n  %tprod = fmul double %tv1, %tv2\n  %next_t_acc = fadd double %t_acc, %tprod\n  %next_ti = add i64 %ti, 1\n  br label %t_loop\n");
        out.push_str("done:\n  ret double %t_acc\n}\n\n");

        out.push_str("define linkonce_odr void @ifa_simd_multi_arena_tripartite_f32(ptr %dst, ptr %src1, ptr %src2, i64 %len, i64 %stride_dst, i64 %stride1, i64 %stride2) alwaysinline {\n");
        out.push_str("entry:\n  %unroll_len = and i64 %len, -4\n  br label %u_loop\n");
        out.push_str("u_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %u_step ]\n  %has_u = icmp ult i64 %i, %unroll_len\n  br i1 %has_u, label %u_step, label %t_loop\n");
        out.push_str("u_step:\n  %id0 = mul i64 %i, %stride_dst\n  %i1_0 = mul i64 %i, %stride1\n  %i2_0 = mul i64 %i, %stride2\n  %i_1 = add i64 %i, 1\n  %id1 = mul i64 %i_1, %stride_dst\n  %i1_1 = mul i64 %i_1, %stride1\n  %i2_1 = mul i64 %i_1, %stride2\n  %i_2 = add i64 %i, 2\n  %id2 = mul i64 %i_2, %stride_dst\n  %i1_2 = mul i64 %i_2, %stride1\n  %i2_2 = mul i64 %i_2, %stride2\n  %i_3 = add i64 %i, 3\n  %id3 = mul i64 %i_3, %stride_dst\n  %i1_3 = mul i64 %i_3, %stride1\n  %i2_3 = mul i64 %i_3, %stride2\n  %pd0 = getelementptr inbounds float, ptr %dst, i64 %id0\n  %pd1 = getelementptr inbounds float, ptr %dst, i64 %id1\n  %pd2 = getelementptr inbounds float, ptr %dst, i64 %id2\n  %pd3 = getelementptr inbounds float, ptr %dst, i64 %id3\n  %p1_0 = getelementptr inbounds float, ptr %src1, i64 %i1_0\n  %p1_1 = getelementptr inbounds float, ptr %src1, i64 %i1_1\n  %p1_2 = getelementptr inbounds float, ptr %src1, i64 %i1_2\n  %p1_3 = getelementptr inbounds float, ptr %src1, i64 %i1_3\n  %p2_0 = getelementptr inbounds float, ptr %src2, i64 %i2_0\n  %p2_1 = getelementptr inbounds float, ptr %src2, i64 %i2_1\n  %p2_2 = getelementptr inbounds float, ptr %src2, i64 %i2_2\n  %p2_3 = getelementptr inbounds float, ptr %src2, i64 %i2_3\n  %vd0 = load float, ptr %pd0, align 4\n  %vd1 = load float, ptr %pd1, align 4\n  %vd2 = load float, ptr %pd2, align 4\n  %vd3 = load float, ptr %pd3, align 4\n  %v1_0 = load float, ptr %p1_0, align 4\n  %v1_1 = load float, ptr %p1_1, align 4\n  %v1_2 = load float, ptr %p1_2, align 4\n  %v1_3 = load float, ptr %p1_3, align 4\n  %v2_0 = load float, ptr %p2_0, align 4\n  %v2_1 = load float, ptr %p2_1, align 4\n  %v2_2 = load float, ptr %p2_2, align 4\n  %v2_3 = load float, ptr %p2_3, align 4\n  %pr0 = fmul float %v1_0, %v2_0\n  %pr1 = fmul float %v1_1, %v2_1\n  %pr2 = fmul float %v1_2, %v2_2\n  %pr3 = fmul float %v1_3, %v2_3\n  %r0 = fadd float %vd0, %pr0\n  %r1 = fadd float %vd1, %pr1\n  %r2 = fadd float %vd2, %pr2\n  %r3 = fadd float %vd3, %pr3\n  store float %r0, ptr %pd0, align 4\n  store float %r1, ptr %pd1, align 4\n  store float %r2, ptr %pd2, align 4\n  store float %r3, ptr %pd3, align 4\n  %next_i = add i64 %i, 4\n  br label %u_loop\n");
        out.push_str("t_loop:\n  %ti = phi i64 [ %unroll_len, %u_loop ], [ %next_ti, %t_step ]\n  %has_t = icmp ult i64 %ti, %len\n  br i1 %has_t, label %t_step, label %done\n");
        out.push_str("t_step:\n  %tid = mul i64 %ti, %stride_dst\n  %ti1 = mul i64 %ti, %stride1\n  %ti2 = mul i64 %ti, %stride2\n  %tpd = getelementptr inbounds float, ptr %dst, i64 %tid\n  %tp1 = getelementptr inbounds float, ptr %src1, i64 %ti1\n  %tp2 = getelementptr inbounds float, ptr %src2, i64 %ti2\n  %tvd = load float, ptr %tpd, align 4\n  %tv1 = load float, ptr %tp1, align 4\n  %tv2 = load float, ptr %tp2, align 4\n  %tpr = fmul float %tv1, %tv2\n  %tr = fadd float %tvd, %tpr\n  store float %tr, ptr %tpd, align 4\n  %next_ti = add i64 %ti, 1\n  br label %t_loop\n");
        out.push_str("done:\n  ret void\n}\n\n");

        out.push_str("define linkonce_odr void @ifa_simd_multi_arena_conv2d_f32(ptr %dst, ptr %img, ptr %weights, ptr %bias, i64 %h_out, i64 %w_out, i64 %stride_y, i64 %stride_x, i64 %img_width, i32 %activation) alwaysinline {\n");
        out.push_str("entry:\n  %has_bias = icmp ne ptr %bias, null\n  %w0 = load float, ptr %weights, align 4\n  br i1 %has_bias, label %load_b, label %zero_b\n");
        out.push_str("load_b:\n  %b_val = load float, ptr %bias, align 4\n  br label %y_init\n");
        out.push_str("zero_b:\n  br label %y_init\n");
        out.push_str("y_init:\n  %bias_scalar = phi float [ %b_val, %load_b ], [ 0.0, %zero_b ]\n  %is_relu = icmp eq i32 %activation, 1\n  br label %y_loop\n");
        out.push_str("y_loop:\n  %y = phi i64 [ 0, %y_init ], [ %next_y, %y_next ]\n  %has_y = icmp ult i64 %y, %h_out\n  br i1 %has_y, label %x_init, label %done\n");
        out.push_str("x_init:\n  %y_str = mul i64 %y, %stride_y\n  %y_off = mul i64 %y_str, %img_width\n  %y_out_off = mul i64 %y, %w_out\n  br label %x_loop\n");
        out.push_str("x_loop:\n  %x = phi i64 [ 0, %x_init ], [ %next_x, %x_step ]\n  %has_x = icmp ult i64 %x, %w_out\n  br i1 %has_x, label %x_step, label %y_next\n");
        out.push_str("x_step:\n  %x_str = mul i64 %x, %stride_x\n  %in_idx = add i64 %y_off, %x_str\n  %out_idx = add i64 %y_out_off, %x\n  %p_in = getelementptr inbounds float, ptr %img, i64 %in_idx\n  %v_in = load float, ptr %p_in, align 4\n  %prod = fmul float %v_in, %w0\n  %accum = fadd float %prod, %bias_scalar\n  %relu_cond = fcmp ogt float %accum, 0.0\n  %relu_val = select i1 %relu_cond, float %accum, float 0.0\n  %act_val = select i1 %is_relu, float %relu_val, float %accum\n  %p_dst = getelementptr inbounds float, ptr %dst, i64 %out_idx\n  %old_dst = load float, ptr %p_dst, align 4\n  %new_dst = fadd float %old_dst, %act_val\n  store float %new_dst, ptr %p_dst, align 4\n  %next_x = add i64 %x, 1\n  br label %x_loop, !llvm.loop !74\n");
        out.push_str("y_next:\n  %next_y = add i64 %y, 1\n  br label %y_loop\n");
        out.push_str("done:\n  ret void\n}\n\n");

        out.push_str("define linkonce_odr void @ifa_simd_multi_arena_conv2d_f64(ptr %dst, ptr %img, ptr %weights, ptr %bias, i64 %h_out, i64 %w_out, i64 %stride_y, i64 %stride_x, i64 %img_width, i32 %activation) alwaysinline {\n");
        out.push_str("entry:\n  %has_bias = icmp ne ptr %bias, null\n  %w0 = load double, ptr %weights, align 8\n  br i1 %has_bias, label %load_b, label %zero_b\n");
        out.push_str("load_b:\n  %b_val = load double, ptr %bias, align 8\n  br label %y_init\n");
        out.push_str("zero_b:\n  br label %y_init\n");
        out.push_str("y_init:\n  %bias_scalar = phi double [ %b_val, %load_b ], [ 0.0, %zero_b ]\n  %is_relu = icmp eq i32 %activation, 1\n  br label %y_loop\n");
        out.push_str("y_loop:\n  %y = phi i64 [ 0, %y_init ], [ %next_y, %y_next ]\n  %has_y = icmp ult i64 %y, %h_out\n  br i1 %has_y, label %x_init, label %done\n");
        out.push_str("x_init:\n  %y_str = mul i64 %y, %stride_y\n  %y_off = mul i64 %y_str, %img_width\n  %y_out_off = mul i64 %y, %w_out\n  br label %x_loop\n");
        out.push_str("x_loop:\n  %x = phi i64 [ 0, %x_init ], [ %next_x, %x_step ]\n  %has_x = icmp ult i64 %x, %w_out\n  br i1 %has_x, label %x_step, label %y_next\n");
        out.push_str("x_step:\n  %x_str = mul i64 %x, %stride_x\n  %in_idx = add i64 %y_off, %x_str\n  %out_idx = add i64 %y_out_off, %x\n  %p_in = getelementptr inbounds double, ptr %img, i64 %in_idx\n  %v_in = load double, ptr %p_in, align 8\n  %prod = fmul double %v_in, %w0\n  %accum = fadd double %prod, %bias_scalar\n  %relu_cond = fcmp ogt double %accum, 0.0\n  %relu_val = select i1 %relu_cond, double %accum, double 0.0\n  %act_val = select i1 %is_relu, double %relu_val, double %accum\n  %p_dst = getelementptr inbounds double, ptr %dst, i64 %out_idx\n  %old_dst = load double, ptr %p_dst, align 8\n  %new_dst = fadd double %old_dst, %act_val\n  store double %new_dst, ptr %p_dst, align 8\n  %next_x = add i64 %x, 1\n  br label %x_loop, !llvm.loop !74\n");
        out.push_str("y_next:\n  %next_y = add i64 %y, 1\n  br label %y_loop\n");
        out.push_str("done:\n  ret void\n}\n\n");

        out.push_str("define linkonce_odr void @ifa_simd_multi_arena_conv2d_i64(ptr %dst, ptr %img, ptr %weights, ptr %bias, i64 %h_out, i64 %w_out, i64 %stride_y, i64 %stride_x, i64 %img_width, i32 %activation) alwaysinline {\n");
        out.push_str("entry:\n  %has_bias = icmp ne ptr %bias, null\n  %w0 = load i64, ptr %weights, align 8\n  br i1 %has_bias, label %load_b, label %zero_b\n");
        out.push_str("load_b:\n  %b_val = load i64, ptr %bias, align 8\n  br label %y_init\n");
        out.push_str("zero_b:\n  br label %y_init\n");
        out.push_str("y_init:\n  %bias_scalar = phi i64 [ %b_val, %load_b ], [ 0, %zero_b ]\n  %is_relu = icmp eq i32 %activation, 1\n  br label %y_loop\n");
        out.push_str("y_loop:\n  %y = phi i64 [ 0, %y_init ], [ %next_y, %y_next ]\n  %has_y = icmp ult i64 %y, %h_out\n  br i1 %has_y, label %x_init, label %done\n");
        out.push_str("x_init:\n  %y_str = mul i64 %y, %stride_y\n  %y_off = mul i64 %y_str, %img_width\n  %y_out_off = mul i64 %y, %w_out\n  br label %x_loop\n");
        out.push_str("x_loop:\n  %x = phi i64 [ 0, %x_init ], [ %next_x, %x_step ]\n  %has_x = icmp ult i64 %x, %w_out\n  br i1 %has_x, label %x_step, label %y_next\n");
        out.push_str("x_step:\n  %x_str = mul i64 %x, %stride_x\n  %in_idx = add i64 %y_off, %x_str\n  %out_idx = add i64 %y_out_off, %x\n  %p_in = getelementptr inbounds i64, ptr %img, i64 %in_idx\n  %v_in = load i64, ptr %p_in, align 8\n  %prod = mul i64 %v_in, %w0\n  %accum = add i64 %prod, %bias_scalar\n  %relu_cond = icmp sgt i64 %accum, 0\n  %relu_val = select i1 %relu_cond, i64 %accum, i64 0\n  %act_val = select i1 %is_relu, i64 %relu_val, i64 %accum\n  %p_dst = getelementptr inbounds i64, ptr %dst, i64 %out_idx\n  %old_dst = load i64, ptr %p_dst, align 8\n  %new_dst = add i64 %old_dst, %act_val\n  store i64 %new_dst, ptr %p_dst, align 8\n  %next_x = add i64 %x, 1\n  br label %x_loop, !llvm.loop !74\n");
        out.push_str("y_next:\n  %next_y = add i64 %y, 1\n  br label %y_loop\n");
        out.push_str("done:\n  ret void\n}\n\n");

        out.push_str("define linkonce_odr void @ifa_simd_multi_arena_conv3d_f32(ptr %dst, ptr %volume, ptr %filter, ptr %bias, i64 %d_out, i64 %h_out, i64 %w_out, i64 %stride_z, i64 %stride_y, i64 %stride_x, i64 %plane_pitch, i64 %row_pitch, i32 %activation) alwaysinline {\n");
        out.push_str("entry:\n  %has_bias = icmp ne ptr %bias, null\n  %f0 = load float, ptr %filter, align 4\n  br i1 %has_bias, label %load_b, label %zero_b\n");
        out.push_str("load_b:\n  %b_val = load float, ptr %bias, align 4\n  br label %z_init\n");
        out.push_str("zero_b:\n  br label %z_init\n");
        out.push_str("z_init:\n  %bias_scalar = phi float [ %b_val, %load_b ], [ 0.0, %zero_b ]\n  %is_relu = icmp eq i32 %activation, 1\n  br label %z_loop\n");
        out.push_str("z_loop:\n  %z = phi i64 [ 0, %z_init ], [ %next_z, %z_next ]\n  %has_z = icmp ult i64 %z, %d_out\n  br i1 %has_z, label %y_init, label %done\n");
        out.push_str("y_init:\n  %z_str = mul i64 %z, %stride_z\n  %z_off = mul i64 %z_str, %plane_pitch\n  %z_out_plane = mul i64 %z, %h_out\n  br label %y_loop\n");
        out.push_str("y_loop:\n  %y = phi i64 [ 0, %y_init ], [ %next_y, %y_next ]\n  %has_y = icmp ult i64 %y, %h_out\n  br i1 %has_y, label %x_init, label %z_next\n");
        out.push_str("x_init:\n  %y_str = mul i64 %y, %stride_y\n  %y_off = mul i64 %y_str, %row_pitch\n  %zy_in_off = add i64 %z_off, %y_off\n  %zy_out_elem = add i64 %z_out_plane, %y\n  %zy_out_off = mul i64 %zy_out_elem, %w_out\n  br label %x_loop\n");
        out.push_str("x_loop:\n  %x = phi i64 [ 0, %x_init ], [ %next_x, %x_step ]\n  %has_x = icmp ult i64 %x, %w_out\n  br i1 %has_x, label %x_step, label %y_next\n");
        out.push_str("x_step:\n  %x_str = mul i64 %x, %stride_x\n  %in_idx = add i64 %zy_in_off, %x_str\n  %out_idx = add i64 %zy_out_off, %x\n  %p_in = getelementptr inbounds float, ptr %volume, i64 %in_idx\n  %v_in = load float, ptr %p_in, align 4\n  %prod = fmul float %v_in, %f0\n  %accum = fadd float %prod, %bias_scalar\n  %relu_cond = fcmp ogt float %accum, 0.0\n  %relu_val = select i1 %relu_cond, float %accum, float 0.0\n  %act_val = select i1 %is_relu, float %relu_val, float %accum\n  %p_dst = getelementptr inbounds float, ptr %dst, i64 %out_idx\n  %old_dst = load float, ptr %p_dst, align 4\n  %new_dst = fadd float %old_dst, %act_val\n  store float %new_dst, ptr %p_dst, align 4\n  %next_x = add i64 %x, 1\n  br label %x_loop, !llvm.loop !73\n");
        out.push_str("y_next:\n  %next_y = add i64 %y, 1\n  br label %y_loop\n");
        out.push_str("z_next:\n  %next_z = add i64 %z, 1\n  br label %z_loop\n");
        out.push_str("done:\n  ret void\n}\n\n");

        out.push_str("define linkonce_odr void @ifa_simd_multi_arena_conv3d_f64(ptr %dst, ptr %volume, ptr %filter, ptr %bias, i64 %d_out, i64 %h_out, i64 %w_out, i64 %stride_z, i64 %stride_y, i64 %stride_x, i64 %plane_pitch, i64 %row_pitch, i32 %activation) alwaysinline {\n");
        out.push_str("entry:\n  %has_bias = icmp ne ptr %bias, null\n  %f0 = load double, ptr %filter, align 8\n  br i1 %has_bias, label %load_b, label %zero_b\n");
        out.push_str("load_b:\n  %b_val = load double, ptr %bias, align 8\n  br label %z_init\n");
        out.push_str("zero_b:\n  br label %z_init\n");
        out.push_str("z_init:\n  %bias_scalar = phi double [ %b_val, %load_b ], [ 0.0, %zero_b ]\n  %is_relu = icmp eq i32 %activation, 1\n  br label %z_loop\n");
        out.push_str("z_loop:\n  %z = phi i64 [ 0, %z_init ], [ %next_z, %z_next ]\n  %has_z = icmp ult i64 %z, %d_out\n  br i1 %has_z, label %y_init, label %done\n");
        out.push_str("y_init:\n  %z_str = mul i64 %z, %stride_z\n  %z_off = mul i64 %z_str, %plane_pitch\n  %z_out_plane = mul i64 %z, %h_out\n  br label %y_loop\n");
        out.push_str("y_loop:\n  %y = phi i64 [ 0, %y_init ], [ %next_y, %y_next ]\n  %has_y = icmp ult i64 %y, %h_out\n  br i1 %has_y, label %x_init, label %z_next\n");
        out.push_str("x_init:\n  %y_str = mul i64 %y, %stride_y\n  %y_off = mul i64 %y_str, %row_pitch\n  %zy_in_off = add i64 %z_off, %y_off\n  %zy_out_elem = add i64 %z_out_plane, %y\n  %zy_out_off = mul i64 %zy_out_elem, %w_out\n  br label %x_loop\n");
        out.push_str("x_loop:\n  %x = phi i64 [ 0, %x_init ], [ %next_x, %x_step ]\n  %has_x = icmp ult i64 %x, %w_out\n  br i1 %has_x, label %x_step, label %y_next\n");
        out.push_str("x_step:\n  %x_str = mul i64 %x, %stride_x\n  %in_idx = add i64 %zy_in_off, %x_str\n  %out_idx = add i64 %zy_out_off, %x\n  %p_in = getelementptr inbounds double, ptr %volume, i64 %in_idx\n  %v_in = load double, ptr %p_in, align 8\n  %prod = fmul double %v_in, %f0\n  %accum = fadd double %prod, %bias_scalar\n  %relu_cond = fcmp ogt double %accum, 0.0\n  %relu_val = select i1 %relu_cond, double %accum, double 0.0\n  %act_val = select i1 %is_relu, double %relu_val, double %accum\n  %p_dst = getelementptr inbounds double, ptr %dst, i64 %out_idx\n  %old_dst = load double, ptr %p_dst, align 8\n  %new_dst = fadd double %old_dst, %act_val\n  store double %new_dst, ptr %p_dst, align 8\n  %next_x = add i64 %x, 1\n  br label %x_loop, !llvm.loop !73\n");
        out.push_str("y_next:\n  %next_y = add i64 %y, 1\n  br label %y_loop\n");
        out.push_str("z_next:\n  %next_z = add i64 %z, 1\n  br label %z_loop\n");
        out.push_str("done:\n  ret void\n}\n\n");

        out.push_str("define linkonce_odr void @ifa_simd_multi_arena_conv3d_i64(ptr %dst, ptr %volume, ptr %filter, ptr %bias, i64 %d_out, i64 %h_out, i64 %w_out, i64 %stride_z, i64 %stride_y, i64 %stride_x, i64 %plane_pitch, i64 %row_pitch, i32 %activation) alwaysinline {\n");
        out.push_str("entry:\n  %has_bias = icmp ne ptr %bias, null\n  %f0 = load i64, ptr %filter, align 8\n  br i1 %has_bias, label %load_b, label %zero_b\n");
        out.push_str("load_b:\n  %b_val = load i64, ptr %bias, align 8\n  br label %z_init\n");
        out.push_str("zero_b:\n  br label %z_init\n");
        out.push_str("z_init:\n  %bias_scalar = phi i64 [ %b_val, %load_b ], [ 0, %zero_b ]\n  %is_relu = icmp eq i32 %activation, 1\n  br label %z_loop\n");
        out.push_str("z_loop:\n  %z = phi i64 [ 0, %z_init ], [ %next_z, %z_next ]\n  %has_z = icmp ult i64 %z, %d_out\n  br i1 %has_z, label %y_init, label %done\n");
        out.push_str("y_init:\n  %z_str = mul i64 %z, %stride_z\n  %z_off = mul i64 %z_str, %plane_pitch\n  %z_out_plane = mul i64 %z, %h_out\n  br label %y_loop\n");
        out.push_str("y_loop:\n  %y = phi i64 [ 0, %y_init ], [ %next_y, %y_next ]\n  %has_y = icmp ult i64 %y, %h_out\n  br i1 %has_y, label %x_init, label %z_next\n");
        out.push_str("x_init:\n  %y_str = mul i64 %y, %stride_y\n  %y_off = mul i64 %y_str, %row_pitch\n  %zy_in_off = add i64 %z_off, %y_off\n  %zy_out_elem = add i64 %z_out_plane, %y\n  %zy_out_off = mul i64 %zy_out_elem, %w_out\n  br label %x_loop\n");
        out.push_str("x_loop:\n  %x = phi i64 [ 0, %x_init ], [ %next_x, %x_step ]\n  %has_x = icmp ult i64 %x, %w_out\n  br i1 %has_x, label %x_step, label %y_next\n");
        out.push_str("x_step:\n  %x_str = mul i64 %x, %stride_x\n  %in_idx = add i64 %zy_in_off, %x_str\n  %out_idx = add i64 %zy_out_off, %x\n  %p_in = getelementptr inbounds i64, ptr %volume, i64 %in_idx\n  %v_in = load i64, ptr %p_in, align 8\n  %prod = mul i64 %v_in, %f0\n  %accum = add i64 %prod, %bias_scalar\n  %relu_cond = icmp sgt i64 %accum, 0\n  %relu_val = select i1 %relu_cond, i64 %accum, i64 0\n  %act_val = select i1 %is_relu, i64 %relu_val, i64 %accum\n  %p_dst = getelementptr inbounds i64, ptr %dst, i64 %out_idx\n  %old_dst = load i64, ptr %p_dst, align 8\n  %new_dst = add i64 %old_dst, %act_val\n  store i64 %new_dst, ptr %p_dst, align 8\n  %next_x = add i64 %x, 1\n  br label %x_loop, !llvm.loop !73\n");
        out.push_str("y_next:\n  %next_y = add i64 %y, 1\n  br label %y_loop\n");
        out.push_str("z_next:\n  %next_z = add i64 %z, 1\n  br label %z_loop\n");
        out.push_str("done:\n  ret void\n}\n\n");

        // Dilated 2D Convolutions with Fused Bias and ReLU
        out.push_str("define linkonce_odr void @ifa_simd_multi_arena_dilated_conv2d_f32(ptr %dst, ptr %img, ptr %weights, ptr %bias, i64 %h_out, i64 %w_out, i64 %stride_y, i64 %stride_x, i64 %dilation_y, i64 %dilation_x, i64 %kernel_h, i64 %kernel_w, i64 %img_width, i32 %activation) alwaysinline {\n");
        out.push_str("entry:\n  %has_bias = icmp ne ptr %bias, null\n  br i1 %has_bias, label %load_b, label %zero_b\n");
        out.push_str("load_b:\n  %b_val = load float, ptr %bias, align 4\n  br label %y_init\n");
        out.push_str("zero_b:\n  br label %y_init\n");
        out.push_str("y_init:\n  %bias_scalar = phi float [ %b_val, %load_b ], [ 0.0, %zero_b ]\n  %is_relu = icmp eq i32 %activation, 1\n  br label %y_loop\n");
        out.push_str("y_loop:\n  %y = phi i64 [ 0, %y_init ], [ %next_y, %y_next ]\n  %has_y = icmp ult i64 %y, %h_out\n  br i1 %has_y, label %x_init, label %done\n");
        out.push_str("x_init:\n  %y_str = mul i64 %y, %stride_y\n  %y_base = mul i64 %y_str, %img_width\n  %y_out_off = mul i64 %y, %w_out\n  br label %x_loop\n");
        out.push_str("x_loop:\n  %x = phi i64 [ 0, %x_init ], [ %next_x, %x_next ]\n  %has_x = icmp ult i64 %x, %w_out\n  br i1 %has_x, label %k_init, label %y_next\n");
        out.push_str("k_init:\n  %x_base = mul i64 %x, %stride_x\n  %out_idx = add i64 %y_out_off, %x\n  br label %ky_loop\n");
        out.push_str("ky_loop:\n  %ky = phi i64 [ 0, %k_init ], [ %next_ky, %ky_next ]\n  %accum_ky = phi float [ 0.0, %k_init ], [ %accum_ky_next, %ky_next ]\n  %has_ky = icmp ult i64 %ky, %kernel_h\n  br i1 %has_ky, label %kx_init, label %k_done\n");
        out.push_str("kx_init:\n  %ky_dil = mul i64 %ky, %dilation_y\n  %ky_off = mul i64 %ky_dil, %img_width\n  %in_row = add i64 %y_base, %ky_off\n  %w_row = mul i64 %ky, %kernel_w\n  br label %kx_loop\n");
        out.push_str("kx_loop:\n  %kx = phi i64 [ 0, %kx_init ], [ %next_kx, %kx_step ]\n  %accum_kx = phi float [ %accum_ky, %kx_init ], [ %next_accum_kx, %kx_step ]\n  %has_kx = icmp ult i64 %kx, %kernel_w\n  br i1 %has_kx, label %kx_step, label %ky_next\n");
        out.push_str("kx_step:\n  %kx_dil = mul i64 %kx, %dilation_x\n  %in_idx = add i64 %in_row, %x_base\n  %in_full_idx = add i64 %in_idx, %kx_dil\n  %w_idx = add i64 %w_row, %kx\n  %p_in = getelementptr inbounds float, ptr %img, i64 %in_full_idx\n  %p_w = getelementptr inbounds float, ptr %weights, i64 %w_idx\n  %v_in = load float, ptr %p_in, align 4\n  %v_w = load float, ptr %p_w, align 4\n  %prod = fmul float %v_in, %v_w\n  %next_accum_kx = fadd float %accum_kx, %prod\n  %next_kx = add i64 %kx, 1\n  br label %kx_loop, !llvm.loop !74\n");
        out.push_str("ky_next:\n  %accum_ky_next = phi float [ %accum_kx, %kx_loop ]\n  %next_ky = add i64 %ky, 1\n  br label %ky_loop\n");
        out.push_str("k_done:\n  %biased = fadd float %accum_ky, %bias_scalar\n  %relu_cond = fcmp ogt float %biased, 0.0\n  %relu_val = select i1 %relu_cond, float %biased, float 0.0\n  %act_val = select i1 %is_relu, float %relu_val, float %biased\n  %p_dst = getelementptr inbounds float, ptr %dst, i64 %out_idx\n  %old_dst = load float, ptr %p_dst, align 4\n  %new_dst = fadd float %old_dst, %act_val\n  store float %new_dst, ptr %p_dst, align 4\n  br label %x_next\n");
        out.push_str("x_next:\n  %next_x = add i64 %x, 1\n  br label %x_loop\n");
        out.push_str("y_next:\n  %next_y = add i64 %y, 1\n  br label %y_loop\n");
        out.push_str("done:\n  ret void\n}\n\n");

        out.push_str("define linkonce_odr void @ifa_simd_multi_arena_dilated_conv2d_f64(ptr %dst, ptr %img, ptr %weights, ptr %bias, i64 %h_out, i64 %w_out, i64 %stride_y, i64 %stride_x, i64 %dilation_y, i64 %dilation_x, i64 %kernel_h, i64 %kernel_w, i64 %img_width, i32 %activation) alwaysinline {\n");
        out.push_str("entry:\n  %has_bias = icmp ne ptr %bias, null\n  br i1 %has_bias, label %load_b, label %zero_b\n");
        out.push_str("load_b:\n  %b_val = load double, ptr %bias, align 8\n  br label %y_init\n");
        out.push_str("zero_b:\n  br label %y_init\n");
        out.push_str("y_init:\n  %bias_scalar = phi double [ %b_val, %load_b ], [ 0.0, %zero_b ]\n  %is_relu = icmp eq i32 %activation, 1\n  br label %y_loop\n");
        out.push_str("y_loop:\n  %y = phi i64 [ 0, %y_init ], [ %next_y, %y_next ]\n  %has_y = icmp ult i64 %y, %h_out\n  br i1 %has_y, label %x_init, label %done\n");
        out.push_str("x_init:\n  %y_str = mul i64 %y, %stride_y\n  %y_base = mul i64 %y_str, %img_width\n  %y_out_off = mul i64 %y, %w_out\n  br label %x_loop\n");
        out.push_str("x_loop:\n  %x = phi i64 [ 0, %x_init ], [ %next_x, %x_next ]\n  %has_x = icmp ult i64 %x, %w_out\n  br i1 %has_x, label %k_init, label %y_next\n");
        out.push_str("k_init:\n  %x_base = mul i64 %x, %stride_x\n  %out_idx = add i64 %y_out_off, %x\n  br label %ky_loop\n");
        out.push_str("ky_loop:\n  %ky = phi i64 [ 0, %k_init ], [ %next_ky, %ky_next ]\n  %accum_ky = phi double [ 0.0, %k_init ], [ %accum_ky_next, %ky_next ]\n  %has_ky = icmp ult i64 %ky, %kernel_h\n  br i1 %has_ky, label %kx_init, label %k_done\n");
        out.push_str("kx_init:\n  %ky_dil = mul i64 %ky, %dilation_y\n  %ky_off = mul i64 %ky_dil, %img_width\n  %in_row = add i64 %y_base, %ky_off\n  %w_row = mul i64 %ky, %kernel_w\n  br label %kx_loop\n");
        out.push_str("kx_loop:\n  %kx = phi i64 [ 0, %kx_init ], [ %next_kx, %kx_step ]\n  %accum_kx = phi double [ %accum_ky, %kx_init ], [ %next_accum_kx, %kx_step ]\n  %has_kx = icmp ult i64 %kx, %kernel_w\n  br i1 %has_kx, label %kx_step, label %ky_next\n");
        out.push_str("kx_step:\n  %kx_dil = mul i64 %kx, %dilation_x\n  %in_idx = add i64 %in_row, %x_base\n  %in_full_idx = add i64 %in_idx, %kx_dil\n  %w_idx = add i64 %w_row, %kx\n  %p_in = getelementptr inbounds double, ptr %img, i64 %in_full_idx\n  %p_w = getelementptr inbounds double, ptr %weights, i64 %w_idx\n  %v_in = load double, ptr %p_in, align 8\n  %v_w = load double, ptr %p_w, align 8\n  %prod = fmul double %v_in, %v_w\n  %next_accum_kx = fadd double %accum_kx, %prod\n  %next_kx = add i64 %kx, 1\n  br label %kx_loop, !llvm.loop !74\n");
        out.push_str("ky_next:\n  %accum_ky_next = phi double [ %accum_kx, %kx_loop ]\n  %next_ky = add i64 %ky, 1\n  br label %ky_loop\n");
        out.push_str("k_done:\n  %biased = fadd double %accum_ky, %bias_scalar\n  %relu_cond = fcmp ogt double %biased, 0.0\n  %relu_val = select i1 %relu_cond, double %biased, double 0.0\n  %act_val = select i1 %is_relu, double %relu_val, double %biased\n  %p_dst = getelementptr inbounds double, ptr %dst, i64 %out_idx\n  %old_dst = load double, ptr %p_dst, align 8\n  %new_dst = fadd double %old_dst, %act_val\n  store double %new_dst, ptr %p_dst, align 8\n  br label %x_next\n");
        out.push_str("x_next:\n  %next_x = add i64 %x, 1\n  br label %x_loop\n");
        out.push_str("y_next:\n  %next_y = add i64 %y, 1\n  br label %y_loop\n");
        out.push_str("done:\n  ret void\n}\n\n");

        out.push_str("define linkonce_odr void @ifa_simd_multi_arena_dilated_conv2d_i64(ptr %dst, ptr %img, ptr %weights, ptr %bias, i64 %h_out, i64 %w_out, i64 %stride_y, i64 %stride_x, i64 %dilation_y, i64 %dilation_x, i64 %kernel_h, i64 %kernel_w, i64 %img_width, i32 %activation) alwaysinline {\n");
        out.push_str("entry:\n  %has_bias = icmp ne ptr %bias, null\n  br i1 %has_bias, label %load_b, label %zero_b\n");
        out.push_str("load_b:\n  %b_val = load i64, ptr %bias, align 8\n  br label %y_init\n");
        out.push_str("zero_b:\n  br label %y_init\n");
        out.push_str("y_init:\n  %bias_scalar = phi i64 [ %b_val, %load_b ], [ 0, %zero_b ]\n  %is_relu = icmp eq i32 %activation, 1\n  br label %y_loop\n");
        out.push_str("y_loop:\n  %y = phi i64 [ 0, %y_init ], [ %next_y, %y_next ]\n  %has_y = icmp ult i64 %y, %h_out\n  br i1 %has_y, label %x_init, label %done\n");
        out.push_str("x_init:\n  %y_str = mul i64 %y, %stride_y\n  %y_base = mul i64 %y_str, %img_width\n  %y_out_off = mul i64 %y, %w_out\n  br label %x_loop\n");
        out.push_str("x_loop:\n  %x = phi i64 [ 0, %x_init ], [ %next_x, %x_next ]\n  %has_x = icmp ult i64 %x, %w_out\n  br i1 %has_x, label %k_init, label %y_next\n");
        out.push_str("k_init:\n  %x_base = mul i64 %x, %stride_x\n  %out_idx = add i64 %y_out_off, %x\n  br label %ky_loop\n");
        out.push_str("ky_loop:\n  %ky = phi i64 [ 0, %k_init ], [ %next_ky, %ky_next ]\n  %accum_ky = phi i64 [ 0, %k_init ], [ %accum_ky_next, %ky_next ]\n  %has_ky = icmp ult i64 %ky, %kernel_h\n  br i1 %has_ky, label %kx_init, label %k_done\n");
        out.push_str("kx_init:\n  %ky_dil = mul i64 %ky, %dilation_y\n  %ky_off = mul i64 %ky_dil, %img_width\n  %in_row = add i64 %y_base, %ky_off\n  %w_row = mul i64 %ky, %kernel_w\n  br label %kx_loop\n");
        out.push_str("kx_loop:\n  %kx = phi i64 [ 0, %kx_init ], [ %next_kx, %kx_step ]\n  %accum_kx = phi i64 [ %accum_ky, %kx_init ], [ %next_accum_kx, %kx_step ]\n  %has_kx = icmp ult i64 %kx, %kernel_w\n  br i1 %has_kx, label %kx_step, label %ky_next\n");
        out.push_str("kx_step:\n  %kx_dil = mul i64 %kx, %dilation_x\n  %in_idx = add i64 %in_row, %x_base\n  %in_full_idx = add i64 %in_idx, %kx_dil\n  %w_idx = add i64 %w_row, %kx\n  %p_in = getelementptr inbounds i64, ptr %img, i64 %in_full_idx\n  %p_w = getelementptr inbounds i64, ptr %weights, i64 %w_idx\n  %v_in = load i64, ptr %p_in, align 8\n  %v_w = load i64, ptr %p_w, align 8\n  %prod = mul i64 %v_in, %v_w\n  %next_accum_kx = add i64 %accum_kx, %prod\n  %next_kx = add i64 %kx, 1\n  br label %kx_loop, !llvm.loop !74\n");
        out.push_str("ky_next:\n  %accum_ky_next = phi i64 [ %accum_kx, %kx_loop ]\n  %next_ky = add i64 %ky, 1\n  br label %ky_loop\n");
        out.push_str("k_done:\n  %biased = add i64 %accum_ky, %bias_scalar\n  %relu_cond = icmp sgt i64 %biased, 0\n  %relu_val = select i1 %relu_cond, i64 %biased, i64 0\n  %act_val = select i1 %is_relu, i64 %relu_val, i64 %biased\n  %p_dst = getelementptr inbounds i64, ptr %dst, i64 %out_idx\n  %old_dst = load i64, ptr %p_dst, align 8\n  %new_dst = add i64 %old_dst, %act_val\n  store i64 %new_dst, ptr %p_dst, align 8\n  br label %x_next\n");
        out.push_str("x_next:\n  %next_x = add i64 %x, 1\n  br label %x_loop\n");
        out.push_str("y_next:\n  %next_y = add i64 %y, 1\n  br label %y_loop\n");
        out.push_str("done:\n  ret void\n}\n\n");

        // Spatial Max-Pooling 2D Kernels
        out.push_str("define linkonce_odr void @ifa_simd_multi_arena_maxpool2d_f32(ptr %dst, ptr %img, i64 %h_out, i64 %w_out, i64 %stride_y, i64 %stride_x, i64 %pool_h, i64 %pool_w, i64 %img_width) alwaysinline {\n");
        out.push_str("entry:\n  br label %y_loop\n");
        out.push_str("y_loop:\n  %y = phi i64 [ 0, %entry ], [ %next_y, %y_next ]\n  %has_y = icmp ult i64 %y, %h_out\n  br i1 %has_y, label %x_init, label %done\n");
        out.push_str("x_init:\n  %y_str = mul i64 %y, %stride_y\n  %y_base = mul i64 %y_str, %img_width\n  %y_out_off = mul i64 %y, %w_out\n  br label %x_loop\n");
        out.push_str("x_loop:\n  %x = phi i64 [ 0, %x_init ], [ %next_x, %x_next ]\n  %has_x = icmp ult i64 %x, %w_out\n  br i1 %has_x, label %p_init, label %y_next\n");
        out.push_str("p_init:\n  %x_base = mul i64 %x, %stride_x\n  %out_idx = add i64 %y_out_off, %x\n  br label %py_loop\n");
        out.push_str("py_loop:\n  %py = phi i64 [ 0, %p_init ], [ %next_py, %py_next ]\n  %max_py = phi float [ 0xFFF0000000000000, %p_init ], [ %max_py_next, %py_next ]\n  %has_py = icmp ult i64 %py, %pool_h\n  br i1 %has_py, label %px_init, label %p_done\n");
        out.push_str("px_init:\n  %py_off = mul i64 %py, %img_width\n  %in_row = add i64 %y_base, %py_off\n  br label %px_loop\n");
        out.push_str("px_loop:\n  %px = phi i64 [ 0, %px_init ], [ %next_px, %px_step ]\n  %max_px = phi float [ %max_py, %px_init ], [ %next_max_px, %px_step ]\n  %has_px = icmp ult i64 %px, %pool_w\n  br i1 %has_px, label %px_step, label %py_next\n");
        out.push_str("px_step:\n  %in_idx = add i64 %in_row, %x_base\n  %in_full_idx = add i64 %in_idx, %px\n  %p_in = getelementptr inbounds float, ptr %img, i64 %in_full_idx\n  %v_in = load float, ptr %p_in, align 4\n  %gt_cond = fcmp ogt float %v_in, %max_px\n  %next_max_px = select i1 %gt_cond, float %v_in, float %max_px\n  %next_px = add i64 %px, 1\n  br label %px_loop, !llvm.loop !74\n");
        out.push_str("py_next:\n  %max_py_next = phi float [ %max_px, %px_loop ]\n  %next_py = add i64 %py, 1\n  br label %py_loop\n");
        out.push_str("p_done:\n  %p_dst = getelementptr inbounds float, ptr %dst, i64 %out_idx\n  store float %max_py, ptr %p_dst, align 4\n  br label %x_next\n");
        out.push_str("x_next:\n  %next_x = add i64 %x, 1\n  br label %x_loop\n");
        out.push_str("y_next:\n  %next_y = add i64 %y, 1\n  br label %y_loop\n");
        out.push_str("done:\n  ret void\n}\n\n");

        out.push_str("define linkonce_odr void @ifa_simd_multi_arena_maxpool2d_f64(ptr %dst, ptr %img, i64 %h_out, i64 %w_out, i64 %stride_y, i64 %stride_x, i64 %pool_h, i64 %pool_w, i64 %img_width) alwaysinline {\n");
        out.push_str("entry:\n  br label %y_loop\n");
        out.push_str("y_loop:\n  %y = phi i64 [ 0, %entry ], [ %next_y, %y_next ]\n  %has_y = icmp ult i64 %y, %h_out\n  br i1 %has_y, label %x_init, label %done\n");
        out.push_str("x_init:\n  %y_str = mul i64 %y, %stride_y\n  %y_base = mul i64 %y_str, %img_width\n  %y_out_off = mul i64 %y, %w_out\n  br label %x_loop\n");
        out.push_str("x_loop:\n  %x = phi i64 [ 0, %x_init ], [ %next_x, %x_next ]\n  %has_x = icmp ult i64 %x, %w_out\n  br i1 %has_x, label %p_init, label %y_next\n");
        out.push_str("p_init:\n  %x_base = mul i64 %x, %stride_x\n  %out_idx = add i64 %y_out_off, %x\n  br label %py_loop\n");
        out.push_str("py_loop:\n  %py = phi i64 [ 0, %p_init ], [ %next_py, %py_next ]\n  %max_py = phi double [ 0xFFF0000000000000, %p_init ], [ %max_py_next, %py_next ]\n  %has_py = icmp ult i64 %py, %pool_h\n  br i1 %has_py, label %px_init, label %p_done\n");
        out.push_str("px_init:\n  %py_off = mul i64 %py, %img_width\n  %in_row = add i64 %y_base, %py_off\n  br label %px_loop\n");
        out.push_str("px_loop:\n  %px = phi i64 [ 0, %px_init ], [ %next_px, %px_step ]\n  %max_px = phi double [ %max_py, %px_init ], [ %next_max_px, %px_step ]\n  %has_px = icmp ult i64 %px, %pool_w\n  br i1 %has_px, label %px_step, label %py_next\n");
        out.push_str("px_step:\n  %in_idx = add i64 %in_row, %x_base\n  %in_full_idx = add i64 %in_idx, %px\n  %p_in = getelementptr inbounds double, ptr %img, i64 %in_full_idx\n  %v_in = load double, ptr %p_in, align 8\n  %gt_cond = fcmp ogt double %v_in, %max_px\n  %next_max_px = select i1 %gt_cond, double %v_in, double %max_px\n  %next_px = add i64 %px, 1\n  br label %px_loop, !llvm.loop !74\n");
        out.push_str("py_next:\n  %max_py_next = phi double [ %max_px, %px_loop ]\n  %next_py = add i64 %py, 1\n  br label %py_loop\n");
        out.push_str("p_done:\n  %p_dst = getelementptr inbounds double, ptr %dst, i64 %out_idx\n  store double %max_py, ptr %p_dst, align 8\n  br label %x_next\n");
        out.push_str("x_next:\n  %next_x = add i64 %x, 1\n  br label %x_loop\n");
        out.push_str("y_next:\n  %next_y = add i64 %y, 1\n  br label %y_loop\n");
        out.push_str("done:\n  ret void\n}\n\n");

        out.push_str("define linkonce_odr void @ifa_simd_multi_arena_maxpool2d_i64(ptr %dst, ptr %img, i64 %h_out, i64 %w_out, i64 %stride_y, i64 %stride_x, i64 %pool_h, i64 %pool_w, i64 %img_width) alwaysinline {\n");
        out.push_str("entry:\n  br label %y_loop\n");
        out.push_str("y_loop:\n  %y = phi i64 [ 0, %entry ], [ %next_y, %y_next ]\n  %has_y = icmp ult i64 %y, %h_out\n  br i1 %has_y, label %x_init, label %done\n");
        out.push_str("x_init:\n  %y_str = mul i64 %y, %stride_y\n  %y_base = mul i64 %y_str, %img_width\n  %y_out_off = mul i64 %y, %w_out\n  br label %x_loop\n");
        out.push_str("x_loop:\n  %x = phi i64 [ 0, %x_init ], [ %next_x, %x_next ]\n  %has_x = icmp ult i64 %x, %w_out\n  br i1 %has_x, label %p_init, label %y_next\n");
        out.push_str("p_init:\n  %x_base = mul i64 %x, %stride_x\n  %out_idx = add i64 %y_out_off, %x\n  br label %py_loop\n");
        out.push_str("py_loop:\n  %py = phi i64 [ 0, %p_init ], [ %next_py, %py_next ]\n  %max_py = phi i64 [ -9223372036854775808, %p_init ], [ %max_py_next, %py_next ]\n  %has_py = icmp ult i64 %py, %pool_h\n  br i1 %has_py, label %px_init, label %p_done\n");
        out.push_str("px_init:\n  %py_off = mul i64 %py, %img_width\n  %in_row = add i64 %y_base, %py_off\n  br label %px_loop\n");
        out.push_str("px_loop:\n  %px = phi i64 [ 0, %px_init ], [ %next_px, %px_step ]\n  %max_px = phi i64 [ %max_py, %px_init ], [ %next_max_px, %px_step ]\n  %has_px = icmp ult i64 %px, %pool_w\n  br i1 %has_px, label %px_step, label %py_next\n");
        out.push_str("px_step:\n  %in_idx = add i64 %in_row, %x_base\n  %in_full_idx = add i64 %in_idx, %px\n  %p_in = getelementptr inbounds i64, ptr %img, i64 %in_full_idx\n  %v_in = load i64, ptr %p_in, align 8\n  %gt_cond = icmp sgt i64 %v_in, %max_px\n  %next_max_px = select i1 %gt_cond, i64 %v_in, i64 %max_px\n  %next_px = add i64 %px, 1\n  br label %px_loop, !llvm.loop !74\n");
        out.push_str("py_next:\n  %max_py_next = phi i64 [ %max_px, %px_loop ]\n  %next_py = add i64 %py, 1\n  br label %py_loop\n");
        out.push_str("p_done:\n  %p_dst = getelementptr inbounds i64, ptr %dst, i64 %out_idx\n  store i64 %max_py, ptr %p_dst, align 8\n  br label %x_next\n");
        out.push_str("x_next:\n  %next_x = add i64 %x, 1\n  br label %x_loop\n");
        out.push_str("y_next:\n  %next_y = add i64 %y, 1\n  br label %y_loop\n");
        out.push_str("done:\n  ret void\n}\n\n");

        // Spatial Average-Pooling 2D Kernels
        out.push_str("define linkonce_odr void @ifa_simd_multi_arena_avgpool2d_f32(ptr %dst, ptr %img, i64 %h_out, i64 %w_out, i64 %stride_y, i64 %stride_x, i64 %pool_h, i64 %pool_w, i64 %img_width) alwaysinline {\n");
        out.push_str("entry:\n  %area_i64 = mul i64 %pool_h, %pool_w\n  %area_f = sitofp i64 %area_i64 to float\n  %inv_area = fdiv float 1.0, %area_f\n  br label %y_loop\n");
        out.push_str("y_loop:\n  %y = phi i64 [ 0, %entry ], [ %next_y, %y_next ]\n  %has_y = icmp ult i64 %y, %h_out\n  br i1 %has_y, label %x_init, label %done\n");
        out.push_str("x_init:\n  %y_str = mul i64 %y, %stride_y\n  %y_base = mul i64 %y_str, %img_width\n  %y_out_off = mul i64 %y, %w_out\n  br label %x_loop\n");
        out.push_str("x_loop:\n  %x = phi i64 [ 0, %x_init ], [ %next_x, %x_next ]\n  %has_x = icmp ult i64 %x, %w_out\n  br i1 %has_x, label %p_init, label %y_next\n");
        out.push_str("p_init:\n  %x_base = mul i64 %x, %stride_x\n  %out_idx = add i64 %y_out_off, %x\n  br label %py_loop\n");
        out.push_str("py_loop:\n  %py = phi i64 [ 0, %p_init ], [ %next_py, %py_next ]\n  %sum_py = phi float [ 0.0, %p_init ], [ %sum_py_next, %py_next ]\n  %has_py = icmp ult i64 %py, %pool_h\n  br i1 %has_py, label %px_init, label %p_done\n");
        out.push_str("px_init:\n  %py_off = mul i64 %py, %img_width\n  %in_row = add i64 %y_base, %py_off\n  br label %px_loop\n");
        out.push_str("px_loop:\n  %px = phi i64 [ 0, %px_init ], [ %next_px, %px_step ]\n  %sum_px = phi float [ %sum_py, %px_init ], [ %next_sum_px, %px_step ]\n  %has_px = icmp ult i64 %px, %pool_w\n  br i1 %has_px, label %px_step, label %py_next\n");
        out.push_str("px_step:\n  %in_idx = add i64 %in_row, %x_base\n  %in_full_idx = add i64 %in_idx, %px\n  %p_in = getelementptr inbounds float, ptr %img, i64 %in_full_idx\n  %v_in = load float, ptr %p_in, align 4\n  %next_sum_px = fadd float %sum_px, %v_in\n  %next_px = add i64 %px, 1\n  br label %px_loop, !llvm.loop !74\n");
        out.push_str("py_next:\n  %sum_py_next = phi float [ %sum_px, %px_loop ]\n  %next_py = add i64 %py, 1\n  br label %py_loop\n");
        out.push_str("p_done:\n  %avg_val = fmul float %sum_py, %inv_area\n  %p_dst = getelementptr inbounds float, ptr %dst, i64 %out_idx\n  store float %avg_val, ptr %p_dst, align 4\n  br label %x_next\n");
        out.push_str("x_next:\n  %next_x = add i64 %x, 1\n  br label %x_loop\n");
        out.push_str("y_next:\n  %next_y = add i64 %y, 1\n  br label %y_loop\n");
        out.push_str("done:\n  ret void\n}\n\n");

        out.push_str("define linkonce_odr void @ifa_simd_multi_arena_avgpool2d_f64(ptr %dst, ptr %img, i64 %h_out, i64 %w_out, i64 %stride_y, i64 %stride_x, i64 %pool_h, i64 %pool_w, i64 %img_width) alwaysinline {\n");
        out.push_str("entry:\n  %area_i64 = mul i64 %pool_h, %pool_w\n  %area_f = sitofp i64 %area_i64 to double\n  %inv_area = fdiv double 1.0, %area_f\n  br label %y_loop\n");
        out.push_str("y_loop:\n  %y = phi i64 [ 0, %entry ], [ %next_y, %y_next ]\n  %has_y = icmp ult i64 %y, %h_out\n  br i1 %has_y, label %x_init, label %done\n");
        out.push_str("x_init:\n  %y_str = mul i64 %y, %stride_y\n  %y_base = mul i64 %y_str, %img_width\n  %y_out_off = mul i64 %y, %w_out\n  br label %x_loop\n");
        out.push_str("x_loop:\n  %x = phi i64 [ 0, %x_init ], [ %next_x, %x_next ]\n  %has_x = icmp ult i64 %x, %w_out\n  br i1 %has_x, label %p_init, label %y_next\n");
        out.push_str("p_init:\n  %x_base = mul i64 %x, %stride_x\n  %out_idx = add i64 %y_out_off, %x\n  br label %py_loop\n");
        out.push_str("py_loop:\n  %py = phi i64 [ 0, %p_init ], [ %next_py, %py_next ]\n  %sum_py = phi double [ 0.0, %p_init ], [ %sum_py_next, %py_next ]\n  %has_py = icmp ult i64 %py, %pool_h\n  br i1 %has_py, label %px_init, label %p_done\n");
        out.push_str("px_init:\n  %py_off = mul i64 %py, %img_width\n  %in_row = add i64 %y_base, %py_off\n  br label %px_loop\n");
        out.push_str("px_loop:\n  %px = phi i64 [ 0, %px_init ], [ %next_px, %px_step ]\n  %sum_px = phi double [ %sum_py, %px_init ], [ %next_sum_px, %px_step ]\n  %has_px = icmp ult i64 %px, %pool_w\n  br i1 %has_px, label %px_step, label %py_next\n");
        out.push_str("px_step:\n  %in_idx = add i64 %in_row, %x_base\n  %in_full_idx = add i64 %in_idx, %px\n  %p_in = getelementptr inbounds double, ptr %img, i64 %in_full_idx\n  %v_in = load double, ptr %p_in, align 8\n  %next_sum_px = fadd double %sum_px, %v_in\n  %next_px = add i64 %px, 1\n  br label %px_loop, !llvm.loop !74\n");
        out.push_str("py_next:\n  %sum_py_next = phi double [ %sum_px, %px_loop ]\n  %next_py = add i64 %py, 1\n  br label %py_loop\n");
        out.push_str("p_done:\n  %avg_val = fmul double %sum_py, %inv_area\n  %p_dst = getelementptr inbounds double, ptr %dst, i64 %out_idx\n  store double %avg_val, ptr %p_dst, align 8\n  br label %x_next\n");
        out.push_str("x_next:\n  %next_x = add i64 %x, 1\n  br label %x_loop\n");
        out.push_str("y_next:\n  %next_y = add i64 %y, 1\n  br label %y_loop\n");
        out.push_str("done:\n  ret void\n}\n\n");

        out.push_str("define linkonce_odr void @ifa_simd_multi_arena_avgpool2d_i64(ptr %dst, ptr %img, i64 %h_out, i64 %w_out, i64 %stride_y, i64 %stride_x, i64 %pool_h, i64 %pool_w, i64 %img_width) alwaysinline {\n");
        out.push_str("entry:\n  %area = mul i64 %pool_h, %pool_w\n  br label %y_loop\n");
        out.push_str("y_loop:\n  %y = phi i64 [ 0, %entry ], [ %next_y, %y_next ]\n  %has_y = icmp ult i64 %y, %h_out\n  br i1 %has_y, label %x_init, label %done\n");
        out.push_str("x_init:\n  %y_str = mul i64 %y, %stride_y\n  %y_base = mul i64 %y_str, %img_width\n  %y_out_off = mul i64 %y, %w_out\n  br label %x_loop\n");
        out.push_str("x_loop:\n  %x = phi i64 [ 0, %x_init ], [ %next_x, %x_next ]\n  %has_x = icmp ult i64 %x, %w_out\n  br i1 %has_x, label %p_init, label %y_next\n");
        out.push_str("p_init:\n  %x_base = mul i64 %x, %stride_x\n  %out_idx = add i64 %y_out_off, %x\n  br label %py_loop\n");
        out.push_str("py_loop:\n  %py = phi i64 [ 0, %p_init ], [ %next_py, %py_next ]\n  %sum_py = phi i64 [ 0, %p_init ], [ %sum_py_next, %py_next ]\n  %has_py = icmp ult i64 %py, %pool_h\n  br i1 %has_py, label %px_init, label %p_done\n");
        out.push_str("px_init:\n  %py_off = mul i64 %py, %img_width\n  %in_row = add i64 %y_base, %py_off\n  br label %px_loop\n");
        out.push_str("px_loop:\n  %px = phi i64 [ 0, %px_init ], [ %next_px, %px_step ]\n  %sum_px = phi i64 [ %sum_py, %px_init ], [ %next_sum_px, %px_step ]\n  %has_px = icmp ult i64 %px, %pool_w\n  br i1 %has_px, label %px_step, label %py_next\n");
        out.push_str("px_step:\n  %in_idx = add i64 %in_row, %x_base\n  %in_full_idx = add i64 %in_idx, %px\n  %p_in = getelementptr inbounds i64, ptr %img, i64 %in_full_idx\n  %v_in = load i64, ptr %p_in, align 8\n  %next_sum_px = add i64 %sum_px, %v_in\n  %next_px = add i64 %px, 1\n  br label %px_loop, !llvm.loop !74\n");
        out.push_str("py_next:\n  %sum_py_next = phi i64 [ %sum_px, %px_loop ]\n  %next_py = add i64 %py, 1\n  br label %py_loop\n");
        out.push_str("p_done:\n  %avg_val = sdiv i64 %sum_py, %area\n  %p_dst = getelementptr inbounds i64, ptr %dst, i64 %out_idx\n  store i64 %avg_val, ptr %p_dst, align 8\n  br label %x_next\n");
        out.push_str("x_next:\n  %next_x = add i64 %x, 1\n  br label %x_loop\n");
        out.push_str("y_next:\n  %next_y = add i64 %y, 1\n  br label %y_loop\n");
        out.push_str("done:\n  ret void\n}\n\n");

        // Multi-Arena Depthwise 2D Convolutions
        out.push_str("define linkonce_odr void @ifa_simd_multi_arena_depthwise_conv2d_f32(ptr %dst, ptr %img, ptr %weights, ptr %bias, i64 %channels, i64 %h_out, i64 %w_out, i64 %stride_y, i64 %stride_x, i64 %kernel_h, i64 %kernel_w, i64 %img_h, i64 %img_w, i32 %activation) alwaysinline {\n");
        out.push_str("entry:\n  %has_bias = icmp ne ptr %bias, null\n  %is_relu = icmp eq i32 %activation, 1\n  %in_area = mul i64 %img_h, %img_w\n  %kernel_area = mul i64 %kernel_h, %kernel_w\n  %out_area = mul i64 %h_out, %w_out\n  br label %c_loop\n");
        out.push_str("c_loop:\n  %c = phi i64 [ 0, %entry ], [ %next_c, %c_next ]\n  %has_c = icmp ult i64 %c, %channels\n  br i1 %has_c, label %c_body, label %done\n");
        out.push_str("c_body:\n  %c_img_off = mul i64 %c, %in_area\n  %c_w_off = mul i64 %c, %kernel_area\n  %c_dst_off = mul i64 %c, %out_area\n  br i1 %has_bias, label %load_b, label %zero_b\n");
        out.push_str("load_b:\n  %p_b = getelementptr inbounds float, ptr %bias, i64 %c\n  %b_val = load float, ptr %p_b, align 4\n  br label %y_init\n");
        out.push_str("zero_b:\n  br label %y_init\n");
        out.push_str("y_init:\n  %bias_scalar = phi float [ %b_val, %load_b ], [ 0.0, %zero_b ]\n  br label %y_loop\n");
        out.push_str("y_loop:\n  %y = phi i64 [ 0, %y_init ], [ %next_y, %y_next ]\n  %has_y = icmp ult i64 %y, %h_out\n  br i1 %has_y, label %x_init, label %c_next\n");
        out.push_str("x_init:\n  %y_str = mul i64 %y, %stride_y\n  %y_base = mul i64 %y_str, %img_w\n  %y_out_off = mul i64 %y, %w_out\n  br label %x_loop\n");
        out.push_str("x_loop:\n  %x = phi i64 [ 0, %x_init ], [ %next_x, %x_next ]\n  %has_x = icmp ult i64 %x, %w_out\n  br i1 %has_x, label %k_init, label %y_next\n");
        out.push_str("k_init:\n  %x_base = mul i64 %x, %stride_x\n  %out_idx_rel = add i64 %y_out_off, %x\n  %out_idx = add i64 %c_dst_off, %out_idx_rel\n  br label %ky_loop\n");
        out.push_str("ky_loop:\n  %ky = phi i64 [ 0, %k_init ], [ %next_ky, %ky_next ]\n  %accum_ky = phi float [ 0.0, %k_init ], [ %accum_ky_next, %ky_next ]\n  %has_ky = icmp ult i64 %ky, %kernel_h\n  br i1 %has_ky, label %kx_init, label %k_done\n");
        out.push_str("kx_init:\n  %ky_off = mul i64 %ky, %img_w\n  %in_row = add i64 %y_base, %ky_off\n  %w_row = mul i64 %ky, %kernel_w\n  br label %kx_loop\n");
        out.push_str("kx_loop:\n  %kx = phi i64 [ 0, %kx_init ], [ %next_kx, %kx_step ]\n  %accum_kx = phi float [ %accum_ky, %kx_init ], [ %next_accum_kx, %kx_step ]\n  %has_kx = icmp ult i64 %kx, %kernel_w\n  br i1 %has_kx, label %kx_step, label %ky_next\n");
        out.push_str("kx_step:\n  %in_pix = add i64 %in_row, %x_base\n  %in_idx_rel = add i64 %in_pix, %kx\n  %in_idx = add i64 %c_img_off, %in_idx_rel\n  %w_idx_rel = add i64 %w_row, %kx\n  %w_idx = add i64 %c_w_off, %w_idx_rel\n  %p_in = getelementptr inbounds float, ptr %img, i64 %in_idx\n  %p_w = getelementptr inbounds float, ptr %weights, i64 %w_idx\n  %v_in = load float, ptr %p_in, align 4\n  %v_w = load float, ptr %p_w, align 4\n  %prod = fmul float %v_in, %v_w\n  %next_accum_kx = fadd float %accum_kx, %prod\n  %next_kx = add i64 %kx, 1\n  br label %kx_loop, !llvm.loop !74\n");
        out.push_str("ky_next:\n  %accum_ky_next = phi float [ %accum_kx, %kx_loop ]\n  %next_ky = add i64 %ky, 1\n  br label %ky_loop\n");
        out.push_str("k_done:\n  %biased = fadd float %accum_ky, %bias_scalar\n  %relu_cond = fcmp ogt float %biased, 0.0\n  %relu_val = select i1 %relu_cond, float %biased, float 0.0\n  %act_val = select i1 %is_relu, float %relu_val, float %biased\n  %p_dst = getelementptr inbounds float, ptr %dst, i64 %out_idx\n  store float %act_val, ptr %p_dst, align 4\n  br label %x_next\n");
        out.push_str("x_next:\n  %next_x = add i64 %x, 1\n  br label %x_loop\n");
        out.push_str("y_next:\n  %next_y = add i64 %y, 1\n  br label %y_loop\n");
        out.push_str("c_next:\n  %next_c = add i64 %c, 1\n  br label %c_loop\n");
        out.push_str("done:\n  ret void\n}\n\n");

        out.push_str("define linkonce_odr void @ifa_simd_multi_arena_depthwise_conv2d_f64(ptr %dst, ptr %img, ptr %weights, ptr %bias, i64 %channels, i64 %h_out, i64 %w_out, i64 %stride_y, i64 %stride_x, i64 %kernel_h, i64 %kernel_w, i64 %img_h, i64 %img_w, i32 %activation) alwaysinline {\n");
        out.push_str("entry:\n  %has_bias = icmp ne ptr %bias, null\n  %is_relu = icmp eq i32 %activation, 1\n  %in_area = mul i64 %img_h, %img_w\n  %kernel_area = mul i64 %kernel_h, %kernel_w\n  %out_area = mul i64 %h_out, %w_out\n  br label %c_loop\n");
        out.push_str("c_loop:\n  %c = phi i64 [ 0, %entry ], [ %next_c, %c_next ]\n  %has_c = icmp ult i64 %c, %channels\n  br i1 %has_c, label %c_body, label %done\n");
        out.push_str("c_body:\n  %c_img_off = mul i64 %c, %in_area\n  %c_w_off = mul i64 %c, %kernel_area\n  %c_dst_off = mul i64 %c, %out_area\n  br i1 %has_bias, label %load_b, label %zero_b\n");
        out.push_str("load_b:\n  %p_b = getelementptr inbounds double, ptr %bias, i64 %c\n  %b_val = load double, ptr %p_b, align 8\n  br label %y_init\n");
        out.push_str("zero_b:\n  br label %y_init\n");
        out.push_str("y_init:\n  %bias_scalar = phi double [ %b_val, %load_b ], [ 0.0, %zero_b ]\n  br label %y_loop\n");
        out.push_str("y_loop:\n  %y = phi i64 [ 0, %y_init ], [ %next_y, %y_next ]\n  %has_y = icmp ult i64 %y, %h_out\n  br i1 %has_y, label %x_init, label %c_next\n");
        out.push_str("x_init:\n  %y_str = mul i64 %y, %stride_y\n  %y_base = mul i64 %y_str, %img_w\n  %y_out_off = mul i64 %y, %w_out\n  br label %x_loop\n");
        out.push_str("x_loop:\n  %x = phi i64 [ 0, %x_init ], [ %next_x, %x_next ]\n  %has_x = icmp ult i64 %x, %w_out\n  br i1 %has_x, label %k_init, label %y_next\n");
        out.push_str("k_init:\n  %x_base = mul i64 %x, %stride_x\n  %out_idx_rel = add i64 %y_out_off, %x\n  %out_idx = add i64 %c_dst_off, %out_idx_rel\n  br label %ky_loop\n");
        out.push_str("ky_loop:\n  %ky = phi i64 [ 0, %k_init ], [ %next_ky, %ky_next ]\n  %accum_ky = phi double [ 0.0, %k_init ], [ %accum_ky_next, %ky_next ]\n  %has_ky = icmp ult i64 %ky, %kernel_h\n  br i1 %has_ky, label %kx_init, label %k_done\n");
        out.push_str("kx_init:\n  %ky_off = mul i64 %ky, %img_w\n  %in_row = add i64 %y_base, %ky_off\n  %w_row = mul i64 %ky, %kernel_w\n  br label %kx_loop\n");
        out.push_str("kx_loop:\n  %kx = phi i64 [ 0, %kx_init ], [ %next_kx, %kx_step ]\n  %accum_kx = phi double [ %accum_ky, %kx_init ], [ %next_accum_kx, %kx_step ]\n  %has_kx = icmp ult i64 %kx, %kernel_w\n  br i1 %has_kx, label %kx_step, label %ky_next\n");
        out.push_str("kx_step:\n  %in_pix = add i64 %in_row, %x_base\n  %in_idx_rel = add i64 %in_pix, %kx\n  %in_idx = add i64 %c_img_off, %in_idx_rel\n  %w_idx_rel = add i64 %w_row, %kx\n  %w_idx = add i64 %c_w_off, %w_idx_rel\n  %p_in = getelementptr inbounds double, ptr %img, i64 %in_idx\n  %p_w = getelementptr inbounds double, ptr %weights, i64 %w_idx\n  %v_in = load double, ptr %p_in, align 8\n  %v_w = load double, ptr %p_w, align 8\n  %prod = fmul double %v_in, %v_w\n  %next_accum_kx = fadd double %accum_kx, %prod\n  %next_kx = add i64 %kx, 1\n  br label %kx_loop, !llvm.loop !74\n");
        out.push_str("ky_next:\n  %accum_ky_next = phi double [ %accum_kx, %kx_loop ]\n  %next_ky = add i64 %ky, 1\n  br label %ky_loop\n");
        out.push_str("k_done:\n  %biased = fadd double %accum_ky, %bias_scalar\n  %relu_cond = fcmp ogt double %biased, 0.0\n  %relu_val = select i1 %relu_cond, double %biased, double 0.0\n  %act_val = select i1 %is_relu, double %relu_val, double %biased\n  %p_dst = getelementptr inbounds double, ptr %dst, i64 %out_idx\n  store double %act_val, ptr %p_dst, align 8\n  br label %x_next\n");
        out.push_str("x_next:\n  %next_x = add i64 %x, 1\n  br label %x_loop\n");
        out.push_str("y_next:\n  %next_y = add i64 %y, 1\n  br label %y_loop\n");
        out.push_str("c_next:\n  %next_c = add i64 %c, 1\n  br label %c_loop\n");
        out.push_str("done:\n  ret void\n}\n\n");

        out.push_str("define linkonce_odr void @ifa_simd_multi_arena_depthwise_conv2d_i64(ptr %dst, ptr %img, ptr %weights, ptr %bias, i64 %channels, i64 %h_out, i64 %w_out, i64 %stride_y, i64 %stride_x, i64 %kernel_h, i64 %kernel_w, i64 %img_h, i64 %img_w, i32 %activation) alwaysinline {\n");
        out.push_str("entry:\n  %has_bias = icmp ne ptr %bias, null\n  %is_relu = icmp eq i32 %activation, 1\n  %in_area = mul i64 %img_h, %img_w\n  %kernel_area = mul i64 %kernel_h, %kernel_w\n  %out_area = mul i64 %h_out, %w_out\n  br label %c_loop\n");
        out.push_str("c_loop:\n  %c = phi i64 [ 0, %entry ], [ %next_c, %c_next ]\n  %has_c = icmp ult i64 %c, %channels\n  br i1 %has_c, label %c_body, label %done\n");
        out.push_str("c_body:\n  %c_img_off = mul i64 %c, %in_area\n  %c_w_off = mul i64 %c, %kernel_area\n  %c_dst_off = mul i64 %c, %out_area\n  br i1 %has_bias, label %load_b, label %zero_b\n");
        out.push_str("load_b:\n  %p_b = getelementptr inbounds i64, ptr %bias, i64 %c\n  %b_val = load i64, ptr %p_b, align 8\n  br label %y_init\n");
        out.push_str("zero_b:\n  br label %y_init\n");
        out.push_str("y_init:\n  %bias_scalar = phi i64 [ %b_val, %load_b ], [ 0, %zero_b ]\n  br label %y_loop\n");
        out.push_str("y_loop:\n  %y = phi i64 [ 0, %y_init ], [ %next_y, %y_next ]\n  %has_y = icmp ult i64 %y, %h_out\n  br i1 %has_y, label %x_init, label %c_next\n");
        out.push_str("x_init:\n  %y_str = mul i64 %y, %stride_y\n  %y_base = mul i64 %y_str, %img_w\n  %y_out_off = mul i64 %y, %w_out\n  br label %x_loop\n");
        out.push_str("x_loop:\n  %x = phi i64 [ 0, %x_init ], [ %next_x, %x_next ]\n  %has_x = icmp ult i64 %x, %w_out\n  br i1 %has_x, label %k_init, label %y_next\n");
        out.push_str("k_init:\n  %x_base = mul i64 %x, %stride_x\n  %out_idx_rel = add i64 %y_out_off, %x\n  %out_idx = add i64 %c_dst_off, %out_idx_rel\n  br label %ky_loop\n");
        out.push_str("ky_loop:\n  %ky = phi i64 [ 0, %k_init ], [ %next_ky, %ky_next ]\n  %accum_ky = phi i64 [ 0, %k_init ], [ %accum_ky_next, %ky_next ]\n  %has_ky = icmp ult i64 %ky, %kernel_h\n  br i1 %has_ky, label %kx_init, label %k_done\n");
        out.push_str("kx_init:\n  %ky_off = mul i64 %ky, %img_w\n  %in_row = add i64 %y_base, %ky_off\n  %w_row = mul i64 %ky, %kernel_w\n  br label %kx_loop\n");
        out.push_str("kx_loop:\n  %kx = phi i64 [ 0, %kx_init ], [ %next_kx, %kx_step ]\n  %accum_kx = phi i64 [ %accum_ky, %kx_init ], [ %next_accum_kx, %kx_step ]\n  %has_kx = icmp ult i64 %kx, %kernel_w\n  br i1 %has_kx, label %kx_step, label %ky_next\n");
        out.push_str("kx_step:\n  %in_pix = add i64 %in_row, %x_base\n  %in_idx_rel = add i64 %in_pix, %kx\n  %in_idx = add i64 %c_img_off, %in_idx_rel\n  %w_idx_rel = add i64 %w_row, %kx\n  %w_idx = add i64 %c_w_off, %w_idx_rel\n  %p_in = getelementptr inbounds i64, ptr %img, i64 %in_idx\n  %p_w = getelementptr inbounds i64, ptr %weights, i64 %w_idx\n  %v_in = load i64, ptr %p_in, align 8\n  %v_w = load i64, ptr %p_w, align 8\n  %prod = mul i64 %v_in, %v_w\n  %next_accum_kx = add i64 %accum_kx, %prod\n  %next_kx = add i64 %kx, 1\n  br label %kx_loop, !llvm.loop !74\n");
        out.push_str("ky_next:\n  %accum_ky_next = phi i64 [ %accum_kx, %kx_loop ]\n  %next_ky = add i64 %ky, 1\n  br label %ky_loop\n");
        out.push_str("k_done:\n  %biased = add i64 %accum_ky, %bias_scalar\n  %relu_cond = icmp sgt i64 %biased, 0\n  %relu_val = select i1 %relu_cond, i64 %biased, i64 0\n  %act_val = select i1 %is_relu, i64 %relu_val, i64 %biased\n  %p_dst = getelementptr inbounds i64, ptr %dst, i64 %out_idx\n  store i64 %act_val, ptr %p_dst, align 8\n  br label %x_next\n");
        out.push_str("x_next:\n  %next_x = add i64 %x, 1\n  br label %x_loop\n");
        out.push_str("y_next:\n  %next_y = add i64 %y, 1\n  br label %y_loop\n");
        out.push_str("c_next:\n  %next_c = add i64 %c, 1\n  br label %c_loop\n");
        out.push_str("done:\n  ret void\n}\n\n");

        // Multi-Arena Pointwise (1x1) 2D Convolutions
        out.push_str("define linkonce_odr void @ifa_simd_multi_arena_pointwise_conv2d_f32(ptr %dst, ptr %img, ptr %weights, ptr %bias, i64 %c_in, i64 %c_out, i64 %spatial_size, i32 %activation) alwaysinline {\n");
        out.push_str("entry:\n  %has_bias = icmp ne ptr %bias, null\n  %is_relu = icmp eq i32 %activation, 1\n  br label %co_loop\n");
        out.push_str("co_loop:\n  %co = phi i64 [ 0, %entry ], [ %next_co, %co_next ]\n  %has_co = icmp ult i64 %co, %c_out\n  br i1 %has_co, label %co_body, label %done\n");
        out.push_str("co_body:\n  %w_co_off = mul i64 %co, %c_in\n  %dst_co_off = mul i64 %co, %spatial_size\n  br i1 %has_bias, label %load_b, label %zero_b\n");
        out.push_str("load_b:\n  %p_b = getelementptr inbounds float, ptr %bias, i64 %co\n  %b_val = load float, ptr %p_b, align 4\n  br label %p_init\n");
        out.push_str("zero_b:\n  br label %p_init\n");
        out.push_str("p_init:\n  %bias_scalar = phi float [ %b_val, %load_b ], [ 0.0, %zero_b ]\n  br label %p_loop\n");
        out.push_str("p_loop:\n  %p = phi i64 [ 0, %p_init ], [ %next_p, %p_next ]\n  %has_p = icmp ult i64 %p, %spatial_size\n  br i1 %has_p, label %ci_init, label %co_next\n");
        out.push_str("ci_init:\n  %out_idx = add i64 %dst_co_off, %p\n  br label %ci_loop\n");
        out.push_str("ci_loop:\n  %ci = phi i64 [ 0, %ci_init ], [ %next_ci, %ci_step ]\n  %accum_ci = phi float [ 0.0, %ci_init ], [ %next_accum_ci, %ci_step ]\n  %has_ci = icmp ult i64 %ci, %c_in\n  br i1 %has_ci, label %ci_step, label %ci_done\n");
        out.push_str("ci_step:\n  %in_ci_off = mul i64 %ci, %spatial_size\n  %in_idx = add i64 %in_ci_off, %p\n  %w_idx = add i64 %w_co_off, %ci\n  %p_in = getelementptr inbounds float, ptr %img, i64 %in_idx\n  %p_w = getelementptr inbounds float, ptr %weights, i64 %w_idx\n  %v_in = load float, ptr %p_in, align 4\n  %v_w = load float, ptr %p_w, align 4\n  %prod = fmul float %v_in, %v_w\n  %next_accum_ci = fadd float %accum_ci, %prod\n  %next_ci = add i64 %ci, 1\n  br label %ci_loop, !llvm.loop !74\n");
        out.push_str("ci_done:\n  %biased = fadd float %accum_ci, %bias_scalar\n  %relu_cond = fcmp ogt float %biased, 0.0\n  %relu_val = select i1 %relu_cond, float %biased, float 0.0\n  %act_val = select i1 %is_relu, float %relu_val, float %biased\n  %p_dst = getelementptr inbounds float, ptr %dst, i64 %out_idx\n  store float %act_val, ptr %p_dst, align 4\n  br label %p_next\n");
        out.push_str("p_next:\n  %next_p = add i64 %p, 1\n  br label %p_loop\n");
        out.push_str("co_next:\n  %next_co = add i64 %co, 1\n  br label %co_loop\n");
        out.push_str("done:\n  ret void\n}\n\n");

        out.push_str("define linkonce_odr void @ifa_simd_multi_arena_pointwise_conv2d_f64(ptr %dst, ptr %img, ptr %weights, ptr %bias, i64 %c_in, i64 %c_out, i64 %spatial_size, i32 %activation) alwaysinline {\n");
        out.push_str("entry:\n  %has_bias = icmp ne ptr %bias, null\n  %is_relu = icmp eq i32 %activation, 1\n  br label %co_loop\n");
        out.push_str("co_loop:\n  %co = phi i64 [ 0, %entry ], [ %next_co, %co_next ]\n  %has_co = icmp ult i64 %co, %c_out\n  br i1 %has_co, label %co_body, label %done\n");
        out.push_str("co_body:\n  %w_co_off = mul i64 %co, %c_in\n  %dst_co_off = mul i64 %co, %spatial_size\n  br i1 %has_bias, label %load_b, label %zero_b\n");
        out.push_str("load_b:\n  %p_b = getelementptr inbounds double, ptr %bias, i64 %co\n  %b_val = load double, ptr %p_b, align 8\n  br label %p_init\n");
        out.push_str("zero_b:\n  br label %p_init\n");
        out.push_str("p_init:\n  %bias_scalar = phi double [ %b_val, %load_b ], [ 0.0, %zero_b ]\n  br label %p_loop\n");
        out.push_str("p_loop:\n  %p = phi i64 [ 0, %p_init ], [ %next_p, %p_next ]\n  %has_p = icmp ult i64 %p, %spatial_size\n  br i1 %has_p, label %ci_init, label %co_next\n");
        out.push_str("ci_init:\n  %out_idx = add i64 %dst_co_off, %p\n  br label %ci_loop\n");
        out.push_str("ci_loop:\n  %ci = phi i64 [ 0, %ci_init ], [ %next_ci, %ci_step ]\n  %accum_ci = phi double [ 0.0, %ci_init ], [ %next_accum_ci, %ci_step ]\n  %has_ci = icmp ult i64 %ci, %c_in\n  br i1 %has_ci, label %ci_step, label %ci_done\n");
        out.push_str("ci_step:\n  %in_ci_off = mul i64 %ci, %spatial_size\n  %in_idx = add i64 %in_ci_off, %p\n  %w_idx = add i64 %w_co_off, %ci\n  %p_in = getelementptr inbounds double, ptr %img, i64 %in_idx\n  %p_w = getelementptr inbounds double, ptr %weights, i64 %w_idx\n  %v_in = load double, ptr %p_in, align 8\n  %v_w = load double, ptr %p_w, align 8\n  %prod = fmul double %v_in, %v_w\n  %next_accum_ci = fadd double %accum_ci, %prod\n  %next_ci = add i64 %ci, 1\n  br label %ci_loop, !llvm.loop !74\n");
        out.push_str("ci_done:\n  %biased = fadd double %accum_ci, %bias_scalar\n  %relu_cond = fcmp ogt double %biased, 0.0\n  %relu_val = select i1 %relu_cond, double %biased, double 0.0\n  %act_val = select i1 %is_relu, double %relu_val, double %biased\n  %p_dst = getelementptr inbounds double, ptr %dst, i64 %out_idx\n  store double %act_val, ptr %p_dst, align 8\n  br label %p_next\n");
        out.push_str("p_next:\n  %next_p = add i64 %p, 1\n  br label %p_loop\n");
        out.push_str("co_next:\n  %next_co = add i64 %co, 1\n  br label %co_loop\n");
        out.push_str("done:\n  ret void\n}\n\n");

        out.push_str("define linkonce_odr void @ifa_simd_multi_arena_pointwise_conv2d_i64(ptr %dst, ptr %img, ptr %weights, ptr %bias, i64 %c_in, i64 %c_out, i64 %spatial_size, i32 %activation) alwaysinline {\n");
        out.push_str("entry:\n  %has_bias = icmp ne ptr %bias, null\n  %is_relu = icmp eq i32 %activation, 1\n  br label %co_loop\n");
        out.push_str("co_loop:\n  %co = phi i64 [ 0, %entry ], [ %next_co, %co_next ]\n  %has_co = icmp ult i64 %co, %c_out\n  br i1 %has_co, label %co_body, label %done\n");
        out.push_str("co_body:\n  %w_co_off = mul i64 %co, %c_in\n  %dst_co_off = mul i64 %co, %spatial_size\n  br i1 %has_bias, label %load_b, label %zero_b\n");
        out.push_str("load_b:\n  %p_b = getelementptr inbounds i64, ptr %bias, i64 %co\n  %b_val = load i64, ptr %p_b, align 8\n  br label %p_init\n");
        out.push_str("zero_b:\n  br label %p_init\n");
        out.push_str("p_init:\n  %bias_scalar = phi i64 [ %b_val, %load_b ], [ 0, %zero_b ]\n  br label %p_loop\n");
        out.push_str("p_loop:\n  %p = phi i64 [ 0, %p_init ], [ %next_p, %p_next ]\n  %has_p = icmp ult i64 %p, %spatial_size\n  br i1 %has_p, label %ci_init, label %co_next\n");
        out.push_str("ci_init:\n  %out_idx = add i64 %dst_co_off, %p\n  br label %ci_loop\n");
        out.push_str("ci_loop:\n  %ci = phi i64 [ 0, %ci_init ], [ %next_ci, %ci_step ]\n  %accum_ci = phi i64 [ 0, %ci_init ], [ %next_accum_ci, %ci_step ]\n  %has_ci = icmp ult i64 %ci, %c_in\n  br i1 %has_ci, label %ci_step, label %ci_done\n");
        out.push_str("ci_step:\n  %in_ci_off = mul i64 %ci, %spatial_size\n  %in_idx = add i64 %in_ci_off, %p\n  %w_idx = add i64 %w_co_off, %ci\n  %p_in = getelementptr inbounds i64, ptr %img, i64 %in_idx\n  %p_w = getelementptr inbounds i64, ptr %weights, i64 %w_idx\n  %v_in = load i64, ptr %p_in, align 8\n  %v_w = load i64, ptr %p_w, align 8\n  %prod = mul i64 %v_in, %v_w\n  %next_accum_ci = add i64 %accum_ci, %prod\n  %next_ci = add i64 %ci, 1\n  br label %ci_loop, !llvm.loop !74\n");
        out.push_str("ci_done:\n  %biased = add i64 %accum_ci, %bias_scalar\n  %relu_cond = icmp sgt i64 %biased, 0\n  %relu_val = select i1 %relu_cond, i64 %biased, i64 0\n  %act_val = select i1 %is_relu, i64 %relu_val, i64 %biased\n  %p_dst = getelementptr inbounds i64, ptr %dst, i64 %out_idx\n  store i64 %act_val, ptr %p_dst, align 8\n  br label %p_next\n");
        out.push_str("p_next:\n  %next_p = add i64 %p, 1\n  br label %p_loop\n");
        out.push_str("co_next:\n  %next_co = add i64 %co, 1\n  br label %co_loop\n");
        out.push_str("done:\n  ret void\n}\n\n");

        // Multi-Arena 2D Batch Normalization
        out.push_str("define linkonce_odr void @ifa_simd_multi_arena_batch_norm2d_f32(ptr %dst, ptr %src, ptr %gamma, ptr %beta, ptr %mean, ptr %var, i64 %channels, i64 %spatial_size, float %epsilon, i32 %activation) alwaysinline {\n");
        out.push_str("entry:\n  %has_gamma = icmp ne ptr %gamma, null\n  %has_beta = icmp ne ptr %beta, null\n  %is_relu = icmp eq i32 %activation, 1\n  br label %c_loop\n");
        out.push_str("c_loop:\n  %c = phi i64 [ 0, %entry ], [ %next_c, %c_next ]\n  %has_c = icmp ult i64 %c, %channels\n  br i1 %has_c, label %c_body, label %done\n");
        out.push_str("c_body:\n  %p_mean = getelementptr inbounds float, ptr %mean, i64 %c\n  %m_val = load float, ptr %p_mean, align 4\n  %p_var = getelementptr inbounds float, ptr %var, i64 %c\n  %v_val = load float, ptr %p_var, align 4\n  %v_eps = fadd float %v_val, %epsilon\n  %std_dev = call float @llvm.sqrt.f32(float %v_eps)\n  %inv_std = fdiv float 1.0, %std_dev\n  br i1 %has_gamma, label %load_g, label %one_g\n");
        out.push_str("load_g:\n  %p_g = getelementptr inbounds float, ptr %gamma, i64 %c\n  %g_val = load float, ptr %p_g, align 4\n  br label %beta_check\n");
        out.push_str("one_g:\n  br label %beta_check\n");
        out.push_str("beta_check:\n  %gamma_val = phi float [ %g_val, %load_g ], [ 1.0, %one_g ]\n  br i1 %has_beta, label %load_b, label %zero_b\n");
        out.push_str("load_b:\n  %p_b = getelementptr inbounds float, ptr %beta, i64 %c\n  %b_val = load float, ptr %p_b, align 4\n  br label %coeff_calc\n");
        out.push_str("zero_b:\n  br label %coeff_calc\n");
        out.push_str("coeff_calc:\n  %beta_val = phi float [ %b_val, %load_b ], [ 0.0, %zero_b ]\n  %scale = fmul float %gamma_val, %inv_std\n  %m_scale = fmul float %m_val, %scale\n  %shift = fsub float %beta_val, %m_scale\n  %c_base = mul i64 %c, %spatial_size\n  br label %p_loop\n");
        out.push_str("p_loop:\n  %i = phi i64 [ 0, %coeff_calc ], [ %next_i, %p_next ]\n  %has_i = icmp ult i64 %i, %spatial_size\n  br i1 %has_i, label %p_step, label %c_next\n");
        out.push_str("p_step:\n  %idx = add i64 %c_base, %i\n  %p_src = getelementptr inbounds float, ptr %src, i64 %idx\n  %x_val = load float, ptr %p_src, align 4\n  %scaled = fmul float %x_val, %scale\n  %normed = fadd float %scaled, %shift\n  %relu_cond = fcmp ogt float %normed, 0.0\n  %relu_val = select i1 %relu_cond, float %normed, float 0.0\n  %act_val = select i1 %is_relu, float %relu_val, float %normed\n  %p_dst = getelementptr inbounds float, ptr %dst, i64 %idx\n  store float %act_val, ptr %p_dst, align 4\n  br label %p_next\n");
        out.push_str("p_next:\n  %next_i = add i64 %i, 1\n  br label %p_loop, !llvm.loop !74\n");
        out.push_str("c_next:\n  %next_c = add i64 %c, 1\n  br label %c_loop\n");
        out.push_str("done:\n  ret void\n}\n\n");

        out.push_str("define linkonce_odr void @ifa_simd_multi_arena_batch_norm2d_f64(ptr %dst, ptr %src, ptr %gamma, ptr %beta, ptr %mean, ptr %var, i64 %channels, i64 %spatial_size, double %epsilon, i32 %activation) alwaysinline {\n");
        out.push_str("entry:\n  %has_gamma = icmp ne ptr %gamma, null\n  %has_beta = icmp ne ptr %beta, null\n  %is_relu = icmp eq i32 %activation, 1\n  br label %c_loop\n");
        out.push_str("c_loop:\n  %c = phi i64 [ 0, %entry ], [ %next_c, %c_next ]\n  %has_c = icmp ult i64 %c, %channels\n  br i1 %has_c, label %c_body, label %done\n");
        out.push_str("c_body:\n  %p_mean = getelementptr inbounds double, ptr %mean, i64 %c\n  %m_val = load double, ptr %p_mean, align 8\n  %p_var = getelementptr inbounds double, ptr %var, i64 %c\n  %v_val = load double, ptr %p_var, align 8\n  %v_eps = fadd double %v_val, %epsilon\n  %std_dev = call double @llvm.sqrt.f64(double %v_eps)\n  %inv_std = fdiv double 1.0, %std_dev\n  br i1 %has_gamma, label %load_g, label %one_g\n");
        out.push_str("load_g:\n  %p_g = getelementptr inbounds double, ptr %gamma, i64 %c\n  %g_val = load double, ptr %p_g, align 8\n  br label %beta_check\n");
        out.push_str("one_g:\n  br label %beta_check\n");
        out.push_str("beta_check:\n  %gamma_val = phi double [ %g_val, %load_g ], [ 1.0, %one_g ]\n  br i1 %has_beta, label %load_b, label %zero_b\n");
        out.push_str("load_b:\n  %p_b = getelementptr inbounds double, ptr %beta, i64 %c\n  %b_val = load double, ptr %p_b, align 8\n  br label %coeff_calc\n");
        out.push_str("zero_b:\n  br label %coeff_calc\n");
        out.push_str("coeff_calc:\n  %beta_val = phi double [ %b_val, %load_b ], [ 0.0, %zero_b ]\n  %scale = fmul double %gamma_val, %inv_std\n  %m_scale = fmul double %m_val, %scale\n  %shift = fsub double %beta_val, %m_scale\n  %c_base = mul i64 %c, %spatial_size\n  br label %p_loop\n");
        out.push_str("p_loop:\n  %i = phi i64 [ 0, %coeff_calc ], [ %next_i, %p_next ]\n  %has_i = icmp ult i64 %i, %spatial_size\n  br i1 %has_i, label %p_step, label %c_next\n");
        out.push_str("p_step:\n  %idx = add i64 %c_base, %i\n  %p_src = getelementptr inbounds double, ptr %src, i64 %idx\n  %x_val = load double, ptr %p_src, align 8\n  %scaled = fmul double %x_val, %scale\n  %normed = fadd double %scaled, %shift\n  %relu_cond = fcmp ogt double %normed, 0.0\n  %relu_val = select i1 %relu_cond, double %normed, double 0.0\n  %act_val = select i1 %is_relu, double %relu_val, double %normed\n  %p_dst = getelementptr inbounds double, ptr %dst, i64 %idx\n  store double %act_val, ptr %p_dst, align 8\n  br label %p_next\n");
        out.push_str("p_next:\n  %next_i = add i64 %i, 1\n  br label %p_loop, !llvm.loop !74\n");
        out.push_str("c_next:\n  %next_c = add i64 %c, 1\n  br label %c_loop\n");
        out.push_str("done:\n  ret void\n}\n\n");

        // 6. Arena Slice Count-If Reductions (Conditional Counting Zero-Heap)
        out.push_str("; IFA Standard Library SIMD Contiguous Arena Slice Count-If Reductions\n");

        out.push_str("define linkonce_odr i64 @ifa_simd_arena_slice_count_if_gt_f32(ptr %src, i64 %len, float %threshold) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -8\n  %splat = insertelement <8 x float> poison, float %threshold, i32 0\n  %vthresh = shufflevector <8 x float> %splat, <8 x float> poison, <8 x i32> zeroinitializer\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <8 x i32> [ zeroinitializer, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
        out.push_str("vec_step:\n  %p = getelementptr inbounds float, ptr %src, i64 %i\n  %v = load <8 x float>, ptr %p, align 32\n  %mask = fcmp ogt <8 x float> %v, %vthresh\n  %z = zext <8 x i1> %mask to <8 x i32>\n  %next_acc = add <8 x i32> %acc, %z\n  %next_i = add i64 %i, 8\n  br label %vec_loop, !llvm.loop !18\n");
        out.push_str("reduce:\n  %vec_sum32 = call i32 @llvm.vector.reduce.add.v8i32(<8 x i32> %acc)\n  %vec_sum = zext i32 %vec_sum32 to i64\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi i64 [ %vec_sum, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp = getelementptr inbounds float, ptr %src, i64 %ti\n  %tv = load float, ptr %tp, align 4\n  %tcmp = fcmp ogt float %tv, %threshold\n  %tinc = zext i1 %tcmp to i64\n  %next_s_acc = add i64 %s_acc, %tinc\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret i64 %s_acc\n}\n\n");

        out.push_str("define linkonce_odr i64 @ifa_simd_arena_slice_count_if_gt_f64(ptr %src, i64 %len, double %threshold) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -4\n  %splat = insertelement <4 x double> poison, double %threshold, i32 0\n  %vthresh = shufflevector <4 x double> %splat, <4 x double> poison, <4 x i32> zeroinitializer\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <4 x i64> [ zeroinitializer, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
        out.push_str("vec_step:\n  %p = getelementptr inbounds double, ptr %src, i64 %i\n  %v = load <4 x double>, ptr %p, align 32\n  %mask = fcmp ogt <4 x double> %v, %vthresh\n  %z = zext <4 x i1> %mask to <4 x i64>\n  %next_acc = add <4 x i64> %acc, %z\n  %next_i = add i64 %i, 4\n  br label %vec_loop, !llvm.loop !19\n");
        out.push_str("reduce:\n  %vec_sum = call i64 @llvm.vector.reduce.add.v4i64(<4 x i64> %acc)\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi i64 [ %vec_sum, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp = getelementptr inbounds double, ptr %src, i64 %ti\n  %tv = load double, ptr %tp, align 8\n  %tcmp = fcmp ogt double %tv, %threshold\n  %tinc = zext i1 %tcmp to i64\n  %next_s_acc = add i64 %s_acc, %tinc\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret i64 %s_acc\n}\n\n");

        out.push_str("define linkonce_odr i64 @ifa_simd_arena_slice_count_if_gt_i32(ptr %src, i64 %len, i32 %threshold) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -8\n  %splat = insertelement <8 x i32> poison, i32 %threshold, i32 0\n  %vthresh = shufflevector <8 x i32> %splat, <8 x i32> poison, <8 x i32> zeroinitializer\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <8 x i32> [ zeroinitializer, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
        out.push_str("vec_step:\n  %p = getelementptr inbounds i32, ptr %src, i64 %i\n  %v = load <8 x i32>, ptr %p, align 32\n  %mask = icmp sgt <8 x i32> %v, %vthresh\n  %z = zext <8 x i1> %mask to <8 x i32>\n  %next_acc = add <8 x i32> %acc, %z\n  %next_i = add i64 %i, 8\n  br label %vec_loop, !llvm.loop !18\n");
        out.push_str("reduce:\n  %vec_sum32 = call i32 @llvm.vector.reduce.add.v8i32(<8 x i32> %acc)\n  %vec_sum = zext i32 %vec_sum32 to i64\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi i64 [ %vec_sum, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp = getelementptr inbounds i32, ptr %src, i64 %ti\n  %tv = load i32, ptr %tp, align 4\n  %tcmp = icmp sgt i32 %tv, %threshold\n  %tinc = zext i1 %tcmp to i64\n  %next_s_acc = add i64 %s_acc, %tinc\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret i64 %s_acc\n}\n\n");

        out.push_str("define linkonce_odr i64 @ifa_simd_arena_slice_count_if_gt_i64(ptr %src, i64 %len, i64 %threshold) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -4\n  %splat = insertelement <4 x i64> poison, i64 %threshold, i32 0\n  %vthresh = shufflevector <4 x i64> %splat, <4 x i64> poison, <4 x i32> zeroinitializer\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <4 x i64> [ zeroinitializer, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
        out.push_str("vec_step:\n  %p = getelementptr inbounds i64, ptr %src, i64 %i\n  %v = load <4 x i64>, ptr %p, align 32\n  %mask = icmp sgt <4 x i64> %v, %vthresh\n  %z = zext <4 x i1> %mask to <4 x i64>\n  %next_acc = add <4 x i64> %acc, %z\n  %next_i = add i64 %i, 4\n  br label %vec_loop, !llvm.loop !19\n");
        out.push_str("reduce:\n  %vec_sum = call i64 @llvm.vector.reduce.add.v4i64(<4 x i64> %acc)\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi i64 [ %vec_sum, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp = getelementptr inbounds i64, ptr %src, i64 %ti\n  %tv = load i64, ptr %tp, align 8\n  %tcmp = icmp sgt i64 %tv, %threshold\n  %tinc = zext i1 %tcmp to i64\n  %next_s_acc = add i64 %s_acc, %tinc\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret i64 %s_acc\n}\n\n");

        out.push_str("define linkonce_odr i64 @ifa_simd_arena_slice_count_if_lt_i32(ptr %src, i64 %len, i32 %threshold) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -8\n  %splat = insertelement <8 x i32> poison, i32 %threshold, i32 0\n  %vthresh = shufflevector <8 x i32> %splat, <8 x i32> poison, <8 x i32> zeroinitializer\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <8 x i32> [ zeroinitializer, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
        out.push_str("vec_step:\n  %p = getelementptr inbounds i32, ptr %src, i64 %i\n  %v = load <8 x i32>, ptr %p, align 32\n  %mask = icmp slt <8 x i32> %v, %vthresh\n  %z = zext <8 x i1> %mask to <8 x i32>\n  %next_acc = add <8 x i32> %acc, %z\n  %next_i = add i64 %i, 8\n  br label %vec_loop, !llvm.loop !18\n");
        out.push_str("reduce:\n  %vec_sum32 = call i32 @llvm.vector.reduce.add.v8i32(<8 x i32> %acc)\n  %vec_sum = zext i32 %vec_sum32 to i64\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi i64 [ %vec_sum, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp = getelementptr inbounds i32, ptr %src, i64 %ti\n  %tv = load i32, ptr %tp, align 4\n  %tcmp = icmp slt i32 %tv, %threshold\n  %tinc = zext i1 %tcmp to i64\n  %next_s_acc = add i64 %s_acc, %tinc\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret i64 %s_acc\n}\n\n");

        out.push_str("define linkonce_odr i64 @ifa_simd_arena_slice_count_if_eq_i32(ptr %src, i64 %len, i32 %target) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -8\n  %splat = insertelement <8 x i32> poison, i32 %target, i32 0\n  %vtarget = shufflevector <8 x i32> %splat, <8 x i32> poison, <8 x i32> zeroinitializer\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <8 x i32> [ zeroinitializer, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
        out.push_str("vec_step:\n  %p = getelementptr inbounds i32, ptr %src, i64 %i\n  %v = load <8 x i32>, ptr %p, align 32\n  %mask = icmp eq <8 x i32> %v, %vtarget\n  %z = zext <8 x i1> %mask to <8 x i32>\n  %next_acc = add <8 x i32> %acc, %z\n  %next_i = add i64 %i, 8\n  br label %vec_loop, !llvm.loop !18\n");
        out.push_str("reduce:\n  %vec_sum32 = call i32 @llvm.vector.reduce.add.v8i32(<8 x i32> %acc)\n  %vec_sum = zext i32 %vec_sum32 to i64\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi i64 [ %vec_sum, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp = getelementptr inbounds i32, ptr %src, i64 %ti\n  %tv = load i32, ptr %tp, align 4\n  %tcmp = icmp eq i32 %tv, %target\n  %tinc = zext i1 %tcmp to i64\n  %next_s_acc = add i64 %s_acc, %tinc\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret i64 %s_acc\n}\n\n");

        out.push_str("define linkonce_odr i64 @ifa_simd_arena_slice_count_if_ne_i32(ptr %src, i64 %len, i32 %target) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -8\n  %splat = insertelement <8 x i32> poison, i32 %target, i32 0\n  %vtarget = shufflevector <8 x i32> %splat, <8 x i32> poison, <8 x i32> zeroinitializer\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <8 x i32> [ zeroinitializer, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
        out.push_str("vec_step:\n  %p = getelementptr inbounds i32, ptr %src, i64 %i\n  %v = load <8 x i32>, ptr %p, align 32\n  %mask = icmp ne <8 x i32> %v, %vtarget\n  %z = zext <8 x i1> %mask to <8 x i32>\n  %next_acc = add <8 x i32> %acc, %z\n  %next_i = add i64 %i, 8\n  br label %vec_loop, !llvm.loop !18\n");
        out.push_str("reduce:\n  %vec_sum32 = call i32 @llvm.vector.reduce.add.v8i32(<8 x i32> %acc)\n  %vec_sum = zext i32 %vec_sum32 to i64\n  br label %tail_loop\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi i64 [ %vec_sum, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp = getelementptr inbounds i32, ptr %src, i64 %ti\n  %tv = load i32, ptr %tp, align 4\n  %tcmp = icmp ne i32 %tv, %target\n  %tinc = zext i1 %tcmp to i64\n  %next_s_acc = add i64 %s_acc, %tinc\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret i64 %s_acc\n}\n\n");

        // 7. Arena Slice Predicated Filters (Zero-Heap Stream Compaction)
        out.push_str("; IFA Standard Library SIMD Contiguous Arena Slice Predicated Filters\n");

        out.push_str("define linkonce_odr i64 @ifa_simd_arena_slice_filter_gt_i32(ptr %src, ptr %dst, i64 %len, i32 %threshold) alwaysinline {\n");
        out.push_str("entry:\n  br label %loop\n");
        out.push_str("loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %step ]\n  %out_cnt = phi i64 [ 0, %entry ], [ %next_out_cnt, %step ]\n  %cond = icmp ult i64 %i, %len\n  br i1 %cond, label %check, label %done\n");
        out.push_str("check:\n  %p_src = getelementptr inbounds i32, ptr %src, i64 %i\n  %val = load i32, ptr %p_src, align 4\n  %cmp = icmp sgt i32 %val, %threshold\n  br i1 %cmp, label %store_val, label %step\n");
        out.push_str("store_val:\n  %p_dst = getelementptr inbounds i32, ptr %dst, i64 %out_cnt\n  store i32 %val, ptr %p_dst, align 4\n  %inc_cnt = add i64 %out_cnt, 1\n  br label %step\n");
        out.push_str("step:\n  %next_out_cnt = phi i64 [ %inc_cnt, %store_val ], [ %out_cnt, %check ]\n  %next_i = add i64 %i, 1\n  br label %loop, !llvm.loop !18\n");
        out.push_str("done:\n  ret i64 %out_cnt\n}\n\n");

        out.push_str("define linkonce_odr i64 @ifa_simd_arena_slice_filter_gt_f32(ptr %src, ptr %dst, i64 %len, float %threshold) alwaysinline {\n");
        out.push_str("entry:\n  br label %loop\n");
        out.push_str("loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %step ]\n  %out_cnt = phi i64 [ 0, %entry ], [ %next_out_cnt, %step ]\n  %cond = icmp ult i64 %i, %len\n  br i1 %cond, label %check, label %done\n");
        out.push_str("check:\n  %p_src = getelementptr inbounds float, ptr %src, i64 %i\n  %val = load float, ptr %p_src, align 4\n  %cmp = fcmp ogt float %val, %threshold\n  br i1 %cmp, label %store_val, label %step\n");
        out.push_str("store_val:\n  %p_dst = getelementptr inbounds float, ptr %dst, i64 %out_cnt\n  store float %val, ptr %p_dst, align 4\n  %inc_cnt = add i64 %out_cnt, 1\n  br label %step\n");
        out.push_str("step:\n  %next_out_cnt = phi i64 [ %inc_cnt, %store_val ], [ %out_cnt, %check ]\n  %next_i = add i64 %i, 1\n  br label %loop, !llvm.loop !18\n");
        out.push_str("done:\n  ret i64 %out_cnt\n}\n\n");

        out.push_str("define linkonce_odr i64 @ifa_simd_arena_slice_filter_gt_f64(ptr %src, ptr %dst, i64 %len, double %threshold) alwaysinline {\n");
        out.push_str("entry:\n  br label %loop\n");
        out.push_str("loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %step ]\n  %out_cnt = phi i64 [ 0, %entry ], [ %next_out_cnt, %step ]\n  %cond = icmp ult i64 %i, %len\n  br i1 %cond, label %check, label %done\n");
        out.push_str("check:\n  %p_src = getelementptr inbounds double, ptr %src, i64 %i\n  %val = load double, ptr %p_src, align 8\n  %cmp = fcmp ogt double %val, %threshold\n  br i1 %cmp, label %store_val, label %step\n");
        out.push_str("store_val:\n  %p_dst = getelementptr inbounds double, ptr %dst, i64 %out_cnt\n  store double %val, ptr %p_dst, align 8\n  %inc_cnt = add i64 %out_cnt, 1\n  br label %step\n");
        out.push_str("step:\n  %next_out_cnt = phi i64 [ %inc_cnt, %store_val ], [ %out_cnt, %check ]\n  %next_i = add i64 %i, 1\n  br label %loop, !llvm.loop !19\n");
        out.push_str("done:\n  ret i64 %out_cnt\n}\n\n");

        out.push_str("define linkonce_odr i64 @ifa_simd_arena_slice_filter_gt_i64(ptr %src, ptr %dst, i64 %len, i64 %threshold) alwaysinline {\n");
        out.push_str("entry:\n  br label %loop\n");
        out.push_str("loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %step ]\n  %out_cnt = phi i64 [ 0, %entry ], [ %next_out_cnt, %step ]\n  %cond = icmp ult i64 %i, %len\n  br i1 %cond, label %check, label %done\n");
        out.push_str("check:\n  %p_src = getelementptr inbounds i64, ptr %src, i64 %i\n  %val = load i64, ptr %p_src, align 8\n  %cmp = icmp sgt i64 %val, %threshold\n  br i1 %cmp, label %store_val, label %step\n");
        out.push_str("store_val:\n  %p_dst = getelementptr inbounds i64, ptr %dst, i64 %out_cnt\n  store i64 %val, ptr %p_dst, align 8\n  %inc_cnt = add i64 %out_cnt, 1\n  br label %step\n");
        out.push_str("step:\n  %next_out_cnt = phi i64 [ %inc_cnt, %store_val ], [ %out_cnt, %check ]\n  %next_i = add i64 %i, 1\n  br label %loop, !llvm.loop !19\n");
        out.push_str("done:\n  ret i64 %out_cnt\n}\n\n");

        out.push_str("define linkonce_odr i64 @ifa_simd_arena_slice_filter_lt_i32(ptr %src, ptr %dst, i64 %len, i32 %threshold) alwaysinline {\n");
        out.push_str("entry:\n  br label %loop\n");
        out.push_str("loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %step ]\n  %out_cnt = phi i64 [ 0, %entry ], [ %next_out_cnt, %step ]\n  %cond = icmp ult i64 %i, %len\n  br i1 %cond, label %check, label %done\n");
        out.push_str("check:\n  %p_src = getelementptr inbounds i32, ptr %src, i64 %i\n  %val = load i32, ptr %p_src, align 4\n  %cmp = icmp slt i32 %val, %threshold\n  br i1 %cmp, label %store_val, label %step\n");
        out.push_str("store_val:\n  %p_dst = getelementptr inbounds i32, ptr %dst, i64 %out_cnt\n  store i32 %val, ptr %p_dst, align 4\n  %inc_cnt = add i64 %out_cnt, 1\n  br label %step\n");
        out.push_str("step:\n  %next_out_cnt = phi i64 [ %inc_cnt, %store_val ], [ %out_cnt, %check ]\n  %next_i = add i64 %i, 1\n  br label %loop, !llvm.loop !18\n");
        out.push_str("done:\n  ret i64 %out_cnt\n}\n\n");

        out.push_str("define linkonce_odr i64 @ifa_simd_arena_slice_filter_eq_i32(ptr %src, ptr %dst, i64 %len, i32 %target) alwaysinline {\n");
        out.push_str("entry:\n  br label %loop\n");
        out.push_str("loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %step ]\n  %out_cnt = phi i64 [ 0, %entry ], [ %next_out_cnt, %step ]\n  %cond = icmp ult i64 %i, %len\n  br i1 %cond, label %check, label %done\n");
        out.push_str("check:\n  %p_src = getelementptr inbounds i32, ptr %src, i64 %i\n  %val = load i32, ptr %p_src, align 4\n  %cmp = icmp eq i32 %val, %target\n  br i1 %cmp, label %store_val, label %step\n");
        out.push_str("store_val:\n  %p_dst = getelementptr inbounds i32, ptr %dst, i64 %out_cnt\n  store i32 %val, ptr %p_dst, align 4\n  %inc_cnt = add i64 %out_cnt, 1\n  br label %step\n");
        out.push_str("step:\n  %next_out_cnt = phi i64 [ %inc_cnt, %store_val ], [ %out_cnt, %check ]\n  %next_i = add i64 %i, 1\n  br label %loop, !llvm.loop !18\n");
        out.push_str("done:\n  ret i64 %out_cnt\n}\n\n");

        // 8. Arena Slice Conditional Projections & Clamping
        out.push_str("; IFA Standard Library SIMD Contiguous Arena Slice Conditional Projections & Clamping\n");

        out.push_str("define linkonce_odr void @ifa_simd_arena_slice_select_gt_f32(ptr %src, ptr %dst, i64 %len, float %threshold, float %fallback) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -8\n  %splat_t = insertelement <8 x float> poison, float %threshold, i32 0\n  %vthresh = shufflevector <8 x float> %splat_t, <8 x float> poison, <8 x i32> zeroinitializer\n  %splat_f = insertelement <8 x float> poison, float %fallback, i32 0\n  %vfall = shufflevector <8 x float> %splat_f, <8 x float> poison, <8 x i32> zeroinitializer\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %tail_loop\n");
        out.push_str("vec_step:\n  %p = getelementptr inbounds float, ptr %src, i64 %i\n  %pd = getelementptr inbounds float, ptr %dst, i64 %i\n  %v = load <8 x float>, ptr %p, align 32\n  %mask = fcmp ogt <8 x float> %v, %vthresh\n  %res = select <8 x i1> %mask, <8 x float> %v, <8 x float> %vfall\n  store <8 x float> %res, ptr %pd, align 32\n  %next_i = add i64 %i, 8\n  br label %vec_loop, !llvm.loop !18\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %vec_loop ], [ %next_ti, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp = getelementptr inbounds float, ptr %src, i64 %ti\n  %tpd = getelementptr inbounds float, ptr %dst, i64 %ti\n  %tv = load float, ptr %tp, align 4\n  %tmask = fcmp ogt float %tv, %threshold\n  %tres = select i1 %tmask, float %tv, float %fallback\n  store float %tres, ptr %tpd, align 4\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret void\n}\n\n");

        out.push_str("define linkonce_odr void @ifa_simd_arena_slice_select_gt_i32(ptr %src, ptr %dst, i64 %len, i32 %threshold, i32 %fallback) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -8\n  %splat_t = insertelement <8 x i32> poison, i32 %threshold, i32 0\n  %vthresh = shufflevector <8 x i32> %splat_t, <8 x i32> poison, <8 x i32> zeroinitializer\n  %splat_f = insertelement <8 x i32> poison, i32 %fallback, i32 0\n  %vfall = shufflevector <8 x i32> %splat_f, <8 x i32> poison, <8 x i32> zeroinitializer\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %tail_loop\n");
        out.push_str("vec_step:\n  %p = getelementptr inbounds i32, ptr %src, i64 %i\n  %pd = getelementptr inbounds i32, ptr %dst, i64 %i\n  %v = load <8 x i32>, ptr %p, align 32\n  %mask = icmp sgt <8 x i32> %v, %vthresh\n  %res = select <8 x i1> %mask, <8 x i32> %v, <8 x i32> %vfall\n  store <8 x i32> %res, ptr %pd, align 32\n  %next_i = add i64 %i, 8\n  br label %vec_loop, !llvm.loop !18\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %vec_loop ], [ %next_ti, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp = getelementptr inbounds i32, ptr %src, i64 %ti\n  %tpd = getelementptr inbounds i32, ptr %dst, i64 %ti\n  %tv = load i32, ptr %tp, align 4\n  %tmask = icmp sgt i32 %tv, %threshold\n  %tres = select i1 %tmask, i32 %tv, i32 %fallback\n  store i32 %tres, ptr %tpd, align 4\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret void\n}\n\n");

        out.push_str("define linkonce_odr void @ifa_simd_arena_slice_clamp_f32(ptr %src, ptr %dst, i64 %len, float %min_val, float %max_val) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -8\n  %splat_min = insertelement <8 x float> poison, float %min_val, i32 0\n  %vmin = shufflevector <8 x float> %splat_min, <8 x float> poison, <8 x i32> zeroinitializer\n  %splat_max = insertelement <8 x float> poison, float %max_val, i32 0\n  %vmax = shufflevector <8 x float> %splat_max, <8 x float> poison, <8 x i32> zeroinitializer\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %tail_loop\n");
        out.push_str("vec_step:\n  %p = getelementptr inbounds float, ptr %src, i64 %i\n  %pd = getelementptr inbounds float, ptr %dst, i64 %i\n  %v = load <8 x float>, ptr %p, align 32\n  %c_lo = fcmp olt <8 x float> %v, %vmin\n  %v_lo = select <8 x i1> %c_lo, <8 x float> %vmin, <8 x float> %v\n  %c_hi = fcmp ogt <8 x float> %v_lo, %vmax\n  %v_clamped = select <8 x i1> %c_hi, <8 x float> %vmax, <8 x float> %v_lo\n  store <8 x float> %v_clamped, ptr %pd, align 32\n  %next_i = add i64 %i, 8\n  br label %vec_loop, !llvm.loop !18\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %vec_loop ], [ %next_ti, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp = getelementptr inbounds float, ptr %src, i64 %ti\n  %tpd = getelementptr inbounds float, ptr %dst, i64 %ti\n  %tv = load float, ptr %tp, align 4\n  %tc_lo = fcmp olt float %tv, %min_val\n  %tv_lo = select i1 %tc_lo, float %min_val, float %tv\n  %tc_hi = fcmp ogt float %tv_lo, %max_val\n  %tv_clamped = select i1 %tc_hi, float %max_val, float %tv_lo\n  store float %tv_clamped, ptr %tpd, align 4\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret void\n}\n\n");

        out.push_str("define linkonce_odr void @ifa_simd_arena_slice_clamp_i32(ptr %src, ptr %dst, i64 %len, i32 %min_val, i32 %max_val) alwaysinline {\n");
        out.push_str("entry:\n  %vec_len = and i64 %len, -8\n  %splat_min = insertelement <8 x i32> poison, i32 %min_val, i32 0\n  %vmin = shufflevector <8 x i32> %splat_min, <8 x i32> poison, <8 x i32> zeroinitializer\n  %splat_max = insertelement <8 x i32> poison, i32 %max_val, i32 0\n  %vmax = shufflevector <8 x i32> %splat_max, <8 x i32> poison, <8 x i32> zeroinitializer\n  br label %vec_loop\n");
        out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %tail_loop\n");
        out.push_str("vec_step:\n  %p = getelementptr inbounds i32, ptr %src, i64 %i\n  %pd = getelementptr inbounds i32, ptr %dst, i64 %i\n  %v = load <8 x i32>, ptr %p, align 32\n  %c_lo = icmp slt <8 x i32> %v, %vmin\n  %v_lo = select <8 x i1> %c_lo, <8 x i32> %vmin, <8 x i32> %v\n  %c_hi = icmp sgt <8 x i32> %v_lo, %vmax\n  %v_clamped = select <8 x i1> %c_hi, <8 x i32> %vmax, <8 x i32> %v_lo\n  store <8 x i32> %v_clamped, ptr %pd, align 32\n  %next_i = add i64 %i, 8\n  br label %vec_loop, !llvm.loop !18\n");
        out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %vec_loop ], [ %next_ti, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
        out.push_str("tail_step:\n  %tp = getelementptr inbounds i32, ptr %src, i64 %ti\n  %tpd = getelementptr inbounds i32, ptr %dst, i64 %ti\n  %tv = load i32, ptr %tp, align 4\n  %tc_lo = icmp slt i32 %tv, %min_val\n  %tv_lo = select i1 %tc_lo, i32 %min_val, i32 %tv\n  %tc_hi = icmp sgt i32 %tv_lo, %max_val\n  %tv_clamped = select i1 %tc_hi, i32 %max_val, i32 %tv_lo\n  store i32 %tv_clamped, ptr %tpd, align 4\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
        out.push_str("done:\n  ret void\n}\n\n");

        if self.target.arch == TargetArch::AArch64 {
            out.push_str("; AArch64 Advanced SIMD (NEON) Hardware-Accelerated Vectorizers\n");
            out.push_str("define linkonce_odr float @ifa_neon_slice_sum_f32(ptr %src, i64 %len) alwaysinline {\n");
            out.push_str("entry:\n  %vec_len = and i64 %len, -4\n  br label %vec_loop\n");
            out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <4 x float> [ zeroinitializer, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
            out.push_str("vec_step:\n  %p = getelementptr inbounds float, ptr %src, i64 %i\n  %v = load <4 x float>, ptr %p, align 4\n  %next_acc = fadd <4 x float> %acc, %v\n  %next_i = add i64 %i, 4\n  br label %vec_loop, !llvm.loop !6\n");
            out.push_str("reduce:\n  %vec_sum = call float @llvm.vector.reduce.fadd.v4f32(float 0.0, <4 x float> %acc)\n  br label %tail_loop\n");
            out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi float [ %vec_sum, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
            out.push_str("tail_step:\n  %tp = getelementptr inbounds float, ptr %src, i64 %ti\n  %tv = load float, ptr %tp, align 4\n  %next_s_acc = fadd float %s_acc, %tv\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
            out.push_str("done:\n  ret float %s_acc\n}\n\n");

            out.push_str("define linkonce_odr float @ifa_neon_slice_min_f32(ptr %src, i64 %len) alwaysinline {\n");
            out.push_str("entry:\n  %vec_len = and i64 %len, -4\n  br label %vec_loop\n");
            out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <4 x float> [ <float 0x7FF0000000000000, float 0x7FF0000000000000, float 0x7FF0000000000000, float 0x7FF0000000000000>, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
            out.push_str("vec_step:\n  %p = getelementptr inbounds float, ptr %src, i64 %i\n  %v = load <4 x float>, ptr %p, align 4\n  %cmp = fcmp olt <4 x float> %v, %acc\n  %next_acc = select <4 x i1> %cmp, <4 x float> %v, <4 x float> %acc\n  %next_i = add i64 %i, 4\n  br label %vec_loop, !llvm.loop !6\n");
            out.push_str("reduce:\n  %vec_min = call float @llvm.aarch64.neon.fminnmv.f32.v4f32(<4 x float> %acc)\n  br label %tail_loop\n");
            out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi float [ %vec_min, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
            out.push_str("tail_step:\n  %tp = getelementptr inbounds float, ptr %src, i64 %ti\n  %tv = load float, ptr %tp, align 4\n  %tcmp = fcmp olt float %tv, %s_acc\n  %next_s_acc = select i1 %tcmp, float %tv, float %s_acc\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
            out.push_str("done:\n  ret float %s_acc\n}\n\n");

            out.push_str("define linkonce_odr float @ifa_neon_slice_max_f32(ptr %src, i64 %len) alwaysinline {\n");
            out.push_str("entry:\n  %vec_len = and i64 %len, -4\n  br label %vec_loop\n");
            out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <4 x float> [ <float 0xFFF0000000000000, float 0xFFF0000000000000, float 0xFFF0000000000000, float 0xFFF0000000000000>, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
            out.push_str("vec_step:\n  %p = getelementptr inbounds float, ptr %src, i64 %i\n  %v = load <4 x float>, ptr %p, align 4\n  %cmp = fcmp ogt <4 x float> %v, %acc\n  %next_acc = select <4 x i1> %cmp, <4 x float> %v, <4 x float> %acc\n  %next_i = add i64 %i, 4\n  br label %vec_loop, !llvm.loop !6\n");
            out.push_str("reduce:\n  %vec_max = call float @llvm.aarch64.neon.fmaxnmv.f32.v4f32(<4 x float> %acc)\n  br label %tail_loop\n");
            out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi float [ %vec_max, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
            out.push_str("tail_step:\n  %tp = getelementptr inbounds float, ptr %src, i64 %ti\n  %tv = load float, ptr %tp, align 4\n  %tcmp = fcmp ogt float %tv, %s_acc\n  %next_s_acc = select i1 %tcmp, float %tv, float %s_acc\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
            out.push_str("done:\n  ret float %s_acc\n}\n\n");

            out.push_str("define linkonce_odr i32 @ifa_neon_slice_min_i32(ptr %src, i64 %len) alwaysinline {\n");
            out.push_str("entry:\n  %vec_len = and i64 %len, -4\n  br label %vec_loop\n");
            out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <4 x i32> [ <i32 2147483647, i32 2147483647, i32 2147483647, i32 2147483647>, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
            out.push_str("vec_step:\n  %p = getelementptr inbounds i32, ptr %src, i64 %i\n  %v = load <4 x i32>, ptr %p, align 4\n  %cmp = icmp slt <4 x i32> %v, %acc\n  %next_acc = select <4 x i1> %cmp, <4 x i32> %v, <4 x i32> %acc\n  %next_i = add i64 %i, 4\n  br label %vec_loop, !llvm.loop !6\n");
            out.push_str("reduce:\n  %vec_min = call i32 @llvm.aarch64.neon.sminv.i32.v4i32(<4 x i32> %acc)\n  br label %tail_loop\n");
            out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi i32 [ %vec_min, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
            out.push_str("tail_step:\n  %tp = getelementptr inbounds i32, ptr %src, i64 %ti\n  %tv = load i32, ptr %tp, align 4\n  %tcmp = icmp slt i32 %tv, %s_acc\n  %next_s_acc = select i1 %tcmp, i32 %tv, i32 %s_acc\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
            out.push_str("done:\n  ret i32 %s_acc\n}\n\n");

            out.push_str("define linkonce_odr i32 @ifa_neon_slice_max_i32(ptr %src, i64 %len) alwaysinline {\n");
            out.push_str("entry:\n  %vec_len = and i64 %len, -4\n  br label %vec_loop\n");
            out.push_str("vec_loop:\n  %i = phi i64 [ 0, %entry ], [ %next_i, %vec_step ]\n  %acc = phi <4 x i32> [ <i32 -2147483648, i32 -2147483648, i32 -2147483648, i32 -2147483648>, %entry ], [ %next_acc, %vec_step ]\n  %has_vec = icmp ult i64 %i, %vec_len\n  br i1 %has_vec, label %vec_step, label %reduce\n");
            out.push_str("vec_step:\n  %p = getelementptr inbounds i32, ptr %src, i64 %i\n  %v = load <4 x i32>, ptr %p, align 4\n  %cmp = icmp sgt <4 x i32> %v, %acc\n  %next_acc = select <4 x i1> %cmp, <4 x i32> %v, <4 x i32> %acc\n  %next_i = add i64 %i, 4\n  br label %vec_loop, !llvm.loop !6\n");
            out.push_str("reduce:\n  %vec_max = call i32 @llvm.aarch64.neon.smaxv.i32.v4i32(<4 x i32> %acc)\n  br label %tail_loop\n");
            out.push_str("tail_loop:\n  %ti = phi i64 [ %vec_len, %reduce ], [ %next_ti, %tail_step ]\n  %s_acc = phi i32 [ %vec_max, %reduce ], [ %next_s_acc, %tail_step ]\n  %has_tail = icmp ult i64 %ti, %len\n  br i1 %has_tail, label %tail_step, label %done\n");
            out.push_str("tail_step:\n  %tp = getelementptr inbounds i32, ptr %src, i64 %ti\n  %tv = load i32, ptr %tp, align 4\n  %tcmp = icmp sgt i32 %tv, %s_acc\n  %next_s_acc = select i1 %tcmp, i32 %tv, i32 %s_acc\n  %next_ti = add i64 %ti, 1\n  br label %tail_loop\n");
            out.push_str("done:\n  ret i32 %s_acc\n}\n\n");
        }

        // Fast-path 1-cycle CPU inlined generation check (alwaysinline with branch weights)
        // Validates: generation_counter == remembered_gen, FLAG_ACTIVE is set, and FLAG_QUARANTINED is not set.
        out.push_str(
            "; Inlined 1-cycle CPU generation check with quarantine & liveness validation\n",
        );
        out.push_str("define linkonce_odr void @ifa_rt_gen_check(ptr %ptr, i32 %remembered_gen) alwaysinline {\n");
        out.push_str("entry:\n");
        out.push_str("  %is_null = icmp eq ptr %ptr, null\n");
        out.push_str("  br i1 %is_null, label %ok, label %check\n\n");
        out.push_str("check:\n");
        out.push_str("  %hdr_ptr = getelementptr inbounds i8, ptr %ptr, i64 -8\n");
        out.push_str("  %actual_gen = load i32, ptr %hdr_ptr, align 4\n");
        out.push_str("  %flags_ptr = getelementptr inbounds i8, ptr %ptr, i64 -4\n");
        out.push_str("  %flags = load i16, ptr %flags_ptr, align 2\n");
        out.push_str("  %gen_match = icmp eq i32 %actual_gen, %remembered_gen\n");
        out.push_str("  %act_bit = and i16 %flags, 1\n");
        out.push_str("  %is_active = icmp eq i16 %act_bit, 1\n");
        out.push_str("  %quar_bit = and i16 %flags, 16\n");
        out.push_str("  %not_quar = icmp eq i16 %quar_bit, 0\n");
        out.push_str("  %state_ok = and i1 %is_active, %not_quar\n");
        out.push_str("  %match = and i1 %gen_match, %state_ok\n");
        out.push_str("  br i1 %match, label %ok, label %uaf, !prof !0\n\n");
        out.push_str("ok:\n");
        out.push_str("  ret void\n\n");
        out.push_str("uaf:\n");
        out.push_str(
            "  call void @ifa_rt_panic_uaf(ptr %ptr, i32 %remembered_gen, i32 %actual_gen)\n",
        );
        out.push_str("  unreachable\n");
        out.push_str("}\n\n");

        // WASI entry point wrapper when a main function is defined
        if self.target.arch == TargetArch::Wasm32Wasi {
            let has_main = module
                .functions
                .iter()
                .find(|f| INTERNER.resolve(&f.name) == "main");
            if let Some(main_fn) = has_main {
                let is_unit = matches!(main_fn.ret_ty, ifa_fir::FirType::Unit);
                let call_str = if is_unit {
                    "  call i32 @main()\n".to_string()
                } else {
                    let ty = fir_to_llvm_type(&main_fn.ret_ty)?;
                    format!("  call {} @main()\n", ty)
                };
                out.push_str("; WASI entrypoint wrapper\n");
                out.push_str(&format!(
                    "define void @_start() {{\nentry:\n{}  ret void\n}}\n\n",
                    call_str
                ));
            }
        }

        // 3.5. Emit structure type definitions
        let mut declared_structs = BTreeSet::new();
        if !module.structs.is_empty() {
            out.push_str("; Structure Type Definitions\n");
            for st in &module.structs {
                let st_name = INTERNER.resolve(&st.name);
                declared_structs.insert(st_name.to_string());
                let mut field_types = Vec::new();
                for (_, f_ty) in &st.fields {
                    field_types.push(fir_to_llvm_type(f_ty)?);
                }
                out.push_str(&format!(
                    "%struct.{} = type {{ {} }}\n",
                    st_name,
                    field_types.join(", ")
                ));
            }
            out.push('\n');
        }

        // Also emit synthesized structure definitions (e.g. closures, environment records, generic instances) in deterministic order
        fn collect_struct_names(ty: &ifa_fir::FirType, out: &mut BTreeMap<String, usize>) {
            match ty {
                ifa_fir::FirType::Struct(name, fields) => {
                    let s_name = INTERNER.resolve(name);
                    let count = if s_name.starts_with("List__") || s_name == "List" {
                        3
                    } else {
                        fields.len().max(1)
                    };
                    out.entry(s_name.clone()).or_insert(count);
                    if let Some(elem_name) = s_name.strip_prefix("List__") {
                        collect_struct_names(&fir_type_from_elem_name(elem_name), out);
                    }
                    for (_, f_ty) in fields {
                        collect_struct_names(f_ty, out);
                    }
                }
                ifa_fir::FirType::Pointer(inner)
                | ifa_fir::FirType::Optional(inner)
                | ifa_fir::FirType::GenerationalRef(inner)
                | ifa_fir::FirType::Array(inner, _)
                | ifa_fir::FirType::Slice(inner) => {
                    collect_struct_names(inner, out);
                }
                ifa_fir::FirType::Range { elem, .. } => {
                    collect_struct_names(elem, out);
                }
                _ => {}
            }
        }

        let mut synthesized_structs: BTreeMap<String, usize> = BTreeMap::new();
        for st in &module.structs {
            for (_, f_ty) in &st.fields {
                collect_struct_names(f_ty, &mut synthesized_structs);
            }
        }
        for func in &module.functions {
            for p in &func.params {
                collect_struct_names(&p.ty, &mut synthesized_structs);
            }
            collect_struct_names(&func.ret_ty, &mut synthesized_structs);
            for block in &func.blocks {
                for (_, p_ty) in &block.params {
                    collect_struct_names(p_ty, &mut synthesized_structs);
                }
                for inst in &block.instructions {
                    match &inst.expr {
                        ValueExpr::Alloca { ty, .. } => {
                            collect_struct_names(ty, &mut synthesized_structs);
                        }
                        ValueExpr::StructInit { name, fields } => {
                            let s_name = INTERNER.resolve(name);
                            let count = if s_name.starts_with("List__") || s_name == "List" {
                                3
                            } else {
                                fields.len().max(1)
                            };
                            synthesized_structs.entry(s_name).or_insert(count);
                        }
                        _ => {}
                    }
                }
            }
        }

        // Remove explicitly declared structs
        for st_name in &declared_structs {
            synthesized_structs.remove(st_name);
        }

        if !synthesized_structs.is_empty() {
            out.push_str("; Synthesized Closure & Environment Structure Definitions\n");
            for (st_name, field_count) in synthesized_structs {
                if st_name.starts_with("List__") || st_name == "List" {
                    out.push_str(&format!("%struct.{} = type {{ ptr, i64, i64 }}\n", st_name));
                } else {
                    let field_types = vec!["i64"; field_count.max(1)];
                    out.push_str(&format!(
                        "%struct.{} = type {{ {} }}\n",
                        st_name,
                        field_types.join(", ")
                    ));
                }
            }
            out.push('\n');
        }

        // 3.5. Emit enumeration / tagged union type definitions
        if !module.enums.is_empty() {
            out.push_str("; Enumeration / Tagged Union Type Definitions\n");
            for en in &module.enums {
                let en_name = INTERNER.resolve(&en.name);
                out.push_str(&format!("%enum.{} = type {{ i64, i64 }}\n", en_name));
            }
            out.push('\n');
        }

        // 3.6. Emit AOT Monomorphic Trait VTables
        let mut type_to_methods: HashMap<String, Vec<String>> = HashMap::new();
        for func in &module.functions {
            let fn_name = INTERNER.resolve(&func.name);
            if let Some((type_prefix, method_name)) = fn_name.rsplit_once("__") {
                if !type_prefix.is_empty() && !method_name.is_empty() {
                    type_to_methods
                        .entry(type_prefix.to_string())
                        .or_default()
                        .push(fn_name);
                }
            }
        }
        if !type_to_methods.is_empty() {
            out.push_str("; AOT Monomorphic Trait VTables\n");
            let mut sorted_types: Vec<_> = type_to_methods.into_iter().collect();
            sorted_types.sort_by(|a, b| a.0.cmp(&b.0));
            for (type_name, mut methods) in sorted_types {
                methods.sort();
                let ptr_list: Vec<String> = methods.iter().map(|m| format!("ptr @{}", m)).collect();
                out.push_str(&format!(
                    "@__ifa_vtable_{} = internal constant [{} x ptr] [{}], align 8\n",
                    type_name,
                    ptr_list.len(),
                    ptr_list.join(", ")
                ));
            }
            out.push('\n');
        }

        // 3b. Scan and emit isolated blocking FFI pack structs and execution thunks
        let mut blocking_targets: std::collections::BTreeMap<
            ifa_span::Symbol,
            (String, Vec<String>),
        > = std::collections::BTreeMap::new();
        for func in &module.functions {
            for block in &func.blocks {
                for inst in &block.instructions {
                    if let ValueExpr::BlockingCallDirect { name, args } = &inst.expr {
                        if !blocking_targets.contains_key(name) {
                            let (ret_ty_str, param_types) = if let Some(target_fn) =
                                module.functions.iter().find(|f| f.name == *name)
                            {
                                let ret_ty = fir_to_llvm_type(&target_fn.ret_ty)
                                    .unwrap_or_else(|_| "i64".to_string());
                                let params: Vec<String> = target_fn
                                    .params
                                    .iter()
                                    .map(|p| match &p.ty {
                                        ifa_fir::FirType::Array(..) => "ptr".to_string(),
                                        _ => fir_to_llvm_type(&p.ty)
                                            .unwrap_or_else(|_| "i64".to_string()),
                                    })
                                    .collect();
                                (ret_ty, params)
                            } else {
                                ("i64".to_string(), vec!["i64".to_string(); args.len()])
                            };
                            blocking_targets.insert(*name, (ret_ty_str, param_types));
                        }
                    }
                }
            }
        }

        if !blocking_targets.is_empty() {
            out.push_str("; Isolated Blocking FFI Pack Structs & Execution Thunks\n");
            for (sym, (ret_ty_str, param_types)) in &blocking_targets {
                let callee = INTERNER.resolve(sym);
                // Declare target if external
                if !module
                    .functions
                    .iter()
                    .any(|f| f.name == *sym && !f.blocks.is_empty())
                {
                    out.push_str(&format!(
                        "declare {} @{}({})\n",
                        ret_ty_str,
                        callee,
                        param_types.join(", ")
                    ));
                }

                // Pack struct
                let mut pack_fields = param_types.clone();
                if ret_ty_str != "void" {
                    pack_fields.push(ret_ty_str.clone());
                } else {
                    pack_fields.push("i8".to_string());
                }
                out.push_str(&format!(
                    "%struct.ifa_pack_{} = type {{ {} }}\n",
                    callee,
                    pack_fields.join(", ")
                ));

                // Execution thunk
                out.push_str(&format!(
                    "define internal ptr @ifa_thunk_blocking_{}(ptr %ctx) {{\nentry:\n",
                    callee
                ));
                for (idx, p_ty) in param_types.iter().enumerate() {
                    out.push_str(&format!(
                        "  %arg_slot_{} = getelementptr inbounds %struct.ifa_pack_{}, ptr %ctx, i32 0, i32 {}\n",
                        idx, callee, idx
                    ));
                    out.push_str(&format!(
                        "  %arg_{} = load {}, ptr %arg_slot_{}, align 8\n",
                        idx, p_ty, idx
                    ));
                }
                let call_args: Vec<String> = param_types
                    .iter()
                    .enumerate()
                    .map(|(idx, p_ty)| format!("{} %arg_{}", p_ty, idx))
                    .collect();
                if ret_ty_str == "void" {
                    out.push_str(&format!(
                        "  call void @{}({})\n",
                        callee,
                        call_args.join(", ")
                    ));
                } else {
                    out.push_str(&format!(
                        "  %res = call {} @{}({})\n",
                        ret_ty_str,
                        callee,
                        call_args.join(", ")
                    ));
                    out.push_str(&format!(
                        "  %res_slot = getelementptr inbounds %struct.ifa_pack_{}, ptr %ctx, i32 0, i32 {}\n",
                        callee,
                        param_types.len()
                    ));
                    out.push_str(&format!(
                        "  store {} %res, ptr %res_slot, align 8\n",
                        ret_ty_str
                    ));
                }
                out.push_str("  ret ptr %ctx\n}\n\n");
            }
        }

        // 3c. Emit declarations for external functions (with no blocks)
        for func in &module.functions {
            if func.blocks.is_empty() && !blocking_targets.contains_key(&func.name) {
                let fn_name = INTERNER.resolve(&func.name);
                let ret_ty_str = fir_to_llvm_type(&func.ret_ty)?;
                let param_types: Vec<String> = func
                    .params
                    .iter()
                    .map(|p| {
                        if p.mode == ifa_fir::ParamMode::InOut {
                            "ptr".to_string()
                        } else {
                            match &p.ty {
                                ifa_fir::FirType::Array(..) => "ptr".to_string(),
                                _ => fir_to_llvm_type(&p.ty).unwrap_or_else(|_| "i64".to_string()),
                            }
                        }
                    })
                    .collect();
                let strict_attr = if func.is_strict {
                    let has_pointers = func.params.iter().any(|p| {
                        matches!(
                            p.ty,
                            ifa_fir::FirType::Pointer(..) | ifa_fir::FirType::Array(..)
                        )
                    });
                    if has_pointers {
                        " #3"
                    } else {
                        " #0"
                    }
                } else {
                    ""
                };
                out.push_str(&format!(
                    "declare {} @{}({}){}\n",
                    ret_ty_str,
                    fn_name,
                    param_types.join(", "),
                    strict_attr
                ));
            }
        }

        // 4. Emit function definitions
        for func in &module.functions {
            if func.blocks.is_empty() {
                continue;
            }
            self.emit_function(func, module, &mut out)?;
            out.push('\n');
        }

        // 5. Function attribute groups for SIMD vectorization and LTO inlining
        out.push_str("; Function Attributes\n");
        out.push_str(&format!(
            "attributes #0 = {{ mustprogress nofree nosync nounwind willreturn memory(argmem: readwrite) \"target-cpu\"=\"{}\" \"target-features\"=\"{}\" \"no-trapping-math\"=\"true\" }}\n",
            self.target.cpu, self.target.features
        ));
        out.push_str(&format!(
            "attributes #1 = {{ \"target-cpu\"=\"{}\" \"target-features\"=\"{}\" \"no-trapping-math\"=\"true\" }}\n",
            self.target.cpu, self.target.features
        ));
        out.push_str(&format!(
            "attributes #3 = {{ mustprogress nofree nosync nounwind willreturn memory(read) \"target-cpu\"=\"{}\" \"target-features\"=\"{}\" \"no-trapping-math\"=\"true\" }}\n",
            self.target.cpu, self.target.features
        ));
        if self.target.arch == TargetArch::Wasm32Wasi {
            out.push_str(
                "attributes #2 = { \"wasm-import-module\"=\"wasi_snapshot_preview1\" \"wasm-import-name\"=\"fd_write\" }\n",
            );
        }

        // 6. Metadata for branch weights and loop vectorization hints
        out.push_str("\n!0 = !{!\"branch_weights\", i32 1048576, i32 1}\n");
        // 8-lane SIMD vectorization hint (f32, i32)
        out.push_str("!1 = distinct !{!1, !2, !3, !4, !5}\n");
        out.push_str("!2 = !{!\"llvm.loop.vectorize.enable\", i1 1}\n");
        out.push_str("!3 = !{!\"llvm.loop.vectorize.width\", i32 8}\n");
        out.push_str("!4 = !{!\"llvm.loop.interleave.count\", i32 4}\n");
        out.push_str("!5 = !{!\"llvm.loop.unroll.enable\", i1 1}\n");
        // 4-lane SIMD vectorization hint (f64, i64)
        out.push_str("!6 = distinct !{!6, !2, !7, !4, !5}\n");
        out.push_str("!7 = !{!\"llvm.loop.vectorize.width\", i32 4}\n");
        // 16-lane SIMD vectorization hint (u8, i8 bytes, crypto)
        out.push_str("!8 = distinct !{!8, !2, !9, !4, !5}\n");
        out.push_str("!9 = !{!\"llvm.loop.vectorize.width\", i32 16}\n");
        // 2-lane SIMD vectorization hint (AArch64 Neon f64, i64)
        out.push_str("!10 = distinct !{!10, !2, !11, !4, !5}\n");
        out.push_str("!11 = !{!\"llvm.loop.vectorize.width\", i32 2}\n");
        // Predicated tail-folding and strict loop vectorization hints
        out.push_str("!12 = !{!\"llvm.loop.vectorize.predicate.enable\", i1 1}\n");
        out.push_str("!13 = !{!\"llvm.loop.mustprogress\"}\n");
        // 8-lane strict/predicated SIMD vectorization hint (f32, i32 strict slices)
        out.push_str("!14 = distinct !{!14, !2, !3, !4, !5, !12, !13}\n");
        // 4-lane strict/predicated SIMD vectorization hint (f64, i64 strict slices)
        out.push_str("!15 = distinct !{!15, !2, !7, !4, !5, !12, !13}\n");
        // 16-lane strict/predicated SIMD vectorization hint (u8, i8 strict slices)
        out.push_str("!16 = distinct !{!16, !2, !9, !4, !5, !12, !13}\n");
        // 2-lane strict/predicated SIMD vectorization hint (Neon strict slices)
        out.push_str("!17 = distinct !{!17, !2, !11, !4, !5, !12, !13}\n");
        // Contiguous local arena reduction hints (interleave 8, zero-heap strict mode)
        out.push_str("!18 = distinct !{!18, !2, !3, !22, !5, !12, !13}\n");
        out.push_str("!19 = distinct !{!19, !2, !7, !22, !5, !12, !13}\n");
        out.push_str("!20 = distinct !{!20, !2, !9, !22, !5, !12, !13}\n");
        out.push_str("!21 = distinct !{!21, !2, !11, !22, !5, !12, !13}\n");
        out.push_str("!22 = !{!\"llvm.loop.interleave.count\", i32 8}\n");
        // Specialized multidimensional disjoint slice vectorization hints with parallel access groups
        out.push_str("!23 = distinct !{!23, !2, !3, !4, !5, !12, !13, !24}\n");
        out.push_str("!24 = !{!\"llvm.loop.parallel_accesses\", !25}\n");
        out.push_str("!25 = distinct !{}\n");
        out.push_str("!26 = distinct !{!26, !2, !7, !4, !5, !12, !13, !24}\n");
        out.push_str("!27 = distinct !{!27, !2, !9, !4, !5, !12, !13, !24}\n");
        out.push_str("!28 = distinct !{!28, !2, !11, !4, !5, !12, !13, !24}\n");
        // Specialized bare-metal convolution and sliding window vectorization hints (unrolled window, parallel accesses)
        out.push_str("!29 = distinct !{!29, !2, !3, !4, !5, !12, !13, !24}\n");
        out.push_str("!30 = distinct !{!30, !2, !7, !4, !5, !12, !13, !24}\n");
        out.push_str("!31 = distinct !{!31, !2, !9, !4, !5, !12, !13, !24}\n");
        out.push_str("!32 = distinct !{!32, !2, !11, !4, !5, !12, !13, !24}\n");
        // Specialized matrix and tensor kernel hints with LLVM unroll-and-jam, parallel accesses, and tiling
        out.push_str("!33 = distinct !{!33, !2, !3, !4, !5, !12, !13, !24, !37, !38}\n");
        out.push_str("!34 = distinct !{!34, !2, !7, !4, !5, !12, !13, !24, !37, !38}\n");
        out.push_str("!35 = distinct !{!35, !2, !9, !4, !5, !12, !13, !24, !37, !39}\n");
        out.push_str("!36 = distinct !{!36, !2, !11, !4, !5, !12, !13, !24, !37, !38}\n");
        out.push_str("!37 = !{!\"llvm.loop.unroll_and_jam.enable\"}\n");
        out.push_str("!38 = !{!\"llvm.loop.unroll_and_jam.count\", i32 4}\n");
        out.push_str("!39 = !{!\"llvm.loop.unroll_and_jam.count\", i32 8}\n");
        // Specialized in-place zero-copy swap vectorization hints on provably disjoint slices
        out.push_str("!40 = distinct !{!40, !2, !3, !4, !5, !12, !13, !24, !44}\n");
        out.push_str("!41 = distinct !{!41, !2, !7, !4, !5, !12, !13, !24, !44}\n");
        out.push_str("!42 = distinct !{!42, !2, !9, !4, !5, !12, !13, !24, !44}\n");
        out.push_str("!43 = distinct !{!43, !2, !11, !4, !5, !12, !13, !24, !44}\n");
        out.push_str("!44 = !{!\"llvm.loop.unroll.count\", i32 4}\n");
        // Specialized bipartite disjoint window matrix reduction vectorization hints (unroll-and-jam, parallel accesses, noalias)
        out.push_str("!45 = distinct !{!45, !2, !3, !4, !5, !12, !13, !24, !37, !38}\n");
        out.push_str("!46 = distinct !{!46, !2, !7, !4, !5, !12, !13, !24, !37, !38}\n");
        out.push_str("!47 = distinct !{!47, !2, !9, !4, !5, !12, !13, !24, !37, !39}\n");
        out.push_str("!48 = distinct !{!48, !2, !11, !4, !5, !12, !13, !24, !37, !38}\n");
        // Specialized tripartite disjoint window matrix reduction vectorization hints (unroll-and-jam 8x, parallel accesses, noalias)
        out.push_str("!49 = distinct !{!49, !2, !3, !4, !5, !12, !13, !24, !37, !39}\n");
        out.push_str("!50 = distinct !{!50, !2, !7, !4, !5, !12, !13, !24, !37, !39}\n");
        out.push_str("!51 = distinct !{!51, !2, !9, !4, !5, !12, !13, !24, !37, !39}\n");
        out.push_str("!52 = distinct !{!52, !2, !11, !4, !5, !12, !13, !24, !37, !39}\n");
        // Specialized 3D zero-copy strided convolution vectorization hints (unroll-and-jam 8x, parallel accesses, noalias, vector width)
        out.push_str("!53 = distinct !{!53, !2, !3, !4, !5, !12, !13, !24, !37, !39}\n");
        out.push_str("!54 = distinct !{!54, !2, !7, !4, !5, !12, !13, !24, !37, !39}\n");
        out.push_str("!55 = distinct !{!55, !2, !9, !4, !5, !12, !13, !24, !37, !39}\n");
        out.push_str("!56 = distinct !{!56, !2, !11, !4, !5, !12, !13, !24, !37, !39}\n");
        // Specialized 2D zero-copy strided convolution vectorization hints (unroll-and-jam 4x/8x, parallel accesses, noalias, vector width)
        out.push_str("!57 = distinct !{!57, !2, !3, !4, !5, !12, !13, !24, !37, !38}\n");
        out.push_str("!58 = distinct !{!58, !2, !7, !4, !5, !12, !13, !24, !37, !38}\n");
        out.push_str("!59 = distinct !{!59, !2, !9, !4, !5, !12, !13, !24, !37, !39}\n");
        out.push_str("!60 = distinct !{!60, !2, !11, !4, !5, !12, !13, !24, !37, !38}\n");
        // Specialized 1D general strided loop vectorization hints (interleave 4/8, parallel accesses, noalias, vector width)
        out.push_str("!61 = distinct !{!61, !2, !3, !4, !5, !12, !13, !24}\n");
        out.push_str("!62 = distinct !{!62, !2, !7, !4, !5, !12, !13, !24}\n");
        out.push_str("!63 = distinct !{!63, !2, !9, !4, !5, !12, !13, !24}\n");
        out.push_str("!64 = distinct !{!64, !2, !11, !4, !5, !12, !13, !24}\n");
        // Specialized multidimensional strided projection vectorization hints (unroll-and-jam 4x/8x, parallel accesses, noalias, vector width)
        out.push_str("!65 = distinct !{!65, !2, !3, !4, !5, !12, !13, !24, !37, !38}\n");
        out.push_str("!66 = distinct !{!66, !2, !7, !4, !5, !12, !13, !24, !37, !38}\n");
        out.push_str("!67 = distinct !{!67, !2, !9, !4, !5, !12, !13, !24, !37, !39}\n");
        out.push_str("!68 = distinct !{!68, !2, !11, !4, !5, !12, !13, !24, !37, !38}\n");
        // Specialized multi-arena matrix/tensor and elementwise fused kernel hints (unroll-and-jam 8x, parallel accesses, noalias, vector width)
        out.push_str("!69 = distinct !{!69, !2, !3, !4, !5, !12, !13, !24, !37, !39}\n");
        out.push_str("!70 = distinct !{!70, !2, !7, !4, !5, !12, !13, !24, !37, !39}\n");
        out.push_str("!71 = distinct !{!71, !2, !9, !4, !5, !12, !13, !24, !37, !39}\n");
        out.push_str("!72 = distinct !{!72, !2, !11, !4, !5, !12, !13, !24, !37, !39}\n");
        // Specialized multi-arena 2D/3D fused convolution hints (unroll-and-jam 8x, parallel accesses, noalias, vector width)
        out.push_str("!73 = distinct !{!73, !2, !3, !4, !5, !12, !13, !24, !37, !39}\n");
        out.push_str("!74 = distinct !{!74, !2, !7, !4, !5, !12, !13, !24, !37, !39}\n");
        out.push_str("!75 = distinct !{!75, !2, !9, !4, !5, !12, !13, !24, !37, !39}\n");
        out.push_str("!76 = distinct !{!76, !2, !11, !4, !5, !12, !13, !24, !37, !39}\n");

        Ok(out)
    }

    fn emit_function(
        &self,
        func: &FirFunction,
        module: &FirModule,
        out: &mut String,
    ) -> Result<(), LlvmCodegenError> {
        let fn_name = INTERNER.resolve(&func.name);
        let raw_ret_ty = fir_to_llvm_type(&func.ret_ty)?;
        let is_coro = func.is_coroutine();
        let coro_attr = if is_coro { "presplitcoroutine " } else { "" };
        let is_main_unit = fn_name == "main" && raw_ret_ty == "void";
        let ret_ty = if is_coro {
            "ptr"
        } else if is_main_unit {
            "i32"
        } else {
            &raw_ret_ty
        };

        let linkage = if func.is_pub {
            "dso_local "
        } else if fn_name.contains("__") {
            "linkonce_odr "
        } else {
            "internal "
        };

        let attr_group = if func.is_strict { "#0" } else { "#1" };

        let params_str: Vec<String> = func
            .params
            .iter()
            .map(|p| {
                let ty = if p.mode == ifa_fir::ParamMode::InOut {
                    "ptr".to_string()
                } else {
                    match &p.ty {
                        ifa_fir::FirType::Array(..) => "ptr".to_string(),
                        _ => fir_to_llvm_type(&p.ty).unwrap_or_else(|_| "ptr".to_string()),
                    }
                };
                if (func.is_strict
                    || p.noalias
                    || fn_name.contains("__")
                    || p.mode == ifa_fir::ParamMode::InOut)
                    && ty == "ptr"
                    && fn_name != "main"
                    && !fn_name.starts_with("ifa_rt_")
                {
                    format!("ptr noalias %v{}", p.val.0)
                } else {
                    format!("{} %v{}", ty, p.val.0)
                }
            })
            .collect();

        out.push_str(&format!(
            "define {}{} @{}({}) {}{} {{\n",
            linkage,
            ret_ty,
            fn_name,
            params_str.join(", "),
            coro_attr,
            attr_group
        ));

        // Precompute SSA value types within this function
        let mut value_types: HashMap<ifa_fir::ValueId, ifa_fir::FirType> = HashMap::new();
        let mut null_values: std::collections::HashSet<ifa_fir::ValueId> =
            std::collections::HashSet::new();
        for p in &func.params {
            if p.mode == ifa_fir::ParamMode::InOut {
                value_types.insert(p.val, ifa_fir::FirType::Pointer(Box::new(p.ty.clone())));
            } else {
                value_types.insert(p.val, p.ty.clone());
            }
        }
        for block in &func.blocks {
            for (p_id, p_ty) in &block.params {
                value_types.insert(*p_id, p_ty.clone());
            }
            for inst in &block.instructions {
                if let Some(res) = inst.result {
                    if let ValueExpr::Constant(ConstantValue::Null) = &inst.expr {
                        null_values.insert(res);
                    }
                    let ty = match &inst.expr {
                        ValueExpr::Constant(ConstantValue::Float(_, f_ty)) => {
                            ifa_fir::FirType::Float(*f_ty)
                        }
                        ValueExpr::Constant(ConstantValue::Int(_, i_ty)) => {
                            ifa_fir::FirType::Int(*i_ty)
                        }
                        ValueExpr::Constant(ConstantValue::Bool(_)) => ifa_fir::FirType::Bool,
                        ValueExpr::Constant(ConstantValue::Char(_)) => ifa_fir::FirType::Char,
                        ValueExpr::Constant(ConstantValue::String(_)) => ifa_fir::FirType::Str,
                        ValueExpr::FormatString(_) => ifa_fir::FirType::String,
                        ValueExpr::Constant(ConstantValue::Function(_)) => {
                            ifa_fir::FirType::Pointer(Box::new(ifa_fir::FirType::Unit))
                        }
                        ValueExpr::Constant(ConstantValue::Null) => {
                            ifa_fir::FirType::Int(ifa_sema::types::IntType::I64)
                        }
                        ValueExpr::Binary { op, lhs, .. } => match op {
                            BinaryOp::Eq
                            | BinaryOp::Ne
                            | BinaryOp::Lt
                            | BinaryOp::Le
                            | BinaryOp::Gt
                            | BinaryOp::Ge
                            | BinaryOp::And
                            | BinaryOp::Or => ifa_fir::FirType::Bool,
                            _ => value_types
                                .get(lhs)
                                .cloned()
                                .unwrap_or(ifa_fir::FirType::Int(ifa_sema::types::IntType::I64)),
                        },
                        ValueExpr::Unary { op, val } => match op {
                            UnaryOp::Not => ifa_fir::FirType::Bool,
                            UnaryOp::Neg => value_types
                                .get(val)
                                .cloned()
                                .unwrap_or(ifa_fir::FirType::Int(ifa_sema::types::IntType::I64)),
                        },
                        ValueExpr::Alloca { ty, .. } => {
                            ifa_fir::FirType::Pointer(Box::new(ty.clone()))
                        }
                        ValueExpr::Load { ptr } => match value_types.get(ptr) {
                            Some(ifa_fir::FirType::Pointer(inner)) => (**inner).clone(),
                            _ => ifa_fir::FirType::Int(ifa_sema::types::IntType::I64),
                        },
                        ValueExpr::GetElement { base, .. } => match value_types.get(base) {
                            Some(ifa_fir::FirType::Array(inner, _))
                            | Some(ifa_fir::FirType::Slice(inner)) => (**inner).clone(),
                            Some(ifa_fir::FirType::Pointer(inner)) => match &**inner {
                                ifa_fir::FirType::Array(elem, _)
                                | ifa_fir::FirType::Slice(elem) => (**elem).clone(),
                                ifa_fir::FirType::Struct(s_sym, _) => {
                                    let s_name = INTERNER.resolve(s_sym);
                                    if let Some(elem_name) = s_name.strip_prefix("List__") {
                                        fir_type_from_elem_name(elem_name)
                                    } else {
                                        ifa_fir::FirType::Int(ifa_sema::types::IntType::I64)
                                    }
                                }
                                _ => ifa_fir::FirType::Int(ifa_sema::types::IntType::I64),
                            },
                            Some(ifa_fir::FirType::Struct(s_sym, _)) => {
                                let s_name = INTERNER.resolve(s_sym);
                                if let Some(elem_name) = s_name.strip_prefix("List__") {
                                    fir_type_from_elem_name(elem_name)
                                } else {
                                    ifa_fir::FirType::Int(ifa_sema::types::IntType::I64)
                                }
                            }
                            _ => ifa_fir::FirType::Int(ifa_sema::types::IntType::I64),
                        },
                        ValueExpr::SliceSub { base, .. } | ValueExpr::SliceStrided { base, .. } => {
                            match value_types.get(base) {
                                Some(ifa_fir::FirType::Array(inner, _))
                                | Some(ifa_fir::FirType::Slice(inner)) => {
                                    ifa_fir::FirType::Slice(inner.clone())
                                }
                                Some(ifa_fir::FirType::Pointer(inner)) => match &**inner {
                                    ifa_fir::FirType::Array(elem, _)
                                    | ifa_fir::FirType::Slice(elem) => {
                                        ifa_fir::FirType::Slice(elem.clone())
                                    }
                                    _ => ifa_fir::FirType::Slice(Box::new(ifa_fir::FirType::Int(
                                        ifa_sema::types::IntType::I64,
                                    ))),
                                },
                                _ => ifa_fir::FirType::Slice(Box::new(ifa_fir::FirType::Int(
                                    ifa_sema::types::IntType::I64,
                                ))),
                            }
                        }
                        ValueExpr::ArrayInit(elements) => {
                            let elem_ty = elements
                                .first()
                                .and_then(|e| value_types.get(e))
                                .cloned()
                                .unwrap_or(ifa_fir::FirType::Int(ifa_sema::types::IntType::I64));
                            ifa_fir::FirType::Pointer(Box::new(ifa_fir::FirType::Array(
                                Box::new(elem_ty),
                                elements.len() as u32,
                            )))
                        }
                        ValueExpr::CallDirect { name, .. }
                        | ValueExpr::BlockingCallDirect { name, .. } => {
                            let callee = INTERNER.resolve(name);
                            if callee.starts_with("ifa_simd_")
                                || callee.starts_with("ifa_simd_arena_")
                            {
                                let is_f32 = callee.ends_with("_f32");
                                let is_f64 = callee.ends_with("_f64");
                                let is_i32 = callee.ends_with("_i32");
                                let _is_i64 = callee.ends_with("_i64");

                                if callee.contains("dot") {
                                    if is_f64 {
                                        ifa_fir::FirType::Float(ifa_sema::types::FloatType::F64)
                                    } else {
                                        ifa_fir::FirType::Float(ifa_sema::types::FloatType::F32)
                                    }
                                } else if callee.contains("sum")
                                    || callee.contains("prod")
                                    || callee.contains("min")
                                    || callee.contains("max")
                                {
                                    if is_f32 {
                                        ifa_fir::FirType::Float(ifa_sema::types::FloatType::F32)
                                    } else if is_f64 {
                                        ifa_fir::FirType::Float(ifa_sema::types::FloatType::F64)
                                    } else if is_i32 {
                                        ifa_fir::FirType::Int(ifa_sema::types::IntType::I32)
                                    } else {
                                        ifa_fir::FirType::Int(ifa_sema::types::IntType::I64)
                                    }
                                } else if callee.contains("slice_add")
                                    || callee.contains("slice_mul")
                                    || callee.contains("slice_xor")
                                    || callee.contains("select")
                                    || callee.contains("clamp")
                                {
                                    ifa_fir::FirType::Unit
                                } else {
                                    ifa_fir::FirType::Int(ifa_sema::types::IntType::I64)
                                }
                            } else if callee == "process::exec_output"
                                || callee == "exec_output"
                                || callee == "ifa_rt_process_exec_output"
                                || callee == "process::exec_stderr"
                                || callee == "exec_stderr"
                                || callee == "ifa_rt_process_exec_stderr"
                                || callee == "process::find_linker"
                                || callee == "find_linker"
                                || callee == "ifa_rt_process_find_linker"
                                || callee == "process::find_tool"
                                || callee == "find_tool"
                                || callee == "ifa_rt_process_find_tool"
                                || callee == "process::args_get"
                                || callee == "env::args_get"
                                || callee == "args_get"
                                || callee == "ifa_rt_args_get"
                                || callee == "process::env_var"
                                || callee == "env_var"
                                || callee == "ifa_rt_env_var"
                                || callee == "fs::read_to_string"
                                || callee == "read_to_string"
                                || callee == "ifa_rt_fs_read_to_string"
                            {
                                ifa_fir::FirType::String
                            } else if callee == "fs::exists"
                                || callee == "exists"
                                || callee == "ifa_rt_fs_exists"
                                || callee == "fs::write_string"
                                || callee == "write_string"
                                || callee == "ifa_rt_fs_write_string"
                            {
                                ifa_fir::FirType::Bool
                            } else if callee == "process::args_count"
                                || callee == "env::args_count"
                                || callee == "args_count"
                                || callee == "ifa_rt_args_count"
                                || callee == "process::exec"
                                || callee == "exec"
                                || callee == "ifa_rt_process_exec"
                                || callee == "process::exec_with_stdin"
                                || callee == "exec_with_stdin"
                                || callee == "ifa_rt_process_exec_with_stdin"
                                || callee == "fs::file_size"
                                || callee == "file_size"
                                || callee == "ifa_rt_fs_file_size"
                            {
                                ifa_fir::FirType::Int(ifa_sema::types::IntType::I64)
                            } else if let Some(target_fn) = module.functions.iter().find(|f| {
                                f.name == *name
                                    || f.name == INTERNER.intern(&callee)
                                    || callee.ends_with(&format!("::{}", INTERNER.resolve(&f.name)))
                                    || callee.ends_with(&format!("__{}", INTERNER.resolve(&f.name)))
                            }) {
                                target_fn.ret_ty.clone()
                            } else {
                                ifa_fir::FirType::Int(ifa_sema::types::IntType::I64)
                            }
                        }
                        ValueExpr::Spawn { .. } => {
                            ifa_fir::FirType::Int(ifa_sema::types::IntType::I64)
                        }
                        ValueExpr::StructInit { name, .. } => {
                            let st_def = module.structs.iter().find(|s| s.name == *name);
                            let fields = st_def.map(|s| s.fields.clone()).unwrap_or_default();
                            ifa_fir::FirType::Struct(*name, fields)
                        }
                        ValueExpr::EnumInit { enum_name, .. } => {
                            let en_def = module.enums.iter().find(|e| e.name == *enum_name);
                            let variants = en_def.map(|e| e.variants.clone()).unwrap_or_default();
                            ifa_fir::FirType::Enum(*enum_name, variants)
                        }
                        ValueExpr::EnumGetDiscriminant { .. } => {
                            ifa_fir::FirType::Int(ifa_sema::types::IntType::I64)
                        }
                        ValueExpr::EnumGetPayload { payload_ty, .. } => payload_ty.clone(),
                        ValueExpr::GenRef { ptr } => match value_types.get(ptr) {
                            Some(inner) => {
                                ifa_fir::FirType::GenerationalRef(Box::new(inner.clone()))
                            }
                            None => ifa_fir::FirType::Pointer(Box::new(ifa_fir::FirType::Int(
                                ifa_sema::types::IntType::I64,
                            ))),
                        },
                        ValueExpr::GenDeref { ref_val } => match value_types.get(ref_val) {
                            Some(ifa_fir::FirType::GenerationalRef(inner)) => {
                                ifa_fir::FirType::Pointer(Box::new((**inner).clone()))
                            }
                            Some(ifa_fir::FirType::Optional(opt_inner)) => match &**opt_inner {
                                ifa_fir::FirType::GenerationalRef(inner) => {
                                    ifa_fir::FirType::Pointer(Box::new((**inner).clone()))
                                }
                                other => ifa_fir::FirType::Pointer(Box::new(other.clone())),
                            },
                            _ => ifa_fir::FirType::Pointer(Box::new(ifa_fir::FirType::Int(
                                ifa_sema::types::IntType::I64,
                            ))),
                        },
                        ValueExpr::CallArenaAlloc { ty } => {
                            ifa_fir::FirType::Pointer(Box::new(ty.clone()))
                        }
                        ValueExpr::CallArenaMark => {
                            ifa_fir::FirType::Int(ifa_sema::types::IntType::I64)
                        }
                        ValueExpr::CallArenaRewind { .. } => ifa_fir::FirType::Unit,
                        ValueExpr::GenAlloc { ty, .. } => {
                            ifa_fir::FirType::Pointer(Box::new(ty.clone()))
                        }
                        ValueExpr::GetField {
                            base, field_idx, ..
                        } => match value_types.get(base) {
                            Some(ifa_fir::FirType::Struct(s_name, fields)) => {
                                if let Some(st_def) =
                                    module.structs.iter().find(|s| s.name == *s_name)
                                {
                                    if *field_idx < st_def.fields.len() {
                                        st_def.fields[*field_idx].1.clone()
                                    } else {
                                        ifa_fir::FirType::Int(ifa_sema::types::IntType::I64)
                                    }
                                } else if *field_idx < fields.len() {
                                    fields[*field_idx].1.clone()
                                } else {
                                    ifa_fir::FirType::Int(ifa_sema::types::IntType::I64)
                                }
                            }
                            Some(ifa_fir::FirType::Pointer(inner)) => match &**inner {
                                ifa_fir::FirType::Struct(s_name, fields) => {
                                    if let Some(st_def) =
                                        module.structs.iter().find(|s| s.name == *s_name)
                                    {
                                        if *field_idx < st_def.fields.len() {
                                            st_def.fields[*field_idx].1.clone()
                                        } else {
                                            ifa_fir::FirType::Int(ifa_sema::types::IntType::I64)
                                        }
                                    } else if *field_idx < fields.len() {
                                        fields[*field_idx].1.clone()
                                    } else {
                                        ifa_fir::FirType::Int(ifa_sema::types::IntType::I64)
                                    }
                                }
                                _ => ifa_fir::FirType::Int(ifa_sema::types::IntType::I64),
                            },
                            _ => ifa_fir::FirType::Int(ifa_sema::types::IntType::I64),
                        },
                        ValueExpr::GetFieldPtr {
                            base, field_idx, ..
                        } => match value_types.get(base) {
                            Some(ifa_fir::FirType::Pointer(inner)) => match &**inner {
                                ifa_fir::FirType::Struct(s_name, fields) => {
                                    if let Some(st_def) =
                                        module.structs.iter().find(|s| s.name == *s_name)
                                    {
                                        if *field_idx < st_def.fields.len() {
                                            ifa_fir::FirType::Pointer(Box::new(
                                                st_def.fields[*field_idx].1.clone(),
                                            ))
                                        } else {
                                            ifa_fir::FirType::Pointer(Box::new(
                                                ifa_fir::FirType::Int(
                                                    ifa_sema::types::IntType::I64,
                                                ),
                                            ))
                                        }
                                    } else if *field_idx < fields.len() {
                                        ifa_fir::FirType::Pointer(Box::new(
                                            fields[*field_idx].1.clone(),
                                        ))
                                    } else {
                                        ifa_fir::FirType::Pointer(Box::new(ifa_fir::FirType::Int(
                                            ifa_sema::types::IntType::I64,
                                        )))
                                    }
                                }
                                _ => ifa_fir::FirType::Pointer(Box::new(ifa_fir::FirType::Int(
                                    ifa_sema::types::IntType::I64,
                                ))),
                            },
                            Some(ifa_fir::FirType::Struct(s_name, fields)) => {
                                if let Some(st_def) =
                                    module.structs.iter().find(|s| s.name == *s_name)
                                {
                                    if *field_idx < st_def.fields.len() {
                                        ifa_fir::FirType::Pointer(Box::new(
                                            st_def.fields[*field_idx].1.clone(),
                                        ))
                                    } else {
                                        ifa_fir::FirType::Pointer(Box::new(ifa_fir::FirType::Int(
                                            ifa_sema::types::IntType::I64,
                                        )))
                                    }
                                } else if *field_idx < fields.len() {
                                    ifa_fir::FirType::Pointer(Box::new(
                                        fields[*field_idx].1.clone(),
                                    ))
                                } else {
                                    ifa_fir::FirType::Pointer(Box::new(ifa_fir::FirType::Int(
                                        ifa_sema::types::IntType::I64,
                                    )))
                                }
                            }
                            _ => ifa_fir::FirType::Pointer(Box::new(ifa_fir::FirType::Int(
                                ifa_sema::types::IntType::I64,
                            ))),
                        },
                        ValueExpr::GetElementPtr { base, .. } => match value_types.get(base) {
                            Some(ifa_fir::FirType::Array(inner, _))
                            | Some(ifa_fir::FirType::Slice(inner)) => {
                                ifa_fir::FirType::Pointer(inner.clone())
                            }
                            Some(ifa_fir::FirType::Pointer(inner)) => match &**inner {
                                ifa_fir::FirType::Array(elem, _)
                                | ifa_fir::FirType::Slice(elem) => {
                                    ifa_fir::FirType::Pointer(elem.clone())
                                }
                                _ => ifa_fir::FirType::Pointer(Box::new(ifa_fir::FirType::Int(
                                    ifa_sema::types::IntType::I64,
                                ))),
                            },
                            _ => ifa_fir::FirType::Pointer(Box::new(ifa_fir::FirType::Int(
                                ifa_sema::types::IntType::I64,
                            ))),
                        },
                        _ => ifa_fir::FirType::Int(ifa_sema::types::IntType::I64),
                    };
                    value_types.insert(res, ty);
                }
            }
        }

        // Map loaded array variables back to their memory alloca pointers for passing to calls/slices
        let mut array_allocas: HashMap<ifa_fir::ValueId, ifa_fir::ValueId> = HashMap::new();
        let mut array_ptrs: HashMap<ifa_fir::ValueId, String> = HashMap::new();
        for p in &func.params {
            if matches!(p.ty, ifa_fir::FirType::Array(..)) || p.mode == ifa_fir::ParamMode::InOut {
                array_ptrs.insert(p.val, format!("%v{}", p.val.0));
            }
        }
        for block in &func.blocks {
            for inst in &block.instructions {
                if let (Some(res), ValueExpr::Load { ptr }) = (inst.result, &inst.expr) {
                    if let Some(ifa_fir::FirType::Pointer(inner)) = value_types.get(ptr) {
                        if matches!(&**inner, ifa_fir::FirType::Array(..)) {
                            array_allocas.insert(res, *ptr);
                            array_ptrs.insert(res, format!("%v{}", ptr.0));
                        }
                    }
                } else if let (Some(res), ValueExpr::GetElement { .. }) = (inst.result, &inst.expr)
                {
                    if let Some(ty) = value_types.get(&res) {
                        if matches!(ty, ifa_fir::FirType::Array(..)) {
                            array_ptrs.insert(res, format!("%gep_{}", res.0));
                        }
                    }
                } else if let (Some(res), ValueExpr::GetElementPtr { .. }) =
                    (inst.result, &inst.expr)
                {
                    array_ptrs.insert(res, format!("%v{}", res.0));
                }
            }
        }

        // Precompute predecessors and incoming block arguments for phi nodes
        let mut predecessors: HashMap<BlockId, Vec<(BlockId, Vec<ifa_fir::ValueId>)>> =
            HashMap::new();
        for b in &func.blocks {
            if let Some(ref term) = b.terminator {
                match term {
                    Terminator::Branch { target, args } => {
                        predecessors
                            .entry(*target)
                            .or_default()
                            .push((b.id, args.clone()));
                    }
                    Terminator::BranchCond {
                        then_block,
                        then_args,
                        else_block,
                        else_args,
                        ..
                    } => {
                        predecessors
                            .entry(*then_block)
                            .or_default()
                            .push((b.id, then_args.clone()));
                        predecessors
                            .entry(*else_block)
                            .or_default()
                            .push((b.id, else_args.clone()));
                    }
                    Terminator::Switch {
                        cases,
                        default_block,
                        default_args,
                        ..
                    } => {
                        for (_, c_block, c_args) in cases {
                            predecessors
                                .entry(*c_block)
                                .or_default()
                                .push((b.id, c_args.clone()));
                        }
                        predecessors
                            .entry(*default_block)
                            .or_default()
                            .push((b.id, default_args.clone()));
                    }
                    _ => {}
                }
            }
        }

        // Collect constant integers for stride calculations
        let mut const_ints: HashMap<ifa_fir::ValueId, i64> = HashMap::new();
        for block in &func.blocks {
            for inst in &block.instructions {
                if let (Some(res), ValueExpr::Constant(ConstantValue::Int(v, _))) =
                    (inst.result, &inst.expr)
                {
                    const_ints.insert(res, *v as i64);
                }
            }
        }

        // Map strided slice result -> (stride_value_id, Option<constant_stride>)
        let mut strided_slice_info: HashMap<ifa_fir::ValueId, (ifa_fir::ValueId, Option<i64>)> =
            HashMap::new();
        for block in &func.blocks {
            for inst in &block.instructions {
                if let (Some(res), ValueExpr::SliceStrided { base, stride, .. }) =
                    (inst.result, &inst.expr)
                {
                    let direct_const = const_ints.get(stride).copied();
                    let parent_st = strided_slice_info
                        .get(base)
                        .and_then(|(_, c)| *c)
                        .unwrap_or(1);
                    let comb_const = direct_const.map(|c| c * parent_st);
                    strided_slice_info.insert(res, (*stride, comb_const));
                }
            }
        }

        // Basic blocks
        let mut coro_yield_idx: usize = 0;
        let mut eff_idx: usize = 0;
        for (b_idx, block) in func.blocks.iter().enumerate() {
            let label = if b_idx == 0 {
                "entry".to_string()
            } else {
                format!("bb{}", block.id.0)
            };
            out.push_str(&format!("{}:\n", label));

            if is_coro && b_idx == 0 {
                let is_slice_coro = matches!(func.ret_ty, ifa_fir::FirType::Slice(_))
                    || func.blocks.iter().any(|b| {
                        b.instructions.iter().any(|inst| {
                            matches!(
                                inst.expr,
                                ValueExpr::YieldValue { val }
                                    if matches!(
                                        value_types.get(&val),
                                        Some(ifa_fir::FirType::Slice(_))
                                    )
                            )
                        })
                    });
                if is_slice_coro {
                    out.push_str("  %coro.yield_slot = alloca { ptr, i64 }, align 8\n");
                } else {
                    out.push_str("  %coro.yield_slot = alloca i64, align 8\n");
                }
                out.push_str(
                    "  %coro.id = call token @llvm.coro.id(i32 8, ptr %coro.yield_slot, ptr null, ptr null)\n",
                );
                if self.target.arch == TargetArch::Wasm32Wasi {
                    out.push_str("  %coro.size.32 = call i32 @llvm.coro.size.i32()\n");
                    out.push_str("  %coro.size = zext i32 %coro.size.32 to i64\n");
                } else {
                    out.push_str("  %coro.size = call i64 @llvm.coro.size.i64()\n");
                }
                if func.is_strict {
                    out.push_str(
                        "  %coro.alloc = call ptr @ifa_rt_call_arena_alloc(i64 %coro.size, i64 8)\n",
                    );
                } else {
                    out.push_str(
                        "  %coro.alloc = call ptr @ifa_rt_gen_alloc(i64 %coro.size, i64 8, i16 0)\n",
                    );
                }
                out.push_str(
                    "  %coro.hdl = call ptr @llvm.coro.begin(token %coro.id, ptr %coro.alloc)\n",
                );
                if is_slice_coro {
                    out.push_str(
                        "  store { ptr, i64 } zeroinitializer, ptr %coro.yield_slot, align 8\n",
                    );
                } else {
                    out.push_str("  store i64 0, ptr %coro.yield_slot, align 8\n");
                }
            }

            // Emit PHI nodes for block arguments
            if b_idx > 0 && !block.params.is_empty() {
                if let Some(preds) = predecessors.get(&block.id) {
                    for (p_idx, (param_val, param_ty)) in block.params.iter().enumerate() {
                        let ty_str = fir_to_llvm_type(param_ty)?;
                        if ty_str != "void" {
                            let mut incoming_pairs = Vec::new();
                            let mut seen_preds = HashSet::new();
                            for (pred_id, pred_args) in preds {
                                if seen_preds.insert(*pred_id) && p_idx < pred_args.len() {
                                    let incoming_val = pred_args[p_idx];
                                    let pred_label = if *pred_id == func.entry_block {
                                        "entry".to_string()
                                    } else {
                                        format!("bb{}", pred_id.0)
                                    };
                                    incoming_pairs
                                        .push(format!("[ %v{}, %{} ]", incoming_val.0, pred_label));
                                }
                            }
                            if !incoming_pairs.is_empty() {
                                out.push_str(&format!(
                                    "  %v{} = phi {} {}\n",
                                    param_val.0,
                                    ty_str,
                                    incoming_pairs.join(", ")
                                ));
                            }
                        }
                    }
                }
            }

            // SSA Instructions
            for inst in &block.instructions {
                if let Some(res) = inst.result {
                    self.emit_instruction(
                        res.0,
                        &inst.expr,
                        module,
                        &value_types,
                        &null_values,
                        &array_allocas,
                        &array_ptrs,
                        &strided_slice_info,
                        is_coro,
                        &mut coro_yield_idx,
                        out,
                    )?;
                } else {
                    self.emit_effectful_instruction(
                        &inst.expr,
                        module,
                        &value_types,
                        &null_values,
                        &array_allocas,
                        &array_ptrs,
                        &strided_slice_info,
                        is_coro,
                        &mut coro_yield_idx,
                        &mut eff_idx,
                        out,
                    )?;
                }
            }

            // Terminator
            if let Some(ref term) = block.terminator {
                self.emit_terminator(
                    term,
                    &func.ret_ty,
                    &value_types,
                    is_main_unit,
                    is_coro,
                    block.vector_hint.as_ref(),
                    out,
                )?;
            } else {
                out.push_str("  unreachable\n");
            }
        }

        if is_coro {
            out.push_str("coro.final_suspend:\n");
            out.push_str("  %coro.final_tok = call i8 @llvm.coro.suspend(token none, i1 true)\n");
            out.push_str("  switch i8 %coro.final_tok, label %coro.susp_ret [ i8 0, label %coro.cleanup i8 1, label %coro.cleanup ]\n");
            out.push_str("coro.cleanup:\n");
            out.push_str("  %coro.mem = call ptr @llvm.coro.free(token %coro.id, ptr %coro.hdl)\n");
            out.push_str("  call void @ifa_rt_gen_free(ptr %coro.mem)\n");
            out.push_str("  br label %coro.susp_ret\n");
            out.push_str("coro.susp_ret:\n");
            out.push_str("  call i1 @llvm.coro.end(ptr %coro.hdl, i1 false, token none)\n");
            out.push_str("  ret ptr %coro.hdl\n");
        }

        out.push_str("}\n");
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_call_args(
        prefix_id: &str,
        args: &[ifa_fir::ValueId],
        param_types: &[String],
        value_types: &HashMap<ifa_fir::ValueId, ifa_fir::FirType>,
        null_values: &std::collections::HashSet<ifa_fir::ValueId>,
        array_allocas: &HashMap<ifa_fir::ValueId, ifa_fir::ValueId>,
        out: &mut String,
    ) -> Vec<String> {
        let mut args_str: Vec<String> = Vec::with_capacity(args.len());
        for (i, a) in args.iter().enumerate() {
            let p_ty = param_types.get(i).map(|s| s.as_str()).unwrap_or("i64");
            let arg_fir_ty = value_types.get(a);
            if p_ty == "{ ptr, i64 }" {
                match arg_fir_ty {
                    Some(ifa_fir::FirType::Slice(_)) => {
                        args_str.push(format!("{{ ptr, i64 }} %v{}", a.0));
                    }
                    Some(ifa_fir::FirType::Pointer(inner))
                        if matches!(&**inner, ifa_fir::FirType::Slice(_)) =>
                    {
                        out.push_str(&format!(
                            "  %slice_arg_ld_{}_{} = load {{ ptr, i64 }}, ptr %v{}, align 8\n",
                            prefix_id, i, a.0
                        ));
                        args_str.push(format!("{{ ptr, i64 }} %slice_arg_ld_{}_{}", prefix_id, i));
                    }
                    Some(ifa_fir::FirType::Array(_, len)) => {
                        let arr_ptr = array_allocas
                            .get(a)
                            .map(|p| format!("%v{}", p.0))
                            .unwrap_or_else(|| format!("%v{}", a.0));
                        out.push_str(&format!(
                            "  %coerce_t0_{}_{} = insertvalue {{ ptr, i64 }} undef, ptr {}, 0\n",
                            prefix_id, i, arr_ptr
                        ));
                        out.push_str(&format!(
                            "  %coerce_sl_{}_{} = insertvalue {{ ptr, i64 }} %coerce_t0_{}_{}, i64 {}, 1\n",
                            prefix_id, i, prefix_id, i, len
                        ));
                        args_str.push(format!("{{ ptr, i64 }} %coerce_sl_{}_{}", prefix_id, i));
                    }
                    Some(ifa_fir::FirType::Pointer(inner)) => match &**inner {
                        ifa_fir::FirType::Array(_, len) => {
                            out.push_str(&format!(
                                "  %coerce_t0_{}_{} = insertvalue {{ ptr, i64 }} undef, ptr %v{}, 0\n",
                                prefix_id, i, a.0
                            ));
                            out.push_str(&format!(
                                "  %coerce_sl_{}_{} = insertvalue {{ ptr, i64 }} %coerce_t0_{}_{}, i64 {}, 1\n",
                                prefix_id, i, prefix_id, i, len
                            ));
                            args_str.push(format!("{{ ptr, i64 }} %coerce_sl_{}_{}", prefix_id, i));
                        }
                        _ => {
                            args_str.push(format!("{} %v{}", p_ty, a.0));
                        }
                    },
                    _ => {
                        args_str.push(format!("{} %v{}", p_ty, a.0));
                    }
                }
            } else if p_ty == "ptr" {
                if null_values.contains(a) {
                    args_str.push("ptr null".to_string());
                } else if let Some(p) = array_allocas.get(a) {
                    args_str.push(format!("ptr %v{}", p.0));
                } else {
                    args_str.push(format!("ptr %v{}", a.0));
                }
            } else if p_ty.starts_with("{ i1,") {
                if matches!(arg_fir_ty, Some(ifa_fir::FirType::Optional(_))) {
                    args_str.push(format!("{} %v{}", p_ty, a.0));
                } else if null_values.contains(a) {
                    out.push_str(&format!(
                        "  %opt_none_{}_{} = insertvalue {} undef, i1 0, 0\n",
                        prefix_id, i, p_ty
                    ));
                    args_str.push(format!("{} %opt_none_{}_{}", p_ty, prefix_id, i));
                } else {
                    let inner_ty = p_ty
                        .strip_prefix("{ i1, ")
                        .and_then(|s| s.strip_suffix(" }"))
                        .unwrap_or("i64");
                    out.push_str(&format!(
                        "  %opt_wrap_t0_{}_{} = insertvalue {} undef, i1 1, 0\n",
                        prefix_id, i, p_ty
                    ));
                    out.push_str(&format!(
                        "  %opt_wrap_{}_{} = insertvalue {} %opt_wrap_t0_{}_{}, {} %v{}, 1\n",
                        prefix_id, i, p_ty, prefix_id, i, inner_ty, a.0
                    ));
                    args_str.push(format!("{} %opt_wrap_{}_{}", p_ty, prefix_id, i));
                }
            } else if p_ty.starts_with("%struct.") {
                match arg_fir_ty {
                    Some(ifa_fir::FirType::Struct(..)) => {
                        args_str.push(format!("{} %v{}", p_ty, a.0));
                    }
                    Some(ifa_fir::FirType::Pointer(inner))
                        if matches!(&**inner, ifa_fir::FirType::Struct(..)) =>
                    {
                        out.push_str(&format!(
                            "  %st_arg_ld_{}_{} = load {}, ptr %v{}, align 8\n",
                            prefix_id, i, p_ty, a.0
                        ));
                        args_str.push(format!("{} %st_arg_ld_{}_{}", p_ty, prefix_id, i));
                    }
                    Some(ifa_fir::FirType::Pointer(inner)) if p_ty.starts_with("%struct.List") => {
                        let (arr_ptr, arr_len) = match &**inner {
                            ifa_fir::FirType::Array(_, len) => {
                                let ptr_str = array_allocas
                                    .get(a)
                                    .map(|p| format!("%v{}", p.0))
                                    .unwrap_or_else(|| format!("%v{}", a.0));
                                (ptr_str, *len as usize)
                            }
                            _ => (format!("%v{}", a.0), 0),
                        };
                        out.push_str(&format!(
                            "  %list_wrap_t0_{}_{} = insertvalue {} undef, ptr {}, 0\n",
                            prefix_id, i, p_ty, arr_ptr
                        ));
                        out.push_str(&format!(
                            "  %list_wrap_t1_{}_{} = insertvalue {} %list_wrap_t0_{}_{}, i64 {}, 1\n",
                            prefix_id, i, p_ty, prefix_id, i, arr_len
                        ));
                        out.push_str(&format!(
                            "  %list_wrap_{}_{} = insertvalue {} %list_wrap_t1_{}_{}, i64 {}, 2\n",
                            prefix_id, i, p_ty, prefix_id, i, arr_len
                        ));
                        args_str.push(format!("{} %list_wrap_{}_{}", p_ty, prefix_id, i));
                    }
                    Some(ifa_fir::FirType::Array(_, len)) if p_ty.starts_with("%struct.List") => {
                        let ptr_str = array_allocas
                            .get(a)
                            .map(|p| format!("%v{}", p.0))
                            .unwrap_or_else(|| format!("%v{}", a.0));
                        out.push_str(&format!(
                            "  %list_wrap_t0_{}_{} = insertvalue {} undef, ptr {}, 0\n",
                            prefix_id, i, p_ty, ptr_str
                        ));
                        out.push_str(&format!(
                            "  %list_wrap_t1_{}_{} = insertvalue {} %list_wrap_t0_{}_{}, i64 {}, 1\n",
                            prefix_id, i, p_ty, prefix_id, i, len
                        ));
                        out.push_str(&format!(
                            "  %list_wrap_{}_{} = insertvalue {} %list_wrap_t1_{}_{}, i64 {}, 2\n",
                            prefix_id, i, p_ty, prefix_id, i, len
                        ));
                        args_str.push(format!("{} %list_wrap_{}_{}", p_ty, prefix_id, i));
                    }
                    _ => {
                        out.push_str(&format!(
                            "  %st_arg_ld_{}_{} = load {}, ptr %v{}, align 8\n",
                            prefix_id, i, p_ty, a.0
                        ));
                        args_str.push(format!("{} %st_arg_ld_{}_{}", p_ty, prefix_id, i));
                    }
                }
            } else {
                args_str.push(format!("{} %v{}", p_ty, a.0));
            }
        }
        args_str
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_instruction(
        &self,
        res_id: u32,
        expr: &ValueExpr,
        module: &FirModule,
        value_types: &HashMap<ifa_fir::ValueId, ifa_fir::FirType>,
        null_values: &std::collections::HashSet<ifa_fir::ValueId>,
        array_allocas: &HashMap<ifa_fir::ValueId, ifa_fir::ValueId>,
        array_ptrs: &HashMap<ifa_fir::ValueId, String>,
        strided_slice_info: &HashMap<ifa_fir::ValueId, (ifa_fir::ValueId, Option<i64>)>,
        is_coro: bool,
        coro_yield_idx: &mut usize,
        out: &mut String,
    ) -> Result<(), LlvmCodegenError> {
        match expr {
            ValueExpr::Constant(c) => match c {
                ConstantValue::Unit => {
                    // Unit produces void, no SSA value assignment needed
                }
                ConstantValue::Bool(b) => {
                    out.push_str(&format!(
                        "  %v{} = or i1 {}, 0\n",
                        res_id,
                        if *b { 1 } else { 0 }
                    ));
                }
                ConstantValue::Int(val, i_ty) => {
                    let ty_str = match i_ty {
                        ifa_sema::types::IntType::I8 | ifa_sema::types::IntType::U8 => "i8",
                        ifa_sema::types::IntType::I16 | ifa_sema::types::IntType::U16 => "i16",
                        ifa_sema::types::IntType::I32 | ifa_sema::types::IntType::U32 => "i32",
                        _ => "i64",
                    };
                    out.push_str(&format!("  %v{} = add {} {}, 0\n", res_id, ty_str, val));
                }
                ConstantValue::Float(val, f_ty) => {
                    let ty_str = match f_ty {
                        ifa_sema::types::FloatType::F32 => "float",
                        ifa_sema::types::FloatType::F64 => "double",
                    };
                    let formatted_val = format_llvm_float(*val);
                    out.push_str(&format!(
                        "  %v{} = fadd {} {}, 0.0\n",
                        res_id, ty_str, formatted_val
                    ));
                }
                ConstantValue::Char(c) => {
                    out.push_str(&format!("  %v{} = add i8 {}, 0\n", res_id, *c as u8));
                }
                ConstantValue::String(sym) => {
                    let text = INTERNER.resolve(sym);
                    let global_id = self.string_literals.get(&text).unwrap();
                    out.push_str(&format!(
                        "  %v{} = getelementptr inbounds [{} x i8], ptr {}, i64 0, i64 0\n",
                        res_id,
                        text.len() + 1,
                        global_id
                    ));
                }
                ConstantValue::Function(sym) => {
                    let fn_name = INTERNER.resolve(sym);
                    out.push_str(&format!(
                        "  %v{} = getelementptr i8, ptr @{}, i64 0\n",
                        res_id, fn_name
                    ));
                }
                ConstantValue::Null => {
                    out.push_str(&format!("  %v{} = add i64 0, 0\n", res_id));
                }
            },
            ValueExpr::Binary { op, lhs, rhs } => {
                let float_ty = match value_types.get(lhs) {
                    Some(ifa_fir::FirType::Float(f)) => Some(match f {
                        ifa_sema::types::FloatType::F32 => "float",
                        ifa_sema::types::FloatType::F64 => "double",
                    }),
                    _ => None,
                };
                if let Some(ty_str) = float_ty {
                    let op_str = match op {
                        BinaryOp::Add => "fadd",
                        BinaryOp::Sub => "fsub",
                        BinaryOp::Mul => "fmul",
                        BinaryOp::Div => "fdiv",
                        BinaryOp::Eq => "fcmp oeq",
                        BinaryOp::Ne => "fcmp one",
                        BinaryOp::Lt => "fcmp olt",
                        BinaryOp::Le => "fcmp ole",
                        BinaryOp::Gt => "fcmp ogt",
                        BinaryOp::Ge => "fcmp oge",
                        _ => "fadd",
                    };
                    out.push_str(&format!(
                        "  %v{} = {} {} %v{}, %v{}\n",
                        res_id, op_str, ty_str, lhs.0, rhs.0
                    ));
                } else if matches!(
                    value_types.get(lhs),
                    Some(ifa_fir::FirType::String)
                        | Some(ifa_fir::FirType::Str)
                        | Some(ifa_fir::FirType::Optional(_))
                ) && matches!(
                    value_types.get(rhs),
                    Some(ifa_fir::FirType::String)
                        | Some(ifa_fir::FirType::Str)
                        | Some(ifa_fir::FirType::Optional(_))
                ) && (matches!(
                    value_types.get(lhs),
                    Some(ifa_fir::FirType::String) | Some(ifa_fir::FirType::Str)
                ) || matches!(
                    value_types.get(rhs),
                    Some(ifa_fir::FirType::String) | Some(ifa_fir::FirType::Str)
                )) {
                    let (lhs_ptr, lhs_cond) = match value_types.get(lhs) {
                        Some(ifa_fir::FirType::Optional(inner))
                            if matches!(
                                &**inner,
                                ifa_fir::FirType::String | ifa_fir::FirType::Str
                            ) =>
                        {
                            out.push_str(&format!(
                                "  %opt_has_{}_lhs = extractvalue {{ i1, ptr }} %v{}, 0\n",
                                res_id, lhs.0
                            ));
                            out.push_str(&format!(
                                "  %opt_val_{}_lhs = extractvalue {{ i1, ptr }} %v{}, 1\n",
                                res_id, lhs.0
                            ));
                            (
                                format!("%opt_val_{}_lhs", res_id),
                                Some(format!("%opt_has_{}_lhs", res_id)),
                            )
                        }
                        _ => (format!("%v{}", lhs.0), None),
                    };
                    let (rhs_ptr, rhs_cond) = match value_types.get(rhs) {
                        Some(ifa_fir::FirType::Optional(inner))
                            if matches!(
                                &**inner,
                                ifa_fir::FirType::String | ifa_fir::FirType::Str
                            ) =>
                        {
                            out.push_str(&format!(
                                "  %opt_has_{}_rhs = extractvalue {{ i1, ptr }} %v{}, 0\n",
                                res_id, rhs.0
                            ));
                            out.push_str(&format!(
                                "  %opt_val_{}_rhs = extractvalue {{ i1, ptr }} %v{}, 1\n",
                                res_id, rhs.0
                            ));
                            (
                                format!("%opt_val_{}_rhs", res_id),
                                Some(format!("%opt_has_{}_rhs", res_id)),
                            )
                        }
                        _ => (format!("%v{}", rhs.0), None),
                    };

                    out.push_str(&format!(
                        "  %raw_eq_{} = call i1 @ifa_rt_string_eq(ptr {}, ptr {})\n",
                        res_id, lhs_ptr, rhs_ptr
                    ));

                    let eq_val = match (lhs_cond, rhs_cond) {
                        (Some(c1), Some(c2)) => {
                            out.push_str(&format!("  %c1_none_{} = xor i1 {}, true\n", res_id, c1));
                            out.push_str(&format!("  %c2_none_{} = xor i1 {}, true\n", res_id, c2));
                            out.push_str(&format!(
                                "  %both_none_{} = and i1 %c1_none_{}, %c2_none_{}\n",
                                res_id, res_id, res_id
                            ));
                            out.push_str(&format!(
                                "  %both_some_{} = and i1 {}, {}\n",
                                res_id, c1, c2
                            ));
                            out.push_str(&format!(
                                "  %both_eq_{} = and i1 %both_some_{}, %raw_eq_{}\n",
                                res_id, res_id, res_id
                            ));
                            out.push_str(&format!(
                                "  %final_eq_{} = or i1 %both_none_{}, %both_eq_{}\n",
                                res_id, res_id, res_id
                            ));
                            format!("%final_eq_{}", res_id)
                        }
                        (Some(c), None) | (None, Some(c)) => {
                            out.push_str(&format!(
                                "  %final_eq_{} = and i1 {}, %raw_eq_{}\n",
                                res_id, c, res_id
                            ));
                            format!("%final_eq_{}", res_id)
                        }
                        (None, None) => format!("%raw_eq_{}", res_id),
                    };

                    if *op == BinaryOp::Eq {
                        out.push_str(&format!("  %v{} = or i1 {}, 0\n", res_id, eq_val));
                    } else if *op == BinaryOp::Ne {
                        out.push_str(&format!("  %v{} = xor i1 {}, true\n", res_id, eq_val));
                    } else {
                        out.push_str(&format!("  %v{} = or i1 {}, 0\n", res_id, eq_val));
                    }
                } else if matches!(value_types.get(lhs), Some(ifa_fir::FirType::Optional(_)))
                    || matches!(value_types.get(rhs), Some(ifa_fir::FirType::Optional(_)))
                {
                    let (opt_val, opt_ty) =
                        if matches!(value_types.get(lhs), Some(ifa_fir::FirType::Optional(_))) {
                            (lhs, value_types.get(lhs).unwrap())
                        } else {
                            (rhs, value_types.get(rhs).unwrap())
                        };
                    let opt_llvm_ty = fir_to_llvm_type(opt_ty)?;
                    out.push_str(&format!(
                        "  %has_val_{} = extractvalue {} %v{}, 0\n",
                        res_id, opt_llvm_ty, opt_val.0
                    ));
                    if *op == BinaryOp::Eq {
                        out.push_str(&format!(
                            "  %v{} = xor i1 %has_val_{}, true\n",
                            res_id, res_id
                        ));
                    } else {
                        out.push_str(&format!(
                            "  %v{} = or i1 %has_val_{}, false\n",
                            res_id, res_id
                        ));
                    }
                } else if matches!(
                    value_types.get(lhs),
                    Some(ifa_fir::FirType::GenerationalRef(_))
                ) || matches!(
                    value_types.get(rhs),
                    Some(ifa_fir::FirType::GenerationalRef(_))
                ) {
                    let (gr_val, other_val) = if matches!(
                        value_types.get(lhs),
                        Some(ifa_fir::FirType::GenerationalRef(_))
                    ) {
                        (lhs, rhs)
                    } else {
                        (rhs, lhs)
                    };
                    out.push_str(&format!(
                        "  %gr_p_{} = extractvalue {{ ptr, i32, i16, i16 }} %v{}, 0\n",
                        res_id, gr_val.0
                    ));
                    let cmp_inst = if *op == BinaryOp::Eq {
                        "icmp eq"
                    } else {
                        "icmp ne"
                    };
                    if matches!(
                        value_types.get(other_val),
                        Some(ifa_fir::FirType::GenerationalRef(_))
                    ) {
                        out.push_str(&format!(
                            "  %gr_p2_{} = extractvalue {{ ptr, i32, i16, i16 }} %v{}, 0\n",
                            res_id, other_val.0
                        ));
                        out.push_str(&format!(
                            "  %v{} = {} ptr %gr_p_{}, %gr_p2_{}\n",
                            res_id, cmp_inst, res_id, res_id
                        ));
                    } else {
                        out.push_str(&format!(
                            "  %v{} = {} ptr %gr_p_{}, null\n",
                            res_id, cmp_inst, res_id
                        ));
                    }
                } else if matches!(value_types.get(lhs), Some(ifa_fir::FirType::Pointer(_)))
                    || matches!(value_types.get(rhs), Some(ifa_fir::FirType::Pointer(_)))
                {
                    let cmp_inst = if *op == BinaryOp::Eq {
                        "icmp eq"
                    } else {
                        "icmp ne"
                    };
                    if matches!(value_types.get(lhs), Some(ifa_fir::FirType::Pointer(_)))
                        && matches!(value_types.get(rhs), Some(ifa_fir::FirType::Pointer(_)))
                    {
                        out.push_str(&format!(
                            "  %v{} = {} ptr %v{}, %v{}\n",
                            res_id, cmp_inst, lhs.0, rhs.0
                        ));
                    } else {
                        let ptr_val =
                            if matches!(value_types.get(lhs), Some(ifa_fir::FirType::Pointer(_))) {
                                lhs.0
                            } else {
                                rhs.0
                            };
                        out.push_str(&format!(
                            "  %v{} = {} ptr %v{}, null\n",
                            res_id, cmp_inst, ptr_val
                        ));
                    }
                } else {
                    let int_ty_str = match value_types.get(lhs) {
                        Some(ifa_fir::FirType::Int(i)) => match i {
                            ifa_sema::types::IntType::I8 | ifa_sema::types::IntType::U8 => "i8",
                            ifa_sema::types::IntType::I16 | ifa_sema::types::IntType::U16 => "i16",
                            ifa_sema::types::IntType::I32 | ifa_sema::types::IntType::U32 => "i32",
                            _ => "i64",
                        },
                        Some(ifa_fir::FirType::Bool) => "i1",
                        Some(ifa_fir::FirType::Char) => "i8",
                        _ => "i64",
                    };
                    let op_str = match op {
                        BinaryOp::Add => format!("add nsw {}", int_ty_str),
                        BinaryOp::Sub => format!("sub nsw {}", int_ty_str),
                        BinaryOp::Mul => format!("mul nsw {}", int_ty_str),
                        BinaryOp::Div => format!("sdiv {}", int_ty_str),
                        BinaryOp::Rem => format!("srem {}", int_ty_str),
                        BinaryOp::Eq => format!("icmp eq {}", int_ty_str),
                        BinaryOp::Ne => format!("icmp ne {}", int_ty_str),
                        BinaryOp::Lt => format!("icmp slt {}", int_ty_str),
                        BinaryOp::Le => format!("icmp sle {}", int_ty_str),
                        BinaryOp::Gt => format!("icmp sgt {}", int_ty_str),
                        BinaryOp::Ge => format!("icmp sge {}", int_ty_str),
                        BinaryOp::And => "and i1".to_string(),
                        BinaryOp::Or => "or i1".to_string(),
                        BinaryOp::BitAnd => format!("and {}", int_ty_str),
                        BinaryOp::BitOr => format!("or {}", int_ty_str),
                        BinaryOp::BitXor => format!("xor {}", int_ty_str),
                        BinaryOp::Shl => format!("shl {}", int_ty_str),
                        BinaryOp::Shr => format!("ashr {}", int_ty_str),
                    };
                    out.push_str(&format!(
                        "  %v{} = {} %v{}, %v{}\n",
                        res_id, op_str, lhs.0, rhs.0
                    ));
                }
            }
            ValueExpr::Unary { op, val } => match op {
                UnaryOp::Neg => {
                    let float_ty = match value_types.get(val) {
                        Some(ifa_fir::FirType::Float(f)) => Some(match f {
                            ifa_sema::types::FloatType::F32 => "float",
                            ifa_sema::types::FloatType::F64 => "double",
                        }),
                        _ => None,
                    };
                    if let Some(ty_str) = float_ty {
                        out.push_str(&format!("  %v{} = fneg {} %v{}\n", res_id, ty_str, val.0));
                    } else {
                        let int_ty_str = match value_types.get(val) {
                            Some(ifa_fir::FirType::Int(i)) => match i {
                                ifa_sema::types::IntType::I8 | ifa_sema::types::IntType::U8 => "i8",
                                ifa_sema::types::IntType::I16 | ifa_sema::types::IntType::U16 => {
                                    "i16"
                                }
                                ifa_sema::types::IntType::I32 | ifa_sema::types::IntType::U32 => {
                                    "i32"
                                }
                                _ => "i64",
                            },
                            _ => "i64",
                        };
                        out.push_str(&format!(
                            "  %v{} = sub nsw {} 0, %v{}\n",
                            res_id, int_ty_str, val.0
                        ));
                    }
                }
                UnaryOp::Not => {
                    out.push_str(&format!("  %v{} = xor i1 %v{}, true\n", res_id, val.0));
                }
            },
            ValueExpr::Alloca { ty, .. } => {
                let llvm_ty = fir_to_llvm_type(ty)?;
                let align = llvm_align_for_type(ty);
                out.push_str(&format!(
                    "  %v{} = alloca {}, align {}\n",
                    res_id, llvm_ty, align
                ));
            }
            ValueExpr::Load { ptr } => {
                let (ty_str, align) = match value_types.get(ptr) {
                    Some(ifa_fir::FirType::Pointer(inner)) => (
                        fir_to_llvm_type(inner).unwrap_or_else(|_| "i64".to_string()),
                        llvm_align_for_type(inner),
                    ),
                    _ => ("i64".to_string(), 8),
                };
                out.push_str(&format!(
                    "  %v{} = load {}, ptr %v{}, align {}\n",
                    res_id, ty_str, ptr.0, align
                ));
            }
            ValueExpr::Store { ptr, val } => {
                let (ty_str, align) = match value_types.get(val) {
                    Some(ty) => (
                        fir_to_llvm_type(ty).unwrap_or_else(|_| "i64".to_string()),
                        llvm_align_for_type(ty),
                    ),
                    _ => match value_types.get(ptr) {
                        Some(ifa_fir::FirType::Pointer(inner)) => (
                            fir_to_llvm_type(inner).unwrap_or_else(|_| "i64".to_string()),
                            llvm_align_for_type(inner),
                        ),
                        _ => ("i64".to_string(), 8),
                    },
                };
                out.push_str(&format!(
                    "  store {} %v{}, ptr %v{}, align {}\n",
                    ty_str, val.0, ptr.0, align
                ));
            }
            ValueExpr::CallDirect { name, args } => {
                let callee = INTERNER.resolve(name);
                let norm_callee = match callee.as_str() {
                    "fs::read_to_string" | "read_to_string" => "ifa_rt_fs_read_to_string",
                    "fs::write_string" | "write_string" => "ifa_rt_fs_write_string",
                    "fs::exists" | "exists" => "ifa_rt_fs_exists",
                    "fs::file_size" | "file_size" => "ifa_rt_fs_file_size",
                    "process::exec" | "exec" => "ifa_rt_process_exec",
                    "process::exec_output" | "exec_output" => "ifa_rt_process_exec_output",
                    "process::exec_stderr" | "exec_stderr" => "ifa_rt_process_exec_stderr",
                    "process::exec_with_stdin" | "exec_with_stdin" => {
                        "ifa_rt_process_exec_with_stdin"
                    }
                    "process::find_linker" | "find_linker" => "ifa_rt_process_find_linker",
                    "process::find_tool" | "find_tool" => "ifa_rt_process_find_tool",
                    "process::env_var" | "env_var" => "ifa_rt_env_var",
                    "process::args_count" | "env::args_count" | "args_count" => "ifa_rt_args_count",
                    "process::args_get" | "env::args_get" | "args_get" => "ifa_rt_args_get",
                    "string_len" | "String::len" => "ifa_rt_string_len",
                    "string_char_at" | "String::char_at" => "ifa_rt_string_char_at",
                    _ => callee.as_str(),
                };
                let callee_name = norm_callee;
                if callee_name == "println" || callee_name == "ifa_rt_println" {
                    if let Some(arg) = args.first() {
                        out.push_str(&format!("  call void @ifa_rt_println(ptr %v{})\n", arg.0));
                    } else {
                        out.push_str("  call void @ifa_rt_println(ptr null)\n");
                    }
                    out.push_str(&format!("  %v{} = add i64 0, 0\n", res_id));
                } else if callee_name == "print" || callee_name == "ifa_rt_print" {
                    if let Some(arg) = args.first() {
                        out.push_str(&format!("  call void @ifa_rt_print(ptr %v{})\n", arg.0));
                    }
                    out.push_str(&format!("  %v{} = add i64 0, 0\n", res_id));
                } else if callee_name == "ifa_rt_println_i64" {
                    if let Some(arg) = args.first() {
                        out.push_str(&format!(
                            "  call void @ifa_rt_println_i64(i64 %v{})\n",
                            arg.0
                        ));
                    }
                    out.push_str(&format!("  %v{} = add i64 0, 0\n", res_id));
                } else {
                    let (ret_ty_str, param_types) = if let Some(target_fn) =
                        module.functions.iter().find(|f| {
                            f.name == *name
                                || f.name == INTERNER.intern(&callee)
                                || callee.ends_with(&format!("::{}", INTERNER.resolve(&f.name)))
                                || callee.ends_with(&format!("__{}", INTERNER.resolve(&f.name)))
                        }) {
                        let ret_ty = if target_fn.is_coroutine() {
                            "ptr".to_string()
                        } else {
                            fir_to_llvm_type(&target_fn.ret_ty)?
                        };
                        let params: Vec<String> = target_fn
                            .params
                            .iter()
                            .map(|p| {
                                if p.mode == ifa_fir::ParamMode::InOut {
                                    "ptr".to_string()
                                } else {
                                    match &p.ty {
                                        ifa_fir::FirType::Array(..) => "ptr".to_string(),
                                        _ => fir_to_llvm_type(&p.ty)
                                            .unwrap_or_else(|_| "i64".to_string()),
                                    }
                                }
                            })
                            .collect();
                        (ret_ty, params)
                    } else if norm_callee == "ifa_rt_fs_read_to_string" {
                        ("ptr".to_string(), vec!["ptr".to_string()])
                    } else if norm_callee == "ifa_rt_fs_write_string" {
                        ("i1".to_string(), vec!["ptr".to_string(), "ptr".to_string()])
                    } else if norm_callee == "ifa_rt_fs_exists" {
                        ("i1".to_string(), vec!["ptr".to_string()])
                    } else if norm_callee == "ifa_rt_fs_file_size" {
                        ("i64".to_string(), vec!["ptr".to_string()])
                    } else if norm_callee == "ifa_rt_process_exec" {
                        (
                            "i64".to_string(),
                            vec!["ptr".to_string(), "ptr".to_string()],
                        )
                    } else if norm_callee == "ifa_rt_process_exec_output"
                        || norm_callee == "ifa_rt_process_exec_stderr"
                    {
                        (
                            "ptr".to_string(),
                            vec!["ptr".to_string(), "ptr".to_string()],
                        )
                    } else if norm_callee == "ifa_rt_process_exec_with_stdin" {
                        (
                            "i64".to_string(),
                            vec!["ptr".to_string(), "ptr".to_string(), "ptr".to_string()],
                        )
                    } else if norm_callee == "ifa_rt_process_find_linker" {
                        ("ptr".to_string(), Vec::new())
                    } else if norm_callee == "ifa_rt_process_find_tool"
                        || norm_callee == "ifa_rt_env_var"
                    {
                        ("ptr".to_string(), vec!["ptr".to_string()])
                    } else if norm_callee == "ifa_rt_args_count" {
                        ("i64".to_string(), Vec::new())
                    } else if norm_callee == "ifa_rt_args_get" {
                        ("ptr".to_string(), vec!["i64".to_string()])
                    } else if norm_callee == "ifa_rt_string_len" {
                        ("i64".to_string(), vec!["ptr".to_string()])
                    } else if norm_callee == "ifa_rt_string_char_at" {
                        (
                            "i64".to_string(),
                            vec!["ptr".to_string(), "i64".to_string()],
                        )
                    } else if callee.starts_with("ifa_simd_")
                        || callee.starts_with("ifa_simd_arena_")
                    {
                        let is_f32 = callee.ends_with("_f32");
                        let is_f64 = callee.ends_with("_f64");
                        let is_i32 = callee.ends_with("_i32");
                        let _is_i64 = callee.ends_with("_i64");

                        if callee.contains("dot") {
                            let ret = if is_f64 { "double" } else { "float" };
                            (
                                ret.to_string(),
                                vec!["ptr".to_string(), "ptr".to_string(), "i64".to_string()],
                            )
                        } else if callee.contains("count_if") {
                            let thresh_ty = if is_f32 {
                                "float"
                            } else if is_f64 {
                                "double"
                            } else if is_i32 {
                                "i32"
                            } else {
                                "i64"
                            };
                            (
                                "i64".to_string(),
                                vec!["ptr".to_string(), "i64".to_string(), thresh_ty.to_string()],
                            )
                        } else if callee.contains("filter") {
                            let thresh_ty = if is_f32 {
                                "float"
                            } else if is_f64 {
                                "double"
                            } else if is_i32 {
                                "i32"
                            } else {
                                "i64"
                            };
                            (
                                "i64".to_string(),
                                vec![
                                    "ptr".to_string(),
                                    "ptr".to_string(),
                                    "i64".to_string(),
                                    thresh_ty.to_string(),
                                ],
                            )
                        } else if callee.contains("select") || callee.contains("clamp") {
                            let elem_ty = if is_f32 { "float" } else { "i32" };
                            (
                                "void".to_string(),
                                vec![
                                    "ptr".to_string(),
                                    "ptr".to_string(),
                                    "i64".to_string(),
                                    elem_ty.to_string(),
                                    elem_ty.to_string(),
                                ],
                            )
                        } else if callee.contains("sum")
                            || callee.contains("prod")
                            || callee.contains("min")
                            || callee.contains("max")
                        {
                            let ret = if is_f32 {
                                "float"
                            } else if is_f64 {
                                "double"
                            } else if is_i32 {
                                "i32"
                            } else {
                                "i64"
                            };
                            (ret.to_string(), vec!["ptr".to_string(), "i64".to_string()])
                        } else if callee.contains("slice_add")
                            || callee.contains("slice_mul")
                            || callee.contains("slice_xor")
                        {
                            (
                                "void".to_string(),
                                vec![
                                    "ptr".to_string(),
                                    "ptr".to_string(),
                                    "ptr".to_string(),
                                    "i64".to_string(),
                                ],
                            )
                        } else {
                            ("i64".to_string(), vec!["i64".to_string(); args.len()])
                        }
                    } else {
                        ("i64".to_string(), vec!["i64".to_string(); args.len()])
                    };

                    let args_str = Self::emit_call_args(
                        &format!("arg_{}", res_id),
                        args,
                        &param_types,
                        value_types,
                        null_values,
                        array_allocas,
                        out,
                    );

                    let target_fn_opt = module.functions.iter().find(|f| f.name == *name);
                    let is_target_coro = target_fn_opt.map(|f| f.is_coroutine()).unwrap_or(false);

                    if is_target_coro {
                        let target_fn = target_fn_opt.unwrap();
                        out.push_str(&format!(
                            "  %coro_direct_hdl_{} = call ptr @{}({})\n",
                            res_id,
                            callee_name,
                            args_str.join(", ")
                        ));
                        out.push_str(&format!(
                            "  %coro_raw_res_{} = call i64 @ifa_coro_run_to_completion(ptr %coro_direct_hdl_{})\n",
                            res_id, res_id
                        ));
                        let expected_llvm_ty = fir_to_llvm_type(&target_fn.ret_ty)?;
                        if expected_llvm_ty == "i64" {
                            out.push_str(&format!(
                                "  %v{} = add i64 %coro_raw_res_{}, 0\n",
                                res_id, res_id
                            ));
                        } else if expected_llvm_ty == "ptr" {
                            out.push_str(&format!(
                                "  %v{} = inttoptr i64 %coro_raw_res_{} to ptr\n",
                                res_id, res_id
                            ));
                        } else if expected_llvm_ty == "void" {
                            out.push_str(&format!("  %v{} = add i64 0, 0\n", res_id));
                        } else if expected_llvm_ty.starts_with('i') {
                            out.push_str(&format!(
                                "  %v{} = trunc i64 %coro_raw_res_{} to {}\n",
                                res_id, res_id, expected_llvm_ty
                            ));
                        } else if expected_llvm_ty == "float" {
                            out.push_str(&format!(
                                "  %coro_f32_bits_{} = trunc i64 %coro_raw_res_{} to i32\n",
                                res_id, res_id
                            ));
                            out.push_str(&format!(
                                "  %v{} = bitcast i32 %coro_f32_bits_{} to float\n",
                                res_id, res_id
                            ));
                        } else if expected_llvm_ty == "double" {
                            out.push_str(&format!(
                                "  %v{} = bitcast i64 %coro_raw_res_{} to double\n",
                                res_id, res_id
                            ));
                        } else {
                            out.push_str(&format!(
                                "  %v{} = add i64 %coro_raw_res_{}, 0\n",
                                res_id, res_id
                            ));
                        }
                    } else if ret_ty_str == "void" {
                        out.push_str(&format!(
                            "  call void @{}({})\n",
                            callee_name,
                            args_str.join(", ")
                        ));
                        out.push_str(&format!("  %v{} = add i64 0, 0\n", res_id));
                    } else {
                        out.push_str(&format!(
                            "  %v{} = call {} @{}({})\n",
                            res_id,
                            ret_ty_str,
                            callee_name,
                            args_str.join(", ")
                        ));
                    }
                }
            }
            ValueExpr::BlockingCallDirect { name, args } => {
                let callee = INTERNER.resolve(name);
                let (ret_ty_str, param_types) =
                    if let Some(target_fn) = module.functions.iter().find(|f| f.name == *name) {
                        let ret_ty = fir_to_llvm_type(&target_fn.ret_ty)?;
                        let params: Vec<String> = target_fn
                            .params
                            .iter()
                            .map(|p| {
                                if p.mode == ifa_fir::ParamMode::InOut {
                                    "ptr".to_string()
                                } else {
                                    match &p.ty {
                                        ifa_fir::FirType::Array(..) => "ptr".to_string(),
                                        _ => fir_to_llvm_type(&p.ty)
                                            .unwrap_or_else(|_| "i64".to_string()),
                                    }
                                }
                            })
                            .collect();
                        (ret_ty, params)
                    } else {
                        ("i64".to_string(), vec!["i64".to_string(); args.len()])
                    };

                out.push_str(&format!(
                    "  %pack_{} = alloca %struct.ifa_pack_{}, align 8\n",
                    res_id, callee
                ));
                for (i, a) in args.iter().enumerate() {
                    let p_ty = param_types
                        .get(i)
                        .cloned()
                        .unwrap_or_else(|| "i64".to_string());
                    out.push_str(&format!(
                        "  %arg_slot_{}_{} = getelementptr inbounds %struct.ifa_pack_{}, ptr %pack_{}, i32 0, i32 {}\n",
                        res_id, i, callee, res_id, i
                    ));
                    out.push_str(&format!(
                        "  store {} %v{}, ptr %arg_slot_{}_{}, align 8\n",
                        p_ty, a.0, res_id, i
                    ));
                }
                out.push_str(&format!(
                    "  %pack_res_{} = call ptr @ifa_rt_blocking_call(ptr @ifa_thunk_blocking_{}, ptr %pack_{})\n",
                    res_id, callee, res_id
                ));
                if ret_ty_str != "void" {
                    out.push_str(&format!(
                        "  %res_slot_{} = getelementptr inbounds %struct.ifa_pack_{}, ptr %pack_{}, i32 0, i32 {}\n",
                        res_id, callee, res_id, param_types.len()
                    ));
                    out.push_str(&format!(
                        "  %v{} = load {}, ptr %res_slot_{}, align 8\n",
                        res_id, ret_ty_str, res_id
                    ));
                } else {
                    out.push_str(&format!("  %v{} = add i64 0, 0\n", res_id));
                }
            }
            ValueExpr::Call { callee, args } => {
                let ret_ty_str = value_types
                    .get(&ifa_fir::ValueId(res_id))
                    .map(|t| fir_to_llvm_type(t).unwrap_or_else(|_| "i64".to_string()))
                    .unwrap_or_else(|| "i64".to_string());
                let args_str: Vec<String> = args
                    .iter()
                    .map(|a| {
                        let ty = value_types
                            .get(a)
                            .map(|t| fir_to_llvm_type(t).unwrap_or_else(|_| "i64".to_string()))
                            .unwrap_or_else(|| "i64".to_string());
                        format!("{} %v{}", ty, a.0)
                    })
                    .collect();
                let callee_ty_str = value_types
                    .get(callee)
                    .map(|t| fir_to_llvm_type(t).unwrap_or_else(|_| "i64".to_string()))
                    .unwrap_or_else(|| "i64".to_string());
                let callee_target = if callee_ty_str == "ptr" {
                    format!("%v{}", callee.0)
                } else {
                    out.push_str(&format!(
                        "  %callee_ptr_{} = inttoptr i64 %v{} to ptr\n",
                        res_id, callee.0
                    ));
                    format!("%callee_ptr_{}", res_id)
                };
                if ret_ty_str == "void" {
                    out.push_str(&format!(
                        "  call void {}({})\n",
                        callee_target,
                        args_str.join(", ")
                    ));
                    out.push_str(&format!("  %v{} = add i64 0, 0\n", res_id));
                } else {
                    out.push_str(&format!(
                        "  %v{} = call {} {}({})\n",
                        res_id,
                        ret_ty_str,
                        callee_target,
                        args_str.join(", ")
                    ));
                }
            }
            ValueExpr::GenAlloc { ty, arena } => {
                let size = ty.byte_size().max(8);
                let align = llvm_align_for_type(ty).max(8);
                let arena_id = arena.unwrap_or(0);
                if arena_id == ifa_fir::ARENA_THREAD_LOCAL_CALL {
                    out.push_str(&format!(
                        "  %v{} = call ptr @ifa_rt_call_arena_alloc(i64 {}, i64 {})\n",
                        res_id, size, align
                    ));
                } else {
                    out.push_str(&format!(
                        "  %v{} = call ptr @ifa_rt_gen_alloc(i64 {}, i64 {}, i16 {})\n",
                        res_id, size, align, arena_id
                    ));
                }
            }
            ValueExpr::CallArenaAlloc { ty } => {
                let size = ty.byte_size().max(8);
                let align = llvm_align_for_type(ty).max(8);
                out.push_str(&format!(
                    "  %v{} = call ptr @ifa_rt_call_arena_alloc(i64 {}, i64 {})\n",
                    res_id, size, align
                ));
            }
            ValueExpr::CallArenaMark => {
                out.push_str(&format!(
                    "  %v{} = call i64 @ifa_rt_call_arena_mark()\n",
                    res_id
                ));
            }
            ValueExpr::CallArenaRewind { mark } => {
                out.push_str(&format!(
                    "  call void @ifa_rt_call_arena_rewind(i64 %v{})\n",
                    mark.0
                ));
                out.push_str(&format!("  %v{} = add i64 0, 0\n", res_id));
            }
            ValueExpr::GetField {
                base, field_idx, ..
            } => {
                let base_ty = value_types.get(base);
                if let Some(ifa_fir::FirType::Struct(s_sym, _)) = base_ty {
                    let s_name = INTERNER.resolve(s_sym);
                    out.push_str(&format!(
                        "  %v{} = extractvalue %struct.{} %v{}, {}\n",
                        res_id, s_name, base.0, field_idx
                    ));
                } else if let Some(ifa_fir::FirType::Pointer(inner)) = base_ty {
                    if let ifa_fir::FirType::Struct(s_sym, fields) = &**inner {
                        let field_ty_str = if let Some(st_def) =
                            module.structs.iter().find(|s| s.name == *s_sym)
                        {
                            if *field_idx < st_def.fields.len() {
                                fir_to_llvm_type(&st_def.fields[*field_idx].1)
                                    .unwrap_or_else(|_| "i64".to_string())
                            } else {
                                "i64".to_string()
                            }
                        } else if *field_idx < fields.len() {
                            fir_to_llvm_type(&fields[*field_idx].1)
                                .unwrap_or_else(|_| "i64".to_string())
                        } else {
                            "i64".to_string()
                        };
                        out.push_str(&format!(
                            "  %gep_{} = getelementptr inbounds %struct.{}, ptr %v{}, i32 0, i32 {}\n",
                            res_id,
                            INTERNER.resolve(s_sym),
                            base.0,
                            field_idx
                        ));
                        out.push_str(&format!(
                            "  %v{} = load {}, ptr %gep_{}\n",
                            res_id, field_ty_str, res_id
                        ));
                    } else {
                        out.push_str(&format!(
                            "  %gep_{} = getelementptr inbounds i64, ptr %v{}, i32 {}\n",
                            res_id, base.0, field_idx
                        ));
                        out.push_str(&format!("  %v{} = load i64, ptr %gep_{}\n", res_id, res_id));
                    }
                } else {
                    out.push_str(&format!(
                        "  %gep_{} = getelementptr inbounds i64, ptr %v{}, i32 {}\n",
                        res_id, base.0, field_idx
                    ));
                    out.push_str(&format!("  %v{} = load i64, ptr %gep_{}\n", res_id, res_id));
                }
            }
            ValueExpr::GetFieldPtr {
                base, field_idx, ..
            } => {
                let base_ty = value_types.get(base);
                if let Some(ifa_fir::FirType::Pointer(inner)) = base_ty {
                    if let ifa_fir::FirType::Struct(s_sym, _) = &**inner {
                        out.push_str(&format!(
                            "  %v{} = getelementptr inbounds %struct.{}, ptr %v{}, i32 0, i32 {}\n",
                            res_id,
                            INTERNER.resolve(s_sym),
                            base.0,
                            field_idx
                        ));
                    } else {
                        out.push_str(&format!(
                            "  %v{} = getelementptr inbounds i64, ptr %v{}, i32 {}\n",
                            res_id, base.0, field_idx
                        ));
                    }
                } else if let Some(ifa_fir::FirType::Struct(s_sym, _)) = base_ty {
                    out.push_str(&format!(
                        "  %v{} = getelementptr inbounds %struct.{}, ptr %v{}, i32 0, i32 {}\n",
                        res_id,
                        INTERNER.resolve(s_sym),
                        base.0,
                        field_idx
                    ));
                } else {
                    out.push_str(&format!(
                        "  %v{} = getelementptr inbounds i64, ptr %v{}, i32 {}\n",
                        res_id, base.0, field_idx
                    ));
                }
            }
            ValueExpr::GetElementPtr { base, index } => {
                let base_ty = value_types.get(base);
                let (elem_ty_str, _) = match base_ty {
                    Some(ifa_fir::FirType::Array(inner, _))
                    | Some(ifa_fir::FirType::Slice(inner)) => (
                        fir_to_llvm_type(inner).unwrap_or_else(|_| "i64".to_string()),
                        llvm_align_for_type(inner),
                    ),
                    Some(ifa_fir::FirType::Pointer(inner)) => match &**inner {
                        ifa_fir::FirType::Array(elem, _) | ifa_fir::FirType::Slice(elem) => (
                            fir_to_llvm_type(elem).unwrap_or_else(|_| "i64".to_string()),
                            llvm_align_for_type(elem),
                        ),
                        _ => ("i64".to_string(), 8),
                    },
                    _ => ("i64".to_string(), 8),
                };
                let ptr_operand = match base_ty {
                    Some(ifa_fir::FirType::Slice(_)) => {
                        out.push_str(&format!(
                            "  %gep_slice_ptr_{} = extractvalue {{ ptr, i64 }} %v{}, 0\n",
                            res_id, base.0
                        ));
                        format!("%gep_slice_ptr_{}", res_id)
                    }
                    Some(ifa_fir::FirType::Pointer(inner))
                        if matches!(&**inner, ifa_fir::FirType::Slice(_)) =>
                    {
                        out.push_str(&format!(
                            "  %gep_slice_ld_{} = load {{ ptr, i64 }}, ptr %v{}, align 8\n",
                            res_id, base.0
                        ));
                        out.push_str(&format!(
                            "  %gep_slice_ptr_{} = extractvalue {{ ptr, i64 }} %gep_slice_ld_{}, 0\n",
                            res_id, res_id
                        ));
                        format!("%gep_slice_ptr_{}", res_id)
                    }
                    Some(ifa_fir::FirType::Struct(s_sym, _)) => {
                        let s_name = INTERNER.resolve(s_sym);
                        out.push_str(&format!(
                            "  %st_gep_slot_{} = alloca %struct.{}, align 8\n",
                            res_id, s_name
                        ));
                        out.push_str(&format!(
                            "  store %struct.{} %v{}, ptr %st_gep_slot_{}, align 8\n",
                            s_name, base.0, res_id
                        ));
                        format!("%st_gep_slot_{}", res_id)
                    }
                    _ => array_ptrs
                        .get(base)
                        .cloned()
                        .or_else(|| array_allocas.get(base).map(|p| format!("%v{}", p.0)))
                        .unwrap_or_else(|| format!("%v{}", base.0)),
                };
                let effective_idx = if let Some(&(st_vid, c_opt)) = strided_slice_info.get(base) {
                    if let Some(c) = c_opt {
                        if c == 1 {
                            format!("%v{}", index.0)
                        } else if c > 0 && (c as u64).is_power_of_two() {
                            out.push_str(&format!(
                                "  %strided_gep_idx_{} = shl i64 %v{}, {}\n",
                                res_id,
                                index.0,
                                (c as u64).trailing_zeros()
                            ));
                            format!("%strided_gep_idx_{}", res_id)
                        } else {
                            out.push_str(&format!(
                                "  %strided_gep_idx_{} = mul i64 %v{}, {}\n",
                                res_id, index.0, c
                            ));
                            format!("%strided_gep_idx_{}", res_id)
                        }
                    } else {
                        out.push_str(&format!(
                            "  %strided_gep_idx_{} = mul i64 %v{}, %v{}\n",
                            res_id, index.0, st_vid.0
                        ));
                        format!("%strided_gep_idx_{}", res_id)
                    }
                } else {
                    format!("%v{}", index.0)
                };
                out.push_str(&format!(
                    "  %v{} = getelementptr inbounds {}, ptr {}, i64 {}\n",
                    res_id, elem_ty_str, ptr_operand, effective_idx
                ));
            }
            ValueExpr::GenRef { ptr } => {
                let gen_ref_ty = "{ ptr, i32, i16, i16 }";
                out.push_str(&format!(
                    "  %t_gr1_{} = insertvalue {} undef, ptr %v{}, 0\n",
                    res_id, gen_ref_ty, ptr.0
                ));
                out.push_str(&format!(
                    "  %t_gr2_{} = insertvalue {} %t_gr1_{}, i32 1, 1\n",
                    res_id, gen_ref_ty, res_id
                ));
                out.push_str(&format!(
                    "  %t_gr3_{} = insertvalue {} %t_gr2_{}, i16 0, 2\n",
                    res_id, gen_ref_ty, res_id
                ));
                out.push_str(&format!(
                    "  %v{} = insertvalue {} %t_gr3_{}, i16 0, 3\n",
                    res_id, gen_ref_ty, res_id
                ));
            }
            ValueExpr::GenDeref { ref_val: ptr } => {
                let ref_ty = value_types.get(ptr);
                match ref_ty {
                    Some(ifa_fir::FirType::Optional(inner))
                        if matches!(&**inner, ifa_fir::FirType::GenerationalRef(_)) =>
                    {
                        let opt_ty = fir_to_llvm_type(ref_ty.unwrap())?;
                        out.push_str(&format!(
                            "  %gr_{} = extractvalue {} %v{}, 1\n",
                            res_id, opt_ty, ptr.0
                        ));
                        out.push_str(&format!(
                            "  %v{} = extractvalue {{ ptr, i32, i16, i16 }} %gr_{}, 0\n",
                            res_id, res_id
                        ));
                    }
                    Some(ifa_fir::FirType::GenerationalRef(_)) => {
                        out.push_str(&format!(
                            "  %v{} = extractvalue {{ ptr, i32, i16, i16 }} %v{}, 0\n",
                            res_id, ptr.0
                        ));
                    }
                    _ => {
                        out.push_str(&format!(
                            "  %v{} = getelementptr i8, ptr %v{}, i64 0\n",
                            res_id, ptr.0
                        ));
                    }
                }
            }
            ValueExpr::GetElement { base, index } => {
                let base_ty = value_types.get(base);
                let (elem_ty_str, align) = match base_ty {
                    Some(ifa_fir::FirType::Array(inner, _))
                    | Some(ifa_fir::FirType::Slice(inner)) => (
                        fir_to_llvm_type(inner).unwrap_or_else(|_| "i64".to_string()),
                        llvm_align_for_type(inner),
                    ),
                    Some(ifa_fir::FirType::Pointer(inner)) => match &**inner {
                        ifa_fir::FirType::Array(elem, _) | ifa_fir::FirType::Slice(elem) => (
                            fir_to_llvm_type(elem).unwrap_or_else(|_| "i64".to_string()),
                            llvm_align_for_type(elem),
                        ),
                        ifa_fir::FirType::Struct(s_sym, _) => {
                            let s_name = INTERNER.resolve(s_sym);
                            if let Some(elem_name) = s_name.strip_prefix("List__") {
                                let elem_ty = fir_type_from_elem_name(elem_name);
                                (
                                    fir_to_llvm_type(&elem_ty)
                                        .unwrap_or_else(|_| "i64".to_string()),
                                    llvm_align_for_type(&elem_ty),
                                )
                            } else {
                                ("i64".to_string(), 8)
                            }
                        }
                        _ => ("i64".to_string(), 8),
                    },
                    Some(ifa_fir::FirType::Struct(s_sym, _)) => {
                        let s_name = INTERNER.resolve(s_sym);
                        if let Some(elem_name) = s_name.strip_prefix("List__") {
                            let elem_ty = fir_type_from_elem_name(elem_name);
                            (
                                fir_to_llvm_type(&elem_ty).unwrap_or_else(|_| "i64".to_string()),
                                llvm_align_for_type(&elem_ty),
                            )
                        } else {
                            ("i64".to_string(), 8)
                        }
                    }
                    _ => ("i64".to_string(), 8),
                };
                let ptr_operand = match base_ty {
                    Some(ifa_fir::FirType::Slice(_)) => {
                        out.push_str(&format!(
                            "  %slice_elem_ptr_{} = extractvalue {{ ptr, i64 }} %v{}, 0\n",
                            res_id, base.0
                        ));
                        format!("%slice_elem_ptr_{}", res_id)
                    }
                    Some(ifa_fir::FirType::Pointer(inner))
                        if matches!(&**inner, ifa_fir::FirType::Slice(_)) =>
                    {
                        out.push_str(&format!(
                            "  %slice_elem_ld_{} = load {{ ptr, i64 }}, ptr %v{}, align 8\n",
                            res_id, base.0
                        ));
                        out.push_str(&format!(
                            "  %slice_elem_ptr_{} = extractvalue {{ ptr, i64 }} %slice_elem_ld_{}, 0\n",
                            res_id, res_id
                        ));
                        format!("%slice_elem_ptr_{}", res_id)
                    }
                    Some(ifa_fir::FirType::Pointer(inner))
                        if matches!(&**inner, ifa_fir::FirType::Struct(..)) =>
                    {
                        if let ifa_fir::FirType::Struct(s_sym, _) = &**inner {
                            let s_name = INTERNER.resolve(s_sym);
                            if s_name.starts_with("List__") || s_name == "List" {
                                out.push_str(&format!(
                                    "  %list_data_ptr_{} = getelementptr inbounds %struct.{}, ptr %v{}, i32 0, i32 0\n",
                                    res_id, s_name, base.0
                                ));
                                out.push_str(&format!(
                                    "  %list_data_{} = load ptr, ptr %list_data_ptr_{}, align 8\n",
                                    res_id, res_id
                                ));
                                format!("%list_data_{}", res_id)
                            } else {
                                format!("%v{}", base.0)
                            }
                        } else {
                            format!("%v{}", base.0)
                        }
                    }
                    Some(ifa_fir::FirType::Struct(s_sym, _)) => {
                        let s_name = INTERNER.resolve(s_sym);
                        if s_name.starts_with("List__") || s_name == "List" {
                            out.push_str(&format!(
                                "  %list_data_{} = extractvalue %struct.{} %v{}, 0\n",
                                res_id, s_name, base.0
                            ));
                            format!("%list_data_{}", res_id)
                        } else {
                            out.push_str(&format!(
                                "  %st_idx_slot_{} = alloca %struct.{}, align 8\n",
                                res_id, s_name
                            ));
                            out.push_str(&format!(
                                "  store %struct.{} %v{}, ptr %st_idx_slot_{}, align 8\n",
                                s_name, base.0, res_id
                            ));
                            format!("%st_idx_slot_{}", res_id)
                        }
                    }
                    Some(ifa_fir::FirType::Array(..)) => array_ptrs
                        .get(base)
                        .cloned()
                        .or_else(|| array_allocas.get(base).map(|p| format!("%v{}", p.0)))
                        .unwrap_or_else(|| format!("%v{}", base.0)),
                    Some(ifa_fir::FirType::Pointer(inner))
                        if matches!(&**inner, ifa_fir::FirType::Array(..)) =>
                    {
                        array_ptrs
                            .get(base)
                            .cloned()
                            .or_else(|| array_allocas.get(base).map(|p| format!("%v{}", p.0)))
                            .unwrap_or_else(|| format!("%v{}", base.0))
                    }
                    _ => array_ptrs
                        .get(base)
                        .cloned()
                        .or_else(|| array_allocas.get(base).map(|p| format!("%v{}", p.0)))
                        .unwrap_or_else(|| format!("%v{}", base.0)),
                };
                let effective_idx = if let Some(&(st_vid, c_opt)) = strided_slice_info.get(base) {
                    if let Some(c) = c_opt {
                        if c == 1 {
                            format!("%v{}", index.0)
                        } else if c > 0 && (c as u64).is_power_of_two() {
                            out.push_str(&format!(
                                "  %strided_idx_{} = shl i64 %v{}, {}\n",
                                res_id,
                                index.0,
                                (c as u64).trailing_zeros()
                            ));
                            format!("%strided_idx_{}", res_id)
                        } else {
                            out.push_str(&format!(
                                "  %strided_idx_{} = mul i64 %v{}, {}\n",
                                res_id, index.0, c
                            ));
                            format!("%strided_idx_{}", res_id)
                        }
                    } else {
                        out.push_str(&format!(
                            "  %strided_idx_{} = mul i64 %v{}, %v{}\n",
                            res_id, index.0, st_vid.0
                        ));
                        format!("%strided_idx_{}", res_id)
                    }
                } else {
                    format!("%v{}", index.0)
                };
                out.push_str(&format!(
                    "  %gep_{} = getelementptr inbounds {}, ptr {}, i64 {}\n",
                    res_id, elem_ty_str, ptr_operand, effective_idx
                ));
                out.push_str(&format!(
                    "  %v{} = load {}, ptr %gep_{}, align {}\n",
                    res_id, elem_ty_str, res_id, align
                ));
            }
            ValueExpr::ArrayInit(elements) => {
                let count = elements.len().max(1);
                let (elem_ty_str, align) = elements
                    .first()
                    .and_then(|e| value_types.get(e))
                    .map(|ty| {
                        (
                            fir_to_llvm_type(ty).unwrap_or_else(|_| "i64".to_string()),
                            llvm_align_for_type(ty),
                        )
                    })
                    .unwrap_or_else(|| ("i64".to_string(), 8));

                let total_bytes = count * align as usize;
                let arr_align = if total_bytes >= 64 {
                    64
                } else if total_bytes >= 32 {
                    32
                } else if total_bytes >= 16 {
                    16
                } else {
                    align.max(8)
                };

                out.push_str(&format!(
                    "  %arr_alloc_{} = alloca [{} x {}], align {}\n",
                    res_id, count, elem_ty_str, arr_align
                ));
                for (idx, elem) in elements.iter().enumerate() {
                    out.push_str(&format!(
                        "  %elem_ptr_{}_{} = getelementptr inbounds [{} x {}], ptr %arr_alloc_{}, i64 0, i64 {}\n",
                        res_id, idx, count, elem_ty_str, res_id, idx
                    ));
                    out.push_str(&format!(
                        "  store {} %v{}, ptr %elem_ptr_{}_{}, align {}\n",
                        elem_ty_str, elem.0, res_id, idx, align
                    ));
                }
                out.push_str(&format!(
                    "  %v{} = getelementptr inbounds [{} x {}], ptr %arr_alloc_{}, i64 0, i64 0\n",
                    res_id, count, elem_ty_str, res_id
                ));
            }
            ValueExpr::StructInit { name, fields } => {
                let s_name = INTERNER.resolve(name);
                out.push_str(&format!(
                    "  %st_alloc_{} = alloca %struct.{}, align 8\n",
                    res_id, s_name
                ));
                for (idx, field_val) in fields.iter().enumerate() {
                    let f_ty_str = value_types
                        .get(field_val)
                        .and_then(|ty| fir_to_llvm_type(ty).ok())
                        .unwrap_or_else(|| "i64".to_string());
                    out.push_str(&format!(
                        "  %field_ptr_{}_{} = getelementptr inbounds %struct.{}, ptr %st_alloc_{}, i32 0, i32 {}\n",
                        res_id, idx, s_name, res_id, idx
                    ));
                    out.push_str(&format!(
                        "  store {} %v{}, ptr %field_ptr_{}_{}, align 8\n",
                        f_ty_str, field_val.0, res_id, idx
                    ));
                }
                out.push_str(&format!(
                    "  %v{} = load %struct.{}, ptr %st_alloc_{}\n",
                    res_id, s_name, res_id
                ));
            }
            ValueExpr::TupleInit(fields) => {
                let count = fields.len().max(1);
                out.push_str(&format!(
                    "  %tup_alloc_{} = alloca [{} x i64], align 8\n",
                    res_id, count
                ));
                for (idx, field_val) in fields.iter().enumerate() {
                    out.push_str(&format!(
                        "  %tup_elem_{}_{} = getelementptr inbounds [{} x i64], ptr %tup_alloc_{}, i64 0, i64 {}\n",
                        res_id, idx, count, res_id, idx
                    ));
                    out.push_str(&format!(
                        "  store i64 %v{}, ptr %tup_elem_{}_{}, align 8\n",
                        field_val.0, res_id, idx
                    ));
                }
                out.push_str(&format!(
                    "  %v{} = getelementptr inbounds [{} x i64], ptr %tup_alloc_{}, i64 0, i64 0\n",
                    res_id, count, res_id
                ));
            }
            ValueExpr::ChanCreate { capacity, .. } => {
                if let Some(cap) = capacity {
                    out.push_str(&format!(
                        "  %v{} = call ptr @ifa_rt_channel_create(i64 %v{})\n",
                        res_id, cap.0
                    ));
                } else {
                    out.push_str(&format!(
                        "  %v{} = call ptr @ifa_rt_channel_create(i64 0)\n",
                        res_id
                    ));
                }
            }
            ValueExpr::ChanRecv { chan } | ValueExpr::ChanTryRecv { chan } => {
                out.push_str(&format!(
                    "  %chan_out_slot_{} = alloca ptr, align 8\n",
                    res_id
                ));
                if is_coro {
                    let y_id = *coro_yield_idx;
                    *coro_yield_idx += 1;
                    out.push_str(&format!("  br label %coro.recv_poll_{}\n", y_id));
                    out.push_str(&format!("coro.recv_poll_{}:\n", y_id));
                    out.push_str(&format!(
                        "  %recv_st_{}_{} = call i32 @ifa_rt_channel_try_recv(ptr %v{}, ptr %chan_out_slot_{})\n",
                        res_id, y_id, chan.0, res_id
                    ));
                    out.push_str(&format!(
                        "  %recv_empty_{}_{} = icmp eq i32 %recv_st_{}_{}, 1\n",
                        res_id, y_id, res_id, y_id
                    ));
                    out.push_str(&format!(
                        "  br i1 %recv_empty_{}_{}, label %coro.recv_susp_{}, label %coro.recv_done_{}\n",
                        res_id, y_id, y_id, y_id
                    ));
                    out.push_str(&format!("coro.recv_susp_{}:\n", y_id));
                    out.push_str(&format!(
                        "  %coro.recv_tok_{} = call i8 @llvm.coro.suspend(token none, i1 false)\n",
                        y_id
                    ));
                    out.push_str(&format!(
                        "  switch i8 %coro.recv_tok_{}, label %coro.susp_ret [ i8 0, label %coro.recv_poll_{} i8 1, label %coro.cleanup ]\n",
                        y_id, y_id
                    ));
                    out.push_str(&format!("coro.recv_done_{}:\n", y_id));
                } else {
                    out.push_str(&format!(
                        "  call i32 @ifa_rt_channel_recv(ptr %v{}, ptr %chan_out_slot_{})\n",
                        chan.0, res_id
                    ));
                }
                out.push_str(&format!(
                    "  %chan_raw_{} = load ptr, ptr %chan_out_slot_{}, align 8\n",
                    res_id, res_id
                ));
                let dest_ty = value_types.get(&ifa_fir::ValueId(res_id));
                match dest_ty {
                    Some(ifa_fir::FirType::Pointer(_))
                    | Some(ifa_fir::FirType::GenerationalRef(_))
                    | Some(ifa_fir::FirType::Str)
                    | Some(ifa_fir::FirType::String)
                    | Some(ifa_fir::FirType::Struct(..))
                    | Some(ifa_fir::FirType::Enum(..))
                    | Some(ifa_fir::FirType::Array(..))
                    | Some(ifa_fir::FirType::Slice(..))
                    | Some(ifa_fir::FirType::Channel(_))
                    | Some(ifa_fir::FirType::Unit) => {
                        out.push_str(&format!(
                            "  %v{} = bitcast ptr %chan_raw_{} to ptr\n",
                            res_id, res_id
                        ));
                    }
                    Some(ifa_fir::FirType::Int(
                        ifa_sema::types::IntType::I32 | ifa_sema::types::IntType::U32,
                    )) => {
                        out.push_str(&format!(
                            "  %chan_i64_{} = ptrtoint ptr %chan_raw_{} to i64\n",
                            res_id, res_id
                        ));
                        out.push_str(&format!(
                            "  %v{} = trunc i64 %chan_i64_{} to i32\n",
                            res_id, res_id
                        ));
                    }
                    Some(ifa_fir::FirType::Int(
                        ifa_sema::types::IntType::I8 | ifa_sema::types::IntType::U8,
                    )) => {
                        out.push_str(&format!(
                            "  %chan_i64_{} = ptrtoint ptr %chan_raw_{} to i64\n",
                            res_id, res_id
                        ));
                        out.push_str(&format!(
                            "  %v{} = trunc i64 %chan_i64_{} to i8\n",
                            res_id, res_id
                        ));
                    }
                    Some(ifa_fir::FirType::Int(
                        ifa_sema::types::IntType::I16 | ifa_sema::types::IntType::U16,
                    )) => {
                        out.push_str(&format!(
                            "  %chan_i64_{} = ptrtoint ptr %chan_raw_{} to i64\n",
                            res_id, res_id
                        ));
                        out.push_str(&format!(
                            "  %v{} = trunc i64 %chan_i64_{} to i16\n",
                            res_id, res_id
                        ));
                    }
                    Some(ifa_fir::FirType::Bool) => {
                        out.push_str(&format!(
                            "  %chan_i64_{} = ptrtoint ptr %chan_raw_{} to i64\n",
                            res_id, res_id
                        ));
                        out.push_str(&format!(
                            "  %v{} = trunc i64 %chan_i64_{} to i1\n",
                            res_id, res_id
                        ));
                    }
                    Some(ifa_fir::FirType::Float(_)) => {
                        out.push_str(&format!(
                            "  %chan_i64_{} = ptrtoint ptr %chan_raw_{} to i64\n",
                            res_id, res_id
                        ));
                        out.push_str(&format!(
                            "  %v{} = bitcast i64 %chan_i64_{} to double\n",
                            res_id, res_id
                        ));
                    }
                    _ => {
                        out.push_str(&format!(
                            "  %v{} = ptrtoint ptr %chan_raw_{} to i64\n",
                            res_id, res_id
                        ));
                    }
                }
            }
            ValueExpr::ChanTrySend { chan, val } => {
                let is_val_ptr = matches!(
                    value_types.get(val),
                    Some(ifa_fir::FirType::Pointer(_))
                        | Some(ifa_fir::FirType::GenerationalRef(_))
                        | Some(ifa_fir::FirType::Str)
                        | Some(ifa_fir::FirType::String)
                        | Some(ifa_fir::FirType::Struct(..))
                        | Some(ifa_fir::FirType::Enum(..))
                        | Some(ifa_fir::FirType::Array(..))
                        | Some(ifa_fir::FirType::Slice(..))
                        | Some(ifa_fir::FirType::Channel(_))
                        | Some(ifa_fir::FirType::Unit)
                );
                let val_ptr_expr = if is_val_ptr {
                    format!("%v{}", val.0)
                } else {
                    let cast_val = format!("%chan_try_val_cast_{}", val.0);
                    out.push_str(&format!(
                        "  {} = inttoptr i64 %v{} to ptr\n",
                        cast_val, val.0
                    ));
                    cast_val
                };
                out.push_str(&format!(
                    "  %v{} = call i32 @ifa_rt_channel_try_send(ptr %v{}, ptr {})\n",
                    res_id, chan.0, val_ptr_expr
                ));
            }
            ValueExpr::ChanSelect {
                channels,
                has_default,
                timeout,
                priorities,
            } => {
                let num_chans = channels.len();
                let has_timeout = timeout.is_some();
                let total_entries = num_chans + if has_timeout { 1 } else { 0 };
                let arr_len = total_entries.max(1);
                // Zero-allocation wait table descriptor allocated on stack frame
                out.push_str(&format!(
                    "  %select_entries_{} = alloca [{} x %struct.ifa_select_wait_entry], align 8\n",
                    res_id, arr_len
                ));
                out.push_str(&format!(
                    "  %select_table_{} = alloca %struct.ifa_select_wait_table, align 8\n",
                    res_id
                ));
                for (i, chan_id) in channels.iter().enumerate() {
                    let prio = priorities.get(i).copied().unwrap_or(0);
                    out.push_str(&format!(
                        "  %select_entry_{}_{} = getelementptr inbounds [{} x %struct.ifa_select_wait_entry], ptr %select_entries_{}, i64 0, i64 {}\n",
                        res_id, i, arr_len, res_id, i
                    ));
                    out.push_str(&format!(
                        "  %select_chan_slot_{}_{} = getelementptr inbounds %struct.ifa_select_wait_entry, ptr %select_entry_{}_{}, i32 0, i32 0\n",
                        res_id, i, res_id, i
                    ));
                    out.push_str(&format!(
                        "  store ptr %v{}, ptr %select_chan_slot_{}_{}, align 8\n",
                        chan_id.0, res_id, i
                    ));
                    out.push_str(&format!(
                        "  %select_op_slot_{}_{} = getelementptr inbounds %struct.ifa_select_wait_entry, ptr %select_entry_{}_{}, i32 0, i32 1\n",
                        res_id, i, res_id, i
                    ));
                    out.push_str(&format!(
                        "  store i32 0, ptr %select_op_slot_{}_{}, align 4\n",
                        res_id, i
                    ));
                    out.push_str(&format!(
                        "  %select_rdy_slot_{}_{} = getelementptr inbounds %struct.ifa_select_wait_entry, ptr %select_entry_{}_{}, i32 0, i32 2\n",
                        res_id, i, res_id, i
                    ));
                    out.push_str(&format!(
                        "  store i32 0, ptr %select_rdy_slot_{}_{}, align 4\n",
                        res_id, i
                    ));
                    out.push_str(&format!(
                        "  %select_val_slot_{}_{} = getelementptr inbounds %struct.ifa_select_wait_entry, ptr %select_entry_{}_{}, i32 0, i32 3\n",
                        res_id, i, res_id, i
                    ));
                    out.push_str(&format!(
                        "  store ptr null, ptr %select_val_slot_{}_{}, align 8\n",
                        res_id, i
                    ));
                    out.push_str(&format!(
                        "  %select_prio_slot_{}_{} = getelementptr inbounds %struct.ifa_select_wait_entry, ptr %select_entry_{}_{}, i32 0, i32 4\n",
                        res_id, i, res_id, i
                    ));
                    out.push_str(&format!(
                        "  store i32 {}, ptr %select_prio_slot_{}_{}, align 4\n",
                        prio, res_id, i
                    ));
                    out.push_str(&format!(
                        "  %select_pad_slot_{}_{} = getelementptr inbounds %struct.ifa_select_wait_entry, ptr %select_entry_{}_{}, i32 0, i32 5\n",
                        res_id, i, res_id, i
                    ));
                    out.push_str(&format!(
                        "  store i32 0, ptr %select_pad_slot_{}_{}, align 4\n",
                        res_id, i
                    ));
                    out.push_str(&format!(
                        "  %select_timeout_slot_{}_{} = getelementptr inbounds %struct.ifa_select_wait_entry, ptr %select_entry_{}_{}, i32 0, i32 6\n",
                        res_id, i, res_id, i
                    ));
                    out.push_str(&format!(
                        "  store i64 0, ptr %select_timeout_slot_{}_{}, align 8\n",
                        res_id, i
                    ));
                }
                if let Some(t_id) = timeout {
                    let t_idx = num_chans;
                    out.push_str(&format!(
                        "  %select_entry_{}_{} = getelementptr inbounds [{} x %struct.ifa_select_wait_entry], ptr %select_entries_{}, i64 0, i64 {}\n",
                        res_id, t_idx, arr_len, res_id, t_idx
                    ));
                    out.push_str(&format!(
                        "  %select_chan_slot_{}_{} = getelementptr inbounds %struct.ifa_select_wait_entry, ptr %select_entry_{}_{}, i32 0, i32 0\n",
                        res_id, t_idx, res_id, t_idx
                    ));
                    out.push_str(&format!(
                        "  store ptr null, ptr %select_chan_slot_{}_{}, align 8\n",
                        res_id, t_idx
                    ));
                    out.push_str(&format!(
                        "  %select_op_slot_{}_{} = getelementptr inbounds %struct.ifa_select_wait_entry, ptr %select_entry_{}_{}, i32 0, i32 1\n",
                        res_id, t_idx, res_id, t_idx
                    ));
                    out.push_str(&format!(
                        "  store i32 2, ptr %select_op_slot_{}_{}, align 4\n",
                        res_id, t_idx
                    ));
                    out.push_str(&format!(
                        "  %select_rdy_slot_{}_{} = getelementptr inbounds %struct.ifa_select_wait_entry, ptr %select_entry_{}_{}, i32 0, i32 2\n",
                        res_id, t_idx, res_id, t_idx
                    ));
                    out.push_str(&format!(
                        "  store i32 0, ptr %select_rdy_slot_{}_{}, align 4\n",
                        res_id, t_idx
                    ));
                    out.push_str(&format!(
                        "  %select_val_slot_{}_{} = getelementptr inbounds %struct.ifa_select_wait_entry, ptr %select_entry_{}_{}, i32 0, i32 3\n",
                        res_id, t_idx, res_id, t_idx
                    ));
                    out.push_str(&format!(
                        "  store ptr null, ptr %select_val_slot_{}_{}, align 8\n",
                        res_id, t_idx
                    ));
                    out.push_str(&format!(
                        "  %select_prio_slot_{}_{} = getelementptr inbounds %struct.ifa_select_wait_entry, ptr %select_entry_{}_{}, i32 0, i32 4\n",
                        res_id, t_idx, res_id, t_idx
                    ));
                    out.push_str(&format!(
                        "  store i32 -2147483648, ptr %select_prio_slot_{}_{}, align 4\n",
                        res_id, t_idx
                    ));
                    out.push_str(&format!(
                        "  %select_pad_slot_{}_{} = getelementptr inbounds %struct.ifa_select_wait_entry, ptr %select_entry_{}_{}, i32 0, i32 5\n",
                        res_id, t_idx, res_id, t_idx
                    ));
                    out.push_str(&format!(
                        "  store i32 0, ptr %select_pad_slot_{}_{}, align 4\n",
                        res_id, t_idx
                    ));
                    out.push_str(&format!(
                        "  %select_timeout_slot_{}_{} = getelementptr inbounds %struct.ifa_select_wait_entry, ptr %select_entry_{}_{}, i32 0, i32 6\n",
                        res_id, t_idx, res_id, t_idx
                    ));
                    out.push_str(&format!(
                        "  store i64 %v{}, ptr %select_timeout_slot_{}_{}, align 8\n",
                        t_id.0, res_id, t_idx
                    ));
                }
                out.push_str(&format!(
                    "  %select_tbl_ent_{} = getelementptr inbounds %struct.ifa_select_wait_table, ptr %select_table_{}, i32 0, i32 0\n",
                    res_id, res_id
                ));
                out.push_str(&format!(
                    "  %select_base_ent_{} = getelementptr inbounds [{} x %struct.ifa_select_wait_entry], ptr %select_entries_{}, i64 0, i64 0\n",
                    res_id, arr_len, res_id
                ));
                out.push_str(&format!(
                    "  store ptr %select_base_ent_{}, ptr %select_tbl_ent_{}, align 8\n",
                    res_id, res_id
                ));
                out.push_str(&format!(
                    "  %select_tbl_cnt_{} = getelementptr inbounds %struct.ifa_select_wait_table, ptr %select_table_{}, i32 0, i32 1\n",
                    res_id, res_id
                ));
                out.push_str(&format!(
                    "  store i64 {}, ptr %select_tbl_cnt_{}, align 8\n",
                    total_entries, res_id
                ));
                out.push_str(&format!(
                    "  %select_tbl_def_{} = getelementptr inbounds %struct.ifa_select_wait_table, ptr %select_table_{}, i32 0, i32 2\n",
                    res_id, res_id
                ));
                out.push_str(&format!(
                    "  store i32 {}, ptr %select_tbl_def_{}, align 4\n",
                    if *has_default { 1 } else { 0 },
                    res_id
                ));
                out.push_str(&format!(
                    "  %select_tbl_pad_{} = getelementptr inbounds %struct.ifa_select_wait_table, ptr %select_table_{}, i32 0, i32 3\n",
                    res_id, res_id
                ));
                out.push_str(&format!(
                    "  store i32 0, ptr %select_tbl_pad_{}, align 4\n",
                    res_id
                ));
                out.push_str(&format!(
                    "  %select_tbl_start_{} = getelementptr inbounds %struct.ifa_select_wait_table, ptr %select_table_{}, i32 0, i32 4\n",
                    res_id, res_id
                ));
                out.push_str(&format!(
                    "  store i64 -1, ptr %select_tbl_start_{}, align 8\n",
                    res_id
                ));
                if is_coro && !has_default {
                    let y_id = *coro_yield_idx;
                    *coro_yield_idx += 1;
                    out.push_str(&format!("  br label %coro.sel_poll_{}\n", y_id));
                    out.push_str(&format!("coro.sel_poll_{}:\n", y_id));
                    out.push_str(&format!(
                        "  %sel_poll_res_{}_{} = call i64 @ifa_rt_channel_select_table(ptr %select_table_{})\n",
                        res_id, y_id, res_id
                    ));
                    out.push_str(&format!(
                        "  %sel_is_waiting_{}_{} = icmp eq i64 %sel_poll_res_{}_{}, -1\n",
                        res_id, y_id, res_id, y_id
                    ));
                    out.push_str(&format!(
                        "  br i1 %sel_is_waiting_{}_{}, label %coro.sel_susp_{}, label %coro.sel_done_{}\n",
                        res_id, y_id, y_id, y_id
                    ));
                    out.push_str(&format!("coro.sel_susp_{}:\n", y_id));
                    out.push_str(&format!(
                        "  %coro.sel_tok_{} = call i8 @llvm.coro.suspend(token none, i1 false)\n",
                        y_id
                    ));
                    out.push_str(&format!(
                        "  switch i8 %coro.sel_tok_{}, label %coro.susp_ret [ i8 0, label %coro.sel_poll_{} i8 1, label %coro.cleanup ]\n",
                        y_id, y_id
                    ));
                    out.push_str(&format!("coro.sel_done_{}:\n", y_id));
                    out.push_str(&format!(
                        "  %v{} = phi i64 [ %sel_poll_res_{}_{}, %coro.sel_poll_{} ]\n",
                        res_id, res_id, y_id, y_id
                    ));
                } else if is_coro && *has_default {
                    out.push_str(&format!(
                        "  %v{} = call i64 @ifa_rt_channel_select_table(ptr %select_table_{})\n",
                        res_id, res_id
                    ));
                } else {
                    out.push_str(&format!(
                        "  %v{} = call i64 @ifa_rt_channel_select_wait_table(ptr %select_table_{})\n",
                        res_id, res_id
                    ));
                }
            }
            ValueExpr::Spawn { target, args } => {
                let callee = INTERNER.resolve(target);
                let target_fn = module.functions.iter().find(|f| f.name == *target);
                let is_target_coro = target_fn.map(|f| f.is_coroutine()).unwrap_or(false);

                let param_types = if let Some(tf) = target_fn {
                    tf.params
                        .iter()
                        .map(|p| match &p.ty {
                            ifa_fir::FirType::Array(..) => "ptr".to_string(),
                            _ => fir_to_llvm_type(&p.ty).unwrap_or_else(|_| "i64".to_string()),
                        })
                        .collect()
                } else {
                    vec!["i64".to_string(); args.len()]
                };

                let args_str = Self::emit_call_args(
                    &format!("spawn_arg_{}", res_id),
                    args,
                    &param_types,
                    value_types,
                    null_values,
                    array_allocas,
                    out,
                );

                if is_target_coro {
                    if args.is_empty() {
                        out.push_str(&format!(
                            "  %coro_hdl_{} = call ptr @{}()\n",
                            res_id, callee
                        ));
                    } else {
                        out.push_str(&format!(
                            "  %coro_hdl_{} = call ptr @{}({})\n",
                            res_id,
                            callee,
                            args_str.join(", ")
                        ));
                    }
                    out.push_str(&format!(
                        "  %v{} = call i64 @ifa_coro_llvm_spawn(ptr %coro_hdl_{})\n",
                        res_id, res_id
                    ));
                } else if args.is_empty() {
                    out.push_str(&format!(
                        "  %v{} = call i64 @ifa_rt_fiber_spawn(ptr @{}, ptr null)\n",
                        res_id, callee
                    ));
                } else if args.len() == 1 {
                    let arg = args[0];
                    let arg_ty_str = value_types
                        .get(&arg)
                        .and_then(|t| fir_to_llvm_type(t).ok())
                        .unwrap_or_else(|| "i64".to_string());
                    let ptr_val = if arg_ty_str == "ptr" || array_allocas.contains_key(&arg) {
                        format!("%v{}", arg.0)
                    } else if arg_ty_str.starts_with("%struct.") {
                        out.push_str(&format!(
                            "  %spawn_struct_buf_{} = alloca {}, align 8\n",
                            res_id, arg_ty_str
                        ));
                        out.push_str(&format!(
                            "  store {} %v{}, ptr %spawn_struct_buf_{}, align 8\n",
                            arg_ty_str, arg.0, res_id
                        ));
                        format!("%spawn_struct_buf_{}", res_id)
                    } else {
                        out.push_str(&format!(
                            "  %spawn_arg_ptr_{} = inttoptr i64 %v{} to ptr\n",
                            res_id, arg.0
                        ));
                        format!("%spawn_arg_ptr_{}", res_id)
                    };
                    out.push_str(&format!(
                        "  %v{} = call i64 @ifa_rt_fiber_spawn(ptr @{}, ptr {})\n",
                        res_id, callee, ptr_val
                    ));
                } else {
                    let buf_size = args.len() * 8;
                    out.push_str(&format!(
                        "  %spawn_arg_buf_{} = call ptr @ifa_rt_gen_alloc(i64 {}, i64 8, i16 0)\n",
                        res_id, buf_size
                    ));
                    for (i, arg) in args.iter().enumerate() {
                        let arg_ty_str = value_types
                            .get(arg)
                            .and_then(|t| fir_to_llvm_type(t).ok())
                            .unwrap_or_else(|| "i64".to_string());
                        let val_i64 = if arg_ty_str == "ptr" || array_allocas.contains_key(arg) {
                            out.push_str(&format!(
                                "  %spawn_cast_{}_{} = ptrtoint ptr %v{} to i64\n",
                                res_id, i, arg.0
                            ));
                            format!("%spawn_cast_{}_{}", res_id, i)
                        } else if arg_ty_str.starts_with("%struct.") {
                            out.push_str(&format!(
                                "  %spawn_struct_buf_{}_{} = alloca {}, align 8\n",
                                res_id, i, arg_ty_str
                            ));
                            out.push_str(&format!(
                                "  store {} %v{}, ptr %spawn_struct_buf_{}_{}, align 8\n",
                                arg_ty_str, arg.0, res_id, i
                            ));
                            out.push_str(&format!(
                                "  %spawn_cast_{}_{} = ptrtoint ptr %spawn_struct_buf_{}_{} to i64\n",
                                res_id, i, res_id, i
                            ));
                            format!("%spawn_cast_{}_{}", res_id, i)
                        } else {
                            format!("%v{}", arg.0)
                        };
                        out.push_str(&format!(
                            "  %spawn_slot_{}_{} = getelementptr inbounds i64, ptr %spawn_arg_buf_{}, i32 {}\n",
                            res_id, i, res_id, i
                        ));
                        out.push_str(&format!(
                            "  store i64 {}, ptr %spawn_slot_{}_{}, align 8\n",
                            val_i64, res_id, i
                        ));
                    }
                    out.push_str(&format!(
                        "  %v{} = call i64 @ifa_rt_fiber_spawn(ptr @{}, ptr %spawn_arg_buf_{})\n",
                        res_id, callee, res_id
                    ));
                }
            }
            ValueExpr::EnumInit {
                enum_name,
                discriminant,
                payload,
                ..
            } => {
                let e_name = INTERNER.resolve(enum_name);
                out.push_str(&format!(
                    "  %enum_alloc_{} = alloca %enum.{}, align 8\n",
                    res_id, e_name
                ));
                out.push_str(&format!(
                    "  %disc_ptr_{} = getelementptr inbounds %enum.{}, ptr %enum_alloc_{}, i32 0, i32 0\n",
                    res_id, e_name, res_id
                ));
                out.push_str(&format!(
                    "  store i64 {}, ptr %disc_ptr_{}, align 8\n",
                    discriminant, res_id
                ));
                out.push_str(&format!(
                    "  %pay_ptr_{} = getelementptr inbounds %enum.{}, ptr %enum_alloc_{}, i32 0, i32 1\n",
                    res_id, e_name, res_id
                ));
                if let Some(p_val) = payload {
                    let p_ty_str = value_types
                        .get(p_val)
                        .map(fir_to_llvm_type)
                        .unwrap_or(Ok("i64".to_string()))?;
                    if p_ty_str == "i64" {
                        out.push_str(&format!(
                            "  store i64 %v{}, ptr %pay_ptr_{}, align 8\n",
                            p_val.0, res_id
                        ));
                    } else if p_ty_str == "ptr" {
                        out.push_str(&format!(
                            "  %pay_i64_{} = ptrtoint ptr %v{} to i64\n",
                            res_id, p_val.0
                        ));
                        out.push_str(&format!(
                            "  store i64 %pay_i64_{}, ptr %pay_ptr_{}, align 8\n",
                            res_id, res_id
                        ));
                    } else {
                        out.push_str(&format!(
                            "  store {} %v{}, ptr %pay_ptr_{}, align 8\n",
                            p_ty_str, p_val.0, res_id
                        ));
                    }
                } else {
                    out.push_str(&format!(
                        "  store i64 0, ptr %pay_ptr_{}, align 8\n",
                        res_id
                    ));
                }
                out.push_str(&format!(
                    "  %v{} = load %enum.{}, ptr %enum_alloc_{}, align 8\n",
                    res_id, e_name, res_id
                ));
            }
            ValueExpr::EnumGetDiscriminant { base } => {
                let base_ty = value_types.get(base);
                let e_name = match base_ty {
                    Some(ifa_fir::FirType::Enum(s, _)) => INTERNER.resolve(s),
                    _ => "unknown".to_string(),
                };
                if e_name != "unknown" {
                    out.push_str(&format!(
                        "  %v{} = extractvalue %enum.{} %v{}, 0\n",
                        res_id, e_name, base.0
                    ));
                } else {
                    out.push_str(&format!("  %v{} = add i64 0, %v{}\n", res_id, base.0));
                }
            }
            ValueExpr::EnumGetPayload { base, payload_ty } => {
                let base_ty = value_types.get(base);
                let e_name = match base_ty {
                    Some(ifa_fir::FirType::Enum(s, _)) => INTERNER.resolve(s),
                    _ => "unknown".to_string(),
                };
                let p_ty_str = fir_to_llvm_type(payload_ty)?;
                out.push_str(&format!(
                    "  %raw_pay_{} = extractvalue %enum.{} %v{}, 1\n",
                    res_id, e_name, base.0
                ));
                if p_ty_str == "i64" {
                    out.push_str(&format!(
                        "  %v{} = add i64 0, %raw_pay_{}\n",
                        res_id, res_id
                    ));
                } else if p_ty_str == "ptr" {
                    out.push_str(&format!(
                        "  %v{} = inttoptr i64 %raw_pay_{} to ptr\n",
                        res_id, res_id
                    ));
                } else {
                    out.push_str(&format!(
                        "  %cast_alloca_{} = alloca i64, align 8\n",
                        res_id
                    ));
                    out.push_str(&format!(
                        "  store i64 %raw_pay_{}, ptr %cast_alloca_{}, align 8\n",
                        res_id, res_id
                    ));
                    out.push_str(&format!(
                        "  %v{} = load {}, ptr %cast_alloca_{}, align 8\n",
                        res_id, p_ty_str, res_id
                    ));
                }
            }
            ValueExpr::SliceSub { base, start, end } => {
                let base_ty = value_types.get(base);
                let (elem_ty_str, _) = match base_ty {
                    Some(ifa_fir::FirType::Array(inner, _))
                    | Some(ifa_fir::FirType::Slice(inner)) => (
                        fir_to_llvm_type(inner).unwrap_or_else(|_| "i64".to_string()),
                        llvm_align_for_type(inner),
                    ),
                    Some(ifa_fir::FirType::Pointer(inner)) => match &**inner {
                        ifa_fir::FirType::Array(elem, _) | ifa_fir::FirType::Slice(elem) => (
                            fir_to_llvm_type(elem).unwrap_or_else(|_| "i64".to_string()),
                            llvm_align_for_type(elem),
                        ),
                        _ => ("i64".to_string(), 8),
                    },
                    _ => ("i64".to_string(), 8),
                };

                let base_ptr_op = match base_ty {
                    Some(ifa_fir::FirType::Slice(_)) => {
                        out.push_str(&format!(
                            "  %sub_base_ptr_{} = extractvalue {{ ptr, i64 }} %v{}, 0\n",
                            res_id, base.0
                        ));
                        format!("%sub_base_ptr_{}", res_id)
                    }
                    Some(ifa_fir::FirType::Pointer(inner))
                        if matches!(&**inner, ifa_fir::FirType::Slice(_)) =>
                    {
                        out.push_str(&format!(
                            "  %sub_slice_ld_{} = load {{ ptr, i64 }}, ptr %v{}, align 8\n",
                            res_id, base.0
                        ));
                        out.push_str(&format!(
                            "  %sub_base_ptr_{} = extractvalue {{ ptr, i64 }} %sub_slice_ld_{}, 0\n",
                            res_id, res_id
                        ));
                        format!("%sub_base_ptr_{}", res_id)
                    }
                    Some(ifa_fir::FirType::Array(..)) => array_ptrs
                        .get(base)
                        .cloned()
                        .or_else(|| array_allocas.get(base).map(|p| format!("%v{}", p.0)))
                        .unwrap_or_else(|| format!("%v{}", base.0)),
                    Some(ifa_fir::FirType::Pointer(inner))
                        if matches!(&**inner, ifa_fir::FirType::Array(..)) =>
                    {
                        array_ptrs
                            .get(base)
                            .cloned()
                            .or_else(|| array_allocas.get(base).map(|p| format!("%v{}", p.0)))
                            .unwrap_or_else(|| format!("%v{}", base.0))
                    }
                    _ => array_ptrs
                        .get(base)
                        .cloned()
                        .or_else(|| array_allocas.get(base).map(|p| format!("%v{}", p.0)))
                        .unwrap_or_else(|| format!("%v{}", base.0)),
                };

                out.push_str(&format!(
                    "  %sub_start_ptr_{} = getelementptr inbounds {}, ptr {}, i64 %v{}\n",
                    res_id, elem_ty_str, base_ptr_op, start.0
                ));
                out.push_str(&format!(
                    "  %sub_len_{} = sub i64 %v{}, %v{}\n",
                    res_id, end.0, start.0
                ));
                out.push_str(&format!(
                    "  %slice_t0_{} = insertvalue {{ ptr, i64 }} undef, ptr %sub_start_ptr_{}, 0\n",
                    res_id, res_id
                ));
                out.push_str(&format!(
                    "  %v{} = insertvalue {{ ptr, i64 }} %slice_t0_{}, i64 %sub_len_{}, 1\n",
                    res_id, res_id, res_id
                ));
            }
            ValueExpr::SliceStrided {
                base,
                start,
                end,
                stride,
            } => {
                let base_ty = value_types.get(base);
                let (elem_ty_str, _) = match base_ty {
                    Some(ifa_fir::FirType::Array(inner, _))
                    | Some(ifa_fir::FirType::Slice(inner)) => (
                        fir_to_llvm_type(inner).unwrap_or_else(|_| "i64".to_string()),
                        llvm_align_for_type(inner),
                    ),
                    Some(ifa_fir::FirType::Pointer(inner)) => match &**inner {
                        ifa_fir::FirType::Array(elem, _) | ifa_fir::FirType::Slice(elem) => (
                            fir_to_llvm_type(elem).unwrap_or_else(|_| "i64".to_string()),
                            llvm_align_for_type(elem),
                        ),
                        _ => ("i64".to_string(), 8),
                    },
                    _ => ("i64".to_string(), 8),
                };

                let base_ptr_op = match base_ty {
                    Some(ifa_fir::FirType::Slice(_)) => {
                        out.push_str(&format!(
                            "  %strided_base_ptr_{} = extractvalue {{ ptr, i64 }} %v{}, 0\n",
                            res_id, base.0
                        ));
                        format!("%strided_base_ptr_{}", res_id)
                    }
                    Some(ifa_fir::FirType::Pointer(inner))
                        if matches!(&**inner, ifa_fir::FirType::Slice(_)) =>
                    {
                        out.push_str(&format!(
                            "  %strided_slice_ld_{} = load {{ ptr, i64 }}, ptr %v{}, align 8\n",
                            res_id, base.0
                        ));
                        out.push_str(&format!(
                            "  %strided_base_ptr_{} = extractvalue {{ ptr, i64 }} %strided_slice_ld_{}, 0\n",
                            res_id, res_id
                        ));
                        format!("%strided_base_ptr_{}", res_id)
                    }
                    _ => array_ptrs
                        .get(base)
                        .cloned()
                        .or_else(|| array_allocas.get(base).map(|p| format!("%v{}", p.0)))
                        .unwrap_or_else(|| format!("%v{}", base.0)),
                };

                out.push_str(&format!(
                    "  %strided_start_ptr_{} = getelementptr inbounds {}, ptr {}, i64 %v{}\n",
                    res_id, elem_ty_str, base_ptr_op, start.0
                ));
                out.push_str(&format!(
                    "  %strided_span_{} = sub i64 %v{}, %v{}\n",
                    res_id, end.0, start.0
                ));
                out.push_str(&format!(
                    "  %strided_num_{} = add i64 %strided_span_{}, %v{}\n",
                    res_id, res_id, stride.0
                ));
                out.push_str(&format!(
                    "  %strided_num_adj_{} = sub i64 %strided_num_{}, 1\n",
                    res_id, res_id
                ));
                out.push_str(&format!(
                    "  %strided_len_{} = sdiv i64 %strided_num_adj_{}, %v{}\n",
                    res_id, res_id, stride.0
                ));
                out.push_str(&format!(
                    "  %strided_t0_{} = insertvalue {{ ptr, i64 }} undef, ptr %strided_start_ptr_{}, 0\n",
                    res_id, res_id
                ));
                out.push_str(&format!(
                    "  %v{} = insertvalue {{ ptr, i64 }} %strided_t0_{}, i64 %strided_len_{}, 1\n",
                    res_id, res_id, res_id
                ));
            }
            ValueExpr::SliceStridedBoundsCheck { .. } => {}
            ValueExpr::FormatString(parts) => {
                if parts.is_empty() {
                    out.push_str(&format!(
                        "  %v{} = call ptr @ifa_rt_string_concat(ptr null, ptr null)\n",
                        res_id
                    ));
                } else {
                    Self::emit_llvm_part_to_str_ptr(res_id, 0, parts[0], value_types, out);
                    let mut curr_ptr = format!("%fmt_{}_0", res_id);
                    for (idx, &part) in parts.iter().enumerate().skip(1) {
                        Self::emit_llvm_part_to_str_ptr(res_id, idx, part, value_types, out);
                        let part_ptr = format!("%fmt_{}_{}", res_id, idx);
                        let next_ptr = if idx == parts.len() - 1 {
                            format!("%v{}", res_id)
                        } else {
                            format!("%fmt_acc_{}_{}", res_id, idx)
                        };
                        out.push_str(&format!(
                            "  {} = call ptr @ifa_rt_string_concat(ptr {}, ptr {})\n",
                            next_ptr, curr_ptr, part_ptr
                        ));
                        curr_ptr = next_ptr;
                    }
                    if parts.len() == 1 {
                        out.push_str(&format!(
                            "  %v{} = call ptr @ifa_rt_string_concat(ptr %fmt_{}_0, ptr null)\n",
                            res_id, res_id
                        ));
                    }
                }
            }
            ValueExpr::ArrayLen { array } => match value_types.get(array) {
                Some(ifa_fir::FirType::Array(_, len)) => {
                    out.push_str(&format!("  %v{} = add i64 {}, 0\n", res_id, len));
                }
                Some(ifa_fir::FirType::Slice(_)) => {
                    out.push_str(&format!(
                        "  %v{} = extractvalue {{ ptr, i64 }} %v{}, 1\n",
                        res_id, array.0
                    ));
                }
                Some(ifa_fir::FirType::Pointer(inner)) => match &**inner {
                    ifa_fir::FirType::Array(_, len) => {
                        out.push_str(&format!("  %v{} = add i64 {}, 0\n", res_id, len));
                    }
                    ifa_fir::FirType::Slice(_) => {
                        out.push_str(&format!(
                            "  %slice_len_ld_{} = load {{ ptr, i64 }}, ptr %v{}, align 8\n",
                            res_id, array.0
                        ));
                        out.push_str(&format!(
                            "  %v{} = extractvalue {{ ptr, i64 }} %slice_len_ld_{}, 1\n",
                            res_id, res_id
                        ));
                    }
                    _ => {
                        out.push_str(&format!("  %v{} = add i64 0, 0\n", res_id));
                    }
                },
                _ => {
                    out.push_str(&format!("  %v{} = add i64 0, 0\n", res_id));
                }
            },
            ValueExpr::Yield => {
                if is_coro {
                    let y_id = *coro_yield_idx;
                    *coro_yield_idx += 1;
                    out.push_str(&format!(
                        "  %coro.susp_{} = call i8 @llvm.coro.suspend(token none, i1 false)\n",
                        y_id
                    ));
                    out.push_str(&format!(
                        "  switch i8 %coro.susp_{}, label %coro.susp_ret [ i8 0, label %coro.resume_{} i8 1, label %coro.cleanup ]\n",
                        y_id, y_id
                    ));
                    out.push_str(&format!("coro.resume_{}:\n", y_id));
                    out.push_str(&format!("  %v{} = add i64 0, 0\n", res_id));
                } else {
                    out.push_str("  call void @ifa_rt_fiber_yield()\n");
                    out.push_str(&format!("  %v{} = add i64 0, 0\n", res_id));
                }
            }
            ValueExpr::YieldValue { val } => {
                if is_coro {
                    let y_id = *coro_yield_idx;
                    *coro_yield_idx += 1;
                    let val_ty = value_types.get(val);
                    let val_llvm_ty = val_ty
                        .map(fir_to_llvm_type)
                        .transpose()?
                        .unwrap_or_else(|| "i64".to_string());
                    if val_llvm_ty == "i64" {
                        out.push_str(&format!(
                            "  store i64 %v{}, ptr %coro.yield_slot, align 8\n",
                            val.0
                        ));
                    } else if val_llvm_ty == "ptr" {
                        out.push_str(&format!(
                            "  %coro_ptr_cast_{} = ptrtoint ptr %v{} to i64\n",
                            val.0, val.0
                        ));
                        out.push_str(&format!(
                            "  store i64 %coro_ptr_cast_{}, ptr %coro.yield_slot, align 8\n",
                            val.0
                        ));
                    } else if val_llvm_ty == "float" || val_llvm_ty == "double" {
                        out.push_str(&format!(
                            "  store {} %v{}, ptr %coro.yield_slot, align 8\n",
                            val_llvm_ty, val.0
                        ));
                    } else if val_llvm_ty == "{ ptr, i64 }" {
                        out.push_str(&format!(
                            "  store {{ ptr, i64 }} %v{}, ptr %coro.yield_slot, align 8\n",
                            val.0
                        ));
                    } else {
                        out.push_str(&format!(
                            "  %coro_val_cast_{} = sext {} %v{} to i64\n",
                            val.0, val_llvm_ty, val.0
                        ));
                        out.push_str(&format!(
                            "  store i64 %coro_val_cast_{}, ptr %coro.yield_slot, align 8\n",
                            val.0
                        ));
                    }
                    out.push_str(&format!(
                        "  %coro.susp_{} = call i8 @llvm.coro.suspend(token none, i1 false)\n",
                        y_id
                    ));
                    out.push_str(&format!(
                        "  switch i8 %coro.susp_{}, label %coro.susp_ret [ i8 0, label %coro.resume_{} i8 1, label %coro.cleanup ]\n",
                        y_id, y_id
                    ));
                    out.push_str(&format!("coro.resume_{}:\n", y_id));
                    out.push_str(&format!("  %v{} = add i64 0, %v{}\n", res_id, val.0));
                } else {
                    out.push_str("  call void @ifa_rt_fiber_yield()\n");
                    out.push_str(&format!("  %v{} = add i64 0, %v{}\n", res_id, val.0));
                }
            }
            _ => {
                // Default fallback for intermediate structures
                out.push_str(&format!("  %v{} = add i64 0, 0\n", res_id));
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_effectful_instruction(
        &self,
        expr: &ValueExpr,
        module: &FirModule,
        value_types: &HashMap<ifa_fir::ValueId, ifa_fir::FirType>,
        null_values: &std::collections::HashSet<ifa_fir::ValueId>,
        array_allocas: &HashMap<ifa_fir::ValueId, ifa_fir::ValueId>,
        array_ptrs: &HashMap<ifa_fir::ValueId, String>,
        strided_slice_info: &HashMap<ifa_fir::ValueId, (ifa_fir::ValueId, Option<i64>)>,
        is_coro: bool,
        coro_yield_idx: &mut usize,
        eff_idx: &mut usize,
        out: &mut String,
    ) -> Result<(), LlvmCodegenError> {
        match expr {
            ValueExpr::Store { ptr, val } => {
                let (ty_str, align) = match value_types.get(val) {
                    Some(ty) => (
                        fir_to_llvm_type(ty).unwrap_or_else(|_| "i64".to_string()),
                        llvm_align_for_type(ty),
                    ),
                    _ => match value_types.get(ptr) {
                        Some(ifa_fir::FirType::Pointer(inner)) => (
                            fir_to_llvm_type(inner).unwrap_or_else(|_| "i64".to_string()),
                            llvm_align_for_type(inner),
                        ),
                        _ => ("i64".to_string(), 8),
                    },
                };
                out.push_str(&format!(
                    "  store {} %v{}, ptr %v{}, align {}\n",
                    ty_str, val.0, ptr.0, align
                ));
            }
            ValueExpr::CallDirect { name, args } => {
                let callee = INTERNER.resolve(name);
                let norm_callee = match callee.as_str() {
                    "fs::read_to_string" | "read_to_string" => "ifa_rt_fs_read_to_string",
                    "fs::write_string" | "write_string" => "ifa_rt_fs_write_string",
                    "fs::exists" | "exists" => "ifa_rt_fs_exists",
                    "fs::file_size" | "file_size" => "ifa_rt_fs_file_size",
                    "process::exec" | "exec" => "ifa_rt_process_exec",
                    "process::exec_output" | "exec_output" => "ifa_rt_process_exec_output",
                    "process::exec_stderr" | "exec_stderr" => "ifa_rt_process_exec_stderr",
                    "process::exec_with_stdin" | "exec_with_stdin" => {
                        "ifa_rt_process_exec_with_stdin"
                    }
                    "process::find_linker" | "find_linker" => "ifa_rt_process_find_linker",
                    "process::find_tool" | "find_tool" => "ifa_rt_process_find_tool",
                    "process::env_var" | "env_var" => "ifa_rt_env_var",
                    "process::args_count" | "env::args_count" | "args_count" => "ifa_rt_args_count",
                    "process::args_get" | "env::args_get" | "args_get" => "ifa_rt_args_get",
                    "string_len" | "String::len" => "ifa_rt_string_len",
                    "string_char_at" | "String::char_at" => "ifa_rt_string_char_at",
                    _ => callee.as_str(),
                };
                let callee_name = norm_callee;
                if callee_name == "println" {
                    if let Some(arg) = args.first() {
                        out.push_str(&format!("  call void @ifa_rt_println(ptr %v{})\n", arg.0));
                    } else {
                        out.push_str("  call void @ifa_rt_println(ptr null)\n");
                    }
                } else if callee_name == "print" {
                    if let Some(arg) = args.first() {
                        out.push_str(&format!("  call void @ifa_rt_print(ptr %v{})\n", arg.0));
                    }
                } else if callee_name == "ifa_rt_println_i64" {
                    if let Some(arg) = args.first() {
                        out.push_str(&format!(
                            "  call void @ifa_rt_println_i64(i64 %v{})\n",
                            arg.0
                        ));
                    }
                } else {
                    let (ret_ty_str, param_types) = if let Some(target_fn) =
                        module.functions.iter().find(|f| {
                            f.name == *name
                                || f.name == INTERNER.intern(&callee)
                                || callee.ends_with(&format!("::{}", INTERNER.resolve(&f.name)))
                                || callee.ends_with(&format!("__{}", INTERNER.resolve(&f.name)))
                        }) {
                        let ret_ty = if target_fn.is_coroutine() {
                            "ptr".to_string()
                        } else {
                            fir_to_llvm_type(&target_fn.ret_ty)?
                        };
                        let params: Vec<String> = target_fn
                            .params
                            .iter()
                            .map(|p| {
                                if p.mode == ifa_fir::ParamMode::InOut {
                                    "ptr".to_string()
                                } else {
                                    match &p.ty {
                                        ifa_fir::FirType::Array(..) => "ptr".to_string(),
                                        _ => fir_to_llvm_type(&p.ty)
                                            .unwrap_or_else(|_| "i64".to_string()),
                                    }
                                }
                            })
                            .collect();
                        (ret_ty, params)
                    } else if norm_callee == "ifa_rt_fs_read_to_string" {
                        ("ptr".to_string(), vec!["ptr".to_string()])
                    } else if norm_callee == "ifa_rt_fs_write_string" {
                        ("i1".to_string(), vec!["ptr".to_string(), "ptr".to_string()])
                    } else if norm_callee == "ifa_rt_fs_exists" {
                        ("i1".to_string(), vec!["ptr".to_string()])
                    } else if norm_callee == "ifa_rt_fs_file_size" {
                        ("i64".to_string(), vec!["ptr".to_string()])
                    } else if norm_callee == "ifa_rt_process_exec" {
                        (
                            "i64".to_string(),
                            vec!["ptr".to_string(), "ptr".to_string()],
                        )
                    } else if norm_callee == "ifa_rt_process_exec_output"
                        || norm_callee == "ifa_rt_process_exec_stderr"
                    {
                        (
                            "ptr".to_string(),
                            vec!["ptr".to_string(), "ptr".to_string()],
                        )
                    } else if norm_callee == "ifa_rt_process_exec_with_stdin" {
                        (
                            "i64".to_string(),
                            vec!["ptr".to_string(), "ptr".to_string(), "ptr".to_string()],
                        )
                    } else if norm_callee == "ifa_rt_process_find_linker" {
                        ("ptr".to_string(), Vec::new())
                    } else if norm_callee == "ifa_rt_process_find_tool"
                        || norm_callee == "ifa_rt_env_var"
                    {
                        ("ptr".to_string(), vec!["ptr".to_string()])
                    } else if norm_callee == "ifa_rt_args_count" {
                        ("i64".to_string(), Vec::new())
                    } else if norm_callee == "ifa_rt_args_get" {
                        ("ptr".to_string(), vec!["i64".to_string()])
                    } else if norm_callee == "ifa_rt_string_len" {
                        ("i64".to_string(), vec!["ptr".to_string()])
                    } else if norm_callee == "ifa_rt_string_char_at" {
                        (
                            "i64".to_string(),
                            vec!["ptr".to_string(), "i64".to_string()],
                        )
                    } else if callee.starts_with("ifa_simd_")
                        || callee.starts_with("ifa_simd_arena_")
                    {
                        let is_f32 = callee.ends_with("_f32");
                        let is_f64 = callee.ends_with("_f64");
                        let is_i32 = callee.ends_with("_i32");
                        let _is_i64 = callee.ends_with("_i64");

                        if callee.contains("dot") {
                            let ret = if is_f64 { "double" } else { "float" };
                            (
                                ret.to_string(),
                                vec!["ptr".to_string(), "ptr".to_string(), "i64".to_string()],
                            )
                        } else if callee.contains("count_if") {
                            let thresh_ty = if is_f32 {
                                "float"
                            } else if is_f64 {
                                "double"
                            } else if is_i32 {
                                "i32"
                            } else {
                                "i64"
                            };
                            (
                                "i64".to_string(),
                                vec!["ptr".to_string(), "i64".to_string(), thresh_ty.to_string()],
                            )
                        } else if callee.contains("filter") {
                            let thresh_ty = if is_f32 {
                                "float"
                            } else if is_f64 {
                                "double"
                            } else if is_i32 {
                                "i32"
                            } else {
                                "i64"
                            };
                            (
                                "i64".to_string(),
                                vec![
                                    "ptr".to_string(),
                                    "ptr".to_string(),
                                    "i64".to_string(),
                                    thresh_ty.to_string(),
                                ],
                            )
                        } else if callee.contains("select") || callee.contains("clamp") {
                            let elem_ty = if is_f32 { "float" } else { "i32" };
                            (
                                "void".to_string(),
                                vec![
                                    "ptr".to_string(),
                                    "ptr".to_string(),
                                    "i64".to_string(),
                                    elem_ty.to_string(),
                                    elem_ty.to_string(),
                                ],
                            )
                        } else if callee.contains("sum")
                            || callee.contains("prod")
                            || callee.contains("min")
                            || callee.contains("max")
                        {
                            let ret = if is_f32 {
                                "float"
                            } else if is_f64 {
                                "double"
                            } else if is_i32 {
                                "i32"
                            } else {
                                "i64"
                            };
                            (ret.to_string(), vec!["ptr".to_string(), "i64".to_string()])
                        } else if callee.contains("slice_add")
                            || callee.contains("slice_mul")
                            || callee.contains("slice_xor")
                        {
                            (
                                "void".to_string(),
                                vec![
                                    "ptr".to_string(),
                                    "ptr".to_string(),
                                    "ptr".to_string(),
                                    "i64".to_string(),
                                ],
                            )
                        } else {
                            ("i64".to_string(), vec!["i64".to_string(); args.len()])
                        }
                    } else {
                        ("i64".to_string(), vec!["i64".to_string(); args.len()])
                    };
                    let args_str = Self::emit_call_args(
                        &format!("eff_arg_{}", callee),
                        args,
                        &param_types,
                        value_types,
                        null_values,
                        array_allocas,
                        out,
                    );
                    let is_target_coro = module
                        .functions
                        .iter()
                        .find(|f| f.name == *name)
                        .map(|f| f.is_coroutine())
                        .unwrap_or(false);

                    if is_target_coro {
                        let eff_coro_id = format!("eff_coro_direct_{}", eff_idx);
                        *eff_idx += 1;
                        out.push_str(&format!(
                            "  %{} = call ptr @{}({})\n",
                            eff_coro_id,
                            norm_callee,
                            args_str.join(", ")
                        ));
                        out.push_str(&format!(
                            "  call void @ifa_coro_llvm_run(ptr %{})\n",
                            eff_coro_id
                        ));
                    } else {
                        out.push_str(&format!(
                            "  call {} @{}({})\n",
                            ret_ty_str,
                            norm_callee,
                            args_str.join(", ")
                        ));
                    }
                }
            }
            ValueExpr::BlockingCallDirect { name, args } => {
                let callee = INTERNER.resolve(name);
                let (_, param_types) =
                    if let Some(target_fn) = module.functions.iter().find(|f| f.name == *name) {
                        let ret_ty = fir_to_llvm_type(&target_fn.ret_ty)?;
                        let params: Vec<String> = target_fn
                            .params
                            .iter()
                            .map(|p| {
                                if p.mode == ifa_fir::ParamMode::InOut {
                                    "ptr".to_string()
                                } else {
                                    match &p.ty {
                                        ifa_fir::FirType::Array(..) => "ptr".to_string(),
                                        _ => fir_to_llvm_type(&p.ty)
                                            .unwrap_or_else(|_| "i64".to_string()),
                                    }
                                }
                            })
                            .collect();
                        (ret_ty, params)
                    } else {
                        ("i64".to_string(), vec!["i64".to_string(); args.len()])
                    };

                let eff_id = format!("eff_pack_{}", callee);
                out.push_str(&format!(
                    "  %{} = alloca %struct.ifa_pack_{}, align 8\n",
                    eff_id, callee
                ));
                for (i, a) in args.iter().enumerate() {
                    let p_ty = param_types
                        .get(i)
                        .cloned()
                        .unwrap_or_else(|| "i64".to_string());
                    out.push_str(&format!(
                        "  %eff_arg_slot_{}_{} = getelementptr inbounds %struct.ifa_pack_{}, ptr %{}, i32 0, i32 {}\n",
                        callee, i, callee, eff_id, i
                    ));
                    out.push_str(&format!(
                        "  store {} %v{}, ptr %eff_arg_slot_{}_{}, align 8\n",
                        p_ty, a.0, callee, i
                    ));
                }
                out.push_str(&format!(
                    "  call ptr @ifa_rt_blocking_call(ptr @ifa_thunk_blocking_{}, ptr %{})\n",
                    callee, eff_id
                ));
            }
            ValueExpr::Call { callee, args } => {
                let args_str: Vec<String> = args
                    .iter()
                    .map(|a| {
                        let ty = value_types
                            .get(a)
                            .map(|t| fir_to_llvm_type(t).unwrap_or_else(|_| "i64".to_string()))
                            .unwrap_or_else(|| "i64".to_string());
                        format!("{} %v{}", ty, a.0)
                    })
                    .collect();
                out.push_str(&format!(
                    "  call void %v{}({})\n",
                    callee.0,
                    args_str.join(", ")
                ));
            }
            ValueExpr::GenFree { ptr } => {
                out.push_str(&format!("  call void @ifa_rt_gen_free(ptr %v{})\n", ptr.0));
            }
            ValueExpr::CallArenaRewind { mark } => {
                out.push_str(&format!(
                    "  call void @ifa_rt_call_arena_rewind(i64 %v{})\n",
                    mark.0
                ));
            }
            ValueExpr::GenCheck { ref_val, redundant } => {
                if !*redundant {
                    let ref_ty = value_types.get(ref_val);
                    match ref_ty {
                        Some(ifa_fir::FirType::Optional(inner))
                            if matches!(&**inner, ifa_fir::FirType::GenerationalRef(_)) =>
                        {
                            let opt_ty = fir_to_llvm_type(ref_ty.unwrap())?;
                            let chk_id = *eff_idx;
                            *eff_idx += 1;
                            out.push_str(&format!(
                                "  %gr_chk_{} = extractvalue {} %v{}, 1\n",
                                chk_id, opt_ty, ref_val.0
                            ));
                            out.push_str(&format!(
                                "  %ptr_chk_{} = extractvalue {{ ptr, i32, i16, i16 }} %gr_chk_{}, 0\n",
                                chk_id, chk_id
                            ));
                            out.push_str(&format!(
                                "  %gen_chk_{} = extractvalue {{ ptr, i32, i16, i16 }} %gr_chk_{}, 1\n",
                                chk_id, chk_id
                            ));
                            out.push_str(&format!(
                                "  call void @ifa_rt_gen_check(ptr %ptr_chk_{}, i32 %gen_chk_{})\n",
                                chk_id, chk_id
                            ));
                        }
                        Some(ifa_fir::FirType::GenerationalRef(_)) => {
                            let chk_id = *eff_idx;
                            *eff_idx += 1;
                            out.push_str(&format!(
                                "  %ptr_chk_{} = extractvalue {{ ptr, i32, i16, i16 }} %v{}, 0\n",
                                chk_id, ref_val.0
                            ));
                            out.push_str(&format!(
                                "  %gen_chk_{} = extractvalue {{ ptr, i32, i16, i16 }} %v{}, 1\n",
                                chk_id, ref_val.0
                            ));
                            out.push_str(&format!(
                                "  call void @ifa_rt_gen_check(ptr %ptr_chk_{}, i32 %gen_chk_{})\n",
                                chk_id, chk_id
                            ));
                        }
                        _ => {
                            out.push_str(&format!(
                                "  call void @ifa_rt_gen_check(ptr %v{}, i32 1)\n",
                                ref_val.0
                            ));
                        }
                    }
                }
            }
            ValueExpr::BoundsCheck {
                base,
                index,
                redundant,
            } => {
                if !*redundant {
                    let chk_id = *eff_idx;
                    *eff_idx += 1;
                    let base_ty = value_types.get(base);
                    let len_operand_opt = match base_ty {
                        Some(ifa_fir::FirType::Slice(_)) => {
                            out.push_str(&format!(
                                "  %bce_slice_len_{} = extractvalue {{ ptr, i64 }} %v{}, 1\n",
                                chk_id, base.0
                            ));
                            Some(format!("%bce_slice_len_{}", chk_id))
                        }
                        Some(ifa_fir::FirType::Pointer(inner))
                            if matches!(&**inner, ifa_fir::FirType::Slice(_)) =>
                        {
                            out.push_str(&format!(
                                "  %bce_slice_ld_{} = load {{ ptr, i64 }}, ptr %v{}, align 8\n",
                                chk_id, base.0
                            ));
                            out.push_str(&format!(
                                "  %bce_slice_len_{} = extractvalue {{ ptr, i64 }} %bce_slice_ld_{}, 1\n",
                                chk_id, chk_id
                            ));
                            Some(format!("%bce_slice_len_{}", chk_id))
                        }
                        Some(ifa_fir::FirType::Array(_, count)) => Some(count.to_string()),
                        Some(ifa_fir::FirType::Pointer(inner))
                            if matches!(&**inner, ifa_fir::FirType::Array(..)) =>
                        {
                            if let ifa_fir::FirType::Array(_, count) = &**inner {
                                Some(count.to_string())
                            } else {
                                None
                            }
                        }
                        _ => None,
                    };
                    if let Some(len_operand) = len_operand_opt {
                        out.push_str(&format!(
                            "  call void @ifa_rt_bounds_check(i64 %v{}, i64 {}, ptr null)\n",
                            index.0, len_operand
                        ));
                    }
                }
            }
            ValueExpr::SliceBoundsCheck {
                base,
                start,
                end,
                redundant,
            } => {
                if !*redundant {
                    let chk_id = *eff_idx;
                    *eff_idx += 1;
                    let base_ty = value_types.get(base);
                    let len_operand = match base_ty {
                        Some(ifa_fir::FirType::Slice(_)) => {
                            out.push_str(&format!(
                                "  %bce_sub_len_{} = extractvalue {{ ptr, i64 }} %v{}, 1\n",
                                chk_id, base.0
                            ));
                            format!("%bce_sub_len_{}", chk_id)
                        }
                        Some(ifa_fir::FirType::Pointer(inner))
                            if matches!(&**inner, ifa_fir::FirType::Slice(_)) =>
                        {
                            out.push_str(&format!(
                                "  %bce_sub_ld_{} = load {{ ptr, i64 }}, ptr %v{}, align 8\n",
                                chk_id, base.0
                            ));
                            out.push_str(&format!(
                                "  %bce_sub_len_{} = extractvalue {{ ptr, i64 }} %bce_sub_ld_{}, 1\n",
                                chk_id, chk_id
                            ));
                            format!("%bce_sub_len_{}", chk_id)
                        }
                        Some(ifa_fir::FirType::Array(_, count)) => count.to_string(),
                        Some(ifa_fir::FirType::Pointer(inner))
                            if matches!(&**inner, ifa_fir::FirType::Array(..)) =>
                        {
                            if let ifa_fir::FirType::Array(_, count) = &**inner {
                                count.to_string()
                            } else {
                                "0".to_string()
                            }
                        }
                        _ => "0".to_string(),
                    };
                    out.push_str(&format!(
                        "  call void @ifa_rt_slice_bounds_check(i64 %v{}, i64 %v{}, i64 {}, ptr null)\n",
                        start.0, end.0, len_operand
                    ));
                }
            }
            ValueExpr::SliceStridedBoundsCheck {
                base,
                start,
                end,
                stride,
                redundant,
            } => {
                if !*redundant {
                    let chk_id = *eff_idx;
                    *eff_idx += 1;
                    let base_ty = value_types.get(base);
                    let len_operand = match base_ty {
                        Some(ifa_fir::FirType::Slice(_)) => {
                            out.push_str(&format!(
                                "  %bce_strided_len_{} = extractvalue {{ ptr, i64 }} %v{}, 1\n",
                                chk_id, base.0
                            ));
                            format!("%bce_strided_len_{}", chk_id)
                        }
                        Some(ifa_fir::FirType::Pointer(inner))
                            if matches!(&**inner, ifa_fir::FirType::Slice(_)) =>
                        {
                            out.push_str(&format!(
                                "  %bce_strided_ld_{} = load {{ ptr, i64 }}, ptr %v{}, align 8\n",
                                chk_id, base.0
                            ));
                            out.push_str(&format!(
                                "  %bce_strided_len_{} = extractvalue {{ ptr, i64 }} %bce_strided_ld_{}, 1\n",
                                chk_id, chk_id
                            ));
                            format!("%bce_strided_len_{}", chk_id)
                        }
                        Some(ifa_fir::FirType::Array(_, count)) => count.to_string(),
                        Some(ifa_fir::FirType::Pointer(inner))
                            if matches!(&**inner, ifa_fir::FirType::Array(..)) =>
                        {
                            if let ifa_fir::FirType::Array(_, count) = &**inner {
                                count.to_string()
                            } else {
                                "0".to_string()
                            }
                        }
                        _ => "0".to_string(),
                    };
                    out.push_str(&format!(
                        "  call void @ifa_rt_slice_strided_bounds_check(i64 %v{}, i64 %v{}, i64 %v{}, i64 {}, ptr null)\n",
                        start.0, end.0, stride.0, len_operand
                    ));
                }
            }
            ValueExpr::Yield => {
                if is_coro {
                    let y_id = *coro_yield_idx;
                    *coro_yield_idx += 1;
                    out.push_str(&format!(
                        "  %coro.susp_{} = call i8 @llvm.coro.suspend(token none, i1 false)\n",
                        y_id
                    ));
                    out.push_str(&format!(
                        "  switch i8 %coro.susp_{}, label %coro.susp_ret [ i8 0, label %coro.resume_{} i8 1, label %coro.cleanup ]\n",
                        y_id, y_id
                    ));
                    out.push_str(&format!("coro.resume_{}:\n", y_id));
                } else {
                    out.push_str("  call void @ifa_rt_fiber_yield()\n");
                }
            }
            ValueExpr::YieldValue { val } => {
                if is_coro {
                    let y_id = *coro_yield_idx;
                    *coro_yield_idx += 1;
                    let val_ty = value_types.get(val);
                    let val_llvm_ty = val_ty
                        .map(fir_to_llvm_type)
                        .transpose()?
                        .unwrap_or_else(|| "i64".to_string());
                    if val_llvm_ty == "i64" {
                        out.push_str(&format!(
                            "  store i64 %v{}, ptr %coro.yield_slot, align 8\n",
                            val.0
                        ));
                    } else if val_llvm_ty == "ptr" {
                        out.push_str(&format!(
                            "  %coro_ptr_cast_{} = ptrtoint ptr %v{} to i64\n",
                            val.0, val.0
                        ));
                        out.push_str(&format!(
                            "  store i64 %coro_ptr_cast_{}, ptr %coro.yield_slot, align 8\n",
                            val.0
                        ));
                    } else if val_llvm_ty == "float" || val_llvm_ty == "double" {
                        out.push_str(&format!(
                            "  store {} %v{}, ptr %coro.yield_slot, align 8\n",
                            val_llvm_ty, val.0
                        ));
                    } else if val_llvm_ty == "{ ptr, i64 }" {
                        out.push_str(&format!(
                            "  store {{ ptr, i64 }} %v{}, ptr %coro.yield_slot, align 8\n",
                            val.0
                        ));
                    } else {
                        out.push_str(&format!(
                            "  %coro_val_cast_{} = sext {} %v{} to i64\n",
                            val.0, val_llvm_ty, val.0
                        ));
                        out.push_str(&format!(
                            "  store i64 %coro_val_cast_{}, ptr %coro.yield_slot, align 8\n",
                            val.0
                        ));
                    }
                    out.push_str(&format!(
                        "  %coro.susp_{} = call i8 @llvm.coro.suspend(token none, i1 false)\n",
                        y_id
                    ));
                    out.push_str(&format!(
                        "  switch i8 %coro.susp_{}, label %coro.susp_ret [ i8 0, label %coro.resume_{} i8 1, label %coro.cleanup ]\n",
                        y_id, y_id
                    ));
                    out.push_str(&format!("coro.resume_{}:\n", y_id));
                } else {
                    out.push_str("  call void @ifa_rt_fiber_yield()\n");
                }
            }
            ValueExpr::ChanSend { chan, val } => {
                let is_val_ptr = matches!(
                    value_types.get(val),
                    Some(ifa_fir::FirType::Pointer(_))
                        | Some(ifa_fir::FirType::GenerationalRef(_))
                        | Some(ifa_fir::FirType::Str)
                        | Some(ifa_fir::FirType::String)
                        | Some(ifa_fir::FirType::Struct(..))
                        | Some(ifa_fir::FirType::Enum(..))
                        | Some(ifa_fir::FirType::Array(..))
                        | Some(ifa_fir::FirType::Slice(..))
                        | Some(ifa_fir::FirType::Channel(_))
                        | Some(ifa_fir::FirType::Unit)
                );
                let val_ptr_expr = if is_val_ptr {
                    format!("%v{}", val.0)
                } else {
                    let cast_val = format!("%chan_val_cast_{}", val.0);
                    out.push_str(&format!(
                        "  {} = inttoptr i64 %v{} to ptr\n",
                        cast_val, val.0
                    ));
                    cast_val
                };
                if is_coro {
                    let y_id = *coro_yield_idx;
                    *coro_yield_idx += 1;
                    out.push_str(&format!("  br label %coro.send_poll_{}\n", y_id));
                    out.push_str(&format!("coro.send_poll_{}:\n", y_id));
                    out.push_str(&format!(
                        "  %send_st_{}_{} = call i32 @ifa_rt_channel_try_send(ptr %v{}, ptr {})\n",
                        val.0, y_id, chan.0, val_ptr_expr
                    ));
                    out.push_str(&format!(
                        "  %send_full_{}_{} = icmp eq i32 %send_st_{}_{}, 1\n",
                        val.0, y_id, val.0, y_id
                    ));
                    out.push_str(&format!(
                        "  br i1 %send_full_{}_{}, label %coro.send_susp_{}, label %coro.send_done_{}\n",
                        val.0, y_id, y_id, y_id
                    ));
                    out.push_str(&format!("coro.send_susp_{}:\n", y_id));
                    out.push_str(&format!(
                        "  %coro.send_tok_{} = call i8 @llvm.coro.suspend(token none, i1 false)\n",
                        y_id
                    ));
                    out.push_str(&format!(
                        "  switch i8 %coro.send_tok_{}, label %coro.susp_ret [ i8 0, label %coro.send_poll_{} i8 1, label %coro.cleanup ]\n",
                        y_id, y_id
                    ));
                    out.push_str(&format!("coro.send_done_{}:\n", y_id));
                } else {
                    out.push_str(&format!(
                        "  call i32 @ifa_rt_channel_send(ptr %v{}, ptr {})\n",
                        chan.0, val_ptr_expr
                    ));
                }
            }
            ValueExpr::ChanTrySend { chan, val } => {
                let is_val_ptr = matches!(
                    value_types.get(val),
                    Some(ifa_fir::FirType::Pointer(_))
                        | Some(ifa_fir::FirType::GenerationalRef(_))
                        | Some(ifa_fir::FirType::Str)
                        | Some(ifa_fir::FirType::String)
                        | Some(ifa_fir::FirType::Struct(..))
                        | Some(ifa_fir::FirType::Enum(..))
                        | Some(ifa_fir::FirType::Array(..))
                        | Some(ifa_fir::FirType::Slice(..))
                        | Some(ifa_fir::FirType::Channel(_))
                        | Some(ifa_fir::FirType::Unit)
                );
                let val_ptr_expr = if is_val_ptr {
                    format!("%v{}", val.0)
                } else {
                    let cast_val = format!("%chan_try_eff_val_cast_{}_{}", eff_idx, val.0);
                    out.push_str(&format!(
                        "  {} = inttoptr i64 %v{} to ptr\n",
                        cast_val, val.0
                    ));
                    cast_val
                };
                let id = *eff_idx;
                *eff_idx += 1;
                out.push_str(&format!(
                    "  %chan_try_ign_{} = call i32 @ifa_rt_channel_try_send(ptr %v{}, ptr {})\n",
                    id, chan.0, val_ptr_expr
                ));
            }
            ValueExpr::ChanClose { chan } => {
                out.push_str(&format!(
                    "  call void @ifa_rt_channel_close(ptr %v{})\n",
                    chan.0
                ));
            }
            ValueExpr::SetField {
                base,
                field_idx,
                val,
            } => {
                let _ = base;
                out.push_str(&format!(
                    "  %gep_set_{} = getelementptr inbounds i64, ptr %v{}, i32 {}\n",
                    val.0, base.0, field_idx
                ));
                out.push_str(&format!(
                    "  store i64 %v{}, ptr %gep_set_{}\n",
                    val.0, val.0
                ));
            }
            ValueExpr::SetElement { base, index, val } => {
                let base_ty = value_types.get(base);
                let (elem_ty_str, align) = match base_ty {
                    Some(ifa_fir::FirType::Array(inner, _))
                    | Some(ifa_fir::FirType::Slice(inner)) => (
                        fir_to_llvm_type(inner).unwrap_or_else(|_| "i64".to_string()),
                        llvm_align_for_type(inner),
                    ),
                    Some(ifa_fir::FirType::Pointer(inner)) => match &**inner {
                        ifa_fir::FirType::Array(elem, _) | ifa_fir::FirType::Slice(elem) => (
                            fir_to_llvm_type(elem).unwrap_or_else(|_| "i64".to_string()),
                            llvm_align_for_type(elem),
                        ),
                        _ => ("i64".to_string(), 8),
                    },
                    _ => ("i64".to_string(), 8),
                };
                let ptr_operand = match base_ty {
                    Some(ifa_fir::FirType::Slice(_)) => {
                        out.push_str(&format!(
                            "  %slice_set_ptr_{} = extractvalue {{ ptr, i64 }} %v{}, 0\n",
                            val.0, base.0
                        ));
                        format!("%slice_set_ptr_{}", val.0)
                    }
                    Some(ifa_fir::FirType::Pointer(inner))
                        if matches!(&**inner, ifa_fir::FirType::Slice(_)) =>
                    {
                        out.push_str(&format!(
                            "  %slice_set_ld_{} = load {{ ptr, i64 }}, ptr %v{}, align 8\n",
                            val.0, base.0
                        ));
                        out.push_str(&format!(
                            "  %slice_set_ptr_{} = extractvalue {{ ptr, i64 }} %slice_set_ld_{}, 0\n",
                            val.0, val.0
                        ));
                        format!("%slice_set_ptr_{}", val.0)
                    }
                    _ => array_ptrs
                        .get(base)
                        .cloned()
                        .or_else(|| array_allocas.get(base).map(|p| format!("%v{}", p.0)))
                        .unwrap_or_else(|| format!("%v{}", base.0)),
                };
                let effective_idx = if let Some(&(st_vid, c_opt)) = strided_slice_info.get(base) {
                    if let Some(c) = c_opt {
                        if c == 1 {
                            format!("%v{}", index.0)
                        } else if c > 0 && (c as u64).is_power_of_two() {
                            out.push_str(&format!(
                                "  %strided_set_idx_{} = shl i64 %v{}, {}\n",
                                val.0,
                                index.0,
                                (c as u64).trailing_zeros()
                            ));
                            format!("%strided_set_idx_{}", val.0)
                        } else {
                            out.push_str(&format!(
                                "  %strided_set_idx_{} = mul i64 %v{}, {}\n",
                                val.0, index.0, c
                            ));
                            format!("%strided_set_idx_{}", val.0)
                        }
                    } else {
                        out.push_str(&format!(
                            "  %strided_set_idx_{} = mul i64 %v{}, %v{}\n",
                            val.0, index.0, st_vid.0
                        ));
                        format!("%strided_set_idx_{}", val.0)
                    }
                } else {
                    format!("%v{}", index.0)
                };
                out.push_str(&format!(
                    "  %gep_set_{} = getelementptr inbounds {}, ptr {}, i64 {}\n",
                    val.0, elem_ty_str, ptr_operand, effective_idx
                ));
                out.push_str(&format!(
                    "  store {} %v{}, ptr %gep_set_{}, align {}\n",
                    elem_ty_str, val.0, val.0, align
                ));
            }
            ValueExpr::Spawn { target, args } => {
                let callee = INTERNER.resolve(target);
                let target_fn = module.functions.iter().find(|f| f.name == *target);
                let is_target_coro = target_fn.map(|f| f.is_coroutine()).unwrap_or(false);

                let param_types = if let Some(tf) = target_fn {
                    tf.params
                        .iter()
                        .map(|p| match &p.ty {
                            ifa_fir::FirType::Array(..) => "ptr".to_string(),
                            _ => fir_to_llvm_type(&p.ty).unwrap_or_else(|_| "i64".to_string()),
                        })
                        .collect()
                } else {
                    vec!["i64".to_string(); args.len()]
                };

                let args_str = Self::emit_call_args(
                    &format!("spawn_eff_arg_{}", eff_idx),
                    args,
                    &param_types,
                    value_types,
                    null_values,
                    array_allocas,
                    out,
                );

                if is_target_coro {
                    if args.is_empty() {
                        out.push_str(&format!(
                            "  %coro_eff_hdl_{} = call ptr @{}()\n",
                            eff_idx, callee
                        ));
                    } else {
                        out.push_str(&format!(
                            "  %coro_eff_hdl_{} = call ptr @{}({})\n",
                            eff_idx,
                            callee,
                            args_str.join(", ")
                        ));
                    }
                    out.push_str(&format!(
                        "  call i64 @ifa_coro_llvm_spawn(ptr %coro_eff_hdl_{})\n",
                        eff_idx
                    ));
                } else if args.is_empty() {
                    out.push_str(&format!(
                        "  call i64 @ifa_rt_fiber_spawn(ptr @{}, ptr null)\n",
                        callee
                    ));
                } else if args.len() == 1 {
                    let arg = args[0];
                    let arg_ty_str = value_types
                        .get(&arg)
                        .and_then(|t| fir_to_llvm_type(t).ok())
                        .unwrap_or_else(|| "i64".to_string());
                    let ptr_val = if arg_ty_str == "ptr" || array_allocas.contains_key(&arg) {
                        format!("%v{}", arg.0)
                    } else if arg_ty_str.starts_with("%struct.") {
                        out.push_str(&format!(
                            "  %spawn_eff_struct_buf_{} = alloca {}, align 8\n",
                            eff_idx, arg_ty_str
                        ));
                        out.push_str(&format!(
                            "  store {} %v{}, ptr %spawn_eff_struct_buf_{}, align 8\n",
                            arg_ty_str, arg.0, eff_idx
                        ));
                        format!("%spawn_eff_struct_buf_{}", eff_idx)
                    } else {
                        out.push_str(&format!(
                            "  %spawn_eff_ptr_{} = inttoptr i64 %v{} to ptr\n",
                            eff_idx, arg.0
                        ));
                        format!("%spawn_eff_ptr_{}", eff_idx)
                    };
                    out.push_str(&format!(
                        "  call i64 @ifa_rt_fiber_spawn(ptr @{}, ptr {})\n",
                        callee, ptr_val
                    ));
                } else {
                    let buf_size = args.len() * 8;
                    out.push_str(&format!(
                        "  %spawn_eff_buf_{} = call ptr @ifa_rt_gen_alloc(i64 {}, i64 8, i16 0)\n",
                        eff_idx, buf_size
                    ));
                    for (i, arg) in args.iter().enumerate() {
                        let arg_ty_str = value_types
                            .get(arg)
                            .and_then(|t| fir_to_llvm_type(t).ok())
                            .unwrap_or_else(|| "i64".to_string());
                        let val_i64 = if arg_ty_str == "ptr" || array_allocas.contains_key(arg) {
                            out.push_str(&format!(
                                "  %spawn_eff_cast_{}_{} = ptrtoint ptr %v{} to i64\n",
                                eff_idx, i, arg.0
                            ));
                            format!("%spawn_eff_cast_{}_{}", eff_idx, i)
                        } else if arg_ty_str.starts_with("%struct.") {
                            out.push_str(&format!(
                                "  %spawn_eff_struct_{}_{} = alloca {}, align 8\n",
                                eff_idx, i, arg_ty_str
                            ));
                            out.push_str(&format!(
                                "  store {} %v{}, ptr %spawn_eff_struct_{}_{}, align 8\n",
                                arg_ty_str, arg.0, eff_idx, i
                            ));
                            out.push_str(&format!(
                                "  %spawn_eff_cast_{}_{} = ptrtoint ptr %spawn_eff_struct_{}_{} to i64\n",
                                eff_idx, i, eff_idx, i
                            ));
                            format!("%spawn_eff_cast_{}_{}", eff_idx, i)
                        } else {
                            format!("%v{}", arg.0)
                        };
                        out.push_str(&format!(
                            "  %spawn_eff_slot_{}_{} = getelementptr inbounds i64, ptr %spawn_eff_buf_{}, i32 {}\n",
                            eff_idx, i, eff_idx, i
                        ));
                        out.push_str(&format!(
                            "  store i64 {}, ptr %spawn_eff_slot_{}_{}, align 8\n",
                            val_i64, eff_idx, i
                        ));
                    }
                    out.push_str(&format!(
                        "  call i64 @ifa_rt_fiber_spawn(ptr @{}, ptr %spawn_eff_buf_{})\n",
                        callee, eff_idx
                    ));
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn emit_llvm_part_to_str_ptr(
        res_id: u32,
        step: usize,
        part: ValueId,
        value_types: &HashMap<ValueId, ifa_fir::FirType>,
        out: &mut String,
    ) {
        let ty = value_types.get(&part);
        match ty {
            Some(ifa_fir::FirType::String) | Some(ifa_fir::FirType::Str) => {
                out.push_str(&format!(
                    "  %fmt_{}_{} = bitcast ptr %v{} to ptr\n",
                    res_id, step, part.0
                ));
            }
            Some(ifa_fir::FirType::Int(ity)) => {
                let int_ty_str = match ity {
                    ifa_sema::types::IntType::I8 | ifa_sema::types::IntType::U8 => "i8",
                    ifa_sema::types::IntType::I16 | ifa_sema::types::IntType::U16 => "i16",
                    ifa_sema::types::IntType::I32 | ifa_sema::types::IntType::U32 => "i32",
                    _ => "i64",
                };
                if int_ty_str != "i64" {
                    out.push_str(&format!(
                        "  %fmt_ext_{}_{} = sext {} %v{} to i64\n",
                        res_id, step, int_ty_str, part.0
                    ));
                    out.push_str(&format!(
                        "  %fmt_{}_{} = call ptr @ifa_rt_string_from_i64(i64 %fmt_ext_{}_{})\n",
                        res_id, step, res_id, step
                    ));
                } else {
                    out.push_str(&format!(
                        "  %fmt_{}_{} = call ptr @ifa_rt_string_from_i64(i64 %v{})\n",
                        res_id, step, part.0
                    ));
                }
            }
            Some(ifa_fir::FirType::Float(fty)) => {
                let f_str = match fty {
                    ifa_sema::types::FloatType::F32 => "float",
                    ifa_sema::types::FloatType::F64 => "double",
                };
                if f_str == "float" {
                    out.push_str(&format!(
                        "  %fmt_fpext_{}_{} = fpext float %v{} to double\n",
                        res_id, step, part.0
                    ));
                    out.push_str(&format!(
                        "  %fmt_{}_{} = call ptr @ifa_rt_string_from_f64(double %fmt_fpext_{}_{})\n",
                        res_id, step, res_id, step
                    ));
                } else {
                    out.push_str(&format!(
                        "  %fmt_{}_{} = call ptr @ifa_rt_string_from_f64(double %v{})\n",
                        res_id, step, part.0
                    ));
                }
            }
            Some(ifa_fir::FirType::Bool) => {
                out.push_str(&format!(
                    "  %fmt_{}_{} = call ptr @ifa_rt_string_from_bool(i1 %v{})\n",
                    res_id, step, part.0
                ));
            }
            _ => {
                out.push_str(&format!(
                    "  %fmt_{}_{} = bitcast ptr %v{} to ptr\n",
                    res_id, step, part.0
                ));
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_terminator(
        &self,
        term: &Terminator,
        ret_ty: &ifa_fir::FirType,
        value_types: &HashMap<ifa_fir::ValueId, ifa_fir::FirType>,
        is_main_unit: bool,
        is_coro: bool,
        vector_hint: Option<&ifa_fir::LoopVectorHint>,
        out: &mut String,
    ) -> Result<(), LlvmCodegenError> {
        match term {
            Terminator::Return(val_opt) => {
                if is_coro {
                    if let Some(val) = val_opt {
                        let llvm_ty = fir_to_llvm_type(ret_ty)?;
                        if llvm_ty == "i64" {
                            out.push_str(&format!(
                                "  store i64 %v{}, ptr %coro.yield_slot, align 8\n",
                                val.0
                            ));
                        } else if llvm_ty == "ptr" {
                            out.push_str(&format!(
                                "  %coro_ret_cast_{} = ptrtoint ptr %v{} to i64\n",
                                val.0, val.0
                            ));
                            out.push_str(&format!(
                                "  store i64 %coro_ret_cast_{}, ptr %coro.yield_slot, align 8\n",
                                val.0
                            ));
                        } else if llvm_ty.starts_with('i') {
                            out.push_str(&format!(
                                "  %coro_ret_cast_{} = sext {} %v{} to i64\n",
                                val.0, llvm_ty, val.0
                            ));
                            out.push_str(&format!(
                                "  store i64 %coro_ret_cast_{}, ptr %coro.yield_slot, align 8\n",
                                val.0
                            ));
                        } else if llvm_ty != "void" {
                            out.push_str(&format!(
                                "  store {} %v{}, ptr %coro.yield_slot, align 8\n",
                                llvm_ty, val.0
                            ));
                        }
                    }
                    out.push_str("  br label %coro.final_suspend\n");
                    return Ok(());
                }
                if is_main_unit {
                    out.push_str("  ret i32 0\n");
                    return Ok(());
                }
                let llvm_ty = fir_to_llvm_type(ret_ty)?;
                if llvm_ty == "void" {
                    out.push_str("  ret void\n");
                } else if let Some(val) = val_opt {
                    let val_fir_ty = value_types.get(val);
                    let val_llvm_ty = val_fir_ty
                        .and_then(|t| fir_to_llvm_type(t).ok())
                        .unwrap_or_else(|| llvm_ty.clone());
                    if val_llvm_ty == llvm_ty {
                        out.push_str(&format!("  ret {} %v{}\n", llvm_ty, val.0));
                    } else if val_llvm_ty == "i64"
                        && (llvm_ty == "i32" || llvm_ty == "i16" || llvm_ty == "i8")
                    {
                        let cast_id = format!("ret_trunc_{}", val.0);
                        out.push_str(&format!(
                            "  %{} = trunc i64 %v{} to {}\n",
                            cast_id, val.0, llvm_ty
                        ));
                        out.push_str(&format!("  ret {} %{}\n", llvm_ty, cast_id));
                    } else if (val_llvm_ty == "i32" || val_llvm_ty == "i16" || val_llvm_ty == "i8")
                        && llvm_ty == "i64"
                    {
                        let cast_id = format!("ret_zext_{}", val.0);
                        out.push_str(&format!(
                            "  %{} = zext {} %v{} to i64\n",
                            cast_id, val_llvm_ty, val.0
                        ));
                        out.push_str(&format!("  ret i64 %{}\n", cast_id));
                    } else if val_llvm_ty == "ptr" && llvm_ty == "i64" {
                        let cast_id = format!("ret_ptrtoint_{}", val.0);
                        out.push_str(&format!(
                            "  %{} = ptrtoint ptr %v{} to i64\n",
                            cast_id, val.0
                        ));
                        out.push_str(&format!("  ret i64 %{}\n", cast_id));
                    } else if val_llvm_ty == "i64" && llvm_ty == "ptr" {
                        let cast_id = format!("ret_inttoptr_{}", val.0);
                        out.push_str(&format!(
                            "  %{} = inttoptr i64 %v{} to ptr\n",
                            cast_id, val.0
                        ));
                        out.push_str(&format!("  ret ptr %{}\n", cast_id));
                    } else if (llvm_ty.starts_with('[')
                        || llvm_ty.starts_with('{')
                        || llvm_ty.starts_with("%struct."))
                        && val_llvm_ty == "ptr"
                    {
                        let load_id = format!("ret_load_{}", val.0);
                        out.push_str(&format!(
                            "  %{} = load {}, ptr %v{}, align 8\n",
                            load_id, llvm_ty, val.0
                        ));
                        out.push_str(&format!("  ret {} %{}\n", llvm_ty, load_id));
                    } else {
                        out.push_str(&format!("  ret {} %v{}\n", llvm_ty, val.0));
                    }
                } else {
                    out.push_str("  ret void\n");
                }
            }
            Terminator::Branch { target, .. } => {
                if let Some(hint) = vector_hint {
                    let meta_id = if hint.is_multi_arena_conv
                        || ((hint.is_strided_conv2d || hint.is_strided_conv3d)
                            && (hint.is_elementwise_fused || hint.is_multi_arena_matrix))
                    {
                        match hint.vector_width {
                            2 => 76,
                            4 => 74,
                            16 | 32 => 75,
                            _ => 73,
                        }
                    } else if hint.is_strided_multidim {
                        match hint.vector_width {
                            2 => 68,
                            4 => 66,
                            16 | 32 => 67,
                            _ => 65,
                        }
                    } else if hint.is_strided_conv3d {
                        match hint.vector_width {
                            2 => 56,
                            4 => 54,
                            16 | 32 => 55,
                            _ => 53,
                        }
                    } else if hint.is_strided_conv2d {
                        match hint.vector_width {
                            2 => 60,
                            4 => 58,
                            16 | 32 => 59,
                            _ => 57,
                        }
                    } else if hint.is_strided_loop || hint.loop_stride.is_some() {
                        match hint.vector_width {
                            2 => 64,
                            4 => 62,
                            16 | 32 => 63,
                            _ => 61,
                        }
                    } else if hint.is_tripartite_matrix_reduction {
                        match hint.vector_width {
                            2 => 52,
                            4 => 50,
                            16 | 32 => 51,
                            _ => 49,
                        }
                    } else if hint.is_bipartite_matrix_reduction {
                        match hint.vector_width {
                            2 => 48,
                            4 => 46,
                            16 | 32 => 47,
                            _ => 45,
                        }
                    } else if hint.is_swap {
                        match hint.vector_width {
                            2 => 43,
                            4 => 41,
                            16 | 32 => 42,
                            _ => 40,
                        }
                    } else if hint.is_multi_arena_matrix || hint.is_elementwise_fused {
                        match hint.vector_width {
                            2 => 72,
                            4 => 70,
                            16 | 32 => 71,
                            _ => 69,
                        }
                    } else if hint.is_matrix_kernel || hint.is_tiled || hint.unroll_and_jam {
                        match hint.vector_width {
                            2 => 36,
                            4 => 34,
                            16 | 32 => 35,
                            _ => 33,
                        }
                    } else if hint.local_arena
                        && (hint.contiguous_reduction || hint.predicated_scatter_gather)
                    {
                        match hint.vector_width {
                            2 => 21,
                            4 => 19,
                            16 | 32 => 20,
                            _ => 18,
                        }
                    } else if hint.disjoint_slices {
                        match hint.vector_width {
                            2 => 28,
                            4 => 26,
                            16 | 32 => 27,
                            _ => 23,
                        }
                    } else if hint.is_convolution || hint.sliding_window_size.is_some() {
                        match hint.vector_width {
                            2 => 32,
                            4 => 30,
                            16 | 32 => 31,
                            _ => 29,
                        }
                    } else if hint.predicate_enable
                        || hint.predicated_scatter_gather
                        || hint.is_strict
                    {
                        match hint.vector_width {
                            2 => 17,
                            4 => 15,
                            16 | 32 => 16,
                            _ => 14,
                        }
                    } else {
                        match hint.vector_width {
                            2 => 10,
                            4 => 6,
                            16 | 32 => 8,
                            _ => 1,
                        }
                    };
                    out.push_str(&format!(
                        "  br label %bb{}, !llvm.loop !{}\n",
                        target.0, meta_id
                    ));
                } else {
                    out.push_str(&format!("  br label %bb{}\n", target.0));
                }
            }
            Terminator::BranchCond {
                cond,
                then_block,
                else_block,
                ..
            } => {
                if let Some(hint) = vector_hint {
                    let meta_id = if hint.is_multi_arena_conv
                        || ((hint.is_strided_conv2d || hint.is_strided_conv3d)
                            && (hint.is_elementwise_fused || hint.is_multi_arena_matrix))
                    {
                        match hint.vector_width {
                            2 => 76,
                            4 => 74,
                            16 | 32 => 75,
                            _ => 73,
                        }
                    } else if hint.is_strided_multidim {
                        match hint.vector_width {
                            2 => 68,
                            4 => 66,
                            16 | 32 => 67,
                            _ => 65,
                        }
                    } else if hint.is_strided_conv3d {
                        match hint.vector_width {
                            2 => 56,
                            4 => 54,
                            16 | 32 => 55,
                            _ => 53,
                        }
                    } else if hint.is_strided_conv2d {
                        match hint.vector_width {
                            2 => 60,
                            4 => 58,
                            16 | 32 => 59,
                            _ => 57,
                        }
                    } else if hint.is_strided_loop || hint.loop_stride.is_some() {
                        match hint.vector_width {
                            2 => 64,
                            4 => 62,
                            16 | 32 => 63,
                            _ => 61,
                        }
                    } else if hint.is_tripartite_matrix_reduction {
                        match hint.vector_width {
                            2 => 52,
                            4 => 50,
                            16 | 32 => 51,
                            _ => 49,
                        }
                    } else if hint.is_bipartite_matrix_reduction {
                        match hint.vector_width {
                            2 => 48,
                            4 => 46,
                            16 | 32 => 47,
                            _ => 45,
                        }
                    } else if hint.is_swap {
                        match hint.vector_width {
                            2 => 43,
                            4 => 41,
                            16 | 32 => 42,
                            _ => 40,
                        }
                    } else if hint.is_multi_arena_matrix || hint.is_elementwise_fused {
                        match hint.vector_width {
                            2 => 72,
                            4 => 70,
                            16 | 32 => 71,
                            _ => 69,
                        }
                    } else if hint.is_matrix_kernel || hint.is_tiled || hint.unroll_and_jam {
                        match hint.vector_width {
                            2 => 36,
                            4 => 34,
                            16 | 32 => 35,
                            _ => 33,
                        }
                    } else if hint.local_arena
                        && (hint.contiguous_reduction || hint.predicated_scatter_gather)
                    {
                        match hint.vector_width {
                            2 => 21,
                            4 => 19,
                            16 | 32 => 20,
                            _ => 18,
                        }
                    } else if hint.disjoint_slices {
                        match hint.vector_width {
                            2 => 28,
                            4 => 26,
                            16 | 32 => 27,
                            _ => 23,
                        }
                    } else if hint.is_convolution || hint.sliding_window_size.is_some() {
                        match hint.vector_width {
                            2 => 32,
                            4 => 30,
                            16 | 32 => 31,
                            _ => 29,
                        }
                    } else if hint.predicate_enable
                        || hint.predicated_scatter_gather
                        || hint.is_strict
                    {
                        match hint.vector_width {
                            2 => 17,
                            4 => 15,
                            16 | 32 => 16,
                            _ => 14,
                        }
                    } else {
                        match hint.vector_width {
                            2 => 10,
                            4 => 6,
                            16 | 32 => 8,
                            _ => 1,
                        }
                    };
                    let cond_fir_ty = value_types.get(cond);
                    let cond_llvm_ty = cond_fir_ty
                        .and_then(|t| fir_to_llvm_type(t).ok())
                        .unwrap_or_else(|| "i1".to_string());
                    let cond_expr = if cond_llvm_ty == "i1" {
                        format!("%v{}", cond.0)
                    } else if cond_llvm_ty == "ptr" {
                        let cast_id = format!("br_cond_cast_{}", cond.0);
                        out.push_str(&format!(
                            "  %{} = icmp ne ptr %v{}, null\n",
                            cast_id, cond.0
                        ));
                        format!("%{}", cast_id)
                    } else {
                        let cast_id = format!("br_cond_cast_{}", cond.0);
                        out.push_str(&format!(
                            "  %{} = icmp ne {} %v{}, 0\n",
                            cast_id, cond_llvm_ty, cond.0
                        ));
                        format!("%{}", cast_id)
                    };
                    out.push_str(&format!(
                        "  br i1 {}, label %bb{}, label %bb{}, !llvm.loop !{}\n",
                        cond_expr, then_block.0, else_block.0, meta_id
                    ));
                } else {
                    let cond_fir_ty = value_types.get(cond);
                    let cond_llvm_ty = cond_fir_ty
                        .and_then(|t| fir_to_llvm_type(t).ok())
                        .unwrap_or_else(|| "i1".to_string());
                    let cond_expr = if cond_llvm_ty == "i1" {
                        format!("%v{}", cond.0)
                    } else if cond_llvm_ty == "ptr" {
                        let cast_id = format!("br_cond_cast_{}", cond.0);
                        out.push_str(&format!(
                            "  %{} = icmp ne ptr %v{}, null\n",
                            cast_id, cond.0
                        ));
                        format!("%{}", cast_id)
                    } else {
                        let cast_id = format!("br_cond_cast_{}", cond.0);
                        out.push_str(&format!(
                            "  %{} = icmp ne {} %v{}, 0\n",
                            cast_id, cond_llvm_ty, cond.0
                        ));
                        format!("%{}", cast_id)
                    };
                    out.push_str(&format!(
                        "  br i1 {}, label %bb{}, label %bb{}\n",
                        cond_expr, then_block.0, else_block.0
                    ));
                }
            }
            Terminator::Fail(val) => {
                let llvm_ty = fir_to_llvm_type(ret_ty)?;
                if llvm_ty != "void" {
                    out.push_str(&format!("  ret {} %v{}\n", llvm_ty, val.0));
                } else {
                    out.push_str("  unreachable\n");
                }
            }
            Terminator::Unreachable => {
                out.push_str("  unreachable\n");
            }
            Terminator::Switch { .. } => {
                out.push_str("  unreachable\n");
            }
        }
        Ok(())
    }
}

fn escape_llvm_string(s: &str) -> String {
    let mut escaped = String::new();
    for b in s.bytes() {
        if b == b'\\' || b == b'"' || !(32..=126).contains(&b) {
            escaped.push_str(&format!("\\{:02X}", b));
        } else {
            escaped.push(b as char);
        }
    }
    escaped
}

pub(crate) fn fir_type_from_elem_name(elem_name: &str) -> ifa_fir::FirType {
    if elem_name == "string" || elem_name == "String" {
        ifa_fir::FirType::String
    } else if elem_name == "i64" || elem_name == "int" {
        ifa_fir::FirType::Int(ifa_sema::types::IntType::I64)
    } else if elem_name == "i32" {
        ifa_fir::FirType::Int(ifa_sema::types::IntType::I32)
    } else if elem_name == "bool" {
        ifa_fir::FirType::Bool
    } else if let Some(inner) = elem_name.strip_prefix("opt_ref_") {
        ifa_fir::FirType::Optional(Box::new(ifa_fir::FirType::GenerationalRef(Box::new(
            fir_type_from_elem_name(inner),
        ))))
    } else if let Some(inner) = elem_name.strip_prefix("ref_") {
        ifa_fir::FirType::GenerationalRef(Box::new(fir_type_from_elem_name(inner)))
    } else if let Some(inner) = elem_name.strip_prefix("opt_") {
        ifa_fir::FirType::Optional(Box::new(fir_type_from_elem_name(inner)))
    } else {
        ifa_fir::FirType::Struct(INTERNER.intern(elem_name), Vec::new())
    }
}

fn llvm_align_for_type(ty: &ifa_fir::FirType) -> u32 {
    match ty {
        ifa_fir::FirType::Int(i) => match i {
            ifa_sema::types::IntType::I8 | ifa_sema::types::IntType::U8 => 1,
            ifa_sema::types::IntType::I16 | ifa_sema::types::IntType::U16 => 2,
            ifa_sema::types::IntType::I32 | ifa_sema::types::IntType::U32 => 4,
            _ => 8,
        },
        ifa_fir::FirType::Float(f) => match f {
            ifa_sema::types::FloatType::F32 => 4,
            ifa_sema::types::FloatType::F64 => 8,
        },
        ifa_fir::FirType::Bool | ifa_fir::FirType::Char => 1,
        ifa_fir::FirType::Array(elem, len) => {
            let elem_align = llvm_align_for_type(elem);
            let total_bytes = (*len as usize) * (elem_align as usize);
            if total_bytes >= 64 {
                64
            } else if total_bytes >= 32 {
                32
            } else if total_bytes >= 16 {
                16
            } else {
                elem_align.max(8)
            }
        }
        _ => 8,
    }
}

fn format_llvm_float(val: f64) -> String {
    let s = format!("{:e}", val);
    if !s.contains('.') {
        if let Some(pos) = s.find('e') {
            format!("{}.0{}", &s[..pos], &s[pos..])
        } else {
            format!("{}.0", s)
        }
    } else {
        s
    }
}

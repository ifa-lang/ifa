use crate::error::LlvmCodegenError;
use crate::target::{LlvmTargetConfig, TargetArch};
use crate::types::fir_to_llvm_type;
use ifa_fir::{
    BinaryOp, BlockId, ConstantValue, FirFunction, FirModule, Terminator, UnaryOp, ValueExpr,
    ValueId,
};
use ifa_span::INTERNER;
use std::collections::{HashMap, HashSet};

/// Emits canonical textual LLVM IR (.ll) from FIR SSA modules.
pub struct LlvmIrEmitter<'a> {
    target: &'a LlvmTargetConfig,
    string_literals: HashMap<String, String>,
    next_str_id: usize,
}

impl<'a> LlvmIrEmitter<'a> {
    /// Create a new LLVM IR emitter configured for the specified target architecture.
    pub fn new(target: &'a LlvmTargetConfig) -> Self {
        Self {
            target,
            string_literals: HashMap::new(),
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
            out.push_str("declare i64 @ifa_rt_channel_select(ptr, i64, i32)\n");
            out.push_str("declare void @ifa_rt_panic_uaf(ptr, i32, i32)\n");
            out.push_str("declare ptr @ifa_rt_string_concat(ptr, ptr)\n");
            out.push_str("declare ptr @ifa_rt_string_from_i64(i64)\n");
            out.push_str("declare ptr @ifa_rt_string_from_f64(double)\n");
            out.push_str("declare ptr @ifa_rt_string_from_bool(i1)\n");
            out.push_str("declare i64 @ifa_rt_blocking_spawn(ptr, ptr, ptr, ptr)\n");
            out.push_str("declare void @ifa_rt_bounds_check(i64, i64, ptr)\n");
            out.push_str("declare void @ifa_rt_slice_bounds_check(i64, i64, i64, ptr)\n");
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
            out.push_str("declare i64 @ifa_rt_coro_pending_io_count()\n\n");
        } else {
            out.push_str("; IFA Runtime Intrinsic Declarations\n");
            out.push_str("declare void @ifa_rt_println(ptr)\n");
            out.push_str("declare void @ifa_rt_print(ptr)\n");
            out.push_str("declare void @ifa_rt_println_i64(i64)\n");
            out.push_str("declare void @ifa_rt_print_i64(i64)\n");
            out.push_str("declare ptr @ifa_rt_gen_alloc(i64, i64, i16)\n");
            out.push_str("declare void @ifa_rt_gen_free(ptr)\n");
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
            out.push_str("declare i64 @ifa_rt_channel_select(ptr, i64, i32)\n");
            out.push_str("declare void @ifa_rt_panic_uaf(ptr, i32, i32)\n");
            out.push_str("declare ptr @ifa_rt_string_concat(ptr, ptr)\n");
            out.push_str("declare ptr @ifa_rt_string_from_i64(i64)\n");
            out.push_str("declare ptr @ifa_rt_string_from_f64(double)\n");
            out.push_str("declare ptr @ifa_rt_string_from_bool(i1)\n");
            out.push_str("declare i64 @ifa_rt_blocking_spawn(ptr, ptr, ptr, ptr)\n");
            out.push_str("declare void @ifa_rt_bounds_check(i64, i64, ptr)\n");
            out.push_str("declare void @ifa_rt_slice_bounds_check(i64, i64, i64, ptr)\n");
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
            out.push_str("declare i64 @ifa_rt_coro_pending_io_count()\n\n");
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
        out.push_str("declare i64 @llvm.vector.reduce.smax.v4i64(<4 x i64>)\n\n");

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
        let mut declared_structs = std::collections::HashSet::new();
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

        // Also emit synthesized structure definitions (e.g. closures, environment records)
        let mut synthesized_structs: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        for func in &module.functions {
            for block in &func.blocks {
                for inst in &block.instructions {
                    if let ValueExpr::StructInit { name, fields } = &inst.expr {
                        let st_name = INTERNER.resolve(name);
                        if !declared_structs.contains(&st_name)
                            && !synthesized_structs.contains_key(&st_name)
                        {
                            synthesized_structs.insert(st_name, fields.len());
                        }
                    }
                }
            }
        }
        if !synthesized_structs.is_empty() {
            out.push_str("; Synthesized Closure & Environment Structure Definitions\n");
            for (st_name, field_count) in synthesized_structs {
                let field_types = vec!["i64"; field_count.max(1)];
                out.push_str(&format!(
                    "%struct.{} = type {{ {} }}\n",
                    st_name,
                    field_types.join(", ")
                ));
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
                    .map(|p| match &p.ty {
                        ifa_fir::FirType::Array(..) => "ptr".to_string(),
                        _ => fir_to_llvm_type(&p.ty).unwrap_or_else(|_| "i64".to_string()),
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
            "attributes #0 = {{ mustprogress nofree nosync nounwind willreturn memory(none) \"target-cpu\"=\"{}\" \"target-features\"=\"{}\" \"no-trapping-math\"=\"true\" }}\n",
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
                let ty = match &p.ty {
                    ifa_fir::FirType::Array(..) => "ptr".to_string(),
                    _ => fir_to_llvm_type(&p.ty).unwrap_or_else(|_| "ptr".to_string()),
                };
                format!("{} %v{}", ty, p.val.0)
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
        for p in &func.params {
            value_types.insert(p.val, p.ty.clone());
        }
        for block in &func.blocks {
            for (p_id, p_ty) in &block.params {
                value_types.insert(*p_id, p_ty.clone());
            }
            for inst in &block.instructions {
                if let Some(res) = inst.result {
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
                                _ => ifa_fir::FirType::Int(ifa_sema::types::IntType::I64),
                            },
                            _ => ifa_fir::FirType::Int(ifa_sema::types::IntType::I64),
                        },
                        ValueExpr::SliceSub { base, .. } => match value_types.get(base) {
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
                        },
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
                            if callee.starts_with("ifa_simd_") {
                                if callee.ends_with("_f32")
                                    && (callee.contains("dot") || callee.contains("sum"))
                                {
                                    ifa_fir::FirType::Float(ifa_sema::types::FloatType::F32)
                                } else if callee.ends_with("_f64")
                                    && (callee.contains("dot") || callee.contains("sum"))
                                {
                                    ifa_fir::FirType::Float(ifa_sema::types::FloatType::F64)
                                } else if callee.ends_with("_i32") && callee.contains("sum") {
                                    ifa_fir::FirType::Int(ifa_sema::types::IntType::I32)
                                } else if callee.ends_with("_i64") && callee.contains("sum") {
                                    ifa_fir::FirType::Int(ifa_sema::types::IntType::I64)
                                } else if callee.contains("slice_add")
                                    || callee.contains("slice_mul")
                                    || callee.contains("slice_xor")
                                {
                                    ifa_fir::FirType::Unit
                                } else {
                                    ifa_fir::FirType::Int(ifa_sema::types::IntType::I64)
                                }
                            } else if let Some(target_fn) =
                                module.functions.iter().find(|f| f.name == *name)
                            {
                                if target_fn.is_coroutine() {
                                    ifa_fir::FirType::Pointer(Box::new(ifa_fir::FirType::Unit))
                                } else {
                                    target_fn.ret_ty.clone()
                                }
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
                            Some(ifa_fir::FirType::GenerationalRef(inner)) => (**inner).clone(),
                            _ => ifa_fir::FirType::Pointer(Box::new(ifa_fir::FirType::Int(
                                ifa_sema::types::IntType::I64,
                            ))),
                        },
                        ValueExpr::GetFieldPtr {
                            base, field_idx, ..
                        } => match value_types.get(base) {
                            Some(ifa_fir::FirType::Pointer(inner)) => match &**inner {
                                ifa_fir::FirType::Struct(_, fields)
                                    if *field_idx < fields.len() =>
                                {
                                    ifa_fir::FirType::Pointer(Box::new(
                                        fields[*field_idx].1.clone(),
                                    ))
                                }
                                _ => ifa_fir::FirType::Pointer(Box::new(ifa_fir::FirType::Int(
                                    ifa_sema::types::IntType::I64,
                                ))),
                            },
                            Some(ifa_fir::FirType::Struct(_, fields))
                                if *field_idx < fields.len() =>
                            {
                                ifa_fir::FirType::Pointer(Box::new(fields[*field_idx].1.clone()))
                            }
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
        for block in &func.blocks {
            for inst in &block.instructions {
                if let (Some(res), ValueExpr::Load { ptr }) = (inst.result, &inst.expr) {
                    if let Some(ifa_fir::FirType::Pointer(inner)) = value_types.get(ptr) {
                        if matches!(&**inner, ifa_fir::FirType::Array(..)) {
                            array_allocas.insert(res, *ptr);
                        }
                    }
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
                out.push_str("  %coro.yield_slot = alloca i64, align 8\n");
                out.push_str(
                    "  %coro.id = call token @llvm.coro.id(i32 0, ptr %coro.yield_slot, ptr null, ptr null)\n",
                );
                if self.target.arch == TargetArch::Wasm32Wasi {
                    out.push_str("  %coro.size.32 = call i32 @llvm.coro.size.i32()\n");
                    out.push_str("  %coro.size = zext i32 %coro.size.32 to i64\n");
                } else {
                    out.push_str("  %coro.size = call i64 @llvm.coro.size.i64()\n");
                }
                out.push_str(
                    "  %coro.alloc = call ptr @ifa_rt_gen_alloc(i64 %coro.size, i64 8, i16 0)\n",
                );
                out.push_str(
                    "  %coro.hdl = call ptr @llvm.coro.begin(token %coro.id, ptr %coro.alloc)\n",
                );
                out.push_str("  store i64 0, ptr %coro.yield_slot, align 8\n");
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
                        &array_allocas,
                        is_coro,
                        &mut coro_yield_idx,
                        out,
                    )?;
                } else {
                    self.emit_effectful_instruction(
                        &inst.expr,
                        module,
                        &value_types,
                        &array_allocas,
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
                if let Some(p) = array_allocas.get(a) {
                    args_str.push(format!("ptr %v{}", p.0));
                } else {
                    args_str.push(format!("ptr %v{}", a.0));
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
        array_allocas: &HashMap<ifa_fir::ValueId, ifa_fir::ValueId>,
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
                let callee_name = &callee;
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
                        module.functions.iter().find(|f| f.name == *name)
                    {
                        let ret_ty = if target_fn.is_coroutine() {
                            "ptr".to_string()
                        } else {
                            fir_to_llvm_type(&target_fn.ret_ty)?
                        };
                        let params: Vec<String> = target_fn
                            .params
                            .iter()
                            .map(|p| match &p.ty {
                                ifa_fir::FirType::Array(..) => "ptr".to_string(),
                                _ => fir_to_llvm_type(&p.ty).unwrap_or_else(|_| "i64".to_string()),
                            })
                            .collect();
                        (ret_ty, params)
                    } else if callee.starts_with("ifa_simd_") {
                        if callee.ends_with("_f32")
                            && (callee.contains("dot") || callee.contains("sum"))
                        {
                            let p_types = if callee.contains("dot") {
                                vec!["ptr".to_string(), "ptr".to_string(), "i64".to_string()]
                            } else {
                                vec!["ptr".to_string(), "i64".to_string()]
                            };
                            ("float".to_string(), p_types)
                        } else if callee.ends_with("_f64")
                            && (callee.contains("dot") || callee.contains("sum"))
                        {
                            let p_types = if callee.contains("dot") {
                                vec!["ptr".to_string(), "ptr".to_string(), "i64".to_string()]
                            } else {
                                vec!["ptr".to_string(), "i64".to_string()]
                            };
                            ("double".to_string(), p_types)
                        } else if callee.ends_with("_i32") && callee.contains("sum") {
                            (
                                "i32".to_string(),
                                vec!["ptr".to_string(), "i64".to_string()],
                            )
                        } else if callee.ends_with("_i64") && callee.contains("sum") {
                            (
                                "i64".to_string(),
                                vec!["ptr".to_string(), "i64".to_string()],
                            )
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
                        array_allocas,
                        out,
                    );

                    if ret_ty_str == "void" {
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
                            .map(|p| match &p.ty {
                                ifa_fir::FirType::Array(..) => "ptr".to_string(),
                                _ => fir_to_llvm_type(&p.ty).unwrap_or_else(|_| "i64".to_string()),
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
                out.push_str(&format!(
                    "  %v{} = call ptr @ifa_rt_gen_alloc(i64 {}, i64 {}, i16 {})\n",
                    res_id, size, align, arena_id
                ));
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
                out.push_str(&format!(
                    "  %v{} = getelementptr inbounds i64, ptr %v{}, i32 {}\n",
                    res_id, base.0, field_idx
                ));
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
                    _ => array_allocas
                        .get(base)
                        .map(|p| format!("%v{}", p.0))
                        .unwrap_or_else(|| format!("%v{}", base.0)),
                };
                out.push_str(&format!(
                    "  %v{} = getelementptr inbounds {}, ptr {}, i64 %v{}\n",
                    res_id, elem_ty_str, ptr_operand, index.0
                ));
            }
            ValueExpr::GenRef { ptr } | ValueExpr::GenDeref { ref_val: ptr } => {
                out.push_str(&format!(
                    "  %v{} = getelementptr i8, ptr %v{}, i64 0\n",
                    res_id, ptr.0
                ));
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
                        _ => ("i64".to_string(), 8),
                    },
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
                    Some(ifa_fir::FirType::Array(..)) => array_allocas
                        .get(base)
                        .map(|p| format!("%v{}", p.0))
                        .unwrap_or_else(|| format!("%v{}", base.0)),
                    Some(ifa_fir::FirType::Pointer(inner))
                        if matches!(&**inner, ifa_fir::FirType::Array(..)) =>
                    {
                        array_allocas
                            .get(base)
                            .map(|p| format!("%v{}", p.0))
                            .unwrap_or_else(|| format!("%v{}", base.0))
                    }
                    _ => array_allocas
                        .get(base)
                        .map(|p| format!("%v{}", p.0))
                        .unwrap_or_else(|| format!("%v{}", base.0)),
                };
                out.push_str(&format!(
                    "  %gep_{} = getelementptr inbounds {}, ptr {}, i64 %v{}\n",
                    res_id, elem_ty_str, ptr_operand, index.0
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
            ValueExpr::ChanSelect {
                channels,
                has_default,
            } => {
                let n = channels.len();
                let arr_len = n.max(1);
                out.push_str(&format!(
                    "  %select_arr_{} = alloca [{} x ptr], align 8\n",
                    res_id, arr_len
                ));
                for (i, chan_id) in channels.iter().enumerate() {
                    out.push_str(&format!(
                        "  %select_elem_{}_{} = getelementptr inbounds [{} x ptr], ptr %select_arr_{}, i64 0, i64 {}\n",
                        res_id, i, arr_len, res_id, i
                    ));
                    out.push_str(&format!(
                        "  store ptr %v{}, ptr %select_elem_{}_{}, align 8\n",
                        chan_id.0, res_id, i
                    ));
                }
                if is_coro && !has_default {
                    let y_id = *coro_yield_idx;
                    *coro_yield_idx += 1;
                    out.push_str(&format!("  br label %coro.sel_poll_{}\n", y_id));
                    out.push_str(&format!("coro.sel_poll_{}:\n", y_id));
                    out.push_str(&format!(
                        "  %sel_poll_res_{}_{} = call i64 @ifa_rt_channel_select(ptr %select_arr_{}, i64 {}, i32 1)\n",
                        res_id, y_id, res_id, n
                    ));
                    out.push_str(&format!(
                        "  %sel_is_waiting_{}_{} = icmp eq i64 %sel_poll_res_{}_{}, {}\n",
                        res_id, y_id, res_id, y_id, n
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
                } else {
                    out.push_str(&format!(
                        "  %v{} = call i64 @ifa_rt_channel_select(ptr %select_arr_{}, i64 {}, i32 {})\n",
                        res_id,
                        res_id,
                        n,
                        if *has_default { 1 } else { 0 }
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
                    Some(ifa_fir::FirType::Array(..)) => array_allocas
                        .get(base)
                        .map(|p| format!("%v{}", p.0))
                        .unwrap_or_else(|| format!("%v{}", base.0)),
                    Some(ifa_fir::FirType::Pointer(inner))
                        if matches!(&**inner, ifa_fir::FirType::Array(..)) =>
                    {
                        array_allocas
                            .get(base)
                            .map(|p| format!("%v{}", p.0))
                            .unwrap_or_else(|| format!("%v{}", base.0))
                    }
                    _ => array_allocas
                        .get(base)
                        .map(|p| format!("%v{}", p.0))
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
        array_allocas: &HashMap<ifa_fir::ValueId, ifa_fir::ValueId>,
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
                if callee == "println" {
                    if let Some(arg) = args.first() {
                        out.push_str(&format!("  call void @ifa_rt_println(ptr %v{})\n", arg.0));
                    } else {
                        out.push_str("  call void @ifa_rt_println(ptr null)\n");
                    }
                } else if callee == "print" {
                    if let Some(arg) = args.first() {
                        out.push_str(&format!("  call void @ifa_rt_print(ptr %v{})\n", arg.0));
                    }
                } else if callee == "ifa_rt_println_i64" {
                    if let Some(arg) = args.first() {
                        out.push_str(&format!(
                            "  call void @ifa_rt_println_i64(i64 %v{})\n",
                            arg.0
                        ));
                    }
                } else {
                    let (ret_ty_str, param_types) = if let Some(target_fn) =
                        module.functions.iter().find(|f| f.name == *name)
                    {
                        let ret_ty = if target_fn.is_coroutine() {
                            "ptr".to_string()
                        } else {
                            fir_to_llvm_type(&target_fn.ret_ty)?
                        };
                        let params: Vec<String> = target_fn
                            .params
                            .iter()
                            .map(|p| match &p.ty {
                                ifa_fir::FirType::Array(..) => "ptr".to_string(),
                                _ => fir_to_llvm_type(&p.ty).unwrap_or_else(|_| "i64".to_string()),
                            })
                            .collect();
                        (ret_ty, params)
                    } else if callee.starts_with("ifa_simd_") {
                        if callee.ends_with("_f32")
                            && (callee.contains("dot") || callee.contains("sum"))
                        {
                            let p_types = if callee.contains("dot") {
                                vec!["ptr".to_string(), "ptr".to_string(), "i64".to_string()]
                            } else {
                                vec!["ptr".to_string(), "i64".to_string()]
                            };
                            ("float".to_string(), p_types)
                        } else if callee.ends_with("_f64")
                            && (callee.contains("dot") || callee.contains("sum"))
                        {
                            let p_types = if callee.contains("dot") {
                                vec!["ptr".to_string(), "ptr".to_string(), "i64".to_string()]
                            } else {
                                vec!["ptr".to_string(), "i64".to_string()]
                            };
                            ("double".to_string(), p_types)
                        } else if callee.ends_with("_i32") && callee.contains("sum") {
                            (
                                "i32".to_string(),
                                vec!["ptr".to_string(), "i64".to_string()],
                            )
                        } else if callee.ends_with("_i64") && callee.contains("sum") {
                            (
                                "i64".to_string(),
                                vec!["ptr".to_string(), "i64".to_string()],
                            )
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
                        array_allocas,
                        out,
                    );
                    out.push_str(&format!(
                        "  call {} @{}({})\n",
                        ret_ty_str,
                        callee,
                        args_str.join(", ")
                    ));
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
                            .map(|p| match &p.ty {
                                ifa_fir::FirType::Array(..) => "ptr".to_string(),
                                _ => fir_to_llvm_type(&p.ty).unwrap_or_else(|_| "i64".to_string()),
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
            ValueExpr::GenCheck { ref_val, redundant } => {
                if !*redundant {
                    out.push_str(&format!(
                        "  call void @ifa_rt_gen_check(ptr %v{}, i32 1)\n",
                        ref_val.0
                    ));
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
                    let len_operand = match base_ty {
                        Some(ifa_fir::FirType::Slice(_)) => {
                            out.push_str(&format!(
                                "  %bce_slice_len_{} = extractvalue {{ ptr, i64 }} %v{}, 1\n",
                                chk_id, base.0
                            ));
                            format!("%bce_slice_len_{}", chk_id)
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
                            format!("%bce_slice_len_{}", chk_id)
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
                        "  call void @ifa_rt_bounds_check(i64 %v{}, i64 {}, ptr null)\n",
                        index.0, len_operand
                    ));
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
                out.push_str(&format!(
                    "  call i32 @ifa_rt_channel_send(ptr %v{}, ptr {})\n",
                    chan.0, val_ptr_expr
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
                    _ => format!("%v{}", base.0),
                };
                out.push_str(&format!(
                    "  %gep_set_{} = getelementptr inbounds {}, ptr {}, i64 %v{}\n",
                    val.0, elem_ty_str, ptr_operand, index.0
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

    fn emit_terminator(
        &self,
        term: &Terminator,
        ret_ty: &ifa_fir::FirType,
        is_main_unit: bool,
        is_coro: bool,
        vector_hint: Option<&ifa_fir::LoopVectorHint>,
        out: &mut String,
    ) -> Result<(), LlvmCodegenError> {
        match term {
            Terminator::Return(val_opt) => {
                if is_coro {
                    out.push_str("  br label %coro.cleanup\n");
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
                    out.push_str(&format!("  ret {} %v{}\n", llvm_ty, val.0));
                } else {
                    out.push_str("  ret void\n");
                }
            }
            Terminator::Branch { target, .. } => {
                if let Some(hint) = vector_hint {
                    let meta_id = match hint.vector_width {
                        2 => 10,
                        4 => 6,
                        16 | 32 => 8,
                        _ => 1,
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
                    let meta_id = match hint.vector_width {
                        2 => 10,
                        4 => 6,
                        16 | 32 => 8,
                        _ => 1,
                    };
                    out.push_str(&format!(
                        "  br i1 %v{}, label %bb{}, label %bb{}, !llvm.loop !{}\n",
                        cond.0, then_block.0, else_block.0, meta_id
                    ));
                } else {
                    out.push_str(&format!(
                        "  br i1 %v{}, label %bb{}, label %bb{}\n",
                        cond.0, then_block.0, else_block.0
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

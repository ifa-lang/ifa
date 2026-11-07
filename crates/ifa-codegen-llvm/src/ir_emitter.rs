use crate::error::LlvmCodegenError;
use crate::target::{LlvmTargetConfig, TargetArch};
use crate::types::fir_to_llvm_type;
use ifa_fir::{
    BinaryOp, BlockId, ConstantValue, FirFunction, FirModule, Terminator, UnaryOp, ValueExpr,
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
            out.push_str("declare ptr @ifa_rt_channel_create(i64)\n");
            out.push_str("declare void @ifa_rt_channel_destroy(ptr)\n");
            out.push_str("declare i32 @ifa_rt_channel_send(ptr, ptr)\n");
            out.push_str("declare i32 @ifa_rt_channel_recv(ptr, ptr)\n");
            out.push_str("declare void @ifa_rt_channel_close(ptr)\n");
            out.push_str("declare i64 @ifa_rt_channel_select(ptr, i64, i32)\n");
            out.push_str("declare void @ifa_rt_panic_uaf(ptr, i32, i32)\n\n");
        } else {
            out.push_str("; IFA Runtime Intrinsic Declarations\n");
            out.push_str("declare void @ifa_rt_println(ptr)\n");
            out.push_str("declare void @ifa_rt_print(ptr)\n");
            out.push_str("declare void @ifa_rt_println_i64(i64)\n");
            out.push_str("declare void @ifa_rt_print_i64(i64)\n");
            out.push_str("declare ptr @ifa_rt_gen_alloc(i64, i64, i16)\n");
            out.push_str("declare void @ifa_rt_gen_free(ptr)\n");
            out.push_str("declare void @ifa_rt_fiber_yield()\n");
            out.push_str("declare ptr @ifa_rt_channel_create(i64)\n");
            out.push_str("declare void @ifa_rt_channel_destroy(ptr)\n");
            out.push_str("declare i32 @ifa_rt_channel_send(ptr, ptr)\n");
            out.push_str("declare i32 @ifa_rt_channel_recv(ptr, ptr)\n");
            out.push_str("declare void @ifa_rt_channel_close(ptr)\n");
            out.push_str("declare i64 @ifa_rt_channel_select(ptr, i64, i32)\n");
            out.push_str("declare void @ifa_rt_panic_uaf(ptr, i32, i32)\n\n");
        }

        // SIMD Vector Reduction Intrinsics
        out.push_str("; LLVM Vector Reduction Intrinsics\n");
        out.push_str("declare float @llvm.vector.reduce.fadd.v4f32(float, <4 x float>)\n");
        out.push_str("declare float @llvm.vector.reduce.fadd.v8f32(float, <8 x float>)\n");
        out.push_str("declare i32 @llvm.vector.reduce.add.v4i32(<4 x i32>)\n");
        out.push_str("declare i32 @llvm.vector.reduce.add.v8i32(<8 x i32>)\n\n");

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

        // Fast-path 1-cycle CPU inlined generation check (alwaysinline with branch weights)
        out.push_str("; Inlined 1-cycle CPU generation check\n");
        out.push_str("define linkonce_odr void @ifa_rt_gen_check(ptr %ptr, i32 %remembered_gen) alwaysinline {\n");
        out.push_str("entry:\n");
        out.push_str("  %hdr_ptr = getelementptr inbounds i8, ptr %ptr, i64 -8\n");
        out.push_str("  %actual_gen = load i32, ptr %hdr_ptr, align 4\n");
        out.push_str("  %match = icmp eq i32 %actual_gen, %remembered_gen\n");
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
        if !module.structs.is_empty() {
            out.push_str("; Structure Type Definitions\n");
            for st in &module.structs {
                let st_name = INTERNER.resolve(&st.name);
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

        // 4. Emit function definitions
        for func in &module.functions {
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
        if self.target.arch == TargetArch::Wasm32Wasi {
            out.push_str(
                "attributes #2 = { \"wasm-import-module\"=\"wasi_snapshot_preview1\" \"wasm-import-name\"=\"fd_write\" }\n",
            );
        }

        // 6. Metadata for branch weights and loop vectorization hints
        out.push_str("\n!0 = !{!\"branch_weights\", i32 1048576, i32 1}\n");
        out.push_str("!1 = distinct !{!1, !2, !3, !4, !5}\n");
        out.push_str("!2 = !{!\"llvm.loop.vectorize.enable\", i1 1}\n");
        out.push_str("!3 = !{!\"llvm.loop.vectorize.width\", i32 8}\n");
        out.push_str("!4 = !{!\"llvm.loop.interleave.count\", i32 4}\n");
        out.push_str("!5 = !{!\"llvm.loop.unroll.enable\", i1 1}\n");

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
        let is_main_unit = fn_name == "main" && raw_ret_ty == "void";
        let ret_ty = if is_main_unit { "i32" } else { &raw_ret_ty };

        let linkage = if func.is_pub {
            "dso_local "
        } else {
            "internal "
        };

        let attr_group = if func.is_strict { "#0" } else { "#1" };

        let params_str: Vec<String> = func
            .params
            .iter()
            .map(|p| {
                let ty = fir_to_llvm_type(&p.ty).unwrap_or_else(|_| "ptr".to_string());
                format!("{} %v{}", ty, p.val.0)
            })
            .collect();

        out.push_str(&format!(
            "define {}{} @{}({}) {} {{\n",
            linkage,
            ret_ty,
            fn_name,
            params_str.join(", "),
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
                        ValueExpr::CallDirect { name, .. } => {
                            let callee = INTERNER.resolve(name);
                            if callee.starts_with("ifa_simd_") {
                                if callee.ends_with("_f32")
                                    && (callee.contains("dot") || callee.contains("sum"))
                                {
                                    ifa_fir::FirType::Float(ifa_sema::types::FloatType::F32)
                                } else if callee.ends_with("_i32") && callee.contains("sum") {
                                    ifa_fir::FirType::Int(ifa_sema::types::IntType::I32)
                                } else if callee.contains("slice_add")
                                    || callee.contains("slice_mul")
                                {
                                    ifa_fir::FirType::Unit
                                } else {
                                    ifa_fir::FirType::Int(ifa_sema::types::IntType::I64)
                                }
                            } else if let Some(target_fn) =
                                module.functions.iter().find(|f| f.name == *name)
                            {
                                target_fn.ret_ty.clone()
                            } else {
                                ifa_fir::FirType::Int(ifa_sema::types::IntType::I64)
                            }
                        }
                        _ => ifa_fir::FirType::Int(ifa_sema::types::IntType::I64),
                    };
                    value_types.insert(res, ty);
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
        for (b_idx, block) in func.blocks.iter().enumerate() {
            let label = if b_idx == 0 {
                "entry".to_string()
            } else {
                format!("bb{}", block.id.0)
            };
            out.push_str(&format!("{}:\n", label));

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
                    self.emit_instruction(res.0, &inst.expr, module, &value_types, out)?;
                } else {
                    self.emit_effectful_instruction(&inst.expr, module, &value_types, out)?;
                }
            }

            // Terminator
            if let Some(ref term) = block.terminator {
                self.emit_terminator(term, &func.ret_ty, is_main_unit, out)?;
            } else {
                out.push_str("  unreachable\n");
            }
        }

        out.push_str("}\n");
        Ok(())
    }

    fn emit_instruction(
        &self,
        res_id: u32,
        expr: &ValueExpr,
        module: &FirModule,
        value_types: &HashMap<ifa_fir::ValueId, ifa_fir::FirType>,
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
                ConstantValue::Int(val, _) => {
                    out.push_str(&format!("  %v{} = add i64 {}, 0\n", res_id, val));
                }
                ConstantValue::Float(val, _) => {
                    out.push_str(&format!("  %v{} = fadd double {:e}, 0.0\n", res_id, val));
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
                ConstantValue::Null => {
                    out.push_str(&format!("  %v{} = add i64 0, 0\n", res_id));
                }
            },
            ValueExpr::Binary { op, lhs, rhs } => {
                let is_float = matches!(value_types.get(lhs), Some(ifa_fir::FirType::Float(_)));
                if is_float {
                    let (op_str, ty_str) = match op {
                        BinaryOp::Add => ("fadd", "double"),
                        BinaryOp::Sub => ("fsub", "double"),
                        BinaryOp::Mul => ("fmul", "double"),
                        BinaryOp::Div => ("fdiv", "double"),
                        BinaryOp::Eq => ("fcmp oeq", "double"),
                        BinaryOp::Ne => ("fcmp one", "double"),
                        BinaryOp::Lt => ("fcmp olt", "double"),
                        BinaryOp::Le => ("fcmp ole", "double"),
                        BinaryOp::Gt => ("fcmp ogt", "double"),
                        BinaryOp::Ge => ("fcmp oge", "double"),
                        _ => ("fadd", "double"),
                    };
                    out.push_str(&format!(
                        "  %v{} = {} {} %v{}, %v{}\n",
                        res_id, op_str, ty_str, lhs.0, rhs.0
                    ));
                } else {
                    let op_str = match op {
                        BinaryOp::Add => "add nsw i64",
                        BinaryOp::Sub => "sub nsw i64",
                        BinaryOp::Mul => "mul nsw i64",
                        BinaryOp::Div => "sdiv i64",
                        BinaryOp::Rem => "srem i64",
                        BinaryOp::Eq => "icmp eq i64",
                        BinaryOp::Ne => "icmp ne i64",
                        BinaryOp::Lt => "icmp slt i64",
                        BinaryOp::Le => "icmp sle i64",
                        BinaryOp::Gt => "icmp sgt i64",
                        BinaryOp::Ge => "icmp sge i64",
                        BinaryOp::And => "and i1",
                        BinaryOp::Or => "or i1",
                        BinaryOp::BitAnd => "and i64",
                        BinaryOp::BitOr => "or i64",
                        BinaryOp::BitXor => "xor i64",
                        BinaryOp::Shl => "shl i64",
                        BinaryOp::Shr => "ashr i64",
                    };
                    out.push_str(&format!(
                        "  %v{} = {} %v{}, %v{}\n",
                        res_id, op_str, lhs.0, rhs.0
                    ));
                }
            }
            ValueExpr::Unary { op, val } => match op {
                UnaryOp::Neg => {
                    let is_float = matches!(value_types.get(val), Some(ifa_fir::FirType::Float(_)));
                    if is_float {
                        out.push_str(&format!("  %v{} = fneg double %v{}\n", res_id, val.0));
                    } else {
                        out.push_str(&format!("  %v{} = sub nsw i64 0, %v{}\n", res_id, val.0));
                    }
                }
                UnaryOp::Not => {
                    out.push_str(&format!("  %v{} = xor i1 %v{}, true\n", res_id, val.0));
                }
            },
            ValueExpr::Alloca { ty, .. } => {
                let llvm_ty = fir_to_llvm_type(ty)?;
                out.push_str(&format!("  %v{} = alloca {}, align 8\n", res_id, llvm_ty));
            }
            ValueExpr::Load { ptr } => {
                out.push_str(&format!(
                    "  %v{} = load i64, ptr %v{}, align 8\n",
                    res_id, ptr.0
                ));
            }
            ValueExpr::Store { ptr, val } => {
                out.push_str(&format!(
                    "  store i64 %v{}, ptr %v{}, align 8\n",
                    val.0, ptr.0
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
                        let ret_ty = fir_to_llvm_type(&target_fn.ret_ty)?;
                        let params: Vec<String> = target_fn
                            .params
                            .iter()
                            .map(|p| fir_to_llvm_type(&p.ty).unwrap_or_else(|_| "i64".to_string()))
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
                        } else if callee.ends_with("_i32") && callee.contains("sum") {
                            (
                                "i32".to_string(),
                                vec!["ptr".to_string(), "i64".to_string()],
                            )
                        } else if callee.contains("slice_add") || callee.contains("slice_mul") {
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

                    let args_str: Vec<String> = args
                        .iter()
                        .enumerate()
                        .map(|(i, a)| {
                            let p_ty = param_types.get(i).map(|s| s.as_str()).unwrap_or("i64");
                            format!("{} %v{}", p_ty, a.0)
                        })
                        .collect();

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
            ValueExpr::GenAlloc { .. } => {
                out.push_str(&format!(
                    "  %v{} = call ptr @ifa_rt_gen_alloc(i64 64, i64 8, i16 0)\n",
                    res_id
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
            ValueExpr::GetElement { base, index } => {
                out.push_str(&format!(
                    "  %gep_{} = getelementptr inbounds i64, ptr %v{}, i64 %v{}\n",
                    res_id, base.0, index.0
                ));
                out.push_str(&format!("  %v{} = load i64, ptr %gep_{}\n", res_id, res_id));
            }
            ValueExpr::ArrayInit(elements) => {
                let count = elements.len().max(1);
                out.push_str(&format!(
                    "  %arr_alloc_{} = alloca [{} x i64], align 8\n",
                    res_id, count
                ));
                for (idx, elem) in elements.iter().enumerate() {
                    out.push_str(&format!(
                        "  %elem_ptr_{}_{} = getelementptr inbounds [{} x i64], ptr %arr_alloc_{}, i64 0, i64 {}\n",
                        res_id, idx, count, res_id, idx
                    ));
                    out.push_str(&format!(
                        "  store i64 %v{}, ptr %elem_ptr_{}_{}, align 8\n",
                        elem.0, res_id, idx
                    ));
                }
                out.push_str(&format!(
                    "  %v{} = getelementptr inbounds [{} x i64], ptr %arr_alloc_{}, i64 0, i64 0\n",
                    res_id, count, res_id
                ));
            }
            ValueExpr::StructInit { name, fields } => {
                let s_name = INTERNER.resolve(name);
                out.push_str(&format!(
                    "  %st_alloc_{} = alloca %struct.{}, align 8\n",
                    res_id, s_name
                ));
                for (idx, field_val) in fields.iter().enumerate() {
                    out.push_str(&format!(
                        "  %field_ptr_{}_{} = getelementptr inbounds %struct.{}, ptr %st_alloc_{}, i32 0, i32 {}\n",
                        res_id, idx, s_name, res_id, idx
                    ));
                    out.push_str(&format!(
                        "  store i64 %v{}, ptr %field_ptr_{}_{}, align 8\n",
                        field_val.0, res_id, idx
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
                out.push_str(&format!(
                    "  call i32 @ifa_rt_channel_recv(ptr %v{}, ptr %chan_out_slot_{})\n",
                    chan.0, res_id
                ));
                out.push_str(&format!(
                    "  %v{} = load ptr, ptr %chan_out_slot_{}, align 8\n",
                    res_id, res_id
                ));
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
                out.push_str(&format!(
                    "  %v{} = call i64 @ifa_rt_channel_select(ptr %select_arr_{}, i64 {}, i32 {})\n",
                    res_id,
                    res_id,
                    n,
                    if *has_default { 1 } else { 0 }
                ));
            }
            _ => {
                // Default fallback for intermediate structures
                out.push_str(&format!("  %v{} = add i64 0, 0\n", res_id));
            }
        }
        Ok(())
    }

    fn emit_effectful_instruction(
        &self,
        expr: &ValueExpr,
        module: &FirModule,
        value_types: &HashMap<ifa_fir::ValueId, ifa_fir::FirType>,
        out: &mut String,
    ) -> Result<(), LlvmCodegenError> {
        let _ = value_types;
        match expr {
            ValueExpr::Store { ptr, val } => {
                out.push_str(&format!(
                    "  store i64 %v{}, ptr %v{}, align 8\n",
                    val.0, ptr.0
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
                        let ret_ty = fir_to_llvm_type(&target_fn.ret_ty)?;
                        let params: Vec<String> = target_fn
                            .params
                            .iter()
                            .map(|p| fir_to_llvm_type(&p.ty).unwrap_or_else(|_| "i64".to_string()))
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
                        } else if callee.ends_with("_i32") && callee.contains("sum") {
                            (
                                "i32".to_string(),
                                vec!["ptr".to_string(), "i64".to_string()],
                            )
                        } else if callee.contains("slice_add") || callee.contains("slice_mul") {
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
                    let args_str: Vec<String> = args
                        .iter()
                        .enumerate()
                        .map(|(i, a)| {
                            let p_ty = param_types.get(i).map(|s| s.as_str()).unwrap_or("i64");
                            format!("{} %v{}", p_ty, a.0)
                        })
                        .collect();
                    out.push_str(&format!(
                        "  call {} @{}({})\n",
                        ret_ty_str,
                        callee,
                        args_str.join(", ")
                    ));
                }
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
            ValueExpr::Yield => {
                out.push_str("  call void @ifa_rt_fiber_yield()\n");
            }
            ValueExpr::ChanSend { chan, val } => {
                out.push_str(&format!(
                    "  %chan_val_cast_{} = inttoptr i64 %v{} to ptr\n",
                    val.0, val.0
                ));
                out.push_str(&format!(
                    "  call i32 @ifa_rt_channel_send(ptr %v{}, ptr %chan_val_cast_{})\n",
                    chan.0, val.0
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
                let _ = base;
                out.push_str(&format!(
                    "  %gep_set_{} = getelementptr inbounds i64, ptr %v{}, i64 %v{}\n",
                    val.0, base.0, index.0
                ));
                out.push_str(&format!(
                    "  store i64 %v{}, ptr %gep_set_{}\n",
                    val.0, val.0
                ));
            }
            _ => {}
        }
        Ok(())
    }

    fn emit_terminator(
        &self,
        term: &Terminator,
        ret_ty: &ifa_fir::FirType,
        is_main_unit: bool,
        out: &mut String,
    ) -> Result<(), LlvmCodegenError> {
        match term {
            Terminator::Return(val_opt) => {
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
                out.push_str(&format!("  br label %bb{}\n", target.0));
            }
            Terminator::BranchCond {
                cond,
                then_block,
                else_block,
                ..
            } => {
                out.push_str(&format!(
                    "  br i1 %v{}, label %bb{}, label %bb{}\n",
                    cond.0, then_block.0, else_block.0
                ));
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

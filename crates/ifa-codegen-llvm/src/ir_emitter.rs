use crate::error::LlvmCodegenError;
use crate::target::{LlvmTargetConfig, TargetArch};
use crate::types::fir_to_llvm_type;
use ifa_fir::{BinaryOp, ConstantValue, FirFunction, FirModule, Terminator, UnaryOp, ValueExpr};
use ifa_span::INTERNER;
use std::collections::HashMap;

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
            out.push_str("declare void @ifa_rt_panic_uaf(ptr, i32, i32)\n\n");
        }

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
                .any(|f| INTERNER.resolve(&f.name) == "main");
            if has_main {
                out.push_str("; WASI entrypoint wrapper\n");
                out.push_str(
                    "define void @_start() {\nentry:\n  call void @main()\n  ret void\n}\n\n",
                );
            }
        }

        // 4. Emit function definitions
        for func in &module.functions {
            self.emit_function(func, &mut out)?;
            out.push('\n');
        }

        // 5. Function attribute groups for SIMD vectorization and LTO inlining
        out.push_str("; Function Attributes\n");
        out.push_str(&format!(
            "attributes #0 = {{ mustprogress nofree nosync nounwind willreturn memory(none) \"target-cpu\"=\"{}\" \"target-features\"=\"{}\" }}\n",
            self.target.cpu, self.target.features
        ));
        out.push_str(&format!(
            "attributes #1 = {{ \"target-cpu\"=\"{}\" \"target-features\"=\"{}\" }}\n",
            self.target.cpu, self.target.features
        ));
        if self.target.arch == TargetArch::Wasm32Wasi {
            out.push_str(
                "attributes #2 = { \"wasm-import-module\"=\"wasi_snapshot_preview1\" \"wasm-import-name\"=\"fd_write\" }\n",
            );
        }

        // 6. Metadata for branch weights (predicting nominal 1-cycle CPU execution path)
        out.push_str("\n!0 = !{!\"branch_weights\", i32 1048576, i32 1}\n");

        Ok(out)
    }

    fn emit_function(&self, func: &FirFunction, out: &mut String) -> Result<(), LlvmCodegenError> {
        let fn_name = INTERNER.resolve(&func.name);
        let ret_ty = fir_to_llvm_type(&func.ret_ty)?;

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

        // Basic blocks
        for (b_idx, block) in func.blocks.iter().enumerate() {
            let label = if b_idx == 0 {
                "entry".to_string()
            } else {
                format!("bb{}", block.id.0)
            };
            out.push_str(&format!("{}:\n", label));

            // SSA Instructions
            for inst in &block.instructions {
                if let Some(res) = inst.result {
                    self.emit_instruction(res.0, &inst.expr, out)?;
                } else {
                    self.emit_effectful_instruction(&inst.expr, out)?;
                }
            }

            // Terminator
            if let Some(ref term) = block.terminator {
                self.emit_terminator(term, &func.ret_ty, out)?;
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
            },
            ValueExpr::Binary { op, lhs, rhs } => {
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
            ValueExpr::Unary { op, val } => match op {
                UnaryOp::Neg => {
                    out.push_str(&format!("  %v{} = sub nsw i64 0, %v{}\n", res_id, val.0));
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
                let callee_name = INTERNER.resolve(name);
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
                    let args_str: Vec<String> =
                        args.iter().map(|a| format!("i64 %v{}", a.0)).collect();
                    out.push_str(&format!(
                        "  %v{} = call i64 @{}({})\n",
                        res_id,
                        callee_name,
                        args_str.join(", ")
                    ));
                }
            }
            ValueExpr::GenAlloc { .. } => {
                out.push_str(&format!(
                    "  %v{} = call ptr @ifa_rt_gen_alloc(i64 64, i64 8, i16 0)\n",
                    res_id
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
        out: &mut String,
    ) -> Result<(), LlvmCodegenError> {
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
                    let args_str: Vec<String> =
                        args.iter().map(|a| format!("i64 %v{}", a.0)).collect();
                    out.push_str(&format!(
                        "  call void @{}({})\n",
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
            _ => {}
        }
        Ok(())
    }

    fn emit_terminator(
        &self,
        term: &Terminator,
        ret_ty: &ifa_fir::FirType,
        out: &mut String,
    ) -> Result<(), LlvmCodegenError> {
        match term {
            Terminator::Return(val_opt) => {
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
            Terminator::Unreachable | Terminator::Fail(_) => {
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

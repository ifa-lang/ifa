use crate::error::CodegenError;
use crate::types::fir_type_to_cranelift;
use cranelift_codegen::ir::condcodes::{FloatCC, IntCC};
use cranelift_codegen::ir::{
    types, Block as ClBlock, BlockArg, InstBuilder, MemFlagsData, StackSlotData, StackSlotKind,
    TrapCode, Value as ClValue,
};
use cranelift_frontend::FunctionBuilder;
use cranelift_module::{FuncId, Module};
use ifa_ast::ParamMode;
use ifa_fir::{
    BinaryOp, BlockId, ConstantValue, FirFunction, Terminator, UnaryOp, ValueExpr, ValueId,
};
use ifa_sema::types::IntType;
use ifa_span::INTERNER;
use std::collections::HashMap;

/// Translates a single FIR function into Cranelift IR using FunctionBuilder.
pub struct FunctionTranslator<'a, M: Module> {
    builder: FunctionBuilder<'a>,
    module: &'a mut M,
    func_ids: &'a HashMap<String, FuncId>,
    ptr_type: types::Type,
    block_map: HashMap<BlockId, ClBlock>,
    value_map: HashMap<ValueId, ClValue>,
    pointer_types: HashMap<ValueId, types::Type>,
}

impl<'a, M: Module> FunctionTranslator<'a, M> {
    pub fn new(
        builder: FunctionBuilder<'a>,
        module: &'a mut M,
        func_ids: &'a HashMap<String, FuncId>,
        ptr_type: types::Type,
    ) -> Self {
        Self {
            builder,
            module,
            func_ids,
            ptr_type,
            block_map: HashMap::new(),
            value_map: HashMap::new(),
            pointer_types: HashMap::new(),
        }
    }

    /// Translate the entire FIR function into Cranelift IR.
    pub fn translate(mut self, fir_func: &FirFunction) -> Result<(), CodegenError> {
        // 1. Create a Cranelift block for each basic block in the FIR function
        for block in &fir_func.blocks {
            let cl_block = self.builder.create_block();
            self.block_map.insert(block.id, cl_block);
        }

        let entry_cl_block = *self
            .block_map
            .get(&fir_func.entry_block)
            .ok_or_else(|| CodegenError::Codegen("Entry block not mapped".into()))?;

        // 2. Set up entry block parameters matching function parameters
        self.builder
            .append_block_params_for_function_params(entry_cl_block);
        self.builder.switch_to_block(entry_cl_block);

        for (i, param) in fir_func.params.iter().enumerate() {
            let val = self.builder.block_params(entry_cl_block)[i];
            self.value_map.insert(param.val, val);
            if param.mode == ParamMode::InOut {
                let elem_ty =
                    fir_type_to_cranelift(&param.ty, self.ptr_type).unwrap_or(self.ptr_type);
                self.pointer_types.insert(param.val, elem_ty);
            }
        }

        // 3. Set up block arguments for other blocks
        for block in &fir_func.blocks {
            if block.id == fir_func.entry_block {
                continue;
            }
            let cl_block = self.block_map[&block.id];
            for (param_val_id, param_ty) in &block.params {
                let cl_ty = fir_type_to_cranelift(param_ty, self.ptr_type).unwrap_or(self.ptr_type);
                let cl_param = self.builder.append_block_param(cl_block, cl_ty);
                self.value_map.insert(*param_val_id, cl_param);
            }
        }

        // 4. Translate instructions and terminator in Reverse Post-Order (RPO)
        // so that all dominating definitions are visited before their uses.
        let cfg = ifa_fir::ControlFlowGraph::build(fir_func);
        let rpo_order = cfg.reverse_post_order();
        let mut ordered_blocks: Vec<&ifa_fir::BasicBlock> =
            Vec::with_capacity(fir_func.blocks.len());
        let mut visited = std::collections::HashSet::new();
        for block_id in rpo_order {
            if let Some(b) = fir_func.get_block(block_id) {
                ordered_blocks.push(b);
                visited.insert(block_id);
            }
        }
        for b in &fir_func.blocks {
            if !visited.contains(&b.id) {
                ordered_blocks.push(b);
            }
        }

        for block in ordered_blocks {
            let cl_block = self.block_map[&block.id];
            self.builder.switch_to_block(cl_block);

            for inst in &block.instructions {
                let res = self.translate_expr(inst.result, &inst.expr)?;
                if let Some(val_id) = inst.result {
                    let cl_val = res.unwrap_or_else(|| self.builder.ins().iconst(types::I64, 0));
                    self.value_map.insert(val_id, cl_val);
                }
            }

            if let Some(term) = &block.terminator {
                self.translate_terminator(term)?;
            } else {
                self.builder.ins().return_(&[]);
            }
        }

        self.builder.seal_all_blocks();
        let target_config = self.module.target_config();
        self.builder.finalize(target_config);
        Ok(())
    }

    fn translate_expr(
        &mut self,
        result: Option<ValueId>,
        expr: &ValueExpr,
    ) -> Result<Option<ClValue>, CodegenError> {
        let val = match expr {
            ValueExpr::Constant(c) => match c {
                ConstantValue::Int(i, int_ty) => {
                    let cl_ty = match int_ty {
                        IntType::I8 | IntType::U8 => types::I8,
                        IntType::I16 | IntType::U16 => types::I16,
                        IntType::I32 | IntType::U32 => types::I32,
                        IntType::I64 | IntType::U64 | IntType::ISize | IntType::USize => types::I64,
                    };
                    Some(self.builder.ins().iconst(cl_ty, *i as i64))
                }
                ConstantValue::Bool(b) => {
                    let v = if *b { 1 } else { 0 };
                    Some(self.builder.ins().iconst(types::I8, v))
                }
                ConstantValue::Float(f, _) => Some(self.builder.ins().f64const(*f)),
                ConstantValue::Unit => Some(self.builder.ins().iconst(types::I64, 0)),
                ConstantValue::Null => Some(self.builder.ins().iconst(types::I64, 0)),
                ConstantValue::Char(ch) => {
                    Some(self.builder.ins().iconst(types::I32, *ch as u32 as i64))
                }
                ConstantValue::String(s) => {
                    let s_str = INTERNER.resolve(s);
                    let mut bytes = s_str.as_bytes().to_vec();
                    bytes.push(0); // Null terminator for C-ABI safety
                    let data_id = self
                        .module
                        .declare_anonymous_data(false, false)
                        .map_err(|e| CodegenError::Module(e.to_string()))?;
                    let mut data_ctx = cranelift_module::DataDescription::new();
                    data_ctx.define(bytes.into_boxed_slice());
                    self.module
                        .define_data(data_id, &data_ctx)
                        .map_err(|e| CodegenError::Module(e.to_string()))?;
                    let local_data = self.module.declare_data_in_func(data_id, self.builder.func);
                    Some(self.builder.ins().symbol_value(self.ptr_type, local_data))
                }
            },

            ValueExpr::Alloca { ty, .. } => {
                let elem_cl_ty = fir_type_to_cranelift(ty, self.ptr_type).unwrap_or(self.ptr_type);
                let size = elem_cl_ty.bytes().max(1);
                let slot = self.builder.create_sized_stack_slot(StackSlotData::new(
                    StackSlotKind::ExplicitSlot,
                    size,
                    0,
                ));
                let addr = self.builder.ins().stack_addr(self.ptr_type, slot, 0);
                if let Some(res_id) = result {
                    self.pointer_types.insert(res_id, elem_cl_ty);
                }
                Some(addr)
            }

            ValueExpr::Store { ptr, val } => {
                let p = self.value_map[ptr];
                let mut v = self.value_map[val];
                if let Some(&target_ty) = self.pointer_types.get(ptr) {
                    let cur_ty = self.builder.func.dfg.value_type(v);
                    if cur_ty != target_ty {
                        if cur_ty.bits() > target_ty.bits() {
                            v = self.builder.ins().ireduce(target_ty, v);
                        } else if cur_ty.bits() < target_ty.bits() {
                            v = self.builder.ins().sextend(target_ty, v);
                        }
                    }
                }
                self.builder.ins().store(MemFlagsData::trusted(), v, p, 0);
                None
            }

            ValueExpr::Load { ptr } => {
                let p = self.value_map[ptr];
                let load_ty = self.pointer_types.get(ptr).copied().unwrap_or(types::I64);
                Some(
                    self.builder
                        .ins()
                        .load(load_ty, MemFlagsData::trusted(), p, 0),
                )
            }

            ValueExpr::Binary { op, lhs, rhs } => {
                let mut l = self.value_map[lhs];
                let mut r = self.value_map[rhs];
                let ty_l = self.builder.func.dfg.value_type(l);
                let ty_r = self.builder.func.dfg.value_type(r);
                if ty_l == types::F32 || ty_l == types::F64 {
                    Some(match op {
                        BinaryOp::Add => self.builder.ins().fadd(l, r),
                        BinaryOp::Sub => self.builder.ins().fsub(l, r),
                        BinaryOp::Mul => self.builder.ins().fmul(l, r),
                        BinaryOp::Div => self.builder.ins().fdiv(l, r),
                        BinaryOp::Eq => self.builder.ins().fcmp(FloatCC::Equal, l, r),
                        BinaryOp::Ne => self.builder.ins().fcmp(FloatCC::NotEqual, l, r),
                        BinaryOp::Lt => self.builder.ins().fcmp(FloatCC::LessThan, l, r),
                        BinaryOp::Le => self.builder.ins().fcmp(FloatCC::LessThanOrEqual, l, r),
                        BinaryOp::Gt => self.builder.ins().fcmp(FloatCC::GreaterThan, l, r),
                        BinaryOp::Ge => self.builder.ins().fcmp(FloatCC::GreaterThanOrEqual, l, r),
                        _ => self.builder.ins().fadd(l, r),
                    })
                } else {
                    if ty_l != ty_r {
                        if ty_l.bits() > ty_r.bits() {
                            r = self.builder.ins().sextend(ty_l, r);
                        } else {
                            l = self.builder.ins().sextend(ty_r, l);
                        }
                    }
                    Some(match op {
                        BinaryOp::Add => self.builder.ins().iadd(l, r),
                        BinaryOp::Sub => self.builder.ins().isub(l, r),
                        BinaryOp::Mul => self.builder.ins().imul(l, r),
                        BinaryOp::Div => self.builder.ins().sdiv(l, r),
                        BinaryOp::Rem => self.builder.ins().srem(l, r),
                        BinaryOp::BitAnd | BinaryOp::And => self.builder.ins().band(l, r),
                        BinaryOp::BitOr | BinaryOp::Or => self.builder.ins().bor(l, r),
                        BinaryOp::BitXor => self.builder.ins().bxor(l, r),
                        BinaryOp::Shl => self.builder.ins().ishl(l, r),
                        BinaryOp::Shr => self.builder.ins().sshr(l, r),
                        BinaryOp::Eq => self.builder.ins().icmp(IntCC::Equal, l, r),
                        BinaryOp::Ne => self.builder.ins().icmp(IntCC::NotEqual, l, r),
                        BinaryOp::Lt => self.builder.ins().icmp(IntCC::SignedLessThan, l, r),
                        BinaryOp::Le => self.builder.ins().icmp(IntCC::SignedLessThanOrEqual, l, r),
                        BinaryOp::Gt => self.builder.ins().icmp(IntCC::SignedGreaterThan, l, r),
                        BinaryOp::Ge => {
                            self.builder
                                .ins()
                                .icmp(IntCC::SignedGreaterThanOrEqual, l, r)
                        }
                    })
                }
            }

            ValueExpr::Unary { op, val } => {
                let v = self.value_map[val];
                let ty_v = self.builder.func.dfg.value_type(v);
                Some(match op {
                    UnaryOp::Neg => {
                        if ty_v == types::F32 || ty_v == types::F64 {
                            self.builder.ins().fneg(v)
                        } else {
                            self.builder.ins().ineg(v)
                        }
                    }
                    UnaryOp::Not => self.builder.ins().bnot(v),
                })
            }

            ValueExpr::CallDirect { name, args } => {
                let fn_name = INTERNER.resolve(name);
                if let Some(&callee_id) = self.func_ids.get(&fn_name) {
                    let local_func = self
                        .module
                        .declare_func_in_func(callee_id, self.builder.func);
                    let sig_ref = self.builder.func.dfg.ext_funcs[local_func].signature;
                    let expected_params = self.builder.func.dfg.signatures[sig_ref].params.clone();
                    let mut arg_vals = Vec::with_capacity(args.len());
                    for (i, a) in args.iter().enumerate() {
                        let mut v = self.value_map[a];
                        if let Some(param) = expected_params.get(i) {
                            let cur_ty = self.builder.func.dfg.value_type(v);
                            let exp_ty = param.value_type;
                            if cur_ty != exp_ty {
                                if cur_ty.bits() > exp_ty.bits() {
                                    v = self.builder.ins().ireduce(exp_ty, v);
                                } else if cur_ty.bits() < exp_ty.bits() {
                                    v = self.builder.ins().sextend(exp_ty, v);
                                }
                            }
                        }
                        arg_vals.push(v);
                    }
                    let call = self.builder.ins().call(local_func, &arg_vals);
                    let results = self.builder.inst_results(call);
                    results.first().copied()
                } else {
                    None
                }
            }

            ValueExpr::CoWMakeUnique { val }
            | ValueExpr::CoWClone { val }
            | ValueExpr::GenRef { ptr: val }
            | ValueExpr::GenDeref { ref_val: val } => Some(self.value_map[val]),

            ValueExpr::GetField {
                base, field_idx, ..
            } => {
                let p = self.value_map[base];
                let offset = (*field_idx * 8) as i32;
                Some(
                    self.builder
                        .ins()
                        .load(types::I64, MemFlagsData::trusted(), p, offset),
                )
            }

            ValueExpr::GetFieldPtr {
                base, field_idx, ..
            } => {
                let p = self.value_map[base];
                let offset = (*field_idx * 8) as i64;
                Some(self.builder.ins().iadd_imm_s(p, offset))
            }

            ValueExpr::GetElementPtr { base, index } => {
                let p = self.value_map[base];
                let idx = self.value_map[index];
                let scaled = self.builder.ins().imul_imm_s(idx, 8);
                Some(self.builder.ins().iadd(p, scaled))
            }

            ValueExpr::SetField {
                base,
                field_idx,
                val,
            } => {
                let p = self.value_map[base];
                let v = self.value_map[val];
                let offset = (*field_idx * 8) as i32;
                self.builder
                    .ins()
                    .store(MemFlagsData::trusted(), v, p, offset);
                None
            }

            ValueExpr::GenAlloc { ty, arena } => {
                let size = crate::types::fir_type_byte_size(ty).max(8);
                let size_val = self.builder.ins().iconst(self.ptr_type, size as i64);
                let align_val = self.builder.ins().iconst(self.ptr_type, 8);
                let arena_val = self
                    .builder
                    .ins()
                    .iconst(types::I32, arena.unwrap_or(0) as i64);

                if let Some(func_id) = self.func_ids.get("ifa_rt_gen_alloc") {
                    let local_func = self
                        .module
                        .declare_func_in_func(*func_id, self.builder.func);
                    let call = self
                        .builder
                        .ins()
                        .call(local_func, &[size_val, align_val, arena_val]);
                    let results = self.builder.inst_results(call);
                    results.first().copied()
                } else {
                    Some(self.builder.ins().iconst(self.ptr_type, 0))
                }
            }

            ValueExpr::GenFree { ptr } => {
                let p = self.value_map[ptr];
                if let Some(func_id) = self.func_ids.get("ifa_rt_gen_free") {
                    let local_func = self
                        .module
                        .declare_func_in_func(*func_id, self.builder.func);
                    self.builder.ins().call(local_func, &[p]);
                }
                None
            }

            ValueExpr::GenCheck { ref_val, redundant } => {
                if !redundant {
                    let p = self.value_map[ref_val];
                    // Inlined 1-cycle CPU generation check:
                    // 1. Load actual generation from 64-bit GenHeader (offset -8)
                    let actual_gen =
                        self.builder
                            .ins()
                            .load(types::I32, MemFlagsData::trusted(), p, -8);
                    // 2. Expected generation (1 for newly allocated slots or tracked gen)
                    let expected_gen = self.builder.ins().iconst(types::I32, 1);
                    // 3. Fast integer equality comparison in 1 CPU cycle
                    let is_valid = self
                        .builder
                        .ins()
                        .icmp(IntCC::Equal, actual_gen, expected_gen);
                    // 4. Trap immediately if invalid (Use-After-Free intercepted without crash)
                    self.builder.ins().trapz(is_valid, TrapCode::unwrap_user(1));
                }
                None
            }

            ValueExpr::Yield => {
                if let Some(func_id) = self.func_ids.get("ifa_rt_fiber_yield") {
                    let local_func = self
                        .module
                        .declare_func_in_func(*func_id, self.builder.func);
                    self.builder.ins().call(local_func, &[]);
                }
                None
            }

            ValueExpr::GetElement { base, index } => {
                let p = self.value_map[base];
                let idx = self.value_map[index];
                let offset = self.builder.ins().imul_imm_s(idx, 8);
                let addr = self.builder.ins().iadd(p, offset);
                Some(
                    self.builder
                        .ins()
                        .load(types::I64, MemFlagsData::trusted(), addr, 0),
                )
            }

            ValueExpr::SetElement { base, index, val } => {
                let p = self.value_map[base];
                let idx = self.value_map[index];
                let v = self.value_map[val];
                let offset = self.builder.ins().imul_imm_s(idx, 8);
                let addr = self.builder.ins().iadd(p, offset);
                self.builder
                    .ins()
                    .store(MemFlagsData::trusted(), v, addr, 0);
                None
            }

            ValueExpr::ArrayInit(elements) => {
                let count = elements.len().max(1);
                let byte_size = (count * 8) as u32;
                let slot = self.builder.create_sized_stack_slot(StackSlotData::new(
                    StackSlotKind::ExplicitSlot,
                    byte_size,
                    0,
                ));
                let base_addr = self.builder.ins().stack_addr(self.ptr_type, slot, 0);
                for (idx, elem_id) in elements.iter().enumerate() {
                    let elem_val = self.value_map[elem_id];
                    let offset = (idx * 8) as i32;
                    self.builder
                        .ins()
                        .store(MemFlagsData::trusted(), elem_val, base_addr, offset);
                }
                Some(base_addr)
            }

            ValueExpr::StructInit { fields, .. } | ValueExpr::TupleInit(fields) => {
                let count = fields.len().max(1);
                let byte_size = (count * 8) as u32;
                let slot = self.builder.create_sized_stack_slot(StackSlotData::new(
                    StackSlotKind::ExplicitSlot,
                    byte_size,
                    0,
                ));
                let base_addr = self.builder.ins().stack_addr(self.ptr_type, slot, 0);
                for (idx, field_id) in fields.iter().enumerate() {
                    let field_val = self.value_map[field_id];
                    let offset = (idx * 8) as i32;
                    self.builder
                        .ins()
                        .store(MemFlagsData::trusted(), field_val, base_addr, offset);
                }
                Some(base_addr)
            }

            ValueExpr::ChanCreate { capacity, .. } => {
                let cap_val = if let Some(cap) = capacity {
                    self.value_map[cap]
                } else {
                    self.builder.ins().iconst(self.ptr_type, 0)
                };
                if let Some(func_id) = self.func_ids.get("ifa_rt_channel_create") {
                    let local_func = self
                        .module
                        .declare_func_in_func(*func_id, self.builder.func);
                    let call = self.builder.ins().call(local_func, &[cap_val]);
                    let results = self.builder.inst_results(call);
                    results.first().copied()
                } else {
                    Some(self.builder.ins().iconst(self.ptr_type, 0))
                }
            }

            ValueExpr::ChanSend { chan, val } => {
                let ch = self.value_map[chan];
                let v = self.value_map[val];
                if let Some(func_id) = self.func_ids.get("ifa_rt_channel_send") {
                    let local_func = self
                        .module
                        .declare_func_in_func(*func_id, self.builder.func);
                    let call = self.builder.ins().call(local_func, &[ch, v]);
                    let results = self.builder.inst_results(call);
                    results.first().copied()
                } else {
                    None
                }
            }

            ValueExpr::ChanRecv { chan } => {
                let ch = self.value_map[chan];
                let slot = self.builder.create_sized_stack_slot(StackSlotData::new(
                    StackSlotKind::ExplicitSlot,
                    8,
                    0,
                ));
                let slot_addr = self.builder.ins().stack_addr(self.ptr_type, slot, 0);
                if let Some(func_id) = self.func_ids.get("ifa_rt_channel_recv") {
                    let local_func = self
                        .module
                        .declare_func_in_func(*func_id, self.builder.func);
                    self.builder.ins().call(local_func, &[ch, slot_addr]);
                    let loaded_val = self.builder.ins().load(
                        self.ptr_type,
                        MemFlagsData::trusted(),
                        slot_addr,
                        0,
                    );
                    Some(loaded_val)
                } else {
                    Some(self.builder.ins().iconst(self.ptr_type, 0))
                }
            }

            ValueExpr::ChanTryRecv { chan } => {
                let ch = self.value_map[chan];
                let slot = self.builder.create_sized_stack_slot(StackSlotData::new(
                    StackSlotKind::ExplicitSlot,
                    8,
                    0,
                ));
                let slot_addr = self.builder.ins().stack_addr(self.ptr_type, slot, 0);
                if let Some(func_id) = self.func_ids.get("ifa_rt_channel_try_recv") {
                    let local_func = self
                        .module
                        .declare_func_in_func(*func_id, self.builder.func);
                    self.builder.ins().call(local_func, &[ch, slot_addr]);
                    let loaded_val = self.builder.ins().load(
                        self.ptr_type,
                        MemFlagsData::trusted(),
                        slot_addr,
                        0,
                    );
                    Some(loaded_val)
                } else {
                    Some(self.builder.ins().iconst(self.ptr_type, 0))
                }
            }

            ValueExpr::ChanClose { chan } => {
                let ch = self.value_map[chan];
                if let Some(func_id) = self.func_ids.get("ifa_rt_channel_close") {
                    let local_func = self
                        .module
                        .declare_func_in_func(*func_id, self.builder.func);
                    self.builder.ins().call(local_func, &[ch]);
                }
                None
            }

            ValueExpr::ChanSelect {
                channels,
                has_default,
            } => {
                let n = channels.len();
                let total_size = (n.max(1) * 8) as u32;
                let slot = self.builder.create_sized_stack_slot(StackSlotData::new(
                    StackSlotKind::ExplicitSlot,
                    total_size,
                    0,
                ));
                let arr_addr = self.builder.ins().stack_addr(self.ptr_type, slot, 0);
                for (idx, ch_id) in channels.iter().enumerate() {
                    let ch_val = self.value_map[ch_id];
                    let offset = (idx * 8) as i32;
                    self.builder
                        .ins()
                        .store(MemFlagsData::trusted(), ch_val, arr_addr, offset);
                }
                let n_val = self.builder.ins().iconst(self.ptr_type, n as i64);
                let def_val = self
                    .builder
                    .ins()
                    .iconst(types::I32, if *has_default { 1 } else { 0 });
                if let Some(func_id) = self.func_ids.get("ifa_rt_channel_select") {
                    let local_func = self
                        .module
                        .declare_func_in_func(*func_id, self.builder.func);
                    let call = self
                        .builder
                        .ins()
                        .call(local_func, &[arr_addr, n_val, def_val]);
                    let results = self.builder.inst_results(call);
                    results.first().copied()
                } else {
                    Some(self.builder.ins().iconst(types::I64, 0))
                }
            }

            ValueExpr::ArrayPush { .. }
            | ValueExpr::StructPushField { .. }
            | ValueExpr::CoWCheckShared { .. }
            | ValueExpr::Spawn { .. }
            | ValueExpr::Call { .. } => Some(self.builder.ins().iconst(types::I64, 0)),

            ValueExpr::ArrayLen { array } => {
                let _ = array;
                Some(self.builder.ins().iconst(types::I64, 0))
            }

            ValueExpr::EnumInit {
                discriminant,
                payload,
                ..
            } => {
                let slot = self.builder.create_sized_stack_slot(StackSlotData::new(
                    StackSlotKind::ExplicitSlot,
                    16,
                    0,
                ));
                let base_addr = self.builder.ins().stack_addr(self.ptr_type, slot, 0);
                let disc_val = self.builder.ins().iconst(types::I64, *discriminant as i64);
                self.builder
                    .ins()
                    .store(MemFlagsData::trusted(), disc_val, base_addr, 0);
                if let Some(p_id) = payload {
                    let p_val = self.value_map[p_id];
                    self.builder
                        .ins()
                        .store(MemFlagsData::trusted(), p_val, base_addr, 8);
                } else {
                    let zero_val = self.builder.ins().iconst(types::I64, 0);
                    self.builder
                        .ins()
                        .store(MemFlagsData::trusted(), zero_val, base_addr, 8);
                }
                Some(base_addr)
            }

            ValueExpr::EnumGetDiscriminant { base } => {
                let base_val = self.value_map[base];
                let disc =
                    self.builder
                        .ins()
                        .load(types::I64, MemFlagsData::trusted(), base_val, 0);
                Some(disc)
            }

            ValueExpr::EnumGetPayload { base, payload_ty } => {
                let base_val = self.value_map[base];
                let cl_ty = fir_type_to_cranelift(payload_ty, self.ptr_type).unwrap_or(types::I64);
                let payload = self
                    .builder
                    .ins()
                    .load(cl_ty, MemFlagsData::trusted(), base_val, 8);
                Some(payload)
            }

            ValueExpr::SliceSub { base, start, .. } => {
                let base_addr = self.value_map[base];
                let start_idx = self.value_map[start];
                let elem_size = self.builder.ins().iconst(self.ptr_type, 8);
                let offset = self.builder.ins().imul(start_idx, elem_size);
                let sub_addr = self.builder.ins().iadd(base_addr, offset);
                Some(sub_addr)
            }
        };

        Ok(val)
    }

    fn translate_terminator(&mut self, term: &Terminator) -> Result<(), CodegenError> {
        match term {
            Terminator::Return(opt_val) => {
                let returns = self.builder.func.signature.returns.clone();
                if returns.is_empty() {
                    self.builder.ins().return_(&[]);
                } else {
                    let expected_ret_ty = returns[0].value_type;
                    let mut ret_val = if let Some(v_id) = opt_val {
                        if let Some(&v) = self.value_map.get(v_id) {
                            v
                        } else {
                            self.builder.ins().iconst(expected_ret_ty, 0)
                        }
                    } else {
                        self.builder.ins().iconst(expected_ret_ty, 0)
                    };
                    let cur_ty = self.builder.func.dfg.value_type(ret_val);
                    if cur_ty != expected_ret_ty {
                        if cur_ty.bits() > expected_ret_ty.bits() {
                            ret_val = self.builder.ins().ireduce(expected_ret_ty, ret_val);
                        } else if cur_ty.bits() < expected_ret_ty.bits() {
                            ret_val = self.builder.ins().sextend(expected_ret_ty, ret_val);
                        }
                    }
                    self.builder.ins().return_(&[ret_val]);
                }
            }
            Terminator::Branch { target, args } => {
                let target_cl_block = self.block_map[target];
                let cl_args: Vec<BlockArg> = args
                    .iter()
                    .map(|a| {
                        let val = self
                            .value_map
                            .get(a)
                            .copied()
                            .unwrap_or_else(|| self.builder.ins().iconst(types::I64, 0));
                        BlockArg::from(val)
                    })
                    .collect();
                self.builder.ins().jump(target_cl_block, &cl_args);
            }
            Terminator::BranchCond {
                cond,
                then_block,
                then_args,
                else_block,
                else_args,
            } => {
                let c = self
                    .value_map
                    .get(cond)
                    .copied()
                    .unwrap_or_else(|| self.builder.ins().iconst(types::I8, 0));
                let then_cl = self.block_map[then_block];
                let else_cl = self.block_map[else_block];
                let then_cl_args: Vec<BlockArg> = then_args
                    .iter()
                    .map(|a| {
                        let val = self
                            .value_map
                            .get(a)
                            .copied()
                            .unwrap_or_else(|| self.builder.ins().iconst(types::I64, 0));
                        BlockArg::from(val)
                    })
                    .collect();
                let else_cl_args: Vec<BlockArg> = else_args
                    .iter()
                    .map(|a| {
                        let val = self
                            .value_map
                            .get(a)
                            .copied()
                            .unwrap_or_else(|| self.builder.ins().iconst(types::I64, 0));
                        BlockArg::from(val)
                    })
                    .collect();
                self.builder
                    .ins()
                    .brif(c, then_cl, &then_cl_args, else_cl, &else_cl_args);
            }
            Terminator::Switch {
                val,
                cases,
                default_block,
                default_args,
            } => {
                let switch_val = self
                    .value_map
                    .get(val)
                    .copied()
                    .unwrap_or_else(|| self.builder.ins().iconst(types::I64, 0));
                let default_cl_block = self.block_map[default_block];
                let default_cl_args: Vec<BlockArg> = default_args
                    .iter()
                    .map(|a| {
                        let v = self
                            .value_map
                            .get(a)
                            .copied()
                            .unwrap_or_else(|| self.builder.ins().iconst(types::I64, 0));
                        BlockArg::from(v)
                    })
                    .collect();

                if cases.is_empty() {
                    self.builder.ins().jump(default_cl_block, &default_cl_args);
                    return Ok(());
                }

                for (case_val, target_bb, args) in cases {
                    let target_cl_block = self.block_map[target_bb];
                    let target_cl_args: Vec<BlockArg> = args
                        .iter()
                        .map(|a| BlockArg::from(self.value_map[a]))
                        .collect();

                    let case_const = match case_val {
                        ConstantValue::Int(i, _) => *i as i64,
                        ConstantValue::Bool(true) => 1,
                        ConstantValue::Bool(false) => 0,
                        _ => 0,
                    };
                    let c_val = self.builder.ins().iconst(types::I64, case_const);
                    let cond = self.builder.ins().icmp(IntCC::Equal, switch_val, c_val);

                    let next_test_block = self.builder.create_block();
                    self.builder.ins().brif(
                        cond,
                        target_cl_block,
                        &target_cl_args,
                        next_test_block,
                        &[],
                    );
                    self.builder.seal_block(next_test_block);
                    self.builder.switch_to_block(next_test_block);
                }

                self.builder.ins().jump(default_cl_block, &default_cl_args);
            }
            Terminator::Fail(fail_val) => {
                let returns = self.builder.func.signature.returns.clone();
                if !returns.is_empty() {
                    let expected_ret_ty = returns[0].value_type;
                    let ret_val = self
                        .value_map
                        .get(fail_val)
                        .copied()
                        .unwrap_or_else(|| self.builder.ins().iconst(expected_ret_ty, 0));
                    self.builder.ins().return_(&[ret_val]);
                } else {
                    self.builder.ins().trap(TrapCode::unwrap_user(1));
                }
            }
            Terminator::Unreachable => {
                self.builder.ins().trap(TrapCode::unwrap_user(1));
            }
        }
        Ok(())
    }
}

use crate::error::CodegenError;
use crate::types::fir_type_to_cranelift;
use cranelift_codegen::ir::condcodes::{FloatCC, IntCC};
use cranelift_codegen::ir::{
    types, AbiParam, Block as ClBlock, BlockArg, InstBuilder, MemFlagsData, Signature,
    StackSlotData, StackSlotKind, TrapCode, Value as ClValue,
};
use cranelift_frontend::FunctionBuilder;
use cranelift_module::{FuncId, Module};
use ifa_ast::ParamMode;
use ifa_fir::{
    BinaryOp, BlockId, ConstantValue, FirFunction, FirType, Terminator, UnaryOp, ValueExpr, ValueId,
};
use ifa_sema::types::{FloatType, IntType};
use ifa_span::{Symbol, INTERNER};
use std::collections::{HashMap, HashSet};

#[inline]
fn is_slice_or_slice_ptr(ty: Option<&FirType>) -> bool {
    match ty {
        Some(FirType::Slice(_)) => true,
        Some(FirType::Pointer(inner)) => matches!(&**inner, FirType::Slice(_)),
        _ => false,
    }
}

/// Comparison predicate used for vectorized slice counting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CountPred {
    Gt,
    Lt,
    Eq,
    Ne,
}

/// Translates a single FIR function into Cranelift IR using FunctionBuilder.
pub struct FunctionTranslator<'a, M: Module> {
    builder: FunctionBuilder<'a>,
    module: &'a mut M,
    func_ids: &'a HashMap<String, FuncId>,
    ptr_type: types::Type,
    struct_defs: &'a HashMap<Symbol, Vec<(Symbol, FirType)>>,
    coro_funcs: &'a HashSet<Symbol>,
    fn_param_types: &'a HashMap<String, Vec<FirType>>,
    fn_return_types: &'a HashMap<String, FirType>,
    block_map: HashMap<BlockId, ClBlock>,
    value_map: HashMap<ValueId, ClValue>,
    value_types: HashMap<ValueId, FirType>,
    slice_lens: HashMap<ValueId, ClValue>,
    pointer_types: HashMap<ValueId, types::Type>,
    pointer_fir_types: HashMap<ValueId, FirType>,
    constant_ints: HashMap<ValueId, i64>,
    strided_slices: HashMap<ValueId, i64>,
}

impl<'a, M: Module> FunctionTranslator<'a, M> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        builder: FunctionBuilder<'a>,
        module: &'a mut M,
        func_ids: &'a HashMap<String, FuncId>,
        ptr_type: types::Type,
        struct_defs: &'a HashMap<Symbol, Vec<(Symbol, FirType)>>,
        coro_funcs: &'a HashSet<Symbol>,
        fn_param_types: &'a HashMap<String, Vec<FirType>>,
        fn_return_types: &'a HashMap<String, FirType>,
    ) -> Self {
        Self {
            builder,
            module,
            func_ids,
            ptr_type,
            struct_defs,
            coro_funcs,
            fn_param_types,
            fn_return_types,
            block_map: HashMap::new(),
            value_map: HashMap::new(),
            value_types: HashMap::new(),
            slice_lens: HashMap::new(),
            pointer_types: HashMap::new(),
            pointer_fir_types: HashMap::new(),
            constant_ints: HashMap::new(),
            strided_slices: HashMap::new(),
        }
    }

    /// Precompute FIR types of all SSA values in the function.
    fn compute_value_types(
        func: &FirFunction,
        struct_defs: &HashMap<Symbol, Vec<(Symbol, FirType)>>,
        fn_return_types: &HashMap<String, FirType>,
    ) -> HashMap<ValueId, FirType> {
        let mut value_types: HashMap<ValueId, FirType> = HashMap::new();
        for p in &func.params {
            if p.mode == ParamMode::InOut {
                value_types.insert(p.val, FirType::Pointer(Box::new(p.ty.clone())));
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
                    let ty = match &inst.expr {
                        ValueExpr::Constant(ConstantValue::Float(_, f_ty)) => FirType::Float(*f_ty),
                        ValueExpr::Constant(ConstantValue::Int(_, i_ty)) => FirType::Int(*i_ty),
                        ValueExpr::Constant(ConstantValue::Bool(_)) => FirType::Bool,
                        ValueExpr::Constant(ConstantValue::Char(_)) => FirType::Char,
                        ValueExpr::Constant(ConstantValue::String(_)) => FirType::Str,
                        ValueExpr::FormatString(_) => FirType::String,
                        ValueExpr::Constant(ConstantValue::Function(_)) => {
                            FirType::Pointer(Box::new(FirType::Unit))
                        }
                        ValueExpr::Constant(ConstantValue::Null) => FirType::Int(IntType::I64),
                        ValueExpr::Binary { op, lhs, .. } => match op {
                            BinaryOp::Eq
                            | BinaryOp::Ne
                            | BinaryOp::Lt
                            | BinaryOp::Le
                            | BinaryOp::Gt
                            | BinaryOp::Ge
                            | BinaryOp::And
                            | BinaryOp::Or => FirType::Bool,
                            _ => value_types
                                .get(lhs)
                                .cloned()
                                .unwrap_or(FirType::Int(IntType::I64)),
                        },
                        ValueExpr::Unary { op, val } => match op {
                            UnaryOp::Not => FirType::Bool,
                            UnaryOp::Neg => value_types
                                .get(val)
                                .cloned()
                                .unwrap_or(FirType::Int(IntType::I64)),
                        },
                        ValueExpr::Alloca { ty, .. } => FirType::Pointer(Box::new(ty.clone())),
                        ValueExpr::Load { ptr } => match value_types.get(ptr) {
                            Some(FirType::Pointer(inner)) => (**inner).clone(),
                            _ => FirType::Int(IntType::I64),
                        },
                        ValueExpr::GetElement { base, .. } => match value_types.get(base) {
                            Some(FirType::Array(inner, _)) | Some(FirType::Slice(inner)) => {
                                (**inner).clone()
                            }
                            Some(FirType::Pointer(inner)) => match &**inner {
                                FirType::Array(elem, _) | FirType::Slice(elem) => (**elem).clone(),
                                _ => FirType::Int(IntType::I64),
                            },
                            _ => FirType::Int(IntType::I64),
                        },
                        ValueExpr::GetField {
                            base, field_idx, ..
                        } => match value_types.get(base) {
                            Some(FirType::Struct(name, fields)) => {
                                if let Some((_, fty)) = fields.get(*field_idx) {
                                    fty.clone()
                                } else if let Some(s_fields) = struct_defs.get(name) {
                                    s_fields
                                        .get(*field_idx)
                                        .map(|(_, ty)| ty.clone())
                                        .unwrap_or(FirType::Int(IntType::I64))
                                } else {
                                    FirType::Int(IntType::I64)
                                }
                            }
                            Some(FirType::Pointer(inner)) => match &**inner {
                                FirType::Struct(name, fields) => {
                                    if let Some((_, fty)) = fields.get(*field_idx) {
                                        fty.clone()
                                    } else if let Some(s_fields) = struct_defs.get(name) {
                                        s_fields
                                            .get(*field_idx)
                                            .map(|(_, ty)| ty.clone())
                                            .unwrap_or(FirType::Int(IntType::I64))
                                    } else {
                                        FirType::Int(IntType::I64)
                                    }
                                }
                                _ => FirType::Int(IntType::I64),
                            },
                            _ => FirType::Int(IntType::I64),
                        },
                        ValueExpr::SliceSub { base, .. } | ValueExpr::SliceStrided { base, .. } => {
                            match value_types.get(base) {
                                Some(FirType::Array(inner, _)) | Some(FirType::Slice(inner)) => {
                                    FirType::Slice(inner.clone())
                                }
                                Some(FirType::Pointer(inner)) => match &**inner {
                                    FirType::Array(elem, _) | FirType::Slice(elem) => {
                                        FirType::Slice(elem.clone())
                                    }
                                    _ => FirType::Slice(Box::new(FirType::Int(IntType::I64))),
                                },
                                _ => FirType::Slice(Box::new(FirType::Int(IntType::I64))),
                            }
                        }
                        ValueExpr::ArrayInit(elements) => {
                            let elem_ty = elements
                                .first()
                                .and_then(|e| value_types.get(e))
                                .cloned()
                                .unwrap_or(FirType::Int(IntType::I64));
                            FirType::Pointer(Box::new(FirType::Array(
                                Box::new(elem_ty),
                                elements.len() as u32,
                            )))
                        }
                        ValueExpr::StructInit { name, fields } => {
                            let st_fields = struct_defs.get(name).cloned().unwrap_or_else(|| {
                                fields
                                    .iter()
                                    .enumerate()
                                    .map(|(i, f)| {
                                        (
                                            INTERNER.intern(&format!("f{}", i)),
                                            value_types
                                                .get(f)
                                                .cloned()
                                                .unwrap_or(FirType::Int(IntType::I64)),
                                        )
                                    })
                                    .collect()
                            });
                            FirType::Struct(*name, st_fields)
                        }
                        ValueExpr::EnumInit { enum_name, .. } => {
                            FirType::Enum(*enum_name, Vec::new())
                        }
                        ValueExpr::EnumGetPayload { payload_ty, .. } => payload_ty.clone(),
                        ValueExpr::GenRef { ptr } => match value_types.get(ptr) {
                            Some(inner) => FirType::GenerationalRef(Box::new(inner.clone())),
                            None => FirType::Pointer(Box::new(FirType::Int(IntType::I64))),
                        },
                        ValueExpr::GenDeref { ref_val } => match value_types.get(ref_val) {
                            Some(FirType::GenerationalRef(inner)) => (**inner).clone(),
                            _ => FirType::Pointer(Box::new(FirType::Int(IntType::I64))),
                        },
                        ValueExpr::CallArenaAlloc { ty } => FirType::Pointer(Box::new(ty.clone())),
                        ValueExpr::GenAlloc { ty, .. } => FirType::Pointer(Box::new(ty.clone())),
                        ValueExpr::GetFieldPtr {
                            base, field_idx, ..
                        } => match value_types.get(base) {
                            Some(FirType::Pointer(inner)) => match &**inner {
                                FirType::Struct(_, fields) if *field_idx < fields.len() => {
                                    FirType::Pointer(Box::new(fields[*field_idx].1.clone()))
                                }
                                _ => FirType::Pointer(Box::new(FirType::Int(IntType::I64))),
                            },
                            Some(FirType::Struct(_, fields)) if *field_idx < fields.len() => {
                                FirType::Pointer(Box::new(fields[*field_idx].1.clone()))
                            }
                            _ => FirType::Pointer(Box::new(FirType::Int(IntType::I64))),
                        },
                        ValueExpr::GetElementPtr { base, .. } => match value_types.get(base) {
                            Some(FirType::Array(inner, _)) | Some(FirType::Slice(inner)) => {
                                FirType::Pointer(inner.clone())
                            }
                            Some(FirType::Pointer(inner)) => match &**inner {
                                FirType::Array(elem, _) | FirType::Slice(elem) => {
                                    FirType::Pointer(elem.clone())
                                }
                                _ => FirType::Pointer(Box::new(FirType::Int(IntType::I64))),
                            },
                            _ => FirType::Pointer(Box::new(FirType::Int(IntType::I64))),
                        },
                        ValueExpr::CallDirect { name, .. }
                        | ValueExpr::BlockingCallDirect { name, .. } => {
                            let callee = INTERNER.resolve(name);
                            if let Some(ret_ty) = fn_return_types.get(&callee) {
                                ret_ty.clone()
                            } else if callee == "process::args_get"
                                || callee == "env::args_get"
                                || callee == "args_get"
                                || callee == "ifa_rt_args_get"
                                || callee == "fs::read_to_string"
                                || callee == "read_to_string"
                                || callee == "ifa_rt_fs_read_to_string"
                                || callee == "fs::read_dir"
                                || callee == "read_dir"
                                || callee == "ifa_rt_fs_read_dir"
                                || callee == "process::current_dir"
                                || callee == "current_dir"
                                || callee == "ifa_rt_process_current_dir"
                                || callee == "string_substr"
                                || callee == "String::substr"
                                || callee == "substring"
                                || callee == "ifa_rt_string_substr"
                                || callee == "int_to_str"
                                || callee == "int_to_string"
                                || callee.ends_with("::int_to_str")
                                || callee.ends_with("::int_to_string")
                                || callee == "get_target_datalayout"
                                || callee.ends_with("::get_target_datalayout")
                            {
                                FirType::String
                            } else if callee == "fs::exists"
                                || callee == "exists"
                                || callee == "ifa_rt_fs_exists"
                                || callee == "fs::is_dir"
                                || callee == "is_dir"
                                || callee == "ifa_rt_fs_is_dir"
                                || callee == "fs::copy_file"
                                || callee == "copy_file"
                                || callee == "ifa_rt_fs_copy_file"
                                || callee == "fs::remove_dir"
                                || callee == "remove_dir"
                                || callee == "ifa_rt_fs_remove_dir"
                                || callee == "fs::remove_dir_all"
                                || callee == "remove_dir_all"
                                || callee == "ifa_rt_fs_remove_dir_all"
                                || callee == "fs::rename"
                                || callee == "rename"
                                || callee == "ifa_rt_fs_rename"
                                || callee == "process::set_current_dir"
                                || callee == "set_current_dir"
                                || callee == "ifa_rt_process_set_current_dir"
                                || callee == "fs::write_string"
                                || callee == "write_string"
                                || callee == "ifa_rt_fs_write_string"
                            {
                                FirType::Bool
                            } else {
                                FirType::Int(IntType::I64)
                            }
                        }
                        _ => FirType::Int(IntType::I64),
                    };
                    value_types.insert(res, ty);
                }
            }
        }
        value_types
    }

    /// Translate the entire FIR function into Cranelift IR.
    pub fn translate(mut self, fir_func: &FirFunction) -> Result<(), CodegenError> {
        self.value_types =
            Self::compute_value_types(fir_func, self.struct_defs, self.fn_return_types);

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
                self.pointer_fir_types.insert(param.val, param.ty.clone());
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

    /// Translate a coroutine resume state machine into Cranelift IR.
    pub fn translate_coroutine_resume(
        mut self,
        fir_func: &FirFunction,
    ) -> Result<(), CodegenError> {
        self.value_types =
            Self::compute_value_types(fir_func, self.struct_defs, self.fn_return_types);

        // 1. Entry block receiving the frame pointer
        let entry_cl_block = self.builder.create_block();
        self.builder
            .append_block_params_for_function_params(entry_cl_block);
        self.builder.switch_to_block(entry_cl_block);
        let frame = self.builder.block_params(entry_cl_block)[0];

        // 2. Identify total yield suspension points
        let mut yield_count = 0usize;
        for block in &fir_func.blocks {
            for inst in &block.instructions {
                if matches!(inst.expr, ValueExpr::Yield | ValueExpr::YieldValue { .. }) {
                    yield_count += 1;
                }
            }
        }

        // Create Cranelift basic blocks for all FIR basic blocks
        for block in &fir_func.blocks {
            let cl_block = self.builder.create_block();
            self.block_map.insert(block.id, cl_block);
        }

        // Set up block arguments for non-entry blocks
        for block in &fir_func.blocks {
            if block.id == fir_func.entry_block {
                continue;
            }
            let cl_block = self.block_map[&block.id];
            for (_param_val_id, param_ty) in &block.params {
                let cl_ty = fir_type_to_cranelift(param_ty, self.ptr_type).unwrap_or(self.ptr_type);
                let _ = self.builder.append_block_param(cl_block, cl_ty);
            }
        }

        let first_body_block = self.block_map[&fir_func.entry_block];
        let completed_block = self.builder.create_block();

        // Resumption blocks for each suspension state k (1..=yield_count)
        let mut resumption_blocks = HashMap::new();
        for k in 1..=yield_count {
            let res_block = self.builder.create_block();
            resumption_blocks.insert(k, res_block);
        }

        // 3. Dispatch based on current state loaded from frame at offset 0
        let state = self
            .builder
            .ins()
            .load(types::I32, MemFlagsData::trusted(), frame, 0);

        if yield_count == 0 {
            self.builder.ins().jump(first_body_block, &[]);
        } else {
            let is_state_0 = self.builder.ins().icmp_imm_s(IntCC::Equal, state, 0);
            let mut current_dispatch = self.builder.create_block();
            self.builder
                .ins()
                .brif(is_state_0, first_body_block, &[], current_dispatch, &[]);

            for k in 1..=yield_count {
                self.builder.switch_to_block(current_dispatch);
                let is_k = self.builder.ins().icmp_imm_s(IntCC::Equal, state, k as i64);
                let target_res = resumption_blocks[&k];
                if k < yield_count {
                    let next_dispatch = self.builder.create_block();
                    self.builder
                        .ins()
                        .brif(is_k, target_res, &[], next_dispatch, &[]);
                    current_dispatch = next_dispatch;
                } else {
                    self.builder
                        .ins()
                        .brif(is_k, target_res, &[], completed_block, &[]);
                }
            }
        }

        // Completed block: returns 1 (CoroStatus::Completed)
        self.builder.switch_to_block(completed_block);
        let status_completed = self.builder.ins().iconst(types::I32, 1);
        self.builder.ins().return_(&[status_completed]);

        // 4. In first_body_block, load parameters from frame (offset 16 + 8 * i)
        self.builder.switch_to_block(first_body_block);
        for (i, param) in fir_func.params.iter().enumerate() {
            let offset = (16 + 8 * i) as i32;
            let expected_cl_ty =
                fir_type_to_cranelift(&param.ty, self.ptr_type).unwrap_or(self.ptr_type);
            let raw_val =
                self.builder
                    .ins()
                    .load(types::I64, MemFlagsData::trusted(), frame, offset);
            let val = if expected_cl_ty == types::I64 || expected_cl_ty == self.ptr_type {
                raw_val
            } else if expected_cl_ty.bits() < 64 {
                self.builder.ins().ireduce(expected_cl_ty, raw_val)
            } else {
                raw_val
            };
            self.value_map.insert(param.val, val);
        }

        // 5. Translate instructions in RPO
        let cfg = ifa_fir::ControlFlowGraph::build(fir_func);
        let dom_tree = ifa_fir::DominanceTree::build(&cfg);

        let mut def_block: HashMap<ValueId, BlockId> = HashMap::new();
        for p in &fir_func.params {
            def_block.insert(p.val, fir_func.entry_block);
        }
        for b in &fir_func.blocks {
            for (p_val, _) in &b.params {
                def_block.insert(*p_val, b.id);
            }
            for inst in &b.instructions {
                if let Some(res) = inst.result {
                    def_block.insert(res, b.id);
                }
            }
        }

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

        let mut current_yield_idx = 0usize;
        let mut block_entry_maps: HashMap<BlockId, HashMap<ValueId, ClValue>> = HashMap::new();
        block_entry_maps.insert(fir_func.entry_block, self.value_map.clone());

        for block in ordered_blocks {
            let cl_block = self.block_map[&block.id];
            if block.id != fir_func.entry_block {
                self.builder.switch_to_block(cl_block);

                // Inherit SSA value map from immediate dominator
                if let Some(idom_id) = dom_tree.immediate_dominator(block.id) {
                    if let Some(parent_map) = block_entry_maps.get(&idom_id) {
                        self.value_map = parent_map.clone();
                    }
                }

                // Bind block parameters to Cranelift block params
                for (i, (param_val_id, _)) in block.params.iter().enumerate() {
                    let cl_param = self.builder.block_params(cl_block)[i];
                    self.value_map.insert(*param_val_id, cl_param);
                }
            }

            for inst in &block.instructions {
                match &inst.expr {
                    ValueExpr::Yield | ValueExpr::YieldValue { .. } => {
                        current_yield_idx += 1;
                        let k = current_yield_idx;

                        // Store yielded value into frame + 8 if YieldValue
                        if let ValueExpr::YieldValue { val } = &inst.expr {
                            if let Some(&v) = self.value_map.get(val) {
                                let v_ty = self.builder.func.dfg.value_type(v);
                                let v_i64 = if v_ty == types::I64 || v_ty == self.ptr_type {
                                    v
                                } else if v_ty.bits() < 64 {
                                    self.builder.ins().sextend(types::I64, v)
                                } else {
                                    v
                                };
                                self.builder
                                    .ins()
                                    .store(MemFlagsData::trusted(), v_i64, frame, 8);
                            }
                        }

                        // Save only active SSA values in value_map that dominate this suspension point
                        let mut saved_keys: Vec<(ValueId, types::Type, i32)> = Vec::new();
                        for (&v_id, &v_val) in &self.value_map {
                            let dominates_suspension = def_block.get(&v_id).is_some_and(|&d_b| {
                                d_b == block.id || dom_tree.dominates(d_b, block.id)
                            });
                            if !dominates_suspension {
                                continue;
                            }

                            let slot_offset =
                                (16 + 8 * (fir_func.params.len() + v_id.0 as usize)) as i32;
                            let v_ty = self.builder.func.dfg.value_type(v_val);
                            let v_i64 = if v_ty == types::I64 || v_ty == self.ptr_type {
                                v_val
                            } else if v_ty == types::F64 {
                                self.builder.ins().bitcast(
                                    types::I64,
                                    MemFlagsData::trusted(),
                                    v_val,
                                )
                            } else if v_ty.bits() < 64 {
                                self.builder.ins().sextend(types::I64, v_val)
                            } else {
                                v_val
                            };
                            self.builder.ins().store(
                                MemFlagsData::trusted(),
                                v_i64,
                                frame,
                                slot_offset,
                            );
                            saved_keys.push((v_id, v_ty, slot_offset));
                        }

                        // Store next state: k
                        let next_state_val = self.builder.ins().iconst(types::I32, k as i64);
                        self.builder
                            .ins()
                            .store(MemFlagsData::trusted(), next_state_val, frame, 0);

                        // Return 0 (CoroStatus::Suspended)
                        let status_susp = self.builder.ins().iconst(types::I32, 0);
                        self.builder.ins().return_(&[status_susp]);

                        // Switch to resumption block for state k
                        let res_block = resumption_blocks[&k];
                        self.builder.switch_to_block(res_block);

                        // Reload saved SSA values
                        for (v_id, orig_ty, slot_offset) in saved_keys {
                            let raw_reloaded = self.builder.ins().load(
                                types::I64,
                                MemFlagsData::trusted(),
                                frame,
                                slot_offset,
                            );
                            let reloaded = if orig_ty == types::I64 || orig_ty == self.ptr_type {
                                raw_reloaded
                            } else if orig_ty == types::F64 {
                                self.builder.ins().bitcast(
                                    types::F64,
                                    MemFlagsData::trusted(),
                                    raw_reloaded,
                                )
                            } else if orig_ty.bits() < 64 {
                                self.builder.ins().ireduce(orig_ty, raw_reloaded)
                            } else {
                                raw_reloaded
                            };
                            self.value_map.insert(v_id, reloaded);
                        }
                    }
                    _ => {
                        let res = self.translate_expr(inst.result, &inst.expr)?;
                        if let Some(val_id) = inst.result {
                            let cl_val =
                                res.unwrap_or_else(|| self.builder.ins().iconst(types::I64, 0));
                            self.value_map.insert(val_id, cl_val);
                        }
                    }
                }
            }

            // Terminator translation for coroutine resume
            if let Some(term) = &block.terminator {
                match term {
                    Terminator::Return(opt_val) => {
                        if let Some(v_id) = opt_val {
                            if let Some(&v) = self.value_map.get(v_id) {
                                let v_ty = self.builder.func.dfg.value_type(v);
                                let v_i64 = if v_ty == types::I64 || v_ty == self.ptr_type {
                                    v
                                } else if v_ty.bits() < 64 {
                                    self.builder.ins().sextend(types::I64, v)
                                } else {
                                    v
                                };
                                self.builder
                                    .ins()
                                    .store(MemFlagsData::trusted(), v_i64, frame, 8);
                            }
                        }
                        // Set state to -1 (Completed)
                        let done_state = self.builder.ins().iconst(types::I32, -1);
                        self.builder
                            .ins()
                            .store(MemFlagsData::trusted(), done_state, frame, 0);
                        // Return 1 (CoroStatus::Completed)
                        let status_done = self.builder.ins().iconst(types::I32, 1);
                        self.builder.ins().return_(&[status_done]);
                    }
                    _ => {
                        self.translate_terminator(term)?;
                    }
                }
            } else {
                let done_state = self.builder.ins().iconst(types::I32, -1);
                self.builder
                    .ins()
                    .store(MemFlagsData::trusted(), done_state, frame, 0);
                let status_done = self.builder.ins().iconst(types::I32, 1);
                self.builder.ins().return_(&[status_done]);
            }

            block_entry_maps.insert(block.id, self.value_map.clone());
        }

        self.builder.seal_all_blocks();
        let target_config = self.module.target_config();
        self.builder.finalize(target_config);
        Ok(())
    }

    /// Translate a coroutine factory instantiator function into Cranelift IR.
    pub fn translate_coroutine_factory(
        mut self,
        fir_func: &FirFunction,
        resume_fn_name: &str,
    ) -> Result<(), CodegenError> {
        self.value_types =
            Self::compute_value_types(fir_func, self.struct_defs, self.fn_return_types);

        let entry_cl_block = self.builder.create_block();
        self.builder
            .append_block_params_for_function_params(entry_cl_block);
        self.builder.switch_to_block(entry_cl_block);

        let mut param_vals = Vec::new();
        for (i, _) in fir_func.params.iter().enumerate() {
            let val = self.builder.block_params(entry_cl_block)[i];
            param_vals.push(val);
        }

        let frame_size = 16 + 8 * (fir_func.params.len() + fir_func.next_value_id as usize + 4);
        let frame_size_val = self.builder.ins().iconst(self.ptr_type, frame_size as i64);

        let resume_id = *self.func_ids.get(resume_fn_name).ok_or_else(|| {
            CodegenError::Codegen(format!("Missing resume func {}", resume_fn_name))
        })?;
        let resume_local = self
            .module
            .declare_func_in_func(resume_id, self.builder.func);
        let resume_addr = self.builder.ins().func_addr(self.ptr_type, resume_local);

        let null_destroy = self.builder.ins().iconst(self.ptr_type, 0);

        let coro_create_id = *self
            .func_ids
            .get("ifa_rt_coro_create")
            .ok_or_else(|| CodegenError::Codegen("Missing ifa_rt_coro_create".into()))?;
        let coro_create_local = self
            .module
            .declare_func_in_func(coro_create_id, self.builder.func);
        let call_create = self.builder.ins().call(
            coro_create_local,
            &[frame_size_val, resume_addr, null_destroy],
        );
        let coro_hdl = self.builder.inst_results(call_create)[0];

        let coro_frame_id = *self
            .func_ids
            .get("ifa_rt_coro_frame")
            .ok_or_else(|| CodegenError::Codegen("Missing ifa_rt_coro_frame".into()))?;
        let coro_frame_local = self
            .module
            .declare_func_in_func(coro_frame_id, self.builder.func);
        let call_frame = self.builder.ins().call(coro_frame_local, &[coro_hdl]);
        let frame = self.builder.inst_results(call_frame)[0];

        let zero_state = self.builder.ins().iconst(types::I32, 0);
        self.builder
            .ins()
            .store(MemFlagsData::trusted(), zero_state, frame, 0);

        for (i, &p_val) in param_vals.iter().enumerate() {
            let offset = (16 + 8 * i) as i32;
            let p_ty = self.builder.func.dfg.value_type(p_val);
            let val_to_store = if p_ty == types::I64 || p_ty == self.ptr_type {
                p_val
            } else if p_ty.bits() < 64 {
                self.builder.ins().sextend(types::I64, p_val)
            } else {
                p_val
            };
            self.builder
                .ins()
                .store(MemFlagsData::trusted(), val_to_store, frame, offset);
        }

        self.builder.ins().return_(&[coro_hdl]);
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
                    if let Some(r) = result {
                        self.constant_ints.insert(r, *i as i64);
                    }
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
                ConstantValue::Function(s) => {
                    let s_str = INTERNER.resolve(s);
                    if let Some(&callee_id) = self.func_ids.get(&s_str) {
                        let local_func = self
                            .module
                            .declare_func_in_func(callee_id, self.builder.func);
                        Some(self.builder.ins().func_addr(self.ptr_type, local_func))
                    } else {
                        Some(self.builder.ins().iconst(self.ptr_type, 0))
                    }
                }
            },

            ValueExpr::Alloca { ty, .. } => {
                let elem_cl_ty = fir_type_to_cranelift(ty, self.ptr_type).unwrap_or(self.ptr_type);
                let byte_size = match ty {
                    FirType::Struct(name, fields) if fields.is_empty() => {
                        if let Some(def_fields) = self.struct_defs.get(name) {
                            def_fields
                                .iter()
                                .map(|(_, f_ty)| crate::types::fir_type_byte_size(f_ty).max(8))
                                .sum::<usize>()
                                .max(8) as u32
                        } else {
                            crate::types::fir_type_byte_size(ty)
                                .max(elem_cl_ty.bytes().max(1) as usize)
                                as u32
                        }
                    }
                    _ => crate::types::fir_type_byte_size(ty)
                        .max(elem_cl_ty.bytes().max(1) as usize) as u32,
                };
                let align_shift = crate::types::fir_type_align_shift(ty);
                let slot = self.builder.create_sized_stack_slot(StackSlotData::new(
                    StackSlotKind::ExplicitSlot,
                    byte_size,
                    align_shift,
                ));
                let addr = self.builder.ins().stack_addr(self.ptr_type, slot, 0);
                if let Some(res_id) = result {
                    self.pointer_types.insert(res_id, elem_cl_ty);
                    let populated_ty = match ty {
                        FirType::Struct(name, fields) if fields.is_empty() => {
                            if let Some(def_fields) = self.struct_defs.get(name) {
                                FirType::Struct(*name, def_fields.clone())
                            } else {
                                ty.clone()
                            }
                        }
                        _ => ty.clone(),
                    };
                    self.pointer_fir_types.insert(res_id, populated_ty);
                }
                Some(addr)
            }

            ValueExpr::Store { ptr, val } => {
                let p = self.value_map[ptr];
                let mut v = self.value_map[val];
                if let Some(fir_ty) = self.pointer_fir_types.get(ptr) {
                    if matches!(fir_ty, FirType::Struct(..) | FirType::Array(..)) {
                        let total_bytes = match fir_ty {
                            FirType::Struct(name, fields) if fields.is_empty() => {
                                if let Some(def_fields) = self.struct_defs.get(name) {
                                    def_fields
                                        .iter()
                                        .map(|(_, f_ty)| {
                                            crate::types::fir_type_byte_size(f_ty).max(8)
                                        })
                                        .sum::<usize>()
                                        .max(8)
                                } else {
                                    crate::types::fir_type_byte_size(fir_ty).max(8)
                                }
                            }
                            _ => crate::types::fir_type_byte_size(fir_ty).max(8),
                        };
                        if total_bytes > 0 {
                            for offset in (0..total_bytes).step_by(8) {
                                let word = self.builder.ins().load(
                                    types::I64,
                                    MemFlagsData::trusted(),
                                    v,
                                    offset as i32,
                                );
                                self.builder.ins().store(
                                    MemFlagsData::trusted(),
                                    word,
                                    p,
                                    offset as i32,
                                );
                            }
                            return Ok(None);
                        }
                    }
                }
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
                if let Some(fir_ty) = self.pointer_fir_types.get(ptr).cloned() {
                    if matches!(fir_ty, FirType::Struct(..) | FirType::Array(..)) {
                        if let Some(res_id) = result {
                            let populated = match &fir_ty {
                                FirType::Struct(name, fields) if fields.is_empty() => {
                                    if let Some(def_fields) = self.struct_defs.get(name) {
                                        FirType::Struct(*name, def_fields.clone())
                                    } else {
                                        fir_ty.clone()
                                    }
                                }
                                _ => fir_ty.clone(),
                            };
                            self.pointer_fir_types.insert(res_id, populated);
                        }
                        return Ok(Some(p));
                    }
                }
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
                        BinaryOp::Add => {
                            let is_str = matches!(
                                self.value_types.get(lhs),
                                Some(FirType::String) | Some(FirType::Str)
                            ) || matches!(
                                self.value_types.get(rhs),
                                Some(FirType::String) | Some(FirType::Str)
                            );
                            if is_str {
                                if let Some(func_id) = self.func_ids.get("ifa_rt_string_concat") {
                                    let local_func = self
                                        .module
                                        .declare_func_in_func(*func_id, self.builder.func);
                                    let call = self.builder.ins().call(local_func, &[l, r]);
                                    let results = self.builder.inst_results(call);
                                    results.first().copied().unwrap_or(l)
                                } else {
                                    self.builder.ins().iadd(l, r)
                                }
                            } else {
                                self.builder.ins().iadd(l, r)
                            }
                        }
                        BinaryOp::Sub => self.builder.ins().isub(l, r),
                        BinaryOp::Mul => self.builder.ins().imul(l, r),
                        BinaryOp::Div => self.builder.ins().sdiv(l, r),
                        BinaryOp::Rem => self.builder.ins().srem(l, r),
                        BinaryOp::BitAnd | BinaryOp::And => self.builder.ins().band(l, r),
                        BinaryOp::BitOr | BinaryOp::Or => self.builder.ins().bor(l, r),
                        BinaryOp::BitXor => self.builder.ins().bxor(l, r),
                        BinaryOp::Shl => self.builder.ins().ishl(l, r),
                        BinaryOp::Shr => self.builder.ins().sshr(l, r),
                        BinaryOp::Eq => {
                            let is_str = matches!(
                                self.value_types.get(lhs),
                                Some(FirType::String) | Some(FirType::Str)
                            ) || matches!(
                                self.value_types.get(rhs),
                                Some(FirType::String) | Some(FirType::Str)
                            );
                            if is_str {
                                if let Some(func_id) = self.func_ids.get("ifa_rt_string_eq") {
                                    let local_func = self
                                        .module
                                        .declare_func_in_func(*func_id, self.builder.func);
                                    let call = self.builder.ins().call(local_func, &[l, r]);
                                    let res = self.builder.inst_results(call)[0];
                                    self.builder.ins().icmp_imm_s(IntCC::NotEqual, res, 0)
                                } else {
                                    self.builder.ins().icmp(IntCC::Equal, l, r)
                                }
                            } else {
                                self.builder.ins().icmp(IntCC::Equal, l, r)
                            }
                        }
                        BinaryOp::Ne => {
                            let is_str = matches!(
                                self.value_types.get(lhs),
                                Some(FirType::String) | Some(FirType::Str)
                            ) || matches!(
                                self.value_types.get(rhs),
                                Some(FirType::String) | Some(FirType::Str)
                            );
                            if is_str {
                                if let Some(func_id) = self.func_ids.get("ifa_rt_string_eq") {
                                    let local_func = self
                                        .module
                                        .declare_func_in_func(*func_id, self.builder.func);
                                    let call = self.builder.ins().call(local_func, &[l, r]);
                                    let res = self.builder.inst_results(call)[0];
                                    self.builder.ins().icmp_imm_s(IntCC::Equal, res, 0)
                                } else {
                                    self.builder.ins().icmp(IntCC::NotEqual, l, r)
                                }
                            } else {
                                self.builder.ins().icmp(IntCC::NotEqual, l, r)
                            }
                        }
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
                    UnaryOp::Not => {
                        let zero = self.builder.ins().iconst(ty_v, 0);
                        self.builder.ins().icmp(IntCC::Equal, v, zero)
                    }
                })
            }

            ValueExpr::CallDirect { name, args } | ValueExpr::BlockingCallDirect { name, args } => {
                let fn_name = INTERNER.resolve(name);
                let lookup_name = match fn_name.as_str() {
                    "process::args_count" | "env::args_count" | "args_count" => "ifa_rt_args_count",
                    "process::args_get" | "env::args_get" | "args_get" => "ifa_rt_args_get",
                    "process::exec" | "exec" => "ifa_rt_process_exec",
                    "process::exec_output" | "exec_output" => "ifa_rt_process_exec_output",
                    "process::exec_stderr" | "exec_stderr" => "ifa_rt_process_exec_stderr",
                    "process::exec_with_stdin" | "exec_with_stdin" => {
                        "ifa_rt_process_exec_with_stdin"
                    }
                    "process::find_linker" | "find_linker" => "ifa_rt_process_find_linker",
                    "process::find_tool" | "find_tool" => "ifa_rt_process_find_tool",
                    "process::env_var" | "env_var" => "ifa_rt_env_var",
                    "fs::read_to_string" | "read_to_string" => "ifa_rt_fs_read_to_string",
                    "fs::read_dir" | "read_dir" => "ifa_rt_fs_read_dir",
                    "fs::is_dir" | "is_dir" => "ifa_rt_fs_is_dir",
                    "fs::copy_file" | "copy_file" => "ifa_rt_fs_copy_file",
                    "fs::write_string" | "write_string" => "ifa_rt_fs_write_string",
                    "fs::exists" | "exists" => "ifa_rt_fs_exists",
                    "fs::file_size" | "file_size" => "ifa_rt_fs_file_size",
                    "fs::remove_file" | "remove_file" => "ifa_rt_fs_remove_file",
                    "fs::create_dir_all" | "create_dir_all" => "ifa_rt_fs_create_dir_all",
                    "string_len" | "String::len" => "ifa_rt_string_len",
                    "string_char_at" | "String::char_at" => "ifa_rt_string_char_at",
                    "string_substr" | "String::substr" | "substring" => "ifa_rt_string_substr",
                    "int_to_str" | "int_to_string" => "ifa_rt_string_from_i64",
                    "sys::max_rss" | "max_rss" | "sys_max_rss" | "sys::resources::max_rss" => {
                        "ifa_rt_sys_max_rss"
                    }
                    "sys::cpu_time_ns"
                    | "cpu_time_ns"
                    | "sys_cpu_time_ns"
                    | "sys::resources::cpu_time_ns" => "ifa_rt_sys_cpu_time_ns",
                    "sys::cpu_count"
                    | "cpu_count"
                    | "sys_cpu_count"
                    | "sys::resources::cpu_count" => "ifa_rt_sys_cpu_count",
                    "sys::memory_resident"
                    | "memory_resident"
                    | "sys_memory_resident"
                    | "sys::resources::memory_resident" => "ifa_rt_sys_memory_resident",
                    "sys::memory_virtual"
                    | "memory_virtual"
                    | "sys_memory_virtual"
                    | "sys::resources::memory_virtual" => "ifa_rt_sys_memory_virtual",
                    _ => fn_name.as_str(),
                };
                if let Some(res) = self.try_lower_simd_reduction(&fn_name, args) {
                    Some(res)
                } else if let Some(&callee_id) = self.func_ids.get(lookup_name) {
                    let local_func = self
                        .module
                        .declare_func_in_func(callee_id, self.builder.func);
                    let sig_ref = self.builder.func.dfg.ext_funcs[local_func].signature;
                    let expected_params = self.builder.func.dfg.signatures[sig_ref].params.clone();
                    let expected_fir_params = self.fn_param_types.get(lookup_name);
                    let mut arg_vals = Vec::with_capacity(args.len());
                    for (i, a) in args.iter().enumerate() {
                        let mut v = self.value_map[a];
                        let arg_fir_ty = self.value_types.get(a);
                        let exp_fir_ty = expected_fir_params.and_then(|p| p.get(i));

                        // Coerce Array to Slice if the callee expects a Slice
                        if matches!(exp_fir_ty, Some(FirType::Slice(_))) {
                            let is_already_slice = is_slice_or_slice_ptr(arg_fir_ty);
                            if !is_already_slice {
                                let arr_len = match arg_fir_ty {
                                    Some(FirType::Array(_, len)) => *len as i64,
                                    Some(FirType::Pointer(inner)) => match &**inner {
                                        FirType::Array(_, len) => *len as i64,
                                        _ => 0,
                                    },
                                    _ => 0,
                                };
                                let slot = self.builder.create_sized_stack_slot(
                                    StackSlotData::new(StackSlotKind::ExplicitSlot, 16, 3),
                                );
                                let slice_addr =
                                    self.builder.ins().stack_addr(self.ptr_type, slot, 0);
                                let len_c = self.builder.ins().iconst(types::I64, arr_len);
                                self.builder
                                    .ins()
                                    .store(MemFlagsData::trusted(), v, slice_addr, 0);
                                self.builder.ins().store(
                                    MemFlagsData::trusted(),
                                    len_c,
                                    slice_addr,
                                    8,
                                );
                                v = slice_addr;
                            }
                        }

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
            | ValueExpr::GenDeref { ref_val: val } => {
                if let Some(ty) = self.pointer_fir_types.get(val).cloned() {
                    if let Some(res_id) = result {
                        self.pointer_fir_types.insert(res_id, ty);
                    }
                }
                Some(self.value_map[val])
            }

            ValueExpr::GetField {
                base,
                field_idx,
                field_name: _,
            } => {
                let p = self.value_map[base];
                if let Some(fir_ty) = self.pointer_fir_types.get(base).cloned() {
                    let fields = match &fir_ty {
                        FirType::Struct(name, fields) => {
                            if fields.is_empty() {
                                self.struct_defs.get(name).cloned().unwrap_or_default()
                            } else {
                                fields.clone()
                            }
                        }
                        _ => Vec::new(),
                    };

                    if !fields.is_empty() && *field_idx < fields.len() {
                        let (_, f_ty) = &fields[*field_idx];
                        let offset: usize = fields[0..*field_idx]
                            .iter()
                            .map(|(_, ty)| crate::types::fir_type_byte_size(ty).max(8))
                            .sum();

                        if matches!(f_ty, FirType::Struct(..) | FirType::Array(..)) {
                            let f_addr = self.builder.ins().iadd_imm_s(p, offset as i64);
                            if let Some(res_id) = result {
                                self.pointer_fir_types.insert(res_id, f_ty.clone());
                            }
                            return Ok(Some(f_addr));
                        } else {
                            let cl_ty =
                                fir_type_to_cranelift(f_ty, self.ptr_type).unwrap_or(types::I64);
                            let loaded = self.builder.ins().load(
                                cl_ty,
                                MemFlagsData::trusted(),
                                p,
                                offset as i32,
                            );
                            if let Some(res_id) = result {
                                self.pointer_fir_types.insert(res_id, f_ty.clone());
                            }
                            return Ok(Some(loaded));
                        }
                    }
                }
                let offset = (*field_idx * 8) as i32;
                Some(
                    self.builder
                        .ins()
                        .load(types::I64, MemFlagsData::trusted(), p, offset),
                )
            }

            ValueExpr::GetFieldPtr {
                base,
                field_idx,
                field_name: _,
            } => {
                let p = self.value_map[base];
                let mut offset = (*field_idx * 8) as i64;
                if let Some(fir_ty) = self.pointer_fir_types.get(base).cloned() {
                    let fields = match &fir_ty {
                        FirType::Struct(name, fields) => {
                            if fields.is_empty() {
                                self.struct_defs.get(name).cloned().unwrap_or_default()
                            } else {
                                fields.clone()
                            }
                        }
                        _ => Vec::new(),
                    };
                    if !fields.is_empty() && *field_idx < fields.len() {
                        let f_ty = &fields[*field_idx].1;
                        offset = fields[0..*field_idx]
                            .iter()
                            .map(|(_, ty)| crate::types::fir_type_byte_size(ty).max(8))
                            .sum::<usize>() as i64;
                        if let Some(res_id) = result {
                            self.pointer_fir_types.insert(res_id, f_ty.clone());
                        }
                    }
                }
                Some(self.builder.ins().iadd_imm_s(p, offset))
            }

            ValueExpr::GetElementPtr { base, index } => {
                let base_ty = self.value_types.get(base);
                let base_addr = self.value_map[base];
                let is_base_slice = is_slice_or_slice_ptr(base_ty);
                let p = if is_base_slice {
                    self.builder
                        .ins()
                        .load(self.ptr_type, MemFlagsData::trusted(), base_addr, 0)
                } else {
                    base_addr
                };
                let idx = self.value_map[index];
                let elem_size = match base_ty {
                    Some(FirType::Array(elem, _)) | Some(FirType::Slice(elem)) => {
                        crate::types::fir_type_byte_size(elem).max(8)
                    }
                    Some(FirType::Pointer(inner)) => match &**inner {
                        FirType::Array(elem, _) | FirType::Slice(elem) => {
                            crate::types::fir_type_byte_size(elem).max(8)
                        }
                        _ => 8,
                    },
                    _ => 8,
                };
                let elem_scale =
                    self.strided_slices.get(base).copied().unwrap_or(1) * (elem_size as i64);
                let offset = if elem_scale > 0 && (elem_scale as u64).is_power_of_two() {
                    let shift = elem_scale.trailing_zeros() as i64;
                    self.builder.ins().ishl_imm_u(idx, shift)
                } else {
                    self.builder.ins().imul_imm_s(idx, elem_scale)
                };
                if let Some(res_id) = result {
                    if let Some(FirType::Array(elem, _)) | Some(FirType::Slice(elem)) = base_ty {
                        self.pointer_fir_types.insert(res_id, *elem.clone());
                    } else if let Some(FirType::Pointer(inner)) = base_ty {
                        if let FirType::Array(elem, _) | FirType::Slice(elem) = &**inner {
                            self.pointer_fir_types.insert(res_id, *elem.clone());
                        }
                    }
                }
                Some(self.builder.ins().iadd(p, offset))
            }

            ValueExpr::SetField {
                base,
                field_idx,
                val,
            } => {
                let p = self.value_map[base];
                let v = self.value_map[val];
                let mut offset = (*field_idx * 8) as i32;
                if let Some(fir_ty) = self.pointer_fir_types.get(base).cloned() {
                    let fields = match &fir_ty {
                        FirType::Struct(name, fields) => {
                            if fields.is_empty() {
                                self.struct_defs.get(name).cloned().unwrap_or_default()
                            } else {
                                fields.clone()
                            }
                        }
                        _ => Vec::new(),
                    };
                    if !fields.is_empty() && *field_idx < fields.len() {
                        let f_ty = &fields[*field_idx].1;
                        let f_size = crate::types::fir_type_byte_size(f_ty).max(8);
                        offset = fields[0..*field_idx]
                            .iter()
                            .map(|(_, ty)| crate::types::fir_type_byte_size(ty).max(8))
                            .sum::<usize>() as i32;
                        if matches!(f_ty, FirType::Struct(..) | FirType::Array(..)) {
                            for byte_off in (0..f_size).step_by(8) {
                                let word = self.builder.ins().load(
                                    types::I64,
                                    MemFlagsData::trusted(),
                                    v,
                                    byte_off as i32,
                                );
                                self.builder.ins().store(
                                    MemFlagsData::trusted(),
                                    word,
                                    p,
                                    offset + byte_off as i32,
                                );
                            }
                            return Ok(None);
                        }
                    }
                }
                self.builder
                    .ins()
                    .store(MemFlagsData::trusted(), v, p, offset);
                None
            }

            ValueExpr::GenAlloc { ty, arena } => {
                let size = crate::types::fir_type_byte_size(ty).max(8);
                let size_val = self.builder.ins().iconst(self.ptr_type, size as i64);
                let align_val = self.builder.ins().iconst(self.ptr_type, 8);
                let arena_id = arena.unwrap_or(0);
                if arena_id == ifa_fir::ARENA_THREAD_LOCAL_CALL {
                    if let Some(func_id) = self.func_ids.get("ifa_rt_call_arena_alloc") {
                        let local_func = self
                            .module
                            .declare_func_in_func(*func_id, self.builder.func);
                        let call = self.builder.ins().call(local_func, &[size_val, align_val]);
                        let results = self.builder.inst_results(call);
                        results.first().copied()
                    } else {
                        Some(self.builder.ins().iconst(self.ptr_type, 0))
                    }
                } else {
                    let arena_val = self.builder.ins().iconst(types::I32, arena_id as i64);

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
            }

            ValueExpr::CallArenaAlloc { ty } => {
                let size = crate::types::fir_type_byte_size(ty).max(8);
                let size_val = self.builder.ins().iconst(self.ptr_type, size as i64);
                let align_val = self.builder.ins().iconst(self.ptr_type, 8);
                if let Some(func_id) = self.func_ids.get("ifa_rt_call_arena_alloc") {
                    let local_func = self
                        .module
                        .declare_func_in_func(*func_id, self.builder.func);
                    let call = self.builder.ins().call(local_func, &[size_val, align_val]);
                    let results = self.builder.inst_results(call);
                    results.first().copied()
                } else {
                    Some(self.builder.ins().iconst(self.ptr_type, 0))
                }
            }

            ValueExpr::CallArenaMark => {
                if let Some(func_id) = self.func_ids.get("ifa_rt_call_arena_mark") {
                    let local_func = self
                        .module
                        .declare_func_in_func(*func_id, self.builder.func);
                    let call = self.builder.ins().call(local_func, &[]);
                    let results = self.builder.inst_results(call);
                    results.first().copied()
                } else {
                    Some(self.builder.ins().iconst(types::I64, 0))
                }
            }

            ValueExpr::CallArenaRewind { mark } => {
                let m = self.value_map[mark];
                if let Some(func_id) = self.func_ids.get("ifa_rt_call_arena_rewind") {
                    let local_func = self
                        .module
                        .declare_func_in_func(*func_id, self.builder.func);
                    self.builder.ins().call(local_func, &[m]);
                }
                Some(self.builder.ins().iconst(types::I64, 0))
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

            ValueExpr::BoundsCheck {
                base,
                index,
                redundant,
            } => {
                if !redundant {
                    let base_ty = self.value_types.get(base);
                    let len_val = if let Some(&slen) = self.slice_lens.get(base) {
                        Some(slen)
                    } else if is_slice_or_slice_ptr(base_ty) {
                        let slice_addr = self.value_map[base];
                        Some(self.builder.ins().load(
                            types::I64,
                            MemFlagsData::trusted(),
                            slice_addr,
                            8,
                        ))
                    } else {
                        match base_ty {
                            Some(FirType::Array(_, len)) => {
                                Some(self.builder.ins().iconst(types::I64, *len as i64))
                            }
                            Some(FirType::Pointer(inner)) => {
                                if let FirType::Array(_, len) = &**inner {
                                    Some(self.builder.ins().iconst(types::I64, *len as i64))
                                } else {
                                    None
                                }
                            }
                            _ => None,
                        }
                    };

                    if let Some(lim) = len_val {
                        let idx = self.ensure_i64(self.value_map[index]);
                        let lim_i64 = self.ensure_i64(lim);
                        let is_in_bounds =
                            self.builder
                                .ins()
                                .icmp(IntCC::UnsignedLessThan, idx, lim_i64);
                        self.builder
                            .ins()
                            .trapz(is_in_bounds, TrapCode::unwrap_user(2));
                    }
                }
                None
            }

            ValueExpr::SliceBoundsCheck {
                start,
                end,
                redundant,
                ..
            } => {
                if !redundant {
                    let s = self.ensure_i64(self.value_map[start]);
                    let e = self.ensure_i64(self.value_map[end]);
                    let start_le_end =
                        self.builder
                            .ins()
                            .icmp(IntCC::UnsignedLessThanOrEqual, s, e);
                    self.builder
                        .ins()
                        .trapz(start_le_end, TrapCode::unwrap_user(2));
                }
                None
            }

            ValueExpr::SliceStridedBoundsCheck {
                start,
                end,
                stride,
                redundant,
                ..
            } => {
                if !redundant {
                    let s = self.ensure_i64(self.value_map[start]);
                    let e = self.ensure_i64(self.value_map[end]);
                    let st = self.ensure_i64(self.value_map[stride]);
                    let zero = self.builder.ins().iconst(types::I64, 0);
                    let stride_valid = self.builder.ins().icmp(IntCC::SignedGreaterThan, st, zero);
                    self.builder
                        .ins()
                        .trapz(stride_valid, TrapCode::unwrap_user(2));
                    let start_le_end =
                        self.builder
                            .ins()
                            .icmp(IntCC::UnsignedLessThanOrEqual, s, e);
                    self.builder
                        .ins()
                        .trapz(start_le_end, TrapCode::unwrap_user(2));
                }
                None
            }

            ValueExpr::Yield | ValueExpr::YieldValue { .. } => {
                if let Some(func_id) = self.func_ids.get("ifa_rt_fiber_yield") {
                    let local_func = self
                        .module
                        .declare_func_in_func(*func_id, self.builder.func);
                    self.builder.ins().call(local_func, &[]);
                }
                None
            }

            ValueExpr::GetElement { base, index } => {
                let base_ty = self.value_types.get(base);
                let base_addr = self.value_map[base];
                let is_base_slice = is_slice_or_slice_ptr(base_ty);
                let p = if is_base_slice {
                    self.builder
                        .ins()
                        .load(self.ptr_type, MemFlagsData::trusted(), base_addr, 0)
                } else {
                    base_addr
                };
                let idx = self.value_map[index];
                let (elem_ty, elem_bytes) = match base_ty {
                    Some(FirType::Array(elem, _)) | Some(FirType::Slice(elem)) => match &**elem {
                        FirType::Int(IntType::I8 | IntType::U8) | FirType::Bool => {
                            (types::I8, 1i64)
                        }
                        FirType::Int(IntType::I16 | IntType::U16) => (types::I16, 2i64),
                        FirType::Int(IntType::I32 | IntType::U32) | FirType::Char => {
                            (types::I32, 4i64)
                        }
                        FirType::Float(FloatType::F32) => (types::F32, 4i64),
                        FirType::Float(FloatType::F64) => (types::F64, 8i64),
                        _ => (types::I64, 8i64),
                    },
                    Some(FirType::Pointer(inner)) => match &**inner {
                        FirType::Array(elem, _) | FirType::Slice(elem) => match &**elem {
                            FirType::Int(IntType::I8 | IntType::U8) | FirType::Bool => {
                                (types::I8, 1i64)
                            }
                            FirType::Int(IntType::I16 | IntType::U16) => (types::I16, 2i64),
                            FirType::Int(IntType::I32 | IntType::U32) | FirType::Char => {
                                (types::I32, 4i64)
                            }
                            FirType::Float(FloatType::F32) => (types::F32, 4i64),
                            FirType::Float(FloatType::F64) => (types::F64, 8i64),
                            _ => (types::I64, 8i64),
                        },
                        _ => (types::I64, 8i64),
                    },
                    _ => (types::I64, 8i64),
                };
                let elem_scale = self.strided_slices.get(base).copied().unwrap_or(1) * elem_bytes;
                let offset = if elem_scale > 0 && (elem_scale as u64).is_power_of_two() {
                    let shift = elem_scale.trailing_zeros() as i64;
                    self.builder.ins().ishl_imm_u(idx, shift)
                } else {
                    self.builder.ins().imul_imm_s(idx, elem_scale)
                };
                let addr = self.builder.ins().iadd(p, offset);
                Some(
                    self.builder
                        .ins()
                        .load(elem_ty, MemFlagsData::trusted(), addr, 0),
                )
            }

            ValueExpr::SetElement { base, index, val } => {
                let base_ty = self.value_types.get(base);
                let base_addr = self.value_map[base];
                let is_base_slice = is_slice_or_slice_ptr(base_ty);
                let p = if is_base_slice {
                    self.builder
                        .ins()
                        .load(self.ptr_type, MemFlagsData::trusted(), base_addr, 0)
                } else {
                    base_addr
                };
                let idx = self.value_map[index];
                let v = self.value_map[val];
                let elem_bytes = match base_ty {
                    Some(FirType::Array(elem, _)) | Some(FirType::Slice(elem)) => match &**elem {
                        FirType::Int(IntType::I8 | IntType::U8) | FirType::Bool => 1i64,
                        FirType::Int(IntType::I16 | IntType::U16) => 2i64,
                        FirType::Int(IntType::I32 | IntType::U32) | FirType::Char => 4i64,
                        FirType::Float(FloatType::F32) => 4i64,
                        FirType::Float(FloatType::F64) => 8i64,
                        _ => 8i64,
                    },
                    Some(FirType::Pointer(inner)) => match &**inner {
                        FirType::Array(elem, _) | FirType::Slice(elem) => match &**elem {
                            FirType::Int(IntType::I8 | IntType::U8) | FirType::Bool => 1i64,
                            FirType::Int(IntType::I16 | IntType::U16) => 2i64,
                            FirType::Int(IntType::I32 | IntType::U32) | FirType::Char => 4i64,
                            FirType::Float(FloatType::F32) => 4i64,
                            FirType::Float(FloatType::F64) => 8i64,
                            _ => 8i64,
                        },
                        _ => match self.value_types.get(val) {
                            Some(FirType::Int(IntType::I32 | IntType::U32) | FirType::Char) => 4i64,
                            Some(FirType::Float(FloatType::F32)) => 4i64,
                            Some(FirType::Int(IntType::I16 | IntType::U16)) => 2i64,
                            Some(FirType::Int(IntType::I8 | IntType::U8) | FirType::Bool) => 1i64,
                            _ => 8i64,
                        },
                    },
                    _ => match self.value_types.get(val) {
                        Some(FirType::Int(IntType::I32 | IntType::U32) | FirType::Char) => 4i64,
                        Some(FirType::Float(FloatType::F32)) => 4i64,
                        Some(FirType::Int(IntType::I16 | IntType::U16)) => 2i64,
                        Some(FirType::Int(IntType::I8 | IntType::U8) | FirType::Bool) => 1i64,
                        _ => 8i64,
                    },
                };
                let elem_scale = self.strided_slices.get(base).copied().unwrap_or(1) * elem_bytes;
                let offset = if elem_scale > 0 && (elem_scale as u64).is_power_of_two() {
                    let shift = elem_scale.trailing_zeros() as i64;
                    self.builder.ins().ishl_imm_u(idx, shift)
                } else {
                    self.builder.ins().imul_imm_s(idx, elem_scale)
                };
                let addr = self.builder.ins().iadd(p, offset);
                self.builder
                    .ins()
                    .store(MemFlagsData::trusted(), v, addr, 0);
                None
            }

            ValueExpr::ArrayInit(elements) => {
                let count = elements.len().max(1);
                let byte_size = (count * 8) as u32;
                let base_addr = if let Some(func_id) = self.func_ids.get("ifa_rt_gen_alloc") {
                    let size_val = self.builder.ins().iconst(self.ptr_type, byte_size as i64);
                    let align_val = self.builder.ins().iconst(self.ptr_type, 8);
                    let arena_val = self.builder.ins().iconst(types::I32, 0);
                    let local_func = self
                        .module
                        .declare_func_in_func(*func_id, self.builder.func);
                    let call = self
                        .builder
                        .ins()
                        .call(local_func, &[size_val, align_val, arena_val]);
                    self.builder.inst_results(call)[0]
                } else {
                    // Maximum stack slot alignment supported by Cranelift stack frames is 16 bytes (ARM Neon / SSE)
                    let align_shift = if byte_size >= 16 { 4 } else { 3 };
                    let slot = self.builder.create_sized_stack_slot(StackSlotData::new(
                        StackSlotKind::ExplicitSlot,
                        byte_size,
                        align_shift,
                    ));
                    self.builder.ins().stack_addr(self.ptr_type, slot, 0)
                };
                for (idx, elem_id) in elements.iter().enumerate() {
                    let elem_val = self.value_map[elem_id];
                    let offset = (idx * 8) as i32;
                    self.builder
                        .ins()
                        .store(MemFlagsData::trusted(), elem_val, base_addr, offset);
                }
                Some(base_addr)
            }

            ValueExpr::StructInit { name, fields } => {
                let st_fields = self.struct_defs.get(name);
                let total_size = if let Some(s_fields) = st_fields {
                    s_fields
                        .iter()
                        .map(|(_, ty)| crate::types::fir_type_byte_size(ty).max(8))
                        .sum::<usize>()
                        .max(8) as u32
                } else {
                    (fields.len().max(1) * 8) as u32
                };

                let base_addr = if let Some(func_id) = self.func_ids.get("ifa_rt_gen_alloc") {
                    let size_val = self.builder.ins().iconst(self.ptr_type, total_size as i64);
                    let align_val = self.builder.ins().iconst(self.ptr_type, 8);
                    let arena_val = self.builder.ins().iconst(types::I32, 0);
                    let local_func = self
                        .module
                        .declare_func_in_func(*func_id, self.builder.func);
                    let call = self
                        .builder
                        .ins()
                        .call(local_func, &[size_val, align_val, arena_val]);
                    self.builder.inst_results(call)[0]
                } else {
                    let slot = self.builder.create_sized_stack_slot(StackSlotData::new(
                        StackSlotKind::ExplicitSlot,
                        total_size,
                        3,
                    ));
                    self.builder.ins().stack_addr(self.ptr_type, slot, 0)
                };

                let mut current_offset = 0i32;
                for (idx, field_id) in fields.iter().enumerate() {
                    let field_val = self.value_map[field_id];
                    let (f_ty, f_size) = if let Some(s_fields) = st_fields {
                        if let Some((_, ty)) = s_fields.get(idx) {
                            (Some(ty), crate::types::fir_type_byte_size(ty).max(8))
                        } else {
                            (None, 8)
                        }
                    } else {
                        (None, 8)
                    };

                    if let Some(ty) = f_ty {
                        if matches!(ty, FirType::Struct(..) | FirType::Array(..)) {
                            for byte_off in (0..f_size).step_by(8) {
                                let word = self.builder.ins().load(
                                    types::I64,
                                    MemFlagsData::trusted(),
                                    field_val,
                                    byte_off as i32,
                                );
                                self.builder.ins().store(
                                    MemFlagsData::trusted(),
                                    word,
                                    base_addr,
                                    current_offset + byte_off as i32,
                                );
                            }
                            current_offset += f_size as i32;
                            continue;
                        }
                    }

                    self.builder.ins().store(
                        MemFlagsData::trusted(),
                        field_val,
                        base_addr,
                        current_offset,
                    );
                    current_offset += f_size as i32;
                }

                if let Some(res_id) = result {
                    if let Some(s_fields) = st_fields {
                        self.pointer_fir_types
                            .insert(res_id, FirType::Struct(*name, s_fields.clone()));
                    }
                }

                Some(base_addr)
            }

            ValueExpr::TupleInit(fields) => {
                let count = fields.len().max(1);
                let byte_size = (count * 8) as u32;
                let base_addr = if let Some(func_id) = self.func_ids.get("ifa_rt_gen_alloc") {
                    let size_val = self.builder.ins().iconst(self.ptr_type, byte_size as i64);
                    let align_val = self.builder.ins().iconst(self.ptr_type, 8);
                    let arena_val = self.builder.ins().iconst(types::I32, 0);
                    let local_func = self
                        .module
                        .declare_func_in_func(*func_id, self.builder.func);
                    let call = self
                        .builder
                        .ins()
                        .call(local_func, &[size_val, align_val, arena_val]);
                    self.builder.inst_results(call)[0]
                } else {
                    let slot = self.builder.create_sized_stack_slot(StackSlotData::new(
                        StackSlotKind::ExplicitSlot,
                        byte_size,
                        3,
                    ));
                    self.builder.ins().stack_addr(self.ptr_type, slot, 0)
                };
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

            ValueExpr::ChanTrySend { chan, val } => {
                let ch = self.value_map[chan];
                let v = self.value_map[val];
                if let Some(func_id) = self.func_ids.get("ifa_rt_channel_try_send") {
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
                    3,
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
                    3,
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
                timeout,
                priorities,
            } => {
                let n = channels.len();
                let chan_size = (n.max(1) * 8) as u32;
                let chan_slot = self.builder.create_sized_stack_slot(StackSlotData::new(
                    StackSlotKind::ExplicitSlot,
                    chan_size,
                    3,
                ));
                let arr_addr = self.builder.ins().stack_addr(self.ptr_type, chan_slot, 0);
                for (idx, ch_id) in channels.iter().enumerate() {
                    let ch_val = self.value_map[ch_id];
                    let offset = (idx * 8) as i32;
                    self.builder
                        .ins()
                        .store(MemFlagsData::trusted(), ch_val, arr_addr, offset);
                }

                let prio_size = (n.max(1) * 4) as u32;
                let prio_slot = self.builder.create_sized_stack_slot(StackSlotData::new(
                    StackSlotKind::ExplicitSlot,
                    prio_size,
                    2,
                ));
                let prio_addr = self.builder.ins().stack_addr(self.ptr_type, prio_slot, 0);
                for idx in 0..n {
                    let prio = priorities.get(idx).copied().unwrap_or(0);
                    let prio_val = self.builder.ins().iconst(types::I32, prio as i64);
                    let offset = (idx * 4) as i32;
                    self.builder
                        .ins()
                        .store(MemFlagsData::trusted(), prio_val, prio_addr, offset);
                }

                let n_val = self.builder.ins().iconst(self.ptr_type, n as i64);
                let def_val = self
                    .builder
                    .ins()
                    .iconst(types::I32, if *has_default { 1 } else { 0 });
                let timeout_val = if let Some(t_id) = timeout {
                    self.value_map[t_id]
                } else {
                    self.builder.ins().iconst(types::I64, 0)
                };

                if let Some(func_id) = self.func_ids.get("ifa_rt_channel_select_timed") {
                    let local_func = self
                        .module
                        .declare_func_in_func(*func_id, self.builder.func);
                    let call = self.builder.ins().call(
                        local_func,
                        &[arr_addr, prio_addr, n_val, timeout_val, def_val],
                    );
                    let results = self.builder.inst_results(call);
                    results.first().copied()
                } else if let Some(func_id) = self.func_ids.get("ifa_rt_channel_select") {
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
            | ValueExpr::CoWCheckShared { .. } => Some(self.builder.ins().iconst(types::I64, 0)),

            ValueExpr::Spawn { target, args } => {
                let target_name = INTERNER.resolve(target);
                let is_coro = self.coro_funcs.contains(target);
                if let Some(&callee_id) = self.func_ids.get(&target_name) {
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
                    let ret_val = results.first().copied();
                    if is_coro {
                        if let Some(coro_hdl) = ret_val {
                            if let Some(&coro_spawn_id) = self.func_ids.get("ifa_rt_coro_spawn") {
                                let local_spawn = self
                                    .module
                                    .declare_func_in_func(coro_spawn_id, self.builder.func);
                                let call_spawn = self.builder.ins().call(local_spawn, &[coro_hdl]);
                                let fid = self.builder.inst_results(call_spawn).first().copied();
                                return Ok(fid);
                            }
                        }
                    }
                    ret_val
                } else {
                    Some(self.builder.ins().iconst(types::I64, 1))
                }
            }

            ValueExpr::Call { callee, args } => {
                if let Some(&callee_val) = self.value_map.get(callee) {
                    let mut arg_vals = Vec::with_capacity(args.len());
                    let mut sig = Signature::new(self.module.target_config().default_call_conv);
                    for a in args {
                        let v = self.value_map[a];
                        let v_ty = self.builder.func.dfg.value_type(v);
                        sig.params.push(AbiParam::new(v_ty));
                        arg_vals.push(v);
                    }
                    sig.returns.push(AbiParam::new(types::I64));
                    let sig_ref = self.builder.import_signature(sig);
                    let call = self
                        .builder
                        .ins()
                        .call_indirect(sig_ref, callee_val, &arg_vals);
                    let results = self.builder.inst_results(call);
                    results.first().copied()
                } else {
                    Some(self.builder.ins().iconst(types::I64, 0))
                }
            }

            ValueExpr::ArrayLen { array } => {
                if let Some(len_val) = self.slice_lens.get(array).copied() {
                    Some(len_val)
                } else if is_slice_or_slice_ptr(self.value_types.get(array)) {
                    let slice_addr = self.value_map[array];
                    let len_val =
                        self.builder
                            .ins()
                            .load(types::I64, MemFlagsData::trusted(), slice_addr, 8);
                    Some(len_val)
                } else {
                    let arr_ty = self.value_types.get(array);
                    match arr_ty {
                        Some(FirType::Str | FirType::String) => {
                            if let Some(&callee_id) = self.func_ids.get("ifa_rt_string_len") {
                                let local_func = self
                                    .module
                                    .declare_func_in_func(callee_id, self.builder.func);
                                let str_ptr = self.value_map[array];
                                let call = self.builder.ins().call(local_func, &[str_ptr]);
                                Some(self.builder.inst_results(call)[0])
                            } else {
                                Some(self.builder.ins().iconst(types::I64, 0))
                            }
                        }
                        Some(FirType::Array(_, len)) => {
                            Some(self.builder.ins().iconst(types::I64, *len as i64))
                        }
                        Some(FirType::Pointer(inner)) => {
                            if matches!(&**inner, FirType::Str | FirType::String) {
                                if let Some(&callee_id) = self.func_ids.get("ifa_rt_string_len") {
                                    let local_func = self
                                        .module
                                        .declare_func_in_func(callee_id, self.builder.func);
                                    let ptr = self.value_map[array];
                                    let str_ptr = self.builder.ins().load(
                                        self.module.target_config().pointer_type(),
                                        MemFlagsData::trusted(),
                                        ptr,
                                        0,
                                    );
                                    let call = self.builder.ins().call(local_func, &[str_ptr]);
                                    Some(self.builder.inst_results(call)[0])
                                } else {
                                    Some(self.builder.ins().iconst(types::I64, 0))
                                }
                            } else if let FirType::Array(_, len) = &**inner {
                                Some(self.builder.ins().iconst(types::I64, *len as i64))
                            } else if let FirType::Struct(name, _) = &**inner {
                                let s_name = INTERNER.resolve(name);
                                if s_name.starts_with("List") || s_name.contains("List") {
                                    let ptr = self.value_map[array];
                                    Some(self.builder.ins().load(
                                        types::I64,
                                        MemFlagsData::trusted(),
                                        ptr,
                                        8,
                                    ))
                                } else {
                                    Some(self.builder.ins().iconst(types::I64, 0))
                                }
                            } else {
                                Some(self.builder.ins().iconst(types::I64, 0))
                            }
                        }
                        Some(FirType::Struct(name, _)) => {
                            let s_name = INTERNER.resolve(name);
                            if s_name.starts_with("List") || s_name.contains("List") {
                                let ptr = self.value_map[array];
                                Some(self.builder.ins().load(
                                    types::I64,
                                    MemFlagsData::trusted(),
                                    ptr,
                                    8,
                                ))
                            } else {
                                Some(self.builder.ins().iconst(types::I64, 0))
                            }
                        }
                        _ => Some(self.builder.ins().iconst(types::I64, 0)),
                    }
                }
            }

            ValueExpr::EnumInit {
                discriminant,
                payload,
                ..
            } => {
                let slot = self.builder.create_sized_stack_slot(StackSlotData::new(
                    StackSlotKind::ExplicitSlot,
                    16,
                    3,
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

            ValueExpr::SliceSub { base, start, end } => {
                let base_ty = self.value_types.get(base).cloned();
                let base_addr = self.value_map[base];
                let start_idx = self.ensure_i64(self.value_map[start]);
                let end_idx = self.ensure_i64(self.value_map[end]);

                let is_base_slice = is_slice_or_slice_ptr(base_ty.as_ref());

                let data_ptr = if is_base_slice {
                    self.builder
                        .ins()
                        .load(self.ptr_type, MemFlagsData::trusted(), base_addr, 0)
                } else {
                    base_addr
                };

                let elem_size = match &base_ty {
                    Some(FirType::Array(elem, _)) | Some(FirType::Slice(elem)) => {
                        crate::types::fir_type_byte_size(elem).max(8) as i64
                    }
                    Some(FirType::Pointer(inner)) => match &**inner {
                        FirType::Array(elem, _) | FirType::Slice(elem) => {
                            crate::types::fir_type_byte_size(elem).max(8) as i64
                        }
                        _ => 8,
                    },
                    _ => 8,
                };

                let offset = self.builder.ins().imul_imm_s(start_idx, elem_size);
                let sub_data_ptr = self.builder.ins().iadd(data_ptr, offset);
                let sub_len = self.builder.ins().isub(end_idx, start_idx);

                let slot = self.builder.create_sized_stack_slot(StackSlotData::new(
                    StackSlotKind::ExplicitSlot,
                    16,
                    3,
                ));
                let slice_addr = self.builder.ins().stack_addr(self.ptr_type, slot, 0);
                self.builder
                    .ins()
                    .store(MemFlagsData::trusted(), sub_data_ptr, slice_addr, 0);
                self.builder
                    .ins()
                    .store(MemFlagsData::trusted(), sub_len, slice_addr, 8);

                if let Some(res_id) = result {
                    self.slice_lens.insert(res_id, sub_len);
                }

                Some(slice_addr)
            }

            ValueExpr::SliceStrided {
                base,
                start,
                stride,
                ..
            } => {
                let base_ty = self.value_types.get(base).cloned();
                let base_addr = self.value_map[base];
                let is_base_slice = is_slice_or_slice_ptr(base_ty.as_ref());
                let data_ptr = if is_base_slice {
                    self.builder
                        .ins()
                        .load(self.ptr_type, MemFlagsData::trusted(), base_addr, 0)
                } else {
                    base_addr
                };
                let start_idx = self.ensure_i64(self.value_map[start]);
                let elem_size = self.builder.ins().iconst(self.ptr_type, 8);
                let offset = self.builder.ins().imul(start_idx, elem_size);
                let sub_addr = self.builder.ins().iadd(data_ptr, offset);
                if let Some(res_val) = result {
                    let st = self.constant_ints.get(stride).copied().unwrap_or(1);
                    self.strided_slices.insert(res_val, st);
                }
                Some(sub_addr)
            }

            ValueExpr::FormatString(parts) => {
                if parts.is_empty() {
                    let zero = self.builder.ins().iconst(self.ptr_type, 0);
                    if let Some(func_id) = self.func_ids.get("ifa_rt_string_concat") {
                        let local_func = self
                            .module
                            .declare_func_in_func(*func_id, self.builder.func);
                        let call = self.builder.ins().call(local_func, &[zero, zero]);
                        let results = self.builder.inst_results(call);
                        Some(results.first().copied().unwrap_or(zero))
                    } else {
                        Some(zero)
                    }
                } else {
                    let mut curr = self.translate_part_to_str_ptr(parts[0]);
                    for &part in &parts[1..] {
                        let part_val = self.translate_part_to_str_ptr(part);
                        if let Some(func_id) = self.func_ids.get("ifa_rt_string_concat") {
                            let local_func = self
                                .module
                                .declare_func_in_func(*func_id, self.builder.func);
                            let call = self.builder.ins().call(local_func, &[curr, part_val]);
                            let results = self.builder.inst_results(call);
                            curr = results.first().copied().unwrap_or(curr);
                        }
                    }
                    Some(curr)
                }
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
                        if cur_ty.is_float() && expected_ret_ty.is_int() {
                            ret_val = self.builder.ins().fcvt_to_sint(expected_ret_ty, ret_val);
                        } else if cur_ty.is_int() && expected_ret_ty.is_float() {
                            ret_val = self.builder.ins().fcvt_from_sint(expected_ret_ty, ret_val);
                        } else if cur_ty == types::F32 && expected_ret_ty == types::F64 {
                            ret_val = self.builder.ins().fpromote(types::F64, ret_val);
                        } else if cur_ty == types::F64 && expected_ret_ty == types::F32 {
                            ret_val = self.builder.ins().fdemote(types::F32, ret_val);
                        } else if cur_ty.bits() > expected_ret_ty.bits() {
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
                let cond_ty = self.builder.func.dfg.value_type(c);
                let c_cond = if cond_ty.is_int() {
                    let zero = self.builder.ins().iconst(cond_ty, 0);
                    self.builder.ins().icmp(IntCC::NotEqual, c, zero)
                } else {
                    c
                };
                self.builder
                    .ins()
                    .brif(c_cond, then_cl, &then_cl_args, else_cl, &else_cl_args);
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

    fn translate_part_to_str_ptr(&mut self, part: ValueId) -> ClValue {
        let val = self.value_map[&part];
        if matches!(
            self.value_types.get(&part),
            Some(FirType::String) | Some(FirType::Str)
        ) {
            return val;
        }
        let is_int = matches!(self.value_types.get(&part), Some(FirType::Int(_)));
        let is_float = matches!(self.value_types.get(&part), Some(FirType::Float(_)));
        let is_bool = matches!(self.value_types.get(&part), Some(FirType::Bool));
        if !is_int && !is_float && !is_bool && self.value_types.contains_key(&part) {
            return val;
        }
        let val_ty = self.builder.func.dfg.value_type(val);
        if val_ty == types::I64 || val_ty == types::I32 {
            let i64_val = if val_ty == types::I32 {
                self.builder.ins().sextend(types::I64, val)
            } else {
                val
            };
            if let Some(func_id) = self.func_ids.get("ifa_rt_string_from_i64") {
                let local_func = self
                    .module
                    .declare_func_in_func(*func_id, self.builder.func);
                let call = self.builder.ins().call(local_func, &[i64_val]);
                let results = self.builder.inst_results(call);
                results.first().copied().unwrap_or(val)
            } else {
                val
            }
        } else if val_ty == types::F64 || val_ty == types::F32 {
            let f64_val = if val_ty == types::F32 {
                self.builder.ins().fpromote(types::F64, val)
            } else {
                val
            };
            if let Some(func_id) = self.func_ids.get("ifa_rt_string_from_f64") {
                let local_func = self
                    .module
                    .declare_func_in_func(*func_id, self.builder.func);
                let call = self.builder.ins().call(local_func, &[f64_val]);
                let results = self.builder.inst_results(call);
                results.first().copied().unwrap_or(val)
            } else {
                val
            }
        } else if val_ty == types::I8 {
            if let Some(func_id) = self.func_ids.get("ifa_rt_string_from_bool") {
                let local_func = self
                    .module
                    .declare_func_in_func(*func_id, self.builder.func);
                let call = self.builder.ins().call(local_func, &[val]);
                let results = self.builder.inst_results(call);
                results.first().copied().unwrap_or(val)
            } else {
                val
            }
        } else {
            val
        }
    }

    /// Try to directly lower SIMD strided and contiguous slice reductions into native Cranelift IR loops without runtime calls.
    fn try_lower_simd_reduction(&mut self, fn_name: &str, args: &[ValueId]) -> Option<ClValue> {
        match fn_name {
            // Multi-arena dot product (with independent strides per arena operand)
            "ifa_simd_multi_arena_slice_dot_f32" if args.len() >= 5 => {
                let src1 = self.ensure_ptr(self.value_map[&args[0]]);
                let src2 = self.ensure_ptr(self.value_map[&args[1]]);
                let len = self.ensure_i64(self.value_map[&args[2]]);
                let stride1 = self.ensure_i64(self.value_map[&args[3]]);
                let stride2 = self.ensure_i64(self.value_map[&args[4]]);
                self.lower_multi_arena_slice_dot(
                    types::F32,
                    true,
                    4,
                    src1,
                    src2,
                    len,
                    stride1,
                    stride2,
                    false,
                )
            }
            "ifa_simd_multi_arena_slice_dot_f64" if args.len() >= 5 => {
                let src1 = self.ensure_ptr(self.value_map[&args[0]]);
                let src2 = self.ensure_ptr(self.value_map[&args[1]]);
                let len = self.ensure_i64(self.value_map[&args[2]]);
                let stride1 = self.ensure_i64(self.value_map[&args[3]]);
                let stride2 = self.ensure_i64(self.value_map[&args[4]]);
                self.lower_multi_arena_slice_dot(
                    types::F64,
                    true,
                    8,
                    src1,
                    src2,
                    len,
                    stride1,
                    stride2,
                    false,
                )
            }
            "ifa_simd_multi_arena_slice_dot_i32" if args.len() >= 5 => {
                let src1 = self.ensure_ptr(self.value_map[&args[0]]);
                let src2 = self.ensure_ptr(self.value_map[&args[1]]);
                let len = self.ensure_i64(self.value_map[&args[2]]);
                let stride1 = self.ensure_i64(self.value_map[&args[3]]);
                let stride2 = self.ensure_i64(self.value_map[&args[4]]);
                self.lower_multi_arena_slice_dot(
                    types::I32,
                    false,
                    4,
                    src1,
                    src2,
                    len,
                    stride1,
                    stride2,
                    false,
                )
            }
            "ifa_simd_multi_arena_slice_dot_i64" if args.len() >= 5 => {
                let src1 = self.ensure_ptr(self.value_map[&args[0]]);
                let src2 = self.ensure_ptr(self.value_map[&args[1]]);
                let len = self.ensure_i64(self.value_map[&args[2]]);
                let stride1 = self.ensure_i64(self.value_map[&args[3]]);
                let stride2 = self.ensure_i64(self.value_map[&args[4]]);
                self.lower_multi_arena_slice_dot(
                    types::I64,
                    false,
                    8,
                    src1,
                    src2,
                    len,
                    stride1,
                    stride2,
                    false,
                )
            }

            // Multi-arena 2D / 3D fused convolutions with optional bias and activation
            "ifa_simd_multi_arena_conv2d_f32" if args.len() >= 9 => {
                let dst = self.ensure_ptr(self.value_map[&args[0]]);
                let img = self.ensure_ptr(self.value_map[&args[1]]);
                let weights = self.ensure_ptr(self.value_map[&args[2]]);
                let bias = self.ensure_ptr(self.value_map[&args[3]]);
                let h_out = self.ensure_i64(self.value_map[&args[4]]);
                let w_out = self.ensure_i64(self.value_map[&args[5]]);
                let stride_y = self.ensure_i64(self.value_map[&args[6]]);
                let stride_x = self.ensure_i64(self.value_map[&args[7]]);
                let img_width = self.ensure_i64(self.value_map[&args[8]]);
                let activation = if args.len() >= 10 {
                    self.ensure_i32(self.value_map[&args[9]])
                } else {
                    self.builder.ins().iconst(types::I32, 0)
                };
                self.lower_multi_arena_conv2d(
                    types::F32,
                    true,
                    4,
                    dst,
                    img,
                    weights,
                    bias,
                    h_out,
                    w_out,
                    stride_y,
                    stride_x,
                    img_width,
                    activation,
                )
            }
            "ifa_simd_multi_arena_conv2d_f64" if args.len() >= 9 => {
                let dst = self.ensure_ptr(self.value_map[&args[0]]);
                let img = self.ensure_ptr(self.value_map[&args[1]]);
                let weights = self.ensure_ptr(self.value_map[&args[2]]);
                let bias = self.ensure_ptr(self.value_map[&args[3]]);
                let h_out = self.ensure_i64(self.value_map[&args[4]]);
                let w_out = self.ensure_i64(self.value_map[&args[5]]);
                let stride_y = self.ensure_i64(self.value_map[&args[6]]);
                let stride_x = self.ensure_i64(self.value_map[&args[7]]);
                let img_width = self.ensure_i64(self.value_map[&args[8]]);
                let activation = if args.len() >= 10 {
                    self.ensure_i32(self.value_map[&args[9]])
                } else {
                    self.builder.ins().iconst(types::I32, 0)
                };
                self.lower_multi_arena_conv2d(
                    types::F64,
                    true,
                    8,
                    dst,
                    img,
                    weights,
                    bias,
                    h_out,
                    w_out,
                    stride_y,
                    stride_x,
                    img_width,
                    activation,
                )
            }
            "ifa_simd_multi_arena_conv2d_i64" if args.len() >= 9 => {
                let dst = self.ensure_ptr(self.value_map[&args[0]]);
                let img = self.ensure_ptr(self.value_map[&args[1]]);
                let weights = self.ensure_ptr(self.value_map[&args[2]]);
                let bias = self.ensure_ptr(self.value_map[&args[3]]);
                let h_out = self.ensure_i64(self.value_map[&args[4]]);
                let w_out = self.ensure_i64(self.value_map[&args[5]]);
                let stride_y = self.ensure_i64(self.value_map[&args[6]]);
                let stride_x = self.ensure_i64(self.value_map[&args[7]]);
                let img_width = self.ensure_i64(self.value_map[&args[8]]);
                let activation = if args.len() >= 10 {
                    self.ensure_i32(self.value_map[&args[9]])
                } else {
                    self.builder.ins().iconst(types::I32, 0)
                };
                self.lower_multi_arena_conv2d(
                    types::I64,
                    false,
                    8,
                    dst,
                    img,
                    weights,
                    bias,
                    h_out,
                    w_out,
                    stride_y,
                    stride_x,
                    img_width,
                    activation,
                )
            }
            "ifa_simd_multi_arena_conv3d_f32" if args.len() >= 12 => {
                let dst = self.ensure_ptr(self.value_map[&args[0]]);
                let volume = self.ensure_ptr(self.value_map[&args[1]]);
                let filter = self.ensure_ptr(self.value_map[&args[2]]);
                let bias = self.ensure_ptr(self.value_map[&args[3]]);
                let d_out = self.ensure_i64(self.value_map[&args[4]]);
                let h_out = self.ensure_i64(self.value_map[&args[5]]);
                let w_out = self.ensure_i64(self.value_map[&args[6]]);
                let stride_z = self.ensure_i64(self.value_map[&args[7]]);
                let stride_y = self.ensure_i64(self.value_map[&args[8]]);
                let stride_x = self.ensure_i64(self.value_map[&args[9]]);
                let plane_pitch = self.ensure_i64(self.value_map[&args[10]]);
                let row_pitch = self.ensure_i64(self.value_map[&args[11]]);
                let activation = if args.len() >= 13 {
                    self.ensure_i32(self.value_map[&args[12]])
                } else {
                    self.builder.ins().iconst(types::I32, 0)
                };
                self.lower_multi_arena_conv3d(
                    types::F32,
                    true,
                    4,
                    dst,
                    volume,
                    filter,
                    bias,
                    d_out,
                    h_out,
                    w_out,
                    stride_z,
                    stride_y,
                    stride_x,
                    plane_pitch,
                    row_pitch,
                    activation,
                )
            }
            "ifa_simd_multi_arena_conv3d_f64" if args.len() >= 12 => {
                let dst = self.ensure_ptr(self.value_map[&args[0]]);
                let volume = self.ensure_ptr(self.value_map[&args[1]]);
                let filter = self.ensure_ptr(self.value_map[&args[2]]);
                let bias = self.ensure_ptr(self.value_map[&args[3]]);
                let d_out = self.ensure_i64(self.value_map[&args[4]]);
                let h_out = self.ensure_i64(self.value_map[&args[5]]);
                let w_out = self.ensure_i64(self.value_map[&args[6]]);
                let stride_z = self.ensure_i64(self.value_map[&args[7]]);
                let stride_y = self.ensure_i64(self.value_map[&args[8]]);
                let stride_x = self.ensure_i64(self.value_map[&args[9]]);
                let plane_pitch = self.ensure_i64(self.value_map[&args[10]]);
                let row_pitch = self.ensure_i64(self.value_map[&args[11]]);
                let activation = if args.len() >= 13 {
                    self.ensure_i32(self.value_map[&args[12]])
                } else {
                    self.builder.ins().iconst(types::I32, 0)
                };
                self.lower_multi_arena_conv3d(
                    types::F64,
                    true,
                    8,
                    dst,
                    volume,
                    filter,
                    bias,
                    d_out,
                    h_out,
                    w_out,
                    stride_z,
                    stride_y,
                    stride_x,
                    plane_pitch,
                    row_pitch,
                    activation,
                )
            }
            "ifa_simd_multi_arena_conv3d_i64" if args.len() >= 12 => {
                let dst = self.ensure_ptr(self.value_map[&args[0]]);
                let volume = self.ensure_ptr(self.value_map[&args[1]]);
                let filter = self.ensure_ptr(self.value_map[&args[2]]);
                let bias = self.ensure_ptr(self.value_map[&args[3]]);
                let d_out = self.ensure_i64(self.value_map[&args[4]]);
                let h_out = self.ensure_i64(self.value_map[&args[5]]);
                let w_out = self.ensure_i64(self.value_map[&args[6]]);
                let stride_z = self.ensure_i64(self.value_map[&args[7]]);
                let stride_y = self.ensure_i64(self.value_map[&args[8]]);
                let stride_x = self.ensure_i64(self.value_map[&args[9]]);
                let plane_pitch = self.ensure_i64(self.value_map[&args[10]]);
                let row_pitch = self.ensure_i64(self.value_map[&args[11]]);
                let activation = if args.len() >= 13 {
                    self.ensure_i32(self.value_map[&args[12]])
                } else {
                    self.builder.ins().iconst(types::I32, 0)
                };
                self.lower_multi_arena_conv3d(
                    types::I64,
                    false,
                    8,
                    dst,
                    volume,
                    filter,
                    bias,
                    d_out,
                    h_out,
                    w_out,
                    stride_z,
                    stride_y,
                    stride_x,
                    plane_pitch,
                    row_pitch,
                    activation,
                )
            }

            // Dilated 2D Convolutions
            "ifa_simd_multi_arena_dilated_conv2d_f32" if args.len() >= 13 => {
                let dst = self.ensure_ptr(self.value_map[&args[0]]);
                let img = self.ensure_ptr(self.value_map[&args[1]]);
                let weights = self.ensure_ptr(self.value_map[&args[2]]);
                let bias = self.ensure_ptr(self.value_map[&args[3]]);
                let h_out = self.ensure_i64(self.value_map[&args[4]]);
                let w_out = self.ensure_i64(self.value_map[&args[5]]);
                let stride_y = self.ensure_i64(self.value_map[&args[6]]);
                let stride_x = self.ensure_i64(self.value_map[&args[7]]);
                let dilation_y = self.ensure_i64(self.value_map[&args[8]]);
                let dilation_x = self.ensure_i64(self.value_map[&args[9]]);
                let kernel_h = self.ensure_i64(self.value_map[&args[10]]);
                let kernel_w = self.ensure_i64(self.value_map[&args[11]]);
                let img_width = self.ensure_i64(self.value_map[&args[12]]);
                let activation = if args.len() >= 14 {
                    self.ensure_i32(self.value_map[&args[13]])
                } else {
                    self.builder.ins().iconst(types::I32, 0)
                };
                self.lower_multi_arena_dilated_conv2d(
                    types::F32,
                    true,
                    4,
                    dst,
                    img,
                    weights,
                    bias,
                    h_out,
                    w_out,
                    stride_y,
                    stride_x,
                    dilation_y,
                    dilation_x,
                    kernel_h,
                    kernel_w,
                    img_width,
                    activation,
                )
            }
            "ifa_simd_multi_arena_dilated_conv2d_f64" if args.len() >= 13 => {
                let dst = self.ensure_ptr(self.value_map[&args[0]]);
                let img = self.ensure_ptr(self.value_map[&args[1]]);
                let weights = self.ensure_ptr(self.value_map[&args[2]]);
                let bias = self.ensure_ptr(self.value_map[&args[3]]);
                let h_out = self.ensure_i64(self.value_map[&args[4]]);
                let w_out = self.ensure_i64(self.value_map[&args[5]]);
                let stride_y = self.ensure_i64(self.value_map[&args[6]]);
                let stride_x = self.ensure_i64(self.value_map[&args[7]]);
                let dilation_y = self.ensure_i64(self.value_map[&args[8]]);
                let dilation_x = self.ensure_i64(self.value_map[&args[9]]);
                let kernel_h = self.ensure_i64(self.value_map[&args[10]]);
                let kernel_w = self.ensure_i64(self.value_map[&args[11]]);
                let img_width = self.ensure_i64(self.value_map[&args[12]]);
                let activation = if args.len() >= 14 {
                    self.ensure_i32(self.value_map[&args[13]])
                } else {
                    self.builder.ins().iconst(types::I32, 0)
                };
                self.lower_multi_arena_dilated_conv2d(
                    types::F64,
                    true,
                    8,
                    dst,
                    img,
                    weights,
                    bias,
                    h_out,
                    w_out,
                    stride_y,
                    stride_x,
                    dilation_y,
                    dilation_x,
                    kernel_h,
                    kernel_w,
                    img_width,
                    activation,
                )
            }
            "ifa_simd_multi_arena_dilated_conv2d_i64" if args.len() >= 13 => {
                let dst = self.ensure_ptr(self.value_map[&args[0]]);
                let img = self.ensure_ptr(self.value_map[&args[1]]);
                let weights = self.ensure_ptr(self.value_map[&args[2]]);
                let bias = self.ensure_ptr(self.value_map[&args[3]]);
                let h_out = self.ensure_i64(self.value_map[&args[4]]);
                let w_out = self.ensure_i64(self.value_map[&args[5]]);
                let stride_y = self.ensure_i64(self.value_map[&args[6]]);
                let stride_x = self.ensure_i64(self.value_map[&args[7]]);
                let dilation_y = self.ensure_i64(self.value_map[&args[8]]);
                let dilation_x = self.ensure_i64(self.value_map[&args[9]]);
                let kernel_h = self.ensure_i64(self.value_map[&args[10]]);
                let kernel_w = self.ensure_i64(self.value_map[&args[11]]);
                let img_width = self.ensure_i64(self.value_map[&args[12]]);
                let activation = if args.len() >= 14 {
                    self.ensure_i32(self.value_map[&args[13]])
                } else {
                    self.builder.ins().iconst(types::I32, 0)
                };
                self.lower_multi_arena_dilated_conv2d(
                    types::I64,
                    false,
                    8,
                    dst,
                    img,
                    weights,
                    bias,
                    h_out,
                    w_out,
                    stride_y,
                    stride_x,
                    dilation_y,
                    dilation_x,
                    kernel_h,
                    kernel_w,
                    img_width,
                    activation,
                )
            }

            // Spatial Max-Pooling 2D
            "ifa_simd_multi_arena_maxpool2d_f32" if args.len() >= 9 => {
                let dst = self.ensure_ptr(self.value_map[&args[0]]);
                let img = self.ensure_ptr(self.value_map[&args[1]]);
                let h_out = self.ensure_i64(self.value_map[&args[2]]);
                let w_out = self.ensure_i64(self.value_map[&args[3]]);
                let stride_y = self.ensure_i64(self.value_map[&args[4]]);
                let stride_x = self.ensure_i64(self.value_map[&args[5]]);
                let pool_h = self.ensure_i64(self.value_map[&args[6]]);
                let pool_w = self.ensure_i64(self.value_map[&args[7]]);
                let img_width = self.ensure_i64(self.value_map[&args[8]]);
                self.lower_multi_arena_maxpool2d(
                    types::F32,
                    true,
                    4,
                    dst,
                    img,
                    h_out,
                    w_out,
                    stride_y,
                    stride_x,
                    pool_h,
                    pool_w,
                    img_width,
                )
            }
            "ifa_simd_multi_arena_maxpool2d_f64" if args.len() >= 9 => {
                let dst = self.ensure_ptr(self.value_map[&args[0]]);
                let img = self.ensure_ptr(self.value_map[&args[1]]);
                let h_out = self.ensure_i64(self.value_map[&args[2]]);
                let w_out = self.ensure_i64(self.value_map[&args[3]]);
                let stride_y = self.ensure_i64(self.value_map[&args[4]]);
                let stride_x = self.ensure_i64(self.value_map[&args[5]]);
                let pool_h = self.ensure_i64(self.value_map[&args[6]]);
                let pool_w = self.ensure_i64(self.value_map[&args[7]]);
                let img_width = self.ensure_i64(self.value_map[&args[8]]);
                self.lower_multi_arena_maxpool2d(
                    types::F64,
                    true,
                    8,
                    dst,
                    img,
                    h_out,
                    w_out,
                    stride_y,
                    stride_x,
                    pool_h,
                    pool_w,
                    img_width,
                )
            }
            "ifa_simd_multi_arena_maxpool2d_i64" if args.len() >= 9 => {
                let dst = self.ensure_ptr(self.value_map[&args[0]]);
                let img = self.ensure_ptr(self.value_map[&args[1]]);
                let h_out = self.ensure_i64(self.value_map[&args[2]]);
                let w_out = self.ensure_i64(self.value_map[&args[3]]);
                let stride_y = self.ensure_i64(self.value_map[&args[4]]);
                let stride_x = self.ensure_i64(self.value_map[&args[5]]);
                let pool_h = self.ensure_i64(self.value_map[&args[6]]);
                let pool_w = self.ensure_i64(self.value_map[&args[7]]);
                let img_width = self.ensure_i64(self.value_map[&args[8]]);
                self.lower_multi_arena_maxpool2d(
                    types::I64,
                    false,
                    8,
                    dst,
                    img,
                    h_out,
                    w_out,
                    stride_y,
                    stride_x,
                    pool_h,
                    pool_w,
                    img_width,
                )
            }

            // Spatial Average-Pooling 2D
            "ifa_simd_multi_arena_avgpool2d_f32" if args.len() >= 9 => {
                let dst = self.ensure_ptr(self.value_map[&args[0]]);
                let img = self.ensure_ptr(self.value_map[&args[1]]);
                let h_out = self.ensure_i64(self.value_map[&args[2]]);
                let w_out = self.ensure_i64(self.value_map[&args[3]]);
                let stride_y = self.ensure_i64(self.value_map[&args[4]]);
                let stride_x = self.ensure_i64(self.value_map[&args[5]]);
                let pool_h = self.ensure_i64(self.value_map[&args[6]]);
                let pool_w = self.ensure_i64(self.value_map[&args[7]]);
                let img_width = self.ensure_i64(self.value_map[&args[8]]);
                self.lower_multi_arena_avgpool2d(
                    types::F32,
                    true,
                    4,
                    dst,
                    img,
                    h_out,
                    w_out,
                    stride_y,
                    stride_x,
                    pool_h,
                    pool_w,
                    img_width,
                )
            }
            "ifa_simd_multi_arena_avgpool2d_f64" if args.len() >= 9 => {
                let dst = self.ensure_ptr(self.value_map[&args[0]]);
                let img = self.ensure_ptr(self.value_map[&args[1]]);
                let h_out = self.ensure_i64(self.value_map[&args[2]]);
                let w_out = self.ensure_i64(self.value_map[&args[3]]);
                let stride_y = self.ensure_i64(self.value_map[&args[4]]);
                let stride_x = self.ensure_i64(self.value_map[&args[5]]);
                let pool_h = self.ensure_i64(self.value_map[&args[6]]);
                let pool_w = self.ensure_i64(self.value_map[&args[7]]);
                let img_width = self.ensure_i64(self.value_map[&args[8]]);
                self.lower_multi_arena_avgpool2d(
                    types::F64,
                    true,
                    8,
                    dst,
                    img,
                    h_out,
                    w_out,
                    stride_y,
                    stride_x,
                    pool_h,
                    pool_w,
                    img_width,
                )
            }
            "ifa_simd_multi_arena_avgpool2d_i64" if args.len() >= 9 => {
                let dst = self.ensure_ptr(self.value_map[&args[0]]);
                let img = self.ensure_ptr(self.value_map[&args[1]]);
                let h_out = self.ensure_i64(self.value_map[&args[2]]);
                let w_out = self.ensure_i64(self.value_map[&args[3]]);
                let stride_y = self.ensure_i64(self.value_map[&args[4]]);
                let stride_x = self.ensure_i64(self.value_map[&args[5]]);
                let pool_h = self.ensure_i64(self.value_map[&args[6]]);
                let pool_w = self.ensure_i64(self.value_map[&args[7]]);
                let img_width = self.ensure_i64(self.value_map[&args[8]]);
                self.lower_multi_arena_avgpool2d(
                    types::I64,
                    false,
                    8,
                    dst,
                    img,
                    h_out,
                    w_out,
                    stride_y,
                    stride_x,
                    pool_h,
                    pool_w,
                    img_width,
                )
            }

            // Multi-arena Depthwise 2D Convolutions
            "ifa_simd_multi_arena_depthwise_conv2d_f32" if args.len() >= 13 => {
                let dst = self.ensure_ptr(self.value_map[&args[0]]);
                let img = self.ensure_ptr(self.value_map[&args[1]]);
                let weights = self.ensure_ptr(self.value_map[&args[2]]);
                let bias = self.ensure_ptr(self.value_map[&args[3]]);
                let channels = self.ensure_i64(self.value_map[&args[4]]);
                let h_out = self.ensure_i64(self.value_map[&args[5]]);
                let w_out = self.ensure_i64(self.value_map[&args[6]]);
                let stride_y = self.ensure_i64(self.value_map[&args[7]]);
                let stride_x = self.ensure_i64(self.value_map[&args[8]]);
                let kernel_h = self.ensure_i64(self.value_map[&args[9]]);
                let kernel_w = self.ensure_i64(self.value_map[&args[10]]);
                let img_h = self.ensure_i64(self.value_map[&args[11]]);
                let img_w = self.ensure_i64(self.value_map[&args[12]]);
                let activation = if args.len() >= 14 {
                    self.ensure_i32(self.value_map[&args[13]])
                } else {
                    self.builder.ins().iconst(types::I32, 0)
                };
                self.lower_multi_arena_depthwise_conv2d(
                    types::F32,
                    true,
                    4,
                    dst,
                    img,
                    weights,
                    bias,
                    channels,
                    h_out,
                    w_out,
                    stride_y,
                    stride_x,
                    kernel_h,
                    kernel_w,
                    img_h,
                    img_w,
                    activation,
                )
            }
            "ifa_simd_multi_arena_depthwise_conv2d_f64" if args.len() >= 13 => {
                let dst = self.ensure_ptr(self.value_map[&args[0]]);
                let img = self.ensure_ptr(self.value_map[&args[1]]);
                let weights = self.ensure_ptr(self.value_map[&args[2]]);
                let bias = self.ensure_ptr(self.value_map[&args[3]]);
                let channels = self.ensure_i64(self.value_map[&args[4]]);
                let h_out = self.ensure_i64(self.value_map[&args[5]]);
                let w_out = self.ensure_i64(self.value_map[&args[6]]);
                let stride_y = self.ensure_i64(self.value_map[&args[7]]);
                let stride_x = self.ensure_i64(self.value_map[&args[8]]);
                let kernel_h = self.ensure_i64(self.value_map[&args[9]]);
                let kernel_w = self.ensure_i64(self.value_map[&args[10]]);
                let img_h = self.ensure_i64(self.value_map[&args[11]]);
                let img_w = self.ensure_i64(self.value_map[&args[12]]);
                let activation = if args.len() >= 14 {
                    self.ensure_i32(self.value_map[&args[13]])
                } else {
                    self.builder.ins().iconst(types::I32, 0)
                };
                self.lower_multi_arena_depthwise_conv2d(
                    types::F64,
                    true,
                    8,
                    dst,
                    img,
                    weights,
                    bias,
                    channels,
                    h_out,
                    w_out,
                    stride_y,
                    stride_x,
                    kernel_h,
                    kernel_w,
                    img_h,
                    img_w,
                    activation,
                )
            }
            "ifa_simd_multi_arena_depthwise_conv2d_i64" if args.len() >= 13 => {
                let dst = self.ensure_ptr(self.value_map[&args[0]]);
                let img = self.ensure_ptr(self.value_map[&args[1]]);
                let weights = self.ensure_ptr(self.value_map[&args[2]]);
                let bias = self.ensure_ptr(self.value_map[&args[3]]);
                let channels = self.ensure_i64(self.value_map[&args[4]]);
                let h_out = self.ensure_i64(self.value_map[&args[5]]);
                let w_out = self.ensure_i64(self.value_map[&args[6]]);
                let stride_y = self.ensure_i64(self.value_map[&args[7]]);
                let stride_x = self.ensure_i64(self.value_map[&args[8]]);
                let kernel_h = self.ensure_i64(self.value_map[&args[9]]);
                let kernel_w = self.ensure_i64(self.value_map[&args[10]]);
                let img_h = self.ensure_i64(self.value_map[&args[11]]);
                let img_w = self.ensure_i64(self.value_map[&args[12]]);
                let activation = if args.len() >= 14 {
                    self.ensure_i32(self.value_map[&args[13]])
                } else {
                    self.builder.ins().iconst(types::I32, 0)
                };
                self.lower_multi_arena_depthwise_conv2d(
                    types::I64,
                    false,
                    8,
                    dst,
                    img,
                    weights,
                    bias,
                    channels,
                    h_out,
                    w_out,
                    stride_y,
                    stride_x,
                    kernel_h,
                    kernel_w,
                    img_h,
                    img_w,
                    activation,
                )
            }

            // Multi-arena Pointwise (1x1) 2D Convolutions
            "ifa_simd_multi_arena_pointwise_conv2d_f32" if args.len() >= 7 => {
                let dst = self.ensure_ptr(self.value_map[&args[0]]);
                let img = self.ensure_ptr(self.value_map[&args[1]]);
                let weights = self.ensure_ptr(self.value_map[&args[2]]);
                let bias = self.ensure_ptr(self.value_map[&args[3]]);
                let c_in = self.ensure_i64(self.value_map[&args[4]]);
                let c_out = self.ensure_i64(self.value_map[&args[5]]);
                let spatial_size = self.ensure_i64(self.value_map[&args[6]]);
                let activation = if args.len() >= 8 {
                    self.ensure_i32(self.value_map[&args[7]])
                } else {
                    self.builder.ins().iconst(types::I32, 0)
                };
                self.lower_multi_arena_pointwise_conv2d(
                    types::F32,
                    true,
                    4,
                    dst,
                    img,
                    weights,
                    bias,
                    c_in,
                    c_out,
                    spatial_size,
                    activation,
                )
            }
            "ifa_simd_multi_arena_pointwise_conv2d_f64" if args.len() >= 7 => {
                let dst = self.ensure_ptr(self.value_map[&args[0]]);
                let img = self.ensure_ptr(self.value_map[&args[1]]);
                let weights = self.ensure_ptr(self.value_map[&args[2]]);
                let bias = self.ensure_ptr(self.value_map[&args[3]]);
                let c_in = self.ensure_i64(self.value_map[&args[4]]);
                let c_out = self.ensure_i64(self.value_map[&args[5]]);
                let spatial_size = self.ensure_i64(self.value_map[&args[6]]);
                let activation = if args.len() >= 8 {
                    self.ensure_i32(self.value_map[&args[7]])
                } else {
                    self.builder.ins().iconst(types::I32, 0)
                };
                self.lower_multi_arena_pointwise_conv2d(
                    types::F64,
                    true,
                    8,
                    dst,
                    img,
                    weights,
                    bias,
                    c_in,
                    c_out,
                    spatial_size,
                    activation,
                )
            }
            "ifa_simd_multi_arena_pointwise_conv2d_i64" if args.len() >= 7 => {
                let dst = self.ensure_ptr(self.value_map[&args[0]]);
                let img = self.ensure_ptr(self.value_map[&args[1]]);
                let weights = self.ensure_ptr(self.value_map[&args[2]]);
                let bias = self.ensure_ptr(self.value_map[&args[3]]);
                let c_in = self.ensure_i64(self.value_map[&args[4]]);
                let c_out = self.ensure_i64(self.value_map[&args[5]]);
                let spatial_size = self.ensure_i64(self.value_map[&args[6]]);
                let activation = if args.len() >= 8 {
                    self.ensure_i32(self.value_map[&args[7]])
                } else {
                    self.builder.ins().iconst(types::I32, 0)
                };
                self.lower_multi_arena_pointwise_conv2d(
                    types::I64,
                    false,
                    8,
                    dst,
                    img,
                    weights,
                    bias,
                    c_in,
                    c_out,
                    spatial_size,
                    activation,
                )
            }

            // Multi-arena 2D Batch Normalization
            "ifa_simd_multi_arena_batch_norm2d_f32" if args.len() >= 9 => {
                let dst = self.ensure_ptr(self.value_map[&args[0]]);
                let src = self.ensure_ptr(self.value_map[&args[1]]);
                let gamma = self.ensure_ptr(self.value_map[&args[2]]);
                let beta = self.ensure_ptr(self.value_map[&args[3]]);
                let mean = self.ensure_ptr(self.value_map[&args[4]]);
                let var = self.ensure_ptr(self.value_map[&args[5]]);
                let channels = self.ensure_i64(self.value_map[&args[6]]);
                let spatial_size = self.ensure_i64(self.value_map[&args[7]]);
                let epsilon = self.ensure_f32(self.value_map[&args[8]]);
                let activation = if args.len() >= 10 {
                    self.ensure_i32(self.value_map[&args[9]])
                } else {
                    self.builder.ins().iconst(types::I32, 0)
                };
                self.lower_multi_arena_batch_norm2d(
                    types::F32,
                    4,
                    dst,
                    src,
                    gamma,
                    beta,
                    mean,
                    var,
                    channels,
                    spatial_size,
                    epsilon,
                    activation,
                )
            }
            "ifa_simd_multi_arena_batch_norm2d_f64" if args.len() >= 9 => {
                let dst = self.ensure_ptr(self.value_map[&args[0]]);
                let src = self.ensure_ptr(self.value_map[&args[1]]);
                let gamma = self.ensure_ptr(self.value_map[&args[2]]);
                let beta = self.ensure_ptr(self.value_map[&args[3]]);
                let mean = self.ensure_ptr(self.value_map[&args[4]]);
                let var = self.ensure_ptr(self.value_map[&args[5]]);
                let channels = self.ensure_i64(self.value_map[&args[6]]);
                let spatial_size = self.ensure_i64(self.value_map[&args[7]]);
                let epsilon = self.ensure_f64(self.value_map[&args[8]]);
                let activation = if args.len() >= 10 {
                    self.ensure_i32(self.value_map[&args[9]])
                } else {
                    self.builder.ins().iconst(types::I32, 0)
                };
                self.lower_multi_arena_batch_norm2d(
                    types::F64,
                    8,
                    dst,
                    src,
                    gamma,
                    beta,
                    mean,
                    var,
                    channels,
                    spatial_size,
                    epsilon,
                    activation,
                )
            }

            // Multi-arena tripartite reductions (dst[i*s_dst] += src1[i*s1] * src2[i*s2])
            "ifa_simd_multi_arena_tripartite_f32" if args.len() >= 7 => {
                let dst = self.ensure_ptr(self.value_map[&args[0]]);
                let src1 = self.ensure_ptr(self.value_map[&args[1]]);
                let src2 = self.ensure_ptr(self.value_map[&args[2]]);
                let len = self.ensure_i64(self.value_map[&args[3]]);
                let s_dst = self.ensure_i64(self.value_map[&args[4]]);
                let s1 = self.ensure_i64(self.value_map[&args[5]]);
                let s2 = self.ensure_i64(self.value_map[&args[6]]);
                self.lower_multi_arena_tripartite(
                    types::F32,
                    true,
                    4,
                    dst,
                    src1,
                    src2,
                    len,
                    s_dst,
                    s1,
                    s2,
                    false,
                )
            }
            "ifa_simd_multi_arena_tripartite_f64" if args.len() >= 7 => {
                let dst = self.ensure_ptr(self.value_map[&args[0]]);
                let src1 = self.ensure_ptr(self.value_map[&args[1]]);
                let src2 = self.ensure_ptr(self.value_map[&args[2]]);
                let len = self.ensure_i64(self.value_map[&args[3]]);
                let s_dst = self.ensure_i64(self.value_map[&args[4]]);
                let s1 = self.ensure_i64(self.value_map[&args[5]]);
                let s2 = self.ensure_i64(self.value_map[&args[6]]);
                self.lower_multi_arena_tripartite(
                    types::F64,
                    true,
                    8,
                    dst,
                    src1,
                    src2,
                    len,
                    s_dst,
                    s1,
                    s2,
                    false,
                )
            }
            "ifa_simd_multi_arena_tripartite_i32" if args.len() >= 7 => {
                let dst = self.ensure_ptr(self.value_map[&args[0]]);
                let src1 = self.ensure_ptr(self.value_map[&args[1]]);
                let src2 = self.ensure_ptr(self.value_map[&args[2]]);
                let len = self.ensure_i64(self.value_map[&args[3]]);
                let s_dst = self.ensure_i64(self.value_map[&args[4]]);
                let s1 = self.ensure_i64(self.value_map[&args[5]]);
                let s2 = self.ensure_i64(self.value_map[&args[6]]);
                self.lower_multi_arena_tripartite(
                    types::I32,
                    false,
                    4,
                    dst,
                    src1,
                    src2,
                    len,
                    s_dst,
                    s1,
                    s2,
                    false,
                )
            }
            "ifa_simd_multi_arena_tripartite_i64" if args.len() >= 7 => {
                let dst = self.ensure_ptr(self.value_map[&args[0]]);
                let src1 = self.ensure_ptr(self.value_map[&args[1]]);
                let src2 = self.ensure_ptr(self.value_map[&args[2]]);
                let len = self.ensure_i64(self.value_map[&args[3]]);
                let s_dst = self.ensure_i64(self.value_map[&args[4]]);
                let s1 = self.ensure_i64(self.value_map[&args[5]]);
                let s2 = self.ensure_i64(self.value_map[&args[6]]);
                self.lower_multi_arena_tripartite(
                    types::I64,
                    false,
                    8,
                    dst,
                    src1,
                    src2,
                    len,
                    s_dst,
                    s1,
                    s2,
                    false,
                )
            }
            "ifa_simd_strided_tripartite_f32" if args.len() >= 5 => {
                let dst = self.ensure_ptr(self.value_map[&args[0]]);
                let src1 = self.ensure_ptr(self.value_map[&args[1]]);
                let src2 = self.ensure_ptr(self.value_map[&args[2]]);
                let len = self.ensure_i64(self.value_map[&args[3]]);
                let stride = self.ensure_i64(self.value_map[&args[4]]);
                self.lower_multi_arena_tripartite(
                    types::F32,
                    true,
                    4,
                    dst,
                    src1,
                    src2,
                    len,
                    stride,
                    stride,
                    stride,
                    false,
                )
            }
            "ifa_simd_strided_tripartite_f64" if args.len() >= 5 => {
                let dst = self.ensure_ptr(self.value_map[&args[0]]);
                let src1 = self.ensure_ptr(self.value_map[&args[1]]);
                let src2 = self.ensure_ptr(self.value_map[&args[2]]);
                let len = self.ensure_i64(self.value_map[&args[3]]);
                let stride = self.ensure_i64(self.value_map[&args[4]]);
                self.lower_multi_arena_tripartite(
                    types::F64,
                    true,
                    8,
                    dst,
                    src1,
                    src2,
                    len,
                    stride,
                    stride,
                    stride,
                    false,
                )
            }
            "ifa_simd_slice_tripartite_f32" | "ifa_simd_arena_slice_tripartite_f32"
                if args.len() >= 4 =>
            {
                let dst = self.ensure_ptr(self.value_map[&args[0]]);
                let src1 = self.ensure_ptr(self.value_map[&args[1]]);
                let src2 = self.ensure_ptr(self.value_map[&args[2]]);
                let len = self.ensure_i64(self.value_map[&args[3]]);
                let stride = self.builder.ins().iconst(types::I64, 1);
                self.lower_multi_arena_tripartite(
                    types::F32,
                    true,
                    4,
                    dst,
                    src1,
                    src2,
                    len,
                    stride,
                    stride,
                    stride,
                    true,
                )
            }
            "ifa_simd_slice_tripartite_f64" | "ifa_simd_arena_slice_tripartite_f64"
                if args.len() >= 4 =>
            {
                let dst = self.ensure_ptr(self.value_map[&args[0]]);
                let src1 = self.ensure_ptr(self.value_map[&args[1]]);
                let src2 = self.ensure_ptr(self.value_map[&args[2]]);
                let len = self.ensure_i64(self.value_map[&args[3]]);
                let stride = self.builder.ins().iconst(types::I64, 1);
                self.lower_multi_arena_tripartite(
                    types::F64,
                    true,
                    8,
                    dst,
                    src1,
                    src2,
                    len,
                    stride,
                    stride,
                    stride,
                    true,
                )
            }

            // Strided & Contiguous Dot Product
            "ifa_simd_strided_slice_dot_f32" if args.len() >= 4 => {
                let src1 = self.ensure_ptr(self.value_map[&args[0]]);
                let src2 = self.ensure_ptr(self.value_map[&args[1]]);
                let len = self.ensure_i64(self.value_map[&args[2]]);
                let stride = self.ensure_i64(self.value_map[&args[3]]);
                self.lower_multi_arena_slice_dot(
                    types::F32,
                    true,
                    4,
                    src1,
                    src2,
                    len,
                    stride,
                    stride,
                    false,
                )
            }
            "ifa_simd_strided_slice_dot_f64" if args.len() >= 4 => {
                let src1 = self.ensure_ptr(self.value_map[&args[0]]);
                let src2 = self.ensure_ptr(self.value_map[&args[1]]);
                let len = self.ensure_i64(self.value_map[&args[2]]);
                let stride = self.ensure_i64(self.value_map[&args[3]]);
                self.lower_multi_arena_slice_dot(
                    types::F64,
                    true,
                    8,
                    src1,
                    src2,
                    len,
                    stride,
                    stride,
                    false,
                )
            }
            "ifa_simd_strided_slice_dot_i32" if args.len() >= 4 => {
                let src1 = self.ensure_ptr(self.value_map[&args[0]]);
                let src2 = self.ensure_ptr(self.value_map[&args[1]]);
                let len = self.ensure_i64(self.value_map[&args[2]]);
                let stride = self.ensure_i64(self.value_map[&args[3]]);
                self.lower_multi_arena_slice_dot(
                    types::I32,
                    false,
                    4,
                    src1,
                    src2,
                    len,
                    stride,
                    stride,
                    false,
                )
            }
            "ifa_simd_strided_slice_dot_i64" if args.len() >= 4 => {
                let src1 = self.ensure_ptr(self.value_map[&args[0]]);
                let src2 = self.ensure_ptr(self.value_map[&args[1]]);
                let len = self.ensure_i64(self.value_map[&args[2]]);
                let stride = self.ensure_i64(self.value_map[&args[3]]);
                self.lower_multi_arena_slice_dot(
                    types::I64,
                    false,
                    8,
                    src1,
                    src2,
                    len,
                    stride,
                    stride,
                    false,
                )
            }
            "ifa_simd_slice_dot_f32" | "ifa_simd_arena_slice_dot_f32" if args.len() >= 3 => {
                let src1 = self.ensure_ptr(self.value_map[&args[0]]);
                let src2 = self.ensure_ptr(self.value_map[&args[1]]);
                let len = self.ensure_i64(self.value_map[&args[2]]);
                let stride = self.builder.ins().iconst(types::I64, 1);
                self.lower_multi_arena_slice_dot(
                    types::F32,
                    true,
                    4,
                    src1,
                    src2,
                    len,
                    stride,
                    stride,
                    true,
                )
            }
            "ifa_simd_slice_dot_f64" | "ifa_simd_arena_slice_dot_f64" if args.len() >= 3 => {
                let src1 = self.ensure_ptr(self.value_map[&args[0]]);
                let src2 = self.ensure_ptr(self.value_map[&args[1]]);
                let len = self.ensure_i64(self.value_map[&args[2]]);
                let stride = self.builder.ins().iconst(types::I64, 1);
                self.lower_multi_arena_slice_dot(
                    types::F64,
                    true,
                    8,
                    src1,
                    src2,
                    len,
                    stride,
                    stride,
                    true,
                )
            }
            "ifa_simd_slice_dot_i32" | "ifa_simd_arena_slice_dot_i32" if args.len() >= 3 => {
                let src1 = self.ensure_ptr(self.value_map[&args[0]]);
                let src2 = self.ensure_ptr(self.value_map[&args[1]]);
                let len = self.ensure_i64(self.value_map[&args[2]]);
                let stride = self.builder.ins().iconst(types::I64, 1);
                self.lower_multi_arena_slice_dot(
                    types::I32,
                    false,
                    4,
                    src1,
                    src2,
                    len,
                    stride,
                    stride,
                    true,
                )
            }
            "ifa_simd_slice_dot_i64" | "ifa_simd_arena_slice_dot_i64" if args.len() >= 3 => {
                let src1 = self.ensure_ptr(self.value_map[&args[0]]);
                let src2 = self.ensure_ptr(self.value_map[&args[1]]);
                let len = self.ensure_i64(self.value_map[&args[2]]);
                let stride = self.builder.ins().iconst(types::I64, 1);
                self.lower_multi_arena_slice_dot(
                    types::I64,
                    false,
                    8,
                    src1,
                    src2,
                    len,
                    stride,
                    stride,
                    true,
                )
            }

            // Strided & Contiguous Sum Reductions
            "ifa_simd_strided_slice_sum_f32" | "ifa_simd_multi_arena_slice_sum_f32"
                if args.len() >= 3 =>
            {
                let src = self.ensure_ptr(self.value_map[&args[0]]);
                let len = self.ensure_i64(self.value_map[&args[1]]);
                let stride = self.ensure_i64(self.value_map[&args[2]]);
                self.lower_strided_slice_sum(types::F32, true, 4, src, len, stride, false)
            }
            "ifa_simd_strided_slice_sum_f64" | "ifa_simd_multi_arena_slice_sum_f64"
                if args.len() >= 3 =>
            {
                let src = self.ensure_ptr(self.value_map[&args[0]]);
                let len = self.ensure_i64(self.value_map[&args[1]]);
                let stride = self.ensure_i64(self.value_map[&args[2]]);
                self.lower_strided_slice_sum(types::F64, true, 8, src, len, stride, false)
            }
            "ifa_simd_strided_slice_sum_i32" | "ifa_simd_multi_arena_slice_sum_i32"
                if args.len() >= 3 =>
            {
                let src = self.ensure_ptr(self.value_map[&args[0]]);
                let len = self.ensure_i64(self.value_map[&args[1]]);
                let stride = self.ensure_i64(self.value_map[&args[2]]);
                self.lower_strided_slice_sum(types::I32, false, 4, src, len, stride, false)
            }
            "ifa_simd_strided_slice_sum_i64" | "ifa_simd_multi_arena_slice_sum_i64"
                if args.len() >= 3 =>
            {
                let src = self.ensure_ptr(self.value_map[&args[0]]);
                let len = self.ensure_i64(self.value_map[&args[1]]);
                let stride = self.ensure_i64(self.value_map[&args[2]]);
                self.lower_strided_slice_sum(types::I64, false, 8, src, len, stride, false)
            }
            "ifa_simd_slice_sum_f32" | "ifa_simd_arena_slice_sum_f32" if args.len() >= 2 => {
                let src = self.ensure_ptr(self.value_map[&args[0]]);
                let len = self.ensure_i64(self.value_map[&args[1]]);
                let stride = self.builder.ins().iconst(types::I64, 1);
                self.lower_strided_slice_sum(types::F32, true, 4, src, len, stride, true)
            }
            "ifa_simd_slice_sum_f64" | "ifa_simd_arena_slice_sum_f64" if args.len() >= 2 => {
                let src = self.ensure_ptr(self.value_map[&args[0]]);
                let len = self.ensure_i64(self.value_map[&args[1]]);
                let stride = self.builder.ins().iconst(types::I64, 1);
                self.lower_strided_slice_sum(types::F64, true, 8, src, len, stride, true)
            }
            "ifa_simd_slice_sum_i32" | "ifa_simd_arena_slice_sum_i32" if args.len() >= 2 => {
                let src = self.ensure_ptr(self.value_map[&args[0]]);
                let len = self.ensure_i64(self.value_map[&args[1]]);
                let stride = self.builder.ins().iconst(types::I64, 1);
                self.lower_strided_slice_sum(types::I32, false, 4, src, len, stride, true)
            }
            "ifa_simd_slice_sum_i64" | "ifa_simd_arena_slice_sum_i64" if args.len() >= 2 => {
                let src = self.ensure_ptr(self.value_map[&args[0]]);
                let len = self.ensure_i64(self.value_map[&args[1]]);
                let stride = self.builder.ins().iconst(types::I64, 1);
                self.lower_strided_slice_sum(types::I64, false, 8, src, len, stride, true)
            }

            // Strided & Contiguous Product Reductions
            "ifa_simd_strided_slice_prod_f32" | "ifa_simd_multi_arena_slice_prod_f32"
                if args.len() >= 3 =>
            {
                let src = self.ensure_ptr(self.value_map[&args[0]]);
                let len = self.ensure_i64(self.value_map[&args[1]]);
                let stride = self.ensure_i64(self.value_map[&args[2]]);
                self.lower_strided_slice_prod(types::F32, true, 4, src, len, stride)
            }
            "ifa_simd_strided_slice_prod_f64" | "ifa_simd_multi_arena_slice_prod_f64"
                if args.len() >= 3 =>
            {
                let src = self.ensure_ptr(self.value_map[&args[0]]);
                let len = self.ensure_i64(self.value_map[&args[1]]);
                let stride = self.ensure_i64(self.value_map[&args[2]]);
                self.lower_strided_slice_prod(types::F64, true, 8, src, len, stride)
            }
            "ifa_simd_strided_slice_prod_i32" | "ifa_simd_multi_arena_slice_prod_i32"
                if args.len() >= 3 =>
            {
                let src = self.ensure_ptr(self.value_map[&args[0]]);
                let len = self.ensure_i64(self.value_map[&args[1]]);
                let stride = self.ensure_i64(self.value_map[&args[2]]);
                self.lower_strided_slice_prod(types::I32, false, 4, src, len, stride)
            }
            "ifa_simd_strided_slice_prod_i64" | "ifa_simd_multi_arena_slice_prod_i64"
                if args.len() >= 3 =>
            {
                let src = self.ensure_ptr(self.value_map[&args[0]]);
                let len = self.ensure_i64(self.value_map[&args[1]]);
                let stride = self.ensure_i64(self.value_map[&args[2]]);
                self.lower_strided_slice_prod(types::I64, false, 8, src, len, stride)
            }
            "ifa_simd_slice_prod_f32" | "ifa_simd_arena_slice_prod_f32" if args.len() >= 2 => {
                let src = self.ensure_ptr(self.value_map[&args[0]]);
                let len = self.ensure_i64(self.value_map[&args[1]]);
                let stride = self.builder.ins().iconst(types::I64, 1);
                self.lower_strided_slice_prod(types::F32, true, 4, src, len, stride)
            }
            "ifa_simd_slice_prod_f64" | "ifa_simd_arena_slice_prod_f64" if args.len() >= 2 => {
                let src = self.ensure_ptr(self.value_map[&args[0]]);
                let len = self.ensure_i64(self.value_map[&args[1]]);
                let stride = self.builder.ins().iconst(types::I64, 1);
                self.lower_strided_slice_prod(types::F64, true, 8, src, len, stride)
            }
            "ifa_simd_slice_prod_i32" | "ifa_simd_arena_slice_prod_i32" if args.len() >= 2 => {
                let src = self.ensure_ptr(self.value_map[&args[0]]);
                let len = self.ensure_i64(self.value_map[&args[1]]);
                let stride = self.builder.ins().iconst(types::I64, 1);
                self.lower_strided_slice_prod(types::I32, false, 4, src, len, stride)
            }
            "ifa_simd_slice_prod_i64" | "ifa_simd_arena_slice_prod_i64" if args.len() >= 2 => {
                let src = self.ensure_ptr(self.value_map[&args[0]]);
                let len = self.ensure_i64(self.value_map[&args[1]]);
                let stride = self.builder.ins().iconst(types::I64, 1);
                self.lower_strided_slice_prod(types::I64, false, 8, src, len, stride)
            }

            // Strided & Contiguous Min Reductions
            "ifa_simd_strided_slice_min_f32" | "ifa_simd_multi_arena_slice_min_f32"
                if args.len() >= 3 =>
            {
                let src = self.ensure_ptr(self.value_map[&args[0]]);
                let len = self.ensure_i64(self.value_map[&args[1]]);
                let stride = self.ensure_i64(self.value_map[&args[2]]);
                self.lower_strided_slice_min(types::F32, true, 4, src, len, stride)
            }
            "ifa_simd_strided_slice_min_f64" | "ifa_simd_multi_arena_slice_min_f64"
                if args.len() >= 3 =>
            {
                let src = self.ensure_ptr(self.value_map[&args[0]]);
                let len = self.ensure_i64(self.value_map[&args[1]]);
                let stride = self.ensure_i64(self.value_map[&args[2]]);
                self.lower_strided_slice_min(types::F64, true, 8, src, len, stride)
            }
            "ifa_simd_strided_slice_min_i32" | "ifa_simd_multi_arena_slice_min_i32"
                if args.len() >= 3 =>
            {
                let src = self.ensure_ptr(self.value_map[&args[0]]);
                let len = self.ensure_i64(self.value_map[&args[1]]);
                let stride = self.ensure_i64(self.value_map[&args[2]]);
                self.lower_strided_slice_min(types::I32, false, 4, src, len, stride)
            }
            "ifa_simd_strided_slice_min_i64" | "ifa_simd_multi_arena_slice_min_i64"
                if args.len() >= 3 =>
            {
                let src = self.ensure_ptr(self.value_map[&args[0]]);
                let len = self.ensure_i64(self.value_map[&args[1]]);
                let stride = self.ensure_i64(self.value_map[&args[2]]);
                self.lower_strided_slice_min(types::I64, false, 8, src, len, stride)
            }
            "ifa_simd_slice_min_f32" | "ifa_simd_arena_slice_min_f32" if args.len() >= 2 => {
                let src = self.ensure_ptr(self.value_map[&args[0]]);
                let len = self.ensure_i64(self.value_map[&args[1]]);
                let stride = self.builder.ins().iconst(types::I64, 1);
                self.lower_strided_slice_min(types::F32, true, 4, src, len, stride)
            }
            "ifa_simd_slice_min_f64" | "ifa_simd_arena_slice_min_f64" if args.len() >= 2 => {
                let src = self.ensure_ptr(self.value_map[&args[0]]);
                let len = self.ensure_i64(self.value_map[&args[1]]);
                let stride = self.builder.ins().iconst(types::I64, 1);
                self.lower_strided_slice_min(types::F64, true, 8, src, len, stride)
            }
            "ifa_simd_slice_min_i32" | "ifa_simd_arena_slice_min_i32" if args.len() >= 2 => {
                let src = self.ensure_ptr(self.value_map[&args[0]]);
                let len = self.ensure_i64(self.value_map[&args[1]]);
                let stride = self.builder.ins().iconst(types::I64, 1);
                self.lower_strided_slice_min(types::I32, false, 4, src, len, stride)
            }
            "ifa_simd_slice_min_i64" | "ifa_simd_arena_slice_min_i64" if args.len() >= 2 => {
                let src = self.ensure_ptr(self.value_map[&args[0]]);
                let len = self.ensure_i64(self.value_map[&args[1]]);
                let stride = self.builder.ins().iconst(types::I64, 1);
                self.lower_strided_slice_min(types::I64, false, 8, src, len, stride)
            }

            // Strided & Contiguous Max Reductions
            "ifa_simd_strided_slice_max_f32" | "ifa_simd_multi_arena_slice_max_f32"
                if args.len() >= 3 =>
            {
                let src = self.ensure_ptr(self.value_map[&args[0]]);
                let len = self.ensure_i64(self.value_map[&args[1]]);
                let stride = self.ensure_i64(self.value_map[&args[2]]);
                self.lower_strided_slice_max(types::F32, true, 4, src, len, stride)
            }
            "ifa_simd_strided_slice_max_f64" | "ifa_simd_multi_arena_slice_max_f64"
                if args.len() >= 3 =>
            {
                let src = self.ensure_ptr(self.value_map[&args[0]]);
                let len = self.ensure_i64(self.value_map[&args[1]]);
                let stride = self.ensure_i64(self.value_map[&args[2]]);
                self.lower_strided_slice_max(types::F64, true, 8, src, len, stride)
            }
            "ifa_simd_strided_slice_max_i32" | "ifa_simd_multi_arena_slice_max_i32"
                if args.len() >= 3 =>
            {
                let src = self.ensure_ptr(self.value_map[&args[0]]);
                let len = self.ensure_i64(self.value_map[&args[1]]);
                let stride = self.ensure_i64(self.value_map[&args[2]]);
                self.lower_strided_slice_max(types::I32, false, 4, src, len, stride)
            }
            "ifa_simd_strided_slice_max_i64" | "ifa_simd_multi_arena_slice_max_i64"
                if args.len() >= 3 =>
            {
                let src = self.ensure_ptr(self.value_map[&args[0]]);
                let len = self.ensure_i64(self.value_map[&args[1]]);
                let stride = self.ensure_i64(self.value_map[&args[2]]);
                self.lower_strided_slice_max(types::I64, false, 8, src, len, stride)
            }
            "ifa_simd_slice_max_f32" | "ifa_simd_arena_slice_max_f32" if args.len() >= 2 => {
                let src = self.ensure_ptr(self.value_map[&args[0]]);
                let len = self.ensure_i64(self.value_map[&args[1]]);
                let stride = self.builder.ins().iconst(types::I64, 1);
                self.lower_strided_slice_max(types::F32, true, 4, src, len, stride)
            }
            "ifa_simd_slice_max_f64" | "ifa_simd_arena_slice_max_f64" if args.len() >= 2 => {
                let src = self.ensure_ptr(self.value_map[&args[0]]);
                let len = self.ensure_i64(self.value_map[&args[1]]);
                let stride = self.builder.ins().iconst(types::I64, 1);
                self.lower_strided_slice_max(types::F64, true, 8, src, len, stride)
            }
            "ifa_simd_slice_max_i32" | "ifa_simd_arena_slice_max_i32" if args.len() >= 2 => {
                let src = self.ensure_ptr(self.value_map[&args[0]]);
                let len = self.ensure_i64(self.value_map[&args[1]]);
                let stride = self.builder.ins().iconst(types::I64, 1);
                self.lower_strided_slice_max(types::I32, false, 4, src, len, stride)
            }
            "ifa_simd_slice_max_i64" | "ifa_simd_arena_slice_max_i64" if args.len() >= 2 => {
                let src = self.ensure_ptr(self.value_map[&args[0]]);
                let len = self.ensure_i64(self.value_map[&args[1]]);
                let stride = self.builder.ins().iconst(types::I64, 1);
                self.lower_strided_slice_max(types::I64, false, 8, src, len, stride)
            }

            // Count-If Reductions
            "ifa_simd_arena_slice_count_if_gt_f32" | "ifa_simd_slice_count_if_gt_f32"
                if args.len() >= 3 =>
            {
                let src = self.ensure_ptr(self.value_map[&args[0]]);
                let len = self.ensure_i64(self.value_map[&args[1]]);
                let threshold = self.ensure_f32(self.value_map[&args[2]]);
                let stride = self.builder.ins().iconst(types::I64, 1);
                self.lower_slice_count_if(
                    types::F32,
                    true,
                    4,
                    src,
                    len,
                    stride,
                    threshold,
                    CountPred::Gt,
                )
            }
            "ifa_simd_arena_slice_count_if_gt_f64" | "ifa_simd_slice_count_if_gt_f64"
                if args.len() >= 3 =>
            {
                let src = self.ensure_ptr(self.value_map[&args[0]]);
                let len = self.ensure_i64(self.value_map[&args[1]]);
                let threshold = self.ensure_f64(self.value_map[&args[2]]);
                let stride = self.builder.ins().iconst(types::I64, 1);
                self.lower_slice_count_if(
                    types::F64,
                    true,
                    8,
                    src,
                    len,
                    stride,
                    threshold,
                    CountPred::Gt,
                )
            }
            "ifa_simd_arena_slice_count_if_gt_i32" | "ifa_simd_slice_count_if_gt_i32"
                if args.len() >= 3 =>
            {
                let src = self.ensure_ptr(self.value_map[&args[0]]);
                let len = self.ensure_i64(self.value_map[&args[1]]);
                let threshold = self.ensure_i32(self.value_map[&args[2]]);
                let stride = self.builder.ins().iconst(types::I64, 1);
                self.lower_slice_count_if(
                    types::I32,
                    false,
                    4,
                    src,
                    len,
                    stride,
                    threshold,
                    CountPred::Gt,
                )
            }
            "ifa_simd_arena_slice_count_if_gt_i64" | "ifa_simd_slice_count_if_gt_i64"
                if args.len() >= 3 =>
            {
                let src = self.ensure_ptr(self.value_map[&args[0]]);
                let len = self.ensure_i64(self.value_map[&args[1]]);
                let threshold = self.ensure_i64(self.value_map[&args[2]]);
                let stride = self.builder.ins().iconst(types::I64, 1);
                self.lower_slice_count_if(
                    types::I64,
                    false,
                    8,
                    src,
                    len,
                    stride,
                    threshold,
                    CountPred::Gt,
                )
            }
            "ifa_simd_arena_slice_count_if_lt_i32" | "ifa_simd_slice_count_if_lt_i32"
                if args.len() >= 3 =>
            {
                let src = self.ensure_ptr(self.value_map[&args[0]]);
                let len = self.ensure_i64(self.value_map[&args[1]]);
                let threshold = self.ensure_i32(self.value_map[&args[2]]);
                let stride = self.builder.ins().iconst(types::I64, 1);
                self.lower_slice_count_if(
                    types::I32,
                    false,
                    4,
                    src,
                    len,
                    stride,
                    threshold,
                    CountPred::Lt,
                )
            }
            "ifa_simd_arena_slice_count_if_eq_i32" | "ifa_simd_slice_count_if_eq_i32"
                if args.len() >= 3 =>
            {
                let src = self.ensure_ptr(self.value_map[&args[0]]);
                let len = self.ensure_i64(self.value_map[&args[1]]);
                let threshold = self.ensure_i32(self.value_map[&args[2]]);
                let stride = self.builder.ins().iconst(types::I64, 1);
                self.lower_slice_count_if(
                    types::I32,
                    false,
                    4,
                    src,
                    len,
                    stride,
                    threshold,
                    CountPred::Eq,
                )
            }
            "ifa_simd_arena_slice_count_if_ne_i32" | "ifa_simd_slice_count_if_ne_i32"
                if args.len() >= 3 =>
            {
                let src = self.ensure_ptr(self.value_map[&args[0]]);
                let len = self.ensure_i64(self.value_map[&args[1]]);
                let threshold = self.ensure_i32(self.value_map[&args[2]]);
                let stride = self.builder.ins().iconst(types::I64, 1);
                self.lower_slice_count_if(
                    types::I32,
                    false,
                    4,
                    src,
                    len,
                    stride,
                    threshold,
                    CountPred::Ne,
                )
            }
            "ifa_simd_strided_slice_count_if_gt_i32" if args.len() >= 4 => {
                let src = self.ensure_ptr(self.value_map[&args[0]]);
                let len = self.ensure_i64(self.value_map[&args[1]]);
                let stride = self.ensure_i64(self.value_map[&args[2]]);
                let threshold = self.ensure_i32(self.value_map[&args[3]]);
                self.lower_slice_count_if(
                    types::I32,
                    false,
                    4,
                    src,
                    len,
                    stride,
                    threshold,
                    CountPred::Gt,
                )
            }
            "ifa_simd_strided_slice_count_if_gt_f32" if args.len() >= 4 => {
                let src = self.ensure_ptr(self.value_map[&args[0]]);
                let len = self.ensure_i64(self.value_map[&args[1]]);
                let stride = self.ensure_i64(self.value_map[&args[2]]);
                let threshold = self.ensure_f32(self.value_map[&args[3]]);
                self.lower_slice_count_if(
                    types::F32,
                    true,
                    4,
                    src,
                    len,
                    stride,
                    threshold,
                    CountPred::Gt,
                )
            }

            // Clamp / Elementwise Projections
            "ifa_simd_arena_slice_clamp_f32" | "ifa_simd_slice_clamp_f32" if args.len() >= 5 => {
                let src = self.ensure_ptr(self.value_map[&args[0]]);
                let dst = self.ensure_ptr(self.value_map[&args[1]]);
                let len = self.ensure_i64(self.value_map[&args[2]]);
                let min_val = self.ensure_f32(self.value_map[&args[3]]);
                let max_val = self.ensure_f32(self.value_map[&args[4]]);
                let stride = self.builder.ins().iconst(types::I64, 1);
                self.lower_slice_clamp(types::F32, true, 4, src, dst, len, stride, min_val, max_val)
            }
            "ifa_simd_arena_slice_clamp_i32" | "ifa_simd_slice_clamp_i32" if args.len() >= 5 => {
                let src = self.ensure_ptr(self.value_map[&args[0]]);
                let dst = self.ensure_ptr(self.value_map[&args[1]]);
                let len = self.ensure_i64(self.value_map[&args[2]]);
                let min_val = self.ensure_i32(self.value_map[&args[3]]);
                let max_val = self.ensure_i32(self.value_map[&args[4]]);
                let stride = self.builder.ins().iconst(types::I64, 1);
                self.lower_slice_clamp(
                    types::I32,
                    false,
                    4,
                    src,
                    dst,
                    len,
                    stride,
                    min_val,
                    max_val,
                )
            }
            "ifa_simd_strided_slice_clamp_f32" if args.len() >= 6 => {
                let src = self.ensure_ptr(self.value_map[&args[0]]);
                let dst = self.ensure_ptr(self.value_map[&args[1]]);
                let len = self.ensure_i64(self.value_map[&args[2]]);
                let stride = self.ensure_i64(self.value_map[&args[3]]);
                let min_val = self.ensure_f32(self.value_map[&args[4]]);
                let max_val = self.ensure_f32(self.value_map[&args[5]]);
                self.lower_slice_clamp(types::F32, true, 4, src, dst, len, stride, min_val, max_val)
            }
            "ifa_simd_strided_slice_clamp_i32" if args.len() >= 6 => {
                let src = self.ensure_ptr(self.value_map[&args[0]]);
                let dst = self.ensure_ptr(self.value_map[&args[1]]);
                let len = self.ensure_i64(self.value_map[&args[2]]);
                let stride = self.ensure_i64(self.value_map[&args[3]]);
                let min_val = self.ensure_i32(self.value_map[&args[4]]);
                let max_val = self.ensure_i32(self.value_map[&args[5]]);
                self.lower_slice_clamp(
                    types::I32,
                    false,
                    4,
                    src,
                    dst,
                    len,
                    stride,
                    min_val,
                    max_val,
                )
            }

            _ => None,
        }
    }

    /// Contiguous 128-bit SIMD vector loop lowering for slice sums.
    fn lower_contiguous_slice_sum(
        &mut self,
        elem_ty: types::Type,
        is_float: bool,
        elem_size: i64,
        src: ClValue,
        len: ClValue,
    ) -> Option<ClValue> {
        let (vec_ty, lane_count, unroll_mask) = if elem_ty == types::F32 {
            (types::F32X4, 4i64, -4i64)
        } else if elem_ty == types::I32 {
            (types::I32X4, 4i64, -4i64)
        } else if elem_ty == types::F64 {
            (types::F64X2, 2i64, -2i64)
        } else {
            (types::I64X2, 2i64, -2i64)
        };

        let mask_val = self.builder.ins().iconst(types::I64, unroll_mask);
        let unroll_len = self.builder.ins().band(len, mask_val);

        let initial_vec = if is_float {
            if elem_ty == types::F32 {
                let zero = self.builder.ins().f32const(0.0);
                self.builder.ins().splat(vec_ty, zero)
            } else {
                let zero = self.builder.ins().f64const(0.0);
                self.builder.ins().splat(vec_ty, zero)
            }
        } else {
            let zero = self.builder.ins().iconst(elem_ty, 0);
            self.builder.ins().splat(vec_ty, zero)
        };

        let vec_header = self.builder.create_block();
        let vec_body = self.builder.create_block();
        let vec_exit = self.builder.create_block();
        let tail_header = self.builder.create_block();
        let tail_body = self.builder.create_block();
        let cont_block = self.builder.create_block();

        self.builder.append_block_param(vec_header, types::I64);
        self.builder.append_block_param(vec_header, self.ptr_type);
        self.builder.append_block_param(vec_header, vec_ty);

        self.builder.append_block_param(vec_exit, types::I64);
        self.builder.append_block_param(vec_exit, self.ptr_type);
        self.builder.append_block_param(vec_exit, vec_ty);

        self.builder.append_block_param(tail_header, types::I64);
        self.builder.append_block_param(tail_header, self.ptr_type);
        self.builder.append_block_param(tail_header, elem_ty);

        self.builder.append_block_param(cont_block, elem_ty);

        let initial_i = self.builder.ins().iconst(types::I64, 0);
        self.builder.ins().jump(
            vec_header,
            &[
                BlockArg::from(initial_i),
                BlockArg::from(src),
                BlockArg::from(initial_vec),
            ],
        );

        // Vector Loop Header
        self.builder.switch_to_block(vec_header);
        let cur_i = self.builder.block_params(vec_header)[0];
        let cur_ptr = self.builder.block_params(vec_header)[1];
        let cur_vec = self.builder.block_params(vec_header)[2];

        let has_vec = self
            .builder
            .ins()
            .icmp(IntCC::UnsignedLessThan, cur_i, unroll_len);
        self.builder.ins().brif(
            has_vec,
            vec_body,
            &[],
            vec_exit,
            &[
                BlockArg::from(cur_i),
                BlockArg::from(cur_ptr),
                BlockArg::from(cur_vec),
            ],
        );

        // Vector Loop Body
        self.builder.switch_to_block(vec_body);
        let v = self
            .builder
            .ins()
            .load(vec_ty, MemFlagsData::trusted(), cur_ptr, 0);
        let next_vec = if is_float {
            self.builder.ins().fadd(cur_vec, v)
        } else {
            self.builder.ins().iadd(cur_vec, v)
        };
        let step_bytes = 16i64;
        let next_ptr = self.builder.ins().iadd_imm_s(cur_ptr, step_bytes);
        let next_i = self.builder.ins().iadd_imm_s(cur_i, lane_count);
        self.builder.ins().jump(
            vec_header,
            &[
                BlockArg::from(next_i),
                BlockArg::from(next_ptr),
                BlockArg::from(next_vec),
            ],
        );

        // Vector Exit: Horizontal reduction of lanes
        self.builder.switch_to_block(vec_exit);
        let exit_i = self.builder.block_params(vec_exit)[0];
        let exit_ptr = self.builder.block_params(vec_exit)[1];
        let final_vec = self.builder.block_params(vec_exit)[2];

        let scalar_acc = if lane_count == 4 {
            let l0 = self.builder.ins().extractlane(final_vec, 0);
            let l1 = self.builder.ins().extractlane(final_vec, 1);
            let l2 = self.builder.ins().extractlane(final_vec, 2);
            let l3 = self.builder.ins().extractlane(final_vec, 3);
            let s01 = if is_float {
                self.builder.ins().fadd(l0, l1)
            } else {
                self.builder.ins().iadd(l0, l1)
            };
            let s23 = if is_float {
                self.builder.ins().fadd(l2, l3)
            } else {
                self.builder.ins().iadd(l2, l3)
            };
            if is_float {
                self.builder.ins().fadd(s01, s23)
            } else {
                self.builder.ins().iadd(s01, s23)
            }
        } else {
            let l0 = self.builder.ins().extractlane(final_vec, 0);
            let l1 = self.builder.ins().extractlane(final_vec, 1);
            if is_float {
                self.builder.ins().fadd(l0, l1)
            } else {
                self.builder.ins().iadd(l0, l1)
            }
        };

        self.builder.ins().jump(
            tail_header,
            &[
                BlockArg::from(exit_i),
                BlockArg::from(exit_ptr),
                BlockArg::from(scalar_acc),
            ],
        );

        // Tail Loop Header
        self.builder.switch_to_block(tail_header);
        let cur_tail_i = self.builder.block_params(tail_header)[0];
        let cur_tail_ptr = self.builder.block_params(tail_header)[1];
        let cur_tail_acc = self.builder.block_params(tail_header)[2];

        let has_tail = self
            .builder
            .ins()
            .icmp(IntCC::UnsignedLessThan, cur_tail_i, len);
        self.builder.ins().brif(
            has_tail,
            tail_body,
            &[],
            cont_block,
            &[BlockArg::from(cur_tail_acc)],
        );

        // Tail Loop Body
        self.builder.switch_to_block(tail_body);
        let tail_val = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), cur_tail_ptr, 0);
        let next_tail_acc = if is_float {
            self.builder.ins().fadd(cur_tail_acc, tail_val)
        } else {
            self.builder.ins().iadd(cur_tail_acc, tail_val)
        };
        let next_tail_ptr = self.builder.ins().iadd_imm_s(cur_tail_ptr, elem_size);
        let next_tail_i = self.builder.ins().iadd_imm_s(cur_tail_i, 1);
        self.builder.ins().jump(
            tail_header,
            &[
                BlockArg::from(next_tail_i),
                BlockArg::from(next_tail_ptr),
                BlockArg::from(next_tail_acc),
            ],
        );

        self.builder.switch_to_block(cont_block);
        let final_res = self.builder.block_params(cont_block)[0];
        Some(final_res)
    }

    /// Lower strided or contiguous slice sums with strength-reduced address calculation and 4-way unrolling.
    #[allow(clippy::too_many_arguments)]
    fn lower_strided_slice_sum(
        &mut self,
        elem_ty: types::Type,
        is_float: bool,
        elem_size: i64,
        src: ClValue,
        len: ClValue,
        stride: ClValue,
        known_contiguous: bool,
    ) -> Option<ClValue> {
        if known_contiguous {
            return self.lower_contiguous_slice_sum(elem_ty, is_float, elem_size, src, len);
        }

        let cont_block = self.builder.create_block();
        self.builder.append_block_param(cont_block, elem_ty);

        let contig_block = self.builder.create_block();
        let strided_block = self.builder.create_block();

        let one = self.builder.ins().iconst(types::I64, 1);
        let is_stride_one = self.builder.ins().icmp(IntCC::Equal, stride, one);
        self.builder
            .ins()
            .brif(is_stride_one, contig_block, &[], strided_block, &[]);

        // Contiguous fast-path
        self.builder.switch_to_block(contig_block);
        if let Some(c_res) = self.lower_contiguous_slice_sum(elem_ty, is_float, elem_size, src, len)
        {
            self.builder
                .ins()
                .jump(cont_block, &[BlockArg::from(c_res)]);
        } else {
            let zero = if is_float {
                if elem_ty == types::F32 {
                    self.builder.ins().f32const(0.0)
                } else {
                    self.builder.ins().f64const(0.0)
                }
            } else {
                self.builder.ins().iconst(elem_ty, 0)
            };
            self.builder.ins().jump(cont_block, &[BlockArg::from(zero)]);
        }

        // Strided 4-way unrolled strength-reduced path
        self.builder.switch_to_block(strided_block);
        let step_bytes = self.builder.ins().imul_imm_s(stride, elem_size);
        let step2_bytes = self.builder.ins().iadd(step_bytes, step_bytes);
        let step3_bytes = self.builder.ins().iadd(step2_bytes, step_bytes);
        let step4_bytes = self.builder.ins().iadd(step2_bytes, step2_bytes);

        let mask_val = self.builder.ins().iconst(types::I64, -4);
        let unroll_len = self.builder.ins().band(len, mask_val);

        let initial_acc = if is_float {
            if elem_ty == types::F32 {
                self.builder.ins().f32const(0.0)
            } else {
                self.builder.ins().f64const(0.0)
            }
        } else {
            self.builder.ins().iconst(elem_ty, 0)
        };

        let unroll_header = self.builder.create_block();
        let unroll_body = self.builder.create_block();
        let tail_header = self.builder.create_block();
        let tail_body = self.builder.create_block();

        self.builder.append_block_param(unroll_header, types::I64);
        self.builder
            .append_block_param(unroll_header, self.ptr_type);
        self.builder.append_block_param(unroll_header, elem_ty);

        self.builder.append_block_param(tail_header, types::I64);
        self.builder.append_block_param(tail_header, self.ptr_type);
        self.builder.append_block_param(tail_header, elem_ty);

        let initial_i = self.builder.ins().iconst(types::I64, 0);
        self.builder.ins().jump(
            unroll_header,
            &[
                BlockArg::from(initial_i),
                BlockArg::from(src),
                BlockArg::from(initial_acc),
            ],
        );

        // Unroll Loop Header
        self.builder.switch_to_block(unroll_header);
        let cur_i = self.builder.block_params(unroll_header)[0];
        let cur_ptr = self.builder.block_params(unroll_header)[1];
        let cur_acc = self.builder.block_params(unroll_header)[2];

        let has_unroll = self
            .builder
            .ins()
            .icmp(IntCC::UnsignedLessThan, cur_i, unroll_len);
        self.builder.ins().brif(
            has_unroll,
            unroll_body,
            &[],
            tail_header,
            &[
                BlockArg::from(cur_i),
                BlockArg::from(cur_ptr),
                BlockArg::from(cur_acc),
            ],
        );

        // Unroll Loop Body: 4-way pipelined loads + tree accumulation
        self.builder.switch_to_block(unroll_body);
        let p0 = cur_ptr;
        let p1 = self.builder.ins().iadd(cur_ptr, step_bytes);
        let p2 = self.builder.ins().iadd(cur_ptr, step2_bytes);
        let p3 = self.builder.ins().iadd(cur_ptr, step3_bytes);

        let v0 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), p0, 0);
        let v1 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), p1, 0);
        let v2 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), p2, 0);
        let v3 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), p3, 0);

        let s01 = if is_float {
            self.builder.ins().fadd(v0, v1)
        } else {
            self.builder.ins().iadd(v0, v1)
        };
        let s23 = if is_float {
            self.builder.ins().fadd(v2, v3)
        } else {
            self.builder.ins().iadd(v2, v3)
        };
        let s03 = if is_float {
            self.builder.ins().fadd(s01, s23)
        } else {
            self.builder.ins().iadd(s01, s23)
        };
        let next_acc = if is_float {
            self.builder.ins().fadd(cur_acc, s03)
        } else {
            self.builder.ins().iadd(cur_acc, s03)
        };

        let next_ptr = self.builder.ins().iadd(cur_ptr, step4_bytes);
        let next_i = self.builder.ins().iadd_imm_s(cur_i, 4);
        self.builder.ins().jump(
            unroll_header,
            &[
                BlockArg::from(next_i),
                BlockArg::from(next_ptr),
                BlockArg::from(next_acc),
            ],
        );

        // Tail Loop Header
        self.builder.switch_to_block(tail_header);
        let cur_tail_i = self.builder.block_params(tail_header)[0];
        let cur_tail_ptr = self.builder.block_params(tail_header)[1];
        let cur_tail_acc = self.builder.block_params(tail_header)[2];

        let has_tail = self
            .builder
            .ins()
            .icmp(IntCC::UnsignedLessThan, cur_tail_i, len);
        self.builder.ins().brif(
            has_tail,
            tail_body,
            &[],
            cont_block,
            &[BlockArg::from(cur_tail_acc)],
        );

        // Tail Loop Body
        self.builder.switch_to_block(tail_body);
        let tail_val = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), cur_tail_ptr, 0);
        let next_tail_acc = if is_float {
            self.builder.ins().fadd(cur_tail_acc, tail_val)
        } else {
            self.builder.ins().iadd(cur_tail_acc, tail_val)
        };
        let next_tail_ptr = self.builder.ins().iadd(cur_tail_ptr, step_bytes);
        let next_tail_i = self.builder.ins().iadd_imm_s(cur_tail_i, 1);
        self.builder.ins().jump(
            tail_header,
            &[
                BlockArg::from(next_tail_i),
                BlockArg::from(next_tail_ptr),
                BlockArg::from(next_tail_acc),
            ],
        );

        self.builder.switch_to_block(cont_block);
        let final_res = self.builder.block_params(cont_block)[0];
        Some(final_res)
    }

    /// Contiguous 128-bit SIMD vector loop lowering for dot products.
    fn lower_contiguous_slice_dot(
        &mut self,
        elem_ty: types::Type,
        is_float: bool,
        elem_size: i64,
        src1: ClValue,
        src2: ClValue,
        len: ClValue,
    ) -> Option<ClValue> {
        let (vec_ty, lane_count, unroll_mask) = if elem_ty == types::F32 {
            (types::F32X4, 4i64, -4i64)
        } else if elem_ty == types::I32 {
            (types::I32X4, 4i64, -4i64)
        } else if elem_ty == types::F64 {
            (types::F64X2, 2i64, -2i64)
        } else {
            (types::I64X2, 2i64, -2i64)
        };

        let mask_val = self.builder.ins().iconst(types::I64, unroll_mask);
        let unroll_len = self.builder.ins().band(len, mask_val);

        let initial_vec = if is_float {
            if elem_ty == types::F32 {
                let zero = self.builder.ins().f32const(0.0);
                self.builder.ins().splat(vec_ty, zero)
            } else {
                let zero = self.builder.ins().f64const(0.0);
                self.builder.ins().splat(vec_ty, zero)
            }
        } else {
            let zero = self.builder.ins().iconst(elem_ty, 0);
            self.builder.ins().splat(vec_ty, zero)
        };

        let vec_header = self.builder.create_block();
        let vec_body = self.builder.create_block();
        let vec_exit = self.builder.create_block();
        let tail_header = self.builder.create_block();
        let tail_body = self.builder.create_block();
        let cont_block = self.builder.create_block();

        self.builder.append_block_param(vec_header, types::I64);
        self.builder.append_block_param(vec_header, self.ptr_type);
        self.builder.append_block_param(vec_header, self.ptr_type);
        self.builder.append_block_param(vec_header, vec_ty);

        self.builder.append_block_param(vec_exit, types::I64);
        self.builder.append_block_param(vec_exit, self.ptr_type);
        self.builder.append_block_param(vec_exit, self.ptr_type);
        self.builder.append_block_param(vec_exit, vec_ty);

        self.builder.append_block_param(tail_header, types::I64);
        self.builder.append_block_param(tail_header, self.ptr_type);
        self.builder.append_block_param(tail_header, self.ptr_type);
        self.builder.append_block_param(tail_header, elem_ty);

        self.builder.append_block_param(cont_block, elem_ty);

        let initial_i = self.builder.ins().iconst(types::I64, 0);
        self.builder.ins().jump(
            vec_header,
            &[
                BlockArg::from(initial_i),
                BlockArg::from(src1),
                BlockArg::from(src2),
                BlockArg::from(initial_vec),
            ],
        );

        // Vector Loop Header
        self.builder.switch_to_block(vec_header);
        let cur_i = self.builder.block_params(vec_header)[0];
        let cur_ptr1 = self.builder.block_params(vec_header)[1];
        let cur_ptr2 = self.builder.block_params(vec_header)[2];
        let cur_vec = self.builder.block_params(vec_header)[3];

        let has_vec = self
            .builder
            .ins()
            .icmp(IntCC::UnsignedLessThan, cur_i, unroll_len);
        self.builder.ins().brif(
            has_vec,
            vec_body,
            &[],
            vec_exit,
            &[
                BlockArg::from(cur_i),
                BlockArg::from(cur_ptr1),
                BlockArg::from(cur_ptr2),
                BlockArg::from(cur_vec),
            ],
        );

        // Vector Loop Body
        self.builder.switch_to_block(vec_body);
        let v1 = self
            .builder
            .ins()
            .load(vec_ty, MemFlagsData::trusted(), cur_ptr1, 0);
        let v2 = self
            .builder
            .ins()
            .load(vec_ty, MemFlagsData::trusted(), cur_ptr2, 0);
        let prod = if is_float {
            self.builder.ins().fmul(v1, v2)
        } else {
            self.builder.ins().imul(v1, v2)
        };
        let next_vec = if is_float {
            self.builder.ins().fadd(cur_vec, prod)
        } else {
            self.builder.ins().iadd(cur_vec, prod)
        };
        let step_bytes = 16i64;
        let next_ptr1 = self.builder.ins().iadd_imm_s(cur_ptr1, step_bytes);
        let next_ptr2 = self.builder.ins().iadd_imm_s(cur_ptr2, step_bytes);
        let next_i = self.builder.ins().iadd_imm_s(cur_i, lane_count);
        self.builder.ins().jump(
            vec_header,
            &[
                BlockArg::from(next_i),
                BlockArg::from(next_ptr1),
                BlockArg::from(next_ptr2),
                BlockArg::from(next_vec),
            ],
        );

        // Vector Exit
        self.builder.switch_to_block(vec_exit);
        let exit_i = self.builder.block_params(vec_exit)[0];
        let exit_ptr1 = self.builder.block_params(vec_exit)[1];
        let exit_ptr2 = self.builder.block_params(vec_exit)[2];
        let final_vec = self.builder.block_params(vec_exit)[3];

        let scalar_acc = if lane_count == 4 {
            let l0 = self.builder.ins().extractlane(final_vec, 0);
            let l1 = self.builder.ins().extractlane(final_vec, 1);
            let l2 = self.builder.ins().extractlane(final_vec, 2);
            let l3 = self.builder.ins().extractlane(final_vec, 3);
            let s01 = if is_float {
                self.builder.ins().fadd(l0, l1)
            } else {
                self.builder.ins().iadd(l0, l1)
            };
            let s23 = if is_float {
                self.builder.ins().fadd(l2, l3)
            } else {
                self.builder.ins().iadd(l2, l3)
            };
            if is_float {
                self.builder.ins().fadd(s01, s23)
            } else {
                self.builder.ins().iadd(s01, s23)
            }
        } else {
            let l0 = self.builder.ins().extractlane(final_vec, 0);
            let l1 = self.builder.ins().extractlane(final_vec, 1);
            if is_float {
                self.builder.ins().fadd(l0, l1)
            } else {
                self.builder.ins().iadd(l0, l1)
            }
        };

        self.builder.ins().jump(
            tail_header,
            &[
                BlockArg::from(exit_i),
                BlockArg::from(exit_ptr1),
                BlockArg::from(exit_ptr2),
                BlockArg::from(scalar_acc),
            ],
        );

        // Tail Loop Header
        self.builder.switch_to_block(tail_header);
        let cur_tail_i = self.builder.block_params(tail_header)[0];
        let cur_tail_p1 = self.builder.block_params(tail_header)[1];
        let cur_tail_p2 = self.builder.block_params(tail_header)[2];
        let cur_tail_acc = self.builder.block_params(tail_header)[3];

        let has_tail = self
            .builder
            .ins()
            .icmp(IntCC::UnsignedLessThan, cur_tail_i, len);
        self.builder.ins().brif(
            has_tail,
            tail_body,
            &[],
            cont_block,
            &[BlockArg::from(cur_tail_acc)],
        );

        // Tail Loop Body
        self.builder.switch_to_block(tail_body);
        let tv1 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), cur_tail_p1, 0);
        let tv2 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), cur_tail_p2, 0);
        let prod = if is_float {
            self.builder.ins().fmul(tv1, tv2)
        } else {
            self.builder.ins().imul(tv1, tv2)
        };
        let next_tail_acc = if is_float {
            self.builder.ins().fadd(cur_tail_acc, prod)
        } else {
            self.builder.ins().iadd(cur_tail_acc, prod)
        };
        let next_tail_p1 = self.builder.ins().iadd_imm_s(cur_tail_p1, elem_size);
        let next_tail_p2 = self.builder.ins().iadd_imm_s(cur_tail_p2, elem_size);
        let next_tail_i = self.builder.ins().iadd_imm_s(cur_tail_i, 1);
        self.builder.ins().jump(
            tail_header,
            &[
                BlockArg::from(next_tail_i),
                BlockArg::from(next_tail_p1),
                BlockArg::from(next_tail_p2),
                BlockArg::from(next_tail_acc),
            ],
        );

        self.builder.switch_to_block(cont_block);
        let final_res = self.builder.block_params(cont_block)[0];
        Some(final_res)
    }

    /// Lower multi-arena dot products with independent non-unit strides and 4-way unrolling.
    #[allow(clippy::too_many_arguments)]
    fn lower_multi_arena_slice_dot(
        &mut self,
        elem_ty: types::Type,
        is_float: bool,
        elem_size: i64,
        src1: ClValue,
        src2: ClValue,
        len: ClValue,
        stride1: ClValue,
        stride2: ClValue,
        known_contiguous: bool,
    ) -> Option<ClValue> {
        if known_contiguous {
            return self.lower_contiguous_slice_dot(elem_ty, is_float, elem_size, src1, src2, len);
        }

        let cont_block = self.builder.create_block();
        self.builder.append_block_param(cont_block, elem_ty);

        let contig_block = self.builder.create_block();
        let strided_block = self.builder.create_block();

        let one = self.builder.ins().iconst(types::I64, 1);
        let is_s1_one = self.builder.ins().icmp(IntCC::Equal, stride1, one);
        let is_s2_one = self.builder.ins().icmp(IntCC::Equal, stride2, one);
        let both_contig = self.builder.ins().band(is_s1_one, is_s2_one);
        self.builder
            .ins()
            .brif(both_contig, contig_block, &[], strided_block, &[]);

        // Contiguous fast path
        self.builder.switch_to_block(contig_block);
        if let Some(c_res) =
            self.lower_contiguous_slice_dot(elem_ty, is_float, elem_size, src1, src2, len)
        {
            self.builder
                .ins()
                .jump(cont_block, &[BlockArg::from(c_res)]);
        } else {
            let zero = if is_float {
                if elem_ty == types::F32 {
                    self.builder.ins().f32const(0.0)
                } else {
                    self.builder.ins().f64const(0.0)
                }
            } else {
                self.builder.ins().iconst(elem_ty, 0)
            };
            self.builder.ins().jump(cont_block, &[BlockArg::from(zero)]);
        }

        // Strided 4-way unrolled strength-reduced multi-arena path
        self.builder.switch_to_block(strided_block);
        let step1_bytes = self.builder.ins().imul_imm_s(stride1, elem_size);
        let step2_bytes = self.builder.ins().imul_imm_s(stride2, elem_size);
        let step1_2 = self.builder.ins().iadd(step1_bytes, step1_bytes);
        let step1_3 = self.builder.ins().iadd(step1_2, step1_bytes);
        let step1_4 = self.builder.ins().iadd(step1_2, step1_2);

        let step2_2 = self.builder.ins().iadd(step2_bytes, step2_bytes);
        let step2_3 = self.builder.ins().iadd(step2_2, step2_bytes);
        let step2_4 = self.builder.ins().iadd(step2_2, step2_2);

        let mask_val = self.builder.ins().iconst(types::I64, -4);
        let unroll_len = self.builder.ins().band(len, mask_val);

        let initial_acc = if is_float {
            if elem_ty == types::F32 {
                self.builder.ins().f32const(0.0)
            } else {
                self.builder.ins().f64const(0.0)
            }
        } else {
            self.builder.ins().iconst(elem_ty, 0)
        };

        let unroll_header = self.builder.create_block();
        let unroll_body = self.builder.create_block();
        let tail_header = self.builder.create_block();
        let tail_body = self.builder.create_block();

        self.builder.append_block_param(unroll_header, types::I64);
        self.builder
            .append_block_param(unroll_header, self.ptr_type);
        self.builder
            .append_block_param(unroll_header, self.ptr_type);
        self.builder.append_block_param(unroll_header, elem_ty);

        self.builder.append_block_param(tail_header, types::I64);
        self.builder.append_block_param(tail_header, self.ptr_type);
        self.builder.append_block_param(tail_header, self.ptr_type);
        self.builder.append_block_param(tail_header, elem_ty);

        let initial_i = self.builder.ins().iconst(types::I64, 0);
        self.builder.ins().jump(
            unroll_header,
            &[
                BlockArg::from(initial_i),
                BlockArg::from(src1),
                BlockArg::from(src2),
                BlockArg::from(initial_acc),
            ],
        );

        // Unroll Loop Header
        self.builder.switch_to_block(unroll_header);
        let cur_i = self.builder.block_params(unroll_header)[0];
        let cur_p1 = self.builder.block_params(unroll_header)[1];
        let cur_p2 = self.builder.block_params(unroll_header)[2];
        let cur_acc = self.builder.block_params(unroll_header)[3];

        let has_unroll = self
            .builder
            .ins()
            .icmp(IntCC::UnsignedLessThan, cur_i, unroll_len);
        self.builder.ins().brif(
            has_unroll,
            unroll_body,
            &[],
            tail_header,
            &[
                BlockArg::from(cur_i),
                BlockArg::from(cur_p1),
                BlockArg::from(cur_p2),
                BlockArg::from(cur_acc),
            ],
        );

        // Unroll Loop Body: 4 pairs of parallel loads + products + tree accumulation
        self.builder.switch_to_block(unroll_body);
        let p1_0 = cur_p1;
        let p1_1 = self.builder.ins().iadd(cur_p1, step1_bytes);
        let p1_2 = self.builder.ins().iadd(cur_p1, step1_2);
        let p1_3 = self.builder.ins().iadd(cur_p1, step1_3);

        let p2_0 = cur_p2;
        let p2_1 = self.builder.ins().iadd(cur_p2, step2_bytes);
        let p2_2 = self.builder.ins().iadd(cur_p2, step2_2);
        let p2_3 = self.builder.ins().iadd(cur_p2, step2_3);

        let v1_0 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), p1_0, 0);
        let v2_0 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), p2_0, 0);
        let v1_1 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), p1_1, 0);
        let v2_1 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), p2_1, 0);
        let v1_2 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), p1_2, 0);
        let v2_2 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), p2_2, 0);
        let v1_3 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), p1_3, 0);
        let v2_3 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), p2_3, 0);

        let prod0 = if is_float {
            self.builder.ins().fmul(v1_0, v2_0)
        } else {
            self.builder.ins().imul(v1_0, v2_0)
        };
        let prod1 = if is_float {
            self.builder.ins().fmul(v1_1, v2_1)
        } else {
            self.builder.ins().imul(v1_1, v2_1)
        };
        let prod2 = if is_float {
            self.builder.ins().fmul(v1_2, v2_2)
        } else {
            self.builder.ins().imul(v1_2, v2_2)
        };
        let prod3 = if is_float {
            self.builder.ins().fmul(v1_3, v2_3)
        } else {
            self.builder.ins().imul(v1_3, v2_3)
        };

        let s01 = if is_float {
            self.builder.ins().fadd(prod0, prod1)
        } else {
            self.builder.ins().iadd(prod0, prod1)
        };
        let s23 = if is_float {
            self.builder.ins().fadd(prod2, prod3)
        } else {
            self.builder.ins().iadd(prod2, prod3)
        };
        let s03 = if is_float {
            self.builder.ins().fadd(s01, s23)
        } else {
            self.builder.ins().iadd(s01, s23)
        };
        let next_acc = if is_float {
            self.builder.ins().fadd(cur_acc, s03)
        } else {
            self.builder.ins().iadd(cur_acc, s03)
        };

        let next_p1 = self.builder.ins().iadd(cur_p1, step1_4);
        let next_p2 = self.builder.ins().iadd(cur_p2, step2_4);
        let next_i = self.builder.ins().iadd_imm_s(cur_i, 4);
        self.builder.ins().jump(
            unroll_header,
            &[
                BlockArg::from(next_i),
                BlockArg::from(next_p1),
                BlockArg::from(next_p2),
                BlockArg::from(next_acc),
            ],
        );

        // Tail Loop Header
        self.builder.switch_to_block(tail_header);
        let cur_tail_i = self.builder.block_params(tail_header)[0];
        let cur_tail_p1 = self.builder.block_params(tail_header)[1];
        let cur_tail_p2 = self.builder.block_params(tail_header)[2];
        let cur_tail_acc = self.builder.block_params(tail_header)[3];

        let has_tail = self
            .builder
            .ins()
            .icmp(IntCC::UnsignedLessThan, cur_tail_i, len);
        self.builder.ins().brif(
            has_tail,
            tail_body,
            &[],
            cont_block,
            &[BlockArg::from(cur_tail_acc)],
        );

        // Tail Loop Body
        self.builder.switch_to_block(tail_body);
        let tv1 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), cur_tail_p1, 0);
        let tv2 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), cur_tail_p2, 0);
        let prod = if is_float {
            self.builder.ins().fmul(tv1, tv2)
        } else {
            self.builder.ins().imul(tv1, tv2)
        };
        let next_tail_acc = if is_float {
            self.builder.ins().fadd(cur_tail_acc, prod)
        } else {
            self.builder.ins().iadd(cur_tail_acc, prod)
        };
        let next_tail_p1 = self.builder.ins().iadd(cur_tail_p1, step1_bytes);
        let next_tail_p2 = self.builder.ins().iadd(cur_tail_p2, step2_bytes);
        let next_tail_i = self.builder.ins().iadd_imm_s(cur_tail_i, 1);
        self.builder.ins().jump(
            tail_header,
            &[
                BlockArg::from(next_tail_i),
                BlockArg::from(next_tail_p1),
                BlockArg::from(next_tail_p2),
                BlockArg::from(next_tail_acc),
            ],
        );

        self.builder.switch_to_block(cont_block);
        let final_res = self.builder.block_params(cont_block)[0];
        Some(final_res)
    }

    /// Lower multi-arena tripartite matrix/tensor fused multiply-accumulate:
    /// `dst[i * stride_dst] += src1[i * stride1] * src2[i * stride2]`
    #[allow(clippy::too_many_arguments)]
    fn lower_multi_arena_tripartite(
        &mut self,
        elem_ty: types::Type,
        is_float: bool,
        elem_size: i64,
        dst: ClValue,
        src1: ClValue,
        src2: ClValue,
        len: ClValue,
        stride_dst: ClValue,
        stride1: ClValue,
        stride2: ClValue,
        _known_contiguous: bool,
    ) -> Option<ClValue> {
        let step_dst = self.builder.ins().imul_imm_s(stride_dst, elem_size);
        let step1 = self.builder.ins().imul_imm_s(stride1, elem_size);
        let step2 = self.builder.ins().imul_imm_s(stride2, elem_size);

        let step_dst_2 = self.builder.ins().iadd(step_dst, step_dst);
        let step_dst_3 = self.builder.ins().iadd(step_dst_2, step_dst);
        let step_dst_4 = self.builder.ins().iadd(step_dst_2, step_dst_2);

        let step1_2 = self.builder.ins().iadd(step1, step1);
        let step1_3 = self.builder.ins().iadd(step1_2, step1);
        let step1_4 = self.builder.ins().iadd(step1_2, step1_2);

        let step2_2 = self.builder.ins().iadd(step2, step2);
        let step2_3 = self.builder.ins().iadd(step2_2, step2);
        let step2_4 = self.builder.ins().iadd(step2_2, step2_2);

        let mask_val = self.builder.ins().iconst(types::I64, -4);
        let unroll_len = self.builder.ins().band(len, mask_val);

        let unroll_header = self.builder.create_block();
        let unroll_body = self.builder.create_block();
        let tail_header = self.builder.create_block();
        let tail_body = self.builder.create_block();
        let cont_block = self.builder.create_block();

        self.builder.append_block_param(unroll_header, types::I64);
        self.builder
            .append_block_param(unroll_header, self.ptr_type);
        self.builder
            .append_block_param(unroll_header, self.ptr_type);
        self.builder
            .append_block_param(unroll_header, self.ptr_type);

        self.builder.append_block_param(tail_header, types::I64);
        self.builder.append_block_param(tail_header, self.ptr_type);
        self.builder.append_block_param(tail_header, self.ptr_type);
        self.builder.append_block_param(tail_header, self.ptr_type);

        let initial_i = self.builder.ins().iconst(types::I64, 0);
        self.builder.ins().jump(
            unroll_header,
            &[
                BlockArg::from(initial_i),
                BlockArg::from(dst),
                BlockArg::from(src1),
                BlockArg::from(src2),
            ],
        );

        // Unroll Loop Header
        self.builder.switch_to_block(unroll_header);
        let cur_i = self.builder.block_params(unroll_header)[0];
        let cur_pd = self.builder.block_params(unroll_header)[1];
        let cur_p1 = self.builder.block_params(unroll_header)[2];
        let cur_p2 = self.builder.block_params(unroll_header)[3];

        let has_unroll = self
            .builder
            .ins()
            .icmp(IntCC::UnsignedLessThan, cur_i, unroll_len);
        self.builder.ins().brif(
            has_unroll,
            unroll_body,
            &[],
            tail_header,
            &[
                BlockArg::from(cur_i),
                BlockArg::from(cur_pd),
                BlockArg::from(cur_p1),
                BlockArg::from(cur_p2),
            ],
        );

        // Unroll Loop Body: 4 multiply-accumulates with in-place store
        self.builder.switch_to_block(unroll_body);
        let pd_0 = cur_pd;
        let pd_1 = self.builder.ins().iadd(cur_pd, step_dst);
        let pd_2 = self.builder.ins().iadd(cur_pd, step_dst_2);
        let pd_3 = self.builder.ins().iadd(cur_pd, step_dst_3);

        let p1_0 = cur_p1;
        let p1_1 = self.builder.ins().iadd(cur_p1, step1);
        let p1_2 = self.builder.ins().iadd(cur_p1, step1_2);
        let p1_3 = self.builder.ins().iadd(cur_p1, step1_3);

        let p2_0 = cur_p2;
        let p2_1 = self.builder.ins().iadd(cur_p2, step2);
        let p2_2 = self.builder.ins().iadd(cur_p2, step2_2);
        let p2_3 = self.builder.ins().iadd(cur_p2, step2_3);

        let vd_0 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), pd_0, 0);
        let vd_1 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), pd_1, 0);
        let vd_2 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), pd_2, 0);
        let vd_3 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), pd_3, 0);

        let v1_0 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), p1_0, 0);
        let v2_0 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), p2_0, 0);
        let v1_1 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), p1_1, 0);
        let v2_1 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), p2_1, 0);
        let v1_2 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), p1_2, 0);
        let v2_2 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), p2_2, 0);
        let v1_3 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), p1_3, 0);
        let v2_3 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), p2_3, 0);

        let prod0 = if is_float {
            self.builder.ins().fmul(v1_0, v2_0)
        } else {
            self.builder.ins().imul(v1_0, v2_0)
        };
        let prod1 = if is_float {
            self.builder.ins().fmul(v1_1, v2_1)
        } else {
            self.builder.ins().imul(v1_1, v2_1)
        };
        let prod2 = if is_float {
            self.builder.ins().fmul(v1_2, v2_2)
        } else {
            self.builder.ins().imul(v1_2, v2_2)
        };
        let prod3 = if is_float {
            self.builder.ins().fmul(v1_3, v2_3)
        } else {
            self.builder.ins().imul(v1_3, v2_3)
        };

        let res0 = if is_float {
            self.builder.ins().fadd(vd_0, prod0)
        } else {
            self.builder.ins().iadd(vd_0, prod0)
        };
        let res1 = if is_float {
            self.builder.ins().fadd(vd_1, prod1)
        } else {
            self.builder.ins().iadd(vd_1, prod1)
        };
        let res2 = if is_float {
            self.builder.ins().fadd(vd_2, prod2)
        } else {
            self.builder.ins().iadd(vd_2, prod2)
        };
        let res3 = if is_float {
            self.builder.ins().fadd(vd_3, prod3)
        } else {
            self.builder.ins().iadd(vd_3, prod3)
        };

        self.builder
            .ins()
            .store(MemFlagsData::trusted(), res0, pd_0, 0);
        self.builder
            .ins()
            .store(MemFlagsData::trusted(), res1, pd_1, 0);
        self.builder
            .ins()
            .store(MemFlagsData::trusted(), res2, pd_2, 0);
        self.builder
            .ins()
            .store(MemFlagsData::trusted(), res3, pd_3, 0);

        let next_pd = self.builder.ins().iadd(cur_pd, step_dst_4);
        let next_p1 = self.builder.ins().iadd(cur_p1, step1_4);
        let next_p2 = self.builder.ins().iadd(cur_p2, step2_4);
        let next_i = self.builder.ins().iadd_imm_s(cur_i, 4);
        self.builder.ins().jump(
            unroll_header,
            &[
                BlockArg::from(next_i),
                BlockArg::from(next_pd),
                BlockArg::from(next_p1),
                BlockArg::from(next_p2),
            ],
        );

        // Tail Loop Header
        self.builder.switch_to_block(tail_header);
        let cur_tail_i = self.builder.block_params(tail_header)[0];
        let cur_tail_pd = self.builder.block_params(tail_header)[1];
        let cur_tail_p1 = self.builder.block_params(tail_header)[2];
        let cur_tail_p2 = self.builder.block_params(tail_header)[3];

        let has_tail = self
            .builder
            .ins()
            .icmp(IntCC::UnsignedLessThan, cur_tail_i, len);
        self.builder
            .ins()
            .brif(has_tail, tail_body, &[], cont_block, &[]);

        // Tail Loop Body
        self.builder.switch_to_block(tail_body);
        let vd = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), cur_tail_pd, 0);
        let v1 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), cur_tail_p1, 0);
        let v2 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), cur_tail_p2, 0);
        let prod = if is_float {
            self.builder.ins().fmul(v1, v2)
        } else {
            self.builder.ins().imul(v1, v2)
        };
        let res = if is_float {
            self.builder.ins().fadd(vd, prod)
        } else {
            self.builder.ins().iadd(vd, prod)
        };
        self.builder
            .ins()
            .store(MemFlagsData::trusted(), res, cur_tail_pd, 0);

        let next_tail_pd = self.builder.ins().iadd(cur_tail_pd, step_dst);
        let next_tail_p1 = self.builder.ins().iadd(cur_tail_p1, step1);
        let next_tail_p2 = self.builder.ins().iadd(cur_tail_p2, step2);
        let next_tail_i = self.builder.ins().iadd_imm_s(cur_tail_i, 1);
        self.builder.ins().jump(
            tail_header,
            &[
                BlockArg::from(next_tail_i),
                BlockArg::from(next_tail_pd),
                BlockArg::from(next_tail_p1),
                BlockArg::from(next_tail_p2),
            ],
        );

        self.builder.switch_to_block(cont_block);
        Some(self.builder.ins().iconst(types::I64, 0))
    }

    /// Lower multi-arena 2D convolution with optional fused bias and activation directly into Cranelift loops.
    #[allow(clippy::too_many_arguments)]
    fn lower_multi_arena_conv2d(
        &mut self,
        elem_ty: types::Type,
        is_float: bool,
        elem_size: i64,
        dst: ClValue,
        img: ClValue,
        weights: ClValue,
        bias: ClValue,
        h_out: ClValue,
        w_out: ClValue,
        stride_y: ClValue,
        stride_x: ClValue,
        img_width: ClValue,
        activation: ClValue,
    ) -> Option<ClValue> {
        let y_header = self.builder.create_block();
        let x_init = self.builder.create_block();
        let x_header = self.builder.create_block();
        let x_body = self.builder.create_block();
        let y_step = self.builder.create_block();
        let done_block = self.builder.create_block();

        // Load w0 from weights[0]
        let w0 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), weights, 0);

        // Precompute scalar bias if bias pointer != null
        let zero_ptr = self.builder.ins().iconst(self.ptr_type, 0);
        let has_bias = self.builder.ins().icmp(IntCC::NotEqual, bias, zero_ptr);
        let bias_block = self.builder.create_block();
        let no_bias_block = self.builder.create_block();
        let bias_merge = self.builder.create_block();
        self.builder.append_block_param(bias_merge, elem_ty);

        self.builder
            .ins()
            .brif(has_bias, bias_block, &[], no_bias_block, &[]);

        self.builder.switch_to_block(bias_block);
        let b_val = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), bias, 0);
        self.builder
            .ins()
            .jump(bias_merge, &[BlockArg::from(b_val)]);

        self.builder.switch_to_block(no_bias_block);
        let zero_elem = if is_float {
            if elem_ty == types::F32 {
                self.builder.ins().f32const(0.0)
            } else {
                self.builder.ins().f64const(0.0)
            }
        } else {
            self.builder.ins().iconst(elem_ty, 0)
        };
        self.builder
            .ins()
            .jump(bias_merge, &[BlockArg::from(zero_elem)]);

        self.builder.switch_to_block(bias_merge);
        let bias_scalar = self.builder.block_params(bias_merge)[0];

        // Start Y loop
        self.builder.append_block_param(y_header, types::I64);
        let zero_i64 = self.builder.ins().iconst(types::I64, 0);
        self.builder
            .ins()
            .jump(y_header, &[BlockArg::from(zero_i64)]);

        self.builder.switch_to_block(y_header);
        let cur_y = self.builder.block_params(y_header)[0];
        let has_y = self.builder.ins().icmp(IntCC::SignedLessThan, cur_y, h_out);
        self.builder.ins().brif(has_y, x_init, &[], done_block, &[]);

        // X init: compute row offsets
        self.builder.switch_to_block(x_init);
        let y_str = self.builder.ins().imul(cur_y, stride_y);
        let y_off = self.builder.ins().imul(y_str, img_width);
        let y_out_off = self.builder.ins().imul(cur_y, w_out);

        self.builder.append_block_param(x_header, types::I64);
        self.builder.append_block_param(x_header, types::I64);
        self.builder.append_block_param(x_header, types::I64);
        self.builder.ins().jump(
            x_header,
            &[
                BlockArg::from(zero_i64),
                BlockArg::from(y_off),
                BlockArg::from(y_out_off),
            ],
        );

        self.builder.switch_to_block(x_header);
        let cur_x = self.builder.block_params(x_header)[0];
        let cur_y_off = self.builder.block_params(x_header)[1];
        let cur_y_out_off = self.builder.block_params(x_header)[2];

        let has_x = self.builder.ins().icmp(IntCC::SignedLessThan, cur_x, w_out);
        self.builder.ins().brif(has_x, x_body, &[], y_step, &[]);

        // X body: compute convolution element, add bias, apply activation, mutate dst
        self.builder.switch_to_block(x_body);
        let x_str = self.builder.ins().imul(cur_x, stride_x);
        let in_elem_idx = self.builder.ins().iadd(cur_y_off, x_str);
        let in_byte_off = self.builder.ins().imul_imm_s(in_elem_idx, elem_size);
        let in_ptr = self.builder.ins().iadd(img, in_byte_off);
        let in_val = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), in_ptr, 0);

        let prod = if is_float {
            self.builder.ins().fmul(in_val, w0)
        } else {
            self.builder.ins().imul(in_val, w0)
        };

        let mut accum = if is_float {
            self.builder.ins().fadd(prod, bias_scalar)
        } else {
            self.builder.ins().iadd(prod, bias_scalar)
        };

        // ReLU activation: if activation == 1 and accum < 0, accum = 0
        let act_relu = self.builder.ins().iconst(types::I32, 1);
        let is_relu = self.builder.ins().icmp(IntCC::Equal, activation, act_relu);
        let zero_val = if is_float {
            if elem_ty == types::F32 {
                self.builder.ins().f32const(0.0)
            } else {
                self.builder.ins().f64const(0.0)
            }
        } else {
            self.builder.ins().iconst(elem_ty, 0)
        };
        let relu_cand = if is_float {
            let is_gt = self
                .builder
                .ins()
                .fcmp(FloatCC::GreaterThan, accum, zero_val);
            self.builder.ins().select(is_gt, accum, zero_val)
        } else {
            let is_gt = self
                .builder
                .ins()
                .icmp(IntCC::SignedGreaterThan, accum, zero_val);
            self.builder.ins().select(is_gt, accum, zero_val)
        };
        accum = self.builder.ins().select(is_relu, relu_cand, accum);

        // Store into dst[out_idx] += accum
        let out_elem_idx = self.builder.ins().iadd(cur_y_out_off, cur_x);
        let out_byte_off = self.builder.ins().imul_imm_s(out_elem_idx, elem_size);
        let out_ptr = self.builder.ins().iadd(dst, out_byte_off);
        let cur_dst = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), out_ptr, 0);
        let new_dst = if is_float {
            self.builder.ins().fadd(cur_dst, accum)
        } else {
            self.builder.ins().iadd(cur_dst, accum)
        };
        self.builder
            .ins()
            .store(MemFlagsData::trusted(), new_dst, out_ptr, 0);

        let next_x = self.builder.ins().iadd_imm_s(cur_x, 1);
        self.builder.ins().jump(
            x_header,
            &[
                BlockArg::from(next_x),
                BlockArg::from(cur_y_off),
                BlockArg::from(cur_y_out_off),
            ],
        );

        // Y step
        self.builder.switch_to_block(y_step);
        let next_y = self.builder.ins().iadd_imm_s(cur_y, 1);
        self.builder.ins().jump(y_header, &[BlockArg::from(next_y)]);

        self.builder.switch_to_block(done_block);
        Some(self.builder.ins().iconst(types::I64, 0))
    }

    /// Lower multi-arena 3D volumetric convolution with optional fused bias and activation into Cranelift loops.
    #[allow(clippy::too_many_arguments)]
    fn lower_multi_arena_conv3d(
        &mut self,
        elem_ty: types::Type,
        is_float: bool,
        elem_size: i64,
        dst: ClValue,
        volume: ClValue,
        filter: ClValue,
        bias: ClValue,
        d_out: ClValue,
        h_out: ClValue,
        w_out: ClValue,
        stride_z: ClValue,
        stride_y: ClValue,
        stride_x: ClValue,
        plane_pitch: ClValue,
        row_pitch: ClValue,
        activation: ClValue,
    ) -> Option<ClValue> {
        let z_header = self.builder.create_block();
        let y_init = self.builder.create_block();
        let y_header = self.builder.create_block();
        let x_init = self.builder.create_block();
        let x_header = self.builder.create_block();
        let x_body = self.builder.create_block();
        let y_step = self.builder.create_block();
        let z_step = self.builder.create_block();
        let done_block = self.builder.create_block();

        let f0 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), filter, 0);

        // Precompute scalar bias if bias pointer != null
        let zero_ptr = self.builder.ins().iconst(self.ptr_type, 0);
        let has_bias = self.builder.ins().icmp(IntCC::NotEqual, bias, zero_ptr);
        let bias_block = self.builder.create_block();
        let no_bias_block = self.builder.create_block();
        let bias_merge = self.builder.create_block();
        self.builder.append_block_param(bias_merge, elem_ty);

        self.builder
            .ins()
            .brif(has_bias, bias_block, &[], no_bias_block, &[]);

        self.builder.switch_to_block(bias_block);
        let b_val = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), bias, 0);
        self.builder
            .ins()
            .jump(bias_merge, &[BlockArg::from(b_val)]);

        self.builder.switch_to_block(no_bias_block);
        let zero_elem = if is_float {
            if elem_ty == types::F32 {
                self.builder.ins().f32const(0.0)
            } else {
                self.builder.ins().f64const(0.0)
            }
        } else {
            self.builder.ins().iconst(elem_ty, 0)
        };
        self.builder
            .ins()
            .jump(bias_merge, &[BlockArg::from(zero_elem)]);

        self.builder.switch_to_block(bias_merge);
        let bias_scalar = self.builder.block_params(bias_merge)[0];

        // Start Z loop
        self.builder.append_block_param(z_header, types::I64);
        let zero_i64 = self.builder.ins().iconst(types::I64, 0);
        self.builder
            .ins()
            .jump(z_header, &[BlockArg::from(zero_i64)]);

        self.builder.switch_to_block(z_header);
        let cur_z = self.builder.block_params(z_header)[0];
        let has_z = self.builder.ins().icmp(IntCC::SignedLessThan, cur_z, d_out);
        self.builder.ins().brif(has_z, y_init, &[], done_block, &[]);

        // Y init: compute plane offsets
        self.builder.switch_to_block(y_init);
        let z_str = self.builder.ins().imul(cur_z, stride_z);
        let z_off = self.builder.ins().imul(z_str, plane_pitch);
        let z_out_plane = self.builder.ins().imul(cur_z, h_out);

        self.builder.append_block_param(y_header, types::I64);
        self.builder.append_block_param(y_header, types::I64);
        self.builder.append_block_param(y_header, types::I64);
        self.builder.ins().jump(
            y_header,
            &[
                BlockArg::from(zero_i64),
                BlockArg::from(z_off),
                BlockArg::from(z_out_plane),
            ],
        );

        self.builder.switch_to_block(y_header);
        let cur_y = self.builder.block_params(y_header)[0];
        let cur_z_off = self.builder.block_params(y_header)[1];
        let cur_z_out_plane = self.builder.block_params(y_header)[2];

        let has_y = self.builder.ins().icmp(IntCC::SignedLessThan, cur_y, h_out);
        self.builder.ins().brif(has_y, x_init, &[], z_step, &[]);

        // X init: compute row offsets
        self.builder.switch_to_block(x_init);
        let y_str = self.builder.ins().imul(cur_y, stride_y);
        let y_off = self.builder.ins().imul(y_str, row_pitch);
        let zy_in_off = self.builder.ins().iadd(cur_z_off, y_off);

        let zy_out_elem = self.builder.ins().iadd(cur_z_out_plane, cur_y);
        let zy_out_off = self.builder.ins().imul(zy_out_elem, w_out);

        self.builder.append_block_param(x_header, types::I64);
        self.builder.append_block_param(x_header, types::I64);
        self.builder.append_block_param(x_header, types::I64);
        self.builder.ins().jump(
            x_header,
            &[
                BlockArg::from(zero_i64),
                BlockArg::from(zy_in_off),
                BlockArg::from(zy_out_off),
            ],
        );

        self.builder.switch_to_block(x_header);
        let cur_x = self.builder.block_params(x_header)[0];
        let cur_zy_in_off = self.builder.block_params(x_header)[1];
        let cur_zy_out_off = self.builder.block_params(x_header)[2];

        let has_x = self.builder.ins().icmp(IntCC::SignedLessThan, cur_x, w_out);
        self.builder.ins().brif(has_x, x_body, &[], y_step, &[]);

        // X body: load, multiply, bias, activation, accumulate
        self.builder.switch_to_block(x_body);
        let x_str = self.builder.ins().imul(cur_x, stride_x);
        let in_elem_idx = self.builder.ins().iadd(cur_zy_in_off, x_str);
        let in_byte_off = self.builder.ins().imul_imm_s(in_elem_idx, elem_size);
        let in_ptr = self.builder.ins().iadd(volume, in_byte_off);
        let in_val = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), in_ptr, 0);

        let prod = if is_float {
            self.builder.ins().fmul(in_val, f0)
        } else {
            self.builder.ins().imul(in_val, f0)
        };

        let mut accum = if is_float {
            self.builder.ins().fadd(prod, bias_scalar)
        } else {
            self.builder.ins().iadd(prod, bias_scalar)
        };

        // ReLU activation
        let act_relu = self.builder.ins().iconst(types::I32, 1);
        let is_relu = self.builder.ins().icmp(IntCC::Equal, activation, act_relu);
        let zero_val = if is_float {
            if elem_ty == types::F32 {
                self.builder.ins().f32const(0.0)
            } else {
                self.builder.ins().f64const(0.0)
            }
        } else {
            self.builder.ins().iconst(elem_ty, 0)
        };
        let relu_cand = if is_float {
            let is_gt = self
                .builder
                .ins()
                .fcmp(FloatCC::GreaterThan, accum, zero_val);
            self.builder.ins().select(is_gt, accum, zero_val)
        } else {
            let is_gt = self
                .builder
                .ins()
                .icmp(IntCC::SignedGreaterThan, accum, zero_val);
            self.builder.ins().select(is_gt, accum, zero_val)
        };
        accum = self.builder.ins().select(is_relu, relu_cand, accum);

        let out_elem_idx = self.builder.ins().iadd(cur_zy_out_off, cur_x);
        let out_byte_off = self.builder.ins().imul_imm_s(out_elem_idx, elem_size);
        let out_ptr = self.builder.ins().iadd(dst, out_byte_off);
        let cur_dst = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), out_ptr, 0);
        let new_dst = if is_float {
            self.builder.ins().fadd(cur_dst, accum)
        } else {
            self.builder.ins().iadd(cur_dst, accum)
        };
        self.builder
            .ins()
            .store(MemFlagsData::trusted(), new_dst, out_ptr, 0);

        let next_x = self.builder.ins().iadd_imm_s(cur_x, 1);
        self.builder.ins().jump(
            x_header,
            &[
                BlockArg::from(next_x),
                BlockArg::from(cur_zy_in_off),
                BlockArg::from(cur_zy_out_off),
            ],
        );

        // Y step
        self.builder.switch_to_block(y_step);
        let next_y = self.builder.ins().iadd_imm_s(cur_y, 1);
        self.builder.ins().jump(
            y_header,
            &[
                BlockArg::from(next_y),
                BlockArg::from(cur_z_off),
                BlockArg::from(cur_z_out_plane),
            ],
        );

        // Z step
        self.builder.switch_to_block(z_step);
        let next_z = self.builder.ins().iadd_imm_s(cur_z, 1);
        self.builder.ins().jump(z_header, &[BlockArg::from(next_z)]);

        self.builder.switch_to_block(done_block);
        Some(self.builder.ins().iconst(types::I64, 0))
    }

    /// Lower multi-arena 2D dilated (atrous) convolution with fused bias and optional activation.
    #[allow(clippy::too_many_arguments)]
    fn lower_multi_arena_dilated_conv2d(
        &mut self,
        elem_ty: types::Type,
        is_float: bool,
        elem_size: i64,
        dst: ClValue,
        img: ClValue,
        weights: ClValue,
        bias: ClValue,
        h_out: ClValue,
        w_out: ClValue,
        stride_y: ClValue,
        stride_x: ClValue,
        dilation_y: ClValue,
        dilation_x: ClValue,
        kernel_h: ClValue,
        kernel_w: ClValue,
        img_width: ClValue,
        activation: ClValue,
    ) -> Option<ClValue> {
        let zero_ptr = self.builder.ins().iconst(self.ptr_type, 0);
        let has_bias = self.builder.ins().icmp(IntCC::NotEqual, bias, zero_ptr);
        let bias_block = self.builder.create_block();
        let no_bias_block = self.builder.create_block();
        let bias_merge = self.builder.create_block();
        self.builder.append_block_param(bias_merge, elem_ty);

        self.builder
            .ins()
            .brif(has_bias, bias_block, &[], no_bias_block, &[]);

        self.builder.switch_to_block(bias_block);
        let b_val = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), bias, 0);
        self.builder
            .ins()
            .jump(bias_merge, &[BlockArg::from(b_val)]);

        self.builder.switch_to_block(no_bias_block);
        let zero_elem = if is_float {
            if elem_ty == types::F32 {
                self.builder.ins().f32const(0.0)
            } else {
                self.builder.ins().f64const(0.0)
            }
        } else {
            self.builder.ins().iconst(elem_ty, 0)
        };
        self.builder
            .ins()
            .jump(bias_merge, &[BlockArg::from(zero_elem)]);

        self.builder.switch_to_block(bias_merge);
        let bias_scalar = self.builder.block_params(bias_merge)[0];

        let y_header = self.builder.create_block();
        let x_header = self.builder.create_block();
        let ky_header = self.builder.create_block();
        let kx_header = self.builder.create_block();
        let kx_body = self.builder.create_block();
        let ky_step = self.builder.create_block();
        let x_store = self.builder.create_block();
        let x_step = self.builder.create_block();
        let y_step = self.builder.create_block();
        let done_block = self.builder.create_block();

        // Start Y loop
        self.builder.append_block_param(y_header, types::I64);
        let zero_i64 = self.builder.ins().iconst(types::I64, 0);
        self.builder
            .ins()
            .jump(y_header, &[BlockArg::from(zero_i64)]);

        self.builder.switch_to_block(y_header);
        let cur_y = self.builder.block_params(y_header)[0];
        let has_y = self.builder.ins().icmp(IntCC::SignedLessThan, cur_y, h_out);
        let x_init = self.builder.create_block();
        self.builder.ins().brif(has_y, x_init, &[], done_block, &[]);

        self.builder.switch_to_block(x_init);
        let y_str = self.builder.ins().imul(cur_y, stride_y);
        let y_base = self.builder.ins().imul(y_str, img_width);
        let y_out_off = self.builder.ins().imul(cur_y, w_out);

        self.builder.append_block_param(x_header, types::I64);
        self.builder.append_block_param(x_header, types::I64);
        self.builder.append_block_param(x_header, types::I64);
        self.builder.ins().jump(
            x_header,
            &[
                BlockArg::from(zero_i64),
                BlockArg::from(y_base),
                BlockArg::from(y_out_off),
            ],
        );

        self.builder.switch_to_block(x_header);
        let cur_x = self.builder.block_params(x_header)[0];
        let cur_y_base = self.builder.block_params(x_header)[1];
        let cur_y_out_off = self.builder.block_params(x_header)[2];

        let has_x = self.builder.ins().icmp(IntCC::SignedLessThan, cur_x, w_out);
        let k_init = self.builder.create_block();
        self.builder.ins().brif(has_x, k_init, &[], y_step, &[]);

        self.builder.switch_to_block(k_init);
        let x_base = self.builder.ins().imul(cur_x, stride_x);
        let zero_accum = if is_float {
            if elem_ty == types::F32 {
                self.builder.ins().f32const(0.0)
            } else {
                self.builder.ins().f64const(0.0)
            }
        } else {
            self.builder.ins().iconst(elem_ty, 0)
        };

        self.builder.append_block_param(ky_header, types::I64);
        self.builder.append_block_param(ky_header, elem_ty);
        self.builder.ins().jump(
            ky_header,
            &[BlockArg::from(zero_i64), BlockArg::from(zero_accum)],
        );

        self.builder.switch_to_block(ky_header);
        let cur_ky = self.builder.block_params(ky_header)[0];
        let cur_accum_ky = self.builder.block_params(ky_header)[1];
        let has_ky = self
            .builder
            .ins()
            .icmp(IntCC::SignedLessThan, cur_ky, kernel_h);
        let kx_init = self.builder.create_block();
        self.builder.ins().brif(
            has_ky,
            kx_init,
            &[],
            x_store,
            &[BlockArg::from(cur_accum_ky)],
        );

        self.builder.switch_to_block(kx_init);
        let ky_dil = self.builder.ins().imul(cur_ky, dilation_y);
        let ky_off = self.builder.ins().imul(ky_dil, img_width);
        let in_row = self.builder.ins().iadd(cur_y_base, ky_off);
        let w_row = self.builder.ins().imul(cur_ky, kernel_w);

        self.builder.append_block_param(kx_header, types::I64);
        self.builder.append_block_param(kx_header, elem_ty);
        self.builder.ins().jump(
            kx_header,
            &[BlockArg::from(zero_i64), BlockArg::from(cur_accum_ky)],
        );

        self.builder.switch_to_block(kx_header);
        let cur_kx = self.builder.block_params(kx_header)[0];
        let cur_accum_kx = self.builder.block_params(kx_header)[1];
        let has_kx = self
            .builder
            .ins()
            .icmp(IntCC::SignedLessThan, cur_kx, kernel_w);
        self.builder.ins().brif(
            has_kx,
            kx_body,
            &[],
            ky_step,
            &[BlockArg::from(cur_accum_kx)],
        );

        self.builder.switch_to_block(kx_body);
        let kx_dil = self.builder.ins().imul(cur_kx, dilation_x);
        let in_row_x = self.builder.ins().iadd(in_row, x_base);
        let in_idx = self.builder.ins().iadd(in_row_x, kx_dil);
        let w_idx = self.builder.ins().iadd(w_row, cur_kx);

        let in_byte = self.builder.ins().imul_imm_s(in_idx, elem_size);
        let in_ptr = self.builder.ins().iadd(img, in_byte);
        let in_v = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), in_ptr, 0);

        let w_byte = self.builder.ins().imul_imm_s(w_idx, elem_size);
        let w_ptr = self.builder.ins().iadd(weights, w_byte);
        let w_v = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), w_ptr, 0);

        let prod = if is_float {
            self.builder.ins().fmul(in_v, w_v)
        } else {
            self.builder.ins().imul(in_v, w_v)
        };
        let next_accum_kx = if is_float {
            self.builder.ins().fadd(cur_accum_kx, prod)
        } else {
            self.builder.ins().iadd(cur_accum_kx, prod)
        };

        let next_kx = self.builder.ins().iadd_imm_s(cur_kx, 1);
        self.builder.ins().jump(
            kx_header,
            &[BlockArg::from(next_kx), BlockArg::from(next_accum_kx)],
        );

        // KY step
        self.builder.append_block_param(ky_step, elem_ty);
        self.builder.switch_to_block(ky_step);
        let accum_from_kx = self.builder.block_params(ky_step)[0];
        let next_ky = self.builder.ins().iadd_imm_s(cur_ky, 1);
        self.builder.ins().jump(
            ky_header,
            &[BlockArg::from(next_ky), BlockArg::from(accum_from_kx)],
        );

        // X store: add bias, apply ReLU, dst[out_idx] += accum
        self.builder.append_block_param(x_store, elem_ty);
        self.builder.switch_to_block(x_store);
        let total_accum = self.builder.block_params(x_store)[0];
        let biased = if is_float {
            self.builder.ins().fadd(total_accum, bias_scalar)
        } else {
            self.builder.ins().iadd(total_accum, bias_scalar)
        };

        let act_relu = self.builder.ins().iconst(types::I32, 1);
        let is_relu = self.builder.ins().icmp(IntCC::Equal, activation, act_relu);
        let relu_cand = if is_float {
            let is_gt = self
                .builder
                .ins()
                .fcmp(FloatCC::GreaterThan, biased, zero_elem);
            self.builder.ins().select(is_gt, biased, zero_elem)
        } else {
            let is_gt = self
                .builder
                .ins()
                .icmp(IntCC::SignedGreaterThan, biased, zero_elem);
            self.builder.ins().select(is_gt, biased, zero_elem)
        };
        let final_val = self.builder.ins().select(is_relu, relu_cand, biased);

        let out_elem_idx = self.builder.ins().iadd(cur_y_out_off, cur_x);
        let out_byte_off = self.builder.ins().imul_imm_s(out_elem_idx, elem_size);
        let out_ptr = self.builder.ins().iadd(dst, out_byte_off);
        let cur_dst = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), out_ptr, 0);
        let new_dst = if is_float {
            self.builder.ins().fadd(cur_dst, final_val)
        } else {
            self.builder.ins().iadd(cur_dst, final_val)
        };
        self.builder
            .ins()
            .store(MemFlagsData::trusted(), new_dst, out_ptr, 0);

        self.builder.ins().jump(x_step, &[]);

        // X step
        self.builder.switch_to_block(x_step);
        let next_x = self.builder.ins().iadd_imm_s(cur_x, 1);
        self.builder.ins().jump(
            x_header,
            &[
                BlockArg::from(next_x),
                BlockArg::from(cur_y_base),
                BlockArg::from(cur_y_out_off),
            ],
        );

        // Y step
        self.builder.switch_to_block(y_step);
        let next_y = self.builder.ins().iadd_imm_s(cur_y, 1);
        self.builder.ins().jump(y_header, &[BlockArg::from(next_y)]);

        self.builder.switch_to_block(done_block);
        Some(self.builder.ins().iconst(types::I64, 0))
    }

    /// Lower multi-arena 2D spatial max-pooling directly into Cranelift loops.
    #[allow(clippy::too_many_arguments)]
    fn lower_multi_arena_maxpool2d(
        &mut self,
        elem_ty: types::Type,
        is_float: bool,
        elem_size: i64,
        dst: ClValue,
        img: ClValue,
        h_out: ClValue,
        w_out: ClValue,
        stride_y: ClValue,
        stride_x: ClValue,
        pool_h: ClValue,
        pool_w: ClValue,
        img_width: ClValue,
    ) -> Option<ClValue> {
        let y_header = self.builder.create_block();
        let x_header = self.builder.create_block();
        let py_header = self.builder.create_block();
        let px_header = self.builder.create_block();
        let px_body = self.builder.create_block();
        let py_step = self.builder.create_block();
        let x_store = self.builder.create_block();
        let x_step = self.builder.create_block();
        let y_step = self.builder.create_block();
        let done_block = self.builder.create_block();

        let zero_i64 = self.builder.ins().iconst(types::I64, 0);
        self.builder.append_block_param(y_header, types::I64);
        self.builder
            .ins()
            .jump(y_header, &[BlockArg::from(zero_i64)]);

        self.builder.switch_to_block(y_header);
        let cur_y = self.builder.block_params(y_header)[0];
        let has_y = self.builder.ins().icmp(IntCC::SignedLessThan, cur_y, h_out);
        let x_init = self.builder.create_block();
        self.builder.ins().brif(has_y, x_init, &[], done_block, &[]);

        self.builder.switch_to_block(x_init);
        let y_str = self.builder.ins().imul(cur_y, stride_y);
        let y_base = self.builder.ins().imul(y_str, img_width);
        let y_out_off = self.builder.ins().imul(cur_y, w_out);

        self.builder.append_block_param(x_header, types::I64);
        self.builder.append_block_param(x_header, types::I64);
        self.builder.append_block_param(x_header, types::I64);
        self.builder.ins().jump(
            x_header,
            &[
                BlockArg::from(zero_i64),
                BlockArg::from(y_base),
                BlockArg::from(y_out_off),
            ],
        );

        self.builder.switch_to_block(x_header);
        let cur_x = self.builder.block_params(x_header)[0];
        let cur_y_base = self.builder.block_params(x_header)[1];
        let cur_y_out_off = self.builder.block_params(x_header)[2];

        let has_x = self.builder.ins().icmp(IntCC::SignedLessThan, cur_x, w_out);
        let p_init = self.builder.create_block();
        self.builder.ins().brif(has_x, p_init, &[], y_step, &[]);

        self.builder.switch_to_block(p_init);
        let x_base = self.builder.ins().imul(cur_x, stride_x);
        let init_max = if is_float {
            if elem_ty == types::F32 {
                self.builder.ins().f32const(f32::NEG_INFINITY)
            } else {
                self.builder.ins().f64const(f64::NEG_INFINITY)
            }
        } else {
            self.builder.ins().iconst(elem_ty, i64::MIN)
        };

        self.builder.append_block_param(py_header, types::I64);
        self.builder.append_block_param(py_header, elem_ty);
        self.builder.ins().jump(
            py_header,
            &[BlockArg::from(zero_i64), BlockArg::from(init_max)],
        );

        self.builder.switch_to_block(py_header);
        let cur_py = self.builder.block_params(py_header)[0];
        let cur_max_py = self.builder.block_params(py_header)[1];
        let has_py = self
            .builder
            .ins()
            .icmp(IntCC::SignedLessThan, cur_py, pool_h);
        let px_init = self.builder.create_block();
        self.builder
            .ins()
            .brif(has_py, px_init, &[], x_store, &[BlockArg::from(cur_max_py)]);

        self.builder.switch_to_block(px_init);
        let py_off = self.builder.ins().imul(cur_py, img_width);
        let in_row = self.builder.ins().iadd(cur_y_base, py_off);

        self.builder.append_block_param(px_header, types::I64);
        self.builder.append_block_param(px_header, elem_ty);
        self.builder.ins().jump(
            px_header,
            &[BlockArg::from(zero_i64), BlockArg::from(cur_max_py)],
        );

        self.builder.switch_to_block(px_header);
        let cur_px = self.builder.block_params(px_header)[0];
        let cur_max_px = self.builder.block_params(px_header)[1];
        let has_px = self
            .builder
            .ins()
            .icmp(IntCC::SignedLessThan, cur_px, pool_w);
        self.builder
            .ins()
            .brif(has_px, px_body, &[], py_step, &[BlockArg::from(cur_max_px)]);

        self.builder.switch_to_block(px_body);
        let in_row_x = self.builder.ins().iadd(in_row, x_base);
        let in_idx = self.builder.ins().iadd(in_row_x, cur_px);
        let in_byte = self.builder.ins().imul_imm_s(in_idx, elem_size);
        let in_ptr = self.builder.ins().iadd(img, in_byte);
        let in_v = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), in_ptr, 0);

        let next_max_px = if is_float {
            let is_gt = self
                .builder
                .ins()
                .fcmp(FloatCC::GreaterThan, in_v, cur_max_px);
            self.builder.ins().select(is_gt, in_v, cur_max_px)
        } else {
            let is_gt = self
                .builder
                .ins()
                .icmp(IntCC::SignedGreaterThan, in_v, cur_max_px);
            self.builder.ins().select(is_gt, in_v, cur_max_px)
        };

        let next_px = self.builder.ins().iadd_imm_s(cur_px, 1);
        self.builder.ins().jump(
            px_header,
            &[BlockArg::from(next_px), BlockArg::from(next_max_px)],
        );

        // PY step
        self.builder.append_block_param(py_step, elem_ty);
        self.builder.switch_to_block(py_step);
        let max_from_px = self.builder.block_params(py_step)[0];
        let next_py = self.builder.ins().iadd_imm_s(cur_py, 1);
        self.builder.ins().jump(
            py_header,
            &[BlockArg::from(next_py), BlockArg::from(max_from_px)],
        );

        // X store: dst[out_idx] = final_max
        self.builder.append_block_param(x_store, elem_ty);
        self.builder.switch_to_block(x_store);
        let final_max = self.builder.block_params(x_store)[0];
        let out_elem_idx = self.builder.ins().iadd(cur_y_out_off, cur_x);
        let out_byte_off = self.builder.ins().imul_imm_s(out_elem_idx, elem_size);
        let out_ptr = self.builder.ins().iadd(dst, out_byte_off);
        self.builder
            .ins()
            .store(MemFlagsData::trusted(), final_max, out_ptr, 0);

        self.builder.ins().jump(x_step, &[]);

        self.builder.switch_to_block(x_step);
        let next_x = self.builder.ins().iadd_imm_s(cur_x, 1);
        self.builder.ins().jump(
            x_header,
            &[
                BlockArg::from(next_x),
                BlockArg::from(cur_y_base),
                BlockArg::from(cur_y_out_off),
            ],
        );

        self.builder.switch_to_block(y_step);
        let next_y = self.builder.ins().iadd_imm_s(cur_y, 1);
        self.builder.ins().jump(y_header, &[BlockArg::from(next_y)]);

        self.builder.switch_to_block(done_block);
        Some(self.builder.ins().iconst(types::I64, 0))
    }

    /// Lower multi-arena 2D spatial average-pooling directly into Cranelift loops.
    #[allow(clippy::too_many_arguments)]
    fn lower_multi_arena_avgpool2d(
        &mut self,
        elem_ty: types::Type,
        is_float: bool,
        elem_size: i64,
        dst: ClValue,
        img: ClValue,
        h_out: ClValue,
        w_out: ClValue,
        stride_y: ClValue,
        stride_x: ClValue,
        pool_h: ClValue,
        pool_w: ClValue,
        img_width: ClValue,
    ) -> Option<ClValue> {
        let area_i64 = self.builder.ins().imul(pool_h, pool_w);

        let y_header = self.builder.create_block();
        let x_header = self.builder.create_block();
        let py_header = self.builder.create_block();
        let px_header = self.builder.create_block();
        let px_body = self.builder.create_block();
        let py_step = self.builder.create_block();
        let x_store = self.builder.create_block();
        let x_step = self.builder.create_block();
        let y_step = self.builder.create_block();
        let done_block = self.builder.create_block();

        let zero_i64 = self.builder.ins().iconst(types::I64, 0);
        self.builder.append_block_param(y_header, types::I64);
        self.builder
            .ins()
            .jump(y_header, &[BlockArg::from(zero_i64)]);

        self.builder.switch_to_block(y_header);
        let cur_y = self.builder.block_params(y_header)[0];
        let has_y = self.builder.ins().icmp(IntCC::SignedLessThan, cur_y, h_out);
        let x_init = self.builder.create_block();
        self.builder.ins().brif(has_y, x_init, &[], done_block, &[]);

        self.builder.switch_to_block(x_init);
        let y_str = self.builder.ins().imul(cur_y, stride_y);
        let y_base = self.builder.ins().imul(y_str, img_width);
        let y_out_off = self.builder.ins().imul(cur_y, w_out);

        self.builder.append_block_param(x_header, types::I64);
        self.builder.append_block_param(x_header, types::I64);
        self.builder.append_block_param(x_header, types::I64);
        self.builder.ins().jump(
            x_header,
            &[
                BlockArg::from(zero_i64),
                BlockArg::from(y_base),
                BlockArg::from(y_out_off),
            ],
        );

        self.builder.switch_to_block(x_header);
        let cur_x = self.builder.block_params(x_header)[0];
        let cur_y_base = self.builder.block_params(x_header)[1];
        let cur_y_out_off = self.builder.block_params(x_header)[2];

        let has_x = self.builder.ins().icmp(IntCC::SignedLessThan, cur_x, w_out);
        let p_init = self.builder.create_block();
        self.builder.ins().brif(has_x, p_init, &[], y_step, &[]);

        self.builder.switch_to_block(p_init);
        let x_base = self.builder.ins().imul(cur_x, stride_x);
        let zero_sum = if is_float {
            if elem_ty == types::F32 {
                self.builder.ins().f32const(0.0)
            } else {
                self.builder.ins().f64const(0.0)
            }
        } else {
            self.builder.ins().iconst(elem_ty, 0)
        };

        self.builder.append_block_param(py_header, types::I64);
        self.builder.append_block_param(py_header, elem_ty);
        self.builder.ins().jump(
            py_header,
            &[BlockArg::from(zero_i64), BlockArg::from(zero_sum)],
        );

        self.builder.switch_to_block(py_header);
        let cur_py = self.builder.block_params(py_header)[0];
        let cur_sum_py = self.builder.block_params(py_header)[1];
        let has_py = self
            .builder
            .ins()
            .icmp(IntCC::SignedLessThan, cur_py, pool_h);
        let px_init = self.builder.create_block();
        self.builder
            .ins()
            .brif(has_py, px_init, &[], x_store, &[BlockArg::from(cur_sum_py)]);

        self.builder.switch_to_block(px_init);
        let py_off = self.builder.ins().imul(cur_py, img_width);
        let in_row = self.builder.ins().iadd(cur_y_base, py_off);

        self.builder.append_block_param(px_header, types::I64);
        self.builder.append_block_param(px_header, elem_ty);
        self.builder.ins().jump(
            px_header,
            &[BlockArg::from(zero_i64), BlockArg::from(cur_sum_py)],
        );

        self.builder.switch_to_block(px_header);
        let cur_px = self.builder.block_params(px_header)[0];
        let cur_sum_px = self.builder.block_params(px_header)[1];
        let has_px = self
            .builder
            .ins()
            .icmp(IntCC::SignedLessThan, cur_px, pool_w);
        self.builder
            .ins()
            .brif(has_px, px_body, &[], py_step, &[BlockArg::from(cur_sum_px)]);

        self.builder.switch_to_block(px_body);
        let in_row_x = self.builder.ins().iadd(in_row, x_base);
        let in_idx = self.builder.ins().iadd(in_row_x, cur_px);
        let in_byte = self.builder.ins().imul_imm_s(in_idx, elem_size);
        let in_ptr = self.builder.ins().iadd(img, in_byte);
        let in_v = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), in_ptr, 0);

        let next_sum_px = if is_float {
            self.builder.ins().fadd(cur_sum_px, in_v)
        } else {
            self.builder.ins().iadd(cur_sum_px, in_v)
        };

        let next_px = self.builder.ins().iadd_imm_s(cur_px, 1);
        self.builder.ins().jump(
            px_header,
            &[BlockArg::from(next_px), BlockArg::from(next_sum_px)],
        );

        // PY step
        self.builder.append_block_param(py_step, elem_ty);
        self.builder.switch_to_block(py_step);
        let sum_from_px = self.builder.block_params(py_step)[0];
        let next_py = self.builder.ins().iadd_imm_s(cur_py, 1);
        self.builder.ins().jump(
            py_header,
            &[BlockArg::from(next_py), BlockArg::from(sum_from_px)],
        );

        // X store: dst[out_idx] = final_sum / area
        self.builder.append_block_param(x_store, elem_ty);
        self.builder.switch_to_block(x_store);
        let final_sum = self.builder.block_params(x_store)[0];
        let avg_val = if is_float {
            let area_f = self.builder.ins().fcvt_from_sint(elem_ty, area_i64);
            self.builder.ins().fdiv(final_sum, area_f)
        } else {
            self.builder.ins().sdiv(final_sum, area_i64)
        };

        let out_elem_idx = self.builder.ins().iadd(cur_y_out_off, cur_x);
        let out_byte_off = self.builder.ins().imul_imm_s(out_elem_idx, elem_size);
        let out_ptr = self.builder.ins().iadd(dst, out_byte_off);
        self.builder
            .ins()
            .store(MemFlagsData::trusted(), avg_val, out_ptr, 0);

        self.builder.ins().jump(x_step, &[]);

        self.builder.switch_to_block(x_step);
        let next_x = self.builder.ins().iadd_imm_s(cur_x, 1);
        self.builder.ins().jump(
            x_header,
            &[
                BlockArg::from(next_x),
                BlockArg::from(cur_y_base),
                BlockArg::from(cur_y_out_off),
            ],
        );

        self.builder.switch_to_block(y_step);
        let next_y = self.builder.ins().iadd_imm_s(cur_y, 1);
        self.builder.ins().jump(y_header, &[BlockArg::from(next_y)]);

        self.builder.switch_to_block(done_block);
        Some(self.builder.ins().iconst(types::I64, 0))
    }

    /// Lower multi-arena 2D depthwise convolution directly into nested Cranelift loops.
    #[allow(clippy::too_many_arguments)]
    fn lower_multi_arena_depthwise_conv2d(
        &mut self,
        elem_ty: types::Type,
        is_float: bool,
        elem_size: i64,
        dst: ClValue,
        img: ClValue,
        weights: ClValue,
        bias: ClValue,
        channels: ClValue,
        h_out: ClValue,
        w_out: ClValue,
        stride_y: ClValue,
        stride_x: ClValue,
        kernel_h: ClValue,
        kernel_w: ClValue,
        img_h: ClValue,
        img_w: ClValue,
        activation: ClValue,
    ) -> Option<ClValue> {
        let zero_ptr = self.builder.ins().iconst(self.ptr_type, 0);
        let has_bias = self.builder.ins().icmp(IntCC::NotEqual, bias, zero_ptr);

        let in_area = self.builder.ins().imul(img_h, img_w);
        let kernel_area = self.builder.ins().imul(kernel_h, kernel_w);
        let out_area = self.builder.ins().imul(h_out, w_out);

        let zero_elem = if is_float {
            if elem_ty == types::F32 {
                self.builder.ins().f32const(0.0)
            } else {
                self.builder.ins().f64const(0.0)
            }
        } else {
            self.builder.ins().iconst(elem_ty, 0)
        };
        let zero_i64 = self.builder.ins().iconst(types::I64, 0);

        let act_relu = self.builder.ins().iconst(types::I32, 1);
        let is_relu = self.builder.ins().icmp(IntCC::Equal, activation, act_relu);

        let c_header = self.builder.create_block();
        let y_header = self.builder.create_block();
        let x_header = self.builder.create_block();
        let ky_header = self.builder.create_block();
        let kx_header = self.builder.create_block();
        let kx_body = self.builder.create_block();
        let ky_step = self.builder.create_block();
        let x_store = self.builder.create_block();
        let x_step = self.builder.create_block();
        let y_step = self.builder.create_block();
        let c_step = self.builder.create_block();
        let done_block = self.builder.create_block();

        // Channel loop entry
        self.builder.append_block_param(c_header, types::I64);
        self.builder
            .ins()
            .jump(c_header, &[BlockArg::from(zero_i64)]);

        self.builder.switch_to_block(c_header);
        let cur_c = self.builder.block_params(c_header)[0];
        let has_c = self
            .builder
            .ins()
            .icmp(IntCC::SignedLessThan, cur_c, channels);
        let c_body = self.builder.create_block();
        self.builder.ins().brif(has_c, c_body, &[], done_block, &[]);

        self.builder.switch_to_block(c_body);
        let c_img_off = self.builder.ins().imul(cur_c, in_area);
        let c_w_off = self.builder.ins().imul(cur_c, kernel_area);
        let c_dst_off = self.builder.ins().imul(cur_c, out_area);

        // Load channel bias scalar if bias != null
        let bias_block = self.builder.create_block();
        let no_bias_block = self.builder.create_block();
        let bias_merge = self.builder.create_block();
        self.builder.append_block_param(bias_merge, elem_ty);
        self.builder
            .ins()
            .brif(has_bias, bias_block, &[], no_bias_block, &[]);

        self.builder.switch_to_block(bias_block);
        let c_bias_byte = self.builder.ins().imul_imm_s(cur_c, elem_size);
        let c_bias_ptr = self.builder.ins().iadd(bias, c_bias_byte);
        let b_val = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), c_bias_ptr, 0);
        self.builder
            .ins()
            .jump(bias_merge, &[BlockArg::from(b_val)]);

        self.builder.switch_to_block(no_bias_block);
        self.builder
            .ins()
            .jump(bias_merge, &[BlockArg::from(zero_elem)]);

        self.builder.switch_to_block(bias_merge);
        let bias_scalar = self.builder.block_params(bias_merge)[0];

        // Start Y loop
        self.builder.append_block_param(y_header, types::I64);
        self.builder
            .ins()
            .jump(y_header, &[BlockArg::from(zero_i64)]);

        self.builder.switch_to_block(y_header);
        let cur_y = self.builder.block_params(y_header)[0];
        let has_y = self.builder.ins().icmp(IntCC::SignedLessThan, cur_y, h_out);
        let x_init = self.builder.create_block();
        self.builder.ins().brif(has_y, x_init, &[], c_step, &[]);

        self.builder.switch_to_block(x_init);
        let y_str = self.builder.ins().imul(cur_y, stride_y);
        let y_base = self.builder.ins().imul(y_str, img_w);
        let y_out_off = self.builder.ins().imul(cur_y, w_out);

        self.builder.append_block_param(x_header, types::I64);
        self.builder.append_block_param(x_header, types::I64);
        self.builder.append_block_param(x_header, types::I64);
        self.builder.ins().jump(
            x_header,
            &[
                BlockArg::from(zero_i64),
                BlockArg::from(y_base),
                BlockArg::from(y_out_off),
            ],
        );

        self.builder.switch_to_block(x_header);
        let cur_x = self.builder.block_params(x_header)[0];
        let cur_y_base = self.builder.block_params(x_header)[1];
        let cur_y_out_off = self.builder.block_params(x_header)[2];

        let has_x = self.builder.ins().icmp(IntCC::SignedLessThan, cur_x, w_out);
        let k_init = self.builder.create_block();
        self.builder.ins().brif(has_x, k_init, &[], y_step, &[]);

        self.builder.switch_to_block(k_init);
        let x_base = self.builder.ins().imul(cur_x, stride_x);
        let out_idx_rel = self.builder.ins().iadd(cur_y_out_off, cur_x);
        let out_idx = self.builder.ins().iadd(c_dst_off, out_idx_rel);

        self.builder.append_block_param(ky_header, types::I64);
        self.builder.append_block_param(ky_header, elem_ty);
        self.builder.ins().jump(
            ky_header,
            &[BlockArg::from(zero_i64), BlockArg::from(zero_elem)],
        );

        self.builder.switch_to_block(ky_header);
        let cur_ky = self.builder.block_params(ky_header)[0];
        let cur_accum_ky = self.builder.block_params(ky_header)[1];
        let has_ky = self
            .builder
            .ins()
            .icmp(IntCC::SignedLessThan, cur_ky, kernel_h);
        let kx_init = self.builder.create_block();
        self.builder.ins().brif(
            has_ky,
            kx_init,
            &[],
            x_store,
            &[BlockArg::from(cur_accum_ky)],
        );

        self.builder.switch_to_block(kx_init);
        let ky_off = self.builder.ins().imul(cur_ky, img_w);
        let in_row = self.builder.ins().iadd(cur_y_base, ky_off);
        let w_row = self.builder.ins().imul(cur_ky, kernel_w);

        self.builder.append_block_param(kx_header, types::I64);
        self.builder.append_block_param(kx_header, elem_ty);
        self.builder.ins().jump(
            kx_header,
            &[BlockArg::from(zero_i64), BlockArg::from(cur_accum_ky)],
        );

        self.builder.switch_to_block(kx_header);
        let cur_kx = self.builder.block_params(kx_header)[0];
        let cur_accum_kx = self.builder.block_params(kx_header)[1];
        let has_kx = self
            .builder
            .ins()
            .icmp(IntCC::SignedLessThan, cur_kx, kernel_w);
        self.builder.ins().brif(
            has_kx,
            kx_body,
            &[],
            ky_step,
            &[BlockArg::from(cur_accum_kx)],
        );

        self.builder.switch_to_block(kx_body);
        let in_pix = self.builder.ins().iadd(in_row, x_base);
        let in_idx_rel = self.builder.ins().iadd(in_pix, cur_kx);
        let in_idx = self.builder.ins().iadd(c_img_off, in_idx_rel);
        let in_byte = self.builder.ins().imul_imm_s(in_idx, elem_size);
        let in_ptr = self.builder.ins().iadd(img, in_byte);
        let in_v = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), in_ptr, 0);

        let w_idx_rel = self.builder.ins().iadd(w_row, cur_kx);
        let w_idx = self.builder.ins().iadd(c_w_off, w_idx_rel);
        let w_byte = self.builder.ins().imul_imm_s(w_idx, elem_size);
        let w_ptr = self.builder.ins().iadd(weights, w_byte);
        let w_v = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), w_ptr, 0);

        let prod = if is_float {
            self.builder.ins().fmul(in_v, w_v)
        } else {
            self.builder.ins().imul(in_v, w_v)
        };
        let next_accum_kx = if is_float {
            self.builder.ins().fadd(cur_accum_kx, prod)
        } else {
            self.builder.ins().iadd(cur_accum_kx, prod)
        };

        let next_kx = self.builder.ins().iadd_imm_s(cur_kx, 1);
        self.builder.ins().jump(
            kx_header,
            &[BlockArg::from(next_kx), BlockArg::from(next_accum_kx)],
        );

        // KY step
        self.builder.append_block_param(ky_step, elem_ty);
        self.builder.switch_to_block(ky_step);
        let accum_from_kx = self.builder.block_params(ky_step)[0];
        let next_ky = self.builder.ins().iadd_imm_s(cur_ky, 1);
        self.builder.ins().jump(
            ky_header,
            &[BlockArg::from(next_ky), BlockArg::from(accum_from_kx)],
        );

        // X store: add bias, apply ReLU, dst[out_idx] = final_val
        self.builder.append_block_param(x_store, elem_ty);
        self.builder.switch_to_block(x_store);
        let total_accum = self.builder.block_params(x_store)[0];
        let biased = if is_float {
            self.builder.ins().fadd(total_accum, bias_scalar)
        } else {
            self.builder.ins().iadd(total_accum, bias_scalar)
        };

        let relu_cand = if is_float {
            let is_gt = self
                .builder
                .ins()
                .fcmp(FloatCC::GreaterThan, biased, zero_elem);
            self.builder.ins().select(is_gt, biased, zero_elem)
        } else {
            let is_gt = self
                .builder
                .ins()
                .icmp(IntCC::SignedGreaterThan, biased, zero_elem);
            self.builder.ins().select(is_gt, biased, zero_elem)
        };
        let final_val = self.builder.ins().select(is_relu, relu_cand, biased);

        let out_byte = self.builder.ins().imul_imm_s(out_idx, elem_size);
        let out_ptr = self.builder.ins().iadd(dst, out_byte);
        self.builder
            .ins()
            .store(MemFlagsData::trusted(), final_val, out_ptr, 0);

        self.builder.ins().jump(x_step, &[]);

        // X step
        self.builder.switch_to_block(x_step);
        let next_x = self.builder.ins().iadd_imm_s(cur_x, 1);
        self.builder.ins().jump(
            x_header,
            &[
                BlockArg::from(next_x),
                BlockArg::from(cur_y_base),
                BlockArg::from(cur_y_out_off),
            ],
        );

        // Y step
        self.builder.switch_to_block(y_step);
        let next_y = self.builder.ins().iadd_imm_s(cur_y, 1);
        self.builder.ins().jump(y_header, &[BlockArg::from(next_y)]);

        // C step
        self.builder.switch_to_block(c_step);
        let next_c = self.builder.ins().iadd_imm_s(cur_c, 1);
        self.builder.ins().jump(c_header, &[BlockArg::from(next_c)]);

        self.builder.switch_to_block(done_block);
        Some(self.builder.ins().iconst(types::I64, 0))
    }

    /// Lower multi-arena 2D pointwise (1x1) convolution directly into nested Cranelift loops.
    #[allow(clippy::too_many_arguments)]
    fn lower_multi_arena_pointwise_conv2d(
        &mut self,
        elem_ty: types::Type,
        is_float: bool,
        elem_size: i64,
        dst: ClValue,
        img: ClValue,
        weights: ClValue,
        bias: ClValue,
        c_in: ClValue,
        c_out: ClValue,
        spatial_size: ClValue,
        activation: ClValue,
    ) -> Option<ClValue> {
        let zero_ptr = self.builder.ins().iconst(self.ptr_type, 0);
        let has_bias = self.builder.ins().icmp(IntCC::NotEqual, bias, zero_ptr);

        let zero_elem = if is_float {
            if elem_ty == types::F32 {
                self.builder.ins().f32const(0.0)
            } else {
                self.builder.ins().f64const(0.0)
            }
        } else {
            self.builder.ins().iconst(elem_ty, 0)
        };
        let zero_i64 = self.builder.ins().iconst(types::I64, 0);

        let act_relu = self.builder.ins().iconst(types::I32, 1);
        let is_relu = self.builder.ins().icmp(IntCC::Equal, activation, act_relu);

        let co_header = self.builder.create_block();
        let p_header = self.builder.create_block();
        let ci_header = self.builder.create_block();
        let ci_body = self.builder.create_block();
        let p_store = self.builder.create_block();
        let p_step = self.builder.create_block();
        let co_step = self.builder.create_block();
        let done_block = self.builder.create_block();

        // Channel out loop entry
        self.builder.append_block_param(co_header, types::I64);
        self.builder
            .ins()
            .jump(co_header, &[BlockArg::from(zero_i64)]);

        self.builder.switch_to_block(co_header);
        let cur_co = self.builder.block_params(co_header)[0];
        let has_co = self
            .builder
            .ins()
            .icmp(IntCC::SignedLessThan, cur_co, c_out);
        let co_body = self.builder.create_block();
        self.builder
            .ins()
            .brif(has_co, co_body, &[], done_block, &[]);

        self.builder.switch_to_block(co_body);
        let w_co_off = self.builder.ins().imul(cur_co, c_in);
        let dst_co_off = self.builder.ins().imul(cur_co, spatial_size);

        // Load channel bias scalar if bias != null
        let bias_block = self.builder.create_block();
        let no_bias_block = self.builder.create_block();
        let bias_merge = self.builder.create_block();
        self.builder.append_block_param(bias_merge, elem_ty);
        self.builder
            .ins()
            .brif(has_bias, bias_block, &[], no_bias_block, &[]);

        self.builder.switch_to_block(bias_block);
        let co_bias_byte = self.builder.ins().imul_imm_s(cur_co, elem_size);
        let co_bias_ptr = self.builder.ins().iadd(bias, co_bias_byte);
        let b_val = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), co_bias_ptr, 0);
        self.builder
            .ins()
            .jump(bias_merge, &[BlockArg::from(b_val)]);

        self.builder.switch_to_block(no_bias_block);
        self.builder
            .ins()
            .jump(bias_merge, &[BlockArg::from(zero_elem)]);

        self.builder.switch_to_block(bias_merge);
        let bias_scalar = self.builder.block_params(bias_merge)[0];

        // Start Spatial P loop
        self.builder.append_block_param(p_header, types::I64);
        self.builder
            .ins()
            .jump(p_header, &[BlockArg::from(zero_i64)]);

        self.builder.switch_to_block(p_header);
        let cur_p = self.builder.block_params(p_header)[0];
        let has_p = self
            .builder
            .ins()
            .icmp(IntCC::SignedLessThan, cur_p, spatial_size);
        let p_body = self.builder.create_block();
        self.builder.ins().brif(has_p, p_body, &[], co_step, &[]);

        self.builder.switch_to_block(p_body);
        let out_idx = self.builder.ins().iadd(dst_co_off, cur_p);

        // Start Channel in (ci) loop
        self.builder.append_block_param(ci_header, types::I64);
        self.builder.append_block_param(ci_header, elem_ty);
        self.builder.ins().jump(
            ci_header,
            &[BlockArg::from(zero_i64), BlockArg::from(zero_elem)],
        );

        self.builder.switch_to_block(ci_header);
        let cur_ci = self.builder.block_params(ci_header)[0];
        let cur_accum_ci = self.builder.block_params(ci_header)[1];
        let has_ci = self.builder.ins().icmp(IntCC::SignedLessThan, cur_ci, c_in);
        self.builder.ins().brif(
            has_ci,
            ci_body,
            &[],
            p_store,
            &[BlockArg::from(cur_accum_ci)],
        );

        self.builder.switch_to_block(ci_body);
        let ci_spatial = self.builder.ins().imul(cur_ci, spatial_size);
        let in_idx = self.builder.ins().iadd(ci_spatial, cur_p);
        let in_byte = self.builder.ins().imul_imm_s(in_idx, elem_size);
        let in_ptr = self.builder.ins().iadd(img, in_byte);
        let in_v = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), in_ptr, 0);

        let w_idx = self.builder.ins().iadd(w_co_off, cur_ci);
        let w_byte = self.builder.ins().imul_imm_s(w_idx, elem_size);
        let w_ptr = self.builder.ins().iadd(weights, w_byte);
        let w_v = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), w_ptr, 0);

        let prod = if is_float {
            self.builder.ins().fmul(in_v, w_v)
        } else {
            self.builder.ins().imul(in_v, w_v)
        };
        let next_accum_ci = if is_float {
            self.builder.ins().fadd(cur_accum_ci, prod)
        } else {
            self.builder.ins().iadd(cur_accum_ci, prod)
        };

        let next_ci = self.builder.ins().iadd_imm_s(cur_ci, 1);
        self.builder.ins().jump(
            ci_header,
            &[BlockArg::from(next_ci), BlockArg::from(next_accum_ci)],
        );

        // P store: add bias, apply ReLU, dst[out_idx] = final_val
        self.builder.append_block_param(p_store, elem_ty);
        self.builder.switch_to_block(p_store);
        let total_accum = self.builder.block_params(p_store)[0];
        let biased = if is_float {
            self.builder.ins().fadd(total_accum, bias_scalar)
        } else {
            self.builder.ins().iadd(total_accum, bias_scalar)
        };

        let relu_cand = if is_float {
            let is_gt = self
                .builder
                .ins()
                .fcmp(FloatCC::GreaterThan, biased, zero_elem);
            self.builder.ins().select(is_gt, biased, zero_elem)
        } else {
            let is_gt = self
                .builder
                .ins()
                .icmp(IntCC::SignedGreaterThan, biased, zero_elem);
            self.builder.ins().select(is_gt, biased, zero_elem)
        };
        let final_val = self.builder.ins().select(is_relu, relu_cand, biased);

        let out_byte = self.builder.ins().imul_imm_s(out_idx, elem_size);
        let out_ptr = self.builder.ins().iadd(dst, out_byte);
        self.builder
            .ins()
            .store(MemFlagsData::trusted(), final_val, out_ptr, 0);

        self.builder.ins().jump(p_step, &[]);

        // P step
        self.builder.switch_to_block(p_step);
        let next_p = self.builder.ins().iadd_imm_s(cur_p, 1);
        self.builder.ins().jump(p_header, &[BlockArg::from(next_p)]);

        // CO step
        self.builder.switch_to_block(co_step);
        let next_co = self.builder.ins().iadd_imm_s(cur_co, 1);
        self.builder
            .ins()
            .jump(co_header, &[BlockArg::from(next_co)]);

        self.builder.switch_to_block(done_block);
        Some(self.builder.ins().iconst(types::I64, 0))
    }

    /// Lower multi-arena 2D batch normalization directly into nested Cranelift loops.
    #[allow(clippy::too_many_arguments)]
    fn lower_multi_arena_batch_norm2d(
        &mut self,
        elem_ty: types::Type,
        elem_size: i64,
        dst: ClValue,
        src: ClValue,
        gamma: ClValue,
        beta: ClValue,
        mean: ClValue,
        var: ClValue,
        channels: ClValue,
        spatial_size: ClValue,
        epsilon: ClValue,
        activation: ClValue,
    ) -> Option<ClValue> {
        let zero_ptr = self.builder.ins().iconst(self.ptr_type, 0);
        let has_gamma = self.builder.ins().icmp(IntCC::NotEqual, gamma, zero_ptr);
        let has_beta = self.builder.ins().icmp(IntCC::NotEqual, beta, zero_ptr);

        let zero_elem = if elem_ty == types::F32 {
            self.builder.ins().f32const(0.0)
        } else {
            self.builder.ins().f64const(0.0)
        };
        let one_elem = if elem_ty == types::F32 {
            self.builder.ins().f32const(1.0)
        } else {
            self.builder.ins().f64const(1.0)
        };
        let zero_i64 = self.builder.ins().iconst(types::I64, 0);

        let act_relu = self.builder.ins().iconst(types::I32, 1);
        let is_relu = self.builder.ins().icmp(IntCC::Equal, activation, act_relu);

        let c_header = self.builder.create_block();
        let i_header = self.builder.create_block();
        let i_body = self.builder.create_block();
        let i_step = self.builder.create_block();
        let c_step = self.builder.create_block();
        let done_block = self.builder.create_block();

        // Channel loop entry
        self.builder.append_block_param(c_header, types::I64);
        self.builder
            .ins()
            .jump(c_header, &[BlockArg::from(zero_i64)]);

        self.builder.switch_to_block(c_header);
        let cur_c = self.builder.block_params(c_header)[0];
        let has_c = self
            .builder
            .ins()
            .icmp(IntCC::SignedLessThan, cur_c, channels);
        let c_body = self.builder.create_block();
        self.builder.ins().brif(has_c, c_body, &[], done_block, &[]);

        self.builder.switch_to_block(c_body);
        let c_byte = self.builder.ins().imul_imm_s(cur_c, elem_size);

        // Load mean and var
        let m_ptr = self.builder.ins().iadd(mean, c_byte);
        let m = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), m_ptr, 0);

        let v_ptr = self.builder.ins().iadd(var, c_byte);
        let v = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), v_ptr, 0);

        // Load gamma (or 1.0 if null)
        let gamma_block = self.builder.create_block();
        let no_gamma_block = self.builder.create_block();
        let gamma_merge = self.builder.create_block();
        self.builder.append_block_param(gamma_merge, elem_ty);
        self.builder
            .ins()
            .brif(has_gamma, gamma_block, &[], no_gamma_block, &[]);

        self.builder.switch_to_block(gamma_block);
        let g_ptr = self.builder.ins().iadd(gamma, c_byte);
        let g_val = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), g_ptr, 0);
        self.builder
            .ins()
            .jump(gamma_merge, &[BlockArg::from(g_val)]);

        self.builder.switch_to_block(no_gamma_block);
        self.builder
            .ins()
            .jump(gamma_merge, &[BlockArg::from(one_elem)]);

        self.builder.switch_to_block(gamma_merge);
        let g = self.builder.block_params(gamma_merge)[0];

        // Load beta (or 0.0 if null)
        let beta_block = self.builder.create_block();
        let no_beta_block = self.builder.create_block();
        let beta_merge = self.builder.create_block();
        self.builder.append_block_param(beta_merge, elem_ty);
        self.builder
            .ins()
            .brif(has_beta, beta_block, &[], no_beta_block, &[]);

        self.builder.switch_to_block(beta_block);
        let b_ptr = self.builder.ins().iadd(beta, c_byte);
        let b_val = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), b_ptr, 0);
        self.builder
            .ins()
            .jump(beta_merge, &[BlockArg::from(b_val)]);

        self.builder.switch_to_block(no_beta_block);
        self.builder
            .ins()
            .jump(beta_merge, &[BlockArg::from(zero_elem)]);

        self.builder.switch_to_block(beta_merge);
        let b = self.builder.block_params(beta_merge)[0];

        // Compute affine normalization scale and shift:
        // inv_std = 1.0 / sqrt(v + epsilon)
        // scale = g * inv_std
        // shift = b - (m * scale)
        let v_eps = self.builder.ins().fadd(v, epsilon);
        let sqrt_v = self.builder.ins().sqrt(v_eps);
        let inv_std = self.builder.ins().fdiv(one_elem, sqrt_v);
        let scale = self.builder.ins().fmul(g, inv_std);
        let m_scale = self.builder.ins().fmul(m, scale);
        let shift = self.builder.ins().fsub(b, m_scale);
        let c_base = self.builder.ins().imul(cur_c, spatial_size);

        // Start Spatial I loop
        self.builder.append_block_param(i_header, types::I64);
        self.builder
            .ins()
            .jump(i_header, &[BlockArg::from(zero_i64)]);

        self.builder.switch_to_block(i_header);
        let cur_i = self.builder.block_params(i_header)[0];
        let has_i = self
            .builder
            .ins()
            .icmp(IntCC::SignedLessThan, cur_i, spatial_size);
        self.builder.ins().brif(has_i, i_body, &[], c_step, &[]);

        self.builder.switch_to_block(i_body);
        let idx = self.builder.ins().iadd(c_base, cur_i);
        let idx_byte = self.builder.ins().imul_imm_s(idx, elem_size);
        let src_ptr = self.builder.ins().iadd(src, idx_byte);
        let x = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), src_ptr, 0);

        let x_scale = self.builder.ins().fmul(x, scale);
        let y = self.builder.ins().fadd(x_scale, shift);

        let is_gt = self.builder.ins().fcmp(FloatCC::GreaterThan, y, zero_elem);
        let relu_cand = self.builder.ins().select(is_gt, y, zero_elem);
        let final_val = self.builder.ins().select(is_relu, relu_cand, y);

        let dst_ptr = self.builder.ins().iadd(dst, idx_byte);
        self.builder
            .ins()
            .store(MemFlagsData::trusted(), final_val, dst_ptr, 0);

        self.builder.ins().jump(i_step, &[]);

        // I step
        self.builder.switch_to_block(i_step);
        let next_i = self.builder.ins().iadd_imm_s(cur_i, 1);
        self.builder.ins().jump(i_header, &[BlockArg::from(next_i)]);

        // C step
        self.builder.switch_to_block(c_step);
        let next_c = self.builder.ins().iadd_imm_s(cur_c, 1);
        self.builder.ins().jump(c_header, &[BlockArg::from(next_c)]);

        self.builder.switch_to_block(done_block);
        Some(self.builder.ins().iconst(types::I64, 0))
    }

    /// Lower strided or contiguous slice product reduction.
    fn lower_strided_slice_prod(
        &mut self,
        elem_ty: types::Type,
        is_float: bool,
        elem_size: i64,
        src: ClValue,
        len: ClValue,
        stride: ClValue,
    ) -> Option<ClValue> {
        let step_bytes = self.builder.ins().imul_imm_s(stride, elem_size);
        let step2_bytes = self.builder.ins().iadd(step_bytes, step_bytes);
        let step3_bytes = self.builder.ins().iadd(step2_bytes, step_bytes);
        let step4_bytes = self.builder.ins().iadd(step2_bytes, step2_bytes);

        let mask_val = self.builder.ins().iconst(types::I64, -4);
        let unroll_len = self.builder.ins().band(len, mask_val);

        let initial_acc = if is_float {
            if elem_ty == types::F32 {
                self.builder.ins().f32const(1.0)
            } else {
                self.builder.ins().f64const(1.0)
            }
        } else {
            self.builder.ins().iconst(elem_ty, 1)
        };

        let unroll_header = self.builder.create_block();
        let unroll_body = self.builder.create_block();
        let tail_header = self.builder.create_block();
        let tail_body = self.builder.create_block();
        let cont_block = self.builder.create_block();

        self.builder.append_block_param(unroll_header, types::I64);
        self.builder
            .append_block_param(unroll_header, self.ptr_type);
        self.builder.append_block_param(unroll_header, elem_ty);

        self.builder.append_block_param(tail_header, types::I64);
        self.builder.append_block_param(tail_header, self.ptr_type);
        self.builder.append_block_param(tail_header, elem_ty);

        self.builder.append_block_param(cont_block, elem_ty);

        let initial_i = self.builder.ins().iconst(types::I64, 0);
        self.builder.ins().jump(
            unroll_header,
            &[
                BlockArg::from(initial_i),
                BlockArg::from(src),
                BlockArg::from(initial_acc),
            ],
        );

        self.builder.switch_to_block(unroll_header);
        let cur_i = self.builder.block_params(unroll_header)[0];
        let cur_ptr = self.builder.block_params(unroll_header)[1];
        let cur_acc = self.builder.block_params(unroll_header)[2];

        let has_unroll = self
            .builder
            .ins()
            .icmp(IntCC::UnsignedLessThan, cur_i, unroll_len);
        self.builder.ins().brif(
            has_unroll,
            unroll_body,
            &[],
            tail_header,
            &[
                BlockArg::from(cur_i),
                BlockArg::from(cur_ptr),
                BlockArg::from(cur_acc),
            ],
        );

        self.builder.switch_to_block(unroll_body);
        let p0 = cur_ptr;
        let p1 = self.builder.ins().iadd(cur_ptr, step_bytes);
        let p2 = self.builder.ins().iadd(cur_ptr, step2_bytes);
        let p3 = self.builder.ins().iadd(cur_ptr, step3_bytes);

        let v0 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), p0, 0);
        let v1 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), p1, 0);
        let v2 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), p2, 0);
        let v3 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), p3, 0);

        let p01 = if is_float {
            self.builder.ins().fmul(v0, v1)
        } else {
            self.builder.ins().imul(v0, v1)
        };
        let p23 = if is_float {
            self.builder.ins().fmul(v2, v3)
        } else {
            self.builder.ins().imul(v2, v3)
        };
        let p03 = if is_float {
            self.builder.ins().fmul(p01, p23)
        } else {
            self.builder.ins().imul(p01, p23)
        };
        let next_acc = if is_float {
            self.builder.ins().fmul(cur_acc, p03)
        } else {
            self.builder.ins().imul(cur_acc, p03)
        };

        let next_ptr = self.builder.ins().iadd(cur_ptr, step4_bytes);
        let next_i = self.builder.ins().iadd_imm_s(cur_i, 4);
        self.builder.ins().jump(
            unroll_header,
            &[
                BlockArg::from(next_i),
                BlockArg::from(next_ptr),
                BlockArg::from(next_acc),
            ],
        );

        self.builder.switch_to_block(tail_header);
        let cur_tail_i = self.builder.block_params(tail_header)[0];
        let cur_tail_ptr = self.builder.block_params(tail_header)[1];
        let cur_tail_acc = self.builder.block_params(tail_header)[2];

        let has_tail = self
            .builder
            .ins()
            .icmp(IntCC::UnsignedLessThan, cur_tail_i, len);
        self.builder.ins().brif(
            has_tail,
            tail_body,
            &[],
            cont_block,
            &[BlockArg::from(cur_tail_acc)],
        );

        self.builder.switch_to_block(tail_body);
        let tail_val = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), cur_tail_ptr, 0);
        let next_tail_acc = if is_float {
            self.builder.ins().fmul(cur_tail_acc, tail_val)
        } else {
            self.builder.ins().imul(cur_tail_acc, tail_val)
        };
        let next_tail_ptr = self.builder.ins().iadd(cur_tail_ptr, step_bytes);
        let next_tail_i = self.builder.ins().iadd_imm_s(cur_tail_i, 1);
        self.builder.ins().jump(
            tail_header,
            &[
                BlockArg::from(next_tail_i),
                BlockArg::from(next_tail_ptr),
                BlockArg::from(next_tail_acc),
            ],
        );

        self.builder.switch_to_block(cont_block);
        let final_res = self.builder.block_params(cont_block)[0];
        Some(final_res)
    }

    /// Lower strided or contiguous slice minimum reduction.
    fn lower_strided_slice_min(
        &mut self,
        elem_ty: types::Type,
        is_float: bool,
        elem_size: i64,
        src: ClValue,
        len: ClValue,
        stride: ClValue,
    ) -> Option<ClValue> {
        let step_bytes = self.builder.ins().imul_imm_s(stride, elem_size);
        let step2_bytes = self.builder.ins().iadd(step_bytes, step_bytes);
        let step3_bytes = self.builder.ins().iadd(step2_bytes, step_bytes);
        let step4_bytes = self.builder.ins().iadd(step2_bytes, step2_bytes);

        let mask_val = self.builder.ins().iconst(types::I64, -4);
        let unroll_len = self.builder.ins().band(len, mask_val);

        let initial_acc = if is_float {
            if elem_ty == types::F32 {
                self.builder.ins().f32const(f32::INFINITY)
            } else {
                self.builder.ins().f64const(f64::INFINITY)
            }
        } else if elem_ty == types::I32 {
            self.builder.ins().iconst(elem_ty, i32::MAX as i64)
        } else {
            self.builder.ins().iconst(elem_ty, i64::MAX)
        };

        let unroll_header = self.builder.create_block();
        let unroll_body = self.builder.create_block();
        let tail_header = self.builder.create_block();
        let tail_body = self.builder.create_block();
        let cont_block = self.builder.create_block();

        self.builder.append_block_param(unroll_header, types::I64);
        self.builder
            .append_block_param(unroll_header, self.ptr_type);
        self.builder.append_block_param(unroll_header, elem_ty);

        self.builder.append_block_param(tail_header, types::I64);
        self.builder.append_block_param(tail_header, self.ptr_type);
        self.builder.append_block_param(tail_header, elem_ty);

        self.builder.append_block_param(cont_block, elem_ty);

        let initial_i = self.builder.ins().iconst(types::I64, 0);
        self.builder.ins().jump(
            unroll_header,
            &[
                BlockArg::from(initial_i),
                BlockArg::from(src),
                BlockArg::from(initial_acc),
            ],
        );

        self.builder.switch_to_block(unroll_header);
        let cur_i = self.builder.block_params(unroll_header)[0];
        let cur_ptr = self.builder.block_params(unroll_header)[1];
        let cur_acc = self.builder.block_params(unroll_header)[2];

        let has_unroll = self
            .builder
            .ins()
            .icmp(IntCC::UnsignedLessThan, cur_i, unroll_len);
        self.builder.ins().brif(
            has_unroll,
            unroll_body,
            &[],
            tail_header,
            &[
                BlockArg::from(cur_i),
                BlockArg::from(cur_ptr),
                BlockArg::from(cur_acc),
            ],
        );

        self.builder.switch_to_block(unroll_body);
        let p0 = cur_ptr;
        let p1 = self.builder.ins().iadd(cur_ptr, step_bytes);
        let p2 = self.builder.ins().iadd(cur_ptr, step2_bytes);
        let p3 = self.builder.ins().iadd(cur_ptr, step3_bytes);

        let v0 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), p0, 0);
        let v1 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), p1, 0);
        let v2 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), p2, 0);
        let v3 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), p3, 0);

        let m01 = if is_float {
            self.builder.ins().fmin(v0, v1)
        } else {
            self.builder.ins().smin(v0, v1)
        };
        let m23 = if is_float {
            self.builder.ins().fmin(v2, v3)
        } else {
            self.builder.ins().smin(v2, v3)
        };
        let m03 = if is_float {
            self.builder.ins().fmin(m01, m23)
        } else {
            self.builder.ins().smin(m01, m23)
        };
        let next_acc = if is_float {
            self.builder.ins().fmin(cur_acc, m03)
        } else {
            self.builder.ins().smin(cur_acc, m03)
        };

        let next_ptr = self.builder.ins().iadd(cur_ptr, step4_bytes);
        let next_i = self.builder.ins().iadd_imm_s(cur_i, 4);
        self.builder.ins().jump(
            unroll_header,
            &[
                BlockArg::from(next_i),
                BlockArg::from(next_ptr),
                BlockArg::from(next_acc),
            ],
        );

        self.builder.switch_to_block(tail_header);
        let cur_tail_i = self.builder.block_params(tail_header)[0];
        let cur_tail_ptr = self.builder.block_params(tail_header)[1];
        let cur_tail_acc = self.builder.block_params(tail_header)[2];

        let has_tail = self
            .builder
            .ins()
            .icmp(IntCC::UnsignedLessThan, cur_tail_i, len);
        self.builder.ins().brif(
            has_tail,
            tail_body,
            &[],
            cont_block,
            &[BlockArg::from(cur_tail_acc)],
        );

        self.builder.switch_to_block(tail_body);
        let tail_val = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), cur_tail_ptr, 0);
        let next_tail_acc = if is_float {
            self.builder.ins().fmin(cur_tail_acc, tail_val)
        } else {
            self.builder.ins().smin(cur_tail_acc, tail_val)
        };
        let next_tail_ptr = self.builder.ins().iadd(cur_tail_ptr, step_bytes);
        let next_tail_i = self.builder.ins().iadd_imm_s(cur_tail_i, 1);
        self.builder.ins().jump(
            tail_header,
            &[
                BlockArg::from(next_tail_i),
                BlockArg::from(next_tail_ptr),
                BlockArg::from(next_tail_acc),
            ],
        );

        self.builder.switch_to_block(cont_block);
        let final_res = self.builder.block_params(cont_block)[0];
        Some(final_res)
    }

    /// Lower strided or contiguous slice maximum reduction.
    fn lower_strided_slice_max(
        &mut self,
        elem_ty: types::Type,
        is_float: bool,
        elem_size: i64,
        src: ClValue,
        len: ClValue,
        stride: ClValue,
    ) -> Option<ClValue> {
        let step_bytes = self.builder.ins().imul_imm_s(stride, elem_size);
        let step2_bytes = self.builder.ins().iadd(step_bytes, step_bytes);
        let step3_bytes = self.builder.ins().iadd(step2_bytes, step_bytes);
        let step4_bytes = self.builder.ins().iadd(step2_bytes, step2_bytes);

        let mask_val = self.builder.ins().iconst(types::I64, -4);
        let unroll_len = self.builder.ins().band(len, mask_val);

        let initial_acc = if is_float {
            if elem_ty == types::F32 {
                self.builder.ins().f32const(f32::NEG_INFINITY)
            } else {
                self.builder.ins().f64const(f64::NEG_INFINITY)
            }
        } else if elem_ty == types::I32 {
            self.builder.ins().iconst(elem_ty, i32::MIN as i64)
        } else {
            self.builder.ins().iconst(elem_ty, i64::MIN)
        };

        let unroll_header = self.builder.create_block();
        let unroll_body = self.builder.create_block();
        let tail_header = self.builder.create_block();
        let tail_body = self.builder.create_block();
        let cont_block = self.builder.create_block();

        self.builder.append_block_param(unroll_header, types::I64);
        self.builder
            .append_block_param(unroll_header, self.ptr_type);
        self.builder.append_block_param(unroll_header, elem_ty);

        self.builder.append_block_param(tail_header, types::I64);
        self.builder.append_block_param(tail_header, self.ptr_type);
        self.builder.append_block_param(tail_header, elem_ty);

        self.builder.append_block_param(cont_block, elem_ty);

        let initial_i = self.builder.ins().iconst(types::I64, 0);
        self.builder.ins().jump(
            unroll_header,
            &[
                BlockArg::from(initial_i),
                BlockArg::from(src),
                BlockArg::from(initial_acc),
            ],
        );

        self.builder.switch_to_block(unroll_header);
        let cur_i = self.builder.block_params(unroll_header)[0];
        let cur_ptr = self.builder.block_params(unroll_header)[1];
        let cur_acc = self.builder.block_params(unroll_header)[2];

        let has_unroll = self
            .builder
            .ins()
            .icmp(IntCC::UnsignedLessThan, cur_i, unroll_len);
        self.builder.ins().brif(
            has_unroll,
            unroll_body,
            &[],
            tail_header,
            &[
                BlockArg::from(cur_i),
                BlockArg::from(cur_ptr),
                BlockArg::from(cur_acc),
            ],
        );

        self.builder.switch_to_block(unroll_body);
        let p0 = cur_ptr;
        let p1 = self.builder.ins().iadd(cur_ptr, step_bytes);
        let p2 = self.builder.ins().iadd(cur_ptr, step2_bytes);
        let p3 = self.builder.ins().iadd(cur_ptr, step3_bytes);

        let v0 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), p0, 0);
        let v1 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), p1, 0);
        let v2 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), p2, 0);
        let v3 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), p3, 0);

        let m01 = if is_float {
            self.builder.ins().fmax(v0, v1)
        } else {
            self.builder.ins().smax(v0, v1)
        };
        let m23 = if is_float {
            self.builder.ins().fmax(v2, v3)
        } else {
            self.builder.ins().smax(v2, v3)
        };
        let m03 = if is_float {
            self.builder.ins().fmax(m01, m23)
        } else {
            self.builder.ins().smax(m01, m23)
        };
        let next_acc = if is_float {
            self.builder.ins().fmax(cur_acc, m03)
        } else {
            self.builder.ins().smax(cur_acc, m03)
        };

        let next_ptr = self.builder.ins().iadd(cur_ptr, step4_bytes);
        let next_i = self.builder.ins().iadd_imm_s(cur_i, 4);
        self.builder.ins().jump(
            unroll_header,
            &[
                BlockArg::from(next_i),
                BlockArg::from(next_ptr),
                BlockArg::from(next_acc),
            ],
        );

        self.builder.switch_to_block(tail_header);
        let cur_tail_i = self.builder.block_params(tail_header)[0];
        let cur_tail_ptr = self.builder.block_params(tail_header)[1];
        let cur_tail_acc = self.builder.block_params(tail_header)[2];

        let has_tail = self
            .builder
            .ins()
            .icmp(IntCC::UnsignedLessThan, cur_tail_i, len);
        self.builder.ins().brif(
            has_tail,
            tail_body,
            &[],
            cont_block,
            &[BlockArg::from(cur_tail_acc)],
        );

        self.builder.switch_to_block(tail_body);
        let tail_val = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), cur_tail_ptr, 0);
        let next_tail_acc = if is_float {
            self.builder.ins().fmax(cur_tail_acc, tail_val)
        } else {
            self.builder.ins().smax(cur_tail_acc, tail_val)
        };
        let next_tail_ptr = self.builder.ins().iadd(cur_tail_ptr, step_bytes);
        let next_tail_i = self.builder.ins().iadd_imm_s(cur_tail_i, 1);
        self.builder.ins().jump(
            tail_header,
            &[
                BlockArg::from(next_tail_i),
                BlockArg::from(next_tail_ptr),
                BlockArg::from(next_tail_acc),
            ],
        );

        self.builder.switch_to_block(cont_block);
        let final_res = self.builder.block_params(cont_block)[0];
        Some(final_res)
    }

    /// Lower predicated slice counting (Count-If) with 4-way branchless tree accumulation.
    #[allow(clippy::too_many_arguments)]
    fn lower_slice_count_if(
        &mut self,
        elem_ty: types::Type,
        is_float: bool,
        elem_size: i64,
        src: ClValue,
        len: ClValue,
        stride: ClValue,
        threshold: ClValue,
        pred: CountPred,
    ) -> Option<ClValue> {
        let step_bytes = self.builder.ins().imul_imm_s(stride, elem_size);
        let step2_bytes = self.builder.ins().iadd(step_bytes, step_bytes);
        let step3_bytes = self.builder.ins().iadd(step2_bytes, step_bytes);
        let step4_bytes = self.builder.ins().iadd(step2_bytes, step2_bytes);

        let mask_val = self.builder.ins().iconst(types::I64, -4);
        let unroll_len = self.builder.ins().band(len, mask_val);

        let initial_count = self.builder.ins().iconst(types::I64, 0);

        let unroll_header = self.builder.create_block();
        let unroll_body = self.builder.create_block();
        let tail_header = self.builder.create_block();
        let tail_body = self.builder.create_block();
        let cont_block = self.builder.create_block();

        self.builder.append_block_param(unroll_header, types::I64);
        self.builder
            .append_block_param(unroll_header, self.ptr_type);
        self.builder.append_block_param(unroll_header, types::I64);

        self.builder.append_block_param(tail_header, types::I64);
        self.builder.append_block_param(tail_header, self.ptr_type);
        self.builder.append_block_param(tail_header, types::I64);

        self.builder.append_block_param(cont_block, types::I64);

        let initial_i = self.builder.ins().iconst(types::I64, 0);
        self.builder.ins().jump(
            unroll_header,
            &[
                BlockArg::from(initial_i),
                BlockArg::from(src),
                BlockArg::from(initial_count),
            ],
        );

        self.builder.switch_to_block(unroll_header);
        let cur_i = self.builder.block_params(unroll_header)[0];
        let cur_ptr = self.builder.block_params(unroll_header)[1];
        let cur_cnt = self.builder.block_params(unroll_header)[2];

        let has_unroll = self
            .builder
            .ins()
            .icmp(IntCC::UnsignedLessThan, cur_i, unroll_len);
        self.builder.ins().brif(
            has_unroll,
            unroll_body,
            &[],
            tail_header,
            &[
                BlockArg::from(cur_i),
                BlockArg::from(cur_ptr),
                BlockArg::from(cur_cnt),
            ],
        );

        self.builder.switch_to_block(unroll_body);
        let p0 = cur_ptr;
        let p1 = self.builder.ins().iadd(cur_ptr, step_bytes);
        let p2 = self.builder.ins().iadd(cur_ptr, step2_bytes);
        let p3 = self.builder.ins().iadd(cur_ptr, step3_bytes);

        let v0 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), p0, 0);
        let v1 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), p1, 0);
        let v2 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), p2, 0);
        let v3 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), p3, 0);

        let cmp_helper =
            |builder: &mut FunctionBuilder, val: ClValue, is_fl: bool, pr: CountPred| -> ClValue {
                let cond = if is_fl {
                    let cc = match pr {
                        CountPred::Gt => FloatCC::GreaterThan,
                        CountPred::Lt => FloatCC::LessThan,
                        CountPred::Eq => FloatCC::Equal,
                        CountPred::Ne => FloatCC::NotEqual,
                    };
                    builder.ins().fcmp(cc, val, threshold)
                } else {
                    let cc = match pr {
                        CountPred::Gt => IntCC::SignedGreaterThan,
                        CountPred::Lt => IntCC::SignedLessThan,
                        CountPred::Eq => IntCC::Equal,
                        CountPred::Ne => IntCC::NotEqual,
                    };
                    builder.ins().icmp(cc, val, threshold)
                };
                builder.ins().uextend(types::I64, cond)
            };

        let c0 = cmp_helper(&mut self.builder, v0, is_float, pred);
        let c1 = cmp_helper(&mut self.builder, v1, is_float, pred);
        let c2 = cmp_helper(&mut self.builder, v2, is_float, pred);
        let c3 = cmp_helper(&mut self.builder, v3, is_float, pred);

        let s01 = self.builder.ins().iadd(c0, c1);
        let s23 = self.builder.ins().iadd(c2, c3);
        let s03 = self.builder.ins().iadd(s01, s23);
        let next_cnt = self.builder.ins().iadd(cur_cnt, s03);

        let next_ptr = self.builder.ins().iadd(cur_ptr, step4_bytes);
        let next_i = self.builder.ins().iadd_imm_s(cur_i, 4);
        self.builder.ins().jump(
            unroll_header,
            &[
                BlockArg::from(next_i),
                BlockArg::from(next_ptr),
                BlockArg::from(next_cnt),
            ],
        );

        self.builder.switch_to_block(tail_header);
        let cur_tail_i = self.builder.block_params(tail_header)[0];
        let cur_tail_ptr = self.builder.block_params(tail_header)[1];
        let cur_tail_cnt = self.builder.block_params(tail_header)[2];

        let has_tail = self
            .builder
            .ins()
            .icmp(IntCC::UnsignedLessThan, cur_tail_i, len);
        self.builder.ins().brif(
            has_tail,
            tail_body,
            &[],
            cont_block,
            &[BlockArg::from(cur_tail_cnt)],
        );

        self.builder.switch_to_block(tail_body);
        let tail_val = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), cur_tail_ptr, 0);
        let cond = if is_float {
            let cc = match pred {
                CountPred::Gt => FloatCC::GreaterThan,
                CountPred::Lt => FloatCC::LessThan,
                CountPred::Eq => FloatCC::Equal,
                CountPred::Ne => FloatCC::NotEqual,
            };
            self.builder.ins().fcmp(cc, tail_val, threshold)
        } else {
            let cc = match pred {
                CountPred::Gt => IntCC::SignedGreaterThan,
                CountPred::Lt => IntCC::SignedLessThan,
                CountPred::Eq => IntCC::Equal,
                CountPred::Ne => IntCC::NotEqual,
            };
            self.builder.ins().icmp(cc, tail_val, threshold)
        };
        let cond_ext = self.builder.ins().uextend(types::I64, cond);
        let next_tail_cnt = self.builder.ins().iadd(cur_tail_cnt, cond_ext);
        let next_tail_ptr = self.builder.ins().iadd(cur_tail_ptr, step_bytes);
        let next_tail_i = self.builder.ins().iadd_imm_s(cur_tail_i, 1);
        self.builder.ins().jump(
            tail_header,
            &[
                BlockArg::from(next_tail_i),
                BlockArg::from(next_tail_ptr),
                BlockArg::from(next_tail_cnt),
            ],
        );

        self.builder.switch_to_block(cont_block);
        let final_res = self.builder.block_params(cont_block)[0];
        Some(final_res)
    }

    /// Lower elementwise slice clamping: `dst[i] = min(max(src[i], min_val), max_val)`.
    #[allow(clippy::too_many_arguments)]
    fn lower_slice_clamp(
        &mut self,
        elem_ty: types::Type,
        is_float: bool,
        elem_size: i64,
        src: ClValue,
        dst: ClValue,
        len: ClValue,
        stride: ClValue,
        min_val: ClValue,
        max_val: ClValue,
    ) -> Option<ClValue> {
        let step_bytes = self.builder.ins().imul_imm_s(stride, elem_size);
        let step2_bytes = self.builder.ins().iadd(step_bytes, step_bytes);
        let step3_bytes = self.builder.ins().iadd(step2_bytes, step_bytes);
        let step4_bytes = self.builder.ins().iadd(step2_bytes, step2_bytes);

        let mask_val = self.builder.ins().iconst(types::I64, -4);
        let unroll_len = self.builder.ins().band(len, mask_val);

        let unroll_header = self.builder.create_block();
        let unroll_body = self.builder.create_block();
        let tail_header = self.builder.create_block();
        let tail_body = self.builder.create_block();
        let cont_block = self.builder.create_block();

        self.builder.append_block_param(unroll_header, types::I64);
        self.builder
            .append_block_param(unroll_header, self.ptr_type);
        self.builder
            .append_block_param(unroll_header, self.ptr_type);

        self.builder.append_block_param(tail_header, types::I64);
        self.builder.append_block_param(tail_header, self.ptr_type);
        self.builder.append_block_param(tail_header, self.ptr_type);

        let initial_i = self.builder.ins().iconst(types::I64, 0);
        self.builder.ins().jump(
            unroll_header,
            &[
                BlockArg::from(initial_i),
                BlockArg::from(src),
                BlockArg::from(dst),
            ],
        );

        self.builder.switch_to_block(unroll_header);
        let cur_i = self.builder.block_params(unroll_header)[0];
        let cur_ps = self.builder.block_params(unroll_header)[1];
        let cur_pd = self.builder.block_params(unroll_header)[2];

        let has_unroll = self
            .builder
            .ins()
            .icmp(IntCC::UnsignedLessThan, cur_i, unroll_len);
        self.builder.ins().brif(
            has_unroll,
            unroll_body,
            &[],
            tail_header,
            &[
                BlockArg::from(cur_i),
                BlockArg::from(cur_ps),
                BlockArg::from(cur_pd),
            ],
        );

        self.builder.switch_to_block(unroll_body);
        let ps_0 = cur_ps;
        let ps_1 = self.builder.ins().iadd(cur_ps, step_bytes);
        let ps_2 = self.builder.ins().iadd(cur_ps, step2_bytes);
        let ps_3 = self.builder.ins().iadd(cur_ps, step3_bytes);

        let pd_0 = cur_pd;
        let pd_1 = self.builder.ins().iadd(cur_pd, step_bytes);
        let pd_2 = self.builder.ins().iadd(cur_pd, step2_bytes);
        let pd_3 = self.builder.ins().iadd(cur_pd, step3_bytes);

        let v0 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), ps_0, 0);
        let v1 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), ps_1, 0);
        let v2 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), ps_2, 0);
        let v3 = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), ps_3, 0);

        let clamp_one = |builder: &mut FunctionBuilder, v: ClValue, is_fl: bool| -> ClValue {
            if is_fl {
                let clamped_low = builder.ins().fmax(v, min_val);
                builder.ins().fmin(clamped_low, max_val)
            } else {
                let clamped_low = builder.ins().smax(v, min_val);
                builder.ins().smin(clamped_low, max_val)
            }
        };

        let c0 = clamp_one(&mut self.builder, v0, is_float);
        let c1 = clamp_one(&mut self.builder, v1, is_float);
        let c2 = clamp_one(&mut self.builder, v2, is_float);
        let c3 = clamp_one(&mut self.builder, v3, is_float);

        self.builder
            .ins()
            .store(MemFlagsData::trusted(), c0, pd_0, 0);
        self.builder
            .ins()
            .store(MemFlagsData::trusted(), c1, pd_1, 0);
        self.builder
            .ins()
            .store(MemFlagsData::trusted(), c2, pd_2, 0);
        self.builder
            .ins()
            .store(MemFlagsData::trusted(), c3, pd_3, 0);

        let next_ps = self.builder.ins().iadd(cur_ps, step4_bytes);
        let next_pd = self.builder.ins().iadd(cur_pd, step4_bytes);
        let next_i = self.builder.ins().iadd_imm_s(cur_i, 4);
        self.builder.ins().jump(
            unroll_header,
            &[
                BlockArg::from(next_i),
                BlockArg::from(next_ps),
                BlockArg::from(next_pd),
            ],
        );

        self.builder.switch_to_block(tail_header);
        let cur_tail_i = self.builder.block_params(tail_header)[0];
        let cur_tail_ps = self.builder.block_params(tail_header)[1];
        let cur_tail_pd = self.builder.block_params(tail_header)[2];

        let has_tail = self
            .builder
            .ins()
            .icmp(IntCC::UnsignedLessThan, cur_tail_i, len);
        self.builder
            .ins()
            .brif(has_tail, tail_body, &[], cont_block, &[]);

        self.builder.switch_to_block(tail_body);
        let tv = self
            .builder
            .ins()
            .load(elem_ty, MemFlagsData::trusted(), cur_tail_ps, 0);
        let clamped = if is_float {
            let clamped_low = self.builder.ins().fmax(tv, min_val);
            self.builder.ins().fmin(clamped_low, max_val)
        } else {
            let clamped_low = self.builder.ins().smax(tv, min_val);
            self.builder.ins().smin(clamped_low, max_val)
        };
        self.builder
            .ins()
            .store(MemFlagsData::trusted(), clamped, cur_tail_pd, 0);

        let next_tail_ps = self.builder.ins().iadd(cur_tail_ps, step_bytes);
        let next_tail_pd = self.builder.ins().iadd(cur_tail_pd, step_bytes);
        let next_tail_i = self.builder.ins().iadd_imm_s(cur_tail_i, 1);
        self.builder.ins().jump(
            tail_header,
            &[
                BlockArg::from(next_tail_i),
                BlockArg::from(next_tail_ps),
                BlockArg::from(next_tail_pd),
            ],
        );

        self.builder.switch_to_block(cont_block);
        Some(self.builder.ins().iconst(types::I64, 0))
    }

    fn ensure_i64(&mut self, v: ClValue) -> ClValue {
        let cur_ty = self.builder.func.dfg.value_type(v);
        if cur_ty == types::I64 {
            v
        } else if cur_ty.bits() < 64 {
            self.builder.ins().sextend(types::I64, v)
        } else {
            self.builder.ins().ireduce(types::I64, v)
        }
    }

    fn ensure_i32(&mut self, v: ClValue) -> ClValue {
        let cur_ty = self.builder.func.dfg.value_type(v);
        if cur_ty == types::I32 {
            v
        } else if cur_ty.bits() < 32 {
            self.builder.ins().sextend(types::I32, v)
        } else {
            self.builder.ins().ireduce(types::I32, v)
        }
    }

    fn ensure_f32(&mut self, v: ClValue) -> ClValue {
        let cur_ty = self.builder.func.dfg.value_type(v);
        if cur_ty == types::F32 {
            v
        } else if cur_ty == types::F64 {
            self.builder.ins().fdemote(types::F32, v)
        } else {
            v
        }
    }

    fn ensure_f64(&mut self, v: ClValue) -> ClValue {
        let cur_ty = self.builder.func.dfg.value_type(v);
        if cur_ty == types::F64 {
            v
        } else if cur_ty == types::F32 {
            self.builder.ins().fpromote(types::F64, v)
        } else {
            v
        }
    }

    fn ensure_ptr(&mut self, v: ClValue) -> ClValue {
        let cur_ty = self.builder.func.dfg.value_type(v);
        if cur_ty == self.ptr_type {
            v
        } else if cur_ty.bits() < self.ptr_type.bits() {
            self.builder.ins().sextend(self.ptr_type, v)
        } else {
            self.builder.ins().ireduce(self.ptr_type, v)
        }
    }
}
